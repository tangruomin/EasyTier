import type { NetworkTypes } from 'easytier-frontend-lib'
import { addPluginListener } from '@tauri-apps/api/core'
import { Utils } from 'easytier-frontend-lib'
import { get_vpn_status, prepare_vpn, start_vpn, stop_vpn } from 'tauri-plugin-vpnservice-api'

type Route = NetworkTypes.Route

interface vpnStatus {
  running: boolean
  ipv4Addr: string | null | undefined
  ipv4Cidr: number | null | undefined
  routes: string[]
  dns: string[]
}

let dhcpPollingTimer: NodeJS.Timeout | null = null
const DHCP_POLLING_INTERVAL = 2000 // 2秒后重试

const curVpnStatus: vpnStatus = {
  running: false,
  ipv4Addr: undefined,
  ipv4Cidr: undefined,
  routes: [],
  dns: [],
}

/** 全局出口默认路由网段。 */
const DEFAULT_ROUTE_CIDR = '0.0.0.0/0'

/** 魔法 DNS 的隧道内假 IP：easytier 核心在本机该地址上提供 DNS 服务。 */
const MAGIC_DNS_IP = '100.100.100.101'

/**
 * 后端当前是否安装了全局出口默认路由（0.0.0.0/0）。
 *
 * 由 proxy_cidrs_updated 事件维护：出口节点全部离线时后端会撤回 0.0.0.0/0
 * （出现在 removed 中），任一出口节点恢复在线时会重新安装（出现在 added 中）。
 * 默认 true 以保持 2.6.4 的既有行为，首个事件到达后即被纠正。
 */
let exitDefaultRouteActive = true

/** 判断网段字符串是否为默认路由。 */
function isDefaultRouteCidr(cidr: string): boolean {
  const normalized = cidr.trim()
  return normalized === DEFAULT_ROUTE_CIDR || normalized === '0/0'
}

/**
 * 根据后端下发的代理网段增删，同步「全局出口默认路由是否生效」。
 *
 * 由 event.ts 通过 composables 自动导入调用（见 vite.config.ts 的 AutoImport.dirs）。
 */
export function applyProxyCidrsChange(added?: string[], removed?: string[]) {
  if (added?.some(isDefaultRouteCidr)) {
    exitDefaultRouteActive = true
  }
  if (removed?.some(isDefaultRouteCidr)) {
    exitDefaultRouteActive = false
  }
}

/**
 * 解析实例配置里的 DNS 模式（`--dns-mode`）。
 *
 * 空值 / 未知值按 `auto` 处理，与 Rust 侧 `DnsMode::from_config_str` 保持一致。
 */
function resolveDnsMode(node_config: NetworkTypes.NetworkConfig): 'auto' | 'custom' | 'exit-node' {
  const mode = (node_config.dns_mode ?? '').trim().toLowerCase()
  if (mode === 'custom' || mode === 'exit-node') {
    return mode
  }
  return 'auto'
}

/** 去掉 DNS 服务器字符串中的端口（VpnService.addDnsServer 只接受地址本身）。 */
function stripDnsPort(server: string): string {
  const s = (server ?? '').trim()
  if (!s) {
    return ''
  }
  // 暂不支持把 IPv6 字面量下发给 VpnService（需要 [addr]:port 形式），直接跳过
  if (s.startsWith('[')) {
    return ''
  }
  const idx = s.indexOf(':')
  return idx >= 0 ? s.slice(0, idx) : s
}

/** 配置里第一个（即出口故障转移顺序中的第一个）可用的出口节点虚拟 IPv4。 */
function pickExitNodeIp(node_config: NetworkTypes.NetworkConfig): string | undefined {
  if (!exitDefaultRouteActive) {
    return undefined
  }
  for (const node of node_config.exit_nodes ?? []) {
    const ip = stripDnsPort(node ?? '')
    if (ip) {
      return ip
    }
  }
  return undefined
}

/**
 * 按 `dns_mode` 计算需要下发给 VpnService 的 DNS 服务器列表。
 *
 * - `custom`：用户填写的 DNS；
 * - `exit-node`：出口节点的虚拟 IP（查询经隧道由出口节点解析，最干净）；
 * - `auto`：有在线出口节点时用出口虚拟 IP，否则回退到魔法 DNS 的假 IP / 系统默认。
 *
 * 注意：这里**不会**下发境外公共 DNS（8.8.8.8 等）——那类地址在国内会被污染/拦截，
 * 反而会连浏览器的 DoH 引导解析一起打断（历史回归点）。
 */
function resolveVpnDnsServers(
  node_config: NetworkTypes.NetworkConfig,
  exitIp?: string,
): string[] {
  const mode = resolveDnsMode(node_config)

  if (mode === 'custom') {
    const custom = (node_config.dns_servers ?? [])
      .map(stripDnsPort)
      .filter(s => s.length > 0)
    if (custom.length > 0) {
      return Array.from(new Set(custom))
    }
    console.warn('dns_mode=custom 但未配置有效 DNS，回退到魔法 DNS / 系统 DNS')
  }

  if (mode === 'exit-node' && !exitIp) {
    console.warn('dns_mode=exit-node 但没有在线出口节点，回退到魔法 DNS / 系统 DNS')
  }

  if ((mode === 'auto' || mode === 'exit-node') && exitIp) {
    return [exitIp]
  }

  return node_config.enable_magic_dns ? [MAGIC_DNS_IP] : []
}

async function requestVpnPermission() {
  console.log('prepare vpn')
  const prepare_ret = await prepare_vpn()
  console.log('prepare vpn', JSON.stringify((prepare_ret)))
  if (prepare_ret?.errorMsg?.length) {
    throw new Error(prepare_ret.errorMsg)
  }

  const granted = prepare_ret?.granted ?? true
  if (!granted) {
    console.info('vpn permission request was denied or dismissed')
  }

  return granted
}

function resetVpnConfigStatus() {
  curVpnStatus.ipv4Addr = undefined
  curVpnStatus.ipv4Cidr = undefined
  curVpnStatus.routes = []
  curVpnStatus.dns = []
  // 复位出口默认路由状态，避免切换/重启网络实例后沿用上一次的旧状态
  exitDefaultRouteActive = true
}

function syncVpnStatusFromNative(status: Awaited<ReturnType<typeof get_vpn_status>>) {
  curVpnStatus.running = status?.running ?? false
  if (!curVpnStatus.running) {
    resetVpnConfigStatus()
    return
  }

  const ipv4WithCidr = status?.ipv4Addr
  if (ipv4WithCidr?.length) {
    const [ipv4Addr, cidr] = ipv4WithCidr.split('/')
    curVpnStatus.ipv4Addr = ipv4Addr

    const parsedCidr = Number(cidr)
    curVpnStatus.ipv4Cidr = Number.isInteger(parsedCidr) ? parsedCidr : undefined
  }
  else {
    curVpnStatus.ipv4Addr = undefined
    curVpnStatus.ipv4Cidr = undefined
  }

  curVpnStatus.routes = [...(status?.routes ?? [])]
  curVpnStatus.dns = [...(status?.dns ?? [])]
}

async function waitVpnStatus(target_status: boolean, timeout_sec: number) {
  const start_time = Date.now()
  while (curVpnStatus.running !== target_status) {
    if (Date.now() - start_time > timeout_sec * 1000) {
      throw new Error('wait vpn status timeout')
    }
    await new Promise(r => setTimeout(r, 50))
  }
}

async function doStopVpn(force = false) {
  const wasRunning = curVpnStatus.running
  if (!force && !wasRunning) {
    return
  }
  console.log('stop vpn')
  const stop_ret = await stop_vpn()
  console.log('stop vpn', JSON.stringify((stop_ret)))
  if (wasRunning) {
    await waitVpnStatus(false, 3)
  }

  resetVpnConfigStatus()
}

async function doStartVpn(ipv4Addr: string, cidr: number, routes: string[], dns: string[]) {
  if (curVpnStatus.running) {
    return
  }

  console.log('start vpn service', ipv4Addr, cidr, routes, dns)
  const request = {
    ipv4Addr: `${ipv4Addr}/${cidr}`,
    routes,
    dns,
    disallowedApplications: ['com.kkrainbow.easytier'],
    mtu: 1300,
  }

  let start_ret = await start_vpn(request)
  console.log('start vpn response', JSON.stringify(start_ret))
  if (start_ret?.errorMsg === 'need_prepare') {
    const granted = await requestVpnPermission()
    if (!granted) {
      throw new Error('vpn_permission_denied')
    }
    start_ret = await start_vpn(request)
    console.log('start vpn retry response', JSON.stringify(start_ret))
  }

  if (start_ret?.errorMsg?.length) {
    throw new Error(start_ret.errorMsg)
  }
  await waitVpnStatus(true, 3)

  curVpnStatus.ipv4Addr = ipv4Addr
  curVpnStatus.ipv4Cidr = cidr
  curVpnStatus.routes = routes
  curVpnStatus.dns = dns
}

async function onVpnServiceStart(payload: any) {
  console.log('vpn service start', JSON.stringify(payload))
  curVpnStatus.running = true
  if (payload.fd) {
    await setTunFd(payload.fd).catch((e) => {
      console.error('set tun fd failed', e)
    })
  }
}

async function onVpnServiceStop(payload: any) {
  console.log('vpn service stop', JSON.stringify(payload))
  curVpnStatus.running = false
  resetVpnConfigStatus()
}

async function registerVpnServiceListener() {
  console.log('register vpn service listener')
  await addPluginListener(
    'vpnservice',
    'vpn_service_start',
    onVpnServiceStart,
  )

  await addPluginListener(
    'vpnservice',
    'vpn_service_stop',
    onVpnServiceStop,
  )
}

function getRoutesForVpn(
  routes: Route[],
  node_config: NetworkTypes.NetworkConfig,
  dnsServers: string[],
): string[] {
  if (!routes) {
    return []
  }

  const ret = []
  for (const r of routes) {
    for (let cidr of r.proxy_cidrs) {
      if (!cidr.includes('/')) {
        cidr += '/32'
      }
      ret.push(cidr)
    }
  }

  node_config.routes.forEach(r => {
    // 全局出口默认路由只在后端仍安装它时才下发。出口节点全部离线时后端会撤回
    // 0.0.0.0/0，这里必须同步剔除，否则 Android 会把公网流量继续送进隧道形成
    // 黑洞、无法回退本机直连。
    if (isDefaultRouteCidr(r) && !exitDefaultRouteActive) {
      console.info('skip default route in vpn because all exit nodes are offline')
      return
    }
    ret.push(r)
  })

  if (node_config.enable_magic_dns) {
    ret.push('100.100.100.101/32')
  }

  // DNS 服务器必须经隧道可达，否则 netd 的查询会从运营商网络直连出去（被污染/被拦截）
  for (const server of dnsServers) {
    ret.push(`${server}/32`)
  }

  // sort and dedup
  return Array.from(new Set(ret)).sort()
}

export async function onNetworkInstanceChange(instanceId: string) {
  console.error('vpn service network instance change id', instanceId)

  if (dhcpPollingTimer) {
    clearTimeout(dhcpPollingTimer)
    dhcpPollingTimer = null
  }

  if (!instanceId) {
    console.warn('vpn service skipped because instance id is empty')
    if (curVpnStatus.running) {
      await doStopVpn()
    }
    return
  }
  const config = await getConfig(instanceId)
  console.log('vpn service loaded config', instanceId, JSON.stringify({
    no_tun: config.no_tun,
    dhcp: config.dhcp,
    enable_magic_dns: config.enable_magic_dns,
  }))
  if (config.no_tun) {
    console.log('vpn service skipped because no_tun is enabled', instanceId)
    return
  }
  const curNetworkInfo = (await collectNetworkInfo(instanceId)).info.map[instanceId]
  if (!curNetworkInfo || curNetworkInfo?.error_msg?.length) {
    console.warn('vpn service skipped because network info is unavailable', instanceId, curNetworkInfo?.error_msg)
    await doStopVpn()
    return
  }

  const virtual_ip = Utils.ipv4ToString(curNetworkInfo?.my_node_info?.virtual_ipv4.address)

  if (config.dhcp && (!virtual_ip || !virtual_ip.length)) {
    console.log('DHCP enabled but no IP yet, will retry in', DHCP_POLLING_INTERVAL, 'ms')
    dhcpPollingTimer = setTimeout(() => {
      onNetworkInstanceChange(instanceId)
    }, DHCP_POLLING_INTERVAL)
    return
  }

  if (!virtual_ip || !virtual_ip.length) {
    await doStopVpn()
    return
  }

  let network_length = curNetworkInfo?.my_node_info?.virtual_ipv4.network_length
  if (!network_length) {
    network_length = 24
  }

  const exitIp = pickExitNodeIp(config)
  const dns = resolveVpnDnsServers(config, exitIp)
  const routes = getRoutesForVpn(curNetworkInfo?.routes, config, dns)

  const ipChanged = virtual_ip !== curVpnStatus.ipv4Addr
  const cidrChanged = network_length !== curVpnStatus.ipv4Cidr
  const routesChanged = JSON.stringify(routes) !== JSON.stringify(curVpnStatus.routes)
  const dnsChanged = JSON.stringify(dns) !== JSON.stringify(curVpnStatus.dns)
  const configChanged = ipChanged || cidrChanged || routesChanged || dnsChanged
  const shouldStartVpn = !curVpnStatus.running

  if (shouldStartVpn || configChanged) {
    console.info('vpn service virtual ip changed', JSON.stringify(curVpnStatus), virtual_ip)
    if (curVpnStatus.running) {
      try {
        await doStopVpn()
      }
      catch (e) {
        console.error(e)
      }
    }

    try {
      await doStartVpn(virtual_ip, network_length, routes, dns)
    }
    catch (e) {
      if (e instanceof Error && e.message === 'need_prepare') {
        console.info('vpn permission is required before starting the Android VPN service')
        return
      }
      if (e instanceof Error && e.message === 'vpn_permission_denied') {
        console.info('vpn permission request was denied or dismissed')
        return
      }
      console.error('start vpn service failed', e)
    }
  }
}

async function isNoTunEnabled(instanceId: string | undefined) {
  if (!instanceId) {
    return false
  }
  return (await getConfig(instanceId)).no_tun ?? false
}

async function findRunningTunInstanceId() {
  const instanceIds = await listNetworkInstanceIds()
  const runningIds = instanceIds.running_inst_ids.map(Utils.UuidToStr)
  console.log('vpn service sync running instances', JSON.stringify(runningIds))

  for (const instanceId of runningIds) {
    if (await isNoTunEnabled(instanceId)) {
      continue
    }

    return instanceId
  }

  return undefined
}

export async function initMobileVpnService() {
  await registerVpnServiceListener()
}

export async function prepareVpnService(instanceId: string) {
  if (await isNoTunEnabled(instanceId)) {
    return
  }
  await requestVpnPermission()
}

export async function syncMobileVpnService() {
  syncVpnStatusFromNative(await get_vpn_status())
  const instanceId = await findRunningTunInstanceId()
  if (instanceId) {
    console.log('vpn service sync selected instance', instanceId)
    await onNetworkInstanceChange(instanceId)
    return
  }

  if (dhcpPollingTimer) {
    clearTimeout(dhcpPollingTimer)
    dhcpPollingTimer = null
  }

  await doStopVpn(true)
}
