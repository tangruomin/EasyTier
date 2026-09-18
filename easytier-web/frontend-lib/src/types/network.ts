import { v4 as uuidv4 } from 'uuid'

export enum NetworkingMethod {
  PublicServer = 0,
  Manual = 1,
  Standalone = 2,
}

export interface SecureModeConfig {
  enabled: boolean
  // Keep protocol compatibility with backend/import-export flows even though the GUI
  // does not render secure-mode or credential inputs.
  local_private_key?: string
  local_public_key?: string
}

export enum AclProtocol {
  Unspecified = 0,
  TCP = 1,
  UDP = 2,
  ICMP = 3,
  ICMPv6 = 4,
  Any = 5,
}

export enum AclAction {
  Noop = 0,
  Allow = 1,
  Drop = 2,
}

export enum AclChainType {
  UnspecifiedChain = 0,
  Inbound = 1,
  Outbound = 2,
  Forward = 3,
}

export interface AclRule {
  name: string
  description: string
  priority: number
  enabled: boolean
  protocol: AclProtocol
  ports: string[]
  source_ips: string[]
  destination_ips: string[]
  source_ports: string[]
  action: AclAction
  rate_limit: number
  burst_limit: number
  stateful: boolean
  source_groups: string[]
  destination_groups: string[]
}

export interface AclChain {
  name: string
  chain_type: AclChainType
  description: string
  enabled: boolean
  rules: AclRule[]
  default_action: AclAction
}

export interface GroupIdentity {
  group_name: string
  group_secret: string
}

export interface GroupInfo {
  declares: GroupIdentity[]
  members: string[]
}

export interface AclV1 {
  chains: AclChain[]
  group?: GroupInfo
}

export interface Acl {
  acl_v1?: AclV1
}

export interface NetworkConfig {
  instance_id: string

  dhcp: boolean
  virtual_ipv4: string
  network_length: number
  hostname?: string
  network_name: string
  network_secret?: string
  credential_file?: string
  secure_mode?: SecureModeConfig

  networking_method: NetworkingMethod

  public_server_url: string
  peer_urls: string[]

  proxy_cidrs: string[]

  enable_vpn_portal: boolean
  vpn_portal_listen_port: number
  vpn_portal_client_network_addr: string
  vpn_portal_client_network_len: number

  advanced_settings: boolean

  listener_urls: string[]
  latency_first: boolean

  dev_name: string

  use_smoltcp?: boolean
  disable_ipv6?: boolean
  ipv6_public_addr_auto?: boolean
  enable_kcp_proxy?: boolean
  disable_kcp_input?: boolean
  enable_quic_proxy?: boolean
  disable_quic_input?: boolean
  disable_p2p?: boolean
  p2p_only?: boolean
  lazy_p2p?: boolean
  bind_device?: boolean
  no_tun?: boolean
  enable_exit_node?: boolean
  relay_all_peer_rpc?: boolean
  need_p2p?: boolean
  multi_thread?: boolean
  proxy_forward_by_system?: boolean
  disable_encryption?: boolean
  disable_tcp_hole_punching?: boolean
  disable_udp_hole_punching?: boolean
  disable_upnp?: boolean
  enable_udp_broadcast_relay?: boolean
  disable_sym_hole_punching?: boolean

  enable_relay_network_whitelist?: boolean
  relay_network_whitelist: string[]

  enable_manual_routes: boolean
  routes: string[]

  exit_nodes: string[]

  enable_socks5?: boolean
  socks5_port: number

  mtu: number | null
  instance_recv_bps_limit: number | null
  mapped_listeners: string[]

  enable_magic_dns?: boolean
  enable_private_mode?: boolean

  // DNS 上游模式：'auto'（默认，等价于未设置或空字符串）/ 'custom' / 'exit-node'。
  // 它只决定「域名查询交给谁解析」，与 enable_magic_dns（魔法 DNS）可组合使用。
  // DNS upstream mode: 'auto' (default, same as unset or empty string) / 'custom' / 'exit-node'.
  // It only decides who resolves domain queries and can be combined with enable_magic_dns.
  dns_mode?: string
  // dns_mode = 'custom' 时使用的 DNS 服务器列表，可省略端口（默认 53）。
  // DNS servers used when dns_mode = 'custom'; the port may be omitted (defaults to 53).
  dns_servers?: string[]
  // 出口节点是否禁止提供隧道内 DNS 服务。默认 false = 出口节点在虚拟 IP:53 提供 DNS 服务。
  // Whether the exit node disables the in-tunnel DNS service. Default false = the exit node
  // serves DNS on virtual IP:53.
  disable_exit_dns?: boolean

  // ---------------------------------------------------------------------------
  // WG 混淆（抗 DPI）：仅对 wg:// 隧道生效。
  // WG obfuscation (anti-DPI); only affects wg:// tunnels.
  // ---------------------------------------------------------------------------
  // 总开关，默认关闭：false / 未设置 = 使用原生 WireGuard，行为与之前完全一致。
  // 开启后隧道两端必须使用完全相同的混淆参数，且不再兼容旧版本节点与公网服务器。
  // Master switch, off by default: false / unset = plain WireGuard, identical to before.
  // Once enabled, both ends must use exactly the same parameters, and old nodes / public
  // servers are no longer compatible.
  wg_obfs?: boolean
  // 以下 7 个混淆参数均为可选：
  //   * 未设置（undefined / null）= 使用代码内置默认值
  //     （S1=37、S2=42、S3=19、S4=11、Jc=4、Jmin=200、Jmax=260，见 WG_OBFS_DEFAULTS）；
  //   * 显式填 0 = 该字段不做填充 / 不发送 junk（与“未设置”含义不同）。
  // 合法范围：S1/S2/S3 0-64、S4 0-32、Jc 0-10、Jmin/Jmax 64-1024 且 Jmin <= Jmax，
  // 并且 [Jmin,Jmax] 不得包含 148+S1 / 92+S2 / 64+S3。
  // All 7 obfuscation parameters below are optional:
  //   * unset (undefined / null) = use the built-in defaults
  //     (S1=37, S2=42, S3=19, S4=11, Jc=4, Jmin=200, Jmax=260; see WG_OBFS_DEFAULTS);
  //   * an explicit 0 = no padding / no junk for that field (this differs from "unset").
  // Valid ranges: S1/S2/S3 0-64, S4 0-32, Jc 0-10, Jmin/Jmax 64-1024 with Jmin <= Jmax, and
  // [Jmin,Jmax] must not contain 148+S1 / 92+S2 / 64+S3.
  wg_obfs_s1?: number
  wg_obfs_s2?: number
  wg_obfs_s3?: number
  wg_obfs_s4?: number
  wg_obfs_jc?: number
  wg_obfs_jmin?: number
  wg_obfs_jmax?: number

  port_forwards: PortForwardConfig[]
  acl?: Acl
}

/** DNS 上游模式取值，需与后端 `DnsMode`（`--dns-mode`）保持一致。 */
// DNS upstream mode values; must stay in sync with the backend `DnsMode` (`--dns-mode`).
export const DNS_MODE_AUTO = 'auto'
export const DNS_MODE_CUSTOM = 'custom'
export const DNS_MODE_EXIT_NODE = 'exit-node'

export type DnsMode = typeof DNS_MODE_AUTO | typeof DNS_MODE_CUSTOM | typeof DNS_MODE_EXIT_NODE

/**
 * 读取 dns_mode：undefined / 空字符串 / 无法识别的取值都按 'auto' 处理（与后端一致）。
 * Read dns_mode: undefined, empty string and unknown values all fall back to 'auto'
 * (same behaviour as the backend).
 */
export function getDnsMode(config: NetworkConfig | undefined): DnsMode {
  const mode = (config?.dns_mode ?? '').trim().toLowerCase()
  switch (mode) {
    case DNS_MODE_CUSTOM:
      return DNS_MODE_CUSTOM
    case DNS_MODE_EXIT_NODE:
    case 'exit_node':
    case 'exitnode':
      return DNS_MODE_EXIT_NODE
    default:
      return DNS_MODE_AUTO
  }
}

/** 过滤 DNS 服务器列表中的空白项并 trim。 / Trim entries and drop blanks from a DNS server list. */
export function cleanDnsServers(servers: string[] | undefined): string[] {
  return (servers ?? []).map((server) => server.trim()).filter((server) => server.length > 0)
}

/**
 * 解析用户输入的 DNS 服务器文本：按英文/中文逗号、分号或空白分隔，并过滤空项。
 * Parse user-entered DNS server text: split on ASCII/CJK commas, semicolons or whitespace,
 * then drop empty entries.
 */
export function parseDnsServersText(text: string | undefined): string[] {
  return cleanDnsServers((text ?? '').split(/[,，;；\s]+/))
}

/** 将 DNS 服务器列表序列化为逗号分隔文本。 / Serialize a DNS server list as comma-separated text. */
export function formatDnsServersText(servers: string[] | undefined): string {
  return cleanDnsServers(servers).join(', ')
}

// ---------------------------------------------------------------------------
// WG 混淆（抗 DPI）参数的常量与工具
// Constants and helpers for the WG obfuscation (anti-DPI) parameters.
// ---------------------------------------------------------------------------

/** WG 混淆中可写的 7 个参数字段名。 / The 7 writable WG obfuscation parameter field names. */
export type WgObfsField =
  | 'wg_obfs_s1'
  | 'wg_obfs_s2'
  | 'wg_obfs_s3'
  | 'wg_obfs_s4'
  | 'wg_obfs_jc'
  | 'wg_obfs_jmin'
  | 'wg_obfs_jmax'

/** 单个参数的规格：内置默认值 + 合法范围。 / Spec of one parameter: built-in default + valid range. */
export interface WgObfsParamSpec {
  /** 未设置该字段时使用的内置默认值（与后端代码内默认值一致）。 */
  /** Built-in default used when the field is unset (identical to the backend default). */
  default: number
  /** 合法下界（含）。 / Inclusive lower bound. */
  min: number
  /** 合法上界（含）。 / Inclusive upper bound. */
  max: number
}

/**
 * 7 个 WG 混淆参数的内置默认值与合法范围，供界面显示提示、钳制用户输入使用。
 * 未设置（undefined / null）时后端使用这些默认值：S1=37、S2=42、S3=19、S4=11、Jc=4、
 * Jmin=200、Jmax=260；显式填 0 表示该字段不做填充 / 不发送 junk。
 * Built-in defaults and valid ranges of the 7 WG obfuscation parameters, used by the UI for
 * placeholders and input clamping. When a field is unset (undefined / null) the backend uses
 * these defaults: S1=37, S2=42, S3=19, S4=11, Jc=4, Jmin=200, Jmax=260. An explicit 0 means
 * "no padding / no junk" for that field.
 */
export const WG_OBFS_DEFAULTS: Record<WgObfsField, WgObfsParamSpec> = {
  wg_obfs_s1: { default: 37, min: 0, max: 64 },
  wg_obfs_s2: { default: 42, min: 0, max: 64 },
  wg_obfs_s3: { default: 19, min: 0, max: 64 },
  wg_obfs_s4: { default: 11, min: 0, max: 32 },
  wg_obfs_jc: { default: 4, min: 0, max: 10 },
  wg_obfs_jmin: { default: 200, min: 64, max: 1024 },
  wg_obfs_jmax: { default: 260, min: 64, max: 1024 },
}

/**
 * junk 探针偏移量：junk 长度区间 [Jmin,Jmax] 不得包含 148+S1 / 92+S2 / 64+S3，
 * 否则后端会关闭 junk 填充并告警。
 * Junk probe offsets: [Jmin,Jmax] must not contain 148+S1 / 92+S2 / 64+S3, otherwise the
 * backend disables junk padding and emits a warning.
 */
export const WG_OBFS_JUNK_PROBE_OFFSETS: Record<'s1' | 's2' | 's3', number> = {
  s1: 148,
  s2: 92,
  s3: 64,
}

/**
 * 把用户输入钳制到该字段的合法范围内。
 * 留空 / 非数字 / 非有限值返回 undefined（= 该字段不该被写入，让后端使用内置默认值）；
 * 超出范围时返回边界值（而不是 undefined）。注意 0 是合法输入，必须原样保留。
 * Clamp user input into the valid range of the field.
 * Empty / non-numeric / non-finite input returns undefined (= the field should not be written at
 * all, so the backend keeps its built-in default); out-of-range input returns the bound (not
 * undefined). Note that 0 is a valid value and must be preserved as-is.
 */
export function clampWgObfsValue(field: WgObfsField, value: unknown): number | undefined {
  const spec = WG_OBFS_DEFAULTS[field]
  if (value === undefined || value === null || value === '') {
    return undefined
  }

  const num = typeof value === 'number' ? value : Number(value)
  if (!Number.isFinite(num)) {
    return undefined
  }

  const int = Math.round(num)
  if (int < spec.min) {
    return spec.min
  }
  if (int > spec.max) {
    return spec.max
  }
  return int
}

/** junk 区间冲突检查的输入；未设置的字段按内置默认值参与计算。 */
/** Input of the junk range check; unset fields participate with their built-in defaults. */
export interface WgObfsJunkRangeInput {
  s1?: number | null
  s2?: number | null
  s3?: number | null
  jmin?: number | null
  jmax?: number | null
}

/**
 * 返回落在 [Jmin,Jmax] 区间内的 junk 探针值（去重、升序）。
 * 未设置的参数用 WG_OBFS_DEFAULTS 的内置默认值参与计算（与后端行为一致）；
 * 返回非空数组表示后端会关闭 junk 填充并告警，界面应提示用户改参数。
 * Returns the (deduplicated, ascending) junk probe values that fall inside [Jmin, Jmax].
 * Unset parameters participate with their built-in WG_OBFS_DEFAULTS value, matching the
 * backend. A non-empty result means the backend disables junk padding and warns, so the UI
 * should ask the user to change the parameters.
 */
export function wgObfsJunkProbeConflicts(input: WgObfsJunkRangeInput): number[] {
  const pick = (value: number | null | undefined, fallback: number): number =>
    value === undefined || value === null ? fallback : value

  const jmin = pick(input.jmin, WG_OBFS_DEFAULTS.wg_obfs_jmin.default)
  const jmax = pick(input.jmax, WG_OBFS_DEFAULTS.wg_obfs_jmax.default)
  const low = Math.min(jmin, jmax)
  const high = Math.max(jmin, jmax)

  const probes = [
    WG_OBFS_JUNK_PROBE_OFFSETS.s1 + pick(input.s1, WG_OBFS_DEFAULTS.wg_obfs_s1.default),
    WG_OBFS_JUNK_PROBE_OFFSETS.s2 + pick(input.s2, WG_OBFS_DEFAULTS.wg_obfs_s2.default),
    WG_OBFS_JUNK_PROBE_OFFSETS.s3 + pick(input.s3, WG_OBFS_DEFAULTS.wg_obfs_s3.default),
  ]

  return Array.from(new Set(probes.filter((probe) => probe >= low && probe <= high)))
    .sort((a, b) => a - b)
}

export function DEFAULT_NETWORK_CONFIG(): NetworkConfig {
  return {
    instance_id: uuidv4(),

    dhcp: true,
    virtual_ipv4: '',
    network_length: 24,
    network_name: 'easytier',
    network_secret: '',
    credential_file: '',

    networking_method: NetworkingMethod.Manual,
    public_server_url: '',
    peer_urls: [],

    proxy_cidrs: [],

    enable_vpn_portal: false,
    vpn_portal_listen_port: 22022,
    vpn_portal_client_network_addr: '',
    vpn_portal_client_network_len: 24,

    advanced_settings: false,

    listener_urls: [
      'tcp://0.0.0.0:11010',
      'udp://0.0.0.0:11010',
      'wg://0.0.0.0:11011',
    ],
    latency_first: false,
    dev_name: '',

    use_smoltcp: false,
    disable_ipv6: false,
    ipv6_public_addr_auto: false,
    enable_kcp_proxy: false,
    disable_kcp_input: false,
    enable_quic_proxy: false,
    disable_quic_input: false,
    disable_p2p: false,
    p2p_only: false,
    lazy_p2p: false,
    bind_device: true,
    no_tun: false,
    enable_exit_node: false,
    relay_all_peer_rpc: false,
    need_p2p: false,
    multi_thread: true,
    proxy_forward_by_system: false,
    disable_encryption: false,
    disable_tcp_hole_punching: false,
    disable_udp_hole_punching: false,
    disable_upnp: false,
    enable_udp_broadcast_relay: false,
    disable_sym_hole_punching: false,
    enable_relay_network_whitelist: false,
    relay_network_whitelist: [],
    enable_manual_routes: false,
    routes: [],
    exit_nodes: [],
    enable_socks5: false,
    socks5_port: 1080,
    mtu: null,
    instance_recv_bps_limit: null,
    mapped_listeners: [],
    enable_magic_dns: false,
    enable_private_mode: false,
    dns_mode: DNS_MODE_AUTO,
    dns_servers: [],
    disable_exit_dns: false,
    // WG 混淆总开关默认关闭；其余 7 个参数保持 undefined（= 使用内置默认值）。
    // 这里绝不能写 0，0 表示“显式关闭该项填充”，与“用内置默认值”含义不同。
    // WG obfuscation is off by default; the other 7 parameters stay undefined (= built-in
    // defaults). Never write 0 here: 0 means "explicitly disable that padding", which is not
    // the same as "use the built-in default".
    wg_obfs: false,
    port_forwards: [],
    acl: {
      acl_v1: {
        group: {
          declares: [],
          members: [],
        },
        chains: [],
      },
    },
  }
}

function cleanPeerUrls(urls: string[] | undefined): string[] {
  return (urls ?? []).map((url) => url.trim()).filter((url) => url.length > 0)
}

export function normalizeNetworkConfig(config: NetworkConfig): NetworkConfig {
  const normalized: NetworkConfig = {
    ...config,
    peer_urls: cleanPeerUrls(config.peer_urls),
  }

  const publicServerUrl = normalized.public_server_url?.trim() ?? ''

  switch (normalized.networking_method) {
    case NetworkingMethod.PublicServer:
      normalized.peer_urls = publicServerUrl ? [publicServerUrl] : []
      break
    case NetworkingMethod.Manual:
      break
    case NetworkingMethod.Standalone:
    default:
      normalized.peer_urls = []
      break
  }

  normalized.networking_method = NetworkingMethod.Manual
  normalized.public_server_url = ''
  // DNS 字段：写入规范化的显式取值，避免 undefined / 空字符串在后端落到不同分支。
  // DNS fields: write normalised explicit values so that undefined / empty string can never
  // hit different code paths on the backend.
  normalized.dns_mode = getDnsMode(normalized)
  normalized.dns_servers = cleanDnsServers(normalized.dns_servers)
  // WG 混淆：只把总开关规范化为布尔（!!），未设置按关闭处理。
  // 7 个参数保持原样（undefined = 使用后端内置默认值），这里绝不填默认数字，
  // 也不会把 undefined 变成 0，否则就无法区分“留空”和“用户显式填 0”。
  // WG obfuscation: only coerce the master switch to a boolean (!!); unset counts as off.
  // The 7 parameters are left untouched (undefined = use the backend built-in default). Never
  // fill in default numbers here and never turn undefined into 0, otherwise "left empty" and
  // "the user explicitly typed 0" could not be told apart.
  normalized.wg_obfs = !!normalized.wg_obfs
  return normalized
}

export function toBackendNetworkConfig(config: NetworkConfig): NetworkConfig {
  return normalizeNetworkConfig(config)
}

export interface NetworkInstance {
  instance_id: string

  running: boolean
  error_msg: string

  detail?: NetworkInstanceRunningInfo
}

export interface NetworkInstanceRunningInfo {
  dev_name: string
  my_node_info: NodeInfo
  events: Array<string>,
  routes: Route[]
  peers: PeerInfo[]
  peer_route_pairs: PeerRoutePair[]
  running: boolean
  error_msg?: string
}

export interface Ipv4Addr {
  addr: number
}

export interface Ipv4Inet {
  address: Ipv4Addr
  network_length: number
}

export interface Ipv6Addr {
  part1: number
  part2: number
  part3: number
  part4: number
}

export interface Url {
  url: string
}

export interface NodeInfo {
  virtual_ipv4: Ipv4Inet,
  hostname: string
  version: string
  ips: {
    public_ipv4: Ipv4Addr
    interface_ipv4s: Ipv4Addr[]
    public_ipv6: Ipv6Addr
    interface_ipv6s: Ipv6Addr[]
    listeners: {
      serialization: string
      scheme_end: number
      username_end: number
      host_start: number
      host_end: number
      host: any
      port?: number
      path_start: number
      query_start?: number
      fragment_start?: number
    }[]
  }
  stun_info: StunInfo
  listeners: Url[]
  vpn_portal_cfg?: string
  peer_id: number
}

export interface StunInfo {
  udp_nat_type: number
  tcp_nat_type: number
  last_update_time: number
}

export interface Route {
  peer_id: number
  ipv4_addr: Ipv4Inet | string | null
  next_hop_peer_id: number
  cost: number
  proxy_cidrs: string[]
  hostname: string
  stun_info?: StunInfo
  inst_id: string
  version: string
}

export interface PeerInfo {
  peer_id: number
  conns: PeerConnInfo[]
}

export interface PeerConnInfo {
  conn_id: string
  my_peer_id: number
  is_client: boolean
  peer_id: number
  features: string[]
  tunnel?: TunnelInfo
  stats?: PeerConnStats
  loss_rate: number
}

export interface PeerRoutePair {
  route: Route
  peer?: PeerInfo
}

export interface UrlPb {
  url: string
}

export interface TunnelInfo {
  tunnel_type: string
  local_addr: UrlPb
  remote_addr: UrlPb
}

export interface PeerConnStats {
  rx_bytes: number
  tx_bytes: number
  rx_packets: number
  tx_packets: number
  latency_us: number
}

export interface PortForwardConfig {
  bind_ip: string,
  bind_port: number,
  dst_ip: string,
  dst_port: number,
  proto: string
}

// 添加新行
export const addRow = (rows: PortForwardConfig[]) => {
  rows.push({
    proto: 'tcp',
    bind_ip: '',
    bind_port: 65535,
    dst_ip: '',
    dst_port: 65535,
  });
};

// 删除行
export const removeRow = (index: number, rows: PortForwardConfig[]) => {
  rows.splice(index, 1);
};

export enum EventType {
  TunDeviceReady = 'TunDeviceReady', // string
  TunDeviceError = 'TunDeviceError', // string

  PeerAdded = 'PeerAdded', // number
  PeerRemoved = 'PeerRemoved', // number
  PeerConnAdded = 'PeerConnAdded', // PeerConnInfo
  PeerConnRemoved = 'PeerConnRemoved', // PeerConnInfo

  ListenerAdded = 'ListenerAdded', // any
  ListenerAddFailed = 'ListenerAddFailed', // any, string
  ListenerAcceptFailed = 'ListenerAcceptFailed', // any, string
  ConnectionAccepted = 'ConnectionAccepted', // string, string
  ConnectionError = 'ConnectionError', // string, string, string

  Connecting = 'Connecting', // any
  ConnectError = 'ConnectError', // string, string, string

  VpnPortalStarted = 'VpnPortalStarted', // string
  VpnPortalClientConnected = 'VpnPortalClientConnected', // string, string
  VpnPortalClientDisconnected = 'VpnPortalClientDisconnected', // string, string, string

  DhcpIpv4Changed = 'DhcpIpv4Changed', // ipv4 | null, ipv4 | null
  DhcpIpv4Conflicted = 'DhcpIpv4Conflicted', // ipv4 | null

  PortForwardAdded = 'PortForwardAdded', // PortForwardConfigPb

  ProxyCidrsUpdated = 'ProxyCidrsUpdated', // string[], string[]

  UdpBroadcastRelayStartResult = 'UdpBroadcastRelayStartResult', // { capture_backend?: string, error?: string }
}
