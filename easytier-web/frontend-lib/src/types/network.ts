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
