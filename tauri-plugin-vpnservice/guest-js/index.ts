import { invoke } from '@tauri-apps/api/core'

export async function ping(value: string): Promise<string | null> {
  return await invoke<{ value?: string }>('plugin:vpnservice|ping', {
    payload: {
      value,
    },
  }).then((r) => (r.value ? r.value : null));
}

export interface InvokeResponse {
  errorMsg?: string;
  granted?: boolean;
}

export interface StartVpnRequest {
  ipv4Addr?: string;
  routes?: string[];
  /**
   * 下发给 VpnService 的 DNS 服务器列表。由前端按实例配置的 dns_mode 决定：
   * auto（有在线出口 -> 出口虚拟 IP；否则 100.100.100.101）/ custom（用户填写）
   * / exit-node（出口虚拟 IP）。
   */
  dns?: string[];
  disallowedApplications?: string[];
  mtu?: number;
}

export interface VpnStatusResponse {
  running: boolean;
  ipv4Addr?: string;
  routes?: string[];
  dns?: string[];
}

export async function prepare_vpn(): Promise<InvokeResponse | null> {
  return await invoke<InvokeResponse>('plugin:vpnservice|prepare_vpn', {})
}

export async function start_vpn(request: StartVpnRequest): Promise<InvokeResponse | null> {
  return await invoke<InvokeResponse>('plugin:vpnservice|start_vpn', {
    ...request,
  })
}

export async function stop_vpn(): Promise<InvokeResponse | null> {
  return await invoke<InvokeResponse>('plugin:vpnservice|stop_vpn', {})
}

export async function get_vpn_status(): Promise<VpnStatusResponse | null> {
  return await invoke<VpnStatusResponse>('plugin:vpnservice|get_vpn_status', {})
}
