<script setup lang="ts">
import { AutoComplete, Button, Checkbox, Dialog, Divider, InputNumber, InputText, Panel, Password, SelectButton, ToggleButton } from 'primevue'
import InputGroup from 'primevue/inputgroup'
import InputGroupAddon from 'primevue/inputgroupaddon'
import {
  addRow,
  clampWgObfsValue,
  DEFAULT_NETWORK_CONFIG,
  DNS_MODE_AUTO,
  DNS_MODE_CUSTOM,
  DNS_MODE_EXIT_NODE,
  formatDnsServersText,
  getDnsMode,
  NetworkConfig,
  normalizeNetworkConfig,
  parseDnsServersText,
  removeRow,
  WG_OBFS_DEFAULTS,
  WgObfsField,
  wgObfsJunkProbeConflicts
} from '../types/network'
import { computed, ref, onMounted, onUnmounted, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import AclManager from './acl/AclManager.vue'
import UrlListInput from './UrlListInput.vue'

const props = defineProps<{
  configInvalid?: boolean
  hostname?: string
}>()

defineEmits(['runNetwork'])

const curNetwork = defineModel('curNetwork', {
  type: Object as () => NetworkConfig,
  default: DEFAULT_NETWORK_CONFIG,
})

const { t } = useI18n()

const protos: { [proto: string]: number } = {
  tcp: 11010,
  udp: 11010,
  wg: 11011,
  ws: 11011,
  wss: 11012,
  quic: 11012,
  faketcp: 11013,
  http: 80,
  https: 443,
  txt: 0,
  srv: 0,
}

const inetSuggestions = ref([''])

function searchInetSuggestions(e: { query: string }) {
  if (e.query.search('/') >= 0) {
    inetSuggestions.value = [e.query]
  } else {
    const ret = []
    for (let i = 0; i < 32; i++) {
      ret.push(`${e.query}/${i}`)
    }
    inetSuggestions.value = ret
  }
}

const exitNodesSuggestions = ref([''])

function searchExitNodesSuggestions(e: { query: string }) {
  const ret = []
  ret.push(e.query)
  exitNodesSuggestions.value = ret
}

const whitelistSuggestions = ref([''])

function searchWhitelistSuggestions(e: { query: string }) {
  const ret = []
  ret.push(e.query)
  whitelistSuggestions.value = ret
}

interface BoolFlag {
  field: keyof NetworkConfig
  help: string
}

const bool_flags: BoolFlag[] = [
  { field: 'latency_first', help: 'latency_first_help' },
  { field: 'use_smoltcp', help: 'use_smoltcp_help' },
  { field: 'disable_ipv6', help: 'disable_ipv6_help' },
  { field: 'ipv6_public_addr_auto', help: 'ipv6_public_addr_auto_help' },
  { field: 'enable_kcp_proxy', help: 'enable_kcp_proxy_help' },
  { field: 'disable_kcp_input', help: 'disable_kcp_input_help' },
  { field: 'enable_quic_proxy', help: 'enable_quic_proxy_help' },
  { field: 'disable_quic_input', help: 'disable_quic_input_help' },
  { field: 'disable_p2p', help: 'disable_p2p_help' },
  { field: 'p2p_only', help: 'p2p_only_help' },
  { field: 'lazy_p2p', help: 'lazy_p2p_help' },
  { field: 'bind_device', help: 'bind_device_help' },
  { field: 'no_tun', help: 'no_tun_help' },
  { field: 'enable_exit_node', help: 'enable_exit_node_help' },
  { field: 'relay_all_peer_rpc', help: 'relay_all_peer_rpc_help' },
  { field: 'need_p2p', help: 'need_p2p_help' },
  { field: 'multi_thread', help: 'multi_thread_help' },
  { field: 'proxy_forward_by_system', help: 'proxy_forward_by_system_help' },
  { field: 'disable_encryption', help: 'disable_encryption_help' },
  { field: 'disable_tcp_hole_punching', help: 'disable_tcp_hole_punching_help' },
  { field: 'disable_udp_hole_punching', help: 'disable_udp_hole_punching_help' },
  { field: 'enable_udp_broadcast_relay', help: 'enable_udp_broadcast_relay_help' },
  { field: 'disable_upnp', help: 'disable_upnp_help' },
  { field: 'disable_sym_hole_punching', help: 'disable_sym_hole_punching_help' },
  { field: 'enable_magic_dns', help: 'enable_magic_dns_help' },
  { field: 'enable_private_mode', help: 'enable_private_mode_help' },
]

const portForwardProtocolOptions = ref(["tcp", "udp"]);

const editingPortForward = ref(false);
const editingPortForwardIndex = ref(-1);
const editingPortForwardData = ref();

function openPortForwardEditor(index: number) {
  editingPortForwardIndex.value = index;
  // deep copy
  editingPortForwardData.value = JSON.parse(JSON.stringify(curNetwork.value.port_forwards[index]));
  editingPortForward.value = true;
}

function addPortForward() {
  addRow(curNetwork.value.port_forwards)
  if (isCompact.value) {
    openPortForwardEditor(curNetwork.value.port_forwards.length - 1)
  }
}

function savePortForward() {
  curNetwork.value.port_forwards[editingPortForwardIndex.value] = editingPortForwardData.value;
  editingPortForward.value = false;
}

const portForwardContainer = ref<HTMLElement | null>(null);
const isCompact = ref(false);


onMounted(() => {
  if (portForwardContainer.value) {
    let resizeObserver = new ResizeObserver(entries => {
      for (const entry of entries) {
        isCompact.value = entry.contentRect.width < 540;
      }
    });
    resizeObserver.observe(portForwardContainer.value);

    onUnmounted(() => {
      if (resizeObserver && portForwardContainer.value) {
        resizeObserver.unobserve(portForwardContainer.value);
      }
    });
  }
});

// ---------------------------------------------------------------------------
// DNS：dns_mode / dns_servers / disable_exit_dns
// 表单只在用户真正改动时才写回这些字段，因此其它字段的往返（round-trip）不受影响。
// DNS: dns_mode / dns_servers / disable_exit_dns.
// The form only writes these fields back once the user actually changes them, so the
// round-trip of every other field stays untouched.
// ---------------------------------------------------------------------------

const dnsModeOptions = computed(() => [
  { label: t('dns_mode_auto'), value: DNS_MODE_AUTO },
  { label: t('dns_mode_custom'), value: DNS_MODE_CUSTOM },
  { label: t('dns_mode_exit_node'), value: DNS_MODE_EXIT_NODE },
])

/** undefined / 空字符串都显示为“默认”（auto）。 / undefined / "" are shown as "Default" (auto). */
const dnsMode = computed({
  get: () => getDnsMode(curNetwork.value),
  set: (value: string) => {
    curNetwork.value.dns_mode = value
  },
})

/** 逗号分隔文本 ⇄ dns_servers 数组，自动过滤空项。 */
/** Comma-separated text ⇄ dns_servers array; empty entries are filtered out. */
// 用一份“草稿文本”做双向绑定：如果直接把 dns_servers 数组渲染回输入框，
// 每敲一个字符都会被重新格式化（例如刚输入的逗号会立刻消失），导致无法输入第二项。
// A separate draft string keeps typing usable: rendering the parsed array straight back
// into the input would re-format on every keystroke and swallow the comma being typed.
const dnsServersDraft = ref('')

const dnsServersText = computed({
  get: () => dnsServersDraft.value,
  set: (value: string) => {
    dnsServersDraft.value = value
    curNetwork.value.dns_servers = parseDnsServersText(value)
  },
})

// 配置对象被外部替换（读取已有配置 / 导入 TOML / 切换实例）时重新同步输入框。
// Re-sync the text box whenever the config object is replaced from the outside
// (loading an existing config, importing TOML, switching instances).
watch(() => curNetwork.value, (network) => {
  dnsServersDraft.value = formatDnsServersText(network?.dns_servers)
}, { immediate: true })

/** 正向语义：勾选 = 出口节点提供隧道内 DNS 服务 = disable_exit_dns 取反。 */
/** Positive semantics: checked = exit node serves in-tunnel DNS = disable_exit_dns negated. */
const provideTunnelDns = computed({
  get: () => !(curNetwork.value?.disable_exit_dns ?? false),
  set: (value: boolean) => {
    curNetwork.value.disable_exit_dns = !value
  },
})

/** 当前模式的说明文案；用显式分支而不是拼接 i18n key，避免 key 写错。 */
/** Help text of the selected mode; explicit branches instead of a computed i18n key. */
const dnsModeHelp = computed(() => {
  switch (dnsMode.value) {
    case DNS_MODE_CUSTOM:
      return t('dns_mode_custom_help')
    case DNS_MODE_EXIT_NODE:
      return t('dns_mode_exit_node_help')
    default:
      return t('dns_mode_auto_help')
  }
})

// ---------------------------------------------------------------------------
// WG 混淆（抗 DPI）：wg_obfs + 7 个参数
// 表单只在用户真正改动时才写回字段；输入框被清空 = 删除该字段（写 undefined），
// 让后端回落到内置默认值，绝不写 0（0 表示“显式关闭该项填充”，是另一种含义）。
// WG obfuscation (anti-DPI): wg_obfs + the 7 parameters.
// The form only writes a field back once the user actually changes it; an emptied input removes
// the field (undefined) so the backend falls back to its built-in default, and never writes 0
// (0 means "explicitly disable that padding", which is a different meaning).
// ---------------------------------------------------------------------------

/** 总开关：未设置按关闭处理。 / Master switch; unset counts as off. */
const wgObfsEnabled = computed({
  get: () => !!curNetwork.value?.wg_obfs,
  set: (value: boolean) => {
    if (!curNetwork.value) {
      return
    }
    curNetwork.value.wg_obfs = !!value
  },
})

/** 参数输入框的占位文本 = 内置默认值。 / Placeholder text of a parameter input = built-in default. */
function wgObfsPlaceholder(field: WgObfsField): string {
  return String(WG_OBFS_DEFAULTS[field].default)
}

/**
 * 写回单个参数：先按范围钳制；留空 / 非法输入（钳制结果为 undefined）则删除字段，
 * 使后端使用内置默认值；显式输入的 0 会被保留。
 * Write one parameter back: clamp it to its range first; empty / invalid input (clamped to
 * undefined) removes the field so the backend uses its built-in default; an explicit 0 is kept.
 */
function setWgObfsParam(field: WgObfsField, value: number | null): void {
  const network = curNetwork.value
  if (!network) {
    return
  }

  // 通过 Partial<Record<...>> 视图删除可选字段：用 delete 而不是写 undefined，
  // 这样配置对象里不会残留值为 undefined 的键（JSON / TOML 序列化时更干净）。
  // A Partial<Record<...>> view lets us delete optional fields; using delete instead of
  // assigning undefined keeps the config object free of undefined-valued keys.
  const params = network as unknown as Partial<Record<WgObfsField, number>>

  const clamped = clampWgObfsValue(field, value)
  if (clamped === undefined) {
    delete params[field]
    return
  }
  params[field] = clamped
}

/** 单个参数的双向绑定：读配置（未设置显示为空），写回时钳制 / 删除。 */
/** Two-way binding of one parameter: read the config (unset renders empty), clamp/remove on write. */
function wgObfsParam(field: WgObfsField) {
  return computed<number | null>({
    get: () => curNetwork.value?.[field] ?? null,
    set: (value: number | null) => setWgObfsParam(field, value),
  })
}

const wgObfsS1 = wgObfsParam('wg_obfs_s1')
const wgObfsS2 = wgObfsParam('wg_obfs_s2')
const wgObfsS3 = wgObfsParam('wg_obfs_s3')
const wgObfsS4 = wgObfsParam('wg_obfs_s4')
const wgObfsJc = wgObfsParam('wg_obfs_jc')
const wgObfsJmin = wgObfsParam('wg_obfs_jmin')
const wgObfsJmax = wgObfsParam('wg_obfs_jmax')

/**
 * 落在 [Jmin,Jmax] 内的 junk 探针值（148+S1 / 92+S2 / 64+S3）；非空表示后端会关闭 junk 并告警。
 * Junk probe values inside [Jmin, Jmax]; a non-empty list means the backend disables junk padding.
 */
const wgObfsJunkConflicts = computed(() => wgObfsJunkProbeConflicts({
  s1: curNetwork.value?.wg_obfs_s1,
  s2: curNetwork.value?.wg_obfs_s2,
  s3: curNetwork.value?.wg_obfs_s3,
  jmin: curNetwork.value?.wg_obfs_jmin,
  jmax: curNetwork.value?.wg_obfs_jmax,
}))

function syncNormalizedNetwork(network: NetworkConfig | undefined): void {
  if (!network) {
    return
  }

  Object.assign(network, normalizeNetworkConfig(network))
}

watch(() => curNetwork.value, syncNormalizedNetwork, { immediate: true, deep: false })
</script>

<template>
  <div class="frontend-lib">
    <div class="flex flex-col h-full">
      <div class="flex flex-col">
        <div class="w-full self-center ">
          <Panel :header="t('basic_settings')">
            <div class="flex flex-col gap-y-2">
              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-5/12 grow">
                  <div class="flex items-center" for="virtual_ip">
                    <label class="mr-2"> {{ t('virtual_ipv4') }} </label>
                    <Checkbox v-model="curNetwork.dhcp" input-id="virtual_ip_auto" :binary="true" />

                    <label for="virtual_ip_auto" class="ml-2">
                      {{ t('virtual_ipv4_dhcp') }}
                    </label>
                  </div>
                  <InputGroup>
                    <InputText id="virtual_ip" v-model="curNetwork.virtual_ipv4" :disabled="curNetwork.dhcp"
                      aria-describedby="virtual_ipv4-help" />
                    <InputGroupAddon>
                      <span>/</span>
                    </InputGroupAddon>
                    <InputNumber v-model="curNetwork.network_length" :disabled="curNetwork.dhcp"
                      inputId="horizontal-buttons" showButtons :step="1" mode="decimal" :min="1" :max="32" fluid
                      class="max-w-20" />
                  </InputGroup>
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-5/12 grow">
                  <label for="network_name">{{ t('network_name') }}</label>
                  <InputText id="network_name" v-model="curNetwork.network_name" aria-describedby="network_name-help" />
                </div>
                <div class="flex flex-col gap-2 basis-5/12 grow">
                  <label for="network_secret">{{ t('network_secret') }}</label>
                  <Password id="network_secret" v-model="curNetwork.network_secret"
                    aria-describedby="network_secret-help" toggleMask :feedback="false" />
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-5/12 grow">
                  <div class="flex items-center">
                    <label for="initial_nodes">{{ t('initial_nodes') }}</label>
                    <span class="pi pi-question-circle ml-2 self-center" v-tooltip="t('initial_nodes_help')"></span>
                  </div>
                  <div class="items-center flex flex-col p-fluid gap-y-2">
                    <UrlListInput id="initial_nodes" v-model="curNetwork.peer_urls" :protos="protos"
                      defaultUrl="tcp://:11010" :add-label="t('add_initial_node')"
                      :placeholder="t('initial_node_placeholder')" />
                  </div>
                </div>
              </div>
            </div>
          </Panel>

          <Divider />

          <Panel :header="t('advanced_settings')" toggleable collapsed>
            <div class="flex flex-col gap-y-2">

              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-5/12 grow">
                  <label> {{ t('flags_switch') }} </label>
                  <div class="flex flex-row flex-wrap">

                    <div class="basis-[20rem] flex items-center" v-for="flag in bool_flags">
                      <Checkbox v-model="curNetwork[flag.field]" :input-id="flag.field" :binary="true" />
                      <label :for="flag.field" class="ml-2"> {{ t(flag.field) }} </label>
                      <span class="pi pi-question-circle ml-2 self-center" v-tooltip="t(flag.help)"></span>
                    </div>

                  </div>
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-5/12 grow">
                  <label for="hostname">{{ t('hostname') }}</label>
                  <InputText id="hostname" v-model="curNetwork.hostname" aria-describedby="hostname-help" :format="true"
                    :placeholder="t('hostname_placeholder', [props.hostname])" />
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap w-full">
                <div class="flex flex-col gap-2 grow p-fluid">
                  <label for="username">{{ t('proxy_cidrs') }}</label>
                  <AutoComplete id="subnet-proxy" v-model="curNetwork.proxy_cidrs"
                    :placeholder="t('chips_placeholder', ['10.0.0.0/24'])" class="w-full" multiple fluid
                    :suggestions="inetSuggestions" @complete="searchInetSuggestions" />
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap ">
                <div class="flex flex-col gap-2 grow">
                  <label for="username">VPN Portal</label>
                  <ToggleButton v-model="curNetwork.enable_vpn_portal" on-icon="pi pi-check" off-icon="pi pi-times"
                    :on-label="t('off_text')" :off-label="t('on_text')" class="w-48" />
                  <div v-if="curNetwork.enable_vpn_portal" class="items-center flex flex-row gap-x-4">
                    <div class="flex flex-row gap-x-9 flex-wrap w-full">
                      <div class="flex flex-col gap-2 basis-8/12 grow">
                        <InputGroup>
                          <InputText v-model="curNetwork.vpn_portal_client_network_addr"
                            :placeholder="t('vpn_portal_client_network')" />
                          <InputGroupAddon>
                            <span>/{{ curNetwork.vpn_portal_client_network_len }}</span>
                          </InputGroupAddon>
                        </InputGroup>
                      </div>
                      <div class="flex flex-col gap-2 basis-3/12 grow">
                        <InputNumber v-model="curNetwork.vpn_portal_listen_port" :allow-empty="false" :format="false"
                          :min="0" :max="65535" fluid />
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 grow p-fluid">
                  <label for="listener_urls">{{ t('listener_urls') }}</label>
                  <UrlListInput v-model="curNetwork.listener_urls" :protos="protos" :add-label="t('add_listener_url')"
                    placeholder="0.0.0.0" />
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-5/12 grow">
                  <label for="dev_name">{{ t('dev_name') }}</label>
                  <InputText id="dev_name" v-model="curNetwork.dev_name" aria-describedby="dev_name-help" :format="true"
                    :placeholder="t('dev_name_placeholder')" />
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-5/12 grow">
                  <div class="flex">
                    <label for="mtu">{{ t('mtu') }}</label>
                    <span class="pi pi-question-circle ml-2 self-center" v-tooltip="t('mtu_help')"></span>
                  </div>
                  <InputNumber id="mtu" v-model="curNetwork.mtu" aria-describedby="mtu-help" :format="false"
                    :placeholder="t('mtu_placeholder')" :min="400" :max="1380" fluid />
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-5/12 grow">
                  <div class="flex">
                    <label for="instance_recv_bps_limit">{{ t('instance_recv_bps_limit') }}</label>
                    <span class="pi pi-question-circle ml-2 self-center"
                      v-tooltip="t('instance_recv_bps_limit_help')"></span>
                  </div>
                  <InputNumber id="instance_recv_bps_limit" v-model="curNetwork.instance_recv_bps_limit"
                    aria-describedby="instance_recv_bps_limit-help" :format="false"
                    :placeholder="t('instance_recv_bps_limit_placeholder')" :min="1" fluid />
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-5/12 grow">
                  <div class="flex">
                    <label for="relay_network_whitelist">{{ t('relay_network_whitelist') }}</label>
                    <span class="pi pi-question-circle ml-2 self-center"
                      v-tooltip="t('relay_network_whitelist_help')"></span>
                  </div>
                  <ToggleButton v-model="curNetwork.enable_relay_network_whitelist" on-icon="pi pi-check"
                    off-icon="pi pi-times" :on-label="t('off_text')" :off-label="t('on_text')" class="w-48" />
                  <div v-if="curNetwork.enable_relay_network_whitelist" class="items-center flex flex-row gap-x-4">
                    <div class="min-w-64 w-full">
                      <AutoComplete id="relay_network_whitelist" v-model="curNetwork.relay_network_whitelist"
                        :placeholder="t('relay_network_whitelist')" class="w-full" multiple fluid
                        :suggestions="whitelistSuggestions" @complete="searchWhitelistSuggestions" />
                    </div>
                  </div>
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap ">
                <div class="flex flex-col gap-2 grow">
                  <div class="flex">
                    <label for="routes">{{ t('manual_routes') }}</label>
                    <span class="pi pi-question-circle ml-2 self-center" v-tooltip="t('manual_routes_help')"></span>
                  </div>
                  <ToggleButton v-model="curNetwork.enable_manual_routes" on-icon="pi pi-check" off-icon="pi pi-times"
                    :on-label="t('off_text')" :off-label="t('on_text')" class="w-48" />
                  <div v-if="curNetwork.enable_manual_routes" class="items-center flex flex-row gap-x-4">
                    <div class="min-w-64 w-full">
                      <AutoComplete id="routes" v-model="curNetwork.routes"
                        :placeholder="t('chips_placeholder', ['192.168.0.0/16'])" class="w-full" multiple fluid
                        :suggestions="inetSuggestions" @complete="searchInetSuggestions" />
                    </div>
                  </div>
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap ">
                <div class="flex flex-col gap-2 grow">
                  <div class="flex">
                    <label for="socks5_port">{{ t('socks5') }}</label>
                    <span class="pi pi-question-circle ml-2 self-center" v-tooltip="t('socks5_help')"></span>
                  </div>
                  <ToggleButton v-model="curNetwork.enable_socks5" on-icon="pi pi-check" off-icon="pi pi-times"
                    :on-label="t('off_text')" :off-label="t('on_text')" class="w-48" />
                  <div v-if="curNetwork.enable_socks5" class="items-center flex flex-row gap-x-4">
                    <div class="min-w-64 w-full">
                      <InputNumber id="socks5_port" v-model="curNetwork.socks5_port" aria-describedby="rpc_port-help"
                        :format="false" :allow-empty="false" :min="0" :max="65535" class="w-full" />
                    </div>
                  </div>
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap w-full">
                <div class="flex flex-col gap-2 grow p-fluid">
                  <div class="flex">
                    <label for="exit_nodes">{{ t('exit_nodes') }}</label>
                    <span class="pi pi-question-circle ml-2 self-center" v-tooltip="t('exit_nodes_help')"></span>
                  </div>
                  <AutoComplete id="exit_nodes" v-model="curNetwork.exit_nodes"
                    :placeholder="t('chips_placeholder', ['192.168.8.8'])" class="w-full" multiple fluid
                    :suggestions="exitNodesSuggestions" @complete="searchExitNodesSuggestions" />
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap w-full">
                <div class="flex flex-col gap-2 grow p-fluid">
                  <div class="flex">
                    <label for="mapped_listeners">{{ t('mapped_listeners') }}</label>
                    <span class="pi pi-question-circle ml-2 self-center" v-tooltip="t('mapped_listeners_help')"></span>
                  </div>
                  <UrlListInput v-model="curNetwork.mapped_listeners" :protos="protos"
                    :add-label="t('add_mapped_listener')" />
                </div>
              </div>

            </div>
          </Panel>

          <Divider />

          <Panel :header="t('dns_settings')" toggleable collapsed>
            <div class="flex flex-col gap-y-2">
              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-5/12 grow">
                  <div class="flex">
                    <label for="dns_mode">{{ t('dns_mode') }}</label>
                    <span class="pi pi-question-circle ml-2 self-center" v-tooltip="t('dns_mode_help')"></span>
                  </div>
                  <SelectButton id="dns_mode" v-model="dnsMode" :options="dnsModeOptions" option-label="label"
                    option-value="value" :allow-empty="false" />
                  <small class="p-text-secondary whitespace-pre-wrap">{{ dnsModeHelp }}</small>
                </div>
              </div>

              <div v-if="dnsMode === DNS_MODE_CUSTOM" class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-5/12 grow">
                  <div class="flex">
                    <label for="dns_servers">{{ t('dns_servers') }}</label>
                    <span class="pi pi-question-circle ml-2 self-center" v-tooltip="t('dns_servers_help')"></span>
                  </div>
                  <InputText id="dns_servers" v-model="dnsServersText" :placeholder="t('dns_servers_placeholder')"
                    aria-describedby="dns_servers-help" />
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-5/12 grow">
                  <div class="flex items-center">
                    <Checkbox v-model="provideTunnelDns" input-id="provide_tunnel_dns" :binary="true"
                      :disabled="!curNetwork.enable_exit_node" />
                    <label for="provide_tunnel_dns" class="ml-2"> {{ t('provide_tunnel_dns') }} </label>
                    <span class="pi pi-question-circle ml-2 self-center"
                      v-tooltip="t('provide_tunnel_dns_help')"></span>
                  </div>
                  <small v-if="!curNetwork.enable_exit_node" class="p-text-secondary">
                    {{ t('provide_tunnel_dns_only_exit_node') }}
                  </small>
                </div>
              </div>
            </div>
          </Panel>

          <Divider />

          <Panel :header="t('wg_obfs_settings')" toggleable collapsed>
            <div class="flex flex-col gap-y-2">
              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-5/12 grow">
                  <div class="flex items-center">
                    <Checkbox v-model="wgObfsEnabled" input-id="wg_obfs" :binary="true" />
                    <label for="wg_obfs" class="ml-2"> {{ t('wg_obfs') }} </label>
                    <span class="pi pi-question-circle ml-2 self-center" v-tooltip="t('wg_obfs_help')"></span>
                  </div>
                  <!-- 醒目提示：两端参数必须一致，且不再兼容旧节点 / 公网服务器。
                       Always visible inside the panel, not gated on the checkbox, so the user
                       reads the incompatibility warning before enabling obfuscation. -->
                  <small class="text-red-500 font-semibold whitespace-pre-wrap">
                    <i class="pi pi-exclamation-triangle mr-1"></i>{{ t('wg_obfs_incompatible_warning') }}
                  </small>
                </div>
              </div>

              <!-- 未勾选总开关时不显示 7 个参数输入框（未设置 = 使用内置默认值）。 -->
              <!-- The 7 parameter inputs are hidden while the master switch is off. -->
              <div v-if="wgObfsEnabled" class="flex flex-col gap-y-2">
                <div class="flex flex-row gap-x-9 flex-wrap">
                  <div class="flex flex-col gap-2 basis-5/12 grow">
                    <label for="wg_obfs_s1">{{ t('wg_obfs_s1') }}</label>
                    <InputNumber id="wg_obfs_s1" v-model="wgObfsS1" :allow-empty="true"
                      :placeholder="wgObfsPlaceholder('wg_obfs_s1')" :format="false"
                      :min="WG_OBFS_DEFAULTS.wg_obfs_s1.min" :max="WG_OBFS_DEFAULTS.wg_obfs_s1.max" fluid />
                  </div>
                  <div class="flex flex-col gap-2 basis-5/12 grow">
                    <label for="wg_obfs_s2">{{ t('wg_obfs_s2') }}</label>
                    <InputNumber id="wg_obfs_s2" v-model="wgObfsS2" :allow-empty="true"
                      :placeholder="wgObfsPlaceholder('wg_obfs_s2')" :format="false"
                      :min="WG_OBFS_DEFAULTS.wg_obfs_s2.min" :max="WG_OBFS_DEFAULTS.wg_obfs_s2.max" fluid />
                  </div>
                  <div class="flex flex-col gap-2 basis-5/12 grow">
                    <label for="wg_obfs_s3">{{ t('wg_obfs_s3') }}</label>
                    <InputNumber id="wg_obfs_s3" v-model="wgObfsS3" :allow-empty="true"
                      :placeholder="wgObfsPlaceholder('wg_obfs_s3')" :format="false"
                      :min="WG_OBFS_DEFAULTS.wg_obfs_s3.min" :max="WG_OBFS_DEFAULTS.wg_obfs_s3.max" fluid />
                  </div>
                  <div class="flex flex-col gap-2 basis-5/12 grow">
                    <label for="wg_obfs_s4">{{ t('wg_obfs_s4') }}</label>
                    <InputNumber id="wg_obfs_s4" v-model="wgObfsS4" :allow-empty="true"
                      :placeholder="wgObfsPlaceholder('wg_obfs_s4')" :format="false"
                      :min="WG_OBFS_DEFAULTS.wg_obfs_s4.min" :max="WG_OBFS_DEFAULTS.wg_obfs_s4.max" fluid />
                  </div>
                  <div class="flex flex-col gap-2 basis-5/12 grow">
                    <label for="wg_obfs_jc">{{ t('wg_obfs_jc') }}</label>
                    <InputNumber id="wg_obfs_jc" v-model="wgObfsJc" :allow-empty="true"
                      :placeholder="wgObfsPlaceholder('wg_obfs_jc')" :format="false"
                      :min="WG_OBFS_DEFAULTS.wg_obfs_jc.min" :max="WG_OBFS_DEFAULTS.wg_obfs_jc.max" fluid />
                  </div>
                  <div class="flex flex-col gap-2 basis-5/12 grow">
                    <label for="wg_obfs_jmin">{{ t('wg_obfs_jmin') }}</label>
                    <InputNumber id="wg_obfs_jmin" v-model="wgObfsJmin" :allow-empty="true"
                      :placeholder="wgObfsPlaceholder('wg_obfs_jmin')" :format="false"
                      :min="WG_OBFS_DEFAULTS.wg_obfs_jmin.min" :max="WG_OBFS_DEFAULTS.wg_obfs_jmin.max" fluid />
                  </div>
                  <div class="flex flex-col gap-2 basis-5/12 grow">
                    <label for="wg_obfs_jmax">{{ t('wg_obfs_jmax') }}</label>
                    <InputNumber id="wg_obfs_jmax" v-model="wgObfsJmax" :allow-empty="true"
                      :placeholder="wgObfsPlaceholder('wg_obfs_jmax')" :format="false"
                      :min="WG_OBFS_DEFAULTS.wg_obfs_jmax.min" :max="WG_OBFS_DEFAULTS.wg_obfs_jmax.max" fluid />
                  </div>
                </div>

                <small class="p-text-secondary whitespace-pre-wrap">{{ t('wg_obfs_params_help') }}</small>
                <!-- 动态检测 junk 区间与 148+S1 / 92+S2 / 64+S3 的重合。 -->
                <!-- Dynamic check: does [Jmin,Jmax] contain 148+S1 / 92+S2 / 64+S3? -->
                <small v-if="wgObfsJunkConflicts.length > 0" class="text-red-500 font-semibold whitespace-pre-wrap">
                  <i class="pi pi-exclamation-triangle mr-1"></i>{{ t('wg_obfs_junk_conflict_warning',
                    [wgObfsJunkConflicts.join(', ')]) }}
                </small>
              </div>
            </div>
          </Panel>

          <Divider />

          <Panel :header="t('port_forwards')" toggleable collapsed>
            <div ref="portForwardContainer" class="flex flex-col gap-y-2">
              <div class="flex flex-row gap-x-9 flex-wrap w-full">
                <div class="flex flex-col gap-2 grow p-fluid">
                  <div class="flex">
                    <label for="port_forwards">{{ t('port_forwards_help') }}</label>
                  </div>
                  <div v-for="(row, index) in curNetwork.port_forwards" :key="index" class="form-row">
                    <!-- Wide screen view -->
                    <div v-if="!isCompact" class="flex gap-2 items-end">
                      <SelectButton v-model="row.proto" :options="portForwardProtocolOptions" :allow-empty="false" />
                      <div style="flex-grow: 4;">
                        <InputGroup>
                          <InputText v-model="row.bind_ip" :placeholder="t('port_forwards_bind_addr')" />
                          <InputGroupAddon>
                            <span style="font-weight: bold">:</span>
                          </InputGroupAddon>
                          <InputNumber v-model="row.bind_port" :format="false" inputId="horizontal-buttons" :step="1"
                            mode="decimal" :min="1" :max="65535" fluid class="max-w-20" />
                        </InputGroup>
                      </div>
                      <div style="flex-grow: 4;">
                        <InputGroup>
                          <InputText v-model="row.dst_ip" :placeholder="t('port_forwards_dst_addr')" />
                          <InputGroupAddon>
                            <span style="font-weight: bold">:</span>
                          </InputGroupAddon>
                          <InputNumber v-model="row.dst_port" :format="false" inputId="horizontal-buttons" :step="1"
                            mode="decimal" :min="1" :max="65535" fluid class="max-w-20" />
                        </InputGroup>
                      </div>
                      <div style="flex-grow: 1;">
                        <Button v-if="curNetwork.port_forwards.length > 0" icon="pi pi-trash" severity="danger" text
                          rounded @click="removeRow(index, curNetwork.port_forwards)" />
                      </div>
                    </div>
                    <!-- Small screen view -->
                    <div v-else class="flex justify-between items-center p-2 border-b">
                      <span>{{ row.proto }}://{{ row.bind_ip }}:{{ row.bind_port }}/{{ row.dst_ip }}:{{
                        row.dst_port }}</span>
                      <div class="flex gap-2">
                        <Button icon="pi pi-pencil" class="p-button-sm" @click="openPortForwardEditor(index)" />
                        <Button icon="pi pi-trash" class="p-button-sm p-button-danger"
                          @click="removeRow(index, curNetwork.port_forwards)" />
                      </div>
                    </div>
                  </div>

                  <div class="flex justify-content-end mt-4">
                    <Button icon="pi pi-plus" :label="t('port_forwards_add_btn')" severity="success"
                      @click="addPortForward" />
                  </div>

                  <Dialog v-model:visible="editingPortForward" modal :header="t('edit_port_forward')"
                    :style="{ width: '90vw', maxWidth: '600px' }">
                    <div v-if="editingPortForwardData" class="flex flex-col gap-4">
                      <SelectButton v-model="editingPortForwardData.proto" :options="portForwardProtocolOptions"
                        :allow-empty="false" />
                      <InputGroup>
                        <InputText v-model="editingPortForwardData.bind_ip"
                          :placeholder="t('port_forwards_bind_addr')" />
                        <InputGroupAddon>
                          <span style="font-weight: bold">:</span>
                        </InputGroupAddon>
                        <InputNumber v-model="editingPortForwardData.bind_port" :format="false" :step="1" mode="decimal"
                          :min="1" :max="65535" class="max-w-20" />
                      </InputGroup>
                      <InputGroup>
                        <InputText v-model="editingPortForwardData.dst_ip" :placeholder="t('port_forwards_dst_addr')" />
                        <InputGroupAddon>
                          <span style="font-weight: bold">:</span>
                        </InputGroupAddon>
                        <InputNumber v-model="editingPortForwardData.dst_port" :format="false" :step="1" mode="decimal"
                          :min="1" :max="65535" class="max-w-20" />
                      </InputGroup>
                    </div>
                    <template #footer>
                      <Button :label="t('web.common.cancel')" icon="pi pi-times" @click="editingPortForward = false"
                        text />
                      <Button :label="t('web.common.save')" icon="pi pi-save" @click="savePortForward" />
                    </template>
                  </Dialog>
                </div>
              </div>
            </div>
          </Panel>

          <Divider />

          <Panel :header="t('acl.title')" toggleable collapsed>
            <div v-if="curNetwork.acl" class="flex flex-col gap-y-2">
              <AclManager v-model="curNetwork.acl" />
            </div>
            <div v-else class="flex justify-center p-4">
              <Button :label="t('acl.enabled')"
                @click="curNetwork.acl = { acl_v1: { chains: [], group: { declares: [], members: [] } } }" />
            </div>
          </Panel>

          <div class="flex pt-6 justify-center">
            <Button :label="t('run_network')" icon="pi pi-arrow-right" icon-pos="right" :disabled="configInvalid"
              @click="$emit('runNetwork', curNetwork)" />
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
