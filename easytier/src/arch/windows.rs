use std::{
    collections::HashSet,
    io,
    mem::ManuallyDrop,
    net::SocketAddr,
    os::windows::io::AsRawSocket,
    sync::{Arc, LazyLock, Mutex, Weak},
};

use anyhow::Context;
use network_interface::NetworkInterfaceConfig;
use windows::{
    Win32::{
        Foundation::FALSE,
        NetworkManagement::WindowsFirewall::{
            INetFwPolicy2, INetFwRule, NET_FW_ACTION_ALLOW, NET_FW_PROFILE2_DOMAIN,
            NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC, NET_FW_RULE_DIR_IN,
            NET_FW_RULE_DIR_OUT,
        },
        Networking::WinSock::{
            IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, SIO_UDP_CONNRESET, SOCKET,
            SOCKET_ERROR, WSAGetLastError, WSAIoctl, htonl, setsockopt,
        },
        System::Com::{
            CLSCTX_ALL, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
        },
        System::Ole::{SafeArrayCreateVector, SafeArrayPutElement},
        System::Variant::{VARENUM, VARIANT, VT_ARRAY, VT_BSTR, VT_VARIANT},
    },
    core::{BOOL, BSTR},
};

use crate::common::global_ctx::{ArcGlobalCtx, GlobalCtx};

pub fn disable_connection_reset<S: AsRawSocket>(socket: &S) -> io::Result<()> {
    let handle = SOCKET(socket.as_raw_socket() as usize);

    unsafe {
        // Ignoring UdpSocket's WSAECONNRESET error
        // https://github.com/shadowsocks/shadowsocks-rust/issues/179
        // https://stackoverflow.com/questions/30749423/is-winsock-error-10054-wsaeconnreset-normal-with-udp-to-from-localhost
        //
        // This is because `UdpSocket::recv_from` may return WSAECONNRESET
        // if you called `UdpSocket::send_to` a destination that is not existed (may be closed).
        //
        // It is not an error. Could be ignored completely.
        // We have to ignore it here because it will crash the server.

        let mut bytes_returned: u32 = 0;
        let enable: BOOL = FALSE;

        let ret = WSAIoctl(
            handle,
            SIO_UDP_CONNRESET,
            Some(&enable as *const _ as *const std::ffi::c_void),
            std::mem::size_of_val(&enable) as u32,
            None,
            0,
            &mut bytes_returned as *mut _,
            None,
            None,
        );

        if ret == SOCKET_ERROR {
            let err_code = WSAGetLastError();
            return Err(std::io::Error::from_raw_os_error(err_code.0));
        }
    }

    Ok(())
}

pub fn interface_count() -> io::Result<usize> {
    let ifaces = network_interface::NetworkInterface::show().map_err(|e| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("Failed to get interfaces. error: {}", e),
        )
    })?;
    Ok(ifaces.len())
}

pub fn find_interface_index(iface_name: &str) -> io::Result<u32> {
    let ifaces = network_interface::NetworkInterface::show().map_err(|e| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("Failed to get interfaces. {}, error: {}", iface_name, e),
        )
    })?;
    if let Some(iface) = ifaces.iter().find(|iface| iface.name == iface_name) {
        return Ok(iface.index);
    }
    tracing::error!("Failed to find interface index for {}", iface_name);
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        iface_name.to_string(),
    ))
}

pub fn set_ip_unicast_if(socket: SOCKET, addr: &SocketAddr, iface: &str) -> io::Result<()> {
    let if_index = find_interface_index(iface)?;

    unsafe {
        // https://docs.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
        let ret = match addr {
            SocketAddr::V4(..) => {
                let if_index = htonl(if_index);
                let if_index_bytes = if_index.to_ne_bytes();
                setsockopt(socket, IPPROTO_IP.0, IP_UNICAST_IF, Some(&if_index_bytes))
            }
            SocketAddr::V6(..) => {
                let if_index_bytes = if_index.to_ne_bytes();
                setsockopt(
                    socket,
                    IPPROTO_IPV6.0,
                    IPV6_UNICAST_IF,
                    Some(&if_index_bytes),
                )
            }
        };

        if ret == SOCKET_ERROR {
            let err = std::io::Error::from_raw_os_error(WSAGetLastError().0);
            tracing::error!(
                "set IP_UNICAST_IF / IPV6_UNICAST_IF interface: {}, index: {}, error: {}",
                iface,
                if_index,
                err
            );
            return Err(err);
        }
    }

    Ok(())
}

pub fn setup_socket_for_win<S: AsRawSocket>(
    socket: &S,
    bind_addr: &SocketAddr,
    bind_dev: Option<String>,
    is_udp: bool,
) -> io::Result<()> {
    if is_udp {
        disable_connection_reset(socket)?;
    }

    let socket = SOCKET(socket.as_raw_socket() as usize);

    // let optval = 1_i32.to_ne_bytes();
    // unsafe {
    //     if setsockopt(socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, Some(&optval)) == SOCKET_ERROR {
    //         return Err(io::Error::last_os_error());
    //     }
    // }

    if let Some(iface) = bind_dev {
        set_ip_unicast_if(socket, bind_addr, &iface)?;
    }

    Ok(())
}

struct ComInitializer;

impl ComInitializer {
    fn new() -> windows::core::Result<Self> {
        unsafe { CoInitializeEx(None, COINIT_MULTITHREADED).ok()? };
        Ok(Self)
    }
}

impl Drop for ComInitializer {
    fn drop(&mut self) {
        unsafe {
            CoUninitialize();
        }
    }
}

pub fn do_add_self_to_firewall_allowlist(inbound: bool) -> anyhow::Result<()> {
    let _com = ComInitializer::new()?;
    // Create firewall policy instance
    let policy: INetFwPolicy2 = unsafe {
        CoCreateInstance(
            &windows::Win32::NetworkManagement::WindowsFirewall::NetFwPolicy2,
            None,
            CLSCTX_ALL,
        )
    }?;

    // Create firewall rule instance
    let rule: INetFwRule = unsafe {
        CoCreateInstance(
            &windows::Win32::NetworkManagement::WindowsFirewall::NetFwRule,
            None,
            CLSCTX_ALL,
        )
    }?;

    // Set rule properties
    let exe_path = std::env::current_exe()
        .with_context(|| "Failed to get current executable path when adding firewall rule")?
        .to_string_lossy()
        .replace(r"\\?\", "");

    let name = BSTR::from(format!(
        "EasyTier {} ({})",
        exe_path,
        if inbound { "Inbound" } else { "Outbound" }
    ));
    let desc = BSTR::from("Allow EasyTier to do subnet proxy and kcp proxy");
    let app_path = BSTR::from(&exe_path);

    unsafe {
        rule.SetName(&name)?;
        rule.SetDescription(&desc)?;
        rule.SetApplicationName(&app_path)?;
        rule.SetAction(NET_FW_ACTION_ALLOW)?;
        if inbound {
            rule.SetDirection(NET_FW_RULE_DIR_IN)?; // Allow inbound connections
        } else {
            rule.SetDirection(NET_FW_RULE_DIR_OUT)?; // Allow outbound connections
        }
        rule.SetEnabled(windows::Win32::Foundation::VARIANT_TRUE)?;
        rule.SetProfiles(
            NET_FW_PROFILE2_PRIVATE.0 | NET_FW_PROFILE2_PUBLIC.0 | NET_FW_PROFILE2_DOMAIN.0,
        )?;
        rule.SetGrouping(&BSTR::from("EasyTier"))?;

        // Get rule collection and add new rule
        let rules = policy.Rules()?;
        rules.Remove(&name)?; // Remove existing rule with same name first
        rules.Add(&rule)?;
    }

    Ok(())
}

/// 添加本进程的程序级入站/出站防火墙放行规则（原有行为）。
///
/// 注意：程序规则对运行在 Windows Session 0 服务会话中的进程无法放行 UDP 入站，
/// 所以出口节点还需要端口级规则（见 [`add_exit_node_firewall_rules`]）。
/// 端口规则依赖实例配置，通过 [`register_firewall_global_ctx`] 注册的上下文推导，
/// 或直接调用 [`add_self_to_firewall_allowlist_with_ctx`]。
pub fn add_self_to_firewall_allowlist() -> anyhow::Result<()> {
    // 端口级规则优先创建：本调用不会失败，且不应受下面程序规则失败的影响
    add_registered_exit_node_firewall_rules();

    do_add_self_to_firewall_allowlist(true)?;
    do_add_self_to_firewall_allowlist(false)?;
    Ok(())
}

/// 在原有程序规则的基础上，为出口节点补充端口级入站放行规则。
///
/// 与 [`add_self_to_firewall_allowlist`] 相比，这里直接使用调用方提供的实例上下文，
/// 语义更精确（同一进程可能运行多个实例），推荐在实例启动路径上调用。
#[allow(dead_code)] // 供实例启动路径调用（例如 instance/virtual_nic.rs 创建 TUN 时）
pub fn add_self_to_firewall_allowlist_with_ctx(global_ctx: &GlobalCtx) -> anyhow::Result<()> {
    // 端口规则内部已消化所有失败，不会中断启动流程
    add_exit_node_firewall_rules(global_ctx);

    do_add_self_to_firewall_allowlist(true)?;
    do_add_self_to_firewall_allowlist(false)?;
    Ok(())
}

/// 默认控制端口：与 `IpScheme::Tcp/Udp` 的默认端口保持一致（11010）。
const DEFAULT_CTRL_PORT: u16 = crate::tunnel::IpScheme::Tcp.default_port();

/// 默认 wireguard 隧道监听端口：与 `IpScheme::Wg` 的默认端口保持一致（11011）。
#[cfg(feature = "wireguard")]
const DEFAULT_WG_PORT: u16 = crate::tunnel::IpScheme::Wg.default_port();
#[cfg(not(feature = "wireguard"))]
const DEFAULT_WG_PORT: u16 = 11011;

/// 规则名中 wireguard 数据端口使用的固定标识。
const WG_RULE_KIND: &str = "wg";
/// 规则名中控制端口（tcp/udp 隧道）使用的固定标识。
const CTRL_RULE_KIND: &str = "ctrl";

/// `CREATE_NO_WINDOW`：隐藏 netsh 子进程的控制台窗口，避免弹出黑框。
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// 一条端口级入站规则：`(是否 UDP, 端口, 规则类别)`，
/// 类别取 [`WG_RULE_KIND`] 或 [`CTRL_RULE_KIND`]。
type PortFirewallRule = (bool, u16, &'static str);

/// 为出口节点创建端口级入站放行规则，保证客户端能直连控制端口与 wireguard 数据端口。
///
/// - 仅当本节点是出口节点（[`GlobalCtx::enable_exit_node`]）时创建，纯客户端保持原有程序规则行为；
/// - 端口从本实例配置推导，见 [`collect_exit_node_port_rules`]；
/// - 所有失败只记日志，不会让启动流程失败；可重复调用（同名规则先删后建，幂等）。
pub fn add_exit_node_firewall_rules(global_ctx: &GlobalCtx) {
    if !global_ctx.enable_exit_node() {
        tracing::debug!("本节点不是出口节点，跳过端口级防火墙规则");
        return;
    }

    let instance_tag = firewall_rule_instance_tag(global_ctx);
    let port_rules = collect_exit_node_port_rules(&global_ctx.config.get_listener_uris());
    tracing::debug!(
        "出口节点端口级防火墙规则: instance={}, rules={:?}",
        instance_tag,
        port_rules
    );

    for (is_udp, port, kind) in port_rules {
        // 规则名固定为 EasyTier-<实例标识>-<wg|ctrl>-<udp|tcp>，同一协议+端口只会有一条规则
        let rule_name = format!(
            "EasyTier-{}-{}-{}",
            instance_tag,
            kind,
            if is_udp { "udp" } else { "tcp" }
        );
        add_inbound_port_firewall_rule(&rule_name, is_udp, port);
    }
}

/// 进程内已启动实例的上下文（弱引用）。
/// 供无参入口 [`add_self_to_firewall_allowlist`] 推导「哪些实例是出口节点、要放行哪些端口」。
static REGISTERED_GLOBAL_CTXS: LazyLock<Mutex<Vec<Weak<GlobalCtx>>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

/// 注册实例上下文，让无参的 [`add_self_to_firewall_allowlist`] 能创建出口节点端口级规则。
///
/// 在实例启动路径上调用一次即可；若不方便改造原有调用点，
/// 也可以直接改用 [`add_self_to_firewall_allowlist_with_ctx`] 传入上下文。
/// 这里保存弱引用，实例退出后不会阻止其释放。
#[allow(dead_code)] // 待实例启动路径调用，见函数文档
pub fn register_firewall_global_ctx(global_ctx: &ArcGlobalCtx) {
    let mut ctxs = REGISTERED_GLOBAL_CTXS.lock().unwrap();
    // 清理已退出实例，避免列表无限增长；同一实例只保留一份
    ctxs.retain(|weak| weak.strong_count() > 0);
    let new_weak = Arc::downgrade(global_ctx);
    if !ctxs.iter().any(|weak| weak.ptr_eq(&new_weak)) {
        ctxs.push(new_weak);
    }
}

/// 为所有已注册的出口节点实例创建端口级入站规则；没有已注册实例时什么都不做。
fn add_registered_exit_node_firewall_rules() {
    let ctxs: Vec<ArcGlobalCtx> = {
        let mut guard = REGISTERED_GLOBAL_CTXS.lock().unwrap();
        guard.retain(|weak| weak.strong_count() > 0);
        guard.iter().filter_map(|weak| weak.upgrade()).collect()
    };

    if ctxs.is_empty() {
        tracing::debug!("没有已注册的实例上下文，跳过端口级防火墙规则");
        return;
    }

    for global_ctx in ctxs {
        add_exit_node_firewall_rules(&global_ctx);
    }
}

/// 从监听配置推导出口节点需要放行的入站端口（按 协议+端口 去重）。
///
/// - wireguard 数据端口：取监听配置中 `wg://` 的端口，缺省 [`DEFAULT_WG_PORT`]（11011/UDP）；
/// - 控制端口：取监听配置中 `tcp://` / `udp://` 的端口，缺省 [`DEFAULT_CTRL_PORT`]（11010）；
/// - 配置里没有对应协议的监听端口时退化为默认端口，保证客户端至少能连上控制面与 wg 数据面；
/// - 其它协议（ws/quic/faketcp 等）不在此处放行，避免放行需求之外的端口。
fn collect_exit_node_port_rules(listener_uris: &[url::Url]) -> Vec<PortFirewallRule> {
    let mut rules: Vec<PortFirewallRule> = Vec::new();
    let mut seen: HashSet<(bool, u16)> = HashSet::new();
    let mut has_wg = false;
    let mut has_ctrl = false;

    for uri in listener_uris {
        let Some((is_udp, port, kind)) = listener_url_to_port_rule(uri) else {
            continue;
        };
        if kind == WG_RULE_KIND {
            has_wg = true;
        } else {
            has_ctrl = true;
        }
        // 同一协议 + 端口只保留一条规则
        if seen.insert((is_udp, port)) {
            rules.push((is_udp, port, kind));
        }
    }

    // 配置里没有对应协议的监听端口时，退化为默认端口
    for (is_udp, port, kind) in [
        (true, DEFAULT_WG_PORT, WG_RULE_KIND),
        (true, DEFAULT_CTRL_PORT, CTRL_RULE_KIND),
        (false, DEFAULT_CTRL_PORT, CTRL_RULE_KIND),
    ] {
        // 配置里已有该协议的监听端口时，不需要再补默认端口
        if kind == WG_RULE_KIND && has_wg {
            continue;
        }
        if kind != WG_RULE_KIND && has_ctrl {
            continue;
        }
        if seen.insert((is_udp, port)) {
            rules.push((is_udp, port, kind));
        }
    }

    rules
}

/// 把单条监听 URL 转换成端口规则，只识别 `tcp://` / `udp://`（控制面）与 `wg://`（数据面）。
/// 监听 URL 允许省略端口，此时使用该协议的默认端口。
fn listener_url_to_port_rule(uri: &url::Url) -> Option<PortFirewallRule> {
    let scheme = uri.scheme().to_ascii_lowercase();
    let (is_udp, kind, default_port) = match scheme.as_str() {
        "tcp" => (false, CTRL_RULE_KIND, DEFAULT_CTRL_PORT),
        "udp" => (true, CTRL_RULE_KIND, DEFAULT_CTRL_PORT),
        "wg" => (true, WG_RULE_KIND, DEFAULT_WG_PORT),
        _ => return None,
    };
    Some((is_udp, uri.port().unwrap_or(default_port), kind))
}

/// 规则名中的实例标识：优先使用实例 UUID（去掉横线），拿不到时退化为网络名。
/// 同一实例多次启动时该标识保持稳定，配合「先删后建」即可保证幂等。
fn firewall_rule_instance_tag(global_ctx: &GlobalCtx) -> String {
    let id = global_ctx.get_id().to_string().replace('-', "");
    if !id.is_empty() {
        return id;
    }

    let network_name = sanitize_rule_name_component(&global_ctx.get_network_name());
    if network_name.is_empty() {
        "default".to_string()
    } else {
        network_name
    }
}

/// 只保留可安全出现在 netsh 规则名中的字符，并限制长度。
fn sanitize_rule_name_component(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(*c, '-' | '_' | '.'))
        .take(32)
        .collect()
}

/// 用 `netsh advfirewall firewall` 创建一条入站放行规则（同名规则先删后建）。
///
/// 这里刻意不使用本文件已有的 COM（`INetFwRule`）实现：实测表明 Session 0 服务会话下，
/// 基于 `SetApplicationName` 的程序规则对 UDP 入站无效，而端口级 netsh 规则可靠；
/// netsh 同时省去了为端口范围拼装 SAFEARRAY 的复杂度。
/// 所有失败只记日志，不会让调用方（实例启动流程）失败。
fn add_inbound_port_firewall_rule(rule_name: &str, is_udp: bool, port: u16) {
    let protocol = if is_udp { "UDP" } else { "TCP" };
    let name_arg = format!("name={}", rule_name);
    let protocol_arg = format!("protocol={}", protocol);
    let port_arg = format!("localport={}", port);

    // 先删除同名旧规则再创建：实例重启会重复调用本函数，避免规则堆积；
    // 首次创建时规则并不存在，删除失败属正常情况，不计为错误。
    match run_netsh_firewall(&[
        "advfirewall",
        "firewall",
        "delete",
        "rule",
        name_arg.as_str(),
    ]) {
        Ok(output) if output.status.success() => {
            tracing::debug!("已删除同名旧防火墙规则: {}", rule_name);
        }
        Ok(output) => {
            tracing::debug!(
                "未删除旧防火墙规则（首次创建时属正常）: {}, netsh 输出: {}",
                rule_name,
                summarize_netsh_output(&output)
            );
        }
        Err(err) => {
            tracing::debug!("删除旧防火墙规则失败（忽略）: {}, {}", rule_name, err);
        }
    }

    let args = [
        "advfirewall",
        "firewall",
        "add",
        "rule",
        name_arg.as_str(),
        "dir=in",
        "action=allow",
        protocol_arg.as_str(),
        port_arg.as_str(),
        "profile=any",
        "enable=yes",
    ];

    match run_netsh_firewall(&args) {
        Ok(output) if output.status.success() => {
            tracing::info!(
                "已添加入站放行防火墙规则: name={}, protocol={}, localport={}",
                rule_name,
                protocol,
                port
            );
        }
        Ok(output) => {
            tracing::warn!(
                "添加入站放行防火墙规则失败: name={}, protocol={}, localport={}, exit_code={:?}, netsh 输出: {}",
                rule_name,
                protocol,
                port,
                output.status.code(),
                summarize_netsh_output(&output)
            );
        }
        Err(err) => {
            tracing::warn!(
                "执行 netsh 添加入站放行防火墙规则失败: name={}, protocol={}, localport={}, error={}",
                rule_name,
                protocol,
                port,
                err
            );
        }
    }
}

/// 执行 `netsh advfirewall firewall ...` 并返回输出。
fn run_netsh_firewall(args: &[&str]) -> io::Result<std::process::Output> {
    use std::os::windows::process::CommandExt;

    std::process::Command::new("netsh")
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
}

/// 把 netsh 的 stdout/stderr 压成单行摘要，用于日志（最长 200 字符）。
fn summarize_netsh_output(output: &std::process::Output) -> String {
    let mut summary = String::new();
    for bytes in [&output.stdout, &output.stderr] {
        let part = String::from_utf8_lossy(bytes);
        let part = part.split_whitespace().collect::<Vec<_>>().join(" ");
        if part.is_empty() {
            continue;
        }
        if !summary.is_empty() {
            summary.push(' ');
        }
        summary.push_str(&part);
    }
    summary.chars().take(200).collect()
}

/// Add firewall rules for specified network interface to allow all traffic
pub fn add_interface_to_firewall_allowlist(interface_name: &str) -> anyhow::Result<()> {
    let _com = ComInitializer::new()?;

    // Create firewall policy instance
    let policy: INetFwPolicy2 = unsafe {
        CoCreateInstance(
            &windows::Win32::NetworkManagement::WindowsFirewall::NetFwPolicy2,
            None,
            CLSCTX_ALL,
        )
    }?;

    tracing::info!(
        "Adding comprehensive firewall rules for interface: {}",
        interface_name
    );

    // Create rules for each protocol type
    add_protocol_firewall_rules(&policy, interface_name, "TCP", Some(6))?; // TCP protocol number 6
    tracing::debug!("Added TCP firewall rules for interface: {}", interface_name);

    add_protocol_firewall_rules(&policy, interface_name, "UDP", Some(17))?; // UDP protocol number 17
    tracing::debug!("Added UDP firewall rules for interface: {}", interface_name);

    add_protocol_firewall_rules(&policy, interface_name, "ICMP", Some(1))?; // ICMP protocol number 1
    tracing::debug!(
        "Added ICMP firewall rules for interface: {}",
        interface_name
    );

    // Add fallback rules for all protocols
    add_protocol_firewall_rules(&policy, interface_name, "ALL", None)?;
    tracing::debug!(
        "Added fallback all-protocols rules for interface: {}",
        interface_name
    );

    tracing::info!(
        "Successfully created all firewall rules for interface: {}",
        interface_name
    );

    Ok(())
}

/// Add firewall rules for a specific protocol
fn add_protocol_firewall_rules(
    policy: &INetFwPolicy2,
    interface_name: &str,
    protocol_name: &str,
    protocol_number: Option<i32>,
) -> anyhow::Result<()> {
    // Create rules for both inbound and outbound traffic
    for (is_inbound, direction_name) in [(true, "Inbound"), (false, "Outbound")] {
        // Create firewall rule instance
        let rule: INetFwRule = unsafe {
            CoCreateInstance(
                &windows::Win32::NetworkManagement::WindowsFirewall::NetFwRule,
                None,
                CLSCTX_ALL,
            )
        }?;

        let rule_name = format!(
            "EasyTier {} - {} Protocol ({})",
            interface_name, protocol_name, direction_name
        );
        let description = format!(
            "Allow {} traffic on EasyTier interface {}",
            protocol_name, interface_name
        );

        let name_bstr = BSTR::from(&rule_name);
        let desc_bstr = BSTR::from(&description);

        unsafe {
            rule.SetName(&name_bstr)?;
            rule.SetDescription(&desc_bstr)?;
            if let Some(protocol_number) = protocol_number {
                rule.SetProtocol(protocol_number)?;
            }
            rule.SetAction(NET_FW_ACTION_ALLOW)?;

            if is_inbound {
                rule.SetDirection(NET_FW_RULE_DIR_IN)?;
            } else {
                rule.SetDirection(NET_FW_RULE_DIR_OUT)?;
            }

            rule.SetEnabled(windows::Win32::Foundation::VARIANT_TRUE)?;
            rule.SetProfiles(
                NET_FW_PROFILE2_PRIVATE.0 | NET_FW_PROFILE2_PUBLIC.0 | NET_FW_PROFILE2_DOMAIN.0,
            )?;
            rule.SetGrouping(&BSTR::from("EasyTier"))?;

            // Set the interface for this rule to apply to the specific network interface
            // According to Microsoft docs, interfaces should be represented by their friendly name
            // We need to create a SAFEARRAY of VARIANT strings containing the interface name
            let interface_bstr = BSTR::from(interface_name);

            // Create a SAFEARRAY containing one interface name
            let interface_array = SafeArrayCreateVector(VT_VARIANT, 0, 1);
            if interface_array.is_null() {
                return Err(anyhow::anyhow!("Failed to create SAFEARRAY"));
            }

            let index = 0i32;
            let mut variant_interface = VARIANT::default();
            (*variant_interface.Anonymous.Anonymous).vt = VT_BSTR;
            (*variant_interface.Anonymous.Anonymous).Anonymous.bstrVal =
                ManuallyDrop::new(interface_bstr);

            SafeArrayPutElement(
                interface_array,
                &index as *const _,
                &variant_interface as *const _ as *const std::ffi::c_void,
            )?;

            // Create the VARIANT that contains the SAFEARRAY
            let mut interface_variant = VARIANT::default();
            (*interface_variant.Anonymous.Anonymous).vt = VARENUM(VT_ARRAY.0 | VT_VARIANT.0);
            (*interface_variant.Anonymous.Anonymous).Anonymous.parray = interface_array;

            rule.SetInterfaces(&interface_variant)?;

            // Get rule collection and add new rule
            let rules = policy.Rules()?;
            rules.Remove(&name_bstr)?; // Remove existing rule with same name first
            rules.Add(&rule)?;
        }
    }

    Ok(())
}

/// Remove firewall rules for specified interface
pub fn remove_interface_firewall_rules(interface_name: &str) -> anyhow::Result<()> {
    let _com = ComInitializer::new()?;

    let policy: INetFwPolicy2 = unsafe {
        CoCreateInstance(
            &windows::Win32::NetworkManagement::WindowsFirewall::NetFwPolicy2,
            None,
            CLSCTX_ALL,
        )
    }?;

    let rules = unsafe { policy.Rules()? };

    for protocol_name in ["TCP", "UDP", "ICMP", "ALL"] {
        for direction in ["Inbound", "Outbound"] {
            let rule_name = format!(
                "EasyTier {} - {} Protocol ({})",
                interface_name, protocol_name, direction
            );
            let name_bstr = BSTR::from(&rule_name);
            unsafe {
                let _ = rules.Remove(&name_bstr); // Ignore errors, rule might not exist
            }
        }
    }

    Ok(())
}

/// List EasyTier firewall rules for specified interface (for debugging)
#[allow(dead_code)]
pub fn list_interface_firewall_rules(interface_name: &str) -> anyhow::Result<Vec<String>> {
    let _com = ComInitializer::new()?;

    let policy: INetFwPolicy2 = unsafe {
        CoCreateInstance(
            &windows::Win32::NetworkManagement::WindowsFirewall::NetFwPolicy2,
            None,
            CLSCTX_ALL,
        )
    }?;

    let rules = unsafe { policy.Rules()? };
    let mut found_rules = Vec::new();

    // Check protocol-specific rules
    for protocol_name in ["TCP", "UDP", "ICMP"] {
        for direction in ["Inbound", "Outbound"] {
            let rule_name = format!(
                "EasyTier {} - {} Protocol ({})",
                interface_name, protocol_name, direction
            );
            if check_rule_exists(&rules, &rule_name)? {
                found_rules.push(rule_name);
            }
        }
    }

    // Check fallback protocol rules
    for direction in ["Inbound", "Outbound"] {
        let rule_name = format!(
            "EasyTier {} - All Protocols ({})",
            interface_name, direction
        );
        if check_rule_exists(&rules, &rule_name)? {
            found_rules.push(rule_name);
        }
    }

    Ok(found_rules)
}

/// Check if a firewall rule with specified name exists
fn check_rule_exists(
    rules: &windows::Win32::NetworkManagement::WindowsFirewall::INetFwRules,
    rule_name: &str,
) -> anyhow::Result<bool> {
    let name_bstr = BSTR::from(rule_name);
    unsafe {
        match rules.Item(&name_bstr) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_self_to_firewall_allowlist() {
        let res = add_self_to_firewall_allowlist();
        assert!(res.is_ok());
    }

    #[test]
    fn test_collect_exit_node_port_rules() {
        // 没有监听配置时，退化为默认端口：wg 数据面 UDP 11011 + 控制面 UDP/TCP 11010
        assert_eq!(
            collect_exit_node_port_rules(&[]),
            vec![
                (true, DEFAULT_WG_PORT, WG_RULE_KIND),
                (true, DEFAULT_CTRL_PORT, CTRL_RULE_KIND),
                (false, DEFAULT_CTRL_PORT, CTRL_RULE_KIND),
            ]
        );

        // 从监听 URL 推导端口；同一协议+端口去重；其它协议不创建规则
        let listener_uris = vec![
            "tcp://0.0.0.0:11010".parse().unwrap(),
            "udp://0.0.0.0:11010".parse().unwrap(),
            "udp://0.0.0.0:11010".parse().unwrap(),
            "wg://0.0.0.0:21011".parse().unwrap(),
            "ws://0.0.0.0:11011".parse().unwrap(),
        ];
        assert_eq!(
            collect_exit_node_port_rules(&listener_uris),
            vec![
                (false, 11010, CTRL_RULE_KIND),
                (true, 11010, CTRL_RULE_KIND),
                (true, 21011, WG_RULE_KIND),
            ]
        );
    }

    #[test]
    #[ignore] // Requires administrator privileges, ignored by default
    fn test_interface_firewall_rules() {
        let test_interface = "test_interface";

        // Add firewall rules
        let add_result = add_interface_to_firewall_allowlist(test_interface);
        assert!(
            add_result.is_ok(),
            "Failed to add interface firewall rules: {:?}",
            add_result
        );

        println!(
            "✓ Added comprehensive firewall rules for interface: {}",
            test_interface
        );

        // Verify rules were created
        let rules = list_interface_firewall_rules(test_interface).unwrap();
        println!("Created {} firewall rules:", rules.len());
        for rule in &rules {
            println!("  - {}", rule);
        }

        // Verify required protocol rules are all created
        let expected_protocols = ["TCP", "UDP", "ICMP"];
        let expected_directions = ["Inbound", "Outbound"];

        for protocol in &expected_protocols {
            for direction in &expected_directions {
                let rule_name = format!(
                    "EasyTier {} - {} Protocol ({})",
                    test_interface, protocol, direction
                );
                assert!(
                    rules.contains(&rule_name),
                    "Missing required rule: {}",
                    rule_name
                );
            }
        }

        println!("✓ All required protocol rules (TCP/UDP/ICMP) are present");

        // Remove firewall rules
        let remove_result = remove_interface_firewall_rules(test_interface);
        assert!(
            remove_result.is_ok(),
            "Failed to remove interface firewall rules: {:?}",
            remove_result
        );

        // Verify rules were removed
        let remaining_rules = list_interface_firewall_rules(test_interface).unwrap();
        assert!(
            remaining_rules.is_empty(),
            "Some rules were not removed: {:?}",
            remaining_rules
        );

        println!(
            "✓ Successfully removed all firewall rules for interface: {}",
            test_interface
        );
    }
}
