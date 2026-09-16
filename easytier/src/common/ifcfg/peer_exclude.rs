//! 全局路由（`routes = ["0.0.0.0/0"]`）场景下，为 peer 物理地址安装/删除临时排除路由的
//! 平台相关底层实现。
//!
//! 背景：客户端配置了全局路由（流量走出口节点）后，TUN 的默认路由（`0.0.0.0/0`）会把
//! 「到 peer 物理公网地址」的流量也吸进隧道，形成隧道递归：easytier 自己的 wg 隧道
//! `local_addr` 被绑到 TUN 接口 IP，包从 TUN 出去又回到出口节点自身，表现为出口节点日志出现
//! `remote="wg://<自身公网IP>` 的自连记录、peer 表丢包、隧道每 30~90s 断连。
//! 给 peer 的物理地址补一条走物理接口的主机路由（`/32`）即可让这部分流量绕开隧道。
//!
//! 两个关键设计（三平台一致）：
//! 1. 「物理默认路径」定义为路由表中**带真实网关**的默认路由。easytier 自己安装的 TUN 默认
//!    路由不带网关（on-link / `via 0.0.0.0`），因此天然被过滤掉，无需识别 TUN 的接口名或索引；
//! 2. 排除路由使用 `/32` 主机路由，前缀长度比 TUN 的 `/0` 更长，按最长前缀匹配天然胜出，
//!    因此完全不依赖 metric —— 也就不会触碰 TUN 默认路由的跃点（metric）逻辑。
//!
//! 本模块只负责「取物理默认路径」与「增删主机路由」，策略（何时装、给哪些地址装、记账）
//! 在 `crate::instance::peer_route_exclude` 中实现。

use std::net::Ipv4Addr;

/// 到目标 IP 的「物理默认路径」：网关 + 出接口。
///
/// 注意这里的「物理」不是靠识别具体网卡得到的，而是指路由表中**带真实网关**的默认路由，
/// 因此即使 easytier 的 TUN 默认路由已经胜出，也能稳定拿到物理出口。
#[derive(Debug, Clone)]
pub struct PhysicalDefaultRoute {
    /// 默认网关地址（保证不是 `0.0.0.0`）
    pub gateway: Ipv4Addr,
    /// 出接口描述：Linux/macOS 为接口名，Windows 为 `if <索引>`
    pub interface: String,
    /// Windows 上 `route add ... if <索引>` 需要的接口索引，其它平台为 `None`
    pub interface_index: Option<u32>,
}

/// 查询到 IPv4 默认网关的物理路径（网关 + 出接口）。
///
/// 失败由调用方告警后跳过，不影响进程其它逻辑。
pub async fn get_physical_default_route() -> anyhow::Result<PhysicalDefaultRoute> {
    imp::get_physical_default_route().await
}

/// 为 `target` 安装一条走物理默认路径的临时主机路由（`/32`）。
///
/// 幂等：先尽力删除同目标路由再添加；若添加时提示已存在（`File exists`）也视为成功。
/// Windows 上不使用 `route -p`，即路由是非持久的，进程退出时由 [`delete_host_route`] 清理。
pub async fn add_host_route(target: Ipv4Addr, route: &PhysicalDefaultRoute) -> anyhow::Result<()> {
    imp::add_host_route(target, route).await
}

/// 删除 `target` 的主机路由（`/32`）。
///
/// 路由不存在时返回错误（例如提示 `No such process`），由调用方决定是告警还是忽略。
pub async fn delete_host_route(target: Ipv4Addr) -> anyhow::Result<()> {
    imp::delete_host_route(target).await
}

/// 执行原生命令并返回输出。
///
/// 不使用 shell，参数以数组形式传入，避免引号/转义问题；Windows 下用 `CREATE_NO_WINDOW`
/// 创建子进程，避免弹出控制台窗口。
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
async fn run_cmd(program: &str, args: &[&str]) -> anyhow::Result<std::process::Output> {
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args).stdin(std::process::Stdio::null());
    #[cfg(target_os = "windows")]
    {
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd.output()
        .await
        .with_context(|| format!("执行命令失败: {} {}", program, args.join(" ")))
}

/// 截断命令输出，便于放进 warn 日志（Windows 上先做 UTF-8/GBK 兼容解码）。
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn brief_output(bytes: &[u8]) -> String {
    #[cfg(target_os = "windows")]
    let text = crate::utils::string::utf8_or_gbk_to_string(bytes);
    #[cfg(not(target_os = "windows"))]
    let text = String::from_utf8_lossy(bytes).to_string();
    text.trim().chars().take(200).collect()
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use anyhow::Context;

#[cfg(target_os = "linux")]
mod imp {
    use std::net::Ipv4Addr;

    use anyhow::{Context, bail};

    use super::{PhysicalDefaultRoute, brief_output, run_cmd};

    /// Linux 默认路由表（main 表）的只读视图：无需子进程、不依赖 `iproute2` 是否安装，
    /// 因此优于解析 `ip -4 route show default` 的输出。
    const PROC_NET_ROUTE: &str = "/proc/net/route";

    /// 解析 `/proc/net/route` 的十六进制地址字段。
    ///
    /// 该字段是地址字节按**小端**顺序拼成的 `%08X`：192.168.1.1 打印为 `0101A8C0`，
    /// 因此需要 `swap_bytes` 还原成常规的 IPv4 表示。
    fn parse_le_hex_ipv4(field: &str) -> Option<Ipv4Addr> {
        let raw = u32::from_str_radix(field, 16).ok()?;
        Some(Ipv4Addr::from(raw.swap_bytes()))
    }

    /// 从 `/proc/net/route` 文本中挑出可用的默认路由，按 metric 升序返回。
    ///
    /// 返回元素为 `(接口名, 网关, metric)`。只保留网关非 `0.0.0.0` 的条目：
    /// 网关为 0 的是 on-link 默认路由（easytier 自己安装的 TUN 默认路由即属于此类），
    /// 没有可用的下一跳，无法作为排除路由的出口。
    fn parse_default_routes(content: &str) -> Vec<(String, Ipv4Addr, u32)> {
        let mut routes = Vec::new();
        // 首行是表头：Iface Destination Gateway Flags RefCnt Use Metric Mask MTU ...
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 7 {
                continue;
            }
            // Destination 为 00000000 即为默认路由
            if fields[1] != "00000000" {
                continue;
            }
            let Some(gateway) = parse_le_hex_ipv4(fields[2]) else {
                continue;
            };
            if gateway.is_unspecified() {
                continue;
            }
            let metric = fields[6].parse::<u32>().unwrap_or(0);
            routes.push((fields[0].to_string(), gateway, metric));
        }
        // 多条带网关的默认路由时，按 metric 取最优先的那条
        routes.sort_by_key(|(_, _, metric)| *metric);
        routes
    }

    pub async fn get_physical_default_route() -> anyhow::Result<PhysicalDefaultRoute> {
        let content = tokio::fs::read_to_string(PROC_NET_ROUTE)
            .await
            .with_context(|| format!("读取 {} 失败", PROC_NET_ROUTE))?;

        let Some((interface, gateway, metric)) = parse_default_routes(&content).into_iter().next()
        else {
            bail!(
                "{} 中没有带网关的默认路由，无法确定物理出口",
                PROC_NET_ROUTE
            );
        };

        tracing::debug!(%gateway, %interface, metric, "找到物理默认路由");
        Ok(PhysicalDefaultRoute {
            gateway,
            interface,
            interface_index: None,
        })
    }

    pub async fn add_host_route(
        target: Ipv4Addr,
        route: &PhysicalDefaultRoute,
    ) -> anyhow::Result<()> {
        // 幂等：先尽力删除同目标路由（不存在时 `ip` 会报错，这里直接忽略）
        let _ = delete_host_route(target).await;

        let target_with_prefix = format!("{}/32", target);
        let gateway = route.gateway.to_string();
        let args = [
            "route",
            "add",
            target_with_prefix.as_str(),
            "via",
            gateway.as_str(),
            "dev",
            route.interface.as_str(),
        ];
        let output = run_cmd("ip", &args).await?;
        if !output.status.success() {
            let stderr = brief_output(&output.stderr);
            // 并发安装时可能撞上已经存在的同目标路由，视为成功
            if stderr.contains("File exists") {
                return Ok(());
            }
            bail!("ip route add 失败: {}", stderr);
        }
        Ok(())
    }

    pub async fn delete_host_route(target: Ipv4Addr) -> anyhow::Result<()> {
        let target_with_prefix = format!("{}/32", target);
        let args = ["route", "del", target_with_prefix.as_str()];
        let output = run_cmd("ip", &args).await?;
        if !output.status.success() {
            bail!("ip route del 失败: {}", brief_output(&output.stderr));
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use std::net::Ipv4Addr;

    use anyhow::bail;

    use super::{PhysicalDefaultRoute, brief_output, run_cmd};

    /// 隧道类接口名前缀：这些接口上的默认路由不能作为「物理路径」。
    const TUNNEL_IFACE_PREFIXES: [&str; 4] = ["utun", "tun", "tap", "ipsec"];

    /// 判断接口名是否是隧道接口：这些接口上的默认路由不能作为「物理路径」。
    fn is_tunnel_interface(interface: &str) -> bool {
        TUNNEL_IFACE_PREFIXES
            .iter()
            .any(|prefix| interface.starts_with(prefix))
    }

    /// 解析 `route -n get default` 输出中的 `gateway:` 与 `interface:`。
    ///
    /// 它是内核真正选中的默认路由，正常情况下首选；但当 easytier 已经用 TUN 接管默认路由
    /// 时会返回 TUN 自己的 `link#N`，此时返回 `None`，由 `netstat` 兜底。
    fn parse_route_get_default(output: &str) -> Option<(Ipv4Addr, String)> {
        let mut gateway = None;
        let mut interface = None;
        for line in output.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            match key.trim() {
                "gateway" => gateway = value.trim().parse::<Ipv4Addr>().ok(),
                "interface" => interface = Some(value.trim().to_string()),
                _ => {}
            }
        }
        match (gateway, interface) {
            (Some(gateway), Some(interface)) if !is_tunnel_interface(&interface) => {
                Some((gateway, interface))
            }
            _ => None,
        }
    }

    /// 解析 `netstat -rn -f inet` 输出，取第一条带真实网关（而非 `link#N`）的默认路由。
    ///
    /// 返回 `(网关, 接口名)`。
    fn parse_netstat_default_route(output: &str) -> Option<(Ipv4Addr, String)> {
        for line in output.lines() {
            // Destination Gateway Flags Netif [Expire]
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 {
                continue;
            }
            if fields[0] != "default" && fields[0] != "0.0.0.0" {
                continue;
            }
            // `link#N` 之类的网关无法解析成 IP，顺带就过滤掉了 TUN 的默认路由
            let Ok(gateway) = fields[1].parse::<Ipv4Addr>() else {
                continue;
            };
            let interface = fields[3];
            if is_tunnel_interface(interface) {
                continue;
            }
            return Some((gateway, interface.to_string()));
        }
        None
    }

    pub async fn get_physical_default_route() -> anyhow::Result<PhysicalDefaultRoute> {
        // 优先用 `route -n get default`：它拿到的就是内核选中的那条默认路由
        let from_route_get = match run_cmd("route", &["-n", "get", "default"]).await {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                parse_route_get_default(&stdout)
            }
            Ok(output) => {
                let stderr = brief_output(&output.stderr);
                tracing::debug!(%stderr, "route -n get default 未取到默认路由");
                None
            }
            Err(e) => {
                tracing::debug!(?e, "执行 route -n get default 失败");
                None
            }
        };

        // 兜底：TUN 已经接管默认路由时 `route -n get default` 只会给出 `link#N`，
        // 改为扫描路由表，挑一条带真实网关、且不落在隧道接口上的默认路由
        let found = match from_route_get {
            Some(found) => found,
            None => {
                let output = run_cmd("netstat", &["-rn", "-f", "inet"]).await?;
                if !output.status.success() {
                    bail!("netstat -rn -f inet 失败: {}", brief_output(&output.stderr));
                }
                let stdout = String::from_utf8_lossy(&output.stdout);
                let Some(found) = parse_netstat_default_route(&stdout) else {
                    bail!("没有找到带网关的默认路由，无法确定物理出口");
                };
                found
            }
        };

        let (gateway, interface) = found;
        tracing::debug!(%gateway, %interface, "找到物理默认路由");
        Ok(PhysicalDefaultRoute {
            gateway,
            interface,
            interface_index: None,
        })
    }

    pub async fn add_host_route(
        target: Ipv4Addr,
        route: &PhysicalDefaultRoute,
    ) -> anyhow::Result<()> {
        // 幂等：先尽力删除同目标路由（不存在时 `route` 会报错，这里直接忽略）
        let _ = delete_host_route(target).await;

        let target_str = target.to_string();
        let gateway = route.gateway.to_string();
        let args = ["-n", "add", "-host", target_str.as_str(), gateway.as_str()];
        let output = run_cmd("route", &args).await?;
        if !output.status.success() {
            let stderr = brief_output(&output.stderr);
            if stderr.contains("File exists") {
                return Ok(());
            }
            bail!("route -n add -host 失败: {}", stderr);
        }
        Ok(())
    }

    pub async fn delete_host_route(target: Ipv4Addr) -> anyhow::Result<()> {
        let target_str = target.to_string();
        let args = ["-n", "delete", "-host", target_str.as_str()];
        let output = run_cmd("route", &args).await?;
        if !output.status.success() {
            bail!(
                "route -n delete -host 失败: {}",
                brief_output(&output.stderr)
            );
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
mod imp {
    use std::net::Ipv4Addr;

    use anyhow::bail;
    use winapi::shared::netioapi::{FreeMibTable, GetIpForwardTable2, PMIB_IPFORWARD_TABLE2};
    use winapi::shared::winerror::NO_ERROR;
    use winapi::shared::ws2def::AF_INET;

    use crate::common::ifcfg::win::types::convert_sockaddr_to_ipv4addr;

    use super::{PhysicalDefaultRoute, brief_output, run_cmd};

    /// 用 IP Helper 的 `GetIpForwardTable2` 枚举 IPv4 路由表，选出带真实网关的默认路由。
    ///
    /// 选 `GetIpForwardTable2` 而不是 `GetBestRoute2`：后者按当前路由表返回**最优**路由，
    /// 当 TUN 默认路由已经胜出时会返回 TUN 自己（正是本修复要绕开的那条路径）。
    /// 而 easytier 安装的 TUN 默认路由 next hop 为 `0.0.0.0`（on-link），可以用「网关非 0」
    /// 干净地过滤掉，不需要识别 TUN 的 LUID/接口索引。
    ///
    /// 备选方案（未采用）：解析 `route print -4 0.0.0.0` / `netsh interface ipv4 show route`
    /// 的输出。其数据行虽然是数字，但 `On-link` 之类的字段会随系统语言本地化，稳定性不如
    /// IP Helper API。
    fn find_physical_default_route() -> anyhow::Result<PhysicalDefaultRoute> {
        let mut table: PMIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        let ret = unsafe { GetIpForwardTable2(AF_INET as _, &mut table) };
        if ret != NO_ERROR {
            bail!("GetIpForwardTable2 失败, code: {}", ret);
        }
        if table.is_null() {
            bail!("GetIpForwardTable2 返回空路由表");
        }

        // (路由跃点, 网关, 接口索引)，取跃点最小的带网关默认路由
        let mut best: Option<(u32, Ipv4Addr, u32)> = None;
        // safety: table 由 GetIpForwardTable2 分配，前 NumEntries 条记录有效，读取期间不释放
        let table_ref = unsafe { &*table };
        let entries = table_ref.Table.as_ptr();
        for i in 0..table_ref.NumEntries as usize {
            let entry = unsafe { &*entries.add(i) };
            // 只看默认路由（目的前缀长度为 0）
            if entry.DestinationPrefix.PrefixLength != 0 {
                continue;
            }
            // safety: 表按 AF_INET 查询，NextHop 一定是 IPv4 形式
            let gateway = unsafe { convert_sockaddr_to_ipv4addr(entry.NextHop.Ipv4()) };
            if gateway.is_unspecified() {
                continue;
            }
            let metric = entry.Metric;
            if best
                .as_ref()
                .is_none_or(|(best_metric, _, _)| metric < *best_metric)
            {
                best = Some((metric, gateway, entry.InterfaceIndex));
            }
        }
        unsafe { FreeMibTable(table as _) };

        let Some((metric, gateway, interface_index)) = best else {
            bail!("IPv4 路由表中没有带网关的默认路由，无法确定物理出口");
        };

        tracing::debug!(%gateway, interface_index, metric, "找到物理默认路由");
        Ok(PhysicalDefaultRoute {
            gateway,
            interface: format!("if {}", interface_index),
            interface_index: Some(interface_index),
        })
    }

    pub async fn get_physical_default_route() -> anyhow::Result<PhysicalDefaultRoute> {
        find_physical_default_route()
    }

    pub async fn add_host_route(
        target: Ipv4Addr,
        route: &PhysicalDefaultRoute,
    ) -> anyhow::Result<()> {
        // 幂等：先尽力删除同目标主机路由（不存在时 route.exe 会报错，这里直接忽略）
        let _ = delete_host_route(target).await;

        let target_str = target.to_string();
        let gateway = route.gateway.to_string();
        let if_index = route.interface_index.map(|index| index.to_string());
        // 不加 `-p`：排除路由只需要临时存在，进程退出时由 delete_host_route 清理
        let mut args = vec![
            "add",
            target_str.as_str(),
            "mask",
            "255.255.255.255",
            gateway.as_str(),
            "metric",
            "1",
        ];
        if let Some(if_index) = if_index.as_deref() {
            args.push("if");
            args.push(if_index);
        }
        let output = run_cmd("route", &args).await?;
        if !output.status.success() {
            bail!("route add 失败: {}", brief_output(&output.stderr));
        }
        Ok(())
    }

    pub async fn delete_host_route(target: Ipv4Addr) -> anyhow::Result<()> {
        let target_str = target.to_string();
        // 限定 mask，避免删掉指向同一 IP 的其它（非 /32）路由
        let args = ["delete", target_str.as_str(), "mask", "255.255.255.255"];
        let output = run_cmd("route", &args).await?;
        if !output.status.success() {
            bail!("route delete 失败: {}", brief_output(&output.stderr));
        }
        Ok(())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod imp {
    use std::net::Ipv4Addr;

    use anyhow::bail;

    use super::PhysicalDefaultRoute;

    pub async fn get_physical_default_route() -> anyhow::Result<PhysicalDefaultRoute> {
        bail!("当前平台暂不支持自动安装 peer 排除路由")
    }

    pub async fn add_host_route(
        _target: Ipv4Addr,
        _route: &PhysicalDefaultRoute,
    ) -> anyhow::Result<()> {
        bail!("当前平台暂不支持自动安装 peer 排除路由")
    }

    pub async fn delete_host_route(_target: Ipv4Addr) -> anyhow::Result<()> {
        bail!("当前平台暂不支持自动安装 peer 排除路由")
    }
}
