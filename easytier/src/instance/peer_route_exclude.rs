//! 全局路由（`routes = ["0.0.0.0/0"]`）场景下，为所有 peer 的物理地址安装临时排除路由。
//!
//! 现象与原因：客户端在配置里设置 `routes = ["0.0.0.0/0"]`（全局路由，流量走出口节点）后，
//! 即使 TUN 默认路由已经生效，**到 peer 物理公网地址（例如出口节点公网 IP）的流量仍会被
//! TUN 默认路由吸进隧道**，造成隧道递归/回环：easytier 的 wg 隧道 `local_addr` 变成
//! `wg://10.144.144.1:xxxxx`（源地址绑到了 TUN 接口 IP），包从 TUN 出去又回到出口节点自身，
//! 出口节点日志出现 `remote="wg://<自身公网IP>` 的自连记录，peer 表 loss 25%+、隧道每
//! 30~90s 断连。手工给 peer 物理地址加一条「走物理接口的主机路由」后 loss 降到 0~2%。
//!
//! 修复方式：当配置含全局路由（`0.0.0.0/0`）时，自动为所有 peer 的物理地址添加走物理接口/
//! 网关的**临时**（非持久）`/32` 排除路由，并在实例停止/进程退出时删除，避免残留。
//!
//! 注意：本模块**不涉及** TUN 默认路由的跃点（metric）调整，只安装更长前缀的主机路由。
//!
//! 平台相关的路由查询/增删实现见 `crate::common::ifcfg::peer_exclude`。

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

use once_cell::sync::Lazy;
use tokio::sync::Mutex;

use crate::common::dns;
use crate::common::global_ctx::ArcGlobalCtx;
use crate::common::ifcfg::peer_exclude;

/// 已安装的排除路由记录，用于实例停止/进程退出时清理。
///
/// `route add` / `ip route add` 安装的都是非持久路由，进程不清理就会残留到重启/手工删除。
#[derive(Debug, Clone)]
struct InstalledRoute {
    /// 目标主机地址
    target: Ipv4Addr,
    /// 安装时使用的网关
    gateway: Ipv4Addr,
    /// 安装时使用的出接口描述
    interface: String,
}

/// 本进程安装的排除路由。
///
/// 用 `tokio::sync::Mutex` 而非 `std::sync::Mutex`：安装/删除过程中需要 await 子进程，
/// 不能在 await 期间持有 std 锁。
static INSTALLED: Lazy<Mutex<Vec<InstalledRoute>>> = Lazy::new(|| Mutex::new(Vec::new()));

/// 判断配置的 routes 中是否包含全局路由（`0.0.0.0/0`）。
fn has_global_route(global_ctx: &ArcGlobalCtx) -> bool {
    global_ctx
        .config
        .get_routes()
        .unwrap_or_default()
        .iter()
        .any(|cidr| cidr.network_length() == 0)
}

/// 收集所有 peer 的物理地址（仅 IPv4，去重）。
///
/// - `uri` 直接是 IPv4/IPv6 字面量时直接取用；
/// - `uri` 是域名时用仓库已有的 `crate::common::dns::socket_addrs` 解析（它会按仓库策略
///   优先使用系统 DNS，否则回退 hickory resolver），把解析出的所有 IPv4 地址都纳入排除范围；
/// - 解析失败或只有 IPv6 地址时只告警跳过，不影响其它 peer。
async fn collect_peer_ipv4_targets(global_ctx: &ArcGlobalCtx) -> BTreeSet<Ipv4Addr> {
    let mut targets = BTreeSet::new();

    for peer in global_ctx.config.get_peers() {
        match peer.uri.host() {
            Some(url::Host::Ipv4(ip)) => {
                targets.insert(ip);
            }
            Some(url::Host::Ipv6(ip)) => {
                // 全局路由只针对 IPv4（config 的 routes 是 Ipv4Cidr），IPv6 peer 无需排除
                tracing::debug!(%ip, uri = %peer.uri, "peer 是 IPv6 地址，跳过排除路由");
            }
            Some(url::Host::Domain(domain)) => {
                // 端口与路由无关，缺省端口传 0 即可
                let addrs = match dns::socket_addrs(&peer.uri, || Some(0)).await {
                    Ok(addrs) => addrs,
                    Err(e) => {
                        tracing::warn!(
                            %domain,
                            uri = %peer.uri,
                            ?e,
                            "解析 peer 域名失败，跳过该 peer 的排除路由"
                        );
                        continue;
                    }
                };

                let mut resolved = 0;
                for addr in addrs {
                    if let IpAddr::V4(ip) = addr.ip() {
                        targets.insert(ip);
                        resolved += 1;
                    }
                }
                if resolved == 0 {
                    tracing::warn!(
                        %domain,
                        uri = %peer.uri,
                        "peer 域名没有解析出 IPv4 地址，跳过该 peer 的排除路由"
                    );
                } else {
                    tracing::debug!(%domain, resolved, "peer 域名解析完成");
                }
            }
            None => {
                tracing::warn!(uri = %peer.uri, "peer uri 没有 host，跳过该 peer 的排除路由");
            }
        }
    }

    targets
}

/// 全局路由（routes 含 `0.0.0.0/0`）场景下，为所有 peer 的物理地址安装临时排除路由。
///
/// 返回成功安装（或已存在）的条目数。任何单条失败只告警，不影响其它条目。
///
/// 语义是「同步」而非「追加」：
/// - 已经按当前物理路径安装过的条目直接复用（幂等，不重复添加）；
/// - 网关/接口变化（例如切换网卡）时会先删旧路由再重装；
/// - 已经不在 peer 配置里的目标会被清理，避免残留。
pub async fn install_peer_exclude_routes(global_ctx: &ArcGlobalCtx) -> anyhow::Result<usize> {
    if !has_global_route(global_ctx) {
        tracing::debug!("配置的 routes 中不含全局路由 0.0.0.0/0，跳过 peer 排除路由");
        return Ok(0);
    }

    let targets = collect_peer_ipv4_targets(global_ctx).await;
    if targets.is_empty() {
        tracing::warn!("没有解析出任何 peer 的 IPv4 物理地址，跳过 peer 排除路由");
        return Ok(0);
    }

    // Linux 上如果实例运行在自定义 netns 里，本模块的子进程（ip route）与 /proc 读取都发生在
    // 宿主 netns 中，排除路由可能被装到错误的名字空间。这里只提示、不阻断。
    #[cfg(target_os = "linux")]
    if let Some(netns) = global_ctx.net_ns.name() {
        tracing::warn!(
            %netns,
            "实例运行在自定义 netns 中，peer 排除路由可能被安装到宿主 netns"
        );
    }

    let default_route = match peer_exclude::get_physical_default_route().await {
        Ok(route) => route,
        Err(e) => {
            tracing::warn!(?e, "获取物理默认路由失败，跳过 peer 排除路由");
            return Ok(0);
        }
    };
    let gateway = default_route.gateway;
    let interface = default_route.interface.clone();

    let mut installed = INSTALLED.lock().await;

    // 1) 回收已经不需要的条目：peer 从配置里移除后，避免排除路由残留
    let mut kept = Vec::with_capacity(installed.len());
    for old in installed.drain(..) {
        if targets.contains(&old.target) {
            kept.push(old);
            continue;
        }
        match peer_exclude::delete_host_route(old.target).await {
            Ok(()) => tracing::info!(
                target = %old.target,
                gateway = %old.gateway,
                interface = %old.interface,
                "已删除不再需要的 peer 排除路由"
            ),
            Err(e) => tracing::warn!(
                target = %old.target,
                ?e,
                "删除不再需要的 peer 排除路由失败"
            ),
        }
    }
    *installed = kept;

    // 2) 安装（或复用）当前 peer 的排除路由，逐条隔离失败
    let mut count = 0;
    for target in targets {
        if let Some(index) = installed.iter().position(|route| route.target == target) {
            if installed[index].gateway == gateway && installed[index].interface == interface {
                // 已按当前物理路径安装过，幂等返回
                count += 1;
                continue;
            }
            // 网关/接口变化（例如从 WiFi 切到有线），先删旧路由再重装
            if let Err(e) = peer_exclude::delete_host_route(target).await {
                tracing::warn!(%target, ?e, "删除旧 peer 排除路由失败，继续尝试重装");
            }
            installed.remove(index);
        }

        match peer_exclude::add_host_route(target, &default_route).await {
            Ok(()) => {
                tracing::info!(
                    %target,
                    %gateway,
                    %interface,
                    "已为 peer 物理地址安装排除路由"
                );
                installed.push(InstalledRoute {
                    target,
                    gateway,
                    interface: interface.clone(),
                });
                count += 1;
            }
            Err(e) => tracing::warn!(
                %target,
                %gateway,
                %interface,
                ?e,
                "为 peer 物理地址安装排除路由失败"
            ),
        }
    }

    tracing::info!(count, installed = installed.len(), "peer 排除路由同步完成");
    Ok(count)
}

/// 删除由本模块安装的排除路由（进程退出/实例停止时调用，避免 `route add` 这类非持久路由残留）。
///
/// 逐条删除，失败只告警；无论删除成功与否都会清空进程内的记录。
pub async fn remove_peer_exclude_routes() -> anyhow::Result<usize> {
    let mut installed = INSTALLED.lock().await;
    let routes = std::mem::take(&mut *installed);
    if routes.is_empty() {
        tracing::debug!("没有需要清理的 peer 排除路由");
        return Ok(0);
    }

    let mut removed = 0;
    for route in routes {
        match peer_exclude::delete_host_route(route.target).await {
            Ok(()) => {
                tracing::info!(
                    target = %route.target,
                    gateway = %route.gateway,
                    interface = %route.interface,
                    "已删除 peer 排除路由"
                );
                removed += 1;
            }
            Err(e) => tracing::warn!(
                target = %route.target,
                ?e,
                "删除 peer 排除路由失败"
            ),
        }
    }

    Ok(removed)
}
