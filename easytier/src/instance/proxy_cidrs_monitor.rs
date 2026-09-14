use std::collections::BTreeSet;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use crate::common::global_ctx::{ArcGlobalCtx, GlobalCtxEvent};
use crate::peers::peer_manager::PeerManager;
use tokio_util::task::AbortOnDropHandle;

/// 出口节点在线状态变化后，需要持续稳定多久才真正生效。
///
/// 用于防抖：避免出口节点网络抖动导致 TUN 默认路由被反复增删、造成二次断网。
const EXIT_NODE_STATE_DEBOUNCE: Duration = Duration::from_secs(5);

/// ProxyCidrsMonitor monitors changes in proxy CIDRs from peer routes
/// and emits GlobalCtxEvent::ProxyCidrsUpdated with added/removed diffs.
pub struct ProxyCidrsMonitor {
    peer_mgr: Weak<PeerManager>,
    global_ctx: ArcGlobalCtx,
}

impl ProxyCidrsMonitor {
    pub fn new(peer_mgr: Arc<PeerManager>, global_ctx: ArcGlobalCtx) -> Self {
        Self {
            peer_mgr: Arc::downgrade(&peer_mgr),
            global_ctx,
        }
    }

    /// 判断配置的出口节点中是否至少有一个在线。
    ///
    /// 与出口选择共用 `PeerManager::is_exit_node_online`，保证「选哪个出口」与
    /// 「是否保留默认路由」两处判定使用同一信号源，不会出现结论不一致。
    async fn any_exit_node_online(peer_mgr: &PeerManager, global_ctx: &ArcGlobalCtx) -> bool {
        let exit_nodes = global_ctx.config.get_exit_nodes();
        if exit_nodes.is_empty() {
            return false;
        }
        for exit_node in exit_nodes.iter() {
            if peer_mgr.is_exit_node_online(exit_node).await {
                return true;
            }
        }
        false
    }

    /// Collects current proxy_cidrs from peer routes, VPN portal config, and manual routes.
    /// This is a static function that can be used for initial sync or recovery after Lagged errors.
    ///
    /// 全局出口场景（manual routes 含 `0.0.0.0/0` 且配置了 `exit_nodes`）下，默认路由
    /// 只在「至少一个出口节点在线」时才计入，否则从结果中移除，使 TUN 默认路由被撤回、
    /// 公网流量回退本机直连，避免出口节点离线后形成黑洞导致整机断网。
    pub async fn diff_proxy_cidrs(
        peer_mgr: &PeerManager,
        global_ctx: &ArcGlobalCtx,
        cur_proxy_cidrs: &BTreeSet<cidr::Ipv4Cidr>,
    ) -> (
        BTreeSet<cidr::Ipv4Cidr>,
        Vec<cidr::Ipv4Cidr>,
        Vec<cidr::Ipv4Cidr>,
    ) {
        let proxy_cidrs = if let Some(routes) = global_ctx.config.get_routes() {
            // If manual routes exist, override entire proxy_cidrs
            let mut proxy_cidrs: BTreeSet<cidr::Ipv4Cidr> = routes.into_iter().collect();

            // 仅对「routes 含 0.0.0.0/0 且配置了 exit_nodes」的全局出口场景生效；
            // 普通 -n 子网代理不参与出口存活判定，行为保持 2.6.4 现状。
            if !global_ctx.config.get_exit_nodes().is_empty()
                && !Self::any_exit_node_online(peer_mgr, global_ctx).await
            {
                let before = proxy_cidrs.len();
                proxy_cidrs.retain(|cidr| cidr.network_length() != 0);
                if proxy_cidrs.len() != before {
                    tracing::warn!(
                        "all exit nodes are offline, withdraw the default route and fall back to \
                         direct connection"
                    );
                }
            }

            proxy_cidrs
        } else {
            // Collect proxy_cidrs from routes
            let mut proxy_cidrs = peer_mgr.list_proxy_cidrs().await;

            // Add VPN portal cidr to proxy_cidrs
            if let Some(vpn_cfg) = global_ctx.config.get_vpn_portal_config() {
                proxy_cidrs.insert(vpn_cfg.client_cidr);
            }

            proxy_cidrs
        };

        // Calculate diff
        if cur_proxy_cidrs == &proxy_cidrs {
            return (proxy_cidrs, Vec::new(), Vec::new());
        }
        let added = proxy_cidrs.difference(cur_proxy_cidrs).cloned().collect();
        let removed = cur_proxy_cidrs.difference(&proxy_cidrs).cloned().collect();

        (proxy_cidrs, added, removed)
    }

    /// Starts monitoring proxy_cidrs changes and emits events with diffs
    pub fn start(self) -> AbortOnDropHandle<()> {
        AbortOnDropHandle::new(tokio::spawn(async move {
            let mut cur_proxy_cidrs = BTreeSet::new();
            let mut last_update = None::<Instant>;

            // 出口节点在线状态的去抖状态机：
            // `exit_online` 为当前生效值，`pending` 记录待确认的新状态及其起始时刻。
            let mut exit_online = true;
            let mut pending: Option<(bool, Instant)> = None;

            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;

                let Some(peer_mgr) = self.peer_mgr.upgrade() else {
                    tracing::warn!("peer manager dropped, stopping ProxyCidrsMonitor");
                    break;
                };

                // Check if route info has been updated
                let route_info_changed = {
                    let last_update_time = peer_mgr.get_route_peer_info_last_update_time().await;
                    if last_update == Some(last_update_time) {
                        false
                    } else {
                        last_update = Some(last_update_time);
                        true
                    }
                };

                // 出口节点存活状态必须与路由信息变化一样能够触发重算，
                // 否则出口节点离线时 0.0.0.0/0 永远不会被撤回。
                let exit_node_state_changed = {
                    let exit_nodes = self.global_ctx.config.get_exit_nodes();
                    if exit_nodes.is_empty() {
                        // 未配置出口节点：本逻辑不生效
                        pending = None;
                        exit_online = true;
                        false
                    } else {
                        let observed =
                            Self::any_exit_node_online(peer_mgr.as_ref(), &self.global_ctx).await;
                        if observed == exit_online {
                            pending = None;
                            false
                        } else {
                            // 状态变化需持续稳定 EXIT_NODE_STATE_DEBOUNCE 才真正生效
                            match pending {
                                Some((pending_state, since)) if pending_state == observed => {
                                    if since.elapsed() >= EXIT_NODE_STATE_DEBOUNCE {
                                        exit_online = observed;
                                        pending = None;
                                        if observed {
                                            tracing::info!(
                                                "exit node is online again, restore exit node mode"
                                            );
                                        } else {
                                            tracing::warn!(
                                                "all exit nodes are offline, fall back to direct \
                                                 connection"
                                            );
                                        }
                                        true
                                    } else {
                                        false
                                    }
                                }
                                _ => {
                                    pending = Some((observed, Instant::now()));
                                    false
                                }
                            }
                        }
                    }
                };

                if !route_info_changed && !exit_node_state_changed {
                    continue;
                }

                let (new_proxy_cidrs, added, removed) =
                    Self::diff_proxy_cidrs(peer_mgr.as_ref(), &self.global_ctx, &cur_proxy_cidrs)
                        .await;

                cur_proxy_cidrs = new_proxy_cidrs;

                if added.is_empty() && removed.is_empty() {
                    continue;
                }
                self.global_ctx
                    .issue_event(GlobalCtxEvent::ProxyCidrsUpdated(added, removed));
            }
        }))
    }
}
