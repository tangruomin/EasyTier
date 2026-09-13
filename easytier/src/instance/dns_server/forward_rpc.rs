//! 魔法 DNS 上游转发：把外部域名查询经隧道交给出口节点解析。
//!
//! 背景：启用魔法 DNS 后，非虚拟网域名（非 `.et.net.`）的查询会交给本机上游 DNS。
//! 在 Android 等平台上，easytier 自身的 socket 不经过隧道，而上游又被硬编码为国内
//! DNS（`223.5.5.5` / `180.184.1.1`），因此对 `google.com` 等域名会拿到 GFW 污染的
//! 假 IP，导致「出口节点在海外却打不开网站」。
//!
//! 本模块让客户端把这类查询经隧道交给出口节点，由出口节点用**自身的系统 DNS**
//! （通常位于海外、结果干净）解析后回传原始应答报文。出口节点不可用时，调用方
//! 会回退到本机上游转发，保持 2.6.4 的既有行为。

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::common::PeerId;
use crate::peers::peer_manager::PeerManager;
use crate::peers::route_trait::Route as RouteTrait;
use crate::proto::peer_rpc::{
    MagicDnsForwardRpc, MagicDnsForwardRpcClientFactory, ResolveDnsRequest, ResolveDnsResponse,
};
use crate::proto::rpc_types::controller::BaseController;

/// 出口节点向自身上游 DNS 查询的超时时间。
const UPSTREAM_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// 客户端等待出口节点应答的超时时间。
const EXIT_NODE_RPC_TIMEOUT: Duration = Duration::from_secs(5);

/// 出口节点读不到系统 DNS 配置时使用的兜底上游。
///
/// 刻意不使用 `223.5.5.5` / `180.184.1.1` 等国内 DNS：在「出口节点在海外」的场景下，
/// 它们会对被墙域名返回污染结果，正是本问题要避免的。
const FALLBACK_UPSTREAMS: [&str; 2] = ["8.8.8.8:53", "1.1.1.1:53"];

/// 单次上游查询的接收缓冲上限（UDP 方式下 DNS 报文不会超过该值）。
const MAX_DNS_RESPONSE_SIZE: usize = 4096;

/// 出口节点的上游 DNS 列表：优先使用系统 DNS 配置，读不到时使用兜底上游。
fn upstream_name_servers() -> Vec<SocketAddr> {
    let mut ret = Vec::new();
    if let Ok((config, _)) = hickory_resolver::system_conf::read_system_conf() {
        for ns in config.name_servers() {
            ret.push(ns.socket_addr);
        }
    }

    if ret.is_empty() {
        // 显式标注类型：`parse()` 在 `filter_map` + `extend` 组合下无法自行推断出目标类型
        ret.extend(
            FALLBACK_UPSTREAMS
                .iter()
                .filter_map(|s| s.parse::<SocketAddr>().ok()),
        );
    }

    ret
}

/// 把原始 DNS 查询报文转发给上游 DNS，返回原始应答报文。
async fn relay_query_to_upstream(query: &[u8]) -> Result<Vec<u8>, String> {
    let upstreams = upstream_name_servers();
    let Some(first_upstream) = upstreams.first().copied() else {
        return Err("no upstream dns server available".to_string());
    };

    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("failed to create udp socket: {}", e))?;

    let mut last_error = format!("upstream {} did not respond", first_upstream);
    for upstream in upstreams {
        let query_once = async {
            socket.send_to(query, upstream).await?;
            let mut buf = vec![0u8; MAX_DNS_RESPONSE_SIZE];
            let (len, _) = socket.recv_from(&mut buf).await?;
            Ok::<_, std::io::Error>(buf[..len].to_vec())
        };

        match tokio::time::timeout(UPSTREAM_QUERY_TIMEOUT, query_once).await {
            Ok(Ok(response)) => {
                tracing::debug!(
                    ?upstream,
                    len = response.len(),
                    "relayed magic dns query to upstream"
                );
                return Ok(response);
            }
            Ok(Err(e)) => {
                last_error = format!("upstream {} query failed: {}", upstream, e);
            }
            Err(_) => {
                last_error = format!("upstream {} query timeout", upstream);
            }
        }
    }

    Err(last_error)
}

/// 出口节点侧的魔法 DNS 转发服务：用自身系统 DNS 代客户端解析外部域名。
#[derive(Clone)]
pub struct MagicDnsForwardService;

#[async_trait::async_trait]
impl MagicDnsForwardRpc for MagicDnsForwardService {
    type Controller = BaseController;

    async fn resolve_dns(
        &self,
        _ctrl: BaseController,
        req: ResolveDnsRequest,
    ) -> crate::proto::rpc_types::error::Result<ResolveDnsResponse> {
        if req.query.is_empty() {
            return Ok(ResolveDnsResponse {
                response: Vec::new(),
                error: "empty dns query".to_string(),
            });
        }

        match relay_query_to_upstream(&req.query).await {
            Ok(response) => Ok(ResolveDnsResponse {
                response,
                error: String::new(),
            }),
            Err(error) => {
                tracing::warn!(%error, "failed to relay magic dns query to upstream");
                // 用响应体内的 error 字段回传失败原因，避免把 RPC 层错误语义复杂化
                Ok(ResolveDnsResponse {
                    response: Vec::new(),
                    error,
                })
            }
        }
    }
}

/// 按 `exit_nodes` 配置顺序，选择第一个仍在线（存在 peer 会话）的出口节点。
pub async fn select_online_exit_node(peer_mgr: &PeerManager) -> Option<PeerId> {
    let exit_nodes = peer_mgr.get_global_ctx().config.get_exit_nodes();
    if exit_nodes.is_empty() {
        return None;
    }

    let route = peer_mgr.get_route();
    for exit_node in exit_nodes {
        let peer_id = match exit_node {
            IpAddr::V4(ipv4) => route.get_peer_id_by_ipv4(&ipv4).await,
            IpAddr::V6(ipv6) => route.get_peer_id_by_ipv6(&ipv6).await,
        };
        let Some(peer_id) = peer_id else {
            continue;
        };

        // OSPF 路由表只反映拓扑，还需确认该 peer 的会话仍然存活
        if peer_mgr.get_peer_map().has_peer(peer_id)
            || peer_mgr.has_directly_connected_conn(peer_id)
        {
            return Some(peer_id);
        }
    }

    None
}

/// 把原始 DNS 查询经隧道交给出口节点解析，成功时返回原始 DNS 应答报文。
///
/// 返回 `None` 表示「无法通过出口节点解析」，调用方应回退到本机上游。
pub async fn resolve_dns_via_exit_node(
    peer_mgr: &Arc<PeerManager>,
    query: &[u8],
) -> Option<Vec<u8>> {
    let exit_node_peer_id = select_online_exit_node(peer_mgr.as_ref()).await?;

    let global_ctx = peer_mgr.get_global_ctx();
    let stub = peer_mgr
        .get_peer_rpc_mgr()
        .rpc_client()
        .scoped_client::<MagicDnsForwardRpcClientFactory<BaseController>>(
            peer_mgr.my_peer_id(),
            exit_node_peer_id,
            global_ctx.get_network_name(),
        );

    let request = ResolveDnsRequest {
        query: query.to_vec(),
    };
    let rpc_call = stub.resolve_dns(BaseController::default(), request);

    match tokio::time::timeout(EXIT_NODE_RPC_TIMEOUT, rpc_call).await {
        Ok(Ok(resp)) if resp.error.is_empty() && !resp.response.is_empty() => {
            tracing::debug!(
                ?exit_node_peer_id,
                len = resp.response.len(),
                "resolved dns via exit node"
            );
            Some(resp.response)
        }
        Ok(Ok(resp)) => {
            tracing::warn!(
                ?exit_node_peer_id,
                error = %resp.error,
                "exit node failed to resolve dns"
            );
            None
        }
        Ok(Err(err)) => {
            tracing::warn!(?exit_node_peer_id, ?err, "exit node dns resolve rpc failed");
            None
        }
        Err(_) => {
            tracing::warn!(?exit_node_peer_id, "exit node dns resolve rpc timeout");
            None
        }
    }
}
