//! 客户端侧：把外部域名查询经隧道数据面交给**出口节点自建的 DNS 服务**（虚拟 IP:53）。
//!
//! 设计（对应《easytier-代码修复需求汇总版》3.3.1 / 3.3.2）：
//!
//! * 出口节点在 `enable_exit_node` 时于自己的虚拟 IP:53 上提供 DNS 服务
//!   （见 [`super::exit_dns_server`]），用**出口节点自身的系统 DNS**（通常位于海外、结果干净）
//!   解析外部域名，不需要客户端配置任何东西；
//! * 客户端启用魔法 DNS（`--accept-dns`）时，非虚拟网域名（非 `.et.net.`）的查询优先经隧道
//!   发给出口节点解析，避免落到本机被污染 / 被劫持的上游 DNS；
//! * 出口节点不可用、查询超时或失败时**返回 `None`**，调用方回退到本机上游（自定义上游或
//!   系统 DNS），绝不把客户端降级为境外 DNS 兜底（历史回归点）。
//!
//! 平台差异：Android 上 easytier 的核心进程被 `addDisallowedApplication` 排除在 VPN 之外，
//! 它自己创建的 socket 不会经过隧道，因此本模块在 Android 上直接返回 `None`；安卓端的正确
//! 做法是 `VpnService.addDnsServer(<出口虚拟 IP>)`，让 netd 把查询经隧道送出去。
//!
//! 为什么不用 peer-rpc 中继：RPC 是一条"尽力而为且静默失败"的链路（出口没运行新版本 / 出口
//! 判定不一致 / RPC 超时都会退化成坏上游），而直接查询出口的 DNS 服务是标准 DNS 语义，
//! 支持 TCP 重试与截断处理，且能在出口侧复用系统 DNS 的缓存。

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;

use crate::peers::peer_manager::PeerManager;

/// 单次向出口节点 DNS 服务查询的超时时间（UDP/TCP 各自计算）。
const EXIT_DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(2);

/// DNS 应答缓存的最大条目数（超过后整体清空，避免无限增长）。
const DNS_CACHE_MAX_ENTRIES: usize = 512;

/// 缓存条目的 TTL 下限 / 上限（秒）。
const DNS_CACHE_MIN_TTL: u32 = 5;
const DNS_CACHE_MAX_TTL: u32 = 300;
/// 无法从应答中解析出 TTL 时使用的默认缓存时间（秒）。
const DNS_CACHE_DEFAULT_TTL: u32 = 30;

struct CacheEntry {
    response: Vec<u8>,
    expires_at: Instant,
}

/// 原始查询报文（去掉前 2 字节事务 ID）-> 原始应答报文。
///
/// 同一域名会被系统 / 浏览器反复查询（Android netd 并发度很高），走隧道的查询有额外一跳，
/// 缓存能显著降低延迟与隧道内 DNS 流量。事务 ID 在命中时按新查询改写。
static DNS_CACHE: Lazy<Mutex<HashMap<Vec<u8>, CacheEntry>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// 本平台的核心进程 socket 是否能直接访问虚拟网络（隧道）。
///
/// Android 上核心进程被排除在 VPN 之外，直接查出口虚拟 IP 只会走运营商网络失败，
/// 因此不做无用尝试（否则每个查询都要白等一次超时）。
fn can_reach_tunnel_dns() -> bool {
    !cfg!(target_os = "android") && !cfg!(target_env = "ohos")
}

/// 按 `exit_nodes` 配置顺序，选择第一个仍在线的出口节点地址（仅 IPv4）。
pub async fn select_online_exit_ip(peer_mgr: &PeerManager) -> Option<IpAddr> {
    for exit_node in peer_mgr.get_global_ctx().config.get_exit_nodes() {
        if !matches!(exit_node, IpAddr::V4(_)) {
            continue;
        }
        if peer_mgr.is_exit_node_online(&exit_node).await {
            return Some(exit_node);
        }
        tracing::debug!(
            ?exit_node,
            "exit node is offline, try the next one for dns resolving"
        );
    }
    None
}

/// 从缓存取出应答，并按当前查询改写事务 ID。
fn lookup_cache(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() <= 2 {
        return None;
    }
    let key = query[2..].to_vec();
    let mut cache = DNS_CACHE.lock().ok()?;
    let entry = cache.get(&key)?;
    if entry.expires_at <= Instant::now() {
        cache.remove(&key);
        return None;
    }
    let mut response = entry.response.clone();
    response[0] = query[0];
    response[1] = query[1];
    Some(response)
}

/// 解析应答报文中可缓存的最小 TTL（秒）。
fn response_ttl(response: &[u8]) -> u32 {
    use hickory_proto::op::Message;

    let Ok(msg) = Message::from_vec(response) else {
        return DNS_CACHE_DEFAULT_TTL;
    };
    if msg.response_code() != hickory_proto::op::ResponseCode::NoError {
        return 0;
    }
    let ttl = msg
        .answers()
        .iter()
        .map(|r| r.ttl())
        .min()
        .unwrap_or(DNS_CACHE_DEFAULT_TTL);
    ttl.clamp(DNS_CACHE_MIN_TTL, DNS_CACHE_MAX_TTL)
}

/// 缓存应答报文。
fn store_cache(query: &[u8], response: &[u8]) {
    if query.len() <= 2 || response.len() < 12 {
        return;
    }
    let ttl = response_ttl(response);
    if ttl == 0 {
        return;
    }
    let Ok(mut cache) = DNS_CACHE.lock() else {
        return;
    };
    if cache.len() >= DNS_CACHE_MAX_ENTRIES {
        cache.clear();
    }
    cache.insert(
        query[2..].to_vec(),
        CacheEntry {
            response: response.to_vec(),
            expires_at: Instant::now() + Duration::from_secs(ttl as u64),
        },
    );
}

/// 本节点禁用 IPv6 时，剔除应答中的 AAAA 记录，避免上层优先使用 IPv6 造成连接黑洞。
///
/// 返回 `Some` 表示应答已被改写。
fn strip_aaaa_records(response: &[u8]) -> Option<Vec<u8>> {
    use hickory_proto::op::Message;
    use hickory_proto::rr::RecordType;

    let mut msg = Message::from_vec(response).ok()?;
    let before = msg.answers().len();
    msg.answers_mut()
        .retain(|r| r.record_type() != RecordType::AAAA);
    if msg.answers().len() == before {
        return None;
    }
    msg.to_vec().ok()
}

/// 向出口节点的 DNS 服务（虚拟 IP:53）发起一次查询。
///
/// 先 UDP；应答被截断（TC=1）时改用 TCP 重试——出口节点侧的服务同时监听 UDP 与 TCP。
async fn query_exit_dns_service(exit_ip: IpAddr, query: &[u8]) -> Result<Vec<u8>, String> {
    let addr = SocketAddr::new(exit_ip, 53);
    let udp_response = query_exit_dns_udp(addr, query).await?;

    // TC 位（第 3 字节 bit 1）表示应答被截断，需要改用 TCP 重新查询
    if udp_response.len() >= 4 && (udp_response[2] & 0x02) != 0 {
        tracing::debug!(?addr, "exit dns response truncated, retry over tcp");
        return query_exit_dns_tcp(addr, query).await;
    }

    Ok(udp_response)
}

async fn query_exit_dns_udp(addr: SocketAddr, query: &[u8]) -> Result<Vec<u8>, String> {
    let socket = tokio::net::UdpSocket::bind(("0.0.0.0", 0))
        .await
        .map_err(|e| format!("bind udp socket for exit dns failed: {}", e))?;
    socket
        .connect(addr)
        .await
        .map_err(|e| format!("connect exit dns {} failed: {}", addr, e))?;

    let query_once = async {
        socket.send(query).await?;
        let mut buf = vec![0u8; 4096];
        let len = socket.recv(&mut buf).await?;
        Ok::<_, std::io::Error>(buf[..len].to_vec())
    };

    match tokio::time::timeout(EXIT_DNS_QUERY_TIMEOUT, query_once).await {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(e)) => Err(format!("query exit dns {} failed: {}", addr, e)),
        Err(_) => Err(format!("query exit dns {} timeout", addr)),
    }
}

async fn query_exit_dns_tcp(addr: SocketAddr, query: &[u8]) -> Result<Vec<u8>, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let query_once = async {
        let mut stream = tokio::net::TcpStream::connect(addr).await?;
        let mut framed = Vec::with_capacity(query.len() + 2);
        framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
        framed.extend_from_slice(query);
        stream.write_all(&framed).await?;

        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await?;
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut response = vec![0u8; len];
        stream.read_exact(&mut response).await?;
        Ok::<_, std::io::Error>(response)
    };

    match tokio::time::timeout(EXIT_DNS_QUERY_TIMEOUT, query_once).await {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(e)) => Err(format!("query exit dns {} over tcp failed: {}", addr, e)),
        Err(_) => Err(format!("query exit dns {} over tcp timeout", addr)),
    }
}

/// 尝试经隧道把外部域名查询交给出口节点解析。
///
/// 返回 `None` 表示"无法经出口解析"，调用方必须回退到本机上游。
pub async fn resolve_external_query(peer_mgr: &Arc<PeerManager>, query: &[u8]) -> Option<Vec<u8>> {
    if !can_reach_tunnel_dns() {
        tracing::trace!("skip exit node dns resolving on this platform");
        return None;
    }

    if let Some(cached) = lookup_cache(query) {
        tracing::trace!("magic dns cache hit");
        return Some(cached);
    }

    let exit_ip = match select_online_exit_ip(peer_mgr.as_ref()).await {
        Some(ip) => ip,
        None => {
            tracing::debug!("no online exit node, magic dns falls back to local upstream");
            return None;
        }
    };

    match query_exit_dns_service(exit_ip, query).await {
        Ok(mut response) => {
            if !peer_mgr.get_global_ctx().enable_ipv6_addr()
                && let Some(stripped) = strip_aaaa_records(&response)
            {
                tracing::debug!("ipv6 is disabled, strip aaaa records from exit dns response");
                response = stripped;
            }
            store_cache(query, &response);
            tracing::debug!(?exit_ip, len = response.len(), "resolved via exit node dns");
            Some(response)
        }
        Err(e) => {
            tracing::warn!(
                ?exit_ip,
                error = %e,
                "query exit node dns failed, magic dns falls back to local upstream"
            );
            None
        }
    }
}

/// 汇总当前出口节点 DNS 服务可用性，用于排障日志（出口 IP、是否在线）。
pub async fn describe_exit_nodes(peer_mgr: &PeerManager) -> Vec<(IpAddr, bool)> {
    let mut ret = Vec::new();
    for exit_node in peer_mgr.get_global_ctx().config.get_exit_nodes() {
        let online = peer_mgr.is_exit_node_online(&exit_node).await;
        ret.push((exit_node, online));
    }
    ret
}
