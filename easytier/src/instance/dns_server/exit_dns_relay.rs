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
///
/// 这个超时时间**直接决定魔法 DNS 的最坏延迟**：`handle_udp_packet` 是在 NIC 包处理管线里
/// **同步**调用本模块的（管线串行处理 TUN 收包），所以这里的每一次超时都会让整条数据面
/// 停顿同样长的时间。因此取一个"足够覆盖海外出口一次 DNS 往返"的保守小值（实测日本出口
/// ~80-100ms），而不是最初写死的 2 秒——那会在出口不可用时把 TUN 数据面堵死
/// （真机现象：开启 accept_dns 后整机断网，详见 `easytier-WG混淆与连接生命周期-方案评审.md`）。
const EXIT_DNS_QUERY_TIMEOUT: Duration = Duration::from_millis(400);

/// 熔断阈值：连续失败多少次后，暂停使用出口 DNS。
const EXIT_DNS_BREAKER_FAIL_THRESHOLD: u32 = 3;
/// 熔断时长：暂停期间所有查询直接回退本机上游，**不再产生任何网络等待**。
const EXIT_DNS_BREAKER_COOLDOWN: Duration = Duration::from_secs(30);

/// 出口 DNS 熔断器状态。
struct BreakerState {
    consecutive_failures: u32,
    unusable_until: Option<Instant>,
}

/// 出口 DNS 的熔断器（进程级）。
///
/// 目的：出口节点不可达（被墙 / 掉线 / 参数不一致）时，不能让**每个** DNS 查询都白等一次
/// 超时并阻塞 NIC 管线；连续失败后直接跳过出口路径，隔一段时间再放行一次探测。
static EXIT_DNS_BREAKER: Lazy<Mutex<BreakerState>> = Lazy::new(|| {
    Mutex::new(BreakerState {
        consecutive_failures: 0,
        unusable_until: None,
    })
});

/// 熔断器是否放行（不产生网络等待）。
fn breaker_allows() -> bool {
    let Ok(mut st) = EXIT_DNS_BREAKER.lock() else {
        return true;
    };
    match st.unusable_until {
        Some(until) if until > Instant::now() => false,
        Some(_) => {
            // 冷却结束：放行一次探测
            st.unusable_until = None;
            st.consecutive_failures = 0;
            true
        }
        None => true,
    }
}

/// 记录一次失败；达到阈值则进入冷却。
fn breaker_record_failure() {
    let Ok(mut st) = EXIT_DNS_BREAKER.lock() else {
        return;
    };
    st.consecutive_failures = st.consecutive_failures.saturating_add(1);
    if st.consecutive_failures >= EXIT_DNS_BREAKER_FAIL_THRESHOLD {
        st.unusable_until = Some(Instant::now() + EXIT_DNS_BREAKER_COOLDOWN);
        tracing::warn!(
            cooldown_secs = EXIT_DNS_BREAKER_COOLDOWN.as_secs(),
            "exit node dns keeps failing, disable it temporarily and use local upstream"
        );
    }
}

/// 记录一次成功（重置熔断器）。
fn breaker_record_success() {
    let Ok(mut st) = EXIT_DNS_BREAKER.lock() else {
        return;
    };
    st.consecutive_failures = 0;
    st.unusable_until = None;
}

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
///
/// **重要约束**：本函数是被 NIC 包处理管线**同步**调用的，管线串行处理 TUN 收包，
/// 因此这里绝不能长时间阻塞。所以：
/// * 命中缓存立即返回；
/// * 熔断期内（出口 DNS 连续失败）直接返回 `None`，**零网络等待**；
/// * 单次查询最多等 [`EXIT_DNS_QUERY_TIMEOUT`]（400ms）。
pub async fn resolve_external_query(peer_mgr: &Arc<PeerManager>, query: &[u8]) -> Option<Vec<u8>> {
    if !can_reach_tunnel_dns() {
        tracing::trace!("skip exit node dns resolving on this platform");
        return None;
    }

    if let Some(cached) = lookup_cache(query) {
        tracing::trace!("magic dns cache hit");
        return Some(cached);
    }

    // 熔断：出口 DNS 连续失败后，冷却期内不再产生任何等待（避免阻塞 NIC 管线）
    if !breaker_allows() {
        tracing::trace!("exit node dns is in cooldown, use local upstream directly");
        return None;
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
            breaker_record_success();
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
            breaker_record_failure();
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
