use std::{
    fmt::{Debug, Formatter},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use super::{
    FromUrl, IpVersion, Tunnel, TunnelError, TunnelInfo, TunnelListener, TunnelUrl, ZCPacketSink,
    ZCPacketStream,
    common::wait_for_connect_futures,
    generate_digest_from_str,
    packet_def::{PEER_MANAGER_HEADER_SIZE, ZCPacketType},
    ring::create_ring_tunnel_pair,
};
use crate::tunnel::common::{BindDev, bind};
use crate::{
    common::{config::Flags, global_ctx::ArcGlobalCtx, shrink_dashmap},
    tunnel::{
        build_url_from_socket_addr,
        common::TunnelWrapper,
        packet_def::{WG_TUNNEL_HEADER_SIZE, ZCPacket},
    },
};
use anyhow::Context;
use async_recursion::async_recursion;
use async_trait::async_trait;
use boringtun::{
    noise::{Tunn, TunnResult, errors::WireGuardError},
    x25519::{PublicKey, StaticSecret},
};
use bytes::BytesMut;
use crossbeam::atomic::AtomicCell;
use dashmap::DashMap;
use futures::{SinkExt, StreamExt, stream::FuturesUnordered};
use rand::RngCore;
use tokio::{net::UdpSocket, sync::Mutex, task::JoinSet};

const MAX_PACKET: usize = 2048;

/// 混淆填充余量：单个报文最多追加/前置 64 字节填充（`s1..s3` ≤ 64、`s4` ≤ 32）。
const MAX_OBFS_PADDING: usize = 64;

/// UDP 收包缓冲：`MAX_PACKET` + 混淆填充余量。
/// 混淆 junk 包最长 1024 字节，也落在此范围内，不会被截断成错误的长度。
const MAX_UDP_RECV: usize = MAX_PACKET + MAX_OBFS_PADDING;

/// WireGuard 报文类型（线格式前 4 字节小端 u32，与 boringtun `parse_incoming_packet` 一致）。
const WG_MSG_HANDSHAKE_INIT: u32 = 1;
const WG_MSG_HANDSHAKE_RESPONSE: u32 = 2;
const WG_MSG_COOKIE_REPLY: u32 = 3;
const WG_MSG_DATA: u32 = 4;

/// 未混淆时各类型报文的固定长度（与 boringtun 内部常量 `HANDSHAKE_INIT_SZ` 等一致）。
const WG_HANDSHAKE_INIT_SIZE: usize = 148;
const WG_HANDSHAKE_RESPONSE_SIZE: usize = 92;
const WG_COOKIE_REPLY_SIZE: usize = 64;

/// 混淆参数上限（钳制用，见 [`WgObfsConfig::from_flags`]）。
const WG_OBFS_S1_TO_S3_MAX: u8 = 64;
const WG_OBFS_S4_MAX: u8 = 32;
const WG_OBFS_JC_MAX: u8 = 10;
const WG_OBFS_JUNK_MIN: u16 = 64;
const WG_OBFS_JUNK_MAX: u16 = 1024;

/// B1 客户端握手等待超时：发出 Init 后在该时间内未「收到合法握手报文且会话已建立」即失败。
///
/// 取 5s：与 boringtun 的 `REKEY_TIMEOUT`（5s）对齐，覆盖一次 Init 强制重传
/// （重传间隔见 [`WG_HANDSHAKE_RETRY_INTERVAL`]），同时不让上层 PeerManager 的重试等待过久。
/// 关键点：超时后返回 `Err`，**绝不返回一个会话未建立的隧道**。
const WG_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// B1 握手等待期内 Init 的强制重传间隔（此时 peer 的 routine_task 尚未启动，由等待循环补发）。
const WG_HANDSHAKE_RETRY_INTERVAL: Duration = Duration::from_millis(2000);

/// B2 服务端握手超时：peer 在该时间内未「握手双向确认」则视为半连接，从 peer_map 移除并停止。
const WG_PEER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// 已完成握手的 peer 的空闲回收阈值（沿用既有 61s 行为，不做收紧）。
const WG_PEER_IDLE_TIMEOUT: Duration = Duration::from_secs(61);

/// WG 混淆参数（AmneziaWG 式）。两端必须完全一致，否则无法握手。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WgObfsConfig {
    pub s1: u8, // Init 包前随机填充
    pub s2: u8, // Response 包前随机填充
    pub s3: u8, // Cookie 包前随机填充
    pub s4: u8, // Data 包尾追加
    pub jc: u8, // 握手前 junk 包数量
    pub jmin: u16,
    pub jmax: u16,
}

impl WgObfsConfig {
    /// 内置默认值。
    ///
    /// 刻意避开 AmneziaWG 官方默认值（s1=50 / s2=100 / s3=20 / s4=0 / jc=4 / jmin=50 / jmax=1000），
    /// 且 junk 长度区间 `[jmin, jmax] = [200, 260]` **不包含**握手包混淆后的长度
    /// `148+s1=185`、`92+s2=134`、`64+s3=83`，避免把握手包误判成 junk 而丢弃。
    pub const BUILTIN_DEFAULT: WgObfsConfig = WgObfsConfig {
        s1: 37,
        s2: 42,
        s3: 19,
        s4: 11,
        jc: 4,
        jmin: 200,
        jmax: 260,
    };

    /// 从实例配置解析混淆参数。
    ///
    /// - `flags.wg_obfs != Some(true)` → `None`：原生 WireGuard，完全透传，本文件不做任何改动；
    /// - 否则以 [`Self::BUILTIN_DEFAULT`] 为基准，用 `wg_obfs_s1/s2/s3/s4/jc/jmin/jmax`
    ///   （`Some` 才覆盖）逐项覆盖；
    /// - 所有越界/非法值都 `warn!` 后**钳制**（确定性处理：两端同输入必然得到同结果，
    ///   这是两端参数一致的前提），绝不 panic；
    /// - 若 `[jmin, jmax]` 与 `{148+s1, 92+s2, 64+s3}` 有交集 → `warn!` 并把 `jc` 置 0
    ///   （不发送 junk），避免把握手包误判为 junk。
    pub fn from_flags(flags: &Flags) -> Option<WgObfsConfig> {
        if flags.wg_obfs != Some(true) {
            return None;
        }

        let default = Self::BUILTIN_DEFAULT;
        let s1 = clamp_obfs_u8(
            "wg_obfs_s1",
            flags.wg_obfs_s1,
            WG_OBFS_S1_TO_S3_MAX,
            default.s1,
        );
        let s2 = clamp_obfs_u8(
            "wg_obfs_s2",
            flags.wg_obfs_s2,
            WG_OBFS_S1_TO_S3_MAX,
            default.s2,
        );
        let s3 = clamp_obfs_u8(
            "wg_obfs_s3",
            flags.wg_obfs_s3,
            WG_OBFS_S1_TO_S3_MAX,
            default.s3,
        );
        let s4 = clamp_obfs_u8("wg_obfs_s4", flags.wg_obfs_s4, WG_OBFS_S4_MAX, default.s4);
        let mut jc = clamp_obfs_u8("wg_obfs_jc", flags.wg_obfs_jc, WG_OBFS_JC_MAX, default.jc);
        let jmin = clamp_obfs_junk("wg_obfs_jmin", flags.wg_obfs_jmin, default.jmin);
        let mut jmax = clamp_obfs_junk("wg_obfs_jmax", flags.wg_obfs_jmax, default.jmax);
        if jmin > jmax {
            tracing::warn!(
                jmin,
                jmax,
                "wg 混淆：jmin > jmax，已把 jmax 提升到 jmin（确定性钳制）"
            );
            jmax = jmin;
        }

        // junk 长度区间不能包含握手包混淆后的长度，否则对端会把真正的手握包当 junk 丢弃。
        let handshake_lens = [
            WG_HANDSHAKE_INIT_SIZE + s1 as usize,
            WG_HANDSHAKE_RESPONSE_SIZE + s2 as usize,
            WG_COOKIE_REPLY_SIZE + s3 as usize,
        ];
        if handshake_lens
            .iter()
            .any(|len| (jmin as usize..=jmax as usize).contains(len))
        {
            tracing::warn!(
                ?handshake_lens,
                jmin,
                jmax,
                "wg 混淆：junk 长度区间与握手包长度重叠，已关闭 junk 发送（jc=0）"
            );
            jc = 0;
        }

        Some(WgObfsConfig {
            s1,
            s2,
            s3,
            s4,
            jc,
            jmin,
            jmax,
        })
    }

    /// 是否需要在建立阶段发送 junk 包。
    fn junk_enabled(&self) -> bool {
        self.jc > 0
    }
}

/// 混淆参数（u8 类）钳制：`None` = 用默认值；越界 → `warn!` 后取上限。
fn clamp_obfs_u8(name: &str, value: Option<u32>, max: u8, default: u8) -> u8 {
    match value {
        None => default,
        Some(v) if v > max as u32 => {
            tracing::warn!(
                field = name,
                value = v,
                max,
                "wg 混淆参数越界，已钳制到上限"
            );
            max
        }
        Some(v) => v as u8,
    }
}

/// junk 长度钳制：`None` = 用默认值；越界 → `warn!` 后钳制进 `[WG_OBFS_JUNK_MIN, WG_OBFS_JUNK_MAX]`。
fn clamp_obfs_junk(name: &str, value: Option<u32>, default: u16) -> u16 {
    match value {
        None => default,
        Some(v) => {
            let clamped = v.clamp(WG_OBFS_JUNK_MIN as u32, WG_OBFS_JUNK_MAX as u32) as u16;
            if clamped as u32 != v {
                tracing::warn!(
                    field = name,
                    value = v,
                    min = WG_OBFS_JUNK_MIN,
                    max = WG_OBFS_JUNK_MAX,
                    "wg 混淆 junk 长度越界，已钳制"
                );
            }
            clamped
        }
    }
}

/// 读取线格式前 4 字节小端 u32（报文类型）；长度不足 4 字节时返回 `None`。
fn read_wg_msg_type(data: &[u8]) -> Option<u32> {
    if data.len() < 4 {
        return None;
    }
    Some(u32::from_le_bytes(data[..4].try_into().unwrap()))
}

/// A3 线格式（发送方向）：按混淆配置编码一个要发往对端的报文。
///
/// 返回 `None` 表示「原样发送」：未开启混淆（`obfs == None`，保证原生兼容），
/// 或该报文类型不应出现（`debug!` 后原样发送）。
fn encode_wg_packet(data: &[u8], obfs: Option<WgObfsConfig>) -> Option<Vec<u8>> {
    let obfs = obfs?;
    let msg_type = match read_wg_msg_type(data) {
        Some(t) => t,
        None => {
            tracing::debug!(
                len = data.len(),
                "wg 混淆：报文不足 4 字节，无法判定类型，按原样发送"
            );
            return None;
        }
    };

    let pad = match msg_type {
        WG_MSG_HANDSHAKE_INIT => obfs.s1,
        WG_MSG_HANDSHAKE_RESPONSE => obfs.s2,
        WG_MSG_COOKIE_REPLY => obfs.s3,
        WG_MSG_DATA => obfs.s4,
        other => {
            tracing::debug!(other, "wg 混淆：未知报文类型，按原样发送");
            return None;
        }
    };
    if pad == 0 {
        // 该类型不需要填充：直接原样发送，省一次拷贝
        return None;
    }

    let mut out = vec![0u8; data.len() + pad as usize];
    let mut rng = rand::thread_rng();
    if msg_type == WG_MSG_DATA {
        // Data：填充追加到尾部（接收端剥掉尾部 s4 字节）
        out[..data.len()].copy_from_slice(data);
        rng.fill_bytes(&mut out[data.len()..]);
    } else {
        // Init / Response / Cookie：填充插到头部（接收端剥掉头部 sN 字节）
        rng.fill_bytes(&mut out[..pad as usize]);
        out[pad as usize..].copy_from_slice(data);
    }
    Some(out)
}

/// A4 线格式（接收方向）解码结果。
enum WgDecodedPacket<'a> {
    /// 可以交给 boringtun 处理的报文（已剥离混淆填充）
    Packet { msg_type: u32, payload: &'a [u8] },
    /// 混淆 junk / 无法识别 / 长度非法 → 丢弃
    Junk(&'static str),
}

/// A4 线格式（接收方向）：解码一个从 UDP 收到的报文。
///
/// `obfs == None` → 原样透传给 boringtun（保持既有原生行为，不做任何丢弃）。
///
/// 开启混淆时**必须同时校验长度与「剥离后前 4 字节的消息类型」**，避免把握手包与数据包互相误判：
/// 1. `len == 148+s1` 且剥离 s1 后类型为 1 → Init；
///    `len == 92+s2` 且剥离 s2 后类型为 2 → Response；
///    `len == 64+s3` 且剥离 s3 后类型为 3 → Cookie；
/// 2. 否则：若该 peer **尚未建立会话**且 `jmin <= len <= jmax` → junk，丢弃；
///    （会话建立后同长度的报文按 Data 处理，不会误丢真实数据）
/// 3. 其余 → 视为 Data：剥掉**尾部 s4** 字节（`len <= s4` 则丢弃）；
///    `msg_type` 取剥离后报文的前 4 字节，供调用方判断是否是握手类报文。
fn decode_wg_packet<'a>(
    data: &'a [u8],
    obfs: Option<WgObfsConfig>,
    session_established: bool,
) -> WgDecodedPacket<'a> {
    let Some(obfs) = obfs else {
        return WgDecodedPacket::Packet {
            msg_type: read_wg_msg_type(data).unwrap_or(0),
            payload: data,
        };
    };

    // 1) 握手类报文：长度 + 类型双重校验
    for (msg_type, base_len, pad) in [
        (WG_MSG_HANDSHAKE_INIT, WG_HANDSHAKE_INIT_SIZE, obfs.s1),
        (
            WG_MSG_HANDSHAKE_RESPONSE,
            WG_HANDSHAKE_RESPONSE_SIZE,
            obfs.s2,
        ),
        (WG_MSG_COOKIE_REPLY, WG_COOKIE_REPLY_SIZE, obfs.s3),
    ] {
        let pad = pad as usize;
        if data.len() == base_len + pad && read_wg_msg_type(&data[pad..]) == Some(msg_type) {
            return WgDecodedPacket::Packet {
                msg_type,
                payload: &data[pad..],
            };
        }
    }

    // 2) junk：仅在对端尚未建立会话时判定，避免误丢长度恰好落在 junk 区间内的真实数据包
    if !session_established && (obfs.jmin as usize..=obfs.jmax as usize).contains(&data.len()) {
        return WgDecodedPacket::Junk("会话未建立时收到的 junk 包");
    }

    // 3) 其余按 Data 处理：剥掉尾部 s4 填充
    if data.len() <= obfs.s4 as usize {
        return WgDecodedPacket::Junk("长度不足以剥离 s4 尾部填充");
    }
    let payload = &data[..data.len() - obfs.s4 as usize];
    WgDecodedPacket::Packet {
        msg_type: read_wg_msg_type(payload).unwrap_or(0),
        payload,
    }
}

/// A3：按混淆配置编码后把报文发到 `endpoint`（`None` = 原样发送）。
///
/// 本文件内**所有**通过 UDP 发往对端的报文都必须走这里（含握手/keepalive/数据/Cookie）。
async fn send_encoded_packet(
    udp: &UdpSocket,
    endpoint: SocketAddr,
    obfs: Option<WgObfsConfig>,
    packet: &[u8],
) -> std::io::Result<usize> {
    match encode_wg_packet(packet, obfs) {
        Some(encoded) => udp.send_to(&encoded, endpoint).await,
        None => udp.send_to(packet, endpoint).await,
    }
}

/// A3：在「本端即将发起握手」时发送 `jc` 个长度 `[jmin, jmax]` 随机、内容随机的 junk 包。
///
/// - 长度区间在构建配置时已保证不与握手包长度重叠（见 [`WgObfsConfig::from_flags`]）；
/// - 只在建立阶段发送（客户端在首次 Init 之前、服务端在为新 peer 回握手之前），
///   调用点保证顺序：junk → 握手包，之后不再发送。
async fn send_obfs_junk_packets(udp: &UdpSocket, endpoint: SocketAddr, obfs: WgObfsConfig) {
    if !obfs.junk_enabled() {
        return;
    }

    // 注意：`rand::thread_rng()` 不是 `Send`，绝不能跨 `await` 持有，否则调用方的
    // future 会变成非 `Send`（tokio::spawn 会直接编译失败）。因此先在同步块里把
    // 所有 junk 包生成完，再逐个发送。
    let junk_packets: Vec<Vec<u8>> = {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let span = (obfs.jmax - obfs.jmin) as u32;
        (0..obfs.jc)
            .map(|_| {
                let len = if span == 0 {
                    obfs.jmin as usize
                } else {
                    obfs.jmin as usize + (rng.next_u32() % (span + 1)) as usize
                };
                let mut junk = vec![0u8; len];
                rng.fill_bytes(&mut junk);
                junk
            })
            .collect()
    };

    for (seq, junk) in junk_packets.iter().enumerate() {
        if let Err(e) = udp.send_to(junk, endpoint).await {
            tracing::debug!(?endpoint, seq, "wg 混淆：发送 junk 包失败: {}", e);
            return;
        }
    }
    tracing::debug!(
        ?endpoint,
        jc = obfs.jc,
        jmin = obfs.jmin,
        jmax = obfs.jmax,
        "wg 混淆：已发送建立阶段 junk 包"
    );
}

/// 「会话已建立」判定（A4 与任务 B 共用的 helper）。
///
/// 本仓库 boringtun（`boringtun-easytier` 0.6.1）提供 `Tunn::time_since_last_handshake()`
/// （见 boringtun `src/noise/timers.rs`）：`Some(_)` 表示当前会话已建立，`None` 表示尚未完成握手。
/// 因此不需要「收到/发出过 type 2 或 type 4」的回退判据。
///
/// 语义细节（对 B2 很重要）：boringtun 只在**当前会话**（`Tunn::current`）上报告握手时间，
/// 而 responder 收到 Init 时只写入 session、不设置 `current`（只有收到对端的 data/keepalive
/// 或本端作为 initiator 收到 Response 才会 `set_current_session`）。因此本 helper 表示的是
/// 「握手已推进到本端可用的会话」，而不是「刚收到一个 Init」。
async fn tunn_session_established(tunn: &Mutex<Tunn>) -> bool {
    tunn.lock().await.time_since_last_handshake().is_some()
}

/// 补充项 4.4：wg connector 复用外层隧道的代码层防回环（第二道保险）。
///
/// 当 wg connector 的目标是 peer 的**物理地址**（公网/直连地址）时，是否禁用
/// 「显式绑定接口地址」的 connect fan-out（只允许直连，不回退到外层隧道）。
///
/// 默认 `true` = 新行为：物理目标只做直连，绝不把 socket 钉在可能属于虚拟网络的接口
/// 地址上。`bind_device` 默认为 `true`，`create_connector_by_url` 会把本机所有接口
/// 地址（Windows 上含 EasyTier TUN 的虚拟网地址）都塞进 `bind_addrs`；一旦 wg
/// connector 绑定到该虚拟网地址，socket 会被绑定到 TUN 设备（Windows 为
/// `IP_UNICAST_IF`，Linux 为 `SO_BINDTODEVICE`），wg 握手包直接进入外层隧道，
/// 经出口节点代理 NAT 改写源地址后回环到出口自身的 wg listener，形成回环风暴。
///
/// 需要灰度回滚本项时，把本常量改为 `false` 即可，无需改动其它文件。
const WG_DIRECT_ONLY_FOR_PHYSICAL_DST: bool = true;

/// 保守判断一个 IPv4 地址是否「一定是物理（公网）地址」。
///
/// 只有在拿不到 `GlobalCtx` 时才会用到本兜底判定（参见
/// `WgTunnelConnector::dst_is_in_virtual_network`）：公网单播地址不可能是本虚拟
/// 网络的地址，因此可以安全地按物理地址处理；私网 / 环回 / 链路本地 / 共享地址
/// （100.64.0.0/10，覆盖 Magic DNS 假 IP 100.100.100.101）等一律按「可能是虚拟网
/// 地址」处理，保持原有行为（允许复用外层隧道）。
fn is_definitely_physical_addr_v4(v4: &Ipv4Addr) -> bool {
    let o = v4.octets();
    !(v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_documentation()
        || v4.is_unspecified()
        || v4.is_multicast()
        // 100.64.0.0/10 共享地址（CGNAT），Magic DNS 假 IP 100.100.100.101 落在此段内
        || (o[0] == 100 && (o[1] & 0xc0) == 64))
}

/// 保守判断目标地址是否「一定是物理（公网）地址」，见 `is_definitely_physical_addr_v4`。
fn is_definitely_physical_addr(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_definitely_physical_addr_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_definitely_physical_addr_v4(&v4);
            }
            let seg = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // fe80::/10 链路本地
                || (seg[0] & 0xffc0) == 0xfe80
                // fc00::/7 唯一本地地址
                || (v6.octets()[0] & 0xfe) == 0xfc)
        }
    }
}

#[derive(Debug, Clone)]
enum WgType {
    // used by easytier peer, need remove/add ip header for in/out wg msg
    InternalUse,
    // used by wireguard peer, keep original ip header
    ExternalUse,
}

#[derive(Clone)]
pub struct WgConfig {
    my_secret_key: StaticSecret,
    my_public_key: PublicKey,

    peer_secret_key: StaticSecret,
    peer_public_key: PublicKey,

    wg_type: WgType,

    /// WG 混淆参数（A1/A2）。`None` = 原生 WireGuard（完全透传，不做任何改动），
    /// 由 connector/listener 通过 [`WgConfig::with_obfs`] 注入实例配置（见 `Flags`）。
    obfs: Option<WgObfsConfig>,
}

impl WgConfig {
    pub fn new_from_network_identity(network_name: &str, network_secret: &str) -> Self {
        let mut my_sec = [0u8; 32];
        generate_digest_from_str(network_name, network_secret, &mut my_sec);

        let my_secret_key = StaticSecret::from(my_sec);
        let my_public_key = PublicKey::from(&my_secret_key);
        let peer_secret_key = StaticSecret::from(my_sec);
        let peer_public_key = my_public_key;

        WgConfig {
            my_secret_key,
            my_public_key,
            peer_secret_key,
            peer_public_key,

            wg_type: WgType::InternalUse,

            // 默认原生 WireGuard：是否开启混淆由实例配置（Flags）决定
            obfs: None,
        }
    }

    pub fn new_for_portal(server_key_seed: &str, client_key_seed: &str) -> Self {
        let server_cfg = Self::new_from_network_identity("server", server_key_seed);
        let client_cfg = Self::new_from_network_identity("client", client_key_seed);
        Self {
            my_secret_key: server_cfg.my_secret_key,
            my_public_key: server_cfg.my_public_key,
            peer_secret_key: client_cfg.my_secret_key,
            peer_public_key: client_cfg.my_public_key,

            wg_type: WgType::ExternalUse,

            obfs: None,
        }
    }

    /// 设置混淆参数（`None` = 原生 WireGuard）。新增 builder 方法，不改既有构造函数签名。
    pub fn with_obfs(mut self, obfs: Option<WgObfsConfig>) -> Self {
        self.obfs = obfs;
        self
    }

    /// 当前混淆参数（`None` = 原生 WireGuard）。
    pub fn obfs(&self) -> Option<WgObfsConfig> {
        self.obfs
    }

    /// 便捷方法：直接按实例配置（`Flags`）应用混淆，等价于
    /// `self.with_obfs(WgObfsConfig::from_flags(flags))`。
    pub fn with_obfs_from_flags(self, flags: &Flags) -> Self {
        self.with_obfs(WgObfsConfig::from_flags(flags))
    }

    pub fn my_secret_key(&self) -> &[u8] {
        self.my_secret_key.as_bytes()
    }

    pub fn peer_secret_key(&self) -> &[u8] {
        self.peer_secret_key.as_bytes()
    }

    pub fn my_public_key(&self) -> &[u8] {
        self.my_public_key.as_bytes()
    }

    pub fn peer_public_key(&self) -> &[u8] {
        self.peer_public_key.as_bytes()
    }
}

#[derive(Clone)]
struct WgPeerData {
    udp: Arc<UdpSocket>, // only for send
    endpoint: SocketAddr,
    tunn: Arc<Mutex<Tunn>>,
    wg_type: WgType,
    stopped: Arc<AtomicBool>,
    /// A3/A4：混淆参数。`None` = 原样收发（原生 WireGuard）。
    obfs: Option<WgObfsConfig>,
}

impl Debug for WgPeerData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgPeerData")
            .field("endpoint", &self.endpoint)
            .field("local", &self.udp.local_addr())
            .finish()
    }
}

impl WgPeerData {
    /// A3：按混淆配置编码后发送到本 peer 的 UDP endpoint。
    async fn send_encoded_to_peer(&self, packet: &[u8]) -> std::io::Result<usize> {
        send_encoded_packet(&self.udp, self.endpoint, self.obfs, packet).await
    }

    #[tracing::instrument]
    async fn handle_one_packet_from_me(&self, zc_packet: ZCPacket) -> Result<(), anyhow::Error> {
        let mut send_buf = vec![0u8; MAX_PACKET];

        let packet = if matches!(self.wg_type, WgType::InternalUse) {
            let mut zc_packet = zc_packet.convert_type(ZCPacketType::WG);
            Self::fill_ip_header(&mut zc_packet);
            zc_packet.into_bytes()
        } else {
            zc_packet.convert_type(ZCPacketType::WG).into_bytes()
        };
        tracing::trace!(?packet, "Sending packet to peer");

        let encapsulate_result = {
            let mut peer = self.tunn.lock().await;
            peer.encapsulate(&packet, &mut send_buf)
        };

        tracing::trace!(
            ?encapsulate_result,
            "Received {} bytes from me",
            packet.len()
        );

        match encapsulate_result {
            TunnResult::WriteToNetwork(packet) => {
                self.send_encoded_to_peer(packet)
                    .await
                    .context("Failed to send encrypted IP packet to WireGuard endpoint.")?;
                tracing::debug!(
                    "Sent {} bytes to WireGuard endpoint (encrypted IP packet)",
                    packet.len()
                );
            }
            TunnResult::Err(e) => {
                tracing::error!("Failed to encapsulate IP packet: {:?}", e);
            }
            TunnResult::Done => {
                // Ignored
            }
            other => {
                tracing::error!(
                    "Unexpected WireGuard state during encapsulation: {:?}",
                    other
                );
            }
        };
        Ok(())
    }

    /// WireGuard consumption task. Receives encrypted packets from the WireGuard endpoint,
    /// decapsulates them, and dispatches newly received IP packets.
    ///
    /// A4：入站报文在此统一解码（去混淆填充 / 丢弃 junk）；`obfs == None` 时原样交给 boringtun。
    ///
    /// 返回值：本包是否为「被 boringtun 成功接受的对端加密数据/keepalive 报文」，
    /// 即「对端已能用本次会话加密」的证据（B2 判断握手是否双向确认的依据之一）。
    #[tracing::instrument(skip(sink))]
    pub async fn handle_one_packet_from_peer<S: ZCPacketSink + Unpin>(
        &self,
        mut sink: S,
        recv_buf: &[u8],
    ) -> bool {
        let mut send_buf = vec![0u8; MAX_PACKET];

        // 解码前先取「本包处理前」的会话状态：会话建立后，长度落在 junk 区间的报文按 Data 处理
        let session_established = tunn_session_established(&self.tunn).await;
        let (msg_type, data) = match decode_wg_packet(recv_buf, self.obfs, session_established) {
            WgDecodedPacket::Packet { msg_type, payload } => (msg_type, payload),
            WgDecodedPacket::Junk(reason) => {
                tracing::debug!(
                    len = recv_buf.len(),
                    reason,
                    "wg 收到并丢弃无法识别的报文（混淆 junk / 长度非法）"
                );
                return false;
            }
        };
        let is_data_packet = msg_type == WG_MSG_DATA;

        let decapsulate_result = {
            let mut peer = self.tunn.lock().await;
            peer.decapsulate(None, data, &mut send_buf)
        };

        tracing::debug!("Decapsulation result: {:?}", decapsulate_result);

        let mut data_accepted = false;
        match decapsulate_result {
            TunnResult::WriteToNetwork(packet) => {
                match self.send_encoded_to_peer(packet).await {
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!(
                            "Failed to send decapsulation-instructed packet to WireGuard endpoint: {:?}",
                            e
                        );
                        return false;
                    }
                };
                let mut peer = self.tunn.lock().await;
                loop {
                    let mut send_buf = vec![0u8; MAX_PACKET];
                    match peer.decapsulate(None, &[], &mut send_buf) {
                        TunnResult::WriteToNetwork(packet) => {
                            match self.send_encoded_to_peer(packet).await {
                                Ok(_) => {}
                                Err(e) => {
                                    tracing::error!(
                                        "Failed to send decapsulation-instructed packet to WireGuard endpoint: {:?}",
                                        e
                                    );
                                    break;
                                }
                            };
                        }
                        _ => {
                            break;
                        }
                    }
                }
            }
            TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                tracing::debug!(
                    ?packet,
                    "receive IP packet from peer: {} bytes",
                    packet.len()
                );
                let mut b = BytesMut::new();
                if matches!(self.wg_type, WgType::InternalUse) {
                    b.resize(WG_TUNNEL_HEADER_SIZE, 0);
                    b.extend_from_slice(self.remove_ip_header(packet, packet[0] >> 4 == 4));
                } else {
                    b.extend_from_slice(packet);
                };
                let zc_packet = ZCPacket::new_from_buf(b, ZCPacketType::WG);
                tracing::trace!(?zc_packet, "forward zc_packet to sink");
                let ret = sink.send(zc_packet).await;
                if ret.is_err() {
                    tracing::error!("Failed to send packet to tunnel: {:?}", ret);
                }
                data_accepted = true;
            }
            TunnResult::Done => {
                // 空 payload 的 Data 报文（keepalive）同样证明对端已能用该会话加密
                data_accepted = is_data_packet;
            }
            other => {
                tracing::debug!(
                    "Unexpected WireGuard state during decapsulation: {:?}",
                    other
                );
            }
        }

        data_accepted
    }

    #[tracing::instrument]
    #[async_recursion]
    async fn handle_routine_tun_result<'a: 'async_recursion>(&self, result: TunnResult<'a>) -> () {
        match result {
            TunnResult::WriteToNetwork(packet) => {
                tracing::debug!(
                    "Sending routine packet of {} bytes to WireGuard endpoint",
                    packet.len()
                );
                // A3：routine task 发出的报文（Init 重传 / keepalive / 数据）同样要编码
                match self.send_encoded_to_peer(packet).await {
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!(
                            "Failed to send routine packet to WireGuard endpoint: {:?}",
                            e
                        );
                    }
                };
            }
            TunnResult::Err(WireGuardError::ConnectionExpired) => {
                tracing::warn!("Wireguard handshake has expired!");

                let mut buf = vec![0u8; MAX_PACKET];
                let result = self
                    .tunn
                    .lock()
                    .await
                    .format_handshake_initiation(&mut buf[..], false);

                self.handle_routine_tun_result(result).await
            }
            TunnResult::Err(e) => {
                tracing::error!(
                    "Failed to prepare routine packet for WireGuard endpoint: {:?}",
                    e
                );
            }
            TunnResult::Done => {
                // Sleep for a bit
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            other => {
                tracing::warn!("Unexpected WireGuard routine task state: {:?}", other);
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        };
    }

    /// WireGuard Routine task. Handles Handshake, keep-alive, etc.
    pub async fn routine_task(self) {
        loop {
            let mut send_buf = vec![0u8; MAX_PACKET];
            let tun_result = { self.tunn.lock().await.update_timers(&mut send_buf) };
            self.handle_routine_tun_result(tun_result).await;
        }
    }

    fn fill_ip_header(zc_packet: &mut ZCPacket) {
        let len = zc_packet.payload_len() + PEER_MANAGER_HEADER_SIZE;
        let ip_header = &mut zc_packet.mut_wg_tunnel_header().unwrap().ipv4_header;
        ip_header[0] = 0x45;
        ip_header[1] = 0;
        ip_header[2..4].copy_from_slice(&((len + 20) as u16).to_be_bytes());
        ip_header[4..6].copy_from_slice(&0u16.to_be_bytes());
        ip_header[6..8].copy_from_slice(&0u16.to_be_bytes());
        ip_header[8] = 64;
        ip_header[9] = 0;
        ip_header[10..12].copy_from_slice(&0u16.to_be_bytes());
        ip_header[12..16].copy_from_slice(&0u32.to_be_bytes());
        ip_header[16..20].copy_from_slice(&0u32.to_be_bytes());
    }

    fn remove_ip_header<'a>(&self, packet: &'a [u8], is_v4: bool) -> &'a [u8] {
        if is_v4 { &packet[20..] } else { &packet[40..] }
    }
}

struct WgPeer {
    tunn: Option<Mutex<Tunn>>,
    udp: Arc<UdpSocket>, // only for send
    config: WgConfig,
    endpoint: SocketAddr,

    sink: std::sync::Mutex<Option<Pin<Box<dyn ZCPacketSink>>>>,

    data: Option<WgPeerData>,
    tasks: JoinSet<()>,

    access_time: AtomicCell<std::time::Instant>,

    /// B2：创建时间。用于「从未完成握手」的 peer 的收紧超时判定。
    created_at: std::time::Instant,
    /// B2：「会话已建立」标记（helper 判定）。从未建立的 peer 在握手超时后被回收。
    handshake_established: AtomicBool,
    /// B2：是否已收到过对端被 boringtun 接受的加密数据/keepalive（握手双向确认）。
    data_confirmed: AtomicBool,
    /// B2：「已交付」标记：隧道只交付给 accept 路径一次。
    delivered: AtomicBool,
    /// B2：累计收到的 UDP 包数（仅日志 / 验收用：确认半连接被丢弃）。
    recv_packets: AtomicUsize,
    /// B2：握手完成前暂存的隧道（listener 侧；建立握手后才通过 conn_sender 交付）。
    pending_tunnel: std::sync::Mutex<Option<Box<dyn Tunnel>>>,
}

impl WgPeer {
    fn new(udp: Arc<UdpSocket>, config: WgConfig, endpoint: SocketAddr) -> Self {
        WgPeer {
            tunn: Some(Mutex::new(Tunn::new(
                config.my_secret_key.clone(),
                config.peer_public_key,
                None,
                None,
                rand::thread_rng().next_u32(),
                None,
            ))),

            udp,
            config,
            endpoint,
            sink: std::sync::Mutex::new(None),

            data: None,
            tasks: JoinSet::new(),

            access_time: AtomicCell::new(std::time::Instant::now()),

            created_at: std::time::Instant::now(),
            handshake_established: AtomicBool::new(false),
            data_confirmed: AtomicBool::new(false),
            delivered: AtomicBool::new(false),
            recv_packets: AtomicUsize::new(0),
            pending_tunnel: std::sync::Mutex::new(None),
        }
    }

    async fn handle_packet_from_me<S: ZCPacketStream + Unpin>(mut stream: S, data: WgPeerData) {
        while let Some(Ok(packet)) = stream.next().await {
            let ret = data.handle_one_packet_from_me(packet).await;
            if let Err(e) = ret {
                tracing::error!("Failed to handle packet from me: {}", e);
            }
        }
        data.stopped
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    async fn handle_packet_from_peer(&self, packet: &[u8]) {
        self.access_time.store(std::time::Instant::now());
        self.recv_packets.fetch_add(1, Ordering::Relaxed);
        tracing::trace!("Received {} bytes from peer", packet.len());
        let data = self.data.as_ref().unwrap();
        // TODO: improve this
        let mut sink = self.sink.lock().unwrap().take().unwrap();
        let data_accepted = data.handle_one_packet_from_peer(&mut sink, packet).await;
        self.sink.lock().unwrap().replace(sink);

        // B2：置位「握手已完成」标记——A4 解码 + boringtun 会话状态 + 对端加密数据三者的交集。
        // 只置位不重置：连接建立后即使长时间空闲也保持（沿用 61s 空闲回收）。
        if data_accepted {
            self.data_confirmed.store(true, Ordering::Relaxed);
        }
        if !self.handshake_established.load(Ordering::Relaxed)
            && self.is_session_established().await
        {
            self.handshake_established.store(true, Ordering::Relaxed);
        }
    }

    fn start_and_get_tunnel(&mut self) -> Box<dyn Tunnel> {
        let (stunnel, ctunnel) = create_ring_tunnel_pair();

        let (stream, sink) = stunnel.split();

        let data = WgPeerData {
            udp: self.udp.clone(),
            endpoint: self.endpoint,
            tunn: Arc::new(self.tunn.take().unwrap()),
            wg_type: self.config.wg_type.clone(),
            stopped: Arc::new(AtomicBool::new(false)),
            obfs: self.config.obfs,
        };

        self.data = Some(data.clone());
        self.sink.lock().unwrap().replace(sink);

        self.tasks
            .spawn(Self::handle_packet_from_me(stream, data.clone()));
        self.tasks.spawn(data.routine_task());

        ctunnel
    }

    fn stopped(&self) -> bool {
        self.data
            .as_ref()
            .unwrap()
            .stopped
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// B2：标记停止（半连接超时丢弃 / retain 回收时调用）。内部任务随 `JoinSet` 一起被 abort。
    fn stop(&self) {
        if let Some(data) = self.data.as_ref() {
            data.stopped.store(true, Ordering::Relaxed);
        }
    }

    /// B2：会话是否已建立（A4 与任务 B 共用的 helper 判定）。
    async fn is_session_established(&self) -> bool {
        match self.data.as_ref() {
            Some(data) => tunn_session_established(&data.tunn).await,
            None => match self.tunn.as_ref() {
                Some(tunn) => tunn_session_established(tunn).await,
                None => false,
            },
        }
    }

    /// B2：握手是否已完成（双向确认）：会话已建立 **且** 收到过对端被 boringtun 接受的
    /// 加密数据/keepalive。只有这种 peer 才允许把隧道交付给 accept 路径，
    /// 也只有这种 peer 才享受 61s 的空闲阈值。
    fn is_handshake_confirmed(&self) -> bool {
        self.handshake_established.load(Ordering::Relaxed)
            && self.data_confirmed.load(Ordering::Relaxed)
    }

    fn is_delivered(&self) -> bool {
        self.delivered.load(Ordering::SeqCst)
    }

    fn recv_packet_count(&self) -> usize {
        self.recv_packets.load(Ordering::Relaxed)
    }

    /// B2：取出待交付的隧道。仅在「握手已双向确认且尚未交付」时返回 `Some`，保证只交付一次。
    ///
    /// `delivered` 用 `Option` + 互斥锁保证「只交付一次」，原子标记用于快速路径与验收观测。
    async fn take_tunnel_if_confirmed(&self) -> Option<Box<dyn Tunnel>> {
        if self.delivered.load(Ordering::SeqCst) || !self.is_handshake_confirmed() {
            return None;
        }
        let mut guard = self.pending_tunnel.lock().unwrap();
        let tunnel = guard.take()?;
        self.delivered.store(true, Ordering::SeqCst);
        Some(tunnel)
    }

    /// A3：按混淆配置编码后发送到本 peer 的 UDP endpoint（握手 Init / 重传用）。
    async fn send_to_peer(&self, packet: &[u8]) -> std::io::Result<usize> {
        send_encoded_packet(&self.udp, self.endpoint, self.config.obfs, packet).await
    }

    /// 生成握手 Init 报文。
    ///
    /// `force_resend = true` 时即使 boringtun 认为握手已在进行中也会重新生成
    /// （对应 boringtun 的 `REKEY_TIMEOUT` 重传语义）；返回 `None` 表示当前无需发送。
    async fn create_handshake_init(&self, force_resend: bool) -> Option<Vec<u8>> {
        let mut dst = vec![0u8; MAX_PACKET];
        let handshake_init = self
            .tunn
            .as_ref()
            .unwrap()
            .lock()
            .await
            .format_handshake_initiation(&mut dst, force_resend);

        match handshake_init {
            TunnResult::WriteToNetwork(sent) => Some(sent.to_vec()),
            TunnResult::Done => None,
            other => {
                tracing::warn!(?other, "wg 生成握手 Init 失败");
                None
            }
        }
    }

    /// B1：等待握手完成（客户端）。
    ///
    /// 循环收包（显式超时 [`WG_HANDSHAKE_TIMEOUT`]），每个包先按 A4 解码：
    /// - **只有**解出合法 Init/Response、且被 boringtun 处理、且「会话已建立」（helper 判定）
    ///   才返回 `Ok(())`；
    /// - junk / 无法识别 / 解密失败 → 丢弃后继续等；
    /// - 超时或 socket 错误 → 返回 `Err`，**绝不返回会话未建立的隧道**
    ///   （这是「半连接污染数据面」的根因之一）；
    /// - 等待期内按 [`WG_HANDSHAKE_RETRY_INTERVAL`] 强制重传 Init（此时 routine_task 尚未启动）。
    async fn wait_for_handshake(&self, udp: &UdpSocket) -> Result<(), TunnelError> {
        let tunn = self
            .tunn
            .as_ref()
            .expect("wait_for_handshake 必须在 start_and_get_tunnel 之前调用");
        let mut buf = vec![0u8; MAX_UDP_RECV];
        let deadline = tokio::time::Instant::now() + WG_HANDSHAKE_TIMEOUT;
        let mut next_retry = tokio::time::Instant::now() + WG_HANDSHAKE_RETRY_INTERVAL;

        loop {
            let wake = next_retry.min(deadline);
            let recv = tokio::time::timeout_at(wake, udp.recv_from(&mut buf)).await;
            let (n, recv_addr) = match recv {
                Ok(Ok(ret)) => ret,
                Ok(Err(e)) => {
                    tracing::error!("wg 握手等待：接收失败: {}", e);
                    return Err(TunnelError::IOError(e));
                }
                Err(elapsed) => {
                    if tokio::time::Instant::now() >= deadline {
                        tracing::warn!(
                            endpoint = ?self.endpoint,
                            "wg 握手等待超时（{:?}）：未收到合法握手响应，不交付会话未建立的隧道",
                            WG_HANDSHAKE_TIMEOUT
                        );
                        return Err(TunnelError::Timeout(elapsed));
                    }
                    // 到期强制重传 Init，提高单次连接尝试的成功率
                    if let Some(init) = self.create_handshake_init(true).await {
                        if let Err(e) = self.send_to_peer(&init).await {
                            tracing::error!("wg 握手等待：重传 Init 失败: {}", e);
                            return Err(TunnelError::IOError(e));
                        }
                        tracing::debug!(endpoint = ?self.endpoint, "wg 握手等待：已强制重传 Init");
                    }
                    next_retry = tokio::time::Instant::now() + WG_HANDSHAKE_RETRY_INTERVAL;
                    continue;
                }
            };

            if recv_addr != self.endpoint {
                tracing::warn!(
                    ?recv_addr,
                    expected = ?self.endpoint,
                    "wg 握手等待：收到来自其他地址的报文"
                );
            }

            // A4：解码（junk / 长度非法的报文直接丢弃后继续等）
            let established_before = tunn_session_established(tunn).await;
            let (msg_type, payload) =
                match decode_wg_packet(&buf[..n], self.config.obfs, established_before) {
                    WgDecodedPacket::Packet { msg_type, payload } => (msg_type, payload),
                    WgDecodedPacket::Junk(reason) => {
                        tracing::debug!(len = n, reason, "wg 握手等待：丢弃无法识别的报文");
                        continue;
                    }
                };

            // 只有握手类报文才可能让握手完成；其余交给 boringtun 处理后继续等
            let is_handshake_packet =
                matches!(msg_type, WG_MSG_HANDSHAKE_INIT | WG_MSG_HANDSHAKE_RESPONSE);
            let processed =
                handle_handshake_wait_packet(tunn, udp, self.endpoint, self.config.obfs, payload)
                    .await;
            if is_handshake_packet && processed && tunn_session_established(tunn).await {
                tracing::info!(
                    endpoint = ?self.endpoint,
                    msg_type,
                    "wg 握手完成：会话已建立，交付隧道"
                );
                return Ok(());
            }
        }
    }

    fn udp_socket(&self) -> Arc<UdpSocket> {
        self.udp.clone()
    }
}

/// B1 握手等待期：处理一个已解码的入站报文。
///
/// 只做「decapsulate + 把 boringtun 指示发出的报文编码回发」（例如收到 Response 后
/// boringtun 会指示发一个 keepalive，这正是让对端确认握手的报文）。此时隧道 sink 尚未创建，
/// 握手完成前到达的隧道数据会被丢弃（握手阶段本不应有隧道数据，丢弃无害）。
///
/// 返回 `true` 表示 boringtun 成功处理了该报文（非 `Err`）。
async fn handle_handshake_wait_packet(
    tunn: &Mutex<Tunn>,
    udp: &UdpSocket,
    endpoint: SocketAddr,
    obfs: Option<WgObfsConfig>,
    packet: &[u8],
) -> bool {
    let mut send_buf = vec![0u8; MAX_PACKET];
    let result = {
        let mut peer = tunn.lock().await;
        peer.decapsulate(None, packet, &mut send_buf)
    };

    match result {
        TunnResult::WriteToNetwork(out) => {
            // 先拷出来再发：`out` 借用了 send_buf
            let out = out.to_vec();
            if let Err(e) = send_encoded_packet(udp, endpoint, obfs, &out).await {
                tracing::debug!(?endpoint, "wg 握手等待：回发报文失败: {}", e);
                return false;
            }

            // 排空 boringtun 后续待发报文（与 handle_one_packet_from_peer 的处理保持一致）
            let mut more = vec![0u8; MAX_PACKET];
            loop {
                let drain_result = {
                    let mut peer = tunn.lock().await;
                    peer.decapsulate(None, &[], &mut more)
                };
                match drain_result {
                    TunnResult::WriteToNetwork(out) => {
                        let out = out.to_vec();
                        if let Err(e) = send_encoded_packet(udp, endpoint, obfs, &out).await {
                            tracing::debug!(?endpoint, "wg 握手等待：排空回发失败: {}", e);
                            break;
                        }
                    }
                    _ => break,
                }
            }
            true
        }
        TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..) => true,
        TunnResult::Done => true,
        TunnResult::Err(e) => {
            tracing::debug!(?e, "wg 握手等待：报文被 boringtun 拒绝");
            false
        }
    }
}

type ConnSender = tokio::sync::mpsc::UnboundedSender<Box<dyn Tunnel>>;
type ConnReceiver = tokio::sync::mpsc::UnboundedReceiver<Box<dyn Tunnel>>;

pub struct WgTunnelListener {
    addr: url::Url,
    config: WgConfig,

    udp: Option<Arc<UdpSocket>>,
    conn_recv: ConnReceiver,
    conn_send: Option<ConnSender>,

    wg_peer_map: Arc<DashMap<SocketAddr, Arc<WgPeer>>>,

    tasks: JoinSet<()>,
}

impl WgTunnelListener {
    pub fn new(addr: url::Url, config: WgConfig) -> Self {
        let (conn_send, conn_recv) = tokio::sync::mpsc::unbounded_channel();
        WgTunnelListener {
            addr,
            config,

            udp: None,
            conn_recv,
            conn_send: Some(conn_send),

            wg_peer_map: Arc::new(DashMap::new()),

            tasks: JoinSet::new(),
        }
    }

    fn get_udp_socket(&self) -> Arc<UdpSocket> {
        self.udp.as_ref().unwrap().clone()
    }

    async fn handle_udp_incoming(
        socket: Arc<UdpSocket>,
        config: WgConfig,
        conn_sender: ConnSender,
        peer_map: Arc<DashMap<SocketAddr, Arc<WgPeer>>>,
    ) {
        let mut tasks = JoinSet::new();

        let peer_map_clone: Arc<DashMap<SocketAddr, Arc<WgPeer>>> = peer_map.clone();
        tasks.spawn(async move {
            loop {
                peer_map_clone.retain(|addr, peer| {
                    // B2：从未完成握手（或只有会话、未收到对端加密数据）的 peer —— 例如只收到
                    // 混淆 junk 的对端、或握手响应被中间设备丢掉的半连接 —— 收紧到握手超时，
                    // 避免半连接长期驻留；已完成的 peer 沿用原有 61s 空闲阈值。
                    if !peer.is_handshake_confirmed()
                        && peer.created_at.elapsed() >= WG_PEER_HANDSHAKE_TIMEOUT
                    {
                        tracing::debug!(
                            ?addr,
                            recv = peer.recv_packet_count(),
                            established = peer.handshake_established.load(Ordering::Relaxed),
                            "wg listener: 握手超时，丢弃半连接 peer（不交付隧道）"
                        );
                        peer.stop();
                        return false;
                    }

                    peer.access_time.load().elapsed() < WG_PEER_IDLE_TIMEOUT && !peer.stopped()
                });
                shrink_dashmap(&peer_map_clone, None);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });

        let mut buf = vec![0u8; MAX_UDP_RECV];
        loop {
            let Ok((n, addr)) = socket.recv_from(&mut buf).await else {
                tracing::error!("Failed to receive from UDP socket");
                break;
            };

            let data = &buf[..n];
            tracing::trace!(?n, ?addr, "Received bytes from peer");

            if !peer_map.contains_key(&addr) {
                tracing::info!("New peer: {}", addr);
                let mut wg = WgPeer::new(socket.clone(), config.clone(), addr);
                // B2：先把隧道建出来（内部读/写/定时任务照常运行），但**不**立刻交给 accept 路径，
                // 而是挂在 peer 上，等握手真正完成（双向确认）后再交付一次。
                // TunnelInfo 的构造逻辑保持与改动前完全一致。
                let (stream, sink) = wg.start_and_get_tunnel().split();
                let tunnel = Box::new(TunnelWrapper::new(
                    stream,
                    sink,
                    Some(TunnelInfo {
                        tunnel_type: "wg".to_owned(),
                        local_addr: Some(
                            build_url_from_socket_addr(
                                &socket.local_addr().unwrap().to_string(),
                                "wg",
                            )
                            .into(),
                        ),
                        remote_addr: Some(
                            build_url_from_socket_addr(&addr.to_string(), "wg").into(),
                        ),
                        resolved_remote_addr: Some(
                            build_url_from_socket_addr(&addr.to_string(), "wg").into(),
                        ),
                    }),
                ));
                wg.pending_tunnel.lock().unwrap().replace(tunnel);
                peer_map.insert(addr, Arc::new(wg));

                // A3：本端即将（收到 Init 后）回握手，先发建立阶段的 junk 包。
                // 服务端收到的第一个包（可能就是对端的 junk）到达时即发送，保证顺序：junk → 握手响应。
                if let Some(obfs) = config.obfs {
                    send_obfs_junk_packets(&socket, addr, obfs).await;
                }
            }

            // 取 peer 的 Arc（不持有 DashMap 分片锁）：peer 可能刚被 retain 回收
            // （半连接超时），此时直接丢弃本包即可，下一个包会重新建立 peer。
            let Some(peer) = peer_map.get(&addr).map(|p| Arc::clone(&p)) else {
                tracing::debug!(?addr, "wg listener: peer 已被回收，丢弃本包");
                continue;
            };
            // 入站包处理（A4 解码在 WgPeerData::handle_one_packet_from_peer 内完成）
            peer.handle_packet_from_peer(data).await;

            // B2：只有握手完成（会话已建立 + 收到对端加密数据/keepalive）才把隧道交给
            // accept 路径，且用 delivered 标记保证只交付一次。
            if !peer.is_delivered()
                && let Some(tunnel) = peer.take_tunnel_if_confirmed().await
            {
                tracing::info!(
                    ?addr,
                    recv = peer.recv_packet_count(),
                    "wg listener: 握手完成，交付隧道给 accept 路径"
                );
                if let Err(e) = conn_sender.send(tunnel) {
                    tracing::error!("Failed to send tunnel to conn_sender: {}", e);
                }
            }
        }
    }
}

#[async_trait]
impl TunnelListener for WgTunnelListener {
    async fn listen(&mut self) -> Result<(), TunnelError> {
        let addr = SocketAddr::from_url(self.addr.clone(), IpVersion::Both).await?;
        let tunnel_url: TunnelUrl = self.addr.clone().into();
        self.udp = Some(Arc::new(
            bind()
                .addr(addr)
                .only_v6(true)
                .maybe_dev(tunnel_url.bind_dev())
                .call()?,
        ));
        self.addr
            .set_port(Some(self.udp.as_ref().unwrap().local_addr()?.port()))
            .unwrap();

        self.tasks.spawn(Self::handle_udp_incoming(
            self.get_udp_socket(),
            self.config.clone(),
            self.conn_send.take().unwrap(),
            self.wg_peer_map.clone(),
        ));

        Ok(())
    }

    async fn accept(&mut self) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        if let Some(tunnel) = self.conn_recv.recv().await {
            tracing::info!(?tunnel, "Accepted tunnel");
            return Ok(tunnel);
        }
        Err(TunnelError::Shutdown)
    }

    fn local_url(&self) -> url::Url {
        self.addr.clone()
    }
}

#[derive(Clone)]
pub struct WgTunnelConnector {
    addr: url::Url,
    config: WgConfig,
    udp: Option<Arc<UdpSocket>>,

    bind_addrs: Vec<SocketAddr>,
    ip_version: IpVersion,
    resolved_addr: Option<SocketAddr>,

    /// 用于「物理地址直连优先、禁用外层隧道复用」的防回环判定（补充项 4.4）。
    ///
    /// 可选：`WgTunnelConnector::new` 构造时为 `None`（保持既有调用点行为不变），
    /// 此时退化为 `is_definitely_physical_addr` 的保守兜底判定。推荐调用方
    /// （`connector::create_connector_by_url`）用 `new_with_global_ctx` 或
    /// `set_global_ctx` 注入，以便精确识别本虚拟网络的地址。
    global_ctx: Option<ArcGlobalCtx>,
}

impl Debug for WgTunnelConnector {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgTunnelConnector")
            .field("addr", &self.addr)
            .field("udp", &self.udp)
            .finish()
    }
}

impl WgTunnelConnector {
    pub fn new(addr: url::Url, config: WgConfig) -> Self {
        Self::new_with_global_ctx(addr, config, None)
    }

    /// 带 `GlobalCtx` 的构造：用于「物理地址直连优先、禁用外层隧道复用」的防回环判定
    /// （补充项 4.4）。`connector::create_connector_by_url` 已有 `global_ctx`，推荐使用
    /// 本构造函数。
    pub fn new_with_global_ctx(
        addr: url::Url,
        config: WgConfig,
        global_ctx: Option<ArcGlobalCtx>,
    ) -> Self {
        WgTunnelConnector {
            addr,
            config,
            udp: None,
            bind_addrs: vec![],
            ip_version: IpVersion::Both,
            resolved_addr: None,
            global_ctx,
        }
    }

    /// 延迟注入 `GlobalCtx`，便于在不改构造函数签名的调用点启用防回环判定
    /// （补充项 4.4）：`let mut c = WgTunnelConnector::new(url, cfg); c.set_global_ctx(global_ctx);`
    pub fn set_global_ctx(&mut self, global_ctx: ArcGlobalCtx) {
        self.global_ctx = Some(global_ctx);
    }

    /// 目标地址是否位于本虚拟网络内（此时允许复用外层隧道，保持原有行为）。
    ///
    /// 优先复用 `GlobalCtx::is_ip_in_same_network`（不自行解析配置字符串）；拿不到
    /// `GlobalCtx` 时退化为保守兜底判定：只有公网地址才判定为「物理地址」。
    fn dst_is_in_virtual_network(&self, ip: &IpAddr) -> bool {
        match &self.global_ctx {
            Some(global_ctx) => global_ctx.is_ip_in_same_network(ip),
            None => !is_definitely_physical_addr(ip),
        }
    }

    /// 判断某个绑定地址是否可用于「只允许直连」的物理目标。
    ///
    /// 本虚拟网络的地址（TUN 接口地址）会把 socket 钉在 TUN 设备上，使 wg 包经外层
    /// 隧道回环，因此必须排除。拿不到 `GlobalCtx` 时无法区分虚拟网接口与物理接口，
    /// 保守返回 `false`（调用方会退化为绑定 `0.0.0.0:0`，交给内核路由表选源，而不是
    /// 主动把包送进外层隧道）。
    fn can_bind_for_physical_dst(&self, bind_addr: &SocketAddr) -> bool {
        match &self.global_ctx {
            Some(global_ctx) => !global_ctx.is_ip_local_virtual_ip(&bind_addr.ip()),
            None => false,
        }
    }

    #[tracing::instrument(skip(config))]
    async fn connect_with_socket(
        addr_url: url::Url,
        config: WgConfig,
        udp: UdpSocket,
        addr: SocketAddr,
    ) -> Result<Box<dyn super::Tunnel>, super::TunnelError> {
        tracing::warn!("wg connect: {:?}", addr);
        let local_addr = udp
            .local_addr()
            .with_context(|| "Failed to get local addr")?
            .to_string();

        let mut wg_peer = WgPeer::new(Arc::new(udp), config.clone(), addr);
        let udp = wg_peer.udp_socket();

        // A3：本端即将发起握手 → 先发建立阶段的 junk 包，再发握手 Init
        // （顺序保证：junk → 握手 Init；junk 只在建立阶段发送，之后不再发）。
        if let Some(obfs) = config.obfs {
            send_obfs_junk_packets(&udp, addr, obfs).await;
        }

        // 发出 Init，然后等待握手真正完成（B1）：只有「收到合法握手报文且会话已建立」才继续
        let handshake = wg_peer.create_handshake_init(false).await.ok_or_else(|| {
            TunnelError::InternalError("failed to format wg handshake init".to_owned())
        })?;
        if let Err(e) = wg_peer.send_to_peer(&handshake).await {
            tracing::error!("Failed to send handshake init to WireGuard endpoint: {}", e);
            return Err(TunnelError::IOError(e));
        }
        wg_peer.wait_for_handshake(&udp).await?;

        let tunnel = wg_peer.start_and_get_tunnel();
        let data = wg_peer.data.as_ref().unwrap().clone();
        let mut sink = wg_peer.sink.lock().unwrap().take().unwrap();
        wg_peer.tasks.spawn(async move {
            loop {
                let mut buf = vec![0u8; MAX_UDP_RECV];
                let (n, _) = match udp.recv_from(&mut buf).await {
                    Ok(ret) => ret,
                    Err(e) => {
                        tracing::error!("Failed to receive wg packet: {}", e);
                        break;
                    }
                };
                // A4：解码在 handle_one_packet_from_peer 内完成（junk 直接丢弃）
                data.handle_one_packet_from_peer(&mut sink, &buf[..n]).await;
            }
        });

        let (stream, sink) = tunnel.split();
        let ret = Box::new(TunnelWrapper::new_with_associate_data(
            stream,
            sink,
            Some(TunnelInfo {
                tunnel_type: "wg".to_owned(),
                local_addr: Some(super::build_url_from_socket_addr(&local_addr, "wg").into()),
                remote_addr: Some(addr_url.into()),
                resolved_remote_addr: Some(
                    super::build_url_from_socket_addr(&addr.to_string(), "wg").into(),
                ),
            }),
            Some(Box::new(wg_peer)),
        ));

        Ok(ret)
    }

    async fn connect_with_ipv6(&self, addr: SocketAddr) -> Result<Box<dyn Tunnel>, TunnelError> {
        let socket = bind()
            .addr("[::]:0".parse().unwrap())
            .dev(BindDev::Disabled)
            .only_v6(true)
            .call()?;
        Self::connect_with_socket(self.addr.clone(), self.config.clone(), socket, addr).await
    }
}

#[async_trait]
impl super::TunnelConnector for WgTunnelConnector {
    #[tracing::instrument]
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        let addr = match self.resolved_addr {
            Some(addr) => addr,
            None => SocketAddr::from_url(self.addr.clone(), self.ip_version).await?,
        };

        // 补充项 4.4：直连优先的代码层防回环（第二道保险）。
        //
        // 目标是本虚拟网络之外的物理地址（公网/直连地址）时，只允许直连，不允许把
        // wg 包交给外层隧道；目标是虚拟网络内的地址时才保留原有行为（允许复用外层
        // 隧道）。直连失败时本函数只返回失败，不做任何「退化为外层隧道」的兜底，
        // 由上层（ManualConnectorManager / PeerManager）按既有失败处理与重试。
        let direct_only =
            WG_DIRECT_ONLY_FOR_PHYSICAL_DST && !self.dst_is_in_virtual_network(&addr.ip());
        if direct_only {
            tracing::info!(
                ?addr,
                has_global_ctx = self.global_ctx.is_some(),
                "wg connector: 目标为本虚拟网络之外的物理地址，只允许直连，禁用外层隧道复用（防回环）"
            );
        } else {
            tracing::debug!(
                ?addr,
                "wg connector: 目标可能位于本虚拟网络内，允许复用外层隧道"
            );
        }

        if addr.is_ipv6() {
            return self.connect_with_ipv6(addr).await;
        }

        let mut bind_addrs = if self.bind_addrs.is_empty() {
            vec!["0.0.0.0:0".parse().unwrap()]
        } else {
            self.bind_addrs.clone()
        };

        if direct_only && !self.bind_addrs.is_empty() {
            let (physical, rejected): (Vec<SocketAddr>, Vec<SocketAddr>) = bind_addrs
                .iter()
                .copied()
                .partition(|bind_addr| self.can_bind_for_physical_dst(bind_addr));

            if physical.is_empty() {
                // 所有显式绑定地址都被判定为虚拟网地址（或无法判定）：退化为不显式
                // 绑定，交给内核按路由表选源，而不是继续把 socket 钉在虚拟网接口上
                // ——那正是回环的成因。
                tracing::warn!(
                    ?addr,
                    rejected = ?rejected,
                    has_global_ctx = self.global_ctx.is_some(),
                    "wg connector: 物理目标下没有可用的物理绑定地址，退化为绑定 0.0.0.0:0（不再绑定虚拟网接口，防回环）"
                );
                bind_addrs = vec!["0.0.0.0:0".parse().unwrap()];
            } else {
                if !rejected.is_empty() {
                    tracing::debug!(
                        ?addr,
                        rejected = ?rejected,
                        "wg connector: 物理目标下跳过虚拟网接口绑定地址（防回环）"
                    );
                }
                bind_addrs = physical;
            }
        }

        let futures = FuturesUnordered::new();
        for bind_addr in bind_addrs.into_iter() {
            tracing::info!(?bind_addr, ?addr, "bind addr");
            match bind().addr(bind_addr).only_v6(true).call() {
                Ok(socket) => futures.push(Self::connect_with_socket(
                    self.addr.clone(),
                    self.config.clone(),
                    socket,
                    addr,
                )),
                Err(error) => {
                    tracing::error!(?error, ?bind_addr, ?addr, "bind addr fail");
                    continue;
                }
            }
        }

        wait_for_connect_futures(futures).await
    }

    fn remote_url(&self) -> url::Url {
        self.addr.clone()
    }

    fn set_bind_addrs(&mut self, addrs: Vec<SocketAddr>) {
        self.bind_addrs = addrs;
    }

    fn set_ip_version(&mut self, ip_version: IpVersion) {
        self.ip_version = ip_version;
    }

    fn set_resolved_addr(&mut self, addr: SocketAddr) {
        self.resolved_addr = Some(addr);
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::tunnel::{
        TunnelConnector,
        common::tests::{_tunnel_bench, _tunnel_pingpong},
    };
    use boringtun::*;

    pub fn create_wg_config() -> (WgConfig, WgConfig) {
        let my_secret_key = x25519::StaticSecret::random_from_rng(rand::thread_rng());
        let my_public_key = x25519::PublicKey::from(&my_secret_key);

        let their_secret_key = x25519::StaticSecret::random_from_rng(rand::thread_rng());
        let their_public_key = x25519::PublicKey::from(&their_secret_key);

        let server_cfg = WgConfig {
            my_secret_key: my_secret_key.clone(),
            my_public_key,
            peer_secret_key: their_secret_key.clone(),
            peer_public_key: their_public_key,
            wg_type: WgType::InternalUse,
            obfs: None,
        };

        let client_cfg = WgConfig {
            my_secret_key: their_secret_key,
            my_public_key: their_public_key,
            peer_secret_key: my_secret_key,
            peer_public_key: my_public_key,
            wg_type: WgType::InternalUse,
            obfs: None,
        };

        (server_cfg, client_cfg)
    }

    /// 补充项 4.4：地址分类的保守兜底判定（无需网络，纯逻辑）。
    #[test]
    fn physical_addr_classification() {
        let physical: Vec<IpAddr> = ["8.8.8.8", "35.74.75.198", "1.1.1.1", "2001:4860:4860::8888"]
            .iter()
            .map(|ip| ip.parse().unwrap())
            .collect();
        for ip in physical {
            assert!(is_definitely_physical_addr(&ip), "{} 应判定为物理地址", ip);
        }

        let not_physical: Vec<IpAddr> = [
            "10.126.126.1",    // EasyTier 默认虚拟网段
            "100.100.100.101", // Magic DNS 假 IP，落在 100.64.0.0/10 共享地址段
            "192.168.1.1",
            "172.16.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "::1",
            "fe80::1",
            "fd00::1",
        ]
        .iter()
        .map(|ip| ip.parse().unwrap())
        .collect();
        for ip in not_physical {
            assert!(
                !is_definitely_physical_addr(&ip),
                "{} 不应判定为物理地址",
                ip
            );
        }
    }

    /// 补充项 4.4：无 `GlobalCtx` 时，物理目标必须禁用「显式绑定接口地址」。
    #[test]
    fn physical_dst_disables_iface_bind_without_global_ctx() {
        let connector = WgTunnelConnector::new(
            "wg://35.74.75.198:11011".parse().unwrap(),
            create_wg_config().0,
        );
        assert!(
            !connector.dst_is_in_virtual_network(&"35.74.75.198".parse().unwrap()),
            "公网物理地址不应判定为虚拟网内地址"
        );
        assert!(
            connector.dst_is_in_virtual_network(&"10.126.126.1".parse().unwrap()),
            "虚拟网地址应判定为虚拟网内地址"
        );
        // 拿不到 GlobalCtx 时无法区分虚拟网接口与物理接口 → 保守拒绝显式绑定
        assert!(!connector.can_bind_for_physical_dst(&"192.168.1.5:0".parse().unwrap()));
    }

    /// 构造一个「线格式」假报文：前 4 字节为小端消息类型，其余为可区分的填充。
    fn fake_wg_packet(msg_type: u32, len: usize) -> Vec<u8> {
        assert!(len >= 4);
        let mut buf = vec![0u8; len];
        buf[..4].copy_from_slice(&msg_type.to_le_bytes());
        for (i, b) in buf.iter_mut().enumerate().skip(4) {
            *b = (i % 251) as u8;
        }
        buf
    }

    fn obfs_flags() -> crate::common::config::Flags {
        crate::common::config::gen_default_flags()
    }

    /// A1：`WgObfsConfig::from_flags` 的默认值、逐项覆盖、钳制与 junk 区间校验。
    #[test]
    fn wg_obfs_config_from_flags_default_clamp_and_junk_guard() {
        // 默认关闭 = 原生 WireGuard
        let mut flags = obfs_flags();
        assert!(
            WgObfsConfig::from_flags(&flags).is_none(),
            "未设置 wg_obfs 时必须返回 None（原生 WireGuard 透传）"
        );
        flags.wg_obfs = Some(false);
        assert!(
            WgObfsConfig::from_flags(&flags).is_none(),
            "wg_obfs=false 时必须返回 None"
        );

        // 开启且不覆盖 = 内置默认值
        flags.wg_obfs = Some(true);
        assert_eq!(
            WgObfsConfig::from_flags(&flags),
            Some(WgObfsConfig::BUILTIN_DEFAULT)
        );

        // 内置默认值的 junk 区间不能包含任何握手包混淆后的长度（否则会把握手包当 junk 丢掉）
        let d = WgObfsConfig::BUILTIN_DEFAULT;
        for len in [
            WG_HANDSHAKE_INIT_SIZE + d.s1 as usize,
            WG_HANDSHAKE_RESPONSE_SIZE + d.s2 as usize,
            WG_COOKIE_REPLY_SIZE + d.s3 as usize,
        ] {
            assert!(
                !(d.jmin as usize..=d.jmax as usize).contains(&len),
                "内置默认 junk 区间 [{}..{}] 不应包含握手包长度 {}",
                d.jmin,
                d.jmax,
                len
            );
        }

        // 逐项覆盖（Some 才覆盖；Some(0) 表示该字段不填充 / 不发 junk）
        let mut flags = obfs_flags();
        flags.wg_obfs = Some(true);
        flags.wg_obfs_s1 = Some(1);
        flags.wg_obfs_s2 = Some(2);
        flags.wg_obfs_s3 = Some(3);
        flags.wg_obfs_s4 = Some(4);
        flags.wg_obfs_jc = Some(0);
        flags.wg_obfs_jmin = Some(300);
        flags.wg_obfs_jmax = Some(400);
        let cfg = WgObfsConfig::from_flags(&flags).unwrap();
        assert_eq!(
            (cfg.s1, cfg.s2, cfg.s3, cfg.s4, cfg.jc, cfg.jmin, cfg.jmax),
            (1, 2, 3, 4, 0, 300, 400)
        );

        // 越界值：warn 后钳制，不 panic，且两端同输入必然同结果
        let mut flags = obfs_flags();
        flags.wg_obfs = Some(true);
        flags.wg_obfs_s1 = Some(1000);
        flags.wg_obfs_s2 = Some(1000);
        flags.wg_obfs_s3 = Some(1000);
        flags.wg_obfs_s4 = Some(1000);
        flags.wg_obfs_jc = Some(1000);
        flags.wg_obfs_jmin = Some(0);
        flags.wg_obfs_jmax = Some(100_000);
        let cfg = WgObfsConfig::from_flags(&flags).unwrap();
        assert_eq!((cfg.s1, cfg.s2, cfg.s3), (64, 64, 64), "s1..s3 上限 64");
        assert_eq!(cfg.s4, 32, "s4 上限 32");
        assert_eq!(
            (cfg.jmin, cfg.jmax),
            (64, 1024),
            "junk 长度限制在 64..=1024"
        );
        // 钳制后 [64, 1024] 必然包含 148+64 / 92+64 / 64+64 → junk 必须关闭
        assert_eq!(cfg.jc, 0, "该区间与握手包长度重叠 → junk 关闭");
        assert_eq!(
            WgObfsConfig::from_flags(&flags),
            Some(cfg),
            "同输入必须得到同结果（两端参数一致的前提）"
        );

        // jc 上限 10（用一个不与握手包长度重叠的区间，避免被 junk 保护置 0）
        let mut flags = obfs_flags();
        flags.wg_obfs = Some(true);
        flags.wg_obfs_s1 = Some(0);
        flags.wg_obfs_s2 = Some(0);
        flags.wg_obfs_s3 = Some(0);
        flags.wg_obfs_jc = Some(1000);
        flags.wg_obfs_jmin = Some(200);
        flags.wg_obfs_jmax = Some(300);
        let cfg = WgObfsConfig::from_flags(&flags).unwrap();
        assert_eq!(cfg.jc, 10, "jc 上限 10");
        assert_eq!(
            (cfg.s1, cfg.s2, cfg.s3),
            (0, 0, 0),
            "Some(0) = 该字段不填充"
        );

        // jmin > jmax → 把 jmax 提升到 jmin（确定性钳制）
        let mut flags = obfs_flags();
        flags.wg_obfs = Some(true);
        flags.wg_obfs_jmin = Some(900);
        flags.wg_obfs_jmax = Some(100);
        let cfg = WgObfsConfig::from_flags(&flags).unwrap();
        assert_eq!((cfg.jmin, cfg.jmax), (900, 900));

        // junk 区间与握手包长度重叠 → jc 置 0
        let mut flags = obfs_flags();
        flags.wg_obfs = Some(true);
        flags.wg_obfs_s3 = Some(19); // 64+19 = 83
        flags.wg_obfs_jc = Some(4);
        flags.wg_obfs_jmin = Some(64);
        flags.wg_obfs_jmax = Some(100);
        let cfg = WgObfsConfig::from_flags(&flags).unwrap();
        assert_eq!(cfg.jc, 0, "junk 区间包含 64+s3 时必须关闭 junk");
        assert!(!cfg.junk_enabled());

        // 不重叠则保留 jc
        let mut flags = obfs_flags();
        flags.wg_obfs = Some(true);
        flags.wg_obfs_s1 = Some(37);
        flags.wg_obfs_s2 = Some(42);
        flags.wg_obfs_s3 = Some(19);
        flags.wg_obfs_jc = Some(4);
        flags.wg_obfs_jmin = Some(200);
        flags.wg_obfs_jmax = Some(260);
        let cfg = WgObfsConfig::from_flags(&flags).unwrap();
        assert_eq!(cfg.jc, 4);
        assert!(cfg.junk_enabled());
    }

    /// A2：`WgConfig` 混淆字段默认 `None`，`with_obfs/obfs` 可读写。
    #[test]
    fn wg_config_obfs_builder() {
        let (server_cfg, _) = create_wg_config();
        assert_eq!(server_cfg.obfs(), None, "默认必须是原生 WireGuard");
        let obfs = WgObfsConfig::BUILTIN_DEFAULT;
        assert_eq!(server_cfg.clone().with_obfs(Some(obfs)).obfs(), Some(obfs));
        assert_eq!(server_cfg.clone().with_obfs(None).obfs(), None);

        // 按 Flags 应用
        let mut flags = crate::common::config::gen_default_flags();
        flags.wg_obfs = Some(true);
        let cfg = create_wg_config().0.with_obfs_from_flags(&flags);
        assert_eq!(cfg.obfs(), Some(WgObfsConfig::BUILTIN_DEFAULT));
    }

    /// A3/A4：混淆编解码往返（Init/Response/Cookie 前置填充、Data 尾部填充）。
    #[test]
    fn wg_obfs_encode_decode_roundtrip() {
        let obfs = WgObfsConfig::BUILTIN_DEFAULT;
        for (msg_type, len) in [
            (WG_MSG_HANDSHAKE_INIT, WG_HANDSHAKE_INIT_SIZE),
            (WG_MSG_HANDSHAKE_RESPONSE, WG_HANDSHAKE_RESPONSE_SIZE),
            (WG_MSG_COOKIE_REPLY, WG_COOKIE_REPLY_SIZE),
            (WG_MSG_DATA, 96),
        ] {
            let plain = fake_wg_packet(msg_type, len);
            let encoded = encode_wg_packet(&plain, Some(obfs)).expect("开启混淆后必须编码");
            let pad = match msg_type {
                WG_MSG_HANDSHAKE_INIT => obfs.s1 as usize,
                WG_MSG_HANDSHAKE_RESPONSE => obfs.s2 as usize,
                WG_MSG_COOKIE_REPLY => obfs.s3 as usize,
                _ => obfs.s4 as usize,
            };
            assert_eq!(
                encoded.len(),
                len + pad,
                "msg_type={} 填充长度不对",
                msg_type
            );
            // 前置填充：原报文必须原封不动地出现在尾部
            if msg_type != WG_MSG_DATA {
                assert_eq!(
                    &encoded[pad..],
                    &plain[..],
                    "msg_type={} 前置填充出错",
                    msg_type
                );
            } else {
                assert_eq!(&encoded[..len], &plain[..], "Data 尾部填充出错");
            }

            // 会话未建立时解码也必须能还原（Data 不算 junk：默认区间不含 96+11=107）
            match decode_wg_packet(&encoded, Some(obfs), false) {
                WgDecodedPacket::Packet {
                    msg_type: t,
                    payload,
                } => {
                    assert_eq!(t, msg_type);
                    assert_eq!(payload, &plain[..], "msg_type={} 解码后应还原", msg_type);
                }
                WgDecodedPacket::Junk(reason) => {
                    panic!("msg_type={} 不应被判为 junk: {}", msg_type, reason)
                }
            }
        }
    }

    /// obfs = None 时必须完全透传（原生 WireGuard 兼容，行为与改动前一致）。
    #[test]
    fn wg_obfs_disabled_is_passthrough() {
        let init = fake_wg_packet(WG_MSG_HANDSHAKE_INIT, WG_HANDSHAKE_INIT_SIZE);
        assert!(
            encode_wg_packet(&init, None).is_none(),
            "未开启混淆时必须原样发送"
        );
        match decode_wg_packet(&init, None, false) {
            WgDecodedPacket::Packet { msg_type, payload } => {
                assert_eq!(msg_type, WG_MSG_HANDSHAKE_INIT);
                assert_eq!(payload, &init[..], "未开启混淆时必须原样交给 boringtun");
            }
            WgDecodedPacket::Junk(reason) => panic!("未开启混淆时不应丢弃任何报文: {}", reason),
        }

        // 未知类型 / 长度不足 4 字节：原样发送（不 panic）
        assert!(encode_wg_packet(&[9u8; 32], Some(WgObfsConfig::BUILTIN_DEFAULT)).is_none());
        assert!(encode_wg_packet(&[1u8, 2], Some(WgObfsConfig::BUILTIN_DEFAULT)).is_none());
    }

    /// A4：长度与「剥离后前 4 字节的类型」必须同时匹配，避免把握手包/数据包互相误判。
    #[test]
    fn wg_obfs_decode_requires_len_and_type_match() {
        let obfs = WgObfsConfig::BUILTIN_DEFAULT;

        // 长度 == 148+s1，但类型不是 1（这里为 4）→ 不得当 Init 剥离 s1，只能按 Data 处理
        let fake = fake_wg_packet(WG_MSG_DATA, WG_HANDSHAKE_INIT_SIZE + obfs.s1 as usize);
        match decode_wg_packet(&fake, Some(obfs), false) {
            WgDecodedPacket::Packet { msg_type, payload } => {
                assert_eq!(msg_type, WG_MSG_DATA, "长度匹配但类型不匹配时不得判为 Init");
                assert_eq!(
                    payload.len(),
                    fake.len() - obfs.s4 as usize,
                    "应走 Data 分支（剥尾部 s4）而不是剥头部 s1"
                );
                assert_eq!(payload, &fake[..fake.len() - obfs.s4 as usize]);
            }
            WgDecodedPacket::Junk(reason) => panic!("不应判为 junk: {}", reason),
        }

        // 真 Init 但没有填充（长度 148 != 148+s1）→ 不得当混淆 Init 剥离
        let plain_init = fake_wg_packet(WG_MSG_HANDSHAKE_INIT, WG_HANDSHAKE_INIT_SIZE);
        match decode_wg_packet(&plain_init, Some(obfs), false) {
            WgDecodedPacket::Packet { payload, .. } => {
                assert_eq!(
                    payload.len(),
                    WG_HANDSHAKE_INIT_SIZE - obfs.s4 as usize,
                    "长度不匹配时必须走 Data 分支（交由 boringtun 按长度拒绝）"
                );
            }
            WgDecodedPacket::Junk(reason) => panic!("不应判为 junk: {}", reason),
        }

        // 长度不足 s4 → 丢弃
        assert!(matches!(
            decode_wg_packet(&[0u8; 8], Some(obfs), true),
            WgDecodedPacket::Junk(_)
        ));
    }

    /// A4：junk 只在会话未建立时丢弃；会话建立后，同长度报文必须按 Data 处理（不能误丢真实数据）。
    #[test]
    fn wg_obfs_junk_only_dropped_before_session_established() {
        let obfs = WgObfsConfig::BUILTIN_DEFAULT;

        // 恰好落在 junk 区间内的一段随机内容
        let junk_len = obfs.jmin as usize + 5;
        let junk = vec![0xa5u8; junk_len];
        assert!(matches!(
            decode_wg_packet(&junk, Some(obfs), false),
            WgDecodedPacket::Junk(_)
        ));

        // 会话建立后：同一段内容按 Data 处理（剥掉尾部 s4），交给 boringtun 判真伪
        match decode_wg_packet(&junk, Some(obfs), true) {
            WgDecodedPacket::Packet { payload, .. } => {
                assert_eq!(payload.len(), junk_len - obfs.s4 as usize);
            }
            WgDecodedPacket::Junk(reason) => panic!("会话建立后不应再按 junk 丢弃: {}", reason),
        }

        // 真实数据包（内容与类型都合法）混淆后恰好落在 junk 区间：会话未建立时被当 junk 丢弃，
        // 但它的编码长度是 200（=jmin），属于设计内的边界；会话建立后必须能还原出原始数据。
        let plain = fake_wg_packet(WG_MSG_DATA, obfs.jmin as usize - obfs.s4 as usize);
        let encoded = encode_wg_packet(&plain, Some(obfs)).unwrap();
        assert_eq!(encoded.len(), obfs.jmin as usize);
        assert!(matches!(
            decode_wg_packet(&encoded, Some(obfs), false),
            WgDecodedPacket::Junk(_)
        ));
        match decode_wg_packet(&encoded, Some(obfs), true) {
            WgDecodedPacket::Packet { msg_type, payload } => {
                assert_eq!(msg_type, WG_MSG_DATA);
                assert_eq!(payload, &plain[..]);
            }
            WgDecodedPacket::Junk(reason) => panic!("会话建立后必须按 Data 处理: {}", reason),
        }
    }

    /// A3：junk 包长度必须在 `[jmin, jmax]` 内、内容随机，且不会与握手包长度混淆。
    #[tokio::test]
    async fn wg_obfs_junk_packet_lengths() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let obfs = WgObfsConfig::BUILTIN_DEFAULT;
        send_obfs_junk_packets(&client, server_addr, obfs).await;

        let mut buf = vec![0u8; MAX_UDP_RECV];
        let mut lens = vec![];
        for _ in 0..obfs.jc {
            let (n, _) = tokio::time::timeout(Duration::from_secs(2), server.recv_from(&mut buf))
                .await
                .expect("应收到 junk 包")
                .unwrap();
            assert!(
                (obfs.jmin as usize..=obfs.jmax as usize).contains(&n),
                "junk 长度 {} 不在 [{}, {}] 内",
                n,
                obfs.jmin,
                obfs.jmax
            );
            lens.push(n);
        }
        // 随机长度：不要求全都不同，但至少不能全相同（jmin != jmax 时）
        assert!(lens.iter().any(|l| *l != lens[0]) || obfs.jmin == obfs.jmax);

        // jc = 0 时不发任何包
        let no_junk = WgObfsConfig { jc: 0, ..obfs };
        send_obfs_junk_packets(&client, server_addr, no_junk).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(200), server.recv_from(&mut buf))
                .await
                .is_err(),
            "jc=0 时不应发送 junk 包"
        );
    }

    #[tokio::test]
    async fn wg_pingpong() {
        let (server_cfg, client_cfg) = create_wg_config();
        let listener = WgTunnelListener::new("wg://0.0.0.0:5599".parse().unwrap(), server_cfg);
        let connector = WgTunnelConnector::new("wg://127.0.0.1:5599".parse().unwrap(), client_cfg);
        _tunnel_pingpong(listener, connector).await
    }

    /// A3/A4 + B1/B2 端到端：两端开启同一套混淆参数（含 junk 包），
    /// 客户端必须等握手真正完成才交付隧道，服务端必须等握手双向确认才交付给 accept。
    #[tokio::test]
    async fn wg_pingpong_with_obfs() {
        let (server_cfg, client_cfg) = create_wg_config();
        let obfs = WgObfsConfig::BUILTIN_DEFAULT;

        let listener = WgTunnelListener::new(
            "wg://0.0.0.0:5594".parse().unwrap(),
            server_cfg.with_obfs(Some(obfs)),
        );
        let connector = WgTunnelConnector::new(
            "wg://127.0.0.1:5594".parse().unwrap(),
            client_cfg.with_obfs(Some(obfs)),
        );
        _tunnel_pingpong(listener, connector).await
    }

    /// A3/A4 负例 + B1/B2：混淆参数不一致（仅客户端开启）时，双方都不可能完成握手。
    ///
    /// - B1：客户端等待 [`WG_HANDSHAKE_TIMEOUT`] 后必须返回 `Err`，
    ///   **绝不返回会话未建立的隧道**；
    /// - B2：服务端不得把「握手未完成」的 peer 交付给 accept 路径（不再产生半连接隧道）。
    ///
    /// 该用例耗时约 5s（握手超时）。
    #[tokio::test]
    async fn wg_connect_fails_when_obfs_mismatch() {
        let (server_cfg, client_cfg) = create_wg_config();
        let mut listener =
            WgTunnelListener::new("wg://127.0.0.1:5593".parse().unwrap(), server_cfg);
        listener.listen().await.unwrap();

        let connector = WgTunnelConnector::new(
            "wg://127.0.0.1:5593".parse().unwrap(),
            client_cfg.with_obfs(Some(WgObfsConfig::BUILTIN_DEFAULT)),
        );

        let connect_task = tokio::spawn(async move {
            let mut connector = connector;
            connector.connect().await
        });

        // 让客户端的 junk + Init 到达服务端，再确认服务端没有交付任何隧道
        tokio::time::sleep(Duration::from_millis(300)).await;
        let accept_ret = tokio::time::timeout(Duration::from_millis(500), listener.accept()).await;
        assert!(
            accept_ret.is_err(),
            "B2：握手未完成时不得把隧道交付给 accept 路径（半连接）"
        );

        let connect_ret = connect_task.await.unwrap();
        assert!(
            connect_ret.is_err(),
            "B1：混淆参数不一致时必须连接失败，而不是交付会话未建立的隧道"
        );
    }

    #[tokio::test]
    async fn wg_bench() {
        let (server_cfg, client_cfg) = create_wg_config();
        let listener = WgTunnelListener::new("wg://0.0.0.0:5598".parse().unwrap(), server_cfg);
        let connector = WgTunnelConnector::new("wg://127.0.0.1:5598".parse().unwrap(), client_cfg);
        _tunnel_bench(listener, connector).await
    }

    #[tokio::test]
    async fn wg_bench_with_bind() {
        let (server_cfg, client_cfg) = create_wg_config();
        let listener = WgTunnelListener::new("wg://127.0.0.1:5597".parse().unwrap(), server_cfg);
        let mut connector =
            WgTunnelConnector::new("wg://127.0.0.1:5597".parse().unwrap(), client_cfg);
        connector.set_bind_addrs(vec!["127.0.0.1:0".parse().unwrap()]);
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    #[should_panic]
    async fn wg_bench_with_bind_fail() {
        let (server_cfg, client_cfg) = create_wg_config();
        let listener = WgTunnelListener::new("wg://127.0.0.1:5596".parse().unwrap(), server_cfg);
        let mut connector =
            WgTunnelConnector::new("wg://127.0.0.1:5596".parse().unwrap(), client_cfg);
        connector.set_bind_addrs(vec!["10.0.0.1:0".parse().unwrap()]);
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn wg_server_erase_from_map_after_close() {
        let (server_cfg, client_cfg) = create_wg_config();
        let mut listener =
            WgTunnelListener::new("wg://127.0.0.1:5595".parse().unwrap(), server_cfg);
        listener.listen().await.unwrap();

        const CONN_COUNT: usize = 10;

        tokio::spawn(async move {
            let mut tunnels = vec![];
            for _ in 0..CONN_COUNT {
                let mut connector = WgTunnelConnector::new(
                    "wg://127.0.0.1:5595".parse().unwrap(),
                    client_cfg.clone(),
                );
                let ret = connector.connect().await;
                assert!(ret.is_ok());
                let t = ret.unwrap();
                let (_stream, mut sink) = t.split();
                sink.send(ZCPacket::new_with_payload("payload".as_bytes()))
                    .await
                    .unwrap();
                tunnels.push(t);
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        });

        for _ in 0..CONN_COUNT {
            println!("accepting");
            let conn = listener.accept().await;
            let (mut stream, _sink) = conn.unwrap().split();
            let packet = stream.next().await.unwrap().unwrap();
            assert_eq!("payload".as_bytes(), packet.payload());
            println!("accepting drop");
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        assert_eq!(0, listener.wg_peer_map.len());
    }

    #[tokio::test]
    async fn bind_same_port() {
        let (server_cfg, _client_cfg) = create_wg_config();
        let mut listener = WgTunnelListener::new("wg://[::1]:31015".parse().unwrap(), server_cfg);
        let (server_cfg, _client_cfg) = create_wg_config();
        let mut listener2 = WgTunnelListener::new("wg://[::1]:31015".parse().unwrap(), server_cfg);
        listener.listen().await.unwrap();
        listener2.listen().await.unwrap();
    }

    #[tokio::test]
    async fn ipv6_pingpong() {
        let (server_cfg, client_cfg) = create_wg_config();
        let listener = WgTunnelListener::new("wg://[::1]:31015".parse().unwrap(), server_cfg);
        let connector = WgTunnelConnector::new("wg://[::1]:31015".parse().unwrap(), client_cfg);
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn ipv6_domain_pingpong() {
        let (server_cfg, client_cfg) = create_wg_config();
        let listener = WgTunnelListener::new("wg://[::1]:31016".parse().unwrap(), server_cfg);
        let mut connector =
            WgTunnelConnector::new("wg://test.easytier.top:31016".parse().unwrap(), client_cfg);
        connector.set_ip_version(IpVersion::V6);
        _tunnel_pingpong(listener, connector).await;

        let (server_cfg, client_cfg) = create_wg_config();
        let listener = WgTunnelListener::new("wg://127.0.0.1:31016".parse().unwrap(), server_cfg);
        let mut connector =
            WgTunnelConnector::new("wg://test.easytier.top:31016".parse().unwrap(), client_cfg);
        connector.set_ip_version(IpVersion::V4);
        _tunnel_pingpong(listener, connector).await;
    }

    #[tokio::test]
    async fn test_alloc_port() {
        // v4
        let (server_cfg, _client_cfg) = create_wg_config();
        let mut listener = WgTunnelListener::new("wg://0.0.0.0:0".parse().unwrap(), server_cfg);
        listener.listen().await.unwrap();
        let port = listener.local_url().port().unwrap();
        assert!(port > 0);

        // v6
        let (server_cfg, _client_cfg) = create_wg_config();
        let mut listener = WgTunnelListener::new("wg://[::]:0".parse().unwrap(), server_cfg);
        listener.listen().await.unwrap();
        let port = listener.local_url().port().unwrap();
        assert!(port > 0);
    }
}
