use std::{
    fmt::{Debug, Formatter},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, atomic::AtomicBool},
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
    common::{global_ctx::ArcGlobalCtx, shrink_dashmap},
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
        }
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
                self.udp
                    .send_to(packet, self.endpoint)
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
    #[tracing::instrument(skip(sink))]
    pub async fn handle_one_packet_from_peer<S: ZCPacketSink + Unpin>(
        &self,
        mut sink: S,
        recv_buf: &[u8],
    ) {
        let mut send_buf = vec![0u8; MAX_PACKET];
        let data = recv_buf;
        let decapsulate_result = {
            let mut peer = self.tunn.lock().await;
            peer.decapsulate(None, data, &mut send_buf)
        };

        tracing::debug!("Decapsulation result: {:?}", decapsulate_result);

        match decapsulate_result {
            TunnResult::WriteToNetwork(packet) => {
                match self.udp.send_to(packet, self.endpoint).await {
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!(
                            "Failed to send decapsulation-instructed packet to WireGuard endpoint: {:?}",
                            e
                        );
                        return;
                    }
                };
                let mut peer = self.tunn.lock().await;
                loop {
                    let mut send_buf = vec![0u8; MAX_PACKET];
                    match peer.decapsulate(None, &[], &mut send_buf) {
                        TunnResult::WriteToNetwork(packet) => {
                            match self.udp.send_to(packet, self.endpoint).await {
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
            }
            _ => {
                tracing::debug!(
                    "Unexpected WireGuard state during decapsulation: {:?}",
                    decapsulate_result
                );
            }
        }
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
                match self.udp.send_to(packet, self.endpoint).await {
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
        tracing::trace!("Received {} bytes from peer", packet.len());
        let data = self.data.as_ref().unwrap();
        // TODO: improve this
        let mut sink = self.sink.lock().unwrap().take().unwrap();
        data.handle_one_packet_from_peer(&mut sink, packet).await;
        self.sink.lock().unwrap().replace(sink);
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

    async fn create_handshake_init(&self) -> Vec<u8> {
        let mut dst = vec![0u8; 2048];
        let handshake_init = self
            .tunn
            .as_ref()
            .unwrap()
            .lock()
            .await
            .format_handshake_initiation(&mut dst, false);
        assert!(matches!(handshake_init, TunnResult::WriteToNetwork(_)));
        let handshake_init = if let TunnResult::WriteToNetwork(sent) = handshake_init {
            sent
        } else {
            unreachable!();
        };

        handshake_init.into()
    }

    fn udp_socket(&self) -> Arc<UdpSocket> {
        self.udp.clone()
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
                peer_map_clone.retain(|_, peer| {
                    peer.access_time.load().elapsed().as_secs() < 61 && !peer.stopped()
                });
                shrink_dashmap(&peer_map_clone, None);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });

        let mut buf = vec![0u8; MAX_PACKET];
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
                if let Err(e) = conn_sender.send(tunnel) {
                    tracing::error!("Failed to send tunnel to conn_sender: {}", e);
                }
                peer_map.insert(addr, Arc::new(wg));
            }

            let peer = peer_map.get(&addr).unwrap().clone();
            peer.handle_packet_from_peer(data).await;
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

        // do handshake here so we will return after receive first packet
        let handshake = wg_peer.create_handshake_init().await;
        udp.send_to(&handshake, addr).await?;
        let mut buf = [0u8; MAX_PACKET];
        let (n, recv_addr) = match udp.recv_from(&mut buf).await {
            Ok(ret) => ret,
            Err(e) => {
                tracing::error!("Failed to receive handshake response: {}", e);
                return Err(TunnelError::IOError(e));
            }
        };

        if recv_addr != addr {
            tracing::warn!(?recv_addr, "Received packet from changed address");
        }

        let tunnel = wg_peer.start_and_get_tunnel();
        let data = wg_peer.data.as_ref().unwrap().clone();
        let mut sink = wg_peer.sink.lock().unwrap().take().unwrap();
        wg_peer.tasks.spawn(async move {
            data.handle_one_packet_from_peer(&mut sink, &buf[..n]).await;
            loop {
                let mut buf = vec![0u8; MAX_PACKET];
                let (n, _) = match udp.recv_from(&mut buf).await {
                    Ok(ret) => ret,
                    Err(e) => {
                        tracing::error!("Failed to receive wg packet: {}", e);
                        break;
                    }
                };
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
        };

        let client_cfg = WgConfig {
            my_secret_key: their_secret_key,
            my_public_key: their_public_key,
            peer_secret_key: my_secret_key,
            peer_public_key: my_public_key,
            wg_type: WgType::InternalUse,
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

    #[tokio::test]
    async fn wg_pingpong() {
        let (server_cfg, client_cfg) = create_wg_config();
        let listener = WgTunnelListener::new("wg://0.0.0.0:5599".parse().unwrap(), server_cfg);
        let connector = WgTunnelConnector::new("wg://127.0.0.1:5599".parse().unwrap(), client_cfg);
        _tunnel_pingpong(listener, connector).await
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
