use std::sync::Arc;

use crossbeam::atomic::AtomicCell;
use dashmap::{DashMap, DashSet};
use parking_lot::RwLock;

use tokio::{select, sync::mpsc};

use tracing::Instrument;

use super::{
    PacketRecvChan,
    peer_conn::{PeerConn, PeerConnId},
};
use crate::{common::shrink_dashmap, proto::api::instance::PeerConnInfo};
use crate::{
    common::{
        PeerId,
        error::Error,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
    },
    proto::peer_rpc::PeerIdentityType,
    tunnel::packet_def::ZCPacket,
};
use tokio_util::task::AbortOnDropHandle;

type ArcPeerConn = Arc<PeerConn>;
type ConnMap = Arc<DashMap<PeerConnId, ArcPeerConn>>;

/// 数据面选路的候选项：把 `PeerConn` 中参与挑选的字段抽出来，
/// 使挑选逻辑成为不依赖真实 tunnel 的纯函数，便于单元测试
/// （构造真实 `PeerConn` 需要 ring tunnel + 握手，成本高且易碎）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DataPathCandidate {
    conn_id: PeerConnId,
    /// 连接已关闭，不能再用于发送
    is_closed: bool,
    /// 协议已上报“数据面就绪”（默认 true，见 `PeerConn::is_ready_for_data`）
    ready_for_data: bool,
    /// 是否已有真实延迟采样；无采样时 `latency_us` 恒为 0，绝不代表“最快”
    has_latency_sample: bool,
    latency_us: u64,
}

impl DataPathCandidate {
    /// 是否可作为数据面候选：未关闭且协议认为已就绪。
    fn is_eligible(&self) -> bool {
        !self.is_closed && self.ready_for_data
    }
}

/// 从候选中挑选默认数据面连接，返回被选中的 `conn_id`。
///
/// 规则：
/// 1. 只考虑未关闭且 `ready_for_data == true` 的连接；
/// 2. 在有延迟采样的候选里选延迟最小的一条（`<` 比较，保持原有“先到先得”的稳定性）；
/// 3. 若一条有采样的候选都没有（例如刚建连、pingpong 还没跑完），
///    回退到第一条可用候选，避免“一条都不选”导致数据面死锁；
/// 4. 若没有任何可用候选（全部关闭 / 全部未就绪），返回 `None`
///    （`Peer::send_msg` 会转成 `PeerNoConnectionError`，行为正确）。
///
/// 关键点：**不把“无延迟采样”当成“延迟 0”**，否则刚加入的连接（尤其是握手未完成、
/// 实际不可用的半连接）会凭 0 延迟抢占该 peer 的默认数据面，把整条路径的流量带进黑洞。
fn pick_default_conn(candidates: &[DataPathCandidate]) -> Option<PeerConnId> {
    let mut best_sampled: Option<&DataPathCandidate> = None;
    let mut fallback: Option<&DataPathCandidate> = None;

    for candidate in candidates.iter().filter(|c| c.is_eligible()) {
        if candidate.has_latency_sample {
            if best_sampled.is_none_or(|best| candidate.latency_us < best.latency_us) {
                best_sampled = Some(candidate);
            }
        } else if fallback.is_none() {
            fallback = Some(candidate);
        }
    }

    best_sampled.or(fallback).map(|c| c.conn_id)
}

pub struct Peer {
    pub peer_node_id: PeerId,
    conns: ConnMap,
    global_ctx: ArcGlobalCtx,

    packet_recv_chan: PacketRecvChan,

    close_event_sender: mpsc::Sender<PeerConnId>,
    close_event_listener: AbortOnDropHandle<()>,

    shutdown_notifier: Arc<tokio::sync::Notify>,

    default_conn_id: Arc<AtomicCell<PeerConnId>>,
    peer_identity_type: Arc<AtomicCell<Option<PeerIdentityType>>>,
    peer_public_key: Arc<RwLock<Option<Vec<u8>>>>,
    default_conn_id_clear_task: AbortOnDropHandle<()>,
}

impl Peer {
    pub fn new(
        peer_node_id: PeerId,
        packet_recv_chan: PacketRecvChan,
        global_ctx: ArcGlobalCtx,
    ) -> Self {
        let conns: ConnMap = Arc::new(DashMap::new());
        let (close_event_sender, mut close_event_receiver) = mpsc::channel(10);
        let shutdown_notifier = Arc::new(tokio::sync::Notify::new());
        let peer_identity_type = Arc::new(AtomicCell::new(None));
        let peer_identity_type_copy = peer_identity_type.clone();
        let peer_public_key = Arc::new(RwLock::new(None));
        let peer_public_key_copy = peer_public_key.clone();

        let conns_copy = conns.clone();
        let shutdown_notifier_copy = shutdown_notifier.clone();
        let global_ctx_copy = global_ctx.clone();
        let close_event_listener = AbortOnDropHandle::new(tokio::spawn(
            async move {
                loop {
                    select! {
                        ret = close_event_receiver.recv() => {
                            if ret.is_none() {
                                break;
                            }
                            let ret = ret.unwrap();
                            tracing::warn!(
                                ?peer_node_id,
                                ?ret,
                                "notified that peer conn is closed",
                            );

                            if let Some((_, conn)) = conns_copy.remove(&ret) {
                                global_ctx_copy.issue_event(GlobalCtxEvent::PeerConnRemoved(
                                    conn.get_conn_info(),
                                ));
                                shrink_dashmap(&conns_copy, Some(4));
                                if conns_copy.is_empty() {
                                    peer_identity_type_copy.store(None);
                                    *peer_public_key_copy.write() = None;
                                }
                            }
                        }

                        _ = shutdown_notifier_copy.notified() => {
                            close_event_receiver.close();
                            tracing::warn!(?peer_node_id, "peer close event listener notified");
                        }
                    }
                }
                tracing::info!("peer {} close event listener exit", peer_node_id);
            }
            .instrument(tracing::info_span!(
                "peer_close_event_listener",
                ?peer_node_id,
            )),
        ));

        let default_conn_id = Arc::new(AtomicCell::new(PeerConnId::default()));

        let conns_copy = conns.clone();
        let default_conn_id_copy = default_conn_id.clone();
        let default_conn_id_clear_task = AbortOnDropHandle::new(tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                if conns_copy.len() > 1 {
                    default_conn_id_copy.store(PeerConnId::default());
                }
            }
        }));

        Peer {
            peer_node_id,
            conns,
            packet_recv_chan,
            global_ctx,

            close_event_sender,
            close_event_listener,

            shutdown_notifier,
            default_conn_id,
            peer_identity_type,
            peer_public_key,
            default_conn_id_clear_task,
        }
    }

    pub async fn add_peer_conn(&self, mut conn: PeerConn) -> Result<(), Error> {
        let conn_identity_type = conn.get_peer_identity_type();
        let peer_identity_type = self.peer_identity_type.load();
        if let Some(peer_identity_type) = peer_identity_type {
            if peer_identity_type != conn_identity_type {
                return Err(Error::SecretKeyError(format!(
                    "peer identity type mismatch. peer: {:?}, conn: {:?}",
                    peer_identity_type, conn_identity_type
                )));
            }
        } else {
            self.peer_identity_type.store(Some(conn_identity_type));
        }

        let close_notifier = conn.get_close_notifier();
        let conn_info = conn.get_conn_info();
        let conn_pubkey = conn_info.noise_remote_static_pubkey.clone();
        {
            let mut peer_pubkey = self.peer_public_key.write();
            if let Some(existing_pubkey) = peer_pubkey.as_ref() {
                if existing_pubkey != &conn_pubkey {
                    return Err(Error::SecretKeyError(format!(
                        "peer public key mismatch. peer_id: {}, existing_len: {}, new_len: {}",
                        self.peer_node_id,
                        existing_pubkey.len(),
                        conn_pubkey.len()
                    )));
                }
            } else {
                *peer_pubkey = Some(conn_pubkey);
            }
        }

        conn.start_recv_loop(self.packet_recv_chan.clone()).await;
        conn.start_pingpong();
        self.conns.insert(conn.get_conn_id(), Arc::new(conn));

        let close_event_sender = self.close_event_sender.clone();
        tokio::spawn(async move {
            let conn_id = close_notifier.get_conn_id();
            if let Some(mut waiter) = close_notifier.get_waiter().await {
                let _ = waiter.recv().await;
            }
            if let Err(e) = close_event_sender.send(conn_id).await {
                tracing::warn!(?conn_id, "failed to send close event: {}", e);
            }
        });

        self.global_ctx
            .issue_event(GlobalCtxEvent::PeerConnAdded(conn_info));
        Ok(())
    }

    async fn select_conn(&self) -> Option<ArcPeerConn> {
        // 1. 缓存的默认连接仍然“可用”时优先复用，避免每次发包都重新比较造成的抖动。
        //    注意：必须校验状态，否则已关闭 / 尚未就绪的连接会被一直沿用。
        let default_conn_id = self.default_conn_id.load();
        if let Some(conn) = self.conns.get(&default_conn_id)
            && Self::is_conn_eligible_for_data(conn.value())
        {
            return Some(conn.clone());
        }

        // 2. 收集候选项。这里只把参与挑选的字段拷贝出来，不要在持有 DashMap 迭代器
        //    期间再调用 self.conns.get()（会死锁）。
        let candidates: Vec<DataPathCandidate> = self
            .conns
            .iter()
            .map(|entry| {
                let conn = entry.value();
                DataPathCandidate {
                    conn_id: conn.get_conn_id(),
                    is_closed: conn.is_closed(),
                    ready_for_data: conn.is_ready_for_data(),
                    has_latency_sample: conn.has_latency_sample(),
                    latency_us: conn.get_stats().latency_us,
                }
            })
            .collect();

        // 3. 统一由纯函数挑选：跳过已关闭 / 未就绪的连接，且不把“无采样”当成“延迟 0”。
        let selected_conn_id = pick_default_conn(&candidates)?;
        self.default_conn_id.store(selected_conn_id);
        self.conns.get(&selected_conn_id).map(|conn| conn.clone())
    }

    /// 连接是否可以参与数据面选路：未关闭且协议已上报“数据面就绪”。
    fn is_conn_eligible_for_data(conn: &PeerConn) -> bool {
        !conn.is_closed() && conn.is_ready_for_data()
    }

    pub async fn send_msg(&self, msg: ZCPacket) -> Result<(), Error> {
        let Some(conn) = self.select_conn().await else {
            return Err(Error::PeerNoConnectionError(self.peer_node_id));
        };
        conn.send_msg(msg).await?;

        Ok(())
    }

    pub async fn close_peer_conn(&self, conn_id: &PeerConnId) -> Result<(), Error> {
        let has_key = self.conns.contains_key(conn_id);
        if !has_key {
            return Err(Error::NotFound);
        }
        self.close_event_sender.send(*conn_id).await.unwrap();
        Ok(())
    }

    pub async fn list_peer_conns(&self) -> Vec<PeerConnInfo> {
        let mut conns = vec![];
        for conn in self.conns.iter() {
            // do not lock here, otherwise it will cause dashmap deadlock
            conns.push(conn.clone());
        }

        let mut ret = Vec::new();
        for conn in conns {
            let info = conn.get_conn_info();
            if !info.is_closed {
                ret.push(info);
            } else {
                let conn_id = info.conn_id.parse().unwrap();
                let _ = self.close_peer_conn(&conn_id).await;
            }
        }
        ret
    }

    pub fn has_live_conns(&self) -> bool {
        self.conns.iter().any(|entry| !entry.value().is_closed())
    }

    pub fn has_directly_connected_conn(&self) -> bool {
        self.conns
            .iter()
            .any(|entry| !entry.value().is_closed() && !entry.value().is_hole_punched())
    }

    pub fn get_directly_connections(&self) -> DashSet<uuid::Uuid> {
        self.conns
            .iter()
            .filter(|entry| !(entry.value()).is_hole_punched())
            .map(|entry| (entry.value()).get_conn_id())
            .collect()
    }

    pub fn get_default_conn_id(&self) -> PeerConnId {
        self.default_conn_id.load()
    }

    pub fn get_peer_identity_type(&self) -> Option<PeerIdentityType> {
        self.peer_identity_type.load()
    }

    pub fn get_peer_public_key(&self) -> Option<Vec<u8>> {
        self.peer_public_key.read().clone()
    }
}

// pritn on drop
impl Drop for Peer {
    fn drop(&mut self) {
        self.conns.retain(|_, conn| {
            self.global_ctx
                .issue_event(GlobalCtxEvent::PeerConnRemoved(conn.get_conn_info()));
            false
        });
        self.shutdown_notifier.notify_one();
        tracing::info!("peer {} drop", self.peer_node_id);
    }
}

#[cfg(test)]
mod tests {
    use base64::prelude::{BASE64_STANDARD, Engine as _};
    use rand::rngs::OsRng;
    use std::sync::Arc;
    use tokio::time::timeout;

    use crate::{
        common::{
            config::{NetworkIdentity, PeerConfig},
            global_ctx::{GlobalCtx, tests::get_mock_global_ctx},
            new_peer_id,
        },
        peers::{
            create_packet_recv_chan,
            peer_conn::{PeerConn, PeerConnId},
            peer_session::PeerSessionStore,
        },
        proto::common::SecureModeConfig,
        tunnel::ring::create_ring_tunnel_pair,
    };

    use super::{DataPathCandidate, Peer, pick_default_conn};

    fn set_secure_mode_cfg(global_ctx: &GlobalCtx, enabled: bool) {
        if !enabled {
            global_ctx.config.set_secure_mode(None);
        } else {
            let private = x25519_dalek::StaticSecret::random_from_rng(OsRng);
            let public = x25519_dalek::PublicKey::from(&private);
            global_ctx.config.set_secure_mode(Some(SecureModeConfig {
                enabled: true,
                local_private_key: Some(BASE64_STANDARD.encode(private.as_bytes())),
                local_public_key: Some(BASE64_STANDARD.encode(public.as_bytes())),
            }));
        }
    }

    #[tokio::test]
    async fn close_peer() {
        let (local_packet_send, _local_packet_recv) = create_packet_recv_chan();
        let (remote_packet_send, _remote_packet_recv) = create_packet_recv_chan();
        let global_ctx = get_mock_global_ctx();
        let local_peer = Peer::new(new_peer_id(), local_packet_send, global_ctx.clone());
        let remote_peer = Peer::new(new_peer_id(), remote_packet_send, global_ctx.clone());

        let ps = Arc::new(PeerSessionStore::new());
        let (local_tunnel, remote_tunnel) = create_ring_tunnel_pair();
        let mut local_peer_conn = PeerConn::new(
            local_peer.peer_node_id,
            global_ctx.clone(),
            local_tunnel,
            ps.clone(),
        );
        let mut remote_peer_conn = PeerConn::new(
            remote_peer.peer_node_id,
            global_ctx.clone(),
            remote_tunnel,
            ps.clone(),
        );

        assert!(!local_peer_conn.handshake_done());
        assert!(!remote_peer_conn.handshake_done());

        let (a, b) = tokio::join!(
            local_peer_conn.do_handshake_as_client(),
            remote_peer_conn.do_handshake_as_server()
        );
        a.unwrap();
        b.unwrap();

        let local_conn_id = local_peer_conn.get_conn_id();

        local_peer.add_peer_conn(local_peer_conn).await.unwrap();
        remote_peer.add_peer_conn(remote_peer_conn).await.unwrap();

        assert_eq!(local_peer.list_peer_conns().await.len(), 1);
        assert_eq!(remote_peer.list_peer_conns().await.len(), 1);

        let close_handler =
            tokio::spawn(async move { local_peer.close_peer_conn(&local_conn_id).await });

        // wait for remote peer conn close
        timeout(std::time::Duration::from_secs(5), async {
            while !remote_peer.list_peer_conns().await.is_empty() {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap();

        println!("wait for close handler");
        close_handler.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn reject_peer_conn_with_mismatched_identity_type() {
        let (packet_send, _packet_recv) = create_packet_recv_chan();
        let global_ctx = get_mock_global_ctx();
        let local_peer_id = new_peer_id();
        let remote_peer_id = new_peer_id();
        let peer = Peer::new(remote_peer_id, packet_send, global_ctx);

        let ps = Arc::new(PeerSessionStore::new());

        let (shared_client_tunnel, shared_server_tunnel) = create_ring_tunnel_pair();
        let shared_client_ctx = get_mock_global_ctx();
        let shared_server_ctx = get_mock_global_ctx();
        shared_client_ctx
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec2".to_string()));
        shared_server_ctx
            .config
            .set_network_identity(NetworkIdentity {
                network_name: "net2".to_string(),
                network_secret: None,
                network_secret_digest: None,
            });
        set_secure_mode_cfg(&shared_client_ctx, true);
        set_secure_mode_cfg(&shared_server_ctx, true);
        let remote_url: url::Url = shared_client_tunnel
            .info()
            .unwrap()
            .remote_addr
            .unwrap()
            .url
            .parse()
            .unwrap();
        shared_client_ctx.config.set_peers(vec![PeerConfig {
            uri: remote_url,
            peer_public_key: Some(
                shared_server_ctx
                    .config
                    .get_secure_mode()
                    .unwrap()
                    .local_public_key
                    .unwrap(),
            ),
        }]);
        let mut shared_client_conn = PeerConn::new(
            local_peer_id,
            shared_client_ctx,
            Box::new(shared_client_tunnel),
            ps.clone(),
        );
        let mut shared_server_conn = PeerConn::new(
            remote_peer_id,
            shared_server_ctx,
            Box::new(shared_server_tunnel),
            ps.clone(),
        );
        let (c1, s1) = tokio::join!(
            shared_client_conn.do_handshake_as_client(),
            shared_server_conn.do_handshake_as_server()
        );
        c1.unwrap();
        s1.unwrap();
        assert_eq!(
            shared_client_conn.get_peer_identity_type(),
            crate::proto::peer_rpc::PeerIdentityType::SharedNode
        );

        let (admin_client_tunnel, admin_server_tunnel) = create_ring_tunnel_pair();
        let admin_client_ctx = get_mock_global_ctx();
        let admin_server_ctx = get_mock_global_ctx();
        admin_client_ctx
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec2".to_string()));
        admin_server_ctx
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec2".to_string()));
        set_secure_mode_cfg(&admin_client_ctx, true);
        set_secure_mode_cfg(&admin_server_ctx, true);
        let mut admin_client_conn = PeerConn::new(
            local_peer_id,
            admin_client_ctx,
            Box::new(admin_client_tunnel),
            Arc::new(PeerSessionStore::new()),
        );
        let mut admin_server_conn = PeerConn::new(
            remote_peer_id,
            admin_server_ctx,
            Box::new(admin_server_tunnel),
            Arc::new(PeerSessionStore::new()),
        );
        let (c2, s2) = tokio::join!(
            admin_client_conn.do_handshake_as_client(),
            admin_server_conn.do_handshake_as_server()
        );
        c2.unwrap();
        s2.unwrap();
        assert_eq!(
            admin_client_conn.get_peer_identity_type(),
            crate::proto::peer_rpc::PeerIdentityType::Admin
        );

        peer.add_peer_conn(shared_client_conn).await.unwrap();
        let ret = peer.add_peer_conn(admin_client_conn).await;
        assert!(ret.is_err());
    }

    #[tokio::test]
    async fn reject_peer_conn_with_mismatched_public_key() {
        let (packet_send, _packet_recv) = create_packet_recv_chan();
        let local_peer_id = new_peer_id();
        let remote_peer_id = new_peer_id();
        let peer = Peer::new(remote_peer_id, packet_send, get_mock_global_ctx());
        let ps = Arc::new(PeerSessionStore::new());

        let (client_tunnel_1, server_tunnel_1) = create_ring_tunnel_pair();
        let client_ctx_1 = get_mock_global_ctx();
        let server_ctx_1 = get_mock_global_ctx();
        client_ctx_1
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec1".to_string()));
        server_ctx_1
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec1".to_string()));
        set_secure_mode_cfg(&client_ctx_1, true);
        set_secure_mode_cfg(&server_ctx_1, true);
        let mut client_conn_1 = PeerConn::new(
            local_peer_id,
            client_ctx_1,
            Box::new(client_tunnel_1),
            ps.clone(),
        );
        let mut server_conn_1 = PeerConn::new(
            remote_peer_id,
            server_ctx_1,
            Box::new(server_tunnel_1),
            ps.clone(),
        );
        let (c1, s1) = tokio::join!(
            client_conn_1.do_handshake_as_client(),
            server_conn_1.do_handshake_as_server()
        );
        c1.unwrap();
        s1.unwrap();

        let (client_tunnel_2, server_tunnel_2) = create_ring_tunnel_pair();
        let client_ctx_2 = get_mock_global_ctx();
        let server_ctx_2 = get_mock_global_ctx();
        client_ctx_2
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec1".to_string()));
        server_ctx_2
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec1".to_string()));
        set_secure_mode_cfg(&client_ctx_2, true);
        set_secure_mode_cfg(&server_ctx_2, true);
        let mut client_conn_2 = PeerConn::new(
            local_peer_id,
            client_ctx_2,
            Box::new(client_tunnel_2),
            Arc::new(PeerSessionStore::new()),
        );
        let mut server_conn_2 = PeerConn::new(
            remote_peer_id,
            server_ctx_2,
            Box::new(server_tunnel_2),
            Arc::new(PeerSessionStore::new()),
        );
        let (c2, s2) = tokio::join!(
            client_conn_2.do_handshake_as_client(),
            server_conn_2.do_handshake_as_server()
        );
        c2.unwrap();
        s2.unwrap();

        let pubkey_1 = client_conn_1.get_conn_info().noise_remote_static_pubkey;
        let pubkey_2 = client_conn_2.get_conn_info().noise_remote_static_pubkey;
        assert_ne!(pubkey_1, pubkey_2);

        peer.add_peer_conn(client_conn_1).await.unwrap();
        assert_eq!(peer.get_peer_public_key(), Some(pubkey_1));
        let ret = peer.add_peer_conn(client_conn_2).await;
        assert!(ret.is_err());
    }

    /// 构造一个测试用候选连接。
    fn test_candidate(
        conn_id: u128,
        latency_us: u64,
        has_latency_sample: bool,
        ready_for_data: bool,
    ) -> DataPathCandidate {
        DataPathCandidate {
            conn_id: uuid::Uuid::from_u128(conn_id),
            is_closed: false,
            ready_for_data,
            has_latency_sample,
            latency_us,
        }
    }

    /// 建一对已握手、已各自加入 Peer 的连接，返回
    /// (本地 Peer, 远端 Peer, 本地 conn_id)。远端 Peer 需由调用方持有，
    /// 否则连接会被提前关闭。`ready_for_data` 在加入 Peer 之前设置。
    async fn setup_peer_with_one_conn(ready_for_data: bool) -> (Peer, Peer, PeerConnId) {
        let (local_packet_send, _local_packet_recv) = create_packet_recv_chan();
        let (remote_packet_send, _remote_packet_recv) = create_packet_recv_chan();
        let global_ctx = get_mock_global_ctx();
        let local_peer = Peer::new(new_peer_id(), local_packet_send, global_ctx.clone());
        let remote_peer = Peer::new(new_peer_id(), remote_packet_send, global_ctx.clone());
        let ps = Arc::new(PeerSessionStore::new());

        let (local_tunnel, remote_tunnel) = create_ring_tunnel_pair();
        let mut local_conn = PeerConn::new(
            local_peer.peer_node_id,
            global_ctx.clone(),
            local_tunnel,
            ps.clone(),
        );
        let mut remote_conn = PeerConn::new(
            remote_peer.peer_node_id,
            global_ctx.clone(),
            remote_tunnel,
            ps.clone(),
        );

        let (client_ret, server_ret) = tokio::join!(
            local_conn.do_handshake_as_client(),
            remote_conn.do_handshake_as_server()
        );
        client_ret.unwrap();
        server_ret.unwrap();

        let conn_id = local_conn.get_conn_id();
        // 默认必须是 true（保证 tcp/udp/ws 等既有协议行为不变）
        assert!(local_conn.is_ready_for_data());
        assert!(!local_conn.has_latency_sample());
        local_conn.set_ready_for_data(ready_for_data);

        local_peer.add_peer_conn(local_conn).await.unwrap();
        remote_peer.add_peer_conn(remote_conn).await.unwrap();

        (local_peer, remote_peer, conn_id)
    }

    /// 用例 1：一条“有真实延迟采样”的连接 + 一条“新加入、无采样（延迟记为 0）”的连接
    /// → 必须选中前者，且与遍历顺序无关。
    #[test]
    fn select_conn_prefers_conn_with_real_latency_sample() {
        let sampled = test_candidate(1, 5_000, true, true);
        let fresh = test_candidate(2, 0, false, true);

        assert_eq!(pick_default_conn(&[sampled, fresh]), Some(sampled.conn_id));
        assert_eq!(pick_default_conn(&[fresh, sampled]), Some(sampled.conn_id));

        // 多条都有采样时，仍然选延迟最小的一条
        let slower = test_candidate(3, 80_000, true, true);
        assert_eq!(
            pick_default_conn(&[slower, sampled, fresh]),
            Some(sampled.conn_id)
        );
    }

    /// 用例 2：唯一一条连接未就绪 → 必须返回 None（交给 `PeerNoConnectionError`）；
    /// 已关闭的连接同样不可用；但“唯一一条就绪、只是还没采样”必须回退选中它。
    #[test]
    fn select_conn_returns_none_when_only_conn_is_not_usable() {
        let unready = test_candidate(1, 0, false, false);
        assert_eq!(pick_default_conn(&[unready]), None);

        let closed = DataPathCandidate {
            is_closed: true,
            ..test_candidate(2, 1_000, true, true)
        };
        assert_eq!(pick_default_conn(&[closed]), None);

        // 边界：全都没采样时回退到第一条可用连接，不能“一条都不选”
        let fresh_a = test_candidate(3, 0, false, true);
        let fresh_b = test_candidate(4, 0, false, true);
        assert_eq!(
            pick_default_conn(&[fresh_a, fresh_b]),
            Some(fresh_a.conn_id)
        );
    }

    /// 用例 3：`ready_for_data == true` 的连接优先级不被 `false` 的连接抢占
    /// （即便后者延迟更低或更“新鲜”）。
    #[test]
    fn select_conn_never_picks_not_ready_conn() {
        let ready_sampled = test_candidate(1, 20_000, true, true);
        let unready_faster = test_candidate(2, 1_000, true, false);
        assert_eq!(
            pick_default_conn(&[ready_sampled, unready_faster]),
            Some(ready_sampled.conn_id)
        );

        // 就绪但无采样 vs 未就绪但有采样：仍然选就绪的那条
        let ready_fresh = test_candidate(3, 0, false, true);
        let unready_sampled = test_candidate(4, 1_000, true, false);
        assert_eq!(
            pick_default_conn(&[ready_fresh, unready_sampled]),
            Some(ready_fresh.conn_id)
        );

        // 全部未就绪 / 空集合 → None
        assert_eq!(pick_default_conn(&[unready_faster, unready_sampled]), None);
        assert_eq!(pick_default_conn(&[]), None);
    }

    /// 真实连接对象级别的最小回归：验证 `ready_for_data` 落在 `PeerConn` 上、
    /// 默认 true、accessor 可用，并且 `Peer::select_conn()` 确实按该标志过滤。
    ///
    /// 取舍：往真实连接里注入“延迟采样”需要让 pingpong 真正跑起来（依赖远端
    /// 应答与定时器），测试会不稳定；因此“无采样不得当成延迟 0”的判定放在上面的
    /// 纯函数用例里覆盖，这里只验证标志的承载与过滤接线。
    #[tokio::test]
    async fn select_conn_respects_ready_for_data_flag() {
        // 默认 ready=true：唯一一条连接即使还没采样也必须被选中（回退语义）
        let (local_peer, _remote_peer, conn_id) = setup_peer_with_one_conn(true).await;
        let selected = local_peer.select_conn().await.expect("就绪连接应被选中");
        assert_eq!(selected.get_conn_id(), conn_id);
        assert!(selected.is_ready_for_data());

        // ready=false：唯一一条连接被 select_conn 过滤 → None
        let (local_peer, _remote_peer, _conn_id) = setup_peer_with_one_conn(false).await;
        assert!(local_peer.select_conn().await.is_none());
    }
}
