use std::{
    collections::BTreeSet,
    future::Future,
    sync::{Arc, Weak},
    time::{Duration, Instant},
};

use dashmap::{DashMap, DashSet};
use tokio::{sync::mpsc, task::JoinSet, time::timeout};

use crate::{
    common::{PeerId, dns::socket_addrs, join_joinset_background},
    peers::peer_conn::PeerConnId,
    proto::{
        api::instance::{
            Connector, ConnectorManageRpc, ConnectorStatus, ListConnectorRequest,
            ListConnectorResponse,
        },
        rpc_types::{self, controller::BaseController},
    },
    tunnel::{IpVersion, TunnelConnector, TunnelScheme, matches_scheme},
    utils::weak_upgrade,
};

use crate::{
    common::{
        error::Error,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
        netns::NetNS,
    },
    peers::peer_manager::PeerManager,
    use_global_var,
};

use super::create_connector_by_url;

type ConnectorMap = Arc<DashSet<url::Url>>;

#[derive(Debug, Clone)]
struct ReconnResult {
    dead_url: String,
    peer_id: PeerId,
    conn_id: PeerConnId,
}

/// 重连退避的初始间隔：第 1 次连续失败后等待 2s 再重试
const RECONN_BACKOFF_INITIAL: Duration = Duration::from_secs(2);
/// 重连退避上限：退避时长不会超过 60s
const RECONN_BACKOFF_MAX: Duration = Duration::from_secs(60);
/// 退避抖动比例：在基数上叠加 ±20% 的随机抖动，避免多节点同频重连
const RECONN_BACKOFF_JITTER_PERCENT: u64 = 20;

/// 单个 url（即一个 connector 的 peer_uri）维度的重连退避状态。
/// 注意：状态按 url 隔离，不同 connector / peer 之间互不影响。
#[derive(Debug, Clone, Copy)]
struct BackoffState {
    /// 连续失败次数，连接成功后清零
    fail_count: u32,
    /// 允许下一次重连尝试的最早时刻
    next_attempt_at: Instant,
}

/// 不带抖动的退避基数：第 `fail_count` 次连续失败后的等待时长。
/// 序列为 2s → 4s → 8s → 16s → 32s → 60s → 60s ...（`fail_count` 为 0 时按第 1 次处理）
fn backoff_base_delay(fail_count: u32) -> Duration {
    // 2s * 2^(fail_count-1)，移位上限 6 已经足以触达 60s 上限
    let shift = fail_count.saturating_sub(1).min(6);
    let secs = RECONN_BACKOFF_INITIAL
        .as_secs()
        .saturating_mul(1u64 << shift);
    Duration::from_secs(secs.min(RECONN_BACKOFF_MAX.as_secs()))
}

/// 给退避时长叠加 ±20% 抖动，`jitter` 为随机种子（取模后使用）。
/// 抖动后的结果落在 [0.8 * base, 1.2 * base] 区间内。
fn apply_backoff_jitter(base: Duration, jitter: u64) -> Duration {
    let base_ms = base.as_millis() as u64;
    let span_ms = base_ms * RECONN_BACKOFF_JITTER_PERCENT / 100;
    if span_ms == 0 {
        return base;
    }
    let offset = jitter % (span_ms * 2 + 1);
    Duration::from_millis(base_ms - span_ms + offset)
}

/// 实际使用的退避时长：指数退避基数 + ±20% 随机抖动
fn backoff_delay(fail_count: u32) -> Duration {
    apply_backoff_jitter(backoff_base_delay(fail_count), rand::random::<u64>())
}

/// 按 url 维护的重连退避状态表。
///
/// 设计取舍：
/// - 每个 url 独立演进，某个 peer 反复失败不会拖慢其它 peer / connector 的重连节奏；
/// - 表内通常只有个位数条目，因此 tick 内的遍历/清理开销可忽略，无需额外索引；
/// - 只由本文件的重连流程读写，不参与入站（被动 accept）路径。
#[derive(Default)]
struct BackoffTable {
    inner: DashMap<url::Url, BackoffState>,
}

impl BackoffTable {
    /// 判断当前是否允许对该 url 发起重连：无记录表示从未失败，可立即尝试；
    /// 有记录时只有到达 `next_attempt_at` 才允许尝试（退避窗口内跳过，不阻塞其它条目）。
    fn should_attempt(&self, url: &url::Url, now: Instant) -> bool {
        let Some(state) = self.inner.get(url) else {
            return true;
        };
        now >= state.next_attempt_at
    }

    /// 读取条目的 (连续失败次数, 距离下次允许尝试的剩余时间)
    fn pending(&self, url: &url::Url, now: Instant) -> Option<(u32, Duration)> {
        let state = self.inner.get(url)?;
        Some((
            state.fail_count,
            state.next_attempt_at.saturating_duration_since(now),
        ))
    }

    /// 记录一次连接失败：`fail_count += 1`，并按指数退避设置下次尝试时刻。
    /// 返回 (本次失败计数, 本次退避时长)。
    fn record_failure(&self, url: &url::Url, now: Instant) -> (u32, Duration) {
        let mut state = self
            .inner
            .entry(url.clone())
            .or_insert_with(|| BackoffState {
                fail_count: 0,
                next_attempt_at: now,
            });
        state.fail_count = state.fail_count.saturating_add(1);
        let delay = backoff_delay(state.fail_count);
        state.next_attempt_at = now + delay;
        (state.fail_count, delay)
    }

    /// 记录一次连接成功：清除该 url 的退避状态，回到初始间隔。
    /// 返回被清除条目的失败次数（此前没有失败记录时返回 None）。
    fn record_success(&self, url: &url::Url) -> Option<u32> {
        self.inner.remove(url).map(|(_, state)| state.fail_count)
    }

    /// 清理不再需要跟踪的条目（例如 connector 已被用户删除），返回清理数量。
    /// 先取出全部 key 并释放退避表分片锁，再回调 `keep`，避免持锁访问其它状态集合。
    fn prune(&self, keep: impl Fn(&url::Url) -> bool) -> usize {
        let urls: Vec<url::Url> = self.inner.iter().map(|entry| entry.key().clone()).collect();
        let stale: Vec<url::Url> = urls.into_iter().filter(|url| !keep(url)).collect();
        for url in &stale {
            self.inner.remove(url);
        }
        stale.len()
    }
}

struct ConnectorManagerData {
    connectors: ConnectorMap,
    reconnecting: DashSet<url::Url>,
    /// 按 url 隔离的重连退避状态，避免连接失败后以固定间隔无限重试
    reconn_backoff: BackoffTable,
    peer_manager: Weak<PeerManager>,
    alive_conn_urls: Arc<DashSet<url::Url>>,
    // user removed connector urls
    removed_conn_urls: Arc<DashSet<url::Url>>,
    net_ns: NetNS,
    global_ctx: ArcGlobalCtx,
}

pub struct ManualConnectorManager {
    global_ctx: ArcGlobalCtx,
    data: Arc<ConnectorManagerData>,
    tasks: JoinSet<()>,
}

impl ManualConnectorManager {
    pub fn new(global_ctx: ArcGlobalCtx, peer_manager: Arc<PeerManager>) -> Self {
        let connectors = Arc::new(DashSet::new());
        let tasks = JoinSet::new();

        let mut ret = Self {
            global_ctx: global_ctx.clone(),
            data: Arc::new(ConnectorManagerData {
                connectors,
                reconnecting: DashSet::new(),
                reconn_backoff: BackoffTable::default(),
                peer_manager: Arc::downgrade(&peer_manager),
                alive_conn_urls: Arc::new(DashSet::new()),
                removed_conn_urls: Arc::new(DashSet::new()),
                net_ns: global_ctx.net_ns.clone(),
                global_ctx,
            }),
            tasks,
        };

        ret.tasks
            .spawn(Self::conn_mgr_reconn_routine(ret.data.clone()));

        ret
    }

    fn reconnect_timeout(dead_url: &url::Url) -> Duration {
        let use_long_timeout = matches_scheme!(
            dead_url,
            TunnelScheme::Http | TunnelScheme::Https | TunnelScheme::Txt | TunnelScheme::Srv
        ) || matches!(dead_url.scheme(), "ws" | "wss");

        Duration::from_secs(if use_long_timeout { 20 } else { 2 })
    }

    fn remaining_budget(started_at: Instant, total_timeout: Duration) -> Option<Duration> {
        let remaining = total_timeout.checked_sub(started_at.elapsed())?;
        (!remaining.is_zero()).then_some(remaining)
    }

    fn emit_connect_error(
        data: &ConnectorManagerData,
        dead_url: &url::Url,
        ip_version: IpVersion,
        error: &Error,
    ) {
        data.global_ctx.issue_event(GlobalCtxEvent::ConnectError(
            dead_url.to_string(),
            format!("{:?}", ip_version),
            format!("{:#?}", error),
        ));
    }

    fn reconnect_timeout_error(stage: &str, duration: Duration) -> Error {
        Error::AnyhowError(anyhow::anyhow!("{} timeout after {:?}", stage, duration))
    }

    async fn with_reconnect_timeout<T, F>(
        stage: &'static str,
        started_at: Instant,
        total_timeout: Duration,
        fut: F,
    ) -> Result<T, Error>
    where
        F: Future<Output = Result<T, Error>>,
    {
        let remaining = Self::remaining_budget(started_at, total_timeout)
            .ok_or_else(|| Self::reconnect_timeout_error(stage, started_at.elapsed()))?;
        timeout(remaining, fut)
            .await
            .map_err(|_| Self::reconnect_timeout_error(stage, remaining))?
    }
}

impl ManualConnectorManager {
    pub fn add_connector<T>(&self, connector: T)
    where
        T: TunnelConnector + 'static,
    {
        tracing::info!("add_connector: {}", connector.remote_url());
        self.data.connectors.insert(connector.remote_url());
    }

    pub async fn add_connector_by_url(&self, url: url::Url) -> Result<(), Error> {
        self.data.connectors.insert(url);
        Ok(())
    }

    pub async fn remove_connector(&self, url: url::Url) -> Result<(), Error> {
        tracing::info!("remove_connector: {}", url);
        let url = url.into();
        if !self
            .list_connectors()
            .await
            .iter()
            .any(|x| x.url.as_ref() == Some(&url))
        {
            return Err(Error::NotFound);
        }
        self.data.removed_conn_urls.insert(url.into());
        Ok(())
    }

    pub async fn clear_connectors(&self) {
        self.list_connectors().await.iter().for_each(|x| {
            if let Some(url) = &x.url {
                self.data.removed_conn_urls.insert(url.clone().into());
            }
        });
    }

    pub async fn list_connectors(&self) -> Vec<Connector> {
        let dead_urls: BTreeSet<url::Url> = Self::collect_dead_conns(self.data.clone())
            .await
            .into_iter()
            .collect();

        let mut ret = Vec::new();

        for item in self.data.connectors.iter() {
            let conn_url = item.key().clone();
            let mut status = ConnectorStatus::Connected;
            if dead_urls.contains(&conn_url) {
                status = ConnectorStatus::Disconnected;
            }
            ret.insert(
                0,
                Connector {
                    url: Some(conn_url.into()),
                    status: status.into(),
                },
            );
        }

        let reconnecting_urls: BTreeSet<url::Url> =
            self.data.reconnecting.iter().map(|x| x.clone()).collect();

        for conn_url in reconnecting_urls {
            ret.insert(
                0,
                Connector {
                    url: Some(conn_url.into()),
                    status: ConnectorStatus::Connecting.into(),
                },
            );
        }

        ret
    }

    async fn conn_mgr_reconn_routine(data: Arc<ConnectorManagerData>) {
        tracing::warn!("conn_mgr_routine started");
        let mut reconn_interval = tokio::time::interval(std::time::Duration::from_millis(
            use_global_var!(MANUAL_CONNECTOR_RECONNECT_INTERVAL_MS),
        ));
        let (reconn_result_send, mut reconn_result_recv) = mpsc::channel(100);
        let tasks = Arc::new(std::sync::Mutex::new(JoinSet::new()));
        join_joinset_background(tasks.clone(), "connector_reconnect_tasks".to_string());

        loop {
            tokio::select! {
                _ = reconn_interval.tick() => {
                    let dead_urls = Self::collect_dead_conns(data.clone()).await;
                    // 清理已被删除（且不在重连中）的 connector 的退避状态，避免状态表残留
                    data.reconn_backoff.prune(|url| {
                        data.connectors.contains(url) || data.reconnecting.contains(url)
                    });
                    if dead_urls.is_empty() {
                        continue;
                    }

                    // 同一 tick 内使用同一个 now，保证本轮的退避判定一致
                    let now = Instant::now();
                    let mut attempted = 0usize;
                    let mut backoff_skipped = 0usize;
                    for dead_url in dead_urls {
                        // 退避门控：只跳过本 url 自己的这次重连尝试，不影响其它 peer / connector，
                        // 也不影响对端入站（被动 accept）的连接建立。
                        if !data.reconn_backoff.should_attempt(&dead_url, now) {
                            backoff_skipped += 1;
                            if let Some((fail_count, remaining)) =
                                data.reconn_backoff.pending(&dead_url, now)
                            {
                                tracing::debug!(
                                    "reconnect for {} delayed by backoff, remaining {:.1}s (fail_count {})",
                                    dead_url,
                                    remaining.as_secs_f64(),
                                    fail_count
                                );
                            }
                            continue;
                        }

                        attempted += 1;
                        let data_clone = data.clone();
                        let sender = reconn_result_send.clone();
                        // 注意：退避中的 url 会保留在 connectors 中（不进入 reconnecting），
                        // 因此对端入站连接仍能被正常识别、也不会被本流程摘除。
                        data.connectors.remove(&dead_url).unwrap();
                        let insert_succ = data.reconnecting.insert(dead_url.clone());
                        assert!(insert_succ);

                        tasks.lock().unwrap().spawn(async move {
                            let reconn_ret = Self::conn_reconnect(data_clone.clone(), dead_url.clone() ).await;
                            // 退避只在“本次尝试失败”时增长；成功后清除该 url 的退避状态。
                            // 连接建立后再被断开（下一轮 tick 重新探测为 dead）同样按失败累计。
                            match &reconn_ret {
                                Ok(_) => {
                                    if let Some(fail_count) =
                                        data_clone.reconn_backoff.record_success(&dead_url)
                                    {
                                        tracing::info!(
                                            "reconnect success, backoff reset (was fail_count {}): {}",
                                            fail_count,
                                            dead_url
                                        );
                                    }
                                }
                                Err(error) => {
                                    let (fail_count, delay) = data_clone
                                        .reconn_backoff
                                        .record_failure(&dead_url, Instant::now());
                                    tracing::info!(
                                        "reconnect failed, backoff {:.1}s (fail_count {}, url {}): {:?}",
                                        delay.as_secs_f64(),
                                        fail_count,
                                        dead_url,
                                        error
                                    );
                                }
                            }
                            let _ = sender.send(reconn_ret).await;

                            data_clone.reconnecting.remove(&dead_url).unwrap();
                            data_clone.connectors.insert(dead_url.clone());
                        });
                    }
                    tracing::info!(
                        "reconn_interval tick, done, attempted: {}, backoff_skipped: {}",
                        attempted,
                        backoff_skipped
                    );
                }

                ret = reconn_result_recv.recv() => {
                    tracing::warn!("reconn_tasks done, reconn result: {:?}", ret);
                }
            }
        }
    }

    fn handle_remove_connector(data: Arc<ConnectorManagerData>) {
        let remove_later = DashSet::new();
        for it in data.removed_conn_urls.iter() {
            let url = it.key();
            if data.connectors.remove(url).is_some() {
                tracing::warn!("connector: {}, removed", url);
                continue;
            } else if data.reconnecting.contains(url) {
                tracing::warn!("connector: {}, reconnecting, remove later.", url);
                remove_later.insert(url.clone());
                continue;
            } else {
                tracing::warn!("connector: {}, not found", url);
            }
        }
        data.removed_conn_urls.clear();
        for it in remove_later.iter() {
            data.removed_conn_urls.insert(it.key().clone());
        }
    }

    async fn collect_dead_conns(data: Arc<ConnectorManagerData>) -> BTreeSet<url::Url> {
        Self::handle_remove_connector(data.clone());
        let mut ret = BTreeSet::new();
        let Some(pm) = data.peer_manager.upgrade() else {
            tracing::warn!("peer manager is gone, exit");
            return ret;
        };
        for url in data.connectors.iter().map(|x| x.key().clone()) {
            if !pm.get_peer_map().is_client_url_alive(&url)
                && !pm
                    .get_foreign_network_client()
                    .get_peer_map()
                    .is_client_url_alive(&url)
            {
                ret.insert(url.clone());
            }
        }
        ret
    }

    async fn conn_reconnect_with_ip_version(
        data: Arc<ConnectorManagerData>,
        dead_url: url::Url,
        ip_version: IpVersion,
        started_at: Instant,
        total_timeout: Duration,
    ) -> Result<ReconnResult, Error> {
        let connector = Self::with_reconnect_timeout(
            "resolve",
            started_at,
            total_timeout,
            create_connector_by_url(dead_url.as_str(), &data.global_ctx, ip_version),
        )
        .await?;

        data.global_ctx
            .issue_event(GlobalCtxEvent::Connecting(connector.remote_url()));
        tracing::info!("reconnect try connect... conn: {:?}", connector);
        let Some(pm) = data.peer_manager.upgrade() else {
            return Err(Error::AnyhowError(anyhow::anyhow!(
                "peer manager is gone, cannot reconnect"
            )));
        };

        let tunnel = Self::with_reconnect_timeout(
            "connect",
            started_at,
            total_timeout,
            pm.connect_tunnel(connector),
        )
        .await?;

        let (peer_id, conn_id) = Self::with_reconnect_timeout(
            "handshake",
            started_at,
            total_timeout,
            pm.add_client_tunnel_with_peer_id_hint(tunnel, true, None),
        )
        .await?;

        tracing::info!("reconnect succ: {} {} {}", peer_id, conn_id, dead_url);
        Ok(ReconnResult {
            dead_url: dead_url.to_string(),
            peer_id,
            conn_id,
        })
    }

    async fn conn_reconnect(
        data: Arc<ConnectorManagerData>,
        dead_url: url::Url,
    ) -> Result<ReconnResult, Error> {
        tracing::info!("reconnect: {}", dead_url);

        let mut ip_versions = vec![];
        if matches_scheme!(
            dead_url,
            TunnelScheme::Ring | TunnelScheme::Txt | TunnelScheme::Srv
        ) {
            ip_versions.push(IpVersion::Both);
        } else {
            let converted_dead_url =
                match crate::common::idn::convert_idn_to_ascii(dead_url.clone()) {
                    Ok(url) => url,
                    Err(error) => {
                        let error: Error = error.into();
                        Self::emit_connect_error(&data, &dead_url, IpVersion::Both, &error);
                        return Err(error);
                    }
                };
            let addrs = match Self::with_reconnect_timeout(
                "resolve",
                Instant::now(),
                Self::reconnect_timeout(&dead_url),
                socket_addrs(&converted_dead_url, || Some(1000)),
            )
            .await
            {
                Ok(addrs) => addrs,
                Err(error) => {
                    Self::emit_connect_error(&data, &dead_url, IpVersion::Both, &error);
                    return Err(error);
                }
            };
            tracing::info!(?addrs, ?dead_url, "get ip from url done");
            let mut has_ipv4 = false;
            let mut has_ipv6 = false;
            for addr in addrs {
                if addr.is_ipv4() {
                    if !has_ipv4 {
                        ip_versions.insert(0, IpVersion::V4);
                    }
                    has_ipv4 = true;
                } else if addr.is_ipv6() {
                    if !has_ipv6 {
                        ip_versions.push(IpVersion::V6);
                    }
                    has_ipv6 = true;
                }
            }
        }

        let mut reconn_ret = Err(Error::AnyhowError(anyhow::anyhow!(
            "cannot get ip from url"
        )));
        for ip_version in ip_versions {
            let started_at = Instant::now();
            let ret = Self::conn_reconnect_with_ip_version(
                data.clone(),
                dead_url.clone(),
                ip_version,
                started_at,
                Self::reconnect_timeout(&dead_url),
            )
            .await;
            tracing::info!("reconnect: {} done, ret: {:?}", dead_url, ret);

            match ret {
                Ok(result) => return Ok(result),
                Err(error) => {
                    Self::emit_connect_error(&data, &dead_url, ip_version, &error);
                    reconn_ret = Err(error);
                }
            }
        }

        reconn_ret
    }
}

#[derive(Clone)]
pub struct ConnectorManagerRpcService(pub Weak<ManualConnectorManager>);

#[async_trait::async_trait]
impl ConnectorManageRpc for ConnectorManagerRpcService {
    type Controller = BaseController;

    async fn list_connector(
        &self,
        _: BaseController,
        _request: ListConnectorRequest,
    ) -> Result<ListConnectorResponse, rpc_types::error::Error> {
        let mut ret = ListConnectorResponse::default();
        let connectors = weak_upgrade(&self.0)?.list_connectors().await;
        ret.connectors = connectors;
        Ok(ret)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        peers::tests::create_mock_peer_manager,
        set_global_var,
        tunnel::{Tunnel, TunnelError},
    };

    use super::*;

    #[tokio::test]
    async fn reconnect_timeout_reports_exhausted_budget_for_stage() {
        let started_at = Instant::now() - Duration::from_millis(50);
        let err = ManualConnectorManager::with_reconnect_timeout(
            "resolve",
            started_at,
            Duration::from_millis(1),
            async { Ok::<(), Error>(()) },
        )
        .await
        .unwrap_err();

        let message = err.to_string();
        assert!(message.contains("resolve timeout after"));
    }

    #[tokio::test]
    async fn reconnect_timeout_reports_stage_timeout_with_remaining_budget() {
        let err = ManualConnectorManager::with_reconnect_timeout(
            "handshake",
            Instant::now(),
            Duration::from_millis(10),
            async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                Ok::<(), Error>(())
            },
        )
        .await
        .unwrap_err();

        let message = err.to_string();
        assert!(message.contains("handshake timeout after"));
    }

    #[tokio::test]
    async fn reconnect_timeout_preserves_success_within_budget() {
        let result = ManualConnectorManager::with_reconnect_timeout(
            "connect",
            Instant::now(),
            Duration::from_millis(50),
            async { Ok::<_, Error>(123_u32) },
        )
        .await
        .unwrap();

        assert_eq!(result, 123);
    }

    /// 退避基数序列：2 → 4 → 8 → 16 → 32 → 60 → 60（上限 60s）
    #[test]
    fn backoff_base_delay_follows_exponential_sequence_with_cap() {
        let seq: Vec<u64> = (1..=8).map(|n| backoff_base_delay(n).as_secs()).collect();
        assert_eq!(seq, vec![2, 4, 8, 16, 32, 60, 60, 60]);

        // 非法/未失败输入的兜底行为：按初始间隔处理
        assert_eq!(backoff_base_delay(0), RECONN_BACKOFF_INITIAL);
        // 极端值不应 panic 或溢出
        assert_eq!(backoff_base_delay(u32::MAX), RECONN_BACKOFF_MAX);
    }

    /// 抖动必须落在基数的 ±20% 之内，且确实在区间内取值（不是恒定值）
    #[test]
    fn backoff_jitter_stays_within_20_percent() {
        for fail_count in 1..=7 {
            let base = backoff_base_delay(fail_count);
            let base_ms = base.as_millis() as u64;
            let span_ms = base_ms * RECONN_BACKOFF_JITTER_PERCENT / 100;
            let low = base_ms - span_ms;
            let high = base_ms + span_ms;
            let mut hit_low = false;
            let mut hit_high = false;
            for jitter in 0..=(span_ms * 2 + 1) {
                let ms = apply_backoff_jitter(base, jitter).as_millis() as u64;
                assert!(
                    ms >= low && ms <= high,
                    "fail_count {} jitter {} out of range: {}",
                    fail_count,
                    jitter,
                    ms
                );
                hit_low |= ms == low;
                hit_high |= ms == high;
            }
            assert!(hit_low && hit_high, "jitter range not fully covered");
        }

        // 基数足够小（理论上不会出现）时不做抖动，避免退避被抖到 0
        assert_eq!(
            apply_backoff_jitter(Duration::from_millis(3), 7),
            Duration::from_millis(3)
        );
    }

    /// 连接成功后必须重置为初始间隔
    #[test]
    fn backoff_resets_after_success() {
        let table = BackoffTable::default();
        let url = url::Url::parse("wg://backoff-reset.example.com:11010").unwrap();
        let t0 = Instant::now();

        let (n1, d1) = table.record_failure(&url, t0);
        let (n2, _) = table.record_failure(&url, t0 + Duration::from_secs(3));
        let t2 = t0 + Duration::from_secs(6);
        let (n3, _) = table.record_failure(&url, t2);
        assert_eq!((n1, n2, n3), (1, 2, 3));
        // 第 1 次失败的退避时长应落在 2s ±20%
        assert!(d1 >= Duration::from_millis(1600) && d1 <= Duration::from_millis(2400));

        // 退避窗口内跳过，窗口外允许尝试
        assert!(!table.should_attempt(&url, t2 + Duration::from_millis(1)));
        assert!(table.should_attempt(&url, t2 + backoff_base_delay(3) * 2));
        assert_eq!(table.pending(&url, t2).unwrap().0, 3);

        // 连接成功：状态清空，立即可重试，失败计数归零
        assert_eq!(table.record_success(&url), Some(3));
        assert_eq!(table.pending(&url, t2), None);
        assert!(table.should_attempt(&url, t2 + Duration::from_millis(1)));
        // 重复清除无副作用
        assert_eq!(table.record_success(&url), None);

        // 成功之后重新失败时，退避从初始间隔重新开始
        let (n4, d4) = table.record_failure(&url, t2);
        assert_eq!(n4, 1);
        assert!(d4 >= Duration::from_millis(1600) && d4 <= Duration::from_millis(2400));
    }

    /// 不同 url 的退避状态互相隔离
    #[test]
    fn backoff_is_isolated_per_uri() {
        let table = BackoffTable::default();
        let a = url::Url::parse("wg://a.example.com:11010").unwrap();
        let b = url::Url::parse("wg://b.example.com:11010").unwrap();
        let c = url::Url::parse("wg://c.example.com:11010").unwrap();
        let t0 = Instant::now();

        // a 连续失败 5 次（退避 32s 量级），b 只失败 1 次（退避 2s 量级）
        for _ in 0..5 {
            table.record_failure(&a, t0);
        }
        table.record_failure(&b, t0);

        assert_eq!(table.pending(&a, t0).unwrap().0, 5);
        assert_eq!(table.pending(&b, t0).unwrap().0, 1);

        let later = t0 + Duration::from_millis(2500);
        assert!(!table.should_attempt(&a, later), "a 应仍在退避窗口内");
        assert!(table.should_attempt(&b, later), "b 不应受 a 的退避影响");

        // 从未失败过的 url 不受任何影响
        assert!(table.should_attempt(&c, t0));
        assert_eq!(table.pending(&c, t0), None);

        // 清理：模拟 b 已从 connectors 中移除（例如用户删除 connector），其退避状态应被清理
        let removed = table.prune(|url| url != &b);
        assert_eq!(removed, 1);
        assert!(table.pending(&b, t0).is_none());
        // a 不受影响，退避进度保留
        assert_eq!(table.pending(&a, t0).unwrap().0, 5);
    }

    #[tokio::test]
    async fn test_reconnect_with_connecting_addr() {
        set_global_var!(MANUAL_CONNECTOR_RECONNECT_INTERVAL_MS, 1);

        let peer_mgr = create_mock_peer_manager().await;
        let mgr = ManualConnectorManager::new(peer_mgr.get_global_ctx(), peer_mgr);

        struct MockConnector {}
        #[async_trait::async_trait]
        impl TunnelConnector for MockConnector {
            fn remote_url(&self) -> url::Url {
                url::Url::parse("tcp://aa.com").unwrap()
            }
            async fn connect(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                Err(TunnelError::InvalidPacket("fake error".into()))
            }
        }

        mgr.add_connector(MockConnector {});

        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}
