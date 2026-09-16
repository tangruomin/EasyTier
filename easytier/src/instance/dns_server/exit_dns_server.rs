//! 出口节点侧的 DNS 服务：在**隧道内虚拟 IP:53** 上为客户端提供域名解析。
//!
//! 对应《easytier-代码修复需求汇总版》3.3.1：
//!
//! * 出口节点（`enable_exit_node = true`）独立开启一个 DNS 服务，监听自己的虚拟
//!   IPv4 的 53 端口（UDP + TCP），**不修改出口节点本机的系统 DNS 设置**——这是它与
//!   `--accept-dns`（魔法 DNS 会改写本机系统 DNS，只适合客户端）的关键区别；
//! * 服务内容与魔法 DNS 一致：虚拟网主机名区域（默认 `et.net.`）由本地记录直接应答，
//!   其余域名转发到出口节点自身的系统 DNS（出口通常位于海外，结果干净）；
//! * 客户端侧只需把 DNS 指向该虚拟 IP（Android 用 `VpnService.addDnsServer`，桌面端由
//!   魔法 DNS 经隧道转发，见 [`super::exit_dns_relay`]），即可绕开本地被污染的上游。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::rr::LowerName;
use tokio_util::task::AbortOnDropHandle;

use crate::common::config::parse_dns_servers;
use crate::instance::dns_server::{
    MAGIC_DNS_FAKE_IP,
    config::{GeneralConfigBuilder, RunConfigBuilder},
    server::{Server, build_authority},
    server_instance::build_zone_records,
};
use crate::peers::peer_manager::PeerManager;
use crate::proto::api::instance::Route;

/// 虚拟网主机名记录的刷新间隔：客户端可能随时上下线，定期重建权威区数据。
const ZONE_REFRESH_INTERVAL: Duration = Duration::from_secs(5);

/// 出口节点读不到自身系统 DNS 配置时使用的兜底上游。
///
/// 出口节点通常部署在海外，「干净」是它的核心价值；读不到系统配置时宁可显式用公共 DNS，
/// 也不要回落成 `223.5.5.5` 这类国内 DNS（那正是本问题要避免的污染源）。
const EXIT_FALLBACK_UPSTREAMS: [&str; 2] = ["8.8.8.8:53", "1.1.1.1:53"];

/// 出口节点上的隧道内 DNS 服务。
///
/// `Drop` 时任务被取消（`AbortOnDropHandle`），不会在实例停止后残留。
pub struct ExitDnsServer {
    _handle: AbortOnDropHandle<()>,
    listen_addr: SocketAddr,
}

impl ExitDnsServer {
    /// 在 `tun_ipv4` 的 53 端口启动 DNS 服务（UDP + TCP）。
    pub async fn start(
        peer_mgr: Arc<PeerManager>,
        tun_ipv4: Ipv4Addr,
    ) -> anyhow::Result<ExitDnsServer> {
        let global_ctx = peer_mgr.get_global_ctx();
        let zone = global_ctx.config.get_flags().tld_dns_zone.clone();
        let zone = if zone.trim().is_empty() {
            crate::instance::dns_server::DEFAULT_ET_DNS_ZONE.to_string()
        } else {
            zone
        };

        // 显式上游仅当用户配置了 dns_mode = custom / dns_servers 时生效
        let custom_upstreams = parse_dns_servers(&global_ctx.dns_servers());
        let fallback_upstreams = EXIT_FALLBACK_UPSTREAMS
            .iter()
            .filter_map(|s| s.parse::<SocketAddr>().ok())
            .collect::<Vec<_>>();

        let listen_addr = SocketAddr::new(IpAddr::V4(tun_ipv4), 53);
        let dns_config = RunConfigBuilder::default()
            .general(
                GeneralConfigBuilder::default()
                    .listen_udp(listen_addr.to_string())
                    .listen_tcp(listen_addr.to_string())
                    .build()?,
            )
            // 防递归：不要把本节点虚拟 IP / 魔法 DNS 假 IP 当成上游
            .excluded_forward_nameservers(vec![
                IpAddr::V4(tun_ipv4),
                MAGIC_DNS_FAKE_IP.parse().expect("valid fake ip"),
            ])
            .forward_upstreams(custom_upstreams)
            .fallback_forward_upstreams(fallback_upstreams)
            .build()?;

        let mut server = Server::new(dns_config);
        server.run().await.map_err(|e| {
            anyhow::anyhow!("exit dns server failed to bind {}: {}", listen_addr, e)
        })?;

        tracing::info!(
            %listen_addr,
            udp = ?server.udp_local_addr(),
            tcp = ?server.tcp_local_addr(),
            zone = %zone,
            "exit node dns service started (clients can use this address as dns server)"
        );

        let task_peer_mgr = peer_mgr.clone();
        let task_zone = zone.clone();
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(ZONE_REFRESH_INTERVAL);
            loop {
                ticker.tick().await;
                if let Err(e) = Self::refresh_zone(&server, &task_peer_mgr, &task_zone).await {
                    tracing::warn!("refresh exit dns zone failed: {:?}", e);
                }
            }
        });

        Ok(ExitDnsServer {
            _handle: AbortOnDropHandle::new(handle),
            listen_addr,
        })
    }

    /// 供日志 / 状态查询使用的监听地址。
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// 用当前路由表重建虚拟网主机名区域（`<hostname>.<zone>` -> 虚拟 IPv4）。
    async fn refresh_zone(
        server: &Server,
        peer_mgr: &Arc<PeerManager>,
        zone: &str,
    ) -> anyhow::Result<()> {
        let mut routes: Vec<Route> = peer_mgr.list_routes().await;
        // 把本节点自己也算进去，保证出口节点的名字同样可解析
        let global_ctx = peer_mgr.get_global_ctx();
        routes.push(Route {
            hostname: global_ctx.get_hostname(),
            ipv4_addr: global_ctx.get_ipv4().map(Into::into),
            ..Default::default()
        });
        let records = build_zone_records(routes.iter(), zone)?;
        let authority = build_authority(zone, &records)?;
        server
            .upsert(
                LowerName::from_str(zone)
                    .map_err(|e| anyhow::anyhow!("invalid zone {}: {}", zone, e))?,
                Arc::new(authority),
            )
            .await;
        tracing::debug!(zone = %zone, records = records.len(), "exit dns zone refreshed");
        Ok(())
    }
}
