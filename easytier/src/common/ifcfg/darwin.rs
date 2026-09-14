use std::net::Ipv4Addr;

use super::{Error, IfConfiguerTrait, cidr_to_subnet_mask, run_shell_cmd};
use async_trait::async_trait;
use cidr::{Ipv4Inet, Ipv6Inet};

/// 是否允许强制把默认路由改到 easytier TUN 接口。
///
/// 默认关闭：只做安装后校验与告警。设置环境变量
/// `ET_MACOS_TAKE_OVER_DEFAULT_ROUTE=1`（或 `true`/`yes`）后才会执行强制接管。
fn take_over_default_route_enabled() -> bool {
    match std::env::var("ET_MACOS_TAKE_OVER_DEFAULT_ROUTE") {
        Ok(v) => v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes"),
        Err(_) => false,
    }
}

/// 执行 shell 命令并返回 stdout。
/// `run_shell_cmd` 只返回成功/失败，无法解析输出，故这里单独实现一份。
async fn run_shell_cmd_capture(cmd: &str) -> Result<String, Error> {
    let output = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .await?;

    let stdout = String::from_utf8_lossy(output.stdout.as_slice()).to_string();
    let stderr = String::from_utf8_lossy(output.stderr.as_slice()).to_string();
    tracing::info!(
        ?cmd,
        ec = ?output.status.code(),
        succ = ?output.status.success(),
        ?stdout,
        ?stderr,
        "run shell cmd (capture)"
    );

    if !output.status.success() {
        return Err(Error::ShellCommandError(stdout + &stderr));
    }
    Ok(stdout)
}

/// 从 `route -n get default` 的输出中解析当前生效的默认路由接口名。
fn parse_default_route_interface(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        line.trim()
            .strip_prefix("interface:")
            .map(|iface| iface.trim().to_string())
    })
}

/// 安装默认路由（`0.0.0.0/0`）后的校验，以及可选的强制接管。
///
/// macOS（BSD 路由栈）没有 metric 概念，多条默认路由按路由表顺序匹配，
/// `route -n add` 是否胜出取决于插入位置，行为不可靠。因此这里：
///
/// 1. 默认行为：校验 `route -n get default` 是否走 TUN；未生效则打 WARN，
///    并给出精确的修复命令；
/// 2. 可选行为：设置 `ET_MACOS_TAKE_OVER_DEFAULT_ROUTE=1` 后改为执行
///    `route -n change default -interface <tun>` 强制接管。
///
/// 注意：强制接管会改写用户原有的默认路由，属有副作用的操作，故默认关闭。
async fn verify_or_take_over_default_route(name: &str) {
    let current = match run_shell_cmd_capture("route -n get default").await {
        Ok(out) => parse_default_route_interface(&out),
        Err(err) => {
            tracing::warn!(?err, "failed to query the current default route");
            return;
        }
    };

    if current.as_deref() == Some(name) {
        tracing::info!(%name, "TUN default route is in effect");
        return;
    }

    let fix_cmd = format!("route -n change default -interface {}", name);
    if !take_over_default_route_enabled() {
        tracing::warn!(
            %name,
            current_default_route_interface = ?current,
            %fix_cmd,
            "TUN default route is NOT in effect, traffic will not go through the exit node; \
             run the command below manually to take over the default route, or set \
             ET_MACOS_TAKE_OVER_DEFAULT_ROUTE=1 to let easytier do it automatically"
        );
        return;
    }

    match run_shell_cmd(fix_cmd.as_str()).await {
        Ok(()) => tracing::info!(%fix_cmd, "default route taken over by the TUN interface"),
        Err(err) => tracing::warn!(?err, %fix_cmd, "failed to take over the default route"),
    }
}

pub struct MacIfConfiger {}
#[async_trait]
impl IfConfiguerTrait for MacIfConfiger {
    async fn add_ipv4_route(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
        cost: Option<i32>,
    ) -> Result<(), Error> {
        run_shell_cmd(
            format!(
                "route -n add {} -netmask {} -interface {} -hopcount {}",
                address,
                cidr_to_subnet_mask(cidr_prefix),
                name,
                cost.unwrap_or(7)
            )
            .as_str(),
        )
        .await?;

        // 仅默认路由（0.0.0.0/0，即全局出口场景）需要校验是否真正胜出。
        // 校验失败不影响本次路由安装结果，因此内部只告警、不返回错误。
        if cidr_prefix == 0 {
            verify_or_take_over_default_route(name).await;
        }

        Ok(())
    }

    async fn remove_ipv4_route(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        run_shell_cmd(
            format!(
                "route -n delete {} -netmask {} -interface {}",
                address,
                cidr_to_subnet_mask(cidr_prefix),
                name
            )
            .as_str(),
        )
        .await
    }

    async fn add_ipv4_ip(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        run_shell_cmd(
            format!(
                "ifconfig {} {:?}/{:?} {:?} up",
                name, address, cidr_prefix, address,
            )
            .as_str(),
        )
        .await
    }

    async fn set_link_status(&self, name: &str, up: bool) -> Result<(), Error> {
        run_shell_cmd(format!("ifconfig {} {}", name, if up { "up" } else { "down" }).as_str())
            .await
    }

    async fn remove_ip(&self, name: &str, ip: Option<Ipv4Inet>) -> Result<(), Error> {
        if let Some(ip) = ip {
            run_shell_cmd(format!("ifconfig {} inet {} delete", name, ip.address()).as_str()).await
        } else {
            run_shell_cmd(format!("ifconfig {} inet delete", name).as_str()).await
        }
    }

    async fn set_mtu(&self, name: &str, mtu: u32) -> Result<(), Error> {
        run_shell_cmd(format!("ifconfig {} mtu {}", name, mtu).as_str()).await
    }

    async fn add_ipv6_ip(
        &self,
        name: &str,
        address: std::net::Ipv6Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        run_shell_cmd(format!("ifconfig {} inet6 {}/{} add", name, address, cidr_prefix).as_str())
            .await
    }

    async fn remove_ipv6(&self, name: &str, ip: Option<Ipv6Inet>) -> Result<(), Error> {
        if let Some(ip) = ip {
            run_shell_cmd(format!("ifconfig {} inet6 {} delete", name, ip.address()).as_str()).await
        } else {
            // Remove all IPv6 addresses is more complex on macOS, just succeed
            Ok(())
        }
    }

    async fn add_ipv6_route(
        &self,
        name: &str,
        address: std::net::Ipv6Addr,
        cidr_prefix: u8,
        cost: Option<i32>,
    ) -> Result<(), Error> {
        let cmd = if let Some(cost) = cost {
            format!(
                "route -n add -inet6 {}/{} -interface {} -hopcount {}",
                address, cidr_prefix, name, cost
            )
        } else {
            format!(
                "route -n add -inet6 {}/{} -interface {}",
                address, cidr_prefix, name
            )
        };
        run_shell_cmd(cmd.as_str()).await
    }

    async fn remove_ipv6_route(
        &self,
        name: &str,
        address: std::net::Ipv6Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        run_shell_cmd(
            format!(
                "route -n delete -inet6 {}/{} -interface {}",
                address, cidr_prefix, name
            )
            .as_str(),
        )
        .await
    }
}
