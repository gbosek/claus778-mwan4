use log::{debug, error, info, warn};
use std::env;
use std::io;
use std::process;
use std::time::{Duration, Instant};

mod config;
mod lqe;
mod netlink;
mod prober;

use config::{DaemonConfig, EcmpMode, HashField, MultipathHashPolicy, WeightMode};
use lqe::{LinkQualityEstimator, LinkState};
use netlink::conntrack::ConntrackManager;
use netlink::route::{
    AF_INET, ActiveWanRoute, ActiveWanRouteV6, InstalledVariant, POLICY_RULE_PRIORITY_BASE,
    PROBE_RULE_PRIORITY_BASE, PROBE_TABLE_BASE, PolicyRule, ProbePath, RouteManager,
};
use netlink::util::if_nametoindex;

const STATUS_FILE: &str = "/tmp/mwan4_status.json";
const STATUS_TMP_FILE: &str = "/tmp/mwan4_status.json.tmp";
const PID_FILE: &str = "/var/run/mwan4.pid";

/// PID 档路径（`MWAN4_PID_FILE` 可覆盖，供 netns/userns 测试）。
fn pid_file_path() -> String {
    std::env::var("MWAN4_PID_FILE").unwrap_or_else(|_| PID_FILE.to_string())
}

/// 后备轮询间隔（约 5 分钟）；正常由 link/ifaddr 事件驱动，这里只是安全网。
const IFINDEX_REFRESH_TICKS: u64 = 600;
/// worker 卡住时丢弃指令，而不是无限堆积
const NETLINK_QUEUE_CAPACITY: usize = 64;
const PROBE_PATH_REFRESH_TICKS: u64 = 60;
/// 集合没变也定期重下，修复被别的程序／内核事件改掉的路由。
const ROUTE_HEARTBEAT_TICKS: u64 = 60;
/// 定期校验哈希粒度：启动只写一次，被 sysctl.conf / factory reset 改掉后原本永远不会发现。
const HASH_RECHECK_TICKS: u64 = 60;

/// 状态档新鲜度门槛（秒）；超过此值 LuCI 标记为「资料已过期」。
const STATUS_STALE_SECS: u64 = 10;

const LINK_WATCH_RETRY_TICKS: u64 = 60;

/// 过载转换可插队重下权重，但每次变更都是一次 `RTM_NEWROUTE`，故设 1 秒下限。
const WEIGHT_UPDATE_MIN_SPACING: Duration = Duration::from_millis(1000);

fn print_help(bin_name: &str) {
    println!(
        r#"MWAN4 - Ultra-lightweight Multi-WAN Failover & Health Daemon for Linux / OpenWrt

USAGE:
    {bin_name} [OPTIONS]

OPTIONS:
    -c, --config <FILE>    Path to JSON configuration file (e.g. /etc/mwan4/mwan4.json)
    -t, --check-config <FILE>
                           Validate a configuration file and exit (0 = valid, 1 = invalid)
    --gen-config           Output default JSON configuration template to stdout
    -v, --version          Print version information
    -h, --help             Print this help message
"#
    );
}

/// 行程存活期间一直持有；行程结束由核心自动释放。
static PID_FILE_LOCK: std::sync::OnceLock<std::fs::File> = std::sync::OnceLock::new();

/// 取得 PID 档的 flock 独占锁：随行程结束自动释放，避开读 PID 查 /proc 的 race 与 PID 复用误判。
fn acquire_pid_file() -> Result<(), String> {
    let pid_file = pid_file_path();
    let path = std::path::Path::new(&pid_file);
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|e| format!("failed to open {pid_file}: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if ret != 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
                let existing = std::fs::read_to_string(path).unwrap_or_default();
                return Err(format!(
                    "another mwan4 instance is already running (pid {}); refusing to start",
                    existing.trim()
                ));
            }
            return Err(format!("failed to lock {pid_file}: {e}"));
        }
    }

    {
        use std::io::Write;
        file.set_len(0)
            .map_err(|e| format!("failed to truncate {pid_file}: {e}"))?;
        write!(file, "{}", process::id())
            .map_err(|e| format!("failed to write {pid_file}: {e}"))?;
        file.flush()
            .map_err(|e| format!("failed to flush {pid_file}: {e}"))?;
    }

    let _ = PID_FILE_LOCK.set(file);
    Ok(())
}

fn release_pid_file() {
    let _ = std::fs::remove_file(pid_file_path());
}

/// 交给 netlink worker 执行绪处理：这些 syscall 会阻塞数秒，不能跑在非同步主回圈里。
enum NetlinkCmd {
    /// 空清单 = 删除
    Apply(Vec<ActiveWanRoute>),
    ApplyV6(Vec<ActiveWanRouteV6>),
    /// 每张 WAN 一张独立表 + `oif <wan>` 规则，让探针不依赖主表预设路由；bool = 首次下发（先清残留 /32）。
    SetProbePaths(Vec<ProbePath>, bool),
    FlushConntrack(Vec<ConntrackTarget>),
    SetPolicies(Vec<PolicyRule>),
    ClearRoutes,
}

type NetlinkSender = std::sync::mpsc::SyncSender<NetlinkCmd>;

/// 网卡名 + DOWN 时记下的最后已知 IPv4：flush 延后执行，重拨后现查 IP 会失败或已换新。
type ConntrackTarget = (String, Option<std::net::Ipv4Addr>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetlinkOp {
    Ipv4Routes,
    Ipv6Routes,
    ProbePaths,
    Conntrack,
    Policies,
}

/// 主回圈据此判断「已入伫列」是否真的生效，失败就强制下个 tick 重下。
#[derive(Debug, Clone)]
struct NetlinkOutcome {
    op: NetlinkOp,
    ok: bool,
    detail: Option<String>,
    /// 内核实际生效的 IPv4 变体：`ecmp_mode=auto` 可能被内核退成 standard。
    variant: Option<InstalledVariant>,
}

impl NetlinkOutcome {
    fn new(op: NetlinkOp, ok: bool, detail: Option<String>) -> Self {
        Self {
            op,
            ok,
            detail,
            variant: None,
        }
    }

    fn with_variant(mut self, variant: InstalledVariant) -> Self {
        self.variant = Some(variant);
        self
    }
}

type NetlinkResultSender = std::sync::mpsc::Sender<NetlinkOutcome>;
type NetlinkResultReceiver = std::sync::mpsc::Receiver<NetlinkOutcome>;

fn spawn_netlink_worker(
    route_mgr: RouteManager,
    conntrack_mgr: ConntrackManager,
) -> io::Result<(
    NetlinkSender,
    NetlinkResultReceiver,
    std::thread::JoinHandle<()>,
)> {
    let (tx, rx) = std::sync::mpsc::sync_channel::<NetlinkCmd>(NETLINK_QUEUE_CAPACITY);
    let (result_tx, result_rx): (NetlinkResultSender, NetlinkResultReceiver) =
        std::sync::mpsc::channel::<NetlinkOutcome>();

    let handle = std::thread::Builder::new()
        .name("mwan4-netlink".to_string())
        .spawn(move || {
            let mut route_mgr = route_mgr;
            let mut conntrack_mgr = conntrack_mgr;

            while let Ok(cmd) = rx.recv() {
                // 伫列里可能积压多条陈旧的幂等 Apply，先排空合并成一批再执行。
                let mut batch = vec![cmd];
                while let Ok(more) = rx.try_recv() {
                    batch.push(more);
                }

                let mut apply: Option<Vec<ActiveWanRoute>> = None;
                let mut apply_v6: Option<Vec<ActiveWanRouteV6>> = None;
                let mut probe_paths: Option<(Vec<ProbePath>, bool)> = None;
                let mut flush: Vec<ConntrackTarget> = Vec::new();
                let mut policies: Option<Vec<PolicyRule>> = None;
                let mut clear_routes = false;
                for c in batch {
                    match c {
                        NetlinkCmd::Apply(wans) => apply = Some(wans),
                        NetlinkCmd::ApplyV6(wans) => apply_v6 = Some(wans),
                        NetlinkCmd::SetProbePaths(paths, clean) => {
                            probe_paths = Some((paths, clean))
                        }
                        NetlinkCmd::FlushConntrack(targets) => {
                            for (name, ip) in targets {
                                match flush.iter_mut().find(|(n, _)| *n == name) {
                                    Some((_, existing)) => {
                                        if existing.is_none() {
                                            *existing = ip;
                                        }
                                    }
                                    None => flush.push((name, ip)),
                                }
                            }
                        }
                        NetlinkCmd::SetPolicies(rules) => policies = Some(rules),
                        NetlinkCmd::ClearRoutes => clear_routes = true,
                    }
                }

                if let Some(wans) = apply {
                    let (ok, detail, variant) = match route_mgr.apply_default_routes(&wans) {
                        Ok(()) => (true, None, Some(route_mgr.installed_ipv4_variant())),
                        Err(e) => {
                            debug!("Failed to update kernel IPv4 FIB routes: {e}");
                            (false, Some(e.to_string()), None)
                        }
                    };
                    let outcome = match variant {
                        Some(v) => {
                            NetlinkOutcome::new(NetlinkOp::Ipv4Routes, ok, detail).with_variant(v)
                        }
                        None => NetlinkOutcome::new(NetlinkOp::Ipv4Routes, ok, detail),
                    };
                    let _ = result_tx.send(outcome);
                }
                if let Some(wans) = apply_v6 {
                    let (ok, detail) = match route_mgr.apply_ipv6_default_routes(&wans) {
                        Ok(()) => (true, None),
                        Err(e) => {
                            debug!("Failed to update kernel IPv6 FIB routes: {e}");
                            (false, Some(e.to_string()))
                        }
                    };
                    let _ = result_tx.send(NetlinkOutcome::new(NetlinkOp::Ipv6Routes, ok, detail));
                }
                if let Some((paths, clean_host_routes)) = probe_paths {
                    if clean_host_routes {
                        // 只清探针 /32：同批刚装好的 underlay /32 若一起清，隧道封包会走 ECMP 自环。
                        if let Err(e) = route_mgr.sweep_own_probe_host_routes() {
                            debug!("Probe host route cleanup failed: {e}");
                        }
                    }
                    // 网卡暂时不可用（ENODEV / ENETUNREACH）属预期：只记 debug，下个周期重试。
                    let (ok, detail) = match route_mgr.set_probe_paths(&paths) {
                        Ok(()) => (true, None),
                        Err(e) => {
                            debug!("Probe paths not fully applied yet: {e}");
                            (false, Some(e.to_string()))
                        }
                    };
                    let _ = result_tx.send(NetlinkOutcome::new(NetlinkOp::ProbePaths, ok, detail));
                }
                if let Some(rules) = policies {
                    let (ok, detail) = match route_mgr.set_policy_rules(&rules) {
                        Ok(()) => (true, None),
                        Err(e) => {
                            debug!("Policy rule update failed: {e}");
                            (false, Some(e.to_string()))
                        }
                    };
                    let _ = result_tx.send(NetlinkOutcome::new(NetlinkOp::Policies, ok, detail));
                }
                if !flush.is_empty() {
                    let names = flush
                        .iter()
                        .map(|(name, _)| name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ");
                    let (ok, detail) = match conntrack_mgr.flush_interfaces_conntrack(&flush) {
                        Ok(_) => (true, None),
                        Err(e) => {
                            debug!("[{names}] Conntrack flush failed: {e}");
                            (false, Some(e.to_string()))
                        }
                    };
                    let _ = result_tx.send(NetlinkOutcome::new(NetlinkOp::Conntrack, ok, detail));
                }
                if clear_routes {
                    if let Err(e) = route_mgr.cleanup_routes() {
                        warn!("Failed to remove mwan4 routes / nexthops on shutdown: {e}");
                    }
                    break;
                }
            }
        })
        .map_err(|e| io::Error::other(format!("cannot spawn netlink worker thread: {e}")))?;

    Ok((tx, result_rx, handle))
}

// 讯号处理：procd 停止服务送的是 SIGTERM，只监听 ctrl_c()（SIGINT）会导致无法优雅退出。

#[cfg(unix)]
type SigHandle = Option<tokio::signal::unix::Signal>;
#[cfg(not(unix))]
type SigHandle = ();

#[cfg(unix)]
async fn recv_or_pending(slot: &mut SigHandle) {
    match slot {
        Some(sig) => {
            sig.recv().await;
        }
        None => std::future::pending::<()>().await,
    }
}

#[cfg(unix)]
async fn wait_terminate(term: &mut SigHandle, int: &mut SigHandle) {
    tokio::select! {
        _ = recv_or_pending(term) => {}
        _ = recv_or_pending(int) => {}
    }
}

#[cfg(not(unix))]
async fn wait_terminate(_term: &mut SigHandle, _int: &mut SigHandle) {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(unix)]
fn install_signal_handlers() -> (SigHandle, SigHandle) {
    use tokio::signal::unix::{SignalKind, signal};

    let term = match signal(SignalKind::terminate()) {
        Ok(s) => Some(s),
        Err(e) => {
            warn!("Failed to install SIGTERM handler: {e}");
            None
        }
    };
    let int = match signal(SignalKind::interrupt()) {
        Ok(s) => Some(s),
        Err(e) => {
            warn!("Failed to install SIGINT handler: {e}");
            None
        }
    };
    (term, int)
}

#[cfg(not(unix))]
fn install_signal_handlers() -> (SigHandle, SigHandle) {
    ((), ())
}

// 网卡事件监看：订阅核心的 link / ifaddr 组播，取代定时轮询 ifindex 与 IP。

#[cfg(target_os = "linux")]
type LinkWatch = Option<netlink::link::LinkWatcher>;
/// 非 Linux 平台的空哨兵型别，让两个平台维持同样的形状（`()` 会触发 clippy::let_unit_value）。
#[cfg(not(target_os = "linux"))]
struct LinkWatch;

#[cfg(target_os = "linux")]
async fn wait_link_event(w: &mut LinkWatch) -> Vec<netlink::link::LinkEvent> {
    match w {
        Some(watcher) => watcher.wait_events().await,
        None => {
            std::future::pending::<()>().await;
            Vec::new()
        }
    }
}

#[cfg(not(target_os = "linux"))]
async fn wait_link_event(_w: &mut LinkWatch) -> Vec<netlink::link::LinkEvent> {
    std::future::pending::<()>().await;
    Vec::new()
}

#[cfg(target_os = "linux")]
fn install_link_watcher() -> LinkWatch {
    match netlink::link::LinkWatcher::new() {
        Ok(w) => {
            info!("Subscribed to kernel link/address events (RTNLGRP_LINK + IFADDR)");
            Some(w)
        }
        Err(e) => {
            warn!(
                "Failed to subscribe to kernel link events ({e}); falling back to periodic refresh"
            );
            None
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn install_link_watcher() -> LinkWatch {
    LinkWatch
}

#[cfg(target_os = "linux")]
fn disable_link_watch(w: &mut LinkWatch) {
    *w = None;
}

#[cfg(not(target_os = "linux"))]
fn disable_link_watch(_w: &mut LinkWatch) {}

#[cfg(target_os = "linux")]
fn link_watch_active(w: &LinkWatch) -> bool {
    w.is_some()
}

#[cfg(not(target_os = "linux"))]
fn link_watch_active(_w: &LinkWatch) -> bool {
    false
}

/// 重新解析 ifindex；解析不到就归零（保留旧值会把已死 index 继续写进内核路由）。
fn refresh_ifindex(monitor: &mut WanMonitor, reason: &str) -> bool {
    match if_nametoindex(&monitor.ifname) {
        Ok(idx) => {
            if idx != monitor.ifindex {
                info!(
                    "Interface {} ifindex changed: {} -> {} ({reason})",
                    monitor.ifname, monitor.ifindex, idx
                );
                monitor.ifindex = idx;
                return true;
            }
            false
        }
        Err(e) => {
            if monitor.ifindex != 0 {
                warn!(
                    "Interface {} is gone ({}); marking it unusable until it returns ({reason})",
                    monitor.ifname, e
                );
                monitor.ifindex = 0;
                return true;
            }
            false
        }
    }
}

fn refresh_interface_state(monitors: &mut [WanMonitor], reason: &str) -> bool {
    let mut changed = false;
    for monitor in monitors.iter_mut() {
        changed |= refresh_ifindex(monitor, reason);
        monitor.refresh_cached_ip();
    }
    changed
}

/// 只刷新受影响的网卡：Link 事件按名称、Address 事件按 ifindex，避免每个事件都全量查系统呼叫。
#[cfg(target_os = "linux")]
fn refresh_affected_interfaces(
    monitors: &mut [WanMonitor],
    events: &[netlink::link::LinkEvent],
) -> bool {
    let mut changed = false;
    for monitor in monitors.iter_mut() {
        let mut touched = false;
        let mut reindex = false;
        for e in events {
            match e {
                netlink::link::LinkEvent::Link {
                    ifname: Some(name), ..
                } if name == &monitor.ifname => {
                    touched = true;
                    reindex = true;
                }
                netlink::link::LinkEvent::Address { ifindex } if *ifindex == monitor.ifindex => {
                    touched = true;
                }
                _ => {}
            }
        }
        if !touched {
            continue;
        }
        if reindex {
            changed |= refresh_ifindex(monitor, "kernel link event");
        }
        monitor.refresh_cached_ip();
    }
    changed
}

#[cfg(not(target_os = "linux"))]
fn refresh_affected_interfaces(
    _monitors: &mut [WanMonitor],
    _events: &[netlink::link::LinkEvent],
) -> bool {
    false
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let args: Vec<String> = env::args().collect();
    let bin_name = args.first().map(|s| s.as_str()).unwrap_or("mwan4");

    let mut config_path: Option<String> = None;
    let mut check_config_path: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-c" | "--config" => {
                if i + 1 < args.len() {
                    config_path = Some(args[i + 1].clone());
                    i += 1;
                } else {
                    eprintln!("Error: --config requires a file path argument");
                    process::exit(1);
                }
            }
            other if other.starts_with("--config=") => {
                config_path = Some(other["--config=".len()..].to_string());
            }
            other if other.starts_with("-c=") => {
                config_path = Some(other["-c=".len()..].to_string());
            }
            "-t" | "--check-config" => {
                if i + 1 < args.len() {
                    check_config_path = Some(args[i + 1].clone());
                    i += 1;
                } else {
                    eprintln!("Error: --check-config requires a file path argument");
                    process::exit(1);
                }
            }
            other if other.starts_with("--check-config=") => {
                check_config_path = Some(other["--check-config=".len()..].to_string());
            }
            "--gen-config" => {
                let default_cfg = DaemonConfig::default();
                println!("{}", serde_json::to_string_pretty(&default_cfg).unwrap());
                return Ok(());
            }
            "-v" | "--version" => {
                println!("mwan4 v{}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "-h" | "--help" => {
                print_help(bin_name);
                return Ok(());
            }
            other => {
                eprintln!("Unknown option: {other}");
                print_help(bin_name);
                process::exit(1);
            }
        }
        i += 1;
    }

    if let Some(path) = check_config_path {
        match DaemonConfig::load_from_file(&path) {
            Ok(_) => {
                println!("Configuration OK: {path}");
                return Ok(());
            }
            Err(e) => {
                eprintln!("Configuration error in {path}: {e}");
                process::exit(1);
            }
        }
    }

    let config = match config_path {
        Some(path) => {
            info!("Loading configuration from: {path}");
            DaemonConfig::load_from_file(&path).unwrap_or_else(|e| {
                error!("Failed to load configuration from {path}: {e}");
                process::exit(1);
            })
        }
        None => {
            info!(
                "No config file specified, checking /etc/mwan4/mwan4.json or fallback to defaults..."
            );
            if std::path::Path::new("/etc/mwan4/mwan4.json").exists() {
                DaemonConfig::load_from_file("/etc/mwan4/mwan4.json").unwrap_or_else(|e| {
                    error!("Failed to load /etc/mwan4/mwan4.json: {e}");
                    process::exit(1);
                })
            } else {
                warn!(
                    "Using default built-in configuration (wan1: 192.168.1.1, wan2: 192.168.2.1)"
                );
                DaemonConfig::default()
            }
        }
    };

    if config.probe_timeout_ms > config.check_interval_ms {
        warn!(
            "probe_timeout_ms ({}) is greater than check_interval_ms ({}): \
             the effective probe period will be stretched to the timeout",
            config.probe_timeout_ms, config.check_interval_ms
        );
    }

    // 单实例锁：两个 mwan4 同时操作同一条预设路由会互相覆盖。
    if let Err(e) = acquire_pid_file() {
        error!("{e}");
        process::exit(1);
    }

    info!(
        "Starting mwan4 daemon (Probe interval: {}ms, Timeout: {}ms, Window: {}, Hysteresis: {} success, ECMP mode: {:?})",
        config.check_interval_ms,
        config.probe_timeout_ms,
        config.window_size,
        config.recovery_success_count,
        config.ecmp_mode
    );

    // 单成员没有可分流对象：ECMP/品质/负载感知都退回静态权重，并明确告知使用者。
    if config.interfaces.len() < 2 {
        warn!(
            "Only {} WAN interface configured: multipath and the dynamic weight factors \
             (quality / load_aware) stay off until a second member exists, because a single member \
             always receives 100% of the traffic and every weight change would just rewrite an \
             identical FIB entry.",
            config.interfaces.len()
        );
    }

    // 用明确错误讯息 + exit(1) 取代 expect()：panic=abort 下 panic 只会留下一行堆叠。
    let route_mgr = match RouteManager::new(config.route_priority, config.ecmp_mode) {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to initialize Netlink Route socket: {e} (is CAP_NET_ADMIN granted?)");
            release_pid_file();
            process::exit(1);
        }
    };
    // 先扫掉自己保留区段内残留的探针规则／表内路由：上次的介面顺序可能不同，残留 `oif` 规则会把探针导向旧闸道。
    let mut route_mgr = route_mgr;
    if let Err(e) = route_mgr.sweep_probe_paths() {
        warn!("Failed to sweep stale probe paths on startup: {e}");
    }
    // 清掉上次残留的主表 /32（按专属 metric 转储，涵盖已移除的目标）；执行期只清探针 /32。
    match route_mgr.sweep_all_own_host_routes() {
        Ok(0) => {}
        Ok(n) => info!("Cleaned up {n} leftover mwan4 host route(s) on startup"),
        Err(e) => warn!("Failed to clean up leftover mwan4 host routes: {e}"),
    }
    // 策略规则的保留区段也先清：上次的规则可能指向已不存在的表／网关。
    if let Err(e) = route_mgr.sweep_policy_rules() {
        warn!("Failed to sweep stale policy rules on startup: {e}");
    }
    // 只用于「问内核路径」的查询 socket，与 worker 的写入 socket 分开。
    let mut query_mgr = match RouteManager::new(config.route_priority, config.ecmp_mode) {
        Ok(m) => {
            // 事件回圈上同步使用：逾时缩到 300ms，避免内核不回应时每次查询阻塞 2 秒。
            if let Err(e) = m.set_netlink_timeout(Duration::from_millis(300)) {
                warn!(
                    "Failed to shorten netlink query socket timeouts ({e}); \
                     queries may block longer than expected"
                );
            }
            Some(m)
        }
        Err(e) => {
            warn!(
                "Route query socket unavailable ({e}); probe-path decisions fall back to estimates"
            );
            None
        }
    };
    let conntrack_mgr = match ConntrackManager::new() {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to initialize Netlink Conntrack socket: {e}");
            release_pid_file();
            process::exit(1);
        }
    };
    // worker 建立失败不该用 expect：panic=abort 会让行程在 pid 档与路由清理之前消失。
    let (netlink_tx, netlink_rx, netlink_worker) =
        match spawn_netlink_worker(route_mgr, conntrack_mgr) {
            Ok(parts) => parts,
            Err(e) => {
                error!("Failed to start the netlink worker: {e}");
                release_pid_file();
                process::exit(1);
            }
        };

    let mut monitors: Vec<WanMonitor> = Vec::new();
    for iface_cfg in &config.interfaces {
        let ifindex = match if_nametoindex(&iface_cfg.name) {
            Ok(idx) => {
                info!("Mapped interface {} -> ifindex {}", iface_cfg.name, idx);
                idx
            }
            Err(e) => {
                warn!(
                    "Could not resolve ifindex for interface {}: {}. Will try dynamically during runtime.",
                    iface_cfg.name, e
                );
                0
            }
        };

        monitors.push(WanMonitor {
            ifname: iface_cfg.name.clone(),
            ifindex,
            gateway: iface_cfg.gateway,
            gateway6: iface_cfg.gateway6,
            metric: iface_cfg.metric,
            weight: iface_cfg.weight,
            effective_weight: iface_cfg.weight,
            last_tx_bytes: None,
            last_rx_bytes: None,
            last_stats_at: None,
            tx_bps: 0.0,
            rx_bps: 0.0,
            tx_bps_ewma: 0.0,
            rx_bps_ewma: 0.0,
            load_ewma_ready: false,
            load_pressure_active: false,
            down_bps_capacity: iface_cfg.max_mbps.map(|mbps| mbps * 1_000_000.0),
            up_bps_capacity: iface_cfg
                .up_mbps
                .or(iface_cfg.max_mbps)
                .map(|mbps| mbps * 1_000_000.0),
            targets: iface_cfg.probe_targets.clone(),
            preferred_target: 0,
            underlay_targets: iface_cfg.underlay_targets.clone(),
            cached_ip: crate::netlink::util::get_interface_ipv4(&iface_cfg.name).ok(),
            last_known_ip: crate::netlink::util::get_interface_ipv4(&iface_cfg.name).ok(),
            last_conntrack_flush: None,
            last_probe_error: None,
            last_error_is_local: false,
            local_condition_warned: false,
            probe_path_missing: false,
            last_path_check: None,
            down_since: None,
            last_down_at: None,
            flushed_while_down: false,
            lqe: LinkQualityEstimator::new(iface_cfg.name.clone(), &config),
        });
    }

    let has_ipv6 = monitors.iter().any(|m| m.gateway6.is_some());
    if has_ipv6 {
        info!("IPv6 default route management enabled (interfaces with gateway6)");
    } else if let Ok(table) = std::fs::read_to_string("/proc/net/ipv6_route") {
        // 没设 gateway6 就不管 IPv6 路由；v6 视频（QUIC）会一直走 netifd 单线，故提示一次。
        if has_kernel_ipv6_default_route(&table) {
            info!(
                "IPv6 default route exists but no interface has 'gateway6' configured: IPv6 \
                 traffic is NOT managed by mwan4 (no failover, no per-connection spreading) and \
                 keeps using the kernel's single default route. Video over IPv6 will not benefit \
                 from the multipath hash policy. Set gateway6 on each WAN to include IPv6."
            );
        }
    }

    // 多路径哈希策略写入内核 sysctl（有效开关只有 policy）；失败只告警，旧内核没有这些档案。
    let effective_hash = apply_multipath_hash(config.multipath_hash_policy, has_ipv6);
    let mut effective_hash_v4 = effective_hash
        .iter()
        .find(|(label, _)| *label == "ipv4")
        .map(|(_, eff)| *eff)
        .unwrap_or_default();
    // 两条线以上却只按 L3 哈希 = 同一目的 IP 全挤一条 WAN；明确选 l3/inner 只提示，写 null 却拿到 L3 才告警。
    if monitors.len() >= 2 && effective_hash_v4.l3_only() {
        if config.multipath_hash_policy.is_some() {
            info!(
                "Multipath hash granularity is L3-only ({}) because multipath_hash_policy is \
                 set explicitly; connections to the same destination IP stay on one WAN \
                 (video CDNs, multi-threaded downloads). Use \"l4\" to spread them per \
                 connection.",
                effective_hash_v4.describe()
            );
        } else {
            warn!(
                "Multipath hash granularity is L3-only ({}): with multipath_hash_policy set to \
                 null the kernel's own default is used, and it hashes addresses only - every \
                 connection to the same destination IP uses ONE WAN, so a video CDN's \
                 connections cannot be spread over both lines. Set multipath_hash_policy to \
                 \"l4\" (the default when the key is omitted).",
                effective_hash_v4.describe()
            );
        }
    }

    let probe_interval = Duration::from_millis(config.check_interval_ms);
    let probe_timeout = Duration::from_millis(config.probe_timeout_ms);
    let conntrack_flush_min_interval =
        Duration::from_millis(config.conntrack_flush_min_interval_ms);
    // 内核实际安装 resilient 时关闭 flush-on-switch（它只重映射故障成员的 flow）；依据是 worker 回报的实际变体。
    let mut kernel_resilient = false;
    let mut kernel_variant_known = false;
    let mut ticker = tokio::time::interval(probe_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let (mut sigterm, mut sigint) = install_signal_handlers();
    let mut link_watch = install_link_watcher();

    let mut tick_count: u64 = 0;
    // None = 尚未下发过任何路由，避免开机第一次探测就删掉别人（netifd）的预设路由。
    let mut last_active_ifindexes: Option<Vec<u32>> = None;
    // v6 更新入队失败时暂存重试，否则 need_apply 变回 false 后会永久丢失。
    let mut v6_pending: Option<Vec<ActiveWanRouteV6>> = None;
    let mut probe_paths_dirty = true;
    let mut probe_paths_inflight = false;
    let mut probe_paths_retry_at: u64 = 0;
    let mut probe_host_routes_cleanup = true;
    let mut v4_apply_dirty = false;
    let mut v4_apply_inflight = false;
    let mut v4_retry_at: u64 = 0;
    let mut link_watch_retry_at: u64 = 0;
    let mut route_fail_count: u64 = 0;
    let mut last_route_fail: Option<String> = None;
    let mut conntrack_fail_count: u64 = 0;
    let mut last_conntrack_fail: Option<String> = None;
    let mut netlink_worker_gone = false;
    let mut strict_shared_warned = false;
    let mut degrade_fallback_warned = false;
    let mut dynamic_factor_gate_warned = false;
    // 起点刻意往前推一个 interval，让第一个 tick 就算出容量比例／品质权重，而不是先跑 10 秒设定值。
    let dynamic_weight_interval = Duration::from_millis(config.dynamic_weight_interval_ms);
    let mut weights_dirty = false;
    let mut last_weight_update = Instant::now()
        .checked_sub(dynamic_weight_interval)
        .unwrap_or_else(Instant::now);
    let mut policies_dirty = !config.policies.is_empty();
    let mut policies_inflight = false;
    let mut policies_retry_at: u64 = 0;
    let mut last_policy_signature: Option<Vec<PolicyRule>> = None;

    info!("mwan4 event loop running. Press Ctrl+C to terminate.");

    loop {
        tokio::select! {
            _ = wait_terminate(&mut sigterm, &mut sigint) => {
                info!("Received termination signal (SIGINT/SIGTERM), exiting cleanly...");
                break;
            }
            events = wait_link_event(&mut link_watch) => {
                if events.is_empty() {
                    // 订阅失效可恢复：关掉它、退回轮询，稍后重新订阅。
                    warn!(
                        "Link watcher stopped; falling back to periodic refresh, will retry subscribing shortly"
                    );
                    disable_link_watch(&mut link_watch);
                    link_watch_retry_at = tick_count + LINK_WATCH_RETRY_TICKS;
                    continue;
                }
                if log::log_enabled!(log::Level::Debug) {
                    let ifindexes: Vec<u32> = events.iter().map(|e| e.ifindex()).collect();
                    debug!("Kernel link/address events for ifindex {ifindexes:?}");
                }
                // 接收缓冲溢位（ENOBUFS）= 中间有事件遗失，做一次全量 resync。
                let ifindex_changed = if events
                    .iter()
                    .any(|e| matches!(e, netlink::link::LinkEvent::Resync))
                {
                    warn!("Netlink event buffer overflowed (ENOBUFS); resynchronizing interface state");
                    refresh_interface_state(&mut monitors, "netlink overflow")
                } else {
                    refresh_affected_interfaces(&mut monitors, &events)
                };
                if ifindex_changed {
                    probe_paths_dirty = true;
                }
            }
            _ = ticker.tick() => {
                tick_count += 1;

                // 哈希粒度定期自我修复：启动只写一次，被改回 L3 后状态档会一直显示旧值。
                if tick_count % HASH_RECHECK_TICKS == 0 {
                    let now = read_effective_hash_v4();
                    if !hash_policy_matches(config.multipath_hash_policy, now.policy) {
                        warn!(
                            "Multipath hash granularity drifted (policy {:?} -> want {:?}); \
                             re-applying, otherwise connections to the same destination IP \
                             collapse onto a single WAN",
                            now.policy,
                            config.multipath_hash_policy.map(|p| p.sysctl_value())
                        );
                        let _ = apply_multipath_hash(config.multipath_hash_policy, has_ipv6);
                        effective_hash_v4 = read_effective_hash_v4();
                    } else {
                        effective_hash_v4 = now;
                    }
                }

                // 收集 worker 结果；失败标 dirty，下个 tick 重下同一份期望状态（幂等）。
                while let Ok(outcome) = netlink_rx.try_recv() {
                    match outcome.op {
                        NetlinkOp::Ipv4Routes => {
                            v4_apply_inflight = false;
                            if !outcome.ok {
                                // 去重告警：永久失败时每 2 秒一条会把 logd 环形缓冲冲掉，反而盖掉有用的讯息。
                                let detail = outcome.detail.unwrap_or_else(|| "unknown".into());
                                route_fail_count += 1;
                                if last_route_fail.as_deref() != Some(detail.as_str())
                                    || route_fail_count % 20 == 1
                                {
                                    warn!(
                                        "Kernel IPv4 default route update failed ({detail}); \
                                         re-applying the expected state shortly \
                                         (self-heal, occurrence {route_fail_count})"
                                    );
                                    last_route_fail = Some(detail);
                                }
                                v4_apply_dirty = true;
                                v4_retry_at = tick_count + 4;
                            } else {
                                route_fail_count = 0;
                                last_route_fail = None;
                                if let Some(variant) = outcome.variant {
                                    let resilient = variant == InstalledVariant::Resilient;
                                    if !kernel_variant_known || resilient != kernel_resilient {
                                        kernel_variant_known = true;
                                        kernel_resilient = resilient;
                                        debug!(
                                            "Installed IPv4 default route variant: {} \
                                             (flush_conntrack_on_switch {})",
                                            if resilient {
                                                "resilient nexthop group"
                                            } else {
                                                "standard ECMP"
                                            },
                                            if config.flush_conntrack_on_switch && !resilient {
                                                "enabled"
                                            } else {
                                                "suppressed"
                                            }
                                        );
                                    }
                                }
                            }
                        }
                        NetlinkOp::Ipv6Routes => {
                            if !outcome.ok {
                                debug!("IPv6 FIB update failed; it will be re-applied with the next heartbeat");
                            }
                        }
                        NetlinkOp::ProbePaths => {
                            probe_paths_inflight = false;
                            if !outcome.ok {
                                probe_paths_dirty = true;
                                probe_paths_retry_at = tick_count + 6;
                            }
                        }
                        NetlinkOp::Conntrack => {
                            if !outcome.ok {
                                let detail =
                                    outcome.detail.unwrap_or_else(|| "unknown".into());
                                conntrack_fail_count += 1;
                                if last_conntrack_fail.as_deref() != Some(detail.as_str())
                                    || conntrack_fail_count % 20 == 1
                                {
                                    warn!(
                                        "Conntrack flush failed ({detail}); will retry while the \
                                         link stays down (occurrence {conntrack_fail_count})"
                                    );
                                    last_conntrack_fail = Some(detail);
                                }
                                // 失败的 flush 不算「本次 DOWN 已清」：重设旗标，静默期与限流过后会再送一次（清理幂等）。
                                for monitor in monitors.iter_mut() {
                                    if monitor.down_since.is_some() {
                                        monitor.flushed_while_down = false;
                                    }
                                }
                            } else {
                                conntrack_fail_count = 0;
                                last_conntrack_fail = None;
                            }
                        }
                        NetlinkOp::Policies => {
                            policies_inflight = false;
                            if !outcome.ok {
                                policies_dirty = true;
                                policies_retry_at = tick_count + 6;
                            }
                        }
                    }
                }

                // worker 意外结束只会得到 Disconnected，必须告警并清 inflight，否则旗标永远卡住。
                if !netlink_worker_gone
                    && matches!(
                        netlink_rx.try_recv(),
                        Err(std::sync::mpsc::TryRecvError::Disconnected)
                    )
                {
                    netlink_worker_gone = true;
                    error!(
                        "Netlink worker exited unexpectedly; kernel routes and conntrack will no \
                         longer be updated until the service is restarted"
                    );
                }

                if !link_watch_active(&link_watch) && tick_count >= link_watch_retry_at {
                    link_watch = install_link_watcher();
                    if link_watch_active(&link_watch) {
                        info!("Link watcher re-subscribed successfully");
                    } else {
                        link_watch_retry_at = tick_count + LINK_WATCH_RETRY_TICKS;
                    }
                }

                if let Some(pending) = v6_pending.take() {
                    match netlink_tx.try_send(NetlinkCmd::ApplyV6(pending)) {
                        Ok(()) => {}
                        Err(err) => {
                            let err_desc = err.to_string();
                            if let std::sync::mpsc::TrySendError::Full(NetlinkCmd::ApplyV6(v6))
                            | std::sync::mpsc::TrySendError::Disconnected(NetlinkCmd::ApplyV6(v6)) = err
                            {
                                v6_pending = Some(v6);
                            }
                            debug!("IPv6 FIB update still queued; will retry next tick: {err_desc}");
                        }
                    }
                }

                let mut probe_futs = Vec::with_capacity(monitors.len());
                for monitor in monitors.iter() {
                    // 上一拍失败的线视为疑似故障：同时发出所有目标，否则「先超时再探其余」会让整拍花 2 × timeout。
                    probe_futs.push(prober::probe_interface(
                        &monitor.ifname,
                        &monitor.targets,
                        probe_timeout,
                        monitor.preferred_target,
                        monitor.lqe.consecutive_timeouts > 0,
                    ));
                }
                let samples = futures_util::future::join_all(probe_futs).await;
                let mut state_changed = false;
                // (下标, 是否来自 flush-on-down)；统一延后到路由下发之后入队，避免 conntrack 全表 dump 拖慢切换收敛。
                let mut flush_pending: Vec<(usize, bool)> = Vec::new();

                for (monitor, sample) in monitors.iter_mut().zip(samples.into_iter()) {
                    // 探通的目标成为下个周期的主目标：健康时每周期只发一条探针，失败才回退其余目标。
                    if sample.success {
                        if let Some(idx) = monitor.targets.iter().position(|t| *t == sample.target) {
                            monitor.preferred_target = idx;
                        }
                    }

                    let (new_state, changed) = monitor.lqe.update(&sample);
                    if changed {
                        state_changed = true;
                        monitor.refresh_cached_ip();

                        // 只记录「何时进入 DOWN」；真正的清理延后到确认不是抖动之后。
                        match new_state {
                            LinkState::Down => {
                                let now = Instant::now();
                                monitor.down_since = Some(now);
                                monitor.last_down_at = Some(now);
                            }
                            _ => {
                                monitor.down_since = None;
                                monitor.flushed_while_down = false;
                            }
                        }
                    }

                    // 失败原因是现场区分「线路真的丢包」与「本机没有路由／设备名错误」的唯一线索，必须进状态档。
                    match sample.error_msg.as_deref() {
                        Some(msg) => {
                            let is_local = sample.error_kind == Some(prober::ProbeErrorKind::Local);
                            monitor.last_error_is_local = is_local;
                            if is_local && !monitor.local_condition_warned {
                                monitor.local_condition_warned = true;
                                warn!(
                                    "[{}] Probe cannot even leave the device ({msg}). \
                                     This is a local routing/interface problem, not carrier packet loss; \
                                     the per-WAN probe path will be re-applied.",
                                    monitor.ifname
                                );
                                probe_paths_dirty = true;
                            }
                            if monitor.last_probe_error.as_deref() != Some(msg) {
                                debug!("[{}] Probe error changed: {msg}", monitor.ifname);
                            }
                            monitor.last_probe_error = Some(msg.to_string());

                            // 设备 UP 但本机没有经它的路时探针只会超时，与真丢包难分；连续失败时问一次内核并标成 local_condition。
                            let due = monitor
                                .last_path_check
                                .is_none_or(|t| t.elapsed() >= Duration::from_secs(2));
                            if due && monitor.lqe.consecutive_timeouts >= 2 && monitor.ifindex != 0 {
                                monitor.last_path_check = Some(Instant::now());
                                let target = monitor.targets.iter().find_map(|t| match t.ip() {
                                    std::net::IpAddr::V4(v4) => Some(v4),
                                    std::net::IpAddr::V6(_) => None,
                                });
                                if let Some(target) = target {
                                    if let Some(has_route) = kernel_has_route(
                                        &mut query_mgr,
                                        target,
                                        Some(monitor.ifindex),
                                    ) {
                                        if !has_route && !monitor.probe_path_missing {
                                            monitor.probe_path_missing = true;
                                            warn!(
                                                "[{}] The kernel has NO route to {} via {}. \
                                                 Probes will look like packet loss (on-link blackhole) \
                                                 even though the link may be fine — this is a local \
                                                 routing problem.",
                                                monitor.ifname, target, monitor.ifname
                                            );
                                            probe_paths_dirty = true;
                                        } else if has_route {
                                            monitor.probe_path_missing = false;
                                        }
                                    }
                                }
                            }
                        }
                        None => {
                            monitor.last_probe_error = None;
                            monitor.last_error_is_local = false;
                            monitor.local_condition_warned = false;
                            monitor.probe_path_missing = false;
                        }
                    }
                }

                for monitor in monitors.iter_mut() {
                    if monitor.ifindex == 0 && refresh_ifindex(monitor, "retry after startup") {
                        info!(
                            "Resolved ifindex for {}: {}",
                            monitor.ifname, monitor.ifindex
                        );
                        probe_paths_dirty = true;
                    }
                }

                if tick_count % IFINDEX_REFRESH_TICKS == 0
                    && refresh_interface_state(&mut monitors, "periodic refresh")
                {
                    probe_paths_dirty = true;
                }

                // 存活线 metric 相同 → 全进 ECMP 分流；不同 → 只下发 metric 最小者（主备）。
                let min_up_metric = monitors
                    .iter()
                    .filter(|m| m.lqe.state == LinkState::Up && m.ifindex != 0)
                    .map(|m| m.metric)
                    .min();

                // ⚠️ 探针 /32 的 wants_it 必须用 up_primary 而非 is_active：降级的线仍 Up 且 metric 最小。
                let up_primary = |m: &WanMonitor| {
                    m.lqe.state == LinkState::Up && m.ifindex != 0 && Some(m.metric) == min_up_metric
                };

                // 降级：窗口已满且丢包率达 degrade_loss_threshold 的线移出 ECMP（仍继续探测）。
                let any_undegraded = monitors
                    .iter()
                    .any(|m| up_primary(m) && !m.lqe.is_degraded());
                // 保底：全部降级时保留实测丢包最低的一条，否则会完全没有预设路由。
                let degrade_fallback_slot = if any_undegraded {
                    None
                } else {
                    pick_degrade_fallback(&monitors, |_, m| up_primary(m))
                };
                match degrade_fallback_slot {
                    None => degrade_fallback_warned = false,
                    Some(slot) => {
                        if !degrade_fallback_warned {
                            degrade_fallback_warned = true;
                            warn!(
                                "[{}] All usable WANs are degraded (window loss >= {:.1}%); \
                                 keeping it as the default route anyway so the router is not left \
                                 without an exit. It is still being probed and will rejoin the \
                                 other WANs as soon as its loss drops",
                                monitors[slot].ifname,
                                config.degrade_loss_threshold * 100.0
                            );
                        }
                    }
                }

                let is_active = |slot: usize, m: &WanMonitor| {
                    up_primary(m) && (!m.lqe.is_degraded() || degrade_fallback_slot == Some(slot))
                };

                let stats_now = Instant::now();
                for monitor in monitors.iter_mut() {
                    sample_interface_rates(monitor, stats_now);
                }

                // 动态权重（quality / load_aware，含容量比例）每次变更都会重下 ECMP 路由，故受限速约束。
                // 动态因子的唯一作用是把流量在成员之间挪动：只有一个成员时权重毫无意义
                // （256 个 bucket 全指向同一个 nexthop），却会让预设路由被反复重下（实测单线每 2 秒一次）。
                let dynamic_weights_on = (config.weight_mode == WeightMode::Quality
                    || config.load_aware
                    || config.capacity_weights_on())
                    && monitors.len() >= 2;
                // standard ECMP 下权重一变就重算整张 multipath hash（实测搬走 24%~39% 既有连线）却搬不动大流量。
                let dynamic_factors_on = dynamic_factors_allowed(&config, kernel_resilient);
                // 必须等 worker 回报实际变体后才告警，否则支援 resilient 的机器会被误报。
                if dynamic_weights_on
                    && !dynamic_factors_on
                    && kernel_variant_known
                    && !dynamic_factor_gate_warned
                    && (config.weight_mode == WeightMode::Quality || config.load_aware)
                {
                    dynamic_factor_gate_warned = true;
                    let remedy = if config.ecmp_mode == EcmpMode::Standard {
                        "Use ecmp_mode: resilient (or auto) to make weight changes safe, or set \
                         allow_dynamic_weights_on_standard: true to override this guard."
                    } else {
                        "ecmp_mode is 'auto'/'resilient' but this kernel has no usable nexthop \
                         object support (auto falls back to standard), so the guard stays on; \
                         set allow_dynamic_weights_on_standard: true only if you accept the \
                         rehash cost above."
                    };
                    warn!(
                        "weight_mode/load_aware is configured but the installed ECMP variant is \
                         'standard': dynamic weight factors are IGNORED (keep only the static \
                         weight / max_mbps ratio). In standard mode every weight change recomputes \
                         the whole multipath hash and re-homes 24%~39% of *established* connections \
                         (their NAT source IP changes -> RST / heavy retransmits), while it cannot \
                         move the established flows that caused the imbalance. {remedy}"
                    );
                }
                // 压力 Schmitt 触发器每拍都要更新（纯记忆体状态），转换点不能被 10 秒限速掩盖。
                let active_flags: Vec<bool> = monitors
                    .iter()
                    .enumerate()
                    .map(|(slot, m)| is_active(slot, m))
                    .collect();
                let pressure_transition = if dynamic_weights_on
                    && config.load_aware
                    && dynamic_factors_on
                {
                    update_load_pressure(
                        &mut monitors,
                        &active_flags,
                        config.load_target_ratio,
                        config.load_recover_ratio,
                    )
                } else {
                    false
                };
                // 只有一个「活跃」成员时权重没有可分流对象（DOWN 的成员本来就不在集合里），
                // 权重变更只会等价重写 FIB；多成员时才有意义。
                let multipath_members = active_flags.iter().filter(|active| **active).count();
                if dynamic_weights_on
                    && multipath_members >= 2
                    && weight_update_due(
                        last_weight_update.elapsed(),
                        dynamic_weight_interval,
                        pressure_transition,
                        WEIGHT_UPDATE_MIN_SPACING,
                    )
                {
                    let new_weights = compute_dynamic_weights(
                        &monitors,
                        |slot, _| active_flags[slot],
                        &config,
                        dynamic_factors_on,
                    );
                    let changed = monitors
                        .iter()
                        .enumerate()
                        .any(|(slot, m)| m.effective_weight != new_weights[slot]);
                    if changed {
                        let desc: Vec<String> = monitors
                            .iter()
                            .enumerate()
                            .filter(|(slot, m)| m.effective_weight != new_weights[*slot])
                            .map(|(slot, m)| {
                                format!(
                                    "{}:{}->{}",
                                    m.ifname, m.effective_weight, new_weights[slot]
                                )
                            })
                            .collect();
                        debug!(
                            "Dynamic ECMP weights updated (quality={}, load={}, capacity={}, \
                             load-transition={}): {}",
                            config.weight_mode == WeightMode::Quality,
                            config.load_aware,
                            config.capacity_weights_on(),
                            pressure_transition,
                            desc.join(" ")
                        );
                        for (slot, monitor) in monitors.iter_mut().enumerate() {
                            monitor.effective_weight = new_weights[slot];
                        }
                        weights_dirty = true;
                    }
                    last_weight_update = Instant::now();
                }

                // 无分配的快速比较：多数 tick 集合其实没变，只有真变了才构建路由描述。
                let active_count = monitors
                    .iter()
                    .enumerate()
                    .filter(|(slot, m)| is_active(*slot, m))
                    .count();
                let set_unchanged = match &last_active_ifindexes {
                    None => active_count == 0,
                    Some(prev) => {
                        prev.len() == active_count
                            && monitors
                                .iter()
                                .enumerate()
                                .filter(|(slot, m)| is_active(*slot, m))
                                .map(|(_, m)| m.ifindex)
                                .eq(prev.iter().copied())
                    }
                };

                // 只有指令真的进伫列才更新 last_active_ifindexes；伫列满则保留旧值让下个 tick 重试。
                let route_heartbeat =
                    tick_count % ROUTE_HEARTBEAT_TICKS == 0 && last_active_ifindexes.is_some();
                let need_apply = (!set_unchanged
                    || weights_dirty
                    || (v4_apply_dirty && tick_count >= v4_retry_at)
                    || route_heartbeat)
                    && !v4_apply_inflight;

                if need_apply {
                    let new_set: Vec<u32> = monitors
                        .iter()
                        .enumerate()
                        .filter(|(slot, m)| is_active(*slot, m))
                        .map(|(_, m)| m.ifindex)
                        .collect();
                    if set_unchanged {
                        debug!(
                            "Re-applying IPv4 default route for {:?} \
                             (self-heal / heartbeat / dynamic weights)",
                            new_set
                        );
                    } else {
                        let detail: Vec<String> = monitors
                            .iter()
                            .enumerate()
                            .map(|(slot, m)| {
                                format!(
                                    "{}#{}:{}{}{}",
                                    m.ifname,
                                    m.ifindex,
                                    m.lqe.state,
                                    if is_active(slot, m) {
                                        " in"
                                    } else {
                                        " out"
                                    },
                                    if m.lqe.is_degraded() { " degraded" } else { "" }
                                )
                            })
                            .collect();
                        info!(
                            "Active WAN set changed: {:?} -> {:?} [{}]",
                            last_active_ifindexes,
                            new_set,
                            detail.join(" | ")
                        );
                    }
                    probe_paths_dirty = true;

                    let current_active: Vec<ActiveWanRoute> = monitors
                        .iter()
                        .enumerate()
                        .filter(|(slot, m)| is_active(*slot, m))
                        .map(|(_, m)| ActiveWanRoute {
                            ifname: m.ifname.clone(),
                            ifindex: m.ifindex,
                            gateway: m.gateway,
                            weight: m.effective_weight,
                            metric: m.metric,
                            underlay_targets: m.underlay_targets.clone(),
                        })
                        .collect();

                    // IPv6 路由跟随同一个 IPv4 健康状态（同一条实体链路）。
                    let current_active_v6: Vec<ActiveWanRouteV6> = if has_ipv6 {
                        monitors
                            .iter()
                            .enumerate()
                            .filter(|(slot, m)| is_active(*slot, m) && m.gateway6.is_some())
                            .map(|(_, m)| ActiveWanRouteV6 {
                                ifname: m.ifname.clone(),
                                ifindex: m.ifindex,
                                gateway: m.gateway6,
                                weight: m.effective_weight,
                            })
                            .collect()
                    } else {
                        Vec::new()
                    };

                    match netlink_tx.try_send(NetlinkCmd::Apply(current_active)) {
                        Ok(()) => {
                            v4_apply_inflight = true;
                            v4_apply_dirty = false;
                            weights_dirty = false;

                            // 清理名单只含「新进入存活集合」的成员；连坐其他存活成员会按 WAN IP 清掉一直健康那条线的全部连线（实测 RST）。
                            let flush_on_switch =
                                config.flush_conntrack_on_switch && !kernel_resilient;
                            if !set_unchanged && flush_on_switch && last_active_ifindexes.is_some() {
                                let prev: Vec<u32> =
                                    last_active_ifindexes.clone().unwrap_or_default();
                                flush_pending.extend(
                                    monitors
                                        .iter()
                                        .enumerate()
                                        .filter(|(slot, m)| {
                                            is_active(*slot, m)
                                                && !prev.contains(&m.ifindex)
                                                // 刚从 DOWN 回来的线仍在 25 秒静默期内，flush-on-switch 不该绕过这份保护清它。
                                                && !m.last_down_at.is_some_and(|t| {
                                                    t.elapsed() < CONNTRACK_FLUSH_DOWN_QUIET
                                                })
                                        })
                                        .map(|(idx, _)| (idx, false)),
                                );
                            }
                            last_active_ifindexes = Some(new_set);

                            if has_ipv6 {
                                match netlink_tx.try_send(NetlinkCmd::ApplyV6(current_active_v6)) {
                                    Ok(()) => {
                                        v6_pending = None;
                                    }
                                    Err(err) => {
                                        let err_desc = err.to_string();
                                        if let std::sync::mpsc::TrySendError::Full(
                                            NetlinkCmd::ApplyV6(v6),
                                        )
                                        | std::sync::mpsc::TrySendError::Disconnected(
                                            NetlinkCmd::ApplyV6(v6),
                                        ) = err
                                        {
                                            v6_pending = Some(v6);
                                        }
                                        error!(
                                            "Failed to queue kernel IPv6 FIB route update: {err_desc}. Will retry next tick."
                                        );
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            error!(
                                "Failed to queue kernel FIB route update: {err}. Will retry next tick."
                            );
                        }
                    }
                }

                // 探针路径让探针完全不依赖主表预设路由（「停线→恢复」不再自锁）。
                if tick_count % PROBE_PATH_REFRESH_TICKS == 0 {
                    probe_paths_dirty = true;
                }
                if probe_paths_dirty && !probe_paths_inflight && tick_count >= probe_paths_retry_at {
                    // 必须问内核「有没有预设路由」而非「有没有到目标的路」：自己补的 /32 会造成自我参照振荡（实测装/删各 13 次）。
                    let main_has_default = match query_mgr
                        .as_mut()
                        .map(|q| q.has_main_default_route(AF_INET))
                    {
                        Some(Ok(has)) => has,
                        Some(Err(e)) => {
                            // 查不到时偏向「没有」：多补一条 /32 影响很小，不补则可能让线路永远回不来。
                            debug!("default-route query failed ({e}); assuming there is none");
                            false
                        }
                        None => false,
                    };

                    let mut wants: Vec<(usize, u32, bool, bool, bool, bool, bool)> = Vec::new();
                    for (slot, m) in monitors.iter().enumerate() {
                        if m.ifindex == 0 {
                            continue;
                        }
                        // 「承载中」= Up 且 metric 最小（不排除降级）；用 is_active 会让降级线抢走承载线的回程 /32。
                        let primary = up_primary(m);
                        let strict = effective_rp_filter(&m.ifname) == 1;
                        let shared = monitors.iter().any(|o| {
                            o.ifname != m.ifname && o.targets.iter().any(|t| m.targets.contains(t))
                        });
                        let wants_it = !primary && (!main_has_default || (strict && !shared));
                        // 用内核查询判断这条线能不能真的用（比 sysfs 可靠），设备已 down 时不该把唯一的 /32 给它。
                        let usable = match m.targets.iter().find_map(|t| match t.ip() {
                            std::net::IpAddr::V4(v4) => Some(v4),
                            std::net::IpAddr::V6(_) => None,
                        }) {
                            Some(target) => match kernel_has_route(&mut query_mgr, target, Some(m.ifindex))
                            {
                                Some(false) => false,
                                _ => interface_oper_usable(&m.ifname),
                            },
                            None => interface_oper_usable(&m.ifname),
                        };
                        wants.push((slot, m.metric, primary, strict, shared, wants_it, usable));
                    }

                    // 同一目标只能有一个 /32 拥有者：优先挑设备真的可用的，同群再取 metric 最小者。
                    let owner_of = |target: &std::net::SocketAddr| -> Option<usize> {
                        let mut pool: Vec<(usize, u32, bool)> = Vec::new();
                        for (slot, m) in monitors.iter().enumerate() {
                            if !m.targets.contains(target) {
                                continue;
                            }
                            if let Some(w) = wants.iter().find(|w| w.0 == slot) {
                                if w.5 {
                                    pool.push((slot, m.metric, w.6));
                                }
                            }
                        }
                        if pool.is_empty() {
                            return monitors
                                .iter()
                                .enumerate()
                                .filter(|(_, m)| m.targets.contains(target))
                                .min_by_key(|(slot, m)| (m.metric, *slot))
                                .map(|(slot, _)| slot);
                        }
                        let any_usable = pool.iter().any(|p| p.2);
                        pool.into_iter()
                            .filter(|p| !any_usable || p.2)
                            .min_by_key(|p| (p.1, p.0))
                            .map(|p| p.0)
                    };

                    debug!(
                        "probe-path decision: main_has_default={main_has_default}, \
                         lines=[{}]",
                        wants
                            .iter()
                            .map(|w| format!(
                                "{}:up_primary={} strict={} shared={} want={} usable={}",
                                monitors[w.0].ifname, w.2, w.3, w.4, w.5, w.6
                            ))
                            .collect::<Vec<_>>()
                            .join(" | ")
                    );

                    let mut wanted: Vec<ProbePath> = Vec::with_capacity(monitors.len());
                    for (slot, m) in monitors.iter().enumerate() {
                        if m.ifindex == 0 {
                            continue;
                        }
                        let wants_it = wants
                            .iter()
                            .find(|w| w.0 == slot)
                            .map(|w| w.5)
                            .unwrap_or(false);
                        let main_route_targets: Vec<std::net::Ipv4Addr> = if wants_it {
                            m.targets
                                .iter()
                                .filter(|t| owner_of(t) == Some(slot))
                                .filter_map(|t| match t.ip() {
                                    std::net::IpAddr::V4(v4) => Some(v4),
                                    std::net::IpAddr::V6(_) => None,
                                })
                                .collect()
                        } else {
                            Vec::new()
                        };
                        wanted.push(ProbePath {
                            ifname: m.ifname.clone(),
                            ifindex: m.ifindex,
                            gateway: m.gateway,
                            targets: m
                                .targets
                                .iter()
                                .filter_map(|t| match t.ip() {
                                    std::net::IpAddr::V4(v4) => Some(v4),
                                    std::net::IpAddr::V6(_) => None,
                                })
                                .collect(),
                            table: PROBE_TABLE_BASE + slot as u32,
                            priority: PROBE_RULE_PRIORITY_BASE + slot as u32,
                            main_route_targets,
                        });
                    }

                    let strict_shared_hit = wants
                        .iter()
                        .any(|w| !w.2 && w.3 && w.4 && main_has_default);
                    if strict_shared_hit && !strict_shared_warned {
                        strict_shared_warned = true;
                        warn!(
                            "strict rp_filter (net.ipv4.conf.<wan>.rp_filter=1) combined with SHARED probe \
                             targets cannot probe more than one WAN at a time: the reverse-path check only \
                             accepts a route via the receiving device. Set rp_filter=2 (loose) for the WAN \
                             interfaces, or give each WAN its own probe targets. Only the highest-priority \
                             (lowest metric) line will be monitored."
                        );
                    }
                    debug!(
                        "probe paths queued: [{}]",
                        wanted
                            .iter()
                            .map(|p| format!("{}->/32{:?}", p.ifname, p.main_route_targets))
                            .collect::<Vec<_>>()
                            .join(" | ")
                    );
                    match netlink_tx
                        .try_send(NetlinkCmd::SetProbePaths(wanted, probe_host_routes_cleanup))
                    {
                        Ok(()) => {
                            probe_host_routes_cleanup = false;
                            probe_paths_inflight = true;
                            probe_paths_dirty = false;
                        }
                        Err(err) => {
                            debug!("Probe path update still queued; will retry next tick: {err}");
                        }
                    }
                }

                // 目标 WAN DOWN 时整条政策移除（流量回退 ECMP），恢复自动回来；心跳重下修复被外部删掉的规则。
                if tick_count % PROBE_PATH_REFRESH_TICKS == 0 {
                    policies_dirty = true;
                }
                let policy_wanted = build_policy_rules(&config, &monitors);
                let policy_changed =
                    last_policy_signature.as_deref() != Some(policy_wanted.as_slice());
                if (policy_changed || policies_dirty)
                    && !policies_inflight
                    && tick_count >= policies_retry_at
                {
                    debug!(
                        "Policy rule update queued: {} rule(s) from {} configured policies",
                        policy_wanted.len(),
                        config.policies.len()
                    );
                    match netlink_tx.try_send(NetlinkCmd::SetPolicies(policy_wanted.clone())) {
                        Ok(()) => {
                            policies_inflight = true;
                            policies_dirty = false;
                            last_policy_signature = Some(policy_wanted);
                        }
                        Err(err) => {
                            debug!("Policy rule update still queued; will retry next tick: {err}");
                        }
                    }
                }

                // 路由下发之后才排程 conntrack 清理（worker 只扫一次全表）；DOWN 后等 25 秒确认不是抖动才清。
                if config.flush_conntrack_on_down {
                    let now = Instant::now();
                    for (idx, monitor) in monitors.iter().enumerate() {
                        if monitor.flushed_while_down {
                            continue;
                        }
                        if let Some(since) = monitor.down_since {
                            if now.duration_since(since) >= CONNTRACK_FLUSH_DOWN_QUIET {
                                // ⚠️ 这里只收集、不先标记 flushed_while_down：限流跳过的线若已标记，整段 DOWN 都不会再尝试清理。
                                flush_pending.push((idx, true));
                            }
                        }
                    }
                }

                if !flush_pending.is_empty() {
                    flush_conntrack(
                        &mut monitors,
                        flush_pending,
                        &netlink_tx,
                        Instant::now(),
                        conntrack_flush_min_interval,
                    );
                }

                if tick_count % 2 == 0 || state_changed {
                    let active_names: Vec<&str> = monitors
                        .iter()
                        .enumerate()
                        .filter(|(slot, m)| is_active(*slot, m))
                        .map(|(_, m)| m.ifname.as_str())
                        .collect();
                    let route_desc = build_route_desc(&monitors, &active_names);
                    write_status_file(&monitors, &route_desc, &config, effective_hash_v4);
                }

                if tick_count % 10 == 0 {
                    // 每 8 秒一行的常态摘要会淹掉日志环（状态档 /tmp/mwan4_status.json 已经有完整数值）。
                    for monitor in &monitors {
                        debug!("[{}] {}", monitor.ifname, monitor.lqe.summary());
                    }
                }
            }
        }
    }

    if config.remove_routes_on_exit {
        // 移除本程式下发的预设路由；窗口内整台路由器会失去出口，故预设为 false。
        if let Err(e) = netlink_tx.send(NetlinkCmd::ClearRoutes) {
            warn!("Failed to request default route cleanup: {e}");
        }
    } else {
        // 预设路由保留，但探针路径一定要拆：残留的 `oif` 规则会指向已不存在的网关。
        info!("Leaving the mwan4 default route in place (remove_routes_on_exit = false)");
        // 策略规则一定要拆：它们指向即将被拆的探针表，留着会让流量黑洞而不是回退 ECMP。
        if let Err(e) = netlink_tx.send(NetlinkCmd::SetPolicies(Vec::new())) {
            warn!("Failed to request policy rule cleanup: {e}");
        }
        if let Err(e) = netlink_tx.send(NetlinkCmd::SetProbePaths(Vec::new(), false)) {
            warn!("Failed to request probe path cleanup: {e}");
        }
    }
    drop(netlink_tx);
    if netlink_worker.join().is_err() {
        warn!("Netlink worker thread panicked during shutdown");
    }

    let _ = std::fs::remove_file(STATUS_FILE);
    let _ = std::fs::remove_file(STATUS_TMP_FILE);
    release_pid_file();
    info!("mwan4 daemon stopped.");
    Ok(())
}

/// 判 DOWN 后要持续不可用多久才清 conntrack：10 秒挡不住 8 秒级抖动（实测误清 495 条连线），25 秒能稳稳挡住。
const CONNTRACK_FLUSH_DOWN_QUIET: Duration = Duration::from_secs(25);

struct WanMonitor {
    ifname: String,
    ifindex: u32,
    gateway: Option<std::net::Ipv4Addr>,
    gateway6: Option<std::net::Ipv6Addr>,
    metric: u32,
    weight: u32,
    /// 实际下发到 ECMP 的权重：未启用动态模式时等于 `weight`。
    effective_weight: u32,
    last_tx_bytes: Option<u64>,
    last_rx_bytes: Option<u64>,
    last_stats_at: Option<Instant>,
    tx_bps: f64,
    rx_bps: f64,
    /// 压力判定看平滑值，避免单拍突发就触发权重变更。
    tx_bps_ewma: f64,
    rx_bps_ewma: f64,
    /// 从 0 慢慢爬升会让刚启动的线被误判成空闲，故第一笔直接当初值。
    load_ewma_ready: bool,
    load_pressure_active: bool,
    down_bps_capacity: Option<f64>,
    up_bps_capacity: Option<f64>,
    targets: Vec<std::net::SocketAddr>,
    preferred_target: usize,
    /// 非空同时代表「不能拿这条线去当别条隧道的 underlay 出口」。
    underlay_targets: Vec<std::net::Ipv4Addr>,
    /// 每次写状态档都做 socket + ioctl 太昂贵，故快取。
    cached_ip: Option<std::net::Ipv4Addr>,
    /// 失败时不清空：介面消失/换 IP 后清 conntrack 还要用它匹配 NAT 到旧位址的连线。
    last_known_ip: Option<std::net::Ipv4Addr>,
    last_conntrack_flush: Option<Instant>,
    /// 写进状态档，让「介面不存在／本机无路由」不再被误认成运营商丢包。
    last_probe_error: Option<String>,
    /// 依 errno 分类（不看 strerror 文案），与 `probe_path_missing` 一起决定 local_condition。
    last_error_is_local: bool,
    local_condition_warned: bool,
    /// 内核结论「经这张网卡到目标根本没有路」；这种情况探针只会超时，必须与真丢包区分。
    probe_path_missing: bool,
    last_path_check: Option<Instant>,
    /// 用来区分「短暂抖动」与「真的挂了」——前者不该清 conntrack。
    down_since: Option<Instant>,
    /// 恢复后不清空：用来判断「刚从 DOWN 回来」的线仍在抖动静默期内。
    last_down_at: Option<Instant>,
    flushed_while_down: bool,
    lqe: LinkQualityEstimator,
}

impl WanMonitor {
    /// 查不到时只清 cached_ip，last_known_ip 保留——介面消失/重拨时那正是最需要清理的对象。
    fn refresh_cached_ip(&mut self) {
        match crate::netlink::util::get_interface_ipv4(&self.ifname) {
            Ok(ip) => {
                self.cached_ip = Some(ip);
                self.last_known_ip = Some(ip);
            }
            Err(_) => self.cached_ip = None,
        }
    }
}

/// `last_conntrack_flush` / `flushed_while_down` 必须等真正入队成功才置位：被限流跳过的线若已置位，整段 DOWN 都不会再清。
fn flush_conntrack(
    monitors: &mut [WanMonitor],
    pending: Vec<(usize, bool)>,
    netlink_tx: &NetlinkSender,
    now: Instant,
    min_interval: Duration,
) {
    let mut targets: Vec<ConntrackTarget> = Vec::new();
    let mut marked: Vec<(usize, bool)> = Vec::new();
    for (idx, from_down) in pending {
        let monitor = &monitors[idx];
        if let Some(last) = monitor.last_conntrack_flush {
            if now.duration_since(last) < min_interval {
                debug!(
                    "[{}] Skipping conntrack flush: within min interval",
                    monitor.ifname
                );
                continue;
            }
        }
        // 同一张网卡只清一次；来源旗标 OR 合并，旧 IP 有值优先。
        match targets.iter().position(|(n, _)| n == &monitor.ifname) {
            Some(pos) => {
                marked[pos].1 |= from_down;
                if targets[pos].1.is_none() {
                    targets[pos].1 = monitor.last_known_ip;
                }
            }
            None => {
                targets.push((monitor.ifname.clone(), monitor.last_known_ip));
                marked.push((idx, from_down));
            }
        }
    }
    if targets.is_empty() {
        return;
    }
    match netlink_tx.try_send(NetlinkCmd::FlushConntrack(targets)) {
        Ok(()) => {
            for (idx, from_down) in marked {
                monitors[idx].last_conntrack_flush = Some(now);
                if from_down {
                    monitors[idx].flushed_while_down = true;
                }
            }
        }
        Err(err) => {
            warn!("Failed to queue conntrack flush: {err}");
        }
    }
}

/// active_names 必须由同一套 is_active 判据算出，否则介面显示与实际下发的路由不一致。
fn build_route_desc(monitors: &[WanMonitor], active_names: &[&str]) -> String {
    if active_names.len() > 1 {
        format!("Multipath ECMP ({})", active_names.join(", "))
    } else if active_names.len() == 1 {
        let active_wan = active_names[0];
        let min_cfg_metric = monitors.iter().map(|m| m.metric).min().unwrap_or(1);
        let max_cfg_metric = monitors.iter().map(|m| m.metric).max().unwrap_or(1);
        let my_metric = monitors
            .iter()
            .find(|m| m.ifname == active_wan)
            .map_or(1, |m| m.metric);

        if min_cfg_metric != max_cfg_metric {
            if my_metric == min_cfg_metric {
                format!("Primary Active ({active_wan})")
            } else {
                format!("Failover Active ({active_wan})")
            }
        } else {
            format!("Single Active ({active_wan})")
        }
    } else {
        "All Links DOWN".to_string()
    }
}

#[derive(serde::Serialize)]
struct InterfaceStatus {
    name: String,
    state: String,
    ip: Option<String>,
    gateway: String,
    metric: u32,
    weight: u32,
    effective_weight: u32,
    tx_bps: f64,
    rx_bps: f64,
    load_pct: Option<f64>,
    load_shifted: bool,
    rtt_ms: f64,
    jitter_ms: f64,
    loss_rate: f64,
    consecutive_successes: usize,
    consecutive_timeouts: usize,
    targets: Vec<String>,
    ifindex: u32,
    last_error: Option<String>,
    local_condition: bool,
    degraded: bool,
    samples_in_window: usize,
    window_full: bool,
    state_reason: Option<String>,
}

#[derive(serde::Serialize)]
struct DaemonStatus {
    updated_at: u64,
    stale_after_secs: u64,
    active_routes: String,
    interfaces: Vec<InterfaceStatus>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    policies: Vec<PolicyStatus>,
    hash: HashStatus,
}

/// 为什么放进状态档：「设定档写了 l4」不等于内核真的按连线分流，`l3_only` 就是视频卡顿的成因。
#[derive(serde::Serialize)]
struct HashStatus {
    policy: Option<u8>,
    fields: Option<u32>,
    fields_desc: String,
    l3_only: bool,
}

#[derive(serde::Serialize)]
struct PolicyStatus {
    name: String,
    interface: String,
    priority: u32,
    active: bool,
    source: Vec<String>,
    destination: Vec<String>,
}

/// `fib_multipath_hash_fields` 位元定义（内核 UAPI，数值以 Linux 6.18 实测确认）。
const HASH_FIELDS_L3: u32 =
    HashField::SrcIp.bit() | HashField::DstIp.bit() | HashField::IpProto.bit();
const HASH_FIELDS_L4: u32 = HASH_FIELDS_L3 | HashField::SrcPort.bit() | HashField::DstPort.bit();

fn hash_fields_desc(mask: u32) -> String {
    const ALL: [HashField; 11] = [
        HashField::SrcIp,
        HashField::DstIp,
        HashField::IpProto,
        HashField::SrcPort,
        HashField::DstPort,
        HashField::InnerSrcIp,
        HashField::InnerDstIp,
        HashField::InnerIpProto,
        HashField::FlowLabel,
        HashField::InnerSrcPort,
        HashField::InnerDstPort,
    ];
    let mut names: Vec<&str> = ALL
        .iter()
        .filter(|f| mask & f.bit() != 0)
        .map(|f| f.as_str())
        .collect();
    let known: u32 = ALL.iter().fold(0u32, |acc, f| acc | f.bit());
    let unknown = mask & !known;
    if unknown != 0 {
        names.push("(unknown bits)");
    }
    if names.is_empty() {
        return "none".to_string();
    }
    format!("{mask} ({})", names.join("+"))
}

/// 写入后读回：设定档写了 l4 不等于内核真的按连线分流。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct EffectiveHash {
    policy: Option<u8>,
    fields: Option<u32>,
}

impl EffectiveHash {
    /// 判据只用 policy：实测 fields 写成 1/7/8/9/31/32 都不改变哈希结果。
    fn l3_only(&self) -> bool {
        !matches!(self.policy, Some(1))
    }

    fn describe(&self) -> String {
        match self.fields {
            Some(mask) => format!(
                "policy={} fields={}",
                self.policy
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "n/a".into()),
                hash_fields_desc(mask)
            ),
            None => format!(
                "policy={} fields=n/a (kernel has no fib_multipath_hash_fields)",
                self.policy
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "n/a".into())
            ),
        }
    }
}

/// fields 非 0 时两者都写：实测该档案不影响哈希（policy 才是开关），但部分内核以位元为准。
#[derive(Debug, PartialEq, Eq)]
enum HashFieldsAction {
    PolicyGoverns,
    Extend(u32),
    Covered,
    CannotExpress,
}

fn hash_fields_action(policy: MultipathHashPolicy, current: u32) -> HashFieldsAction {
    let need = match policy {
        MultipathHashPolicy::L3 => HASH_FIELDS_L3,
        MultipathHashPolicy::L4 => HASH_FIELDS_L4,
        MultipathHashPolicy::Inner => return HashFieldsAction::CannotExpress,
    };
    if current == 0 {
        HashFieldsAction::PolicyGoverns
    } else if current & need == need {
        HashFieldsAction::Covered
    } else {
        HashFieldsAction::Extend(current | need)
    }
}

const HASH_POLICY_V4: &str = "/proc/sys/net/ipv4/fib_multipath_hash_policy";
const HASH_FIELDS_V4: &str = "/proc/sys/net/ipv4/fib_multipath_hash_fields";

fn read_sysctl_u8(path: &str) -> Option<u8> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn read_sysctl_u32(path: &str) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn read_effective_hash_v4() -> EffectiveHash {
    EffectiveHash {
        policy: read_sysctl_u8(HASH_POLICY_V4),
        fields: read_sysctl_u32(HASH_FIELDS_V4),
    }
}

/// None（不管理）或读不到读回值都视为符合：启动已告警过，每 30 秒重试只会刷屏。
fn hash_policy_matches(configured: Option<MultipathHashPolicy>, effective: Option<u8>) -> bool {
    match (configured, effective) {
        (None, _) | (Some(_), None) => true,
        (Some(p), Some(v)) => v == p.sysctl_value(),
    }
}

/// 写入 policy（有效开关，None = 不碰）并补齐 fields 缺少的位元（只补不删）；只在值不同时才写，失败只告警。
fn apply_multipath_hash(
    policy: Option<MultipathHashPolicy>,
    has_ipv6: bool,
) -> Vec<(&'static str, EffectiveHash)> {
    let mut paths = vec![("ipv4", HASH_POLICY_V4.to_string())];
    if has_ipv6 {
        paths.push((
            "ipv6",
            "/proc/sys/net/ipv6/fib_multipath_hash_policy".to_string(),
        ));
    }

    let mut applied = Vec::with_capacity(paths.len());
    for (label, path) in paths {
        let mut eff = EffectiveHash::default();

        if let Some(policy) = policy {
            let want = policy.sysctl_value().to_string();
            if read_sysctl_u8(&path) != Some(policy.sysctl_value()) {
                match std::fs::write(&path, format!("{want}\n")) {
                    Ok(()) => info!(
                        "Set multipath hash policy to '{}' ({path})",
                        policy.as_str()
                    ),
                    Err(e) => warn!(
                        "Failed to set multipath hash policy '{}' at {path}: {e} \
                         (kernel too old or /proc not writable?)",
                        policy.as_str()
                    ),
                }
            }
        }
        eff.policy = read_sysctl_u8(&path);

        let fields_path = path.replace("fib_multipath_hash_policy", "fib_multipath_hash_fields");
        let current_fields = read_sysctl_u32(&fields_path);
        eff.fields = current_fields;
        if let (Some(current), Some(policy)) = (current_fields, policy) {
            match hash_fields_action(policy, current) {
                HashFieldsAction::PolicyGoverns | HashFieldsAction::Covered => {}
                HashFieldsAction::Extend(want) => {
                    match std::fs::write(&fields_path, format!("{want}\n")) {
                        Ok(()) => {
                            info!(
                                "Extended fib_multipath_hash_fields {current} -> {} at \
                                 {fields_path} (requested '{}')",
                                hash_fields_desc(want),
                                policy.as_str()
                            );
                            eff.fields = Some(want);
                        }
                        Err(e) => warn!(
                            "Failed to extend fib_multipath_hash_fields to {want} at \
                             {fields_path}: {e}; the requested '{}' granularity may not be in \
                             effect",
                            policy.as_str()
                        ),
                    }
                }
                HashFieldsAction::CannotExpress => warn!(
                    "The '{}' hash policy is not bit-for-bit expressible by \
                     fib_multipath_hash_fields (currently {current}), and measured on Linux \
                     7.1.8 the policy is what actually selects the hash keys: \
                     non-encapsulated traffic in 'inner' mode behaves exactly like 'l3' \
                     (connections to the same destination IP stay on one WAN). Use 'l4' unless \
                     you really need the inner-header behaviour.",
                    policy.as_str()
                ),
            }
        }

        info!("Multipath hash in effect ({label}): {}", eff.describe());
        applied.push((label, eff));
    }
    applied
}

/// standard 下权重一变就重算整张 multipath hash（实测搬走 24%~39% 既有连线），却搬不动大流量。
fn dynamic_factors_allowed(config: &DaemonConfig, kernel_resilient: bool) -> bool {
    let wants_factors = config.weight_mode == WeightMode::Quality || config.load_aware;
    !wants_factors || config.allow_dynamic_weights_on_standard || kernel_resilient
}

/// 权重刻度：整数权重全是 1 时下修会被夹成 1，放大后比例不变（只是刻度变细）。
const DYNAMIC_WEIGHT_RESOLUTION: u32 = 4;

/// 取两方向最大值的利用率：全双工任一方吃满就该移走部分流量。
fn load_utilization(m: &WanMonitor) -> Option<f64> {
    let down = m.down_bps_capacity?;
    let up = m.up_bps_capacity.unwrap_or(down);
    if !(down.is_finite() && down > 0.0 && up.is_finite() && up > 0.0) {
        return None;
    }
    Some((m.rx_bps_ewma / down).max(m.tx_bps_ewma / up))
}

/// 迟滞：利用率 ≥ target 进入、≤ recover 退出；没有记忆位会在门槛附近每几秒跳一次权重。
fn update_load_pressure(
    monitors: &mut [WanMonitor],
    active: &[bool],
    target: f64,
    recover: f64,
) -> bool {
    let mut changed = false;
    for (slot, m) in monitors.iter_mut().enumerate() {
        if !active.get(slot).copied().unwrap_or(false) {
            continue;
        }
        let Some(util) = load_utilization(m) else {
            if m.load_pressure_active {
                m.load_pressure_active = false;
                changed = true;
            }
            continue;
        };
        let was = m.load_pressure_active;
        if m.load_pressure_active {
            if util <= recover {
                m.load_pressure_active = false;
            }
        } else if util >= target {
            m.load_pressure_active = true;
        }
        changed |= m.load_pressure_active != was;
    }
    changed
}

/// 平常受限速约束；压力翻转时允许插队，但仍受 min_spacing 约束。
fn weight_update_due(
    elapsed: Duration,
    interval: Duration,
    pressure_transition: bool,
    min_spacing: Duration,
) -> bool {
    elapsed >= interval || (pressure_transition && elapsed >= min_spacing)
}

/// 在 target 与 recover 之间线性内插：比 0/1 阶梯更容易收敛而不来回震荡。
fn load_factor(m: &WanMonitor, target: f64, recover: f64, min_ratio: f64) -> f64 {
    if !m.load_pressure_active {
        return 1.0;
    }
    let Some(util) = load_utilization(m) else {
        return 1.0;
    };
    let span = target - recover;
    let pressure = if span > 0.0 {
        ((util - recover) / span).clamp(0.0, 1.0)
    } else {
        1.0
    };
    1.0 - pressure * (1.0 - min_ratio)
}

fn quality_factor(m: &WanMonitor, best_rtt: f64, min_ratio: f64) -> f64 {
    let loss = if m.lqe.window_full() {
        m.lqe.loss_rate().clamp(0.0, 1.0)
    } else {
        0.0
    };
    let mut factor = 1.0 - loss;
    if let Some(rtt) = m.lqe.rtt_ewma_ms {
        if rtt.is_finite() && rtt > 0.0 && best_rtt.is_finite() && best_rtt > 0.0 {
            factor *= (best_rtt / rtt).clamp(min_ratio, 1.0);
        }
    }
    factor.clamp(min_ratio, 1.0)
}

/// 全线降级时取实测丢包最低的那条：按设定顺序挑会让剩下的线也一起被打烂。
fn pick_degrade_fallback(
    monitors: &[WanMonitor],
    is_candidate: impl Fn(usize, &WanMonitor) -> bool,
) -> Option<usize> {
    monitors
        .iter()
        .enumerate()
        .filter(|(slot, m)| is_candidate(*slot, m))
        .min_by(|(slot_a, a), (slot_b, b)| {
            a.lqe
                .loss_rate()
                .total_cmp(&b.lqe.loss_rate())
                .then_with(|| (a.metric, *slot_a).cmp(&(b.metric, *slot_b)))
        })
        .map(|(slot, _)| slot)
}

/// 基准权重：任何线设了 max_mbps 就按最大频宽比例（否则用 weight）；最终 = clamp(round(base × 刻度 × 因子), 1, 255)。
fn compute_dynamic_weights(
    monitors: &[WanMonitor],
    is_active: impl Fn(usize, &WanMonitor) -> bool,
    config: &DaemonConfig,
    allow_dynamic_factors: bool,
) -> Vec<u32> {
    let quality_on = config.weight_mode == WeightMode::Quality && allow_dynamic_factors;
    // 容量比例分流看监控物件是否带容量（loop 的启用判断才看 config，两者在 validate 下同步）。
    let bandwidth_on = monitors.iter().any(|m| m.down_bps_capacity.is_some());
    let min_ratio = config.dynamic_weight_min_ratio.clamp(0.05, 1.0);
    let active_flags: Vec<bool> = monitors
        .iter()
        .enumerate()
        .map(|(slot, m)| is_active(slot, m))
        .collect();
    let active_count = active_flags.iter().filter(|a| **a).count();
    let load_on = config.load_aware && active_count >= 2 && allow_dynamic_factors;

    let mut bases: Vec<f64> = monitors.iter().map(|m| m.weight.max(1) as f64).collect();
    if bandwidth_on {
        // 正规化取「所有线」而非当前承载线：分母随成员变动会让绝对权重白变一次并触发无意义重下。
        let min_cap = monitors
            .iter()
            .filter_map(|m| m.down_bps_capacity)
            .filter(|c| c.is_finite() && *c > 0.0)
            .fold(f64::INFINITY, f64::min);
        if min_cap.is_finite() && min_cap > 0.0 {
            for (slot, m) in monitors.iter().enumerate() {
                if !active_flags[slot] {
                    continue;
                }
                if let Some(cap) = m.down_bps_capacity.filter(|c| c.is_finite() && *c > 0.0) {
                    bases[slot] = m.weight.max(1) as f64 * (cap / min_cap);
                }
            }
        }
    }

    let any_pressure = load_on
        && monitors
            .iter()
            .enumerate()
            .any(|(slot, m)| active_flags[slot] && m.load_pressure_active);
    let scale = if quality_on || any_pressure {
        let active_bases: Vec<f64> = bases
            .iter()
            .enumerate()
            .filter(|(slot, _)| active_flags[*slot])
            .map(|(_, b)| *b)
            .collect();
        let min_base = active_bases.iter().copied().fold(f64::INFINITY, f64::min);
        let max_base = active_bases.iter().copied().fold(0.0_f64, f64::max);
        if min_base.is_finite() && min_base > 0.0 && max_base > 0.0 {
            let want = (DYNAMIC_WEIGHT_RESOLUTION as f64 / min_base).max(1.0);
            // 放大后会把最大权重推过上限就干脆不放大：宁可解析度粗，也不要让比例被 255 夹歪。
            if max_base * want <= config::MAX_WEIGHT as f64 {
                want
            } else {
                1.0
            }
        } else {
            1.0
        }
    } else {
        1.0
    };

    let best_rtt = monitors
        .iter()
        .enumerate()
        .filter(|(slot, _)| active_flags[*slot])
        .filter_map(|(_, m)| m.lqe.rtt_ewma_ms)
        .filter(|r| r.is_finite() && *r > 0.0)
        .fold(f64::INFINITY, f64::min);

    monitors
        .iter()
        .enumerate()
        .map(|(slot, m)| {
            if !active_flags[slot] {
                return m.weight;
            }
            let mut factor = 1.0;
            if quality_on {
                factor *= quality_factor(m, best_rtt, min_ratio);
            }
            if load_on {
                factor *= load_factor(
                    m,
                    config.load_target_ratio,
                    config.load_recover_ratio,
                    min_ratio,
                );
            }
            let w = bases[slot] * scale * factor;
            (w.round() as u32).clamp(1, config::MAX_WEIGHT)
        })
        .collect()
}

/// 目标 WAN 不健康时整条政策停用，让流量回退 ECMP 而不是黑洞在死线上。
fn build_policy_rules(config: &DaemonConfig, monitors: &[WanMonitor]) -> Vec<PolicyRule> {
    let mut rules = Vec::new();
    for (index, policy) in config.policies.iter().enumerate() {
        let Some(target) = monitors.iter().find(|m| m.ifname == policy.interface) else {
            continue;
        };
        if target.lqe.state != LinkState::Up || target.ifindex == 0 {
            continue;
        }
        let Some(slot) = config
            .interfaces
            .iter()
            .position(|i| i.name == policy.interface)
        else {
            continue;
        };
        let priority = policy
            .priority
            .unwrap_or(POLICY_RULE_PRIORITY_BASE + index as u32);
        let sources: Vec<Option<(std::net::Ipv4Addr, u8)>> = if policy.source.is_empty() {
            vec![None]
        } else {
            policy
                .source
                .iter()
                .map(|raw| config::parse_ipv4_prefix(raw).ok())
                .collect()
        };
        let destinations: Vec<Option<(std::net::Ipv4Addr, u8)>> = if policy.destination.is_empty() {
            vec![None]
        } else {
            policy
                .destination
                .iter()
                .map(|raw| config::parse_ipv4_prefix(raw).ok())
                .collect()
        };
        for source in &sources {
            for destination in &destinations {
                rules.push(PolicyRule {
                    name: policy.name.clone(),
                    ifindex: target.ifindex,
                    table: PROBE_TABLE_BASE + slot as u32,
                    priority,
                    source: *source,
                    destination: *destination,
                });
            }
        }
    }
    rules
}

/// EWMA 平滑系数（取样周期 = 探测周期）：滤掉单拍突发，又不会跟不上真实的流量转移。
const LOAD_EWMA_ALPHA: f64 = 0.3;

/// 来源是 /sys/class/net/<if>/statistics 的累计值，对转发流量正是该 WAN 的实际承载量。
fn sample_interface_rates(monitor: &mut WanMonitor, now: Instant) {
    let read = |kind: &str| -> Option<u64> {
        std::fs::read_to_string(format!(
            "/sys/class/net/{}/statistics/{kind}",
            monitor.ifname
        ))
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
    };
    let (Some(tx), Some(rx)) = (read("tx_bytes"), read("rx_bytes")) else {
        return;
    };
    if let (Some(prev_tx), Some(prev_rx), Some(prev_at)) = (
        monitor.last_tx_bytes,
        monitor.last_rx_bytes,
        monitor.last_stats_at,
    ) {
        let secs = now.duration_since(prev_at).as_secs_f64();
        if secs > 0.0 {
            // 介面重建时计数器可能归零：saturating_sub 让速率归零而不是暴冲。
            let d_tx = tx.saturating_sub(prev_tx);
            let d_rx = rx.saturating_sub(prev_rx);
            monitor.tx_bps = d_tx as f64 * 8.0 / secs;
            monitor.rx_bps = d_rx as f64 * 8.0 / secs;
            if monitor.load_ewma_ready {
                monitor.tx_bps_ewma += LOAD_EWMA_ALPHA * (monitor.tx_bps - monitor.tx_bps_ewma);
                monitor.rx_bps_ewma += LOAD_EWMA_ALPHA * (monitor.rx_bps - monitor.rx_bps_ewma);
            } else {
                monitor.tx_bps_ewma = monitor.tx_bps;
                monitor.rx_bps_ewma = monitor.rx_bps;
                monitor.load_ewma_ready = true;
            }
        }
    }
    monitor.last_tx_bytes = Some(tx);
    monitor.last_rx_bytes = Some(rx);
    monitor.last_stats_at = Some(now);
}

/// `all` 与装置取大者；strict 时回程必须走同一张网卡，非活跃线因此需要主表 /32。
fn effective_rp_filter(ifname: &str) -> u8 {
    let read = |path: String| -> u8 {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| s.trim().parse::<u8>().ok())
            .unwrap_or(0)
    };
    read("/proc/sys/net/ipv4/conf/all/rp_filter".to_string())
        .max(read(format!("/proc/sys/net/ipv4/conf/{ifname}/rp_filter")))
}

/// 主表同一目标只能有一个 /32 拥有者，必须挑真的能把路由装上的线；读不到时保守回传 true。
fn interface_oper_usable(ifname: &str) -> bool {
    match std::fs::read_to_string(format!("/sys/class/net/{ifname}/operstate")) {
        Ok(state) => {
            let state = state.trim();
            state != "down" && state != "lowerlayerdown"
        }
        Err(_) => true,
    }
}

/// 回传 None = 查不到（socket 不可用或查询失败），呼叫端要保守处理。
fn kernel_has_route(
    mgr: &mut Option<RouteManager>,
    target: std::net::Ipv4Addr,
    oif: Option<u32>,
) -> Option<bool> {
    let mgr = mgr.as_mut()?;
    match mgr.lookup_route(target, oif) {
        Ok(Some(_)) => Some(true),
        Ok(None) => Some(false),
        Err(e) => {
            debug!("route lookup for {target} (oif {oif:?}) failed: {e}");
            None
        }
    }
}

/// 刻意排除 `lo`：多数系统在 lo 上有一条 ::/0 的 null route，算进去会让提示永远不出现。
fn has_kernel_ipv6_default_route(table: &str) -> bool {
    table.lines().any(|line| {
        let mut fields = line.split_whitespace();
        let dest = fields.next().unwrap_or("");
        let plen = fields.next().unwrap_or("");
        let dev = fields.last().unwrap_or("");
        dest.len() == 32
            && dest.bytes().all(|b| b == b'0')
            && plen == "00"
            && !dev.is_empty()
            && dev != "lo"
    })
}

fn write_status_file(
    monitors: &[WanMonitor],
    active_routes: &str,
    config: &DaemonConfig,
    hash: EffectiveHash,
) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut iface_statuses = Vec::with_capacity(monitors.len());
    for m in monitors {
        iface_statuses.push(InterfaceStatus {
            name: m.ifname.clone(),
            state: m.lqe.state.to_string(),
            ip: m.cached_ip.map(|ip| ip.to_string()),
            gateway: m.gateway.map_or_else(|| "-".to_string(), |g| g.to_string()),
            metric: m.metric,
            weight: m.weight,
            effective_weight: m.effective_weight,
            tx_bps: (m.tx_bps * 100.0).round() / 100.0,
            rx_bps: (m.rx_bps * 100.0).round() / 100.0,
            load_pct: load_utilization(m).map(|u| (u * 10000.0).round() / 100.0),
            load_shifted: m.load_pressure_active,
            rtt_ms: (m.lqe.rtt_ewma_ms.unwrap_or(0.0) * 100.0).round() / 100.0,
            jitter_ms: (m.lqe.jitter_ewma_ms * 100.0).round() / 100.0,
            loss_rate: (m.lqe.loss_rate() * 10000.0).round() / 100.0,
            consecutive_successes: m.lqe.consecutive_successes,
            consecutive_timeouts: m.lqe.consecutive_timeouts,
            targets: m.targets.iter().map(|t| t.to_string()).collect(),
            ifindex: m.ifindex,
            last_error: m.last_probe_error.clone(),
            local_condition: m.last_error_is_local || m.probe_path_missing,
            degraded: m.lqe.is_degraded(),
            samples_in_window: m.lqe.window_len(),
            window_full: m.lqe.window_full(),
            state_reason: m.lqe.state_reason().map(|r| r.as_str().to_string()),
        });
    }

    let policy_rules = build_policy_rules(config, monitors);
    let policies: Vec<PolicyStatus> = config
        .policies
        .iter()
        .enumerate()
        .map(|(index, policy)| {
            let priority = policy
                .priority
                .unwrap_or(POLICY_RULE_PRIORITY_BASE + index as u32);
            PolicyStatus {
                name: policy.name.clone(),
                interface: policy.interface.clone(),
                priority,
                active: policy_rules.iter().any(|r| r.priority == priority),
                source: policy.source.clone(),
                destination: policy.destination.clone(),
            }
        })
        .collect();

    let status = DaemonStatus {
        updated_at: now,
        stale_after_secs: STATUS_STALE_SECS,
        active_routes: active_routes.to_string(),
        interfaces: iface_statuses,
        policies,
        hash: HashStatus {
            policy: hash.policy,
            fields: hash.fields,
            fields_desc: hash
                .fields
                .map(hash_fields_desc)
                .unwrap_or_else(|| "n/a".to_string()),
            l3_only: hash.l3_only(),
        },
    };

    if let Ok(json) = serde_json::to_string(&status) {
        if let Err(e) = write_status_atomic(&json) {
            debug!("failed to update status file: {e}");
        }
    }
}

/// 原子且防符号连结：/tmp 可写者能预算符号连结让 root 覆写任意档案，故用 create_new + rename。
fn write_status_atomic(json: &str) -> io::Result<()> {
    use std::io::Write;
    let _ = std::fs::remove_file(STATUS_TMP_FILE);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(STATUS_TMP_FILE)?;
    file.write_all(json.as_bytes())?;
    drop(file);
    std::fs::rename(STATUS_TMP_FILE, STATUS_FILE)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::field_reassign_with_default)]

    use super::*;

    #[test]
    fn test_hash_fields_action_matches_kernel_semantics() {
        use MultipathHashPolicy::{Inner, L3, L4};

        assert_eq!(hash_fields_action(L3, 0), HashFieldsAction::PolicyGoverns);
        assert_eq!(hash_fields_action(L4, 0), HashFieldsAction::PolicyGoverns);

        assert_eq!(hash_fields_action(L4, 7), HashFieldsAction::Extend(31));
        assert_eq!(hash_fields_action(L4, 31), HashFieldsAction::Covered);
        assert_eq!(hash_fields_action(L4, 63), HashFieldsAction::Covered);
        assert_eq!(hash_fields_action(L4, 8), HashFieldsAction::Extend(31));
        assert_eq!(hash_fields_action(L3, 7), HashFieldsAction::Covered);
        assert_eq!(hash_fields_action(L3, 31), HashFieldsAction::Covered);
        assert_eq!(hash_fields_action(L3, 2), HashFieldsAction::Extend(7));
        assert_eq!(
            hash_fields_action(Inner, 7),
            HashFieldsAction::CannotExpress
        );
        assert_eq!(
            hash_fields_action(Inner, 0),
            HashFieldsAction::CannotExpress
        );
    }

    #[test]
    fn test_hash_fields_desc_renders_names() {
        assert_eq!(hash_fields_desc(0), "none");
        assert_eq!(hash_fields_desc(7), "7 (src_ip+dst_ip+ip_proto)");
        assert_eq!(
            hash_fields_desc(HASH_FIELDS_L4),
            "31 (src_ip+dst_ip+ip_proto+src_port+dst_port)"
        );
        assert_eq!(
            hash_fields_desc(
                HASH_FIELDS_L4 | HashField::InnerSrcPort.bit() | HashField::InnerDstPort.bit()
            ),
            "1567 (src_ip+dst_ip+ip_proto+src_port+dst_port+inner_src_port+inner_dst_port)"
        );
        assert_eq!(
            hash_fields_desc(HashField::FlowLabel.bit()),
            "256 (flow_label)"
        );
        assert_eq!(hash_fields_desc(1 << 20), "1048576 ((unknown bits))");
    }

    #[test]
    fn test_effective_hash_l3_only_semantics() {
        assert!(
            EffectiveHash {
                policy: Some(0),
                fields: Some(7),
            }
            .l3_only()
        );
        assert!(
            EffectiveHash {
                policy: Some(0),
                fields: Some(31),
            }
            .l3_only()
        );
        assert!(
            !EffectiveHash {
                policy: Some(1),
                fields: Some(31),
            }
            .l3_only()
        );
        assert!(
            EffectiveHash {
                policy: Some(2),
                fields: Some(224),
            }
            .l3_only()
        );
        assert!(EffectiveHash::default().l3_only());
        assert!(
            EffectiveHash {
                policy: None,
                fields: Some(31)
            }
            .l3_only()
        );
        assert!(
            !EffectiveHash {
                policy: Some(1),
                fields: None
            }
            .l3_only()
        );
        assert!(
            EffectiveHash {
                policy: Some(0),
                fields: None
            }
            .l3_only()
        );
    }

    #[test]
    fn test_hash_policy_drift_detection() {
        use MultipathHashPolicy::{Inner, L3, L4};
        assert!(hash_policy_matches(None, None));
        assert!(hash_policy_matches(None, Some(0)));
        assert!(hash_policy_matches(None, Some(1)));

        assert!(hash_policy_matches(Some(L4), Some(1)));
        assert!(hash_policy_matches(Some(L3), Some(0)));
        assert!(hash_policy_matches(Some(Inner), Some(2)));

        assert!(!hash_policy_matches(Some(L4), Some(0)));
        assert!(!hash_policy_matches(Some(L4), Some(2)));
        assert!(!hash_policy_matches(Some(L3), Some(1)));
        assert!(hash_policy_matches(Some(L4), None));
    }

    /// 真实核心：哈希粒度漂移的检测与自我修复（需要 netns；未设 `MWAN4_NETNS_TEST=1` 时跳过）。
    #[test]
    #[ignore]
    fn netns_hash_policy_drift_repair() {
        let requested = std::env::var("MWAN4_NETNS_TEST").as_deref() == Ok("1");
        let isolated = std::fs::read_link("/proc/self/ns/net")
            .ok()
            .zip(std::fs::read_link("/proc/1/ns/net").ok())
            .is_some_and(|(current, init)| current != init);
        if !requested || !isolated {
            eprintln!("skip: tests require MWAN4_NETNS_TEST=1 AND isolated network namespace");
            return;
        }
        let original = read_effective_hash_v4();

        apply_multipath_hash(Some(MultipathHashPolicy::L4), false);
        let applied = read_effective_hash_v4();
        assert_eq!(
            applied.policy,
            Some(1),
            "apply_multipath_hash 应把 policy 写成 1"
        );
        assert!(hash_policy_matches(
            Some(MultipathHashPolicy::L4),
            applied.policy
        ));

        std::fs::write(HASH_POLICY_V4, "0\n").expect("simulate drift");
        let drifted = read_effective_hash_v4();
        assert_eq!(drifted.policy, Some(0));
        assert!(
            !hash_policy_matches(Some(MultipathHashPolicy::L4), drifted.policy),
            "读回值变成 L3 时必须判定为漂移"
        );

        apply_multipath_hash(Some(MultipathHashPolicy::L4), false);
        assert_eq!(
            read_effective_hash_v4().policy,
            Some(1),
            "自我修复后应回到 l4"
        );

        std::fs::write(HASH_POLICY_V4, "0\n").expect("simulate drift");
        apply_multipath_hash(None, false);
        assert_eq!(
            read_effective_hash_v4().policy,
            Some(0),
            "multipath_hash_policy = null 时必须完全不碰内核"
        );

        if let Some(p) = original.policy {
            let _ = std::fs::write(HASH_POLICY_V4, format!("{p}\n"));
        }
    }

    #[test]
    fn test_has_kernel_ipv6_default_route_ignores_lo_reject_route() {
        let lo_only = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 \
                       00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo\n";
        assert!(!has_kernel_ipv6_default_route(lo_only));
        let real = format!(
            "00000000000000000000000000000000 00 00000000000000000000000000000000 00 \
             00000000000000000000000000000000 00000400 00000001 00000000 00000001   wan1\n{lo_only}"
        );
        assert!(has_kernel_ipv6_default_route(&real));
        let other = "fe800000000000000000000000000000 40 00000000000000000000000000000000 00 \
                     00000000000000000000000000000000 00000400 00000001 00000000 00000001 eth0\n";
        assert!(!has_kernel_ipv6_default_route(other));
        assert!(!has_kernel_ipv6_default_route(""));
    }

    fn monitor(name: &str, last_flush: Option<Instant>) -> WanMonitor {
        WanMonitor {
            ifname: name.to_string(),
            ifindex: 1,
            gateway: None,
            gateway6: None,
            metric: 10,
            weight: 1,
            effective_weight: 1,
            last_tx_bytes: None,
            last_rx_bytes: None,
            last_stats_at: None,
            tx_bps: 0.0,
            rx_bps: 0.0,
            tx_bps_ewma: 0.0,
            rx_bps_ewma: 0.0,
            load_ewma_ready: false,
            load_pressure_active: false,
            down_bps_capacity: None,
            up_bps_capacity: None,
            targets: Vec::new(),
            preferred_target: 0,
            underlay_targets: Vec::new(),
            cached_ip: None,
            last_known_ip: None,
            last_conntrack_flush: last_flush,
            last_probe_error: None,
            last_error_is_local: false,
            local_condition_warned: false,
            probe_path_missing: false,
            last_path_check: None,
            down_since: None,
            last_down_at: None,
            flushed_while_down: false,
            lqe: LinkQualityEstimator::new(name.to_string(), &DaemonConfig::default()),
        }
    }

    fn feed(lqe: &mut LinkQualityEstimator, results: &[bool]) {
        for &ok in results {
            lqe.update(&prober::ProbeSample {
                success: ok,
                rtt: Duration::from_millis(if ok { 20 } else { 500 }),
                target: "223.5.5.5:53".parse().unwrap(),
                error_msg: if ok { None } else { Some("Timeout".into()) },
                error_kind: if ok {
                    None
                } else {
                    Some(prober::ProbeErrorKind::Timeout)
                },
            });
        }
    }

    fn flushed_names(rx: &std::sync::mpsc::Receiver<NetlinkCmd>) -> Vec<String> {
        match rx.try_recv() {
            Ok(NetlinkCmd::FlushConntrack(targets)) => {
                targets.into_iter().map(|(name, _)| name).collect()
            }
            Ok(_) => panic!("应送出 FlushConntrack，实际送出了其他指令"),
            Err(err) => panic!("应送出 FlushConntrack，实际没有送出指令：{err}"),
        }
    }

    /// FIX-7 回归：被最小间隔限流跳过的 flush-on-down 候选不得被标记成「本次 DOWN 已清过」。
    #[test]
    fn test_flush_on_down_marker_is_set_only_after_enqueue() {
        let now = Instant::now();
        let min_interval = Duration::from_secs(10);
        let (tx, rx) = std::sync::mpsc::sync_channel::<NetlinkCmd>(4);
        let mut monitors = vec![monitor("wan1", Some(now - Duration::from_secs(1)))];

        flush_conntrack(&mut monitors, vec![(0, true)], &tx, now, min_interval);
        assert!(
            rx.try_recv().is_err(),
            "最小间隔内不该送出任何 conntrack 清理指令"
        );
        assert!(
            !monitors[0].flushed_while_down,
            "被限流跳过的线若先被标记，整段 DOWN 期间都不会再重试"
        );
        assert_eq!(
            monitors[0].last_conntrack_flush,
            Some(now - Duration::from_secs(1)),
            "被跳过时不该更新清理时间戳"
        );

        let later = now + Duration::from_secs(11);
        flush_conntrack(&mut monitors, vec![(0, true)], &tx, later, min_interval);
        assert_eq!(flushed_names(&rx), vec!["wan1".to_string()]);
        assert!(monitors[0].flushed_while_down);
        assert_eq!(monitors[0].last_conntrack_flush, Some(later));
    }

    #[test]
    fn test_flush_on_switch_does_not_mark_down_flush() {
        let now = Instant::now();
        let (tx, rx) = std::sync::mpsc::sync_channel::<NetlinkCmd>(4);
        let mut monitors = vec![monitor("wan1", None), monitor("wan0", None)];

        flush_conntrack(
            &mut monitors,
            vec![(0, false), (1, false), (0, true)],
            &tx,
            now,
            Duration::from_secs(10),
        );

        assert_eq!(
            flushed_names(&rx),
            vec!["wan1".to_string(), "wan0".to_string()],
            "同一张网卡只能出现一次，且顺序依第一次出现的下标"
        );
        assert!(
            monitors[0].flushed_while_down,
            "wan1 也来自 flush-on-down，来源旗标应合并"
        );
        assert!(
            !monitors[1].flushed_while_down,
            "flush-on-switch 不得把线路标成『DOWN 期间已清』"
        );
    }

    #[test]
    fn test_compute_quality_weights_rtt_and_loss() {
        let mut cfg = DaemonConfig::default();
        cfg.weight_mode = WeightMode::Quality;
        cfg.dynamic_weight_min_ratio = 0.25;
        let mut a = monitor("wan1", None);
        let mut b = monitor("wan2", None);
        let mut c = monitor("wan3", None);
        a.weight = 4;
        b.weight = 4;
        c.weight = 4;
        a.lqe.rtt_ewma_ms = Some(100.0);
        b.lqe.rtt_ewma_ms = Some(400.0);
        c.lqe.rtt_ewma_ms = None; // 没有 RTT 样本 → 不惩罚
        let monitors = vec![a, b, c];
        let weights = compute_dynamic_weights(&monitors, |_, _| true, &cfg, true);
        assert_eq!(weights[0], 4, "最佳 RTT 维持原权重");
        assert_eq!(weights[1], 1, "RTT 4 倍差 → 下修到 min_ratio（4*0.25=1）");
        assert_eq!(weights[2], 4, "没有 RTT 样本不该被惩罚");

        let weights = compute_dynamic_weights(&monitors, |slot, _| slot == 0, &cfg, true);
        assert_eq!(weights[1], 4);
        assert_eq!(weights[2], 4);
    }

    #[test]
    fn test_compute_load_weights_shifts_traffic_to_idle_line() {
        let mut cfg = DaemonConfig::default();
        cfg.load_aware = true;
        cfg.load_target_ratio = 0.80;
        cfg.load_recover_ratio = 0.60;
        cfg.dynamic_weight_min_ratio = 0.25;

        let mut busy = monitor("wan1", None);
        let mut idle = monitor("wan2", None);
        for m in [&mut busy, &mut idle] {
            m.down_bps_capacity = Some(100_000_000.0);
            m.up_bps_capacity = Some(100_000_000.0);
        }
        busy.rx_bps_ewma = 95_000_000.0;
        idle.rx_bps_ewma = 5_000_000.0;
        let mut monitors = vec![busy, idle];
        let active = [true, true];

        update_load_pressure(
            &mut monitors,
            &active,
            cfg.load_target_ratio,
            cfg.load_recover_ratio,
        );
        assert!(monitors[0].load_pressure_active, "95% 应触发过载下修");
        assert!(!monitors[1].load_pressure_active, "5% 不该触发");

        let weights = compute_dynamic_weights(&monitors, |s, _| active[s], &cfg, true);
        assert_eq!(weights, vec![1, 4], "过载线应被下修、空闲线放大来接流量");

        monitors[0].rx_bps_ewma = 70_000_000.0;
        update_load_pressure(
            &mut monitors,
            &active,
            cfg.load_target_ratio,
            cfg.load_recover_ratio,
        );
        assert!(
            monitors[0].load_pressure_active,
            "落在 recover 与 target 之间应保持下修"
        );

        monitors[0].rx_bps_ewma = 10_000_000.0;
        update_load_pressure(
            &mut monitors,
            &active,
            cfg.load_target_ratio,
            cfg.load_recover_ratio,
        );
        assert!(!monitors[0].load_pressure_active);
        let weights = compute_dynamic_weights(&monitors, |s, _| active[s], &cfg, true);
        assert_eq!(weights, vec![1, 1], "压力解除后回到设定权重");

        let mut a = monitor("wan1", None);
        let mut b = monitor("wan2", None);
        for m in [&mut a, &mut b] {
            m.down_bps_capacity = Some(100_000_000.0);
            m.rx_bps_ewma = 90_000_000.0;
        }
        let mut both = vec![a, b];
        update_load_pressure(
            &mut both,
            &active,
            cfg.load_target_ratio,
            cfg.load_recover_ratio,
        );
        let weights = compute_dynamic_weights(&both, |s, _| active[s], &cfg, true);
        assert_eq!(weights, vec![1, 1], "全线过载时维持原比例");

        let only = vec![monitor("wan1", None)];
        let weights = compute_dynamic_weights(&only, |_, _| true, &cfg, true);
        assert_eq!(weights, vec![1]);
    }

    #[test]
    fn test_compute_bandwidth_proportional_weights() {
        let cfg = DaemonConfig::default();

        let mut a = monitor("wan1", None);
        let mut b = monitor("wan2", None);
        a.down_bps_capacity = Some(1_000_000_000.0);
        b.down_bps_capacity = Some(200_000_000.0);
        let weights = compute_dynamic_weights(&[a, b], |_, _| true, &cfg, true);
        assert_eq!(weights, vec![5, 1], "权重比应等于最大频宽比 1000:200");

        let mut a = monitor("wan1", None);
        let mut b = monitor("wan2", None);
        a.down_bps_capacity = Some(1_000_000_000.0);
        b.down_bps_capacity = Some(10_000_000.0);
        let weights = compute_dynamic_weights(&[a, b], |_, _| true, &cfg, true);
        assert_eq!(weights, vec![100, 1]);

        let mut a = monitor("wan1", None);
        let mut b = monitor("wan2", None);
        a.down_bps_capacity = Some(1_000_000_000.0);
        b.down_bps_capacity = Some(1_000_000.0);
        let weights = compute_dynamic_weights(&[a, b], |_, _| true, &cfg, true);
        assert_eq!(weights, vec![config::MAX_WEIGHT, 1], "超过 255:1 应夹住");

        let mut a = monitor("wan1", None);
        let mut b = monitor("wan2", None);
        a.weight = 2;
        a.down_bps_capacity = Some(1_000_000_000.0);
        b.down_bps_capacity = Some(500_000_000.0);
        let weights = compute_dynamic_weights(&[a, b], |_, _| true, &cfg, true);
        assert_eq!(weights, vec![4, 1]);

        let cfg2 = DaemonConfig::default();
        assert!(!cfg2.capacity_weights_on());
        let weights = compute_dynamic_weights(
            &[monitor("wan1", None), monitor("wan2", None)],
            |_, _| true,
            &cfg2,
            true,
        );
        assert_eq!(weights, vec![1, 1]);
    }

    /// 品质模式在预设 `weight = 1` 时也必须真的改变权重（旧版会被夹成 1，功能整个空转）。
    #[test]
    fn test_quality_mode_is_effective_at_default_weight() {
        let mut cfg = DaemonConfig::default();
        cfg.weight_mode = WeightMode::Quality;
        cfg.dynamic_weight_min_ratio = 0.25;

        let mut good = monitor("wan1", None);
        let mut bad = monitor("wan2", None);
        assert_eq!(good.weight, 1, "预设 weight 必须是 1，否则测不到旧版的空转");
        feed(&mut good.lqe, &[true; 10]);
        feed(&mut bad.lqe, &[true; 10]);
        good.lqe.rtt_ewma_ms = Some(20.0);
        bad.lqe.rtt_ewma_ms = Some(200.0);

        let monitors = vec![good, bad];
        let weights = compute_dynamic_weights(&monitors, |_, _| true, &cfg, true);
        assert_eq!(
            weights,
            vec![4, 1],
            "刻度放大到 4 后，RTT 差 10 倍（夹在 min_ratio 0.25）应真的分到 4:1"
        );
    }

    #[test]
    fn test_capacity_weights_stable_when_member_leaves() {
        let cfg = DaemonConfig::default();
        let mk = |name: &str, mbps: f64| {
            let mut m = monitor(name, None);
            m.down_bps_capacity = Some(mbps * 1_000_000.0);
            m
        };
        let full = compute_dynamic_weights(
            &[mk("wan1", 1000.0), mk("wan2", 100.0), mk("wan3", 10.0)],
            |_, _| true,
            &cfg,
            true,
        );
        assert_eq!(full, vec![100, 10, 1]);

        let partial = compute_dynamic_weights(
            &[mk("wan1", 1000.0), mk("wan2", 100.0), mk("wan3", 10.0)],
            |slot, _| slot != 2,
            &cfg,
            true,
        );
        assert_eq!(
            &partial[..2],
            &full[..2],
            "容量最小的线退出后，存活线的权重必须不变（比例本来就没变）"
        );
    }

    #[test]
    fn test_degrade_fallback_prefers_lowest_loss() {
        let mut worse = monitor("wan1", None);
        let mut better = monitor("wan2", None);
        feed(
            &mut worse.lqe,
            &[
                true, true, false, false, false, false, false, true, true, true,
            ],
        );
        feed(
            &mut better.lqe,
            &[true, true, true, true, true, true, true, true, true, false],
        );
        let monitors = vec![worse, better];
        assert_eq!(
            pick_degrade_fallback(&monitors, |_, _| true),
            Some(1),
            "应保留丢包最低的线（10% 胜过 50%）"
        );

        let flat = vec![monitor("wan1", None), monitor("wan2", None)];
        assert_eq!(pick_degrade_fallback(&flat, |_, _| true), Some(0));
        assert_eq!(pick_degrade_fallback(&flat, |_, _| false), None);
    }

    #[test]
    fn test_dynamic_factors_gate_requires_resilient_or_opt_in() {
        let cfg = DaemonConfig::default();
        assert!(dynamic_factors_allowed(&cfg, false));
        assert!(dynamic_factors_allowed(&cfg, true));

        let mut quality = DaemonConfig::default();
        quality.weight_mode = WeightMode::Quality;
        assert!(!dynamic_factors_allowed(&quality, false));

        let mut load = DaemonConfig::default();
        load.load_aware = true;
        assert!(!dynamic_factors_allowed(&load, false));

        assert!(dynamic_factors_allowed(&quality, true));
        assert!(dynamic_factors_allowed(&load, true));

        let mut override_cfg = DaemonConfig::default();
        override_cfg.load_aware = true;
        override_cfg.allow_dynamic_weights_on_standard = true;
        assert!(dynamic_factors_allowed(&override_cfg, false));
    }

    #[test]
    fn test_bandwidth_baseline_plus_load_offload() {
        let mut cfg = DaemonConfig::default();
        cfg.load_aware = true;
        cfg.load_target_ratio = 0.80;
        cfg.load_recover_ratio = 0.60;
        cfg.dynamic_weight_min_ratio = 0.25;

        let mut busy = monitor("wan1", None);
        let mut idle = monitor("wan2", None);
        busy.down_bps_capacity = Some(1_000_000_000.0);
        busy.up_bps_capacity = Some(1_000_000_000.0);
        idle.down_bps_capacity = Some(200_000_000.0);
        idle.up_bps_capacity = Some(200_000_000.0);
        busy.rx_bps_ewma = 950_000_000.0;
        idle.rx_bps_ewma = 10_000_000.0;
        let mut monitors = vec![busy, idle];
        let active = [true, true];
        update_load_pressure(
            &mut monitors,
            &active,
            cfg.load_target_ratio,
            cfg.load_recover_ratio,
        );
        assert!(monitors[0].load_pressure_active);

        let weights = compute_dynamic_weights(&monitors, |s, _| active[s], &cfg, true);
        assert_eq!(weights, vec![5, 4], "过载线在容量基准上被进一步下修");
    }

    #[test]
    fn test_load_pressure_requires_capacity() {
        let mut m = monitor("wan1", None);
        m.rx_bps_ewma = 999_000_000.0;
        assert_eq!(load_utilization(&m), None);
        let mut monitors = vec![m];
        update_load_pressure(&mut monitors, &[true], 0.8, 0.6);
        assert!(!monitors[0].load_pressure_active, "没有容量就不判定过载");
    }

    #[test]
    fn test_load_pressure_reports_transitions_only() {
        let mut busy = monitor("wan1", None);
        let mut calm = monitor("wan2", None);
        busy.down_bps_capacity = Some(100_000_000.0);
        busy.up_bps_capacity = Some(100_000_000.0);
        calm.down_bps_capacity = Some(100_000_000.0);
        calm.up_bps_capacity = Some(100_000_000.0);
        busy.rx_bps_ewma = 90_000_000.0; // 90% → 过载
        calm.rx_bps_ewma = 10_000_000.0; // 10%
        let mut monitors = vec![busy, calm];
        let active = [true, true];

        assert!(update_load_pressure(&mut monitors, &active, 0.8, 0.6));
        assert!(monitors[0].load_pressure_active);
        monitors[0].rx_bps_ewma = 70_000_000.0;
        assert!(!update_load_pressure(&mut monitors, &active, 0.8, 0.6));
        assert!(monitors[0].load_pressure_active, "迟滞死区内维持原状态");
        monitors[0].rx_bps_ewma = 50_000_000.0;
        assert!(update_load_pressure(&mut monitors, &active, 0.8, 0.6));
        assert!(!monitors[0].load_pressure_active);

        monitors[0].rx_bps_ewma = 99_000_000.0;
        assert!(!update_load_pressure(
            &mut monitors,
            &[false, true],
            0.8,
            0.6
        ));

        monitors[0].down_bps_capacity = None;
        monitors[0].load_pressure_active = true;
        assert!(update_load_pressure(&mut monitors, &active, 0.8, 0.6));
        assert!(!monitors[0].load_pressure_active);
    }

    #[test]
    fn test_weight_update_due_rate_limit_and_transition_bypass() {
        let interval = Duration::from_secs(10);
        let floor = Duration::from_millis(1000);

        assert!(!weight_update_due(
            Duration::from_millis(500),
            interval,
            false,
            floor
        ));
        assert!(weight_update_due(
            Duration::from_millis(1000),
            interval,
            true,
            floor
        ));
        assert!(!weight_update_due(
            Duration::from_millis(999),
            interval,
            true,
            floor
        ));
        assert!(weight_update_due(interval, interval, false, floor));
        assert!(weight_update_due(
            Duration::from_secs(30),
            interval,
            false,
            floor
        ));
    }

    #[test]
    fn test_build_policy_rules_expands_and_skips_dead_target() {
        let mut cfg = DaemonConfig::default();
        cfg.interfaces[0].name = "wan1".to_string();
        cfg.interfaces[1].name = "wan2".to_string();
        cfg.policies = vec![
            config::PolicyConfig {
                name: "guest".to_string(),
                source: vec!["192.168.3.0/24".to_string(), "192.168.4.0/24".to_string()],
                destination: vec!["10.0.0.0/8".to_string()],
                interface: "wan2".to_string(),
                priority: None,
                extra: Default::default(),
            },
            config::PolicyConfig {
                name: "dead".to_string(),
                source: vec![],
                destination: vec![],
                interface: "wan1".to_string(),
                priority: None,
                extra: Default::default(),
            },
        ];

        let mut up = monitor("wan2", None);
        up.lqe.state = LinkState::Up;
        up.ifindex = 22;
        let mut down = monitor("wan1", None);
        down.lqe.state = LinkState::Down;
        down.ifindex = 11;
        let monitors = vec![down, up];

        let rules = build_policy_rules(&cfg, &monitors);
        assert_eq!(rules.len(), 2, "2 个来源 × 1 个目的，且 Down 的政策被跳过");
        for rule in &rules {
            assert_eq!(rule.name, "guest");
            assert_eq!(rule.ifindex, 22);
            assert_eq!(rule.table, PROBE_TABLE_BASE + 1, "用目标 WAN 的独立表");
            assert_eq!(rule.priority, POLICY_RULE_PRIORITY_BASE, "预设依政策顺序");
            assert_eq!(rule.destination, Some(("10.0.0.0".parse().unwrap(), 8)));
        }
        let sources: Vec<_> = rules.iter().filter_map(|r| r.source).collect();
        assert!(sources.contains(&("192.168.3.0".parse().unwrap(), 24)));
        assert!(sources.contains(&("192.168.4.0".parse().unwrap(), 24)));

        let mut up_dead = monitor("wan1", None);
        up_dead.lqe.state = LinkState::Up;
        up_dead.ifindex = 11;
        let mut up_guest = monitor("wan2", None);
        up_guest.lqe.state = LinkState::Up;
        up_guest.ifindex = 22;
        let monitors = vec![up_dead, up_guest];
        let rules = build_policy_rules(&cfg, &monitors);
        assert_eq!(rules.len(), 3);
        let wildcard = rules.iter().find(|r| r.name == "dead").unwrap();
        assert_eq!(wildcard.source, None);
        assert_eq!(wildcard.destination, None);
    }
}
