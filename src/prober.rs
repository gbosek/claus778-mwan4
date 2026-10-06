use log::debug;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// 探针失败分类。比对 errno 而非错误字串：glibc 与 musl 的 strerror 文案不同，字串比对在目标平台会整批失效。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeErrorKind {
    Local,
    Timeout,
    Other,
}

#[cfg(target_os = "linux")]
fn classify_io_error(err: &io::Error) -> ProbeErrorKind {
    match err.raw_os_error() {
        // EHOSTUNREACH 不算本机：也可能是上游回的 ICMP host-unreachable（封包确实出去了）。
        Some(libc::ENETUNREACH)
        | Some(libc::ENODEV)
        | Some(libc::EADDRNOTAVAIL)
        | Some(libc::EACCES)
        | Some(libc::EPERM)
        | Some(libc::ENETDOWN)
        | Some(libc::EAFNOSUPPORT)
        | Some(libc::EINVAL) => ProbeErrorKind::Local,
        _ => ProbeErrorKind::Other,
    }
}

#[cfg(not(target_os = "linux"))]
fn classify_io_error(_err: &io::Error) -> ProbeErrorKind {
    ProbeErrorKind::Other
}

#[derive(Debug, Clone)]
pub struct ProbeSample {
    pub success: bool,
    pub rtt: Duration,
    pub target: SocketAddr,
    pub error_msg: Option<String>,
    /// 失败分类（成功时为 None）；状态档与告警据此判断，不去猜 error_msg 文案。
    pub error_kind: Option<ProbeErrorKind>,
}

/// 建立绑定到特定网卡的非阻塞 TCP 套接字。
///
/// 依目标地址选 AF_INET/AF_INET6（固定 AF_INET 会让 IPv6 目标 EINVAL）。
/// SO_LINGER(0) 以 RST 收尾，不留 TIME_WAIT；但无法避免 conntrack（SYN 一送出条目即建立）。
fn create_bound_tcp_socket(iface: &str, target: &SocketAddr) -> io::Result<socket2::Socket> {
    let domain = if target.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };

    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;

    socket.set_nonblocking(true)?;

    if let Err(e) = socket.set_linger(Some(Duration::ZERO)) {
        debug!("[probe] set SO_LINGER(0) failed: {e}");
    }

    #[cfg(target_os = "linux")]
    {
        socket.bind_device(Some(iface.as_bytes()))?;
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = iface;
    }

    Ok(socket)
}

pub async fn probe_single_target(
    iface: &str,
    target: SocketAddr,
    timeout: Duration,
) -> ProbeSample {
    let start = Instant::now();

    let socket = match create_bound_tcp_socket(iface, &target) {
        Ok(s) => s,
        Err(e) => {
            return ProbeSample {
                success: false,
                rtt: timeout,
                target,
                error_msg: Some(format!("Create socket failed: {e}")),
                error_kind: Some(ProbeErrorKind::Local),
            };
        }
    };

    match socket.connect(&target.into()) {
        Ok(()) => {
            let rtt = start.elapsed();
            ProbeSample {
                success: true,
                rtt,
                target,
                error_msg: None,
                error_kind: None,
            }
        }
        Err(e) => {
            let raw_err = e.raw_os_error();
            // EINPROGRESS = 非阻塞 SYN 已发出（Linux 115）。
            let in_progress =
                raw_err == Some(libc::EINPROGRESS) || e.kind() == io::ErrorKind::WouldBlock;

            if !in_progress {
                return ProbeSample {
                    success: false,
                    rtt: start.elapsed(),
                    target,
                    error_msg: Some(format!("Connect immediate error: {e}")),
                    error_kind: Some(classify_io_error(&e)),
                };
            }

            let std_stream: std::net::TcpStream = socket.into();
            let tokio_stream = match tokio::net::TcpStream::from_std(std_stream) {
                Ok(s) => s,
                Err(e) => {
                    return ProbeSample {
                        success: false,
                        rtt: start.elapsed(),
                        target,
                        error_msg: Some(format!("Tokio from_std failed: {e}")),
                        error_kind: Some(ProbeErrorKind::Local),
                    };
                }
            };

            match tokio::time::timeout(timeout, tokio_stream.writable()).await {
                Ok(Ok(())) => {
                    let elapsed = start.elapsed();
                    match tokio_stream.take_error() {
                        Ok(None) => ProbeSample {
                            success: true,
                            rtt: elapsed,
                            target,
                            error_msg: None,
                            error_kind: None,
                        },
                        Ok(Some(err)) => {
                            // RST (ECONNREFUSED) 也代表封包往返成功，链路正常。
                            if err.raw_os_error() == Some(libc::ECONNREFUSED) {
                                ProbeSample {
                                    success: true,
                                    rtt: elapsed,
                                    target,
                                    error_msg: None,
                                    error_kind: None,
                                }
                            } else {
                                ProbeSample {
                                    success: false,
                                    rtt: elapsed,
                                    target,
                                    error_msg: Some(format!("Socket error: {err}")),
                                    error_kind: Some(classify_io_error(&err)),
                                }
                            }
                        }
                        Err(err) => ProbeSample {
                            success: false,
                            rtt: elapsed,
                            error_msg: Some(format!("take_error failed: {err}")),
                            error_kind: Some(ProbeErrorKind::Local),
                            target,
                        },
                    }
                }
                Ok(Err(e)) => ProbeSample {
                    success: false,
                    rtt: start.elapsed(),
                    target,
                    error_msg: Some(format!("Poll writable error: {e}")),
                    error_kind: Some(classify_io_error(&e)),
                },
                Err(_) => {
                    // 超时不等于丢包：上游黑洞 / 缺路由 / 对端不回 SYN-ACK 表象相同。
                    ProbeSample {
                        success: false,
                        rtt: timeout,
                        target,
                        error_msg: Some(format!(
                            "Timeout (no reply within {}ms)",
                            timeout.as_millis()
                        )),
                        error_kind: Some(ProbeErrorKind::Timeout),
                    }
                }
            }
        }
    }
}

/// 主目标成功→主目标；否则第一个成功者；全失败→优先非本机失败（本机 fast-fail 的 rtt≈0 会误导状态档），
/// 没有任何非本机失败时回传主目标那一笔。
fn pick_sample(samples: Vec<ProbeSample>, primary_idx: usize) -> ProbeSample {
    if let Some(primary) = samples.get(primary_idx).filter(|s| s.success) {
        return primary.clone();
    }
    if let Some(success) = samples.iter().find(|s| s.success) {
        return success.clone();
    }
    // 主目标优先、其余照设定顺序，避免同一故障在不同拍回报不同原因。
    let order =
        std::iter::once(primary_idx).chain((0..samples.len()).filter(|i| *i != primary_idx));
    let mut first_non_local: Option<ProbeSample> = None;
    for idx in order {
        if let Some(sample) = samples.get(idx) {
            if sample.error_kind != Some(ProbeErrorKind::Local) && first_non_local.is_none() {
                first_non_local = Some(sample.clone());
            }
        }
    }
    first_non_local.unwrap_or_else(|| {
        samples
            .get(primary_idx)
            .or_else(|| samples.first())
            .cloned()
            .expect("probe_interface 至少会回传一笔样本")
    })
}

/// 「主目标 + 失败才回退」：健康时每周期只发一条连线，主目标失败才并发探其余目标。
///
/// `primary_suspect`（上一拍失败）时所有目标同时发出：否则最坏情况会花 2×timeout（> check_interval_ms），
/// 拖长探测节奏且期间无法处理讯号与 link 事件。`preferred` 由呼叫端维护（上次探通的目标）。
pub async fn probe_interface(
    iface: &str,
    targets: &[SocketAddr],
    timeout: Duration,
    preferred: usize,
    primary_suspect: bool,
) -> ProbeSample {
    if targets.is_empty() {
        return ProbeSample {
            success: false,
            rtt: timeout,
            target: "0.0.0.0:0".parse().unwrap(),
            error_msg: Some("No targets configured".into()),
            error_kind: Some(ProbeErrorKind::Local),
        };
    }

    if targets.len() == 1 {
        return probe_single_target(iface, targets[0], timeout).await;
    }

    let primary_idx = if preferred < targets.len() {
        preferred
    } else {
        0
    };

    // 疑似故障：并发探所有目标，整拍最多 1×timeout（future 是 !Unpin，故 Box::pin）。
    if primary_suspect {
        let futures: Vec<_> = targets
            .iter()
            .map(|&target| Box::pin(probe_single_target(iface, target, timeout)))
            .collect();
        let samples = futures_util::future::join_all(futures).await;
        let sample = pick_sample(samples, primary_idx);
        if sample.success {
            debug!(
                "[{}] Probe success to {} with RTT {:?} (hedged round)",
                iface, sample.target, sample.rtt
            );
        } else if let Some(err) = &sample.error_msg {
            debug!("[{}] Probe all failed to {}: {}", iface, sample.target, err);
        }
        return sample;
    }

    // 第一阶段：只探主目标（健康时每周期的唯一探针）。
    let primary = probe_single_target(iface, targets[primary_idx], timeout).await;
    if primary.success {
        debug!(
            "[{}] Probe success to {} with RTT {:?}",
            iface, primary.target, primary.rtt
        );
        return primary;
    }

    // 保留主目标失败样本供除错；非本机失败（逾时）比 fast-fail 更能代表线路实际状态。
    let first_fail = primary.clone();
    let mut preferred_fail: Option<ProbeSample> =
        if primary.error_kind != Some(ProbeErrorKind::Local) {
            Some(primary)
        } else {
            None
        };

    // 第二阶段：主目标失败才并发探其余目标（future 是 !Unpin，故 Box::pin）。
    let mut futures: Vec<_> = targets
        .iter()
        .enumerate()
        .filter(|(idx, _)| *idx != primary_idx)
        .map(|(_, &target)| Box::pin(probe_single_target(iface, target, timeout)))
        .collect();

    while !futures.is_empty() {
        let (res, _idx, rest) = futures_util::future::select_all(futures).await;
        futures = rest;

        if res.success {
            debug!(
                "[{}] Probe fallback success to {} with RTT {:?}",
                iface, res.target, res.rtt
            );
            return res;
        }
        if res.error_kind != Some(ProbeErrorKind::Local) && preferred_fail.is_none() {
            preferred_fail = Some(res);
        }
    }

    let f = preferred_fail.unwrap_or(first_fail);
    if let Some(err) = &f.error_msg {
        debug!("[{}] Probe all failed to {}: {}", iface, f.target, err);
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(last: u8) -> SocketAddr {
        format!("223.5.5.5:{last}").parse().unwrap()
    }

    fn ok(last: u8, rtt_ms: u64) -> ProbeSample {
        ProbeSample {
            success: true,
            rtt: Duration::from_millis(rtt_ms),
            target: target(last),
            error_msg: None,
            error_kind: None,
        }
    }

    fn fail(last: u8, kind: ProbeErrorKind) -> ProbeSample {
        ProbeSample {
            success: false,
            rtt: Duration::from_millis(400),
            target: target(last),
            error_msg: Some(format!("{kind:?}")),
            error_kind: Some(kind),
        }
    }

    /// 并行一轮的挑选结果必须与旧版「主目标优先」语意一致，否则同一故障会回报不同原因。
    #[test]
    fn test_pick_sample_prefers_primary_then_order_then_non_local_failure() {
        let picked = pick_sample(vec![ok(53, 30), ok(54, 5), ok(55, 7)], 0);
        assert_eq!(picked.target, target(53));
        let picked = pick_sample(vec![ok(53, 5), ok(54, 30)], 1);
        assert_eq!(picked.target, target(54));

        let picked = pick_sample(
            vec![fail(53, ProbeErrorKind::Timeout), ok(54, 22), ok(55, 8)],
            0,
        );
        assert_eq!(picked.target, target(54));

        let picked = pick_sample(
            vec![
                fail(53, ProbeErrorKind::Local),
                fail(54, ProbeErrorKind::Timeout),
                fail(55, ProbeErrorKind::Other),
            ],
            0,
        );
        assert_eq!(picked.target, target(54));
        assert_eq!(picked.error_kind, Some(ProbeErrorKind::Timeout));

        let picked = pick_sample(
            vec![
                fail(53, ProbeErrorKind::Local),
                fail(54, ProbeErrorKind::Local),
            ],
            0,
        );
        assert_eq!(picked.target, target(53));

        let picked = pick_sample(vec![fail(53, ProbeErrorKind::Local)], 7);
        assert_eq!(picked.target, target(53));
    }
}
