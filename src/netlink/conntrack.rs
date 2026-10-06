// 非 Linux 平台上（例如在 Windows 上 `cargo check`）整批变成 dead code。
#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

use log::{debug, info, warn};
use std::io;
use std::net::Ipv4Addr;

#[allow(unused_imports)]
use crate::netlink::util::{
    NlMsgHdr, nlmsg_align, read_i32, read_u16, rta_align, set_socket_timeouts, write_u16,
};
#[allow(dead_code)]
pub const NETLINK_NETFILTER: libc::c_int = 12;
#[allow(dead_code)]
pub const NFNL_SUBSYS_CTNETLINK: u16 = 1;

#[allow(dead_code)]
pub const IPCTNL_MSG_CT_NEW: u16 = 0;
#[allow(dead_code)]
pub const IPCTNL_MSG_CT_GET: u16 = 1;
#[allow(dead_code)]
pub const IPCTNL_MSG_CT_DELETE: u16 = 2;

#[allow(dead_code)]
pub const NLM_F_REQUEST: u16 = 0x01;
#[allow(dead_code)]
pub const NLM_F_DUMP: u16 = 0x300; // NLM_F_ROOT | NLM_F_MATCH

#[allow(dead_code)]
pub const CTA_UNSPEC: u16 = 0;
#[allow(dead_code)]
pub const CTA_TUPLE_ORIG: u16 = 1;
#[allow(dead_code)]
pub const CTA_TUPLE_REPLY: u16 = 2;
#[allow(dead_code)]
pub const CTA_TUPLE_IP: u16 = 1;
#[allow(dead_code)]
pub const CTA_IP_V4_SRC: u16 = 1;
#[allow(dead_code)]
pub const CTA_IP_V4_DST: u16 = 2;
#[allow(dead_code)]
pub const NLA_TYPE_MASK: u16 = 0x3fff;
/// conntrack zone（u16）：带 zone 的部署删除时不回填，内核会在 zone 0 找同 tuple 的连线，漏删甚至误删。
#[allow(dead_code)]
pub const CTA_ZONE: u16 = 18;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct NfGenMsg {
    pub nfgen_family: u8,
    pub version: u8,
    pub res_id: u16,
}

impl NfGenMsg {
    pub const LEN: usize = 4;

    pub fn to_bytes(self) -> [u8; Self::LEN] {
        let mut b = [0u8; Self::LEN];
        b[0] = self.nfgen_family;
        b[1] = self.version;
        write_u16(&mut b, 2, self.res_id);
        b
    }
}

const DUMP_BUF_SIZE: usize = 32 * 1024;
const DELETE_BATCH_LIMIT: usize = 8 * 1024;
const CT_RECV_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const CT_SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

pub struct ConntrackManager {
    #[cfg(target_os = "linux")]
    sock_fd: libc::c_int,
    seq: u32,
}

impl ConntrackManager {
    pub fn new() -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let sock_fd = Self::open_socket()?;
            Ok(Self { sock_fd, seq: 1 })
        }

        #[cfg(not(target_os = "linux"))]
        {
            Ok(Self { seq: 1 })
        }
    }

    #[cfg(target_os = "linux")]
    fn open_socket() -> io::Result<libc::c_int> {
        let sock_fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_NETFILTER,
            )
        };
        if sock_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        sa.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        sa.nl_pid = 0;
        sa.nl_groups = 0;

        let ret = unsafe {
            libc::bind(
                sock_fd,
                &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            unsafe { libc::close(sock_fd) };
            return Err(io::Error::last_os_error());
        }

        if let Err(e) = set_socket_timeouts(sock_fd, Some(CT_RECV_TIMEOUT), Some(CT_SEND_TIMEOUT)) {
            warn!("[Conntrack] Failed to set socket timeouts: {e}");
        }

        Ok(sock_fd)
    }

    /// dump 状态挂在 socket 上：未收到 `NLMSG_DONE` 就结束会让后续 `NLM_F_DUMP` 永远回 `-EBUSY`，逾时后直接重建最干净。
    #[cfg(target_os = "linux")]
    fn reopen_socket(&mut self) {
        if self.sock_fd >= 0 {
            unsafe { libc::close(self.sock_fd) };
        }
        self.sock_fd = -1;
        match Self::open_socket() {
            Ok(fd) => self.sock_fd = fd,
            Err(e) => warn!("[Conntrack] Failed to reopen netlink socket: {e}"),
        }
    }

    /// WAN 掉线 / 活跃集合变化时清理这些网卡上的连线：多张网卡合并为一次全表 dump，避免每张各扫一遍。
    pub fn flush_interfaces_conntrack(
        &mut self,
        ifaces: &[(String, Option<Ipv4Addr>)],
    ) -> io::Result<usize> {
        let mut ips: Vec<Ipv4Addr> = Vec::with_capacity(ifaces.len());
        let mut names: Vec<&str> = Vec::with_capacity(ifaces.len());
        for (ifname, last_known) in ifaces {
            names.push(ifname.as_str());
            match crate::netlink::util::get_interface_ipv4(ifname) {
                Ok(ip) => ips.push(ip),
                Err(e) => {
                    // 介面已消失或正在重拨（PPPoE/USB）时现查会失败；改用 DOWN 时记下的最后已知 IP 才清得到旧位址长连线。
                    if let Some(ip) = last_known {
                        debug!(
                            "[Conntrack] Could not query IP for {ifname} ({e}); \
                             using last known IP {ip}"
                        );
                        ips.push(*ip);
                    } else {
                        warn!(
                            "[Conntrack] Could not query IP for {ifname}: {e}. \
                             Skipping exact conntrack match."
                        );
                    }
                }
            }
        }
        if ips.is_empty() {
            // 查不到 IPv4 必须回 Err 让主回圈保持 dirty 重试；回 Ok(0) 会被当成 DOWN 期间已清理完成。
            return Err(io::Error::other(format!(
                "no IPv4 address could be resolved for [{}]; will retry while the link stays down",
                names.join(", ")
            )));
        }

        info!(
            "[Conntrack] Flushing active conntrack sessions for {} ...",
            names.join(", ")
        );

        #[cfg(target_os = "linux")]
        {
            self.flush_by_ips(&ips)
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = &ips;
            Ok(0)
        }
    }

    #[cfg(target_os = "linux")]
    fn flush_by_ips(&mut self, target_ips: &[Ipv4Addr]) -> io::Result<usize> {
        if self.sock_fd < 0 {
            self.reopen_socket();
            if self.sock_fd < 0 {
                return Err(io::Error::other(
                    "conntrack netlink socket is not available",
                ));
            }
        }

        self.seq = self.seq.wrapping_add(1);
        let dump_seq = self.seq;
        let nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET;
        let req_buf = self.build_msg(nlmsg_type, NLM_F_REQUEST | NLM_F_DUMP, &[]);

        let sent = unsafe {
            libc::send(
                self.sock_fd,
                req_buf.as_ptr() as *const libc::c_void,
                req_buf.len(),
                0,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        if sent as usize != req_buf.len() {
            return Err(io::Error::other(format!(
                "short netlink send for conntrack dump ({sent}/{} bytes)",
                req_buf.len()
            )));
        }

        // 边收边删避免整表暂存；批量 send 后不可排空接收伫列（里面还有核心预填的后续 dump 资料块），改以 nlmsg_seq 区分。
        let mut recv_buf = vec![0u8; DUMP_BUF_SIZE];
        let expected_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_NEW;
        let mut batch: Vec<u8> = Vec::with_capacity(DELETE_BATCH_LIMIT + 64);
        let mut deleted: usize = 0;
        let mut dump_done = false;
        // 有值代表这次 flush 不完整，必须让呼叫端知道并重试。
        let mut first_err: Option<io::Error> = None;

        'outer: loop {
            let n = unsafe {
                libc::recv(
                    self.sock_fd,
                    recv_buf.as_mut_ptr() as *mut libc::c_void,
                    recv_buf.len(),
                    0,
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                if first_err.is_none() {
                    first_err = Some(if e.kind() == io::ErrorKind::WouldBlock {
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "conntrack dump timed out before NLMSG_DONE",
                        )
                    } else {
                        e
                    });
                }
                break;
            }
            if n == 0 {
                if first_err.is_none() {
                    first_err = Some(io::Error::other(
                        "netlink socket closed during conntrack dump",
                    ));
                }
                break;
            }

            let mut offset = 0;
            let len = n as usize;

            while offset + NlMsgHdr::LEN <= len {
                let msg_hdr = match NlMsgHdr::from_bytes(&recv_buf[offset..len]) {
                    Some(h) => h,
                    None => break,
                };
                let msg_len = msg_hdr.nlmsg_len as usize;
                if msg_len < NlMsgHdr::LEN || offset + msg_len > len {
                    // 单则讯息大于缓冲区会被截断而漏掉；datagram 框架仍对齐，继续收完 dump 再回报失败。
                    if first_err.is_none() {
                        first_err = Some(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "conntrack dump message truncated (larger than receive buffer)",
                        ));
                    }
                    break;
                }

                let next_offset = offset + nlmsg_align(msg_len);

                if msg_hdr.nlmsg_type == libc::NLMSG_DONE as u16 {
                    dump_done = true;
                    break 'outer;
                }
                if msg_hdr.nlmsg_type == libc::NLMSG_ERROR as u16 {
                    if msg_hdr.nlmsg_seq == dump_seq {
                        if first_err.is_none() {
                            first_err = Some(Self::nlmsgerr_to_io_error(
                                &recv_buf[offset..offset + msg_len],
                            ));
                        }
                        break 'outer;
                    }
                    // 失败的删除回复（如 ENOENT），忽略后继续收 dump
                    offset = next_offset;
                    continue;
                }

                if msg_hdr.nlmsg_type == expected_type {
                    if msg_hdr.nlmsg_seq != dump_seq {
                        offset = next_offset;
                        continue;
                    }
                    let attrs_offset = offset + NlMsgHdr::LEN + NfGenMsg::LEN;
                    if attrs_offset < offset + msg_len {
                        let attrs_slice = &recv_buf[attrs_offset..offset + msg_len];
                        if let Some((tuple_start, tuple_end, zone)) =
                            Self::extract_matching_orig_tuple(attrs_slice, target_ips)
                        {
                            self.seq = self.seq.wrapping_add(1);
                            Self::append_delete_msg(
                                &mut batch,
                                self.seq,
                                &attrs_slice[tuple_start..tuple_end],
                                zone,
                            );
                            deleted += 1;

                            if batch.len() >= DELETE_BATCH_LIMIT {
                                // 发送失败也不中断 dump（否则核心卡在 dump 进行中，下次永远 EBUSY），记下错误最后回报。
                                if let Err(e) = Self::flush_delete_batch(self.sock_fd, &mut batch) {
                                    if first_err.is_none() {
                                        first_err = Some(e);
                                    }
                                }
                            }
                        }
                    }
                }

                offset = next_offset;
            }
        }

        if let Err(e) = Self::flush_delete_batch(self.sock_fd, &mut batch) {
            if first_err.is_none() {
                first_err = Some(e);
            }
        }

        // 只有 dump 完整走完才排空残留回应；中途失败得重建 socket 丢掉残留 dump 状态，否则下次撞 EBUSY。
        if dump_done {
            Self::drain_nonblocking(self.sock_fd);
        } else {
            self.reopen_socket();
        }

        if let Some(e) = first_err {
            warn!(
                "[Conntrack] Flush did not complete (submitted {deleted} delete requests so far): {e}"
            );
            return Err(e);
        }

        if deleted == 0 {
            debug!("[Conntrack] No active sessions found matching {target_ips:?}");
        } else {
            info!(
                "[Conntrack] Submitted delete requests for {deleted} conntrack entries (IPs {target_ips:?}, dump seq {dump_seq})"
            );
        }
        Ok(deleted)
    }

    /// 把 NLMSG_ERROR 回应转成 `io::Error`（内核错误码放在标头后的第一个 i32）。
    #[cfg(target_os = "linux")]
    fn nlmsgerr_to_io_error(buf: &[u8]) -> io::Error {
        match read_i32(buf, NlMsgHdr::LEN) {
            Some(code) if code < 0 => io::Error::from_raw_os_error(code.saturating_neg()),
            Some(code) => io::Error::other(format!("conntrack dump rejected (error {code})")),
            None => io::Error::other("conntrack dump rejected (malformed NLMSG_ERROR)"),
        }
    }

    /// 就地写入批量缓冲：tuple 借用切片，省掉每条讯息的堆分配与两次 memcpy。
    #[cfg(target_os = "linux")]
    fn append_delete_msg(batch: &mut Vec<u8>, seq: u32, tuple_bytes: &[u8], zone: u16) {
        // zone 0 是预设值，不必显式带
        let zone_attr_len = if zone != 0 { 4 + 2 } else { 0 };
        let msg_len = NlMsgHdr::LEN + NfGenMsg::LEN + tuple_bytes.len() + zone_attr_len;
        // netlink 批次内每则讯息需 4 位元组对齐：nlmsg_len 填实际长度，余下补零。
        let padded_len = nlmsg_align(msg_len);
        let start = batch.len();
        batch.resize(start + padded_len, 0);

        let hdr = NlMsgHdr {
            nlmsg_len: msg_len as u32,
            nlmsg_type: (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_DELETE,
            nlmsg_flags: NLM_F_REQUEST, // 不请求 ACK，避免回应堆满接收伫列
            nlmsg_seq: seq,
            nlmsg_pid: 0,
        };
        let nfgen = NfGenMsg {
            nfgen_family: libc::AF_INET as u8,
            version: 0,
            res_id: 0,
        };

        let hdr_end = start + NlMsgHdr::LEN;
        batch[start..hdr_end].copy_from_slice(&hdr.to_bytes());
        let nfgen_end = hdr_end + NfGenMsg::LEN;
        batch[hdr_end..nfgen_end].copy_from_slice(&nfgen.to_bytes());
        let tuple_end = nfgen_end + tuple_bytes.len();
        batch[nfgen_end..tuple_end].copy_from_slice(tuple_bytes);
        if zone != 0 {
            batch[tuple_end..tuple_end + 2].copy_from_slice(&6u16.to_ne_bytes());
            batch[tuple_end + 2..tuple_end + 4].copy_from_slice(&CTA_ZONE.to_ne_bytes());
            batch[tuple_end + 4..tuple_end + 6].copy_from_slice(&zone.to_ne_bytes());
        }
    }

    #[cfg(target_os = "linux")]
    fn build_msg(&self, nlmsg_type: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
        let total_len = NlMsgHdr::LEN + NfGenMsg::LEN + payload.len();
        let mut buf = Vec::with_capacity(total_len);

        let nlhdr = NlMsgHdr {
            nlmsg_len: total_len as u32,
            nlmsg_type,
            nlmsg_flags: flags,
            nlmsg_seq: self.seq,
            nlmsg_pid: 0,
        };
        let nfgen = NfGenMsg {
            nfgen_family: libc::AF_INET as u8,
            version: 0,
            res_id: 0,
        };

        buf.extend_from_slice(&nlhdr.to_bytes());
        buf.extend_from_slice(&nfgen.to_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    #[cfg(target_os = "linux")]
    fn flush_delete_batch(sock_fd: libc::c_int, batch: &mut Vec<u8>) -> io::Result<()> {
        if batch.is_empty() {
            return Ok(());
        }

        let buf_len = batch.len();
        // datagram 全有或全无：部分发送不可补送（接收端会把半条讯息当新讯息），一律视为失败整批重试。
        let n = unsafe { libc::send(sock_fd, batch.as_ptr() as *const libc::c_void, buf_len, 0) };
        batch.clear();
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n as usize != buf_len {
            return Err(io::Error::other(format!(
                "short netlink send while flushing conntrack deletes ({n}/{buf_len} bytes)"
            )));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn drain_nonblocking(sock_fd: libc::c_int) {
        let mut buf = [0u8; 4096];
        loop {
            let n = unsafe {
                libc::recv(
                    sock_fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if n <= 0 {
                break;
            }
        }
    }

    /// 找出匹配任一 target_ip 的 CTA_TUPLE_ORIG 区间并回传 zone：区间以切片借用（零拷贝），zone 不回填就删不到条目。
    fn extract_matching_orig_tuple(
        attrs: &[u8],
        target_ips: &[Ipv4Addr],
    ) -> Option<(usize, usize, u16)> {
        let mut orig_range: Option<(usize, usize)> = None;
        let mut zone: u16 = 0;
        let mut matched = false;

        let mut offset = 0;
        let nfa_hdr_len = 4; // struct nfattr { u16 nfa_len; u16 nfa_type; }

        while offset + nfa_hdr_len <= attrs.len() {
            let attr_len = match read_u16(attrs, offset) {
                Some(v) => v as usize,
                None => break,
            };
            let attr_type = match read_u16(attrs, offset + 2) {
                Some(v) => v & NLA_TYPE_MASK,
                None => break,
            };

            if attr_len < nfa_hdr_len || offset + attr_len > attrs.len() {
                break;
            }

            let data = &attrs[offset + nfa_hdr_len..offset + attr_len];

            if attr_type == CTA_TUPLE_ORIG {
                orig_range = Some((offset, offset + attr_len));
                if Self::tuple_matches_ip(data, target_ips) {
                    matched = true;
                }
            } else if attr_type == CTA_TUPLE_REPLY && Self::tuple_matches_ip(data, target_ips) {
                matched = true;
            } else if attr_type == CTA_ZONE && data.len() >= 2 {
                zone = read_u16(data, 0).unwrap_or(0);
            }

            offset += rta_align(attr_len);
        }

        orig_range
            .map(|(start, end)| (start, end, zone))
            .filter(|_| matched)
    }

    /// tuple 内 IP 命中任一 target_ip 即算匹配（SNAT 后的 WAN IP 出现在 REPLY dst 或 ORIG src）
    fn tuple_matches_ip(tuple_data: &[u8], target_ips: &[Ipv4Addr]) -> bool {
        let nfa_hdr_len = 4;
        let mut offset = 0;

        while offset + nfa_hdr_len <= tuple_data.len() {
            let attr_len = match read_u16(tuple_data, offset) {
                Some(v) => v as usize,
                None => break,
            };
            let attr_type = match read_u16(tuple_data, offset + 2) {
                Some(v) => v & NLA_TYPE_MASK,
                None => break,
            };

            if attr_len < nfa_hdr_len || offset + attr_len > tuple_data.len() {
                break;
            }

            let data = &tuple_data[offset + nfa_hdr_len..offset + attr_len];

            if attr_type == CTA_TUPLE_IP {
                let mut ip_offset = 0;
                while ip_offset + nfa_hdr_len <= data.len() {
                    let ip_attr_len = match read_u16(data, ip_offset) {
                        Some(v) => v as usize,
                        None => break,
                    };

                    if ip_attr_len < nfa_hdr_len || ip_offset + ip_attr_len > data.len() {
                        break;
                    }

                    let ip_data = &data[ip_offset + nfa_hdr_len..ip_offset + ip_attr_len];
                    if ip_data.len() == 4 {
                        let ip = Ipv4Addr::new(ip_data[0], ip_data[1], ip_data[2], ip_data[3]);
                        if target_ips.contains(&ip) {
                            return true;
                        }
                    }

                    ip_offset += rta_align(ip_attr_len);
                }
            }

            offset += rta_align(attr_len);
        }
        false
    }
}

#[cfg(target_os = "linux")]
impl Drop for ConntrackManager {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.sock_fd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nf_attr(attr_type: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        let len = (4 + payload.len()) as u16;
        v.extend_from_slice(&len.to_ne_bytes());
        v.extend_from_slice(&attr_type.to_ne_bytes());
        v.extend_from_slice(payload);
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v
    }

    #[test]
    fn test_tuple_matches_ip() {
        let ip = Ipv4Addr::new(10, 0, 0, 5);
        let mut inner = nf_attr(CTA_IP_V4_SRC, &[10, 0, 0, 5]);
        inner.extend_from_slice(&nf_attr(CTA_IP_V4_DST, &[8, 8, 8, 8]));
        let tuple = nf_attr(CTA_TUPLE_IP, &inner);

        assert!(ConntrackManager::tuple_matches_ip(&tuple, &[ip]));
        assert!(ConntrackManager::tuple_matches_ip(
            &tuple,
            &[Ipv4Addr::new(9, 9, 9, 9), ip]
        ));
        assert!(!ConntrackManager::tuple_matches_ip(
            &tuple,
            &[Ipv4Addr::new(10, 0, 0, 6)]
        ));
    }

    #[test]
    fn test_extract_matching_orig_tuple() {
        let ip = Ipv4Addr::new(203, 0, 113, 9);
        let mut inner = nf_attr(CTA_IP_V4_SRC, &[192, 168, 1, 100]);
        inner.extend_from_slice(&nf_attr(CTA_IP_V4_DST, &[8, 8, 8, 8]));
        let orig = nf_attr(CTA_TUPLE_ORIG, &nf_attr(CTA_TUPLE_IP, &inner));

        let mut r_inner = nf_attr(CTA_IP_V4_SRC, &[8, 8, 8, 8]);
        r_inner.extend_from_slice(&nf_attr(CTA_IP_V4_DST, &[203, 0, 113, 9]));
        let reply = nf_attr(CTA_TUPLE_REPLY, &nf_attr(CTA_TUPLE_IP, &r_inner));

        let mut attrs = orig.clone();
        attrs.extend_from_slice(&reply);

        let extracted = ConntrackManager::extract_matching_orig_tuple(&attrs, &[ip]);
        assert_eq!(extracted, Some((0, orig.len(), 0)));
        let (start, end, _zone) = extracted.unwrap();
        assert_eq!(&attrs[start..end], &orig[..]);

        assert!(
            ConntrackManager::extract_matching_orig_tuple(&attrs, &[Ipv4Addr::new(1, 2, 3, 4), ip])
                .is_some()
        );

        assert!(
            ConntrackManager::extract_matching_orig_tuple(&attrs, &[Ipv4Addr::new(1, 2, 3, 4)])
                .is_none()
        );
    }

    #[test]
    fn test_extract_matching_orig_tuple_reads_zone() {
        let ip = Ipv4Addr::new(203, 0, 113, 9);
        let mut inner = nf_attr(CTA_IP_V4_SRC, &[203, 0, 113, 9]);
        inner.extend_from_slice(&nf_attr(CTA_IP_V4_DST, &[8, 8, 8, 8]));
        let orig = nf_attr(CTA_TUPLE_ORIG, &nf_attr(CTA_TUPLE_IP, &inner));
        let mut attrs = orig.clone();
        attrs.extend_from_slice(&nf_attr(CTA_ZONE, &7u16.to_ne_bytes()));

        let (_, _, zone) = ConntrackManager::extract_matching_orig_tuple(&attrs, &[ip]).unwrap();
        assert_eq!(zone, 7, "删除非 0 zone 的条目必须原样带回 CTA_ZONE");
    }

    #[test]
    fn test_delete_msg_carries_zone() {
        let tuple = nf_attr(CTA_TUPLE_ORIG, &nf_attr(CTA_TUPLE_IP, &[]));
        let mut batch = Vec::new();
        ConntrackManager::append_delete_msg(&mut batch, 5, &tuple, 3);

        let hdr = NlMsgHdr::from_bytes(&batch).unwrap();
        assert_eq!(
            hdr.nlmsg_type,
            (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_DELETE
        );
        let attrs_start = NlMsgHdr::LEN + NfGenMsg::LEN;
        let attrs = &batch[attrs_start..];
        // tuple 属性的 type 是 CTA_TUPLE_ORIG，紧接著是 CTA_ZONE=18 的 u16
        assert_eq!(read_u16(attrs, 2), Some(CTA_TUPLE_ORIG));
        let tuple_len = read_u16(attrs, 0).unwrap() as usize;
        assert_eq!(read_u16(attrs, tuple_len + 2), Some(CTA_ZONE));
        assert_eq!(read_u16(attrs, tuple_len + 4), Some(3));

        // zone 0 是预设值，不应多带属性（保持与旧版相同的报文）
        let mut batch0 = Vec::new();
        ConntrackManager::append_delete_msg(&mut batch0, 6, &tuple, 0);
        assert_eq!(
            NlMsgHdr::from_bytes(&batch0).unwrap().nlmsg_len + 6,
            hdr.nlmsg_len
        );
    }

    #[test]
    fn test_nfgenmsg_layout() {
        let m = NfGenMsg {
            nfgen_family: 2,
            version: 0,
            res_id: 0,
        };
        assert_eq!(m.to_bytes(), [2, 0, 0, 0]);
    }
}
