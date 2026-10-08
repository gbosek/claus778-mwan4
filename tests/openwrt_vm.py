#!/usr/bin/env python3
"""Run a real OpenWrt x86 QEMU guest with host TAP PPPoE and DHCP WANs.

No host default route or firewall changes. Logs retained on all outcomes.
"""
import argparse
import os
import pathlib
import re
import shlex
import subprocess
import sys
import time
import uuid

import pexpect


def host(*args, sudo=False):
    cmd = (["sudo"] if sudo else []) + list(args)
    print("HOST:", shlex.join(cmd), flush=True)
    return subprocess.run(cmd, check=True, capture_output=True, text=True)


def serial_command_line(command, marker):
    """Render one BusyBox ash command plus its exit-status sentinel.

    A job sent to the background ends with '&', which is already a shell
    list separator: adding ';' produces invalid '&;' (CI #37753230505).
    """
    command = command.rstrip()
    if not command:
        raise ValueError("empty serial command")
    separator = " " if command.endswith(("&", ";")) else "; "
    line = command + separator + f'rc=$?; printf "\\n{marker}%s\\n" "$rc"'
    # The physical tty input has a finite canonical-mode line buffer.
    if len(command) > 170 or len(line) > 220:
        raise ValueError(f"serial command too long ({len(line)} chars)")
    return line


class Lab:
    def __init__(self, args):
        self.image = pathlib.Path(args.image).resolve()
        self.kernel = pathlib.Path(args.kernel).resolve()
        self.distro = args.distro
        self.payload = pathlib.Path(args.payload).resolve()
        self.output = pathlib.Path(args.output).resolve()
        self.output.mkdir(parents=True, exist_ok=True)
        ident = uuid.uuid4().hex[:7]
        self.tap_ppp, self.tap_dhcp = "tp" + ident, "td" + ident
        self.guest = None
        self.services = []
        self.counter = 0
        self.serial = (self.output / "guest-serial.log").open("w", encoding="utf-8")
        self.checkpoints = (self.output / "checkpoints.log").open("w", encoding="utf-8", buffering=1)
        self.phase = "host setup"

    def checkpoint(self, message):
        print(message, flush=True)
        self.checkpoints.write(message + "\n")
        self.checkpoints.flush()

    def command_error(self, command, exc):
        # Preserve the *actual* failed step separately from kernel serial
        # chatter. The uploaded artifact gives actionable state immediately.
        text = (
            f"Phase: {self.phase}\nCommand: {command}\n"
            f"Exception: {exc}\n"
            f"QEMU alive: {self.guest is not None and self.guest.isalive()}\n"
            f"Recent console:\n{self.guest.before[-4000:] if self.guest else 'not launched'}\n"
        )
        (self.output / "last-failure.txt").write_text(text, encoding="utf-8")
        print("GUEST COMMAND FAILURE:\n" + text[-4500:], flush=True)

    def server(self, command):
        print("SERVICE:", shlex.join(command), flush=True)
        log = (self.output / f"service-{len(self.services)}.log").open("w")
        proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
        self.services.append((proc, log))
        time.sleep(0.5)
        if proc.poll() is not None:
            raise RuntimeError(f"service {command} exited with {proc.returncode}")

    def start(self):
        user = os.environ.get("USER", "runner")
        for tap in (self.tap_ppp, self.tap_dhcp):
            host("ip", "tuntap", "add", "dev", tap, "mode", "tap", "user", user, sudo=True)
            host("ip", "link", "set", "dev", tap, "up", sudo=True)
        host("ip", "addr", "add", "203.0.113.1/24", "dev", self.tap_dhcp, sudo=True)
        host("mkdir", "-p", "/etc/ppp", sudo=True)
        subprocess.run(
            ["sudo", "tee", "/etc/ppp/pppoe-server-options"],
            input="noauth\nlcp-echo-interval 2\nlcp-echo-failure 3\n",
            text=True, stdout=subprocess.DEVNULL, check=True
        )
        self.server(["sudo", "pppoe-server", "-F", "-I", self.tap_ppp,
                     "-L", "100.64.1.1", "-R", "100.64.1.2", "-N", "5"])
        self.server(["sudo", "dnsmasq", "--no-daemon", "--port=0",
                     "--interface=" + self.tap_dhcp, "--bind-interfaces",
                     "--dhcp-range=203.0.113.10,203.0.113.50,255.255.255.0,5m",
                     "--dhcp-option=3,203.0.113.1", "--dhcp-authoritative"])
        self.server([sys.executable, "-m", "http.server", "8093",
                     "--bind", "0.0.0.0", "--directory", str(self.payload)])
        command = [
            "qemu-system-x86_64", "-machine", "pc", "-accel", "tcg",
            "-m", "512", "-smp", "2", "-display", "none", "-monitor", "none",
            "-serial", "stdio", "-no-reboot",
            "-kernel", str(self.kernel),
            "-append", "root=/dev/vda2 rootwait rootfstype=ext4 console=ttyS0,115200n8",
            "-drive", "file=" + str(self.image) + ",if=virtio,format=raw",
            "-netdev", "user,id=mgmt",
            "-device", "virtio-net-pci,netdev=mgmt,mac=52:54:00:11:00:01",
            "-netdev", "tap,id=ppp,ifname=" + self.tap_ppp + ",script=no,downscript=no",
            "-device", "virtio-net-pci,netdev=ppp,mac=52:54:00:11:00:02",
            "-netdev", "tap,id=dhcp,ifname=" + self.tap_dhcp + ",script=no,downscript=no",
            "-device", "virtio-net-pci,netdev=dhcp,mac=52:54:00:11:00:03"
        ]
        self.guest = pexpect.spawn(command[0], command[1:],
                                   encoding="utf-8", timeout=120, echo=False)
        self.guest.logfile = self.serial
        # Official OpenWrt x86 actually says:
        # "Please press Enter to activate this console." (confirmed in
        # guest-serial.log from CI run 37748951378).
        # The original regex missed the lowercase "press" and "Please" prefix.
        # The shell prompt may be root@(none):~# before netifd assigns a hostname.
        self.guest.expect([
            r"Please press Enter to activate this console\.",
            r"Press Enter to activate this console",
            r"root@[^:\r\n]+:[^\r\n]*#\s*",
        ], timeout=145)
        self.guest.sendline("")
        self.guest.expect(r"root@[^:\r\n]+:[^\r\n]*#\s*", timeout=35)
        # Fresh OpenWrt ext4 images can have no UCI network file before
        # firstboot scripts finish. BusyBox's built-in ip lacks '-br'.
        self.cmd("cat /etc/openwrt_release; ip link show; "
                 "mkdir -p /etc/config; touch /etc/config/network; "
                 "uci -q show network || true")

    def cmd(self, command, timeout=80):
        self.counter += 1
        marker = f"__MWAN4_RC_{self.counter}_"
        line = serial_command_line(command, marker)
        print("GUEST:", command, flush=True)
        try:
            self.guest.sendline(line)
            self.guest.expect(re.escape(marker) + r"(\d+)", timeout=timeout)
            result = self.guest.match.group(1)
            output = self.guest.before
            self.guest.expect(r"root@[^:\r\n]+:[^\r\n]*#\s*", timeout=15)
            if result != "0":
                raise AssertionError(f"guest rc={result}: {command}\n{output[-2500:]}")
            return output
        except (AssertionError, pexpect.TIMEOUT, pexpect.EOF) as exc:
            self.command_error(command, exc)
            raise

    def dump_routing_diagnostics(self):
        self.cmd(
            "ip -4 rule show; ip -4 route show table all; "
            "nft list ruleset || true",
            timeout=60,
        )

    def guest_job(self, command, name, timeout=120):
        """Run a long operation asynchronously without GNU timeout in guest.

        Only POSIX ash builtins are needed. The host controls the deadline
        using pexpect's explicit polling, while the full stdout/stderr stays
        in a guest file that gets echoed on any failure.
        """
        if not re.fullmatch(r"[a-z][a-z0-9-]*", name):
            raise ValueError(f"invalid guest job label: {name}")
        logfile = f"/tmp/mwan4-{name}.log"
        rcfile = f"/tmp/mwan4-{name}.rc"
        self.cmd(f"rm -f {rcfile}")
        script = f"({command} >{logfile} 2>&1; echo $? >{rcfile}) &"
        self.cmd(script)
        try:
            self.wait(f"test -f {rcfile}", timeout=timeout)
            self.cmd(f'test "$(cat {rcfile})" = 0')
        except (AssertionError, pexpect.TIMEOUT):
            self.cmd(f"tail -n 50 {logfile}")
            self.cmd("ip route show default")
            raise
        return logfile

    def wait(self, command, timeout=90):
        deadline, error = time.monotonic() + timeout, ""
        while time.monotonic() < deadline:
            try:
                self.cmd(command, timeout=15)
                return
            except (AssertionError, pexpect.TIMEOUT) as exc:
                error = str(exc)
                time.sleep(2)
        raise AssertionError(f"timeout waiting for {command}: {error}")

    def tests(self):
        # Management interface is QEMU user-net, never a production interface.
        self.phase = "netifd network interface setup"
        if self.distro == "immortalwrt":
            # A real ImmortalWrt 6.18.52 guest must pass these checks;
            # running the 24.10 userland in its place is not acceptable.
            self.cmd("uname -r | grep -qx 6.18.52")
            self.cmd("grep -qi ImmortalWrt /etc/openwrt_release")
            self.cmd("command -v apk >/dev/null")
            self.checkpoint("PASS: genuine ImmortalWrt 6.18.52 kernel + APK userland")
        else:
            self.cmd("command -v opkg >/dev/null")
        self.wait("pidof netifd >/dev/null", 60)
        # Each UCI command is short enough to survive the BusyBox serial
        # line discipline even while kernel logs are being printed.
        for section in ("lan", "wan", "wan6"):
            self.cmd(f"uci -q delete network.{section} || true")
        self.cmd("uci -q delete network.@device[0] || true")
        for key, value in (
            ("mgmt", "interface"),
            ("mgmt.device", "eth0"),
            ("mgmt.proto", "dhcp"),
            ("mgmt.metric", "300"),
            ("dhcpwan", "interface"),
            ("dhcpwan.device", "eth2"),
            ("dhcpwan.proto", "dhcp"),
            ("dhcpwan.metric", "200"),
            # The TAP gateway 203.0.113.1 is isolated and has NO Internet.
            # Keep it from stealing the default route during package setup.
            ("dhcpwan.defaultroute", "0"),
            ("pppwan", "interface"),
            ("pppwan.device", "eth1"),
            ("pppwan.proto", "pppoe"),
            ("pppwan.username", "test"),
            ("pppwan.password", "test"),
            ("pppwan.metric", "100"),
            ("pppwan.auto", "0"),
        ):
            self.cmd(f"uci set network.{key}={value}")
        self.cmd("uci commit network")
        # netifd reload is asynchronous to avoid stopping the serial shell
        # before its command result marker is printed.
        self.cmd("(/etc/init.d/network reload >/tmp/mwan4-network-reload.log 2>&1) &")
        self.wait('ubus call network.interface.mgmt status | grep -q \'"up": true\'')
        self.phase = "management IP and package installation"
        self.cmd("ping -c 1 -W 3 10.0.2.2 >/dev/null")
        # Earlier builds sent downloads via the isolated DHCP TAP (metric
        # 200 < mgmt 300), which cannot reach Internet package feeds.
        self.cmd("ip route show default | grep -q '10.0.2.2'")
        self.cmd("uci -q get network.dhcpwan.defaultroute | grep -qx 0")
        self.checkpoint("PASS: management default route preserved for feeds")
        self.cmd("nslookup downloads.openwrt.org >/tmp/mwan4-dns.log 2>&1",
                 timeout=35)
        # Genuine distro PBR/firewall4 package, not mock nft rule sets.
        # OpenWrt base BusyBox lacks the 'timeout' applet. Poll a background
        # ash job with a host-side deadline so no GNU binaries are assumed.
        if self.distro == "immortalwrt":
            # Linux 6.18 snapshots use APK, unlike OpenWrt 24.10's opkg.
            # No opkg fallback: exercising the real package manager matters.
            self.guest_job("apk update", "apk-update", timeout=140)
            self.guest_job("apk add ppp ppp-mod-pppoe ip-full nftables-json pbr",
                           "apk-install", timeout=170)
        else:
            self.guest_job("opkg update", "opkg-update", timeout=140)
            self.guest_job("opkg install ppp ppp-mod-pppoe ip-full nftables-json pbr",
                           "opkg-install", timeout=170)
        self.checkpoint("PASS: real distro package manager and PBR dependencies")
        self.cmd("mkdir -p /usr/libexec /etc/config; "
                 "wget -qO /usr/bin/mwan4 http://10.0.2.2:8093/mwan4; "
                 "chmod 755 /usr/bin/mwan4")
        self.cmd("wget -qO /etc/init.d/mwan4 http://10.0.2.2:8093/mwan4-init; "
                 "chmod 755 /etc/init.d/mwan4")
        self.cmd("wget -qO /etc/config/mwan4 http://10.0.2.2:8093/mwan4-uci")
        self.cmd("wget -qO /usr/libexec/mwan4-pbr-compat "
                 "http://10.0.2.2:8093/pbr-compat; chmod 755 /usr/libexec/mwan4-pbr-compat")
        # Switch the isolated DHCP WAN's default route back on after
        # package and payload installation, for real netifd/PBR testing.
        self.cmd("uci set network.dhcpwan.defaultroute=1")
        self.cmd("uci commit network")
        self.cmd("(/etc/init.d/network reload >/tmp/mwan4-wan-reload.log 2>&1) &")
        self.wait("ubus call network.interface.dhcpwan status | grep -q '\"up\": true'", 70)
        self.checkpoint("PASS: isolated DHCP WAN routing enabled after feeds")
        self.cmd('test "$(uci -q get mwan4.global.enabled)" = 0; '
                 '! grep -q "^config interface " /etc/config/mwan4; '
                 '! ip -4 route show table main default proto 77 | grep -q .')
        self.checkpoint("PASS: no WAN routes installed on first installation")
        self.wait('ubus call network.interface.dhcpwan status | grep -q \'"up": true\'')
        self.phase = "PPPoE dial"
        self.cmd("ifup pppwan")
        self.wait('ubus call network.interface.pppwan status | grep -q \'"up": true\'', 120)
        self.cmd(". /lib/functions/network.sh; "
                 "network_get_device pppdev pppwan; test -n \"$pppdev\"; "
                 "ip link show \"$pppdev\"")
        self.checkpoint("PASS: actual PPPoE session established using TAP link")
        for key, value in (
            ("global.enabled", "1"),
            ("global.route_priority", "10"),
            ("global.ecmp_mode", "standard"),
            ("ppp", "interface"),
            ("ppp.network", "pppwan"),
            ("ppp.weight", "2"),
            ("dhcp", "interface"),
            ("dhcp.network", "dhcpwan"),
            ("dhcp.weight", "1"),
        ):
            self.cmd(f"uci set mwan4.{key}={value}")
        self.cmd("uci add_list mwan4.ppp.probe_targets=100.64.1.1:8093")
        self.cmd("uci add_list mwan4.dhcp.probe_targets=203.0.113.1:8093")
        # Deliberately overlap native mwan4 source-policy and standalone
        # PBR. Native rule prefers PPPoE; PBR source match prefers DHCP.
        # This catches precedence regressions that simple nft existence
        # tests cannot observe.
        self.cmd("uci set mwan4.native_ci=policy")
        self.cmd("uci set mwan4.native_ci.interface=ppp")
        self.cmd("uci add_list mwan4.native_ci.source=192.0.2.0/24")
        self.cmd("uci commit mwan4")
        self.phase = "Rust mwan4 + netifd startup"
        self.cmd("/etc/init.d/mwan4 start")
        self.wait("pidof mwan4 >/dev/null", 45)
        self.cmd("/usr/bin/mwan4 --check-config /var/etc/mwan4.json")
        self.wait("ip -4 route show table main default proto 77 | grep -q .", 65)
        self.checkpoint("PASS: Rust service running with genuine OpenWrt netifd/procd")
        self.phase = "PPPoE redial and route rebalance"
        self.cmd("ifdown pppwan")
        self.wait('! ubus call network.interface.pppwan status | grep -q \'"up": true\'', 45)
        self.cmd("ifup pppwan")
        self.wait('ubus call network.interface.pppwan status | grep -q \'"up": true\'', 110)
        self.wait("pidof mwan4 >/dev/null", 45)
        # procd reloads asynchronously after the netifd logical interface
        # announces UP. Poll for configuration/device convergence instead of
        # assuming that observing the daemon PID proves reload completion.
        l3_check = (". /lib/functions/network.sh; "
                    "network_get_device pppdev pppwan; "
                    "test -n \"$pppdev\" && grep -Fq \"$pppdev\" /var/etc/mwan4.json")
        try:
            self.wait(l3_check, timeout=70)
        except (AssertionError, pexpect.TIMEOUT):
            self.cmd("ubus call network.interface.pppwan status")
            self.cmd("cat /var/etc/mwan4.json")
            self.cmd("logread -e mwan4")
            self.cmd("ip -4 route show table main default")
            raise
        self.checkpoint("PASS: PPPoE redial and dynamic L3 interface mapping")
        self.phase = "PBR and firewall4 coexistence"
        for key, value in (
            ("config.enabled", "1"),
            ("config.strict_enforcement", "0"),
            # PBR defaults to the literal logical WAN 'wan', which does not
            # exist in this generic-netifd test. Point it at the NAT-enabled
            # mgmt interface with a real reachable IPv4 gateway.
            ("config.uplink_interface", "mgmt"),
            ("mwan4_ci", "policy"),
            ("mwan4_ci.name", "CI_DHCP_WAN"),
            ("mwan4_ci.src_addr", "192.0.2.0/24"),
            ("mwan4_ci.interface", "dhcpwan"),
        ):
            self.cmd(f"uci set pbr.{key}={value}")
        # dhcpwan does not match PBR's built-in 'wan*' naming heuristic.
        # Explicitly opt in without altering any router-wide defaults.
        self.cmd("uci add_list pbr.config.supported_interface=dhcpwan")
        self.cmd("uci add_list pbr.config.supported_interface=pppwan")
        self.cmd("uci commit pbr")
        self.cmd("/etc/init.d/firewall restart", 80)
        self.cmd("/etc/init.d/pbr restart", 95)
        try:
            self.wait("ip -4 rule show | grep -q fwmark", 55)
        except (AssertionError, pexpect.TIMEOUT):
            self.cmd("uci show pbr.config")
            self.cmd("ubus call network.interface.mgmt status")
            self.cmd("ubus call network.interface.dhcpwan status")
            self.cmd("ip -4 rule show")
            self.cmd("logread -e pbr")
            raise
        self.cmd("fw4 print >/tmp/mwan4-fw4.nft; test -s /tmp/mwan4-fw4.nft")
        self.cmd("nft list ruleset | grep -q pbr")
        self.cmd("/etc/init.d/mwan4 reload")
        self.cmd("grep -E 'policy_skip_mark_mask.*[1-9][0-9]*' /var/etc/mwan4.json")
        self.wait("pidof mwan4 >/dev/null", 45)
        # Both policy systems match 192.0.2.0/24, but only marked flows
        # should escape the native priority-9000 policy. Extract the
        # standalone PBR mark for dhcpwan from the LIVE kernel rules.
        self.phase = "PBR marked/unmarked route precedence"
        rules = self.cmd("ip -4 rule show")
        pbr_mark = None
        for line in rules.splitlines():
            m = re.search(
                r"fwmark\s+(0x[0-9a-fA-F]+)/0x[0-9a-fA-F]+"
                r"\s+lookup\s+(\S+)", line
            )
            if m and int(m.group(1), 16) != 0 and "dhcpwan" in m.group(2):
                pbr_mark = m.group(1)
                break
        if pbr_mark is None:
            raise AssertionError(f"no dhcpwan PBR fwmark rule found:\\n{rules}")
        self.cmd("ip -4 rule show | grep -q 'from 192.0.2.0/24'")
        try:
            self.cmd(
                "ip -4 rule show | grep -Eq 'fwmark (0x)?0(/|[[:space:]]|$)|not fwmark'"
            )
        except (AssertionError, pexpect.TIMEOUT, pexpect.EOF):
            self.dump_routing_diagnostics()
            raise
        try:
            marked = self.cmd(
                f"ip -4 route get 198.18.0.1 from 192.0.2.10 mark {pbr_mark}"
            )
            if not re.search(r"\bdev eth2\b", marked):
                raise AssertionError(
                    f"marked PBR traffic did not select dhcpwan: {marked}"
                )
        except (AssertionError, pexpect.TIMEOUT, pexpect.EOF):
            self.dump_routing_diagnostics()
            raise
        try:
            unmarked = self.cmd(
                "ip -4 route get 198.18.0.1 from 192.0.2.10"
            )
            if not re.search(r"\bdev ppp[^\s]*\b", unmarked):
                raise AssertionError(
                    "unmarked traffic did not retain PPPoE native policy: "
                    f"{unmarked}"
                )
        except (AssertionError, pexpect.TIMEOUT, pexpect.EOF):
            self.dump_routing_diagnostics()
            raise
        self.checkpoint("PASS: overlapping PBR mark beats native policy, unmarked stays PPPoE")
        self.checkpoint("PASS: real firewall4 + standalone PBR mark coexistence")
        self.phase = "DHCP WAN failover and recovery"
        self.cmd("ifdown dhcpwan")
        self.wait('! ubus call network.interface.dhcpwan status | grep -q \'"up": true\'', 45)
        self.cmd("ifup dhcpwan")
        self.wait('ubus call network.interface.dhcpwan status | grep -q \'"up": true\'', 90)
        self.wait("pidof mwan4 >/dev/null", 45)
        self.checkpoint("PASS: DHCP WAN offline and reconnect")
        self.phase = "mwan4 shutdown route rollback"
        self.cmd("/etc/init.d/mwan4 stop")
        self.wait("! pidof mwan4 >/dev/null", 35)
        self.cmd("! ip -4 route show table main default proto 77 | grep -q .")
        self.cmd("ip -4 rule show | grep -q fwmark")
        self.cmd("ip -4 route show table main default | grep -q .")
        self.checkpoint("PASS: OpenWrt guest route rollback keeps PBR and netifd")

    def close(self):
        if self.guest:
            self.guest.terminate(force=True)
        for process, log in reversed(self.services):
            process.terminate()
            try:
                process.wait(timeout=7)
            except subprocess.TimeoutExpired:
                process.kill()
            log.close()
        for tap in (self.tap_ppp, self.tap_dhcp):
            subprocess.run(["sudo", "ip", "link", "del", "dev", tap],
                           capture_output=True, check=False)
        self.serial.close()
        self.checkpoints.close()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--image", required=True)
    p.add_argument("--kernel", required=True)
    p.add_argument("--distro", choices=("openwrt", "immortalwrt"), default="openwrt")
    p.add_argument("--payload", required=True)
    p.add_argument("--output", required=True)
    args = p.parse_args()
    lab = Lab(args)
    try:
        lab.start()
        lab.tests()
    finally:
        lab.close()


if __name__ == "__main__":
    main()
