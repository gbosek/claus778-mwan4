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


class Lab:
    def __init__(self, args):
        self.image = pathlib.Path(args.image).resolve()
        self.payload = pathlib.Path(args.payload).resolve()
        self.output = pathlib.Path(args.output).resolve()
        self.output.mkdir(parents=True, exist_ok=True)
        ident = uuid.uuid4().hex[:7]
        self.tap_ppp, self.tap_dhcp = "tp" + ident, "td" + ident
        self.guest = None
        self.services = []
        self.counter = 0
        self.serial = (self.output / "guest-serial.log").open("w", encoding="utf-8")

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
        # The old regex missed the lowercase "press" and "Please" prefix.
        self.guest.expect([
            r"Please press Enter to activate this console\.",
            r"Press Enter to activate this console",
            r"root@OpenWrt:[^\r\n]*#\s*",
        ], timeout=145)
        self.guest.sendline("")
        self.guest.expect(r"root@OpenWrt:[^\r\n]*#\s*", timeout=35)
        self.cmd("cat /etc/openwrt_release; ip -br link; uci show network")

    def cmd(self, command, timeout=80):
        self.counter += 1
        marker = f"__MWAN4_RC_{self.counter}_"
        print("GUEST:", command, flush=True)
        self.guest.sendline(command + f'; rc=$?; printf "\\n{marker}%s\\n" "$rc"')
        self.guest.expect(re.escape(marker) + r"(\d+)", timeout=timeout)
        result = self.guest.match.group(1)
        output = self.guest.before
        self.guest.expect(r"root@OpenWrt:[^\r\n]*#\s*", timeout=15)
        if result != "0":
            raise AssertionError(f"guest rc={result}: {command}\n{output[-2500:]}")
        return output

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
        self.cmd(
            "uci -q delete network.lan; uci -q delete network.wan; "
            "uci -q delete network.wan6; uci -q delete network.@device[0]; "
            "uci set network.mgmt=interface; uci set network.mgmt.device=eth0; "
            "uci set network.mgmt.proto=dhcp; uci set network.mgmt.metric=300; "
            "uci set network.dhcpwan=interface; uci set network.dhcpwan.device=eth2; "
            "uci set network.dhcpwan.proto=dhcp; uci set network.dhcpwan.metric=200; "
            "uci set network.pppwan=interface; uci set network.pppwan.device=eth1; "
            "uci set network.pppwan.proto=pppoe; uci set network.pppwan.username=test; "
            "uci set network.pppwan.password=test; uci set network.pppwan.metric=100; "
            "uci set network.pppwan.auto=0; uci commit network; /etc/init.d/network restart",
            timeout=80)
        self.wait('ubus call network.interface.mgmt status | grep -q \'"up": true\'')
        self.cmd("ping -c 1 -W 3 10.0.2.2 >/dev/null")
        # Genuine distro PBR/firewall4 package, not mock nft rule sets.
        self.cmd("opkg update >/tmp/opkg-update.log 2>&1 || "
                 "{ tail -n 30 /tmp/opkg-update.log; false; }", timeout=180)
        self.cmd("opkg install ppp ppp-mod-pppoe ip-full nftables-json pbr "
                 ">/tmp/opkg-install.log 2>&1 || "
                 "{ tail -n 60 /tmp/opkg-install.log; false; }", timeout=200)
        self.cmd("mkdir -p /usr/libexec /etc/config; "
                 "wget -qO /usr/bin/mwan4 http://10.0.2.2:8093/mwan4; "
                 "chmod 755 /usr/bin/mwan4")
        self.cmd("wget -qO /etc/init.d/mwan4 http://10.0.2.2:8093/mwan4-init; "
                 "chmod 755 /etc/init.d/mwan4")
        self.cmd("wget -qO /etc/config/mwan4 http://10.0.2.2:8093/mwan4-uci")
        self.cmd("wget -qO /usr/libexec/mwan4-pbr-compat "
                 "http://10.0.2.2:8093/pbr-compat; chmod 755 /usr/libexec/mwan4-pbr-compat")
        self.cmd('test "$(uci -q get mwan4.global.enabled)" = 0; '
                 '! grep -q "^config interface " /etc/config/mwan4; '
                 '! ip -4 route show table main default proto 77 | grep -q .')
        print("PASS: no WAN routes installed on first installation", flush=True)
        self.wait('ubus call network.interface.dhcpwan status | grep -q \'"up": true\'')
        self.cmd("ifup pppwan")
        self.wait('ubus call network.interface.pppwan status | grep -q \'"up": true\'', 120)
        self.cmd(". /lib/functions/network.sh; "
                 "network_get_device pppdev pppwan; test -n \"$pppdev\"; "
                 "ip link show \"$pppdev\"")
        print("PASS: actual PPPoE session established using TAP link", flush=True)
        self.cmd("uci set mwan4.global.enabled=1; "
                 "uci set mwan4.global.route_priority=10; "
                 "uci set mwan4.global.ecmp_mode=standard; "
                 "uci set mwan4.ppp=interface; uci set mwan4.ppp.network=pppwan; "
                 "uci add_list mwan4.ppp.probe_targets=100.64.1.1:8093; "
                 "uci set mwan4.ppp.weight=2; "
                 "uci set mwan4.dhcp=interface; uci set mwan4.dhcp.network=dhcpwan; "
                 "uci add_list mwan4.dhcp.probe_targets=203.0.113.1:8093; "
                 "uci set mwan4.dhcp.weight=1; uci commit mwan4")
        self.cmd("/etc/init.d/mwan4 start")
        self.wait("pidof mwan4 >/dev/null", 45)
        self.cmd("/usr/bin/mwan4 --check-config /var/etc/mwan4.json")
        self.wait("ip -4 route show table main default proto 77 | grep -q .", 65)
        print("PASS: Rust service running with genuine OpenWrt netifd/procd", flush=True)
        self.cmd("ifdown pppwan")
        self.wait('! ubus call network.interface.pppwan status | grep -q \'"up": true\'', 45)
        self.cmd("ifup pppwan")
        self.wait('ubus call network.interface.pppwan status | grep -q \'"up": true\'', 110)
        self.wait("pidof mwan4 >/dev/null", 45)
        self.cmd(". /lib/functions/network.sh; "
                 "network_get_device pppdev pppwan; grep -Fq \"$pppdev\" /var/etc/mwan4.json")
        print("PASS: PPPoE redial and dynamic L3 interface mapping", flush=True)
        self.cmd("uci set pbr.config.enabled=1; "
                 "uci set pbr.config.strict_enforcement=0; "
                 "uci set pbr.mwan4_ci=policy; uci set pbr.mwan4_ci.name=CI_DHCP_WAN; "
                 "uci set pbr.mwan4_ci.src_addr=192.0.2.0/24; "
                 "uci set pbr.mwan4_ci.interface=dhcpwan; uci commit pbr")
        self.cmd("/etc/init.d/firewall restart", 80)
        self.cmd("/etc/init.d/pbr restart", 95)
        self.wait("ip -4 rule show | grep -q fwmark", 55)
        self.cmd("fw4 print >/tmp/mwan4-fw4.nft; test -s /tmp/mwan4-fw4.nft")
        self.cmd("nft list ruleset | grep -q pbr")
        self.cmd("/etc/init.d/mwan4 reload")
        self.cmd("grep -E 'policy_skip_mark_mask.*[1-9][0-9]*' /var/etc/mwan4.json")
        self.wait("pidof mwan4 >/dev/null", 45)
        print("PASS: real firewall4 + standalone PBR mark coexistence", flush=True)
        self.cmd("ifdown dhcpwan")
        self.wait('! ubus call network.interface.dhcpwan status | grep -q \'"up": true\'', 45)
        self.cmd("ifup dhcpwan")
        self.wait('ubus call network.interface.dhcpwan status | grep -q \'"up": true\'', 90)
        self.wait("pidof mwan4 >/dev/null", 45)
        print("PASS: DHCP WAN offline and reconnect", flush=True)
        self.cmd("/etc/init.d/mwan4 stop")
        self.wait("! pidof mwan4 >/dev/null", 35)
        self.cmd("! ip -4 route show table main default proto 77 | grep -q .")
        self.cmd("ip -4 rule show | grep -q fwmark")
        self.cmd("ip -4 route show table main default | grep -q .")
        print("PASS: OpenWrt guest route rollback keeps PBR and netifd", flush=True)

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


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--image", required=True)
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
