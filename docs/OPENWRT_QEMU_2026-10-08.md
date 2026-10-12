# OpenWrt QEMU integration verification — 2026-10-08

## Verified run

- **Successful QEMU CI**: https://github.com/gbosek/claus778-mwan4/actions/runs/37757231624
- **Successful regular CI (same commit)**: https://github.com/gbosek/claus778-mwan4/actions/runs/37757231681
- **Verified revision**: `11e0b1aed1041a8e055a129024a189e2849a338c`
- Test OS: **official OpenWrt 24.10.5 x86_64 ext4 + matching kernel**, QEMU TCG, serial ttyS0; host TAP PPPoE server and isolated DHCP LAN, real guest netifd/procd/firewall4/pbr. No production router touched.

## Real guest checkpoints (all succeeded)

1. Keep QEMU management default route for package feeds, leaving the isolated DHCP test network unable to hijack internet routing.
2. Retrieve OpenWrt package indices and install `ppp`, `ppp-mod-pppoe`, `ip-full`, `nftables-json` and standalone `pbr`.
3. Confirm mwan4's factory UCI config has **global.enabled=0** and no WAN interfaces or owned routes.
4. Establish a real PPPoE session against the TAP-backed Linux `pppoe-server`; resolve the actual kernel L3 device from netifd.
5. Configure two logical WANs and start the actual musl Rust `mwan4` process via OpenWrt procd; validate its generated JSON and installed `proto 77` default route.
6. Perform PPPoE ifdown/ifup; confirm netifd UP and eventual regenerated mwan4 JSON references the active L3 device (asynchronous reload may take seconds).
7. Install and activate real firewall4 + PBR with `pbr.config.uplink_interface='mgmt'`, `dhcpwan`/ `pppwan` explicitly supported, and a source CIDR policy; verify PBR fwmark rules, nft rules, and mwan4 `policy_skip_mark_mask` after reload.
8. DHCP WAN ifdown/ifup; confirm process survived or was restarted and returned to serving.
9. Stop mwan4; verify process exited, owned `proto 77` default routes are gone, a netifd default remains, and standalone PBR mark rules survive.

## Differences from earlier failing runs

- Official QEMU image must provide an interactive ttyS0 console and handle the initial `root@(none)` prompt.
- BusyBox ash serial line inputs are bounded. Commands ending in `&` must **not** have an extra semicolon before the exit-code sentinel.
- The simulated DHCP WAN gateway has **no Internet**. Keep `dhcpwan.defaultroute=0` while running `opkg`, with management NAT as the Internet path; re-enable the isolated WAN route after installation.
- Minimal OpenWrt lacks a `timeout` binary. Package installation runs in background ash subprocesses, with a host-side deadline and diagnostic logs.
- netifd/procd logical-device refresh is asynchronous; tests poll with an upper bound and print diagnostics on failure.
- Standalone PBR defaults to literal UCI `wan`. For this generic-interface VM, explicitly set PBR uplink `mgmt` and register `dhcpwan`/`pppwan` as supported.

## What passing CI does NOT prove

- The test checks nft/PBR rule presence and coexistence, **not yet packet-level policy matching** on live forwarded TCP/UDP flows. ECMP versus PBR exception behavior needs actual packet tests and conntrack inspection.
- No independent IPv6 WAN failure, IPv6 PD, or IPv6 source/destination policy round-trip has been tested.
- No SIGKILL, kernel crash, instantaneous all-WAN-down failover, long-running route convergence, DHCP gateway *change* (rather than interface flap), or full hardware restart soak tests have been performed.
- No flowtable/NPU/PPE hardware offload is implied by ECMP, the Rust binary, or QEMU tests.
- No production firmware was flashed, and no standard OpenWrt Buildroot Rust package installation / package feed validation is implied by staging an actual binary and init files into the guest.

**Release gate**: keep PR as Draft. Continue packet-level PBR matching, IPv6 health, abnormal service-stop, and device-specific offload checks before production use.
