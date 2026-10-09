# Optional PBR interoperability

PBR is optional. MWAN4 alone provides health monitoring, ECMP, metric-tier
failover and native source/destination policies. Install PBR when matching
domains, ports, protocols, MACs or VPN destinations is useful.

Install OpenWrt's regular `pbr` and `luci-app-pbr` independently if desired.
Unmatched traffic still uses the Linux main-table ECMP route. Only traffic
matching actual PBR policies is marked/routed through PBR tables.

Run `/usr/libexec/mwan4-pbr-compat check` or `status` to inspect conflicts.

## Standalone mode (default)

`global.pbr_mode=standalone` works with the regular distro PBR package.
PBR creates its own per-interface tables and mark rules. With the optional
addon installed, native MWAN4 policies exclude PBR's mark mask. Unmarked
traffic keeps native policies and global ECMP. Standalone PBR manages its
own failure semantics; MWAN4 does not synchronize those external tables.

## mossdef consumer mode (experimental, IPv4)

The optional `mwan4-pbr-compat` 0.2.0 package now supplies the consumer API
used by [mossdef PBR 1.2.3](https://github.com/mossdef-org/pbr/tree/1.2.3):
`require('mwan4')`, interface marks and `mwan4_strategy_*` nft chain prefixes.
PBR owns packet matching; Rust owns the marked routes and health decisions.
This is an independently implemented adapter for our FIB data plane, not
a replacement of the Rust daemon with mossdef's ucode daemon.

Available PBR targets:

| Target | Behavior |
|---|---|
| `mwan4_strategy_balanced` | Current global main-table ECMP/metric tier |
| `mwan4_strategy_<logical-WAN>_prefer` | Preferred WAN while healthy; global ECMP when DOWN, degraded or missing |
| `<logical-WAN>` | Same preferred-WAN semantics for interfaces owned by the adapter |

`balanced` follows configured member metrics: equal lowest metrics share
traffic by weight; different metrics select the best available tier. It
does not turn a configured standby tier into load balancing.

Requirements: addon installed, PBR 1.2.3 consumer implementation, fw4 active,
all configured WANs using `option network`, at most 62 WANs, distinct logical
names containing letters/digits/underscores. Keep PBR `fw_mask=00ff0000`,
`uplink_mark=010000` and rule priority in 20000..31000. Widened PBR masks can
expand its cleanup range into other services' rules and are refused here.
PBR netifd extensions must be removed first; they take precedence over this
consumer API. Existing distro PBR 1.2.2 does not provide the strategy API.

After configuring and enabling PBR, opt in using LuCI's advanced **PBR
Integration** setting or:

```sh
uci set pbr.config.ipv6_enabled='0'
uci commit pbr
uci set mwan4.global.pbr_mode='mossdef'
uci commit mwan4
/etc/init.d/mwan4 reload
# PBR is reloaded after publishing the consumer chains/manifest.
/usr/libexec/mwan4-pbr-compat status
```

Example PBR rule (replace subnet and `unicom` with your actual logical WAN):

```uci
config policy 'downloads'
    option name 'Downloads prefer Unicom'
    option src_addr '192.168.1.100'
    option dest_port '80 443'
    option proto 'tcp'
    option interface 'mwan4_strategy_unicom_prefer'
```

Use PBR's resolver integration (e.g. dnsmasq nft sets) for domain matching;
MWAN4 does not perform DNS classification. Configure VPN targets in PBR
normally; interfaces outside MWAN4 continue to use PBR's standalone tables.

### Routing and lifecycle

The adapter owns mark bits `0x3f00`, preserving all other bits. Two IPv4 rules
per target at priorities 8000..8125 first consult main with the default
suppressed (protecting LAN/connected/VPN routes), then use the healthy WAN's
probe table or main-table fallback. Native policies remain at 9000..9063.
Fallback rules remain present when a target is unavailable, so a marked
flow cannot fall into an overlapping native source rule.

Logical targets and marks stay present across DHCP loss/PPPoE redial; only
the live device/table changes. Reordering or removing configured WANs can
change ordinal marks and requires reloading both services. No per-packet
userspace routing is introduced. The idempotent nft batch is included before
PBR's file on fw4 reload. Stopping MWAN4 removes its marked rules but retains
consumer chains, keeping PBR's existing goto references valid. Packets then
use restored/netifd main routing. Nothing enables PBR automatically.

To revert: stop PBR, set `pbr_mode=standalone`, reload MWAN4, then restart
PBR after replacing strategy targets with ordinary WAN/VPN interfaces.
The inert consumer chains can remain until their PBR references have been
removed; never delete a referenced chain while PBR is active.

### Current limits and hardware checks

- Integrated policy matching is IPv4 only. Enabling PBR IPv6 policies is
  refused; defensive IPv6 target chains drop traffic if an invalid external
  ruleset nevertheless references them. Ordinary IPv6 traffic is unaffected.
- Arbitrary member-subset strategies, strict WAN-only blackholes and per-host
  sticky-session policies are not implemented. `<WAN>_prefer` permits fallback;
  it must not be used as a VPN leak-prevention policy.
- PBR reload errors are retained in `/var/etc/mwan4-pbr/reload.log`. Health
  decisions still use IPv4 probes. Failure can reset existing NAT sessions.
- Test actual domain/port traffic, WAN loss/recovery, firewall reload and PPE
  counters on XG2010G. Kernel/VM success does not establish hardware offload.

## Opt-in PBR fwmark exclusion

In standalone mode the init script obtains PBR's `fw_mask` (default
`00ff0000`) and emits `policy_skip_mark_mask`; invalid/zero masks refuse start.
Native rules require masked mark zero, allowing selected packets to reach
PBR's later fwmark rules. Consumer mode also excludes `0x3f00`; its explicit
target rules take precedence. Unmarked traffic retains native policies/ECMP.
