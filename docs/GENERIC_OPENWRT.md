# Generic mwan4 / OpenWrt integration (experimental)

This fork keeps claus778's native Linux FIB/ECMP data plane. It does **not**
depend on Airoha, PON, a particular number of WANs, or a fixed IP address.

## Safe first installation

- `/etc/config/mwan4` contains **no WAN sections** and `global.enabled=0`.
- The service does not start until explicitly enabled **and** at least one
  usable WAN is resolved. A missing/down logical interface is skipped.
- Installing the package does not automatically change the default route.
- In LuCI, add any number of user-selected WANs and then enable mwan4.
- Do not switch a production router to mwan4 without backup and console access.
- Disable competing multi-WAN daemons (mwan3, the different mossdef mwan4);
  their route ownership and configuration formats are incompatible.

## Interface configuration

Recommended: `config interface 'uplink'` with `option network 'wan'`.
Here `wan` is an **existing OpenWrt UCI logical interface**.
On start/reload the init script uses `network_get_device()` and
`network_get_gateway()` from `/lib/functions/network.sh` to discover the
actual L3 netdev and gateway. The latter may be absent (common for PPPoE).
A configured `option gateway` overrides netifd's discovered value.

Backward-compatible mode: `option name 'ethX'` with no `option network`.
This is a Linux kernel netdev; it is **not** an OpenWrt logical interface.
When both are present, `option network` takes precedence.

Link status changes on configured logical interfaces trigger a service reload.
When no usable WAN exists, no route is installed. An off-line WAN is
reconsidered on the next corresponding netifd event.

## Routing policies

UCI policies still use `option interface '<WAN section name>'`.
The init script resolves this section to a current kernel device before
handing policies to Rust. Old configurations directly naming an interface
device remain supported. A policy pointing at an inactive configured logical
WAN is deferred until that WAN comes online.

## PBR (optional)

Standalone distro PBR is supported with optional mark exclusion. The optional
`mwan4-pbr-compat` adapter also offers an explicit IPv4 consumer mode for
mossdef PBR 1.2.3, exposing balanced and preferred-WAN targets while keeping
Rust health management and FIB/ECMP routing. See [configuration and limits](PBR_COMPAT.md).

## Safety and open issues

- `remove_routes_on_exit=0` is upstream's conservative default: stopping an
  already active daemon does **not** guarantee automatic restoration of the
  pre-mwan4 default route. Inspect `ip route` before/after rollback.
- IPv6 gateway discovery is supported as described below. Independent IPv6
  health and integrated PBR IPv6 targets still require separate development.
- Flow offload and hardware acceleration vary by driver; this code does not
  claim hardware ECMP offload.
- In-progress IPv4 connections may reset when a WAN fails or NAT changes.

## IPv6 automatic gateway (experimental)

Choose a logical `network` interface in LuCI. On a reload, the script uses
`network_get_gateway6()` to look up the active IPv6 default gateway. For
OpenWrt configurations with an independent `wan6` interface, set
`option network6 'wan6'`. IPv6 management is allowed only when its
resolved L3 device matches the selected IPv4 WAN L3 device. If netifd
has no gateway, IPv4 remains active and this WAN is excluded from IPv6
ECMP (the Rust backend requires `gateway6` for multipath).

The Rust daemon still uses IPv4 health probes for IPv6 availability.
Independent IPv6 health tracking is a separate future enhancement.

## Default-route recovery (experimental)

For a configured/enabled installation, the init script saves the existing
IPv4 and IPv6 main-table default routes using `ip-full route save` before
starting the daemon. Snapshots live under `/var/run/mwan4-route-backup`
and survive procd reloads but not reboots.

On an explicit `/etc/init.d/mwan4 stop`, rc.common calls
`service_stopped()` **after** killing the daemon. That hook removes only
the daemon's `proto 77` *default* routes in `main` and restores the
snapshot with `ip route restore`. No PBR table is flushed.

If no previous default was saved, the script deliberately leaves the
active route alone to avoid disconnecting an administrator. If restoring
fails, the snapshot is preserved and a warning logged. As with all route
restoration, an obsolete gateway after DHCP/PPPoE churn can fail to
restore; inspect the logged failure and let netifd reacquire the route.

This fork adds an explicit `reload_service()` path because OpenWrt's
default procd reload skips `service_stopped()`. It stops the old
instance, restores default-route snapshots, and then runs
`rc_procd start_service` with new interface state. A SIGKILL cannot
invoke a Rust shutdown handler, and route snapshots can become stale when
DHCP/PPPoE gateways change; kernel namespace and router tests remain
required for complete recovery assurance.

Package installation must never enable mwan4 automatically. Preserve
local UCI config on upgrades. The package installs
`/lib/upgrade/keep.d/mwan4`, which adds `/etc/config/mwan4` to the backup list
for subsequent `sysupgrade` runs. Install this release before the next
firmware upgrade; an explicit `sysupgrade -n` still discards configuration.
Only enable after reviewing chosen WANs.

## Source audit follow-up

- Rust policy sweep now drains all protocol-tagged rules for a reserved
  priority, as policy expansion may generate multiple rules per priority.
- The old checked-in `dist/install.sh` was intentionally disabled because it
  predated safe-first-run and still enabled the daemon automatically. Build
  fresh packages from current sources rather than using repository `dist/`.
- Kernel-mutating Rust netns tests now require a different network namespace
  from PID 1 **in addition to** `MWAN4_NETNS_TEST=1`; do not run privileged
  tests on a production router.
- The JSON status key is now `load_shifted`, not `offloaded`. It represents
  dynamic traffic shifting and does not imply hardware flow offload.

## Non-destructive default route takeover (routing metric check)

Before starting the daemon, OpenWrt init checks both families in the main
routing table. If a non-mwan4 default has a metric **less than or equal**
to `global.route_priority` (default 0), start is refused. This protects
existing netifd defaults against same-metric replacement and guarantees
that a higher-priority ECMP route will actually be used.

Configure the original WAN interfaces in `/etc/config/network` to have
metrics larger than the chosen mwan4 default (e.g. netifd 100/200,
mwan4 10); this must be an explicit user decision, never an installer side
effect. A disabled/unconfigured installation does not inspect or alter any
default routes.

On stop or reload, owned proto-77 default routes are removed first. If a
fresh netifd default remains present, the saved route is discarded rather
than replaying a stale PPPoE/DHCP gateway. The save/restore binary is
an emergency fallback **only** when no current default exists. Gateway
churn and no-default emergency recovery still require real-device tests.
