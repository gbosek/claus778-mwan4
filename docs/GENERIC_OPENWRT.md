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

## PBR (optional; NOT yet integrated)

Existing OpenWrt PBR integration is specific to **mossdef's** mwan4 ucode/nft
API, not the claus778 Rust ECMP daemon. Do not enable their integration
against this backend without an adapter: it expects mark chains and
`require('mwan4')` that this backend does not provide.

A future optional adapter can leave unmatched traffic on native ECMP and
send only selected policies into separate routing tables. PBR is neither
installed nor enabled by this change.

## Safety and open issues

- `remove_routes_on_exit=0` is upstream's conservative default: stopping an
  already active daemon does **not** guarantee automatic restoration of the
  pre-mwan4 default route. Inspect `ip route` before/after rollback.
- This change does not implement IPv6 dynamic gateway discovery, since the
  upstream UCI generator does not yet export `gateway6`. Do not assume
  dual-WAN IPv6 works until it has been separately integrated and tested.
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
local UCI config on upgrades. Only enable after reviewing chosen WANs.
