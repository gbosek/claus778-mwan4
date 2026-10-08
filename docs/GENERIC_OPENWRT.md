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
