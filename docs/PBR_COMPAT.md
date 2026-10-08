# Optional PBR interoperability

This is an **opt-in diagnostics adapter** for claus778's Rust/FIB mwan4.

Install OpenWrt's regular `pbr` and `luci-app-pbr` independently if desired.
Unmatched traffic still uses the Linux main-table ECMP route. Only traffic
matching actual PBR policies is marked/routed through PBR tables.

Run `/usr/libexec/mwan4-pbr-compat check` or `status` to inspect conflicts.

Unlike mossdef's mwan4, claus778 does not provide ucode
`require('mwan4')`, `mwan4_strategy_*` nft chains, or a shared fwmark mask.
Therefore PBR targets named `mwan4_strategy_*` **are not supported**.

This addon does **not yet perform policy synchronization** when WANs fail,
and does not validate that every PBR policy is reachable. It installs no
firewall rules, modifies no network settings and remains safe when PBR is
absent (the check command simply reports it).

Recommended development sequence:
1. Validate standalone PBR's existing per-interface routing tables and
   nft mark rules while ECMP is enabled.
2. Verify that non-matching packets remain unmarked in mwan4's data plane.
3. Verify WAN fail/recovery with selected policies before adding automatic
   suppression/reinstatement or more advanced LuCI support.

## Opt-in PBR fwmark exclusion

Install `mwan4-pbr-compat` separately and enable standalone OpenWrt PBR. With both present, the init script obtains PBR's `fw_mask` (default `00ff0000`) and emits `policy_skip_mark_mask` to the Rust daemon; invalid or zero masks cause start refusal. The Rust netlink rule for native source/destination policies then includes FWMARK=0 and FWMASK=<mask>. PBR-marked packets skip native priority 9000 policies and reach PBR's own later fwmark rules. Unmarked packets keep native policies/default ECMP; the adapter changes neither PBR configuration nor priorities. On PBR UCI changes mwan4 reloads, but real netifd/PBR service race conditions need testing. This is not full PBR strategy group synchronization.
