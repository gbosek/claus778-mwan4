#!/bin/sh
# Privileged Linux network namespace regression for native ECMP/PBR FIB.
# Runs on CI Ubuntu with CAP_NET_ADMIN. No host networking is modified.
set -eu
command -v ip >/dev/null 2>&1 || { echo "SKIP: iproute2 required"; exit 77; }
[ "$(id -u)" = 0 ] || { echo "SKIP: requires root/CAP_NET_ADMIN"; exit 77; }
ns="mwan4-regression-$$"
tmp="$(mktemp -d)"
cleanup() { ip netns del "$ns" 2>/dev/null || :; rm -rf "$tmp"; }
trap cleanup EXIT HUP INT TERM
if ! ip netns add "$ns"; then echo "SKIP: cannot create network namespace"; exit 77; fi
ip -n "$ns" link set lo up
ip -n "$ns" link add wan_a type veth peer name gw_a
ip -n "$ns" link add wan_b type veth peer name gw_b
for dev in wan_a wan_b gw_a gw_b; do ip -n "$ns" link set "$dev" up; done
ip -n "$ns" addr add 198.51.100.2/24 dev wan_a
ip -n "$ns" addr add 198.51.100.1/24 dev gw_a
ip -n "$ns" addr add 203.0.113.2/24 dev wan_b
ip -n "$ns" addr add 203.0.113.1/24 dev gw_b
ip -n "$ns" addr add 192.0.2.2/32 dev lo
ip -n "$ns" -6 addr add 2001:db8:a::2/64 dev wan_a
ip -n "$ns" -6 addr add 2001:db8:a::1/64 dev gw_a
ip -n "$ns" -6 addr add 2001:db8:b::2/64 dev wan_b
ip -n "$ns" -6 addr add 2001:db8:b::1/64 dev gw_b
# Netifd-like baseline default routes: save before installing ECMP.
ip -n "$ns" -4 route add default via 198.51.100.1 dev wan_a metric 100
ip -n "$ns" -4 route add default via 203.0.113.1 dev wan_b metric 200
ip -n "$ns" -6 route add default via 2001:db8:a::1 dev wan_a metric 100
ip -n "$ns" -4 route save table main default > "$tmp/default4.bin"
ip -n "$ns" -6 route save table main default > "$tmp/default6.bin"
[ -s "$tmp/default4.bin" ] && [ -s "$tmp/default6.bin" ]
# ECMP routes are marked RTPROT_MWAN4 (77) and a lower metric.
ip -n "$ns" -4 route add default proto 77 metric 10 \
    nexthop via 198.51.100.1 dev wan_a weight 2 \
    nexthop via 203.0.113.1 dev wan_b weight 1
ip -n "$ns" -6 route add default via 2001:db8:b::1 dev wan_b proto 77 metric 10
ip -n "$ns" -4 route show table main default proto 77 | grep -q 'nexthop'
ip -n "$ns" -6 route show table main default proto 77 | grep -q 'wan_b'
# Marked flows choose PBR's dedicated table BEFORE native mwan4 policy 9000.
ip -n "$ns" -4 route add default via 203.0.113.1 dev wan_b table 201
ip -n "$ns" -4 route add default via 198.51.100.1 dev wan_a table 202
ip -n "$ns" -4 rule add pref 8500 fwmark 0x10000/0xff0000 lookup 201
ip -n "$ns" -4 rule add pref 9000 from 192.0.2.0/24 lookup 202
marked="$(ip -n "$ns" -4 route get 8.8.8.8 from 192.0.2.2 mark 0x10000)"
printf '%s\n' "$marked" | grep -q 'dev wan_b'
unmarked="$(ip -n "$ns" -4 route get 8.8.8.8 from 192.0.2.2)"
printf '%s\n' "$unmarked" | grep -q 'dev wan_a'
# Removing only proto-77 default routes MUST NOT touch PBR's table 201/rule.
ip -n "$ns" -4 route flush table main default proto 77
ip -n "$ns" -6 route flush table main default proto 77
ip -n "$ns" -4 route restore < "$tmp/default4.bin"
ip -n "$ns" -6 route restore < "$tmp/default6.bin"
ip -n "$ns" -4 route show table main default | grep -q 'metric 100'
ip -n "$ns" -6 route show table main default | grep -q 'metric 100'
ip -n "$ns" -4 rule show | grep -q '8500:'
ip -n "$ns" -4 route show table 201 | grep -q 'wan_b'
# PBR remains the exception; main route remains the unmarked default.
ip -n "$ns" -4 route get 8.8.8.8 mark 0x10000 | grep -q 'wan_b'
ip -n "$ns" -4 route get 8.8.8.8 | grep -q 'wan_a'
echo "PASS: kernel ECMP, PBR precedence, IPv4/IPv6 route save/restore and isolation"
