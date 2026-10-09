#!/bin/sh
# Privileged Linux network namespace regression for native ECMP/PBR FIB.
# Runs on CI Ubuntu with CAP_NET_ADMIN. No host networking is modified.
set -eu
command -v ip >/dev/null 2>&1 || { echo "SKIP: iproute2 required"; exit 77; }
[ "$(id -u)" = 0 ] || { echo "SKIP: requires root/CAP_NET_ADMIN"; exit 77; }
ns="mwan4-regression-$"
gw="${ns}-gw"
tmp="$(mktemp -d)"
cleanup() {
    ip netns del "$ns" 2>/dev/null || :
    ip netns del "$gw" 2>/dev/null || :
    rm -rf "$tmp"
}
trap cleanup EXIT HUP INT TERM
if ! ip netns add "$ns"; then echo "SKIP: cannot create WAN namespace"; exit 77; fi
if ! ip netns add "$gw"; then echo "SKIP: cannot create gateway namespace"; exit 77; fi
ip -n "$ns" link set lo up
ip -n "$gw" link set lo up
ip -n "$ns" link add wan_a type veth peer name gw_a
ip -n "$ns" link add wan_b type veth peer name gw_b
# Peer gateways must be in a DIFFERENT network namespace. A gateway IP
# configured locally is rejected by the kernel (observed in CI #1).
ip -n "$ns" link set gw_a netns "$gw"
ip -n "$ns" link set gw_b netns "$gw"
for dev in wan_a wan_b; do ip -n "$ns" link set "$dev" up; done
for dev in gw_a gw_b; do ip -n "$gw" link set "$dev" up; done
ip -n "$ns" addr add 198.51.100.2/24 dev wan_a
ip -n "$gw" addr add 198.51.100.1/24 dev gw_a
ip -n "$ns" addr add 203.0.113.2/24 dev wan_b
ip -n "$gw" addr add 203.0.113.1/24 dev gw_b
ip -n "$ns" addr add 192.0.2.2/32 dev lo
ip -n "$ns" -6 addr add 2001:db8:a::2/64 dev wan_a
ip -n "$gw" -6 addr add 2001:db8:a::1/64 dev gw_a
ip -n "$ns" -6 addr add 2001:db8:b::2/64 dev wan_b
ip -n "$gw" -6 addr add 2001:db8:b::1/64 dev gw_b
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
# A marked flow skips mwan4's native priority-9000 policy and reaches PBR's
# ordinary later priority-30000 rule. Other traffic uses the native policy.
ip -n "$ns" -4 route add default via 203.0.113.1 dev wan_b table 201
ip -n "$ns" -4 route add default via 198.51.100.1 dev wan_a table 202
ip -n "$ns" -4 rule add pref 9000 from 192.0.2.0/24 fwmark 0x0/0xff0000 lookup 202
ip -n "$ns" -4 rule add pref 30000 fwmark 0x10000/0xff0000 lookup 201
marked="$(ip -n "$ns" -4 route get 8.8.8.8 from 192.0.2.2 mark 0x10000)"
printf '%s\n' "$marked" | grep -q 'dev wan_b'
unmarked="$(ip -n "$ns" -4 route get 8.8.8.8 from 192.0.2.2)"
printf '%s\n' "$unmarked" | grep -q 'dev wan_a'
# Optional real nft batch emitted by our ucode renderer. Exercise a packet
# through the PBR-consumer goto chain and preserve an unrelated mark bit.
if [ -n "${1:-}" ]; then
    ip netns exec "$ns" nft add table inet fw4
    ip netns exec "$ns" nft -f "$1"
    ip netns exec "$ns" nft -f "$1" # idempotent firewall reload
    ip netns exec "$ns" nft add chain inet fw4 pbr_test_output '{ type route hook output priority mangle; policy accept; }'
    ip netns exec "$ns" nft add rule inet fw4 pbr_test_output ip daddr 203.0.113.1 meta mark set 0x40000000 goto mwan4_strategy_unicom_prefer_ipv4
    ip netns exec "$ns" nft add chain inet fw4 pbr_test_check '{ type filter hook postrouting priority filter; policy accept; }'
    ip netns exec "$ns" nft add rule inet fw4 pbr_test_check meta mark 0x40000200 oifname wan_b counter
    ip netns exec "$ns" ping -c 1 -W 2 203.0.113.1 >/dev/null
    ip netns exec "$ns" nft list chain inet fw4 pbr_test_check | grep -q 'counter packets 1'
    echo "PASS: actual nft consumer packet, unrelated mark preserved, idempotent reload"
fi
# Removing only proto-77 default routes MUST NOT touch PBR's table 201/rule.
ip -n "$ns" -4 route flush table main default proto 77
ip -n "$ns" -6 route flush table main default proto 77
ip -n "$ns" -4 route restore < "$tmp/default4.bin"
ip -n "$ns" -6 route restore < "$tmp/default6.bin"
ip -n "$ns" -4 route show table main default | grep -q 'metric 100'
ip -n "$ns" -6 route show table main default | grep -q 'metric 100'
ip -n "$ns" -4 rule show | grep -q '30000:'
ip -n "$ns" -4 route show table 201 | grep -q 'wan_b'
# PBR remains the exception; main route remains the unmarked default.
ip -n "$ns" -4 route get 8.8.8.8 mark 0x10000 | grep -q 'wan_b'
ip -n "$ns" -4 route get 8.8.8.8 | grep -q 'wan_a'
echo "PASS: kernel ECMP, PBR precedence, IPv4/IPv6 route save/restore and isolation"
