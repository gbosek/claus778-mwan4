#!/bin/sh
# Test safe first-run and netifd logical WAN mapping without OpenWrt.
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
. "$ROOT/openwrt/luci-app-mwan4/root/etc/init.d/mwan4"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
CONF_DIR="$TMP"
CONF_FILE="$TMP/mwan4.json"
MOCK_ENABLED=0
MOCK_IF=0
MOCK_NETWORK=""
MOCK_NAME=""
MOCK_GATEWAY=""
MOCK_L3=""
MOCK_NETGW=""
MOCK_POLICY=0
logger() { :; }
config_get_bool() {
    local out="$1" section="$2" key="$3" val="$4"
    if [ "$section:$key" = "global:enabled" ]; then val="$MOCK_ENABLED"; fi
    eval "$out=\$val"
}
config_get() {
    local out="$1" section="$2" key="$3" val="${4:-}"
    if [ "$section" = "testwan" ]; then
        case "$key" in
            network) val="$MOCK_NETWORK" ;;
            name) val="$MOCK_NAME" ;;
            gateway) val="$MOCK_GATEWAY" ;;
            enabled) val=1 ;;
        esac
    fi
    if [ "$section" = "testpolicy" ]; then
        case "$key" in
            interface) val="testwan" ;;
            name) val="myrule" ;;
        esac
    fi
    eval "$out=\$val"
}
config_foreach() {
    case "$2" in
        interface) [ "$MOCK_IF" = 1 ] && "$1" testwan || : ;;
        policy) [ "$MOCK_POLICY" = 1 ] && "$1" testpolicy || : ;;
    esac
}
config_list_foreach() {
    [ "$2" = "probe_targets" ] && "$3" "1.1.1.1:53" || :
}
network_get_device() {
    [ -n "$MOCK_L3" ] || return 1
    local out="$1" val="$MOCK_L3"
    eval "$out=\$val"
}
network_get_gateway() {
    [ -n "$MOCK_NETGW" ] || return 1
    local out="$1" val="$MOCK_NETGW"
    eval "$out=\$val"
}
assert_empty() {
    [ ! -e "$CONF_FILE" ] || { echo "unexpected config file" >&2; exit 1; }
}
# Disabled installation with no interfaces
generate_json_config && exit 1 || :
assert_empty
# Enabled but with no interfaces: leave kernel routing untouched
MOCK_ENABLED=1
generate_json_config && exit 1 || :
assert_empty
# An explicit manual device remains supported
MOCK_IF=1
MOCK_NAME="eth7"
generate_json_config
python3 - "$CONF_FILE" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert len(d["interfaces"]) == 1
assert d["interfaces"][0]["name"] == "eth7"
assert d["interfaces"][0]["gateway"] is None
PY
# A logical network overrides the stale/legacy device and discovers gateway
MOCK_NETWORK="wan"
MOCK_L3="pppoe-wan"
MOCK_NETGW="198.51.100.1"
MOCK_POLICY=1
generate_json_config
python3 - "$CONF_FILE" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["interfaces"][0]["name"] == "pppoe-wan"
assert d["interfaces"][0]["gateway"] == "198.51.100.1"
assert d["policies"][0]["interface"] == "pppoe-wan"
PY
# PPPoE has no default gateway, and the device still works.
MOCK_NETGW=""
generate_json_config
python3 - "$CONF_FILE" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["interfaces"][0]["gateway"] is None
PY
# Before the logical L3 device exists, do not silently bind Ethernet.
MOCK_L3=""
generate_json_config && exit 1 || :
assert_empty
echo "PASS: disabled, empty, manual, dynamic PPPoE and policy mapping"
