#!/bin/sh
# Check the read-only helper without touching host nftables.
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
tr -d '\r' < "$ROOT/openwrt/mwan4-pbr-compat/files/usr/libexec/mwan4-pbr-compat" > "$tmp/helper"
cat > "$tmp/nft" <<'EOF'
#!/bin/sh
[ "$*" = 'list table inet mwan3' ] || exit 2
exit "$MOCK_NFT_RC"
EOF
chmod +x "$tmp/nft"
export PATH="$tmp:$PATH" MOCK_NFT_RC=0
if sh "$tmp/helper" check-mark-owner; then
    echo 'accepted a competing mwan3 table' >&2; exit 1
fi
# No competing table or running service on the isolated CI test host.
MOCK_NFT_RC=1
sh "$tmp/helper" check-mark-owner
set -- check-mark-owner
. "$tmp/helper"
for value in 1 2 yes on true; do is_enabled "$value"; done
for value in 0 no off false ''; do
    if is_enabled "$value"; then
        echo "accepted disabled flag: $value" >&2; exit 1
    fi
done
echo 'PASS: competing mwan3 table refused, only read-only nft lookup used'
