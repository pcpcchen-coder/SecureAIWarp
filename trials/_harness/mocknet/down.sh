#!/usr/bin/env bash
# Tear the fake upstream down completely: server, veth, network namespace,
# /etc/hosts block, system trust store entry, certifi patches.
# Keeps pki/ and logs/ unless --purge is given.
set -uo pipefail
D="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$D/mocknet.conf"
BIN="$D/bin/mocknet"
say() { printf '[mocknet down] %s\n' "$*"; }
[ "$(id -u)" = 0 ] || { echo "需要 root" >&2; exit 1; }

# Server
pid="$(cat "$D/state/server.pid" 2>/dev/null || true)"
[ -n "$pid" ] && kill "$pid" 2>/dev/null && say "stopped server pid $pid"
for p in $(pgrep -f "$BIN serve" || true); do kill "$p" 2>/dev/null && say "stopped stray server pid $p"; done
rm -f "$D/state/server.pid"

# veth + namespace (deleting the namespace also deletes the peer)
if [ -e "/sys/class/net/$HOST_IF" ]; then "$BIN" dellink -if "$HOST_IF" && say "deleted $HOST_IF"; fi
if [ -e "$NS_FILE" ]; then umount "$NS_FILE" 2>/dev/null; rm -f "$NS_FILE" && say "removed $NS_FILE"; fi

# /etc/hosts: drop only our marked block
if grep -qF "$HOSTS_MARK_BEGIN" /etc/hosts; then
  tmp="$(mktemp)"
  awk -v b="$HOSTS_MARK_BEGIN" -v e="$HOSTS_MARK_END" '$0==b{skip=1;next} $0==e{skip=0;next} !skip' /etc/hosts > "$tmp"
  cat "$tmp" > /etc/hosts; rm -f "$tmp"
  say "/etc/hosts block removed"
fi
rm -f "$D/state/etc-hosts.orig"

# System trust store
if [ -f "$CA_SYS_FILE" ]; then
  rm -f "$CA_SYS_FILE"
  update-ca-certificates --fresh >/dev/null 2>&1 || update-ca-certificates --fresh
  say "mock CA removed from the system trust store"
fi

# certifi patches
for f in $(cat "$D/state/certifi-patched.list" 2>/dev/null); do
  [ -f "$f" ] && grep -qF "$CERTIFI_MARK_BEGIN" "$f" || continue
  tmp="$(mktemp)"
  awk -v b="$CERTIFI_MARK_BEGIN" -v e="$CERTIFI_MARK_END" '$0==b{skip=1;next} $0==e{skip=0;next} !skip' "$f" > "$tmp"
  # drop the blank line up.sh added before the block
  python3 -I -c 'import sys;p=sys.argv[1];s=open(p).read();open(p,"w").write(s[:-1] if s.endswith("\n\n") else s)' "$tmp"
  cat "$tmp" > "$f"; rm -f "$tmp"
  say "restored certifi bundle $f"
done
rm -f "$D/state/certifi-patched.list" "$D/hosts.warp" "$D/pki/bundle.pem"

# Node copy for the warp shell
if [ "$(readlink "$NODE_LINK" 2>/dev/null)" = "$NODE_COPY" ] || grep -qs "mocknet trial: node wrapper" "$NODE_LINK"; then rm -f "$NODE_LINK"; say "removed $NODE_LINK"; fi
if [ -e "$NODE_COPY" ]; then rm -f "$NODE_COPY"; rmdir "$(dirname "$NODE_COPY")" 2>/dev/null; say "removed $NODE_COPY"; fi

if [ "${1:-}" = "--purge" ]; then
  rm -rf "$D/pki" "$D/logs" "$D/state"
  say "purged pki/, logs/, state/"
fi
say "done"
