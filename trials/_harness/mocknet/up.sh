#!/usr/bin/env bash
# Bring the fake Internet upstream up (idempotent: re-running repairs or
# skips whatever already exists). Needs root.
set -euo pipefail
D="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$D/mocknet.conf"
BIN="$D/bin/mocknet"
mkdir -p "$D/logs" "$D/pki" "$D/state"
say() { printf '[mocknet up] %s\n' "$*"; }
die() { printf '[mocknet up] ERROR: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "需要 root"

# 1. Build (only when sources changed).
if [ ! -x "$BIN" ] || [ -n "$(find "$D/src" -type f -newer "$BIN" 2>/dev/null)" ]; then
  say "building $BIN"
  (cd "$D/src" && CGO_ENABLED=0 GOFLAGS=-mod=mod GOPROXY=off go build -o "$BIN" .)
fi

# 2. PKI: the CA is created once and kept (so trust stays valid across
#    restarts); the leaf is re-issued when the host list changes.
ALL_HOSTS="$SYS_HOSTS $PRIVATE_HOSTS"
want_sans="$(echo $ALL_HOSTS | tr ' ' ',')"
if [ ! -f "$D/pki/ca.pem" ] || [ ! -f "$D/pki/leaf.pem" ] || [ "$(cat "$D/pki/leaf.hosts" 2>/dev/null)" != "$want_sans" ]; then
  "$BIN" pki -dir "$D/pki" -hosts "$want_sans"
  echo "$want_sans" > "$D/pki/leaf.hosts"
fi

# 3. Persistent network namespace for the server.
mkdir -p /run/netns
if ! nsenter --net="$NS_FILE" true 2>/dev/null; then
  say "creating network namespace $NS_FILE"
  umount "$NS_FILE" 2>/dev/null || true
  touch "$NS_FILE"
  unshare --net="$NS_FILE" true
fi

# 4. veth pair + addresses (both idempotent).
if ! [ -e "/sys/class/net/$HOST_IF" ]; then
  "$BIN" veth -host "$HOST_IF" -peer "$PEER_IF" -ns "$NS_FILE"
fi
"$BIN" ifup -if "$HOST_IF" -ip "$HOST_IP"
nsenter --net="$NS_FILE" "$BIN" ifup -if lo
nsenter --net="$NS_FILE" "$BIN" ifup -if "$PEER_IF" -ip "$MOCK_IP"

# 5. Server (detached from this session; survives logout).
health() {
  curl -sS --noproxy '*' -m 3 -o /dev/null -w '%{http_code}' --cacert "$D/pki/ca.pem" \
    --resolve "example.com:443:$MOCK_IP" -H 'User-Agent: mocknet-healthcheck' https://example.com/ 2>/dev/null | grep -q '^200$'
}
pid="$(cat "$D/state/server.pid" 2>/dev/null || true)"
if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && grep -q "mocknet" "/proc/$pid/cmdline" 2>/dev/null && health; then
  if [ "$BIN" -nt "/proc/$pid" ] || [ "$D/pki/leaf.pem" -nt "/proc/$pid" ]; then
    say "binary or certificate changed: restarting server"
    kill "$pid"; sleep 0.5; pid=""
  else
    say "server already running (pid $pid)"
  fi
else
  [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  pid=""
fi
if [ -z "$pid" ]; then
  # also catch a stray server left without a pidfile
  for p in $(pgrep -f "$BIN serve" || true); do kill "$p" 2>/dev/null || true; done
  sleep 0.3
  setsid -f bash -c 'echo $$ > "$1"; exec nsenter --net="$2" "$3" serve -ip "$4" -cert "$5/pki/leaf.pem" -key "$5/pki/leaf.key" -log "$5/logs/requests.jsonl"' \
    _ "$D/state/server.pid" "$NS_FILE" "$BIN" "$MOCK_IP" "$D" </dev/null >>"$D/logs/server.log" 2>&1
  for i in $(seq 1 50); do health && break; sleep 0.1; done
  health || die "server did not become healthy; see $D/logs/server.log"
  say "server started (pid $(cat "$D/state/server.pid"))"
fi

# 6. /etc/hosts block (system-wide names only; never api.anthropic.com).
tmp="$(mktemp)"
awk -v b="$HOSTS_MARK_BEGIN" -v e="$HOSTS_MARK_END" '$0==b{skip=1;next} $0==e{skip=0;next} !skip' /etc/hosts > "$tmp"
{ echo "$HOSTS_MARK_BEGIN"; echo "$MOCK_IP $SYS_HOSTS"; echo "$HOSTS_MARK_END"; } >> "$tmp"
if ! cmp -s "$tmp" /etc/hosts; then
  [ -f "$D/state/etc-hosts.orig" ] || cp -p /etc/hosts "$D/state/etc-hosts.orig"
  cat "$tmp" > /etc/hosts   # keep the inode (the file may be bind-mounted)
  say "/etc/hosts updated"
fi
rm -f "$tmp"

# 7. Gate-only name map (WARP_HOSTS_FILE): every mocked name, including
#    api.anthropic.com.
echo "$MOCK_IP $ALL_HOSTS" > "$D/hosts.warp"

# 8. System trust store.
if ! cmp -s "$D/pki/ca.pem" "$CA_SYS_FILE" 2>/dev/null; then
  cp "$D/pki/ca.pem" "$CA_SYS_FILE"
  update-ca-certificates >/dev/null 2>&1 || update-ca-certificates
  say "mock CA installed into the system trust store"
fi

# 9. Combined bundle for env.sh: system store (+ mock CA) + this machine's
#    agent-proxy bundle, so pointing SSL_CERT_FILE at it loses nothing.
{ cat /etc/ssl/certs/ca-certificates.crt; [ -f /root/.ccr/ca-bundle.crt ] && cat /root/.ccr/ca-bundle.crt; echo; cat "$D/pki/ca.pem"; } > "$D/pki/bundle.pem"

# 10. certifi copies of the machine's own Python installs (NOT the apps'
#     virtualenvs): append the mock CA between markers.
: > "$D/state/certifi-patched.list.new"
for py in /usr/local/bin/python3 /usr/bin/python3; do
  [ -x "$py" ] || continue
  for f in $("$py" -I -c 'import certifi;print(certifi.where())' 2>/dev/null) $(HOME=/root "$py" -c 'import certifi;print(certifi.where())' 2>/dev/null); do
    case "$f" in */scratchpad/trial/apps/*) continue;; esac
    [ -w "$f" ] || continue
    grep -qxF "$f" "$D/state/certifi-patched.list.new" && continue
    if ! grep -qF "$CERTIFI_MARK_BEGIN" "$f"; then
      { echo; echo "$CERTIFI_MARK_BEGIN"; cat "$D/pki/ca.pem"; echo "$CERTIFI_MARK_END"; } >> "$f"
      say "patched certifi bundle $f"
    fi
    echo "$f" >> "$D/state/certifi-patched.list.new"
  done
done
cat "$D/state/certifi-patched.list" "$D/state/certifi-patched.list.new" 2>/dev/null | sort -u > "$D/state/certifi-patched.list.tmp" || true
mv "$D/state/certifi-patched.list.tmp" "$D/state/certifi-patched.list"; rm -f "$D/state/certifi-patched.list.new"

# 11. Node.js inside warp: /usr/local/bin/node is a symlink into /opt, which
#     the warp shell does not mount, so `node` is "not found" in the shell.
#     Put a copy of the same binary under /usr and expose it as
#     /usr/local/sbin/node (first in the shell's fixed PATH). Outside warp the
#     agent PATH still finds /opt/node22/bin/node first; same version.
NODE_SRC="$(readlink -f "$(command -v node 2>/dev/null || echo /opt/node22/bin/node)")"
case "$NODE_SRC" in
  /opt/*)
    if ! cmp -s "$NODE_SRC" "$NODE_COPY" 2>/dev/null; then
      mkdir -p "$(dirname "$NODE_COPY")"; cp "$NODE_SRC" "$NODE_COPY.tmp" && mv "$NODE_COPY.tmp" "$NODE_COPY"
      say "copied $NODE_SRC -> $NODE_COPY"
    fi
    # Wrapper: inside the warp shell (hostname warp-shell) Node must be told
    # to honour HTTP(S)_PROXY (fetch/undici and http/https ignore it by
    # default, and warp does not set NODE_USE_ENV_PROXY). Outside the
    # shell it is a plain pass-through.
    wrapper="#!/bin/sh
# mocknet trial: node wrapper (managed by mocknet/up.sh, removed by down.sh)
if [ \"\$(cat /etc/hostname 2>/dev/null)\" = warp-shell ] && [ -n \"\${HTTPS_PROXY:-}\" ]; then
  export NODE_USE_ENV_PROXY=1
fi
exec $NODE_COPY \"\$@\""
    if [ ! -e "$NODE_LINK" ] || [ "$(readlink "$NODE_LINK")" = "$NODE_COPY" ] || grep -qs "mocknet trial: node wrapper" "$NODE_LINK"; then
      [ -L "$NODE_LINK" ] && rm -f "$NODE_LINK"
      printf '%s\n' "$wrapper" > "$NODE_LINK.tmp" && chmod 755 "$NODE_LINK.tmp" && mv "$NODE_LINK.tmp" "$NODE_LINK"
    else
      say "WARNING: $NODE_LINK exists and is not ours; left untouched"
    fi;;
esac

say "ready: $MOCK_IP serves: $ALL_HOSTS"
say "request log: $D/logs/requests.jsonl    (source $D/env.sh before running apps)"
