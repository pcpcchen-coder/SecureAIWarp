# source this file:  source <TRIAL>/mocknet/env.sh
# Settings for running apps against the mocknet fake upstream, with or
# without warp. (Run up.sh first.)
MOCKNET_DIR="<TRIAL>/mocknet"
export MOCKNET_DIR
. "$MOCKNET_DIR/mocknet.conf"

# --- for warp (the gate runs on the host and reads these) ---------------
# Gate name map: every mocked host, including api.anthropic.com (which is
# deliberately NOT in /etc/hosts because Claude Code on this machine uses the
# real one). Without it, warp would send api.anthropic.com to the real API.
export WARP_HOSTS_FILE="$MOCKNET_DIR/hosts.warp"

# --- trust: the gate's upstream TLS check and every client outside warp --
# This machine's agent environment pins SSL_CERT_FILE / REQUESTS_CA_BUNDLE /
# NODE_EXTRA_CA_CERTS to the agent-proxy bundle, which does not contain the
# mock CA. bundle.pem = system store (already incl. mock CA) + that bundle.
export SSL_CERT_FILE="$MOCKNET_DIR/pki/bundle.pem"      # OpenSSL (curl, Python ssl/urllib/httpx), Go, warp's gate, Node with --use-openssl-ca
export REQUESTS_CA_BUNDLE="$SSL_CERT_FILE"              # Python requests (otherwise uses certifi)
export CURL_CA_BUNDLE="$SSL_CERT_FILE"
export NODE_EXTRA_CA_CERTS="$SSL_CERT_FILE"             # Node.js (fetch/https/axios...) without --use-openssl-ca

# --- outside warp: do not send mocked hosts to the agent proxy -----------
# HTTPS_PROXY on this machine points at an agent proxy that resolves names
# itself and reaches the REAL Internet. Mocked hosts must bypass it.
_mn_np="$(echo $SYS_HOSTS $PRIVATE_HOSTS | tr ' ' ',')"
for _v in NO_PROXY no_proxy; do
  _cur="$(eval echo "\${$_v:-}")"
  case ",$_cur," in *",geocoding-api.open-meteo.com,"*) ;; *) export "$_v=${_cur:+$_cur,}$_mn_np";; esac
done
unset _v _cur _mn_np

# --- Anthropic SDK -------------------------------------------------------
# The machine sets ANTHROPIC_BASE_URL for Claude Code itself. Apps must use
# the SDK default (https://api.anthropic.com), so drop it here. warp never
# passes it into the shell anyway (the shell environment is built from
# scratch).
unset ANTHROPIC_BASE_URL

# Outside warp, api.anthropic.com only reaches the mock through:
#   "$MOCKNET_DIR/bin/mockrun" <command...>
# (private /etc/hosts in a throw-away mount namespace).
