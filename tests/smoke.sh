#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# End-to-end smoke test of this image (MCP gateway and viewer) with the
# engines it needs: containers of the ingetrazo-docker image, one per
# service, on a data folder with one of IngeTrazo's example models.
#
#   IMAGE=ingetrazo-web-viewer:dev ENGINE_IMAGE=ghcr.io/bastelbaus/ingetrazo:dev tests/smoke.sh
set -euo pipefail
# Git Bash on Windows would rewrite container paths such as /opt/… .
export MSYS_NO_PATHCONV=1

IMAGE="${IMAGE:-ingetrazo-web-viewer:dev}"
ENGINE_IMAGE="${ENGINE_IMAGE:-ghcr.io/bastelbaus/ingetrazo:dev}"
TOKEN="smoke-$(date +%s)-token-0123456789"
ETOKEN="smoke-engine-$(date +%s)-0123456789"
PASSWORD="smoke-password"
OAUTH_PASSWORD="smoke-oauth-password"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${SMOKE_WORKDIR:-$(mktemp -d)}"
PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null 2>&1 || PY=python
P="smoke-$$"
net="$P-net"
SUB="10.231.$((RANDOM % 200 + 20))"

MCP_PORT="${SMOKE_MCP_PORT:-18765}"
OAUTH_PORT="${SMOKE_OAUTH_PORT:-18766}"
FOLDERS_MCP_PORT="${SMOKE_FOLDERS_MCP_PORT:-18767}"
VIEWER_PORT="${SMOKE_VIEWER_PORT:-18080}"
NONE_PORT="${SMOKE_NONE_PORT:-18081}"
PROXY_PORT="${SMOKE_PROXY_PORT:-18082}"
OIDC_VIEWER_PORT="${SMOKE_OIDC_VIEWER_PORT:-18083}"
OIDC_PORT="${SMOKE_OIDC_PORT:-18084}"
FOLDERS_VIEWER_PORT="${SMOKE_FOLDERS_VIEWER_PORT:-18085}"

# Docker Desktop on Windows (Git Bash) wants a Windows path for -v.
host_path() { (cd "$1" && (pwd -W 2>/dev/null || pwd)); }

started=()
cleanup() {
  status=$?
  if [ $status -ne 0 ]; then
    for c in "${started[@]}"; do
      echo "---- logs: $c ----"; docker logs "$c" 2>&1 | tail -40 || true
    done
  fi
  if [ ${#started[@]} -gt 0 ]; then docker rm -f -v "${started[@]}" >/dev/null 2>&1 || true; fi
  docker network rm "$net" >/dev/null 2>&1 || true
  exit $status
}
trap cleanup EXIT

# engine NAME MODE [docker run args…]: an ingetrazo-docker engine on $net.
engine() {
  local name="$1" mode="$2"; shift 2
  docker run -d --name "$name" --network "$net" -e ENGINE_MODE="$mode" \
    -e ENGINE_TOKEN="$ETOKEN" -e HEALTH_PORT=8766 "$@" "$ENGINE_IMAGE" engine >/dev/null
  started+=("$name")
}
# web NAME SERVICE ENGINE [docker run args…]: this image's SERVICE (mcp or
# viewer) on $net, using the engine named ENGINE.
web() {
  local name="$1" service="$2" eng="$3"; shift 3
  local url_var=ENGINE_URLS
  [ "$service" = mcp ] && url_var=MCP_ENGINE_URL
  docker run -d --name "$name" --network "$net" -e "$url_var=http://$eng:8766" \
    -e ENGINE_TOKEN="$ETOKEN" "$@" "$IMAGE" "$service" >/dev/null
  started+=("$name")
}
# A cache folder a viewer shares with its engine (same path in both).
cache_dir() { mkdir -p "$WORK/cache-$1"; chmod 777 "$WORK/cache-$1"; host_path "$WORK/cache-$1"; }

mkdir -p "$WORK/data"
chmod 777 "$WORK/data"
docker run --rm --entrypoint cat "$ENGINE_IMAGE" /opt/ingetrazo/examples/arco-yanque.igz \
  > "$WORK/data/arco.igz"
DATA="$(host_path "$WORK/data")"
TESTS="$(host_path "$HERE")"

echo "== image: $IMAGE; engines: $ENGINE_IMAGE ($(docker run --rm --entrypoint cat "$ENGINE_IMAGE" /opt/ingetrazo/BUILD_REF))"

echo "-- the image has no IngeTrazo and no X server"
docker run --rm --entrypoint sh "$IMAGE" -c 'test ! -e /opt/ingetrazo && ! command -v xvfb-run >/dev/null'
echo "  ok"
echo "-- the viewer refuses to start without ENGINE_URLS, the gateway without MCP_ENGINE_URL"
if out="$(docker run --rm -e ADMIN_PASSWORD="$PASSWORD" "$IMAGE" viewer 2>&1)"; then
  echo "it started"; exit 1
fi
echo "$out" | grep -q "ENGINE_URLS"
if out="$(docker run --rm -e MCP_TOKEN="$TOKEN" "$IMAGE" mcp 2>&1)"; then
  echo "it started"; exit 1
fi
echo "$out" | grep -q "MCP_ENGINE_URL"
echo "  ok"

# Fixed addresses (.5 the proxy viewer, .10 the trusted proxy) stay outside
# the range Docker hands out.
docker network create --subnet "$SUB.0/24" --ip-range "$SUB.128/25" "$net" >/dev/null

# ---- MCP gateway: token, OAuth ----------------------------------------------------
engine "$P-mcp-engine" mcp -e INGETRAZO_MODEL=arco.igz -v "$DATA:/data"
web "$P-mcp" mcp "$P-mcp-engine" -p "127.0.0.1:$MCP_PORT:8765" -e HEALTH_PORT=8765 \
  -e MCP_AUTH=token -e MCP_TOKEN="$TOKEN" -v "$DATA:/data:ro"
engine "$P-oauth-engine" mcp -v "$DATA:/data"
web "$P-mcp-oauth" mcp "$P-oauth-engine" -p "127.0.0.1:$OAUTH_PORT:8765" -e HEALTH_PORT=8765 \
  -e MCP_AUTH=oauth -e PUBLIC_URL="http://127.0.0.1:$OAUTH_PORT" -e OAUTH_ALLOW_HTTP=true \
  -e OAUTH_USER=admin -e OAUTH_PASSWORD="$OAUTH_PASSWORD" -v "$DATA:/data:ro"

# ---- viewers: local login, none, proxy, oidc --------------------------------------
C="$(cache_dir viewer)"
engine "$P-viewer-engine" render -v "$DATA:/data:ro" -v "$C:/cache"
web "$P-viewer" viewer "$P-viewer-engine" -p "127.0.0.1:$VIEWER_PORT:8080" \
  -e ADMIN_PASSWORD="$PASSWORD" -e VIEWER_POLL_SECONDS=1 -v "$DATA:/data:ro" -v "$C:/cache"
C="$(cache_dir none)"
engine "$P-none-engine" render -v "$DATA:/data:ro" -v "$C:/cache"
web "$P-viewer-none" viewer "$P-none-engine" -p "127.0.0.1:$NONE_PORT:8080" \
  -e VIEWER_AUTH_MODE=none -v "$DATA:/data:ro" -v "$C:/cache"
C="$(cache_dir proxy)"
engine "$P-proxy-engine" render -v "$DATA:/data:ro" -v "$C:/cache"
web "$P-viewer-proxy" viewer "$P-proxy-engine" --ip "$SUB.5" -p "127.0.0.1:$PROXY_PORT:8080" \
  -e VIEWER_AUTH_MODE=proxy -e PROXY_TRUSTED_IPS="$SUB.10/32" \
  -e PROXY_GROUPS_HEADER=X-authentik-groups -e PROXY_ADMIN_GROUP=viewer-admins \
  -v "$DATA:/data:ro" -v "$C:/cache"
docker run -d --name "$P-oidc" --network "$net" --network-alias oidc \
  -p "127.0.0.1:$OIDC_PORT:9000" -v "$TESTS:/tests:ro" --entrypoint python \
  "$IMAGE" /tests/mock_oidc.py http://oidc:9000 9000 viewer-smoke smoke-secret >/dev/null
started+=("$P-oidc")
C="$(cache_dir oidc)"
engine "$P-oidc-engine" render -v "$DATA:/data:ro" -v "$C:/cache"
web "$P-viewer-oidc" viewer "$P-oidc-engine" -p "127.0.0.1:$OIDC_VIEWER_PORT:8080" \
  -e VIEWER_AUTH_MODE=oidc -e OIDC_ISSUER_URL=http://oidc:9000 \
  -e OIDC_CLIENT_ID=viewer-smoke -e OIDC_CLIENT_SECRET=smoke-secret \
  -e OIDC_REDIRECT_URI="http://127.0.0.1:$OIDC_VIEWER_PORT/auth/callback" \
  -e OIDC_ALLOW_HTTP=true -e OIDC_ADMIN_GROUP=viewer-admins -v "$DATA:/data:ro" -v "$C:/cache"

"$PY" "$TESTS/smoke_mcp.py" "http://127.0.0.1:$MCP_PORT" "$TOKEN"
"$PY" "$TESTS/smoke_oauth.py" "http://127.0.0.1:$OAUTH_PORT" admin "$OAUTH_PASSWORD"
echo "== MCP_AUTH=oauth refuses to start without an https PUBLIC_URL"
if out="$(docker run --rm -e MCP_AUTH=oauth -e PUBLIC_URL=http://example.org \
            -e OAUTH_PASSWORD="$OAUTH_PASSWORD" "$IMAGE" mcp 2>&1)"; then
  echo "it started"; exit 1
fi
echo "$out" | grep -q "PUBLIC_URL must be https"
echo "  ok"
"$PY" "$TESTS/smoke_viewer.py" "http://127.0.0.1:$VIEWER_PORT" admin "$PASSWORD"

echo "-- the engine turns away a wrong secret and tools the viewer does not use"
docker exec -e ETOKEN="$ETOKEN" -e ENGINE="$P-viewer-engine" "$P-viewer" python - <<'PY'
import json, os, urllib.error, urllib.request
token, engine = os.environ["ETOKEN"], os.environ["ENGINE"]
def call(tool, args, tok):
    req = urllib.request.Request(f"http://{engine}:8766/call",
        json.dumps({"tool": tool, "args": args}).encode(),
        {"Authorization": "Bearer " + tok, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
assert call("list_documents", {}, "wrong-" + token) == 401
assert call("save_document", {"path": "/data/x.igz"}, token) == 403
assert call("export_pdf", {"path": "/data/x.pdf"}, token) == 403
assert call("list_documents", {}, token) == 200
PY
echo "  ok"

# ---- two model folders: work (rw) and library (ro, *.bak.igz not listed) ------------
mkdir -p "$WORK/folders/work" "$WORK/folders/library"
chmod 777 "$WORK/folders/work" "$WORK/folders/library"
cp "$WORK/data/arco.igz" "$WORK/folders/library/arco.igz"
cp "$WORK/data/arco.igz" "$WORK/folders/library/arco.bak.igz"
F_WORK="$(host_path "$WORK/folders/work")"
F_LIB="$(host_path "$WORK/folders/library")"
FOLDERS="work:rw; library:ro:exclude=*.bak.igz"
engine "$P-folders-mcp-engine" mcp -e INGETRAZO_MODEL=library/arco.igz -e MODEL_FOLDERS="$FOLDERS" \
  -v "$F_WORK:/data/work" -v "$F_LIB:/data/library:ro"
web "$P-mcp-folders" mcp "$P-folders-mcp-engine" -p "127.0.0.1:$FOLDERS_MCP_PORT:8765" \
  -e HEALTH_PORT=8765 -e MCP_AUTH=token -e MCP_TOKEN="$TOKEN" -e MODEL_FOLDERS="$FOLDERS" \
  -v "$F_WORK:/data/work:ro" -v "$F_LIB:/data/library:ro"
C="$(cache_dir folders)"
engine "$P-folders-engine" render -e MODEL_FOLDERS="$FOLDERS" \
  -v "$F_WORK:/data/work:ro" -v "$F_LIB:/data/library:ro" -v "$C:/cache"
web "$P-viewer-folders" viewer "$P-folders-engine" -p "127.0.0.1:$FOLDERS_VIEWER_PORT:8080" \
  -e VIEWER_AUTH_MODE=none -e VIEWER_PRERENDER=none -e VIEWER_POLL_SECONDS=1 \
  -e MODEL_FOLDERS="$FOLDERS" -v "$F_WORK:/data/work:ro" -v "$F_LIB:/data/library:ro" -v "$C:/cache"
"$PY" "$TESTS/smoke_folders.py" "http://127.0.0.1:$FOLDERS_MCP_PORT" "$TOKEN" \
  "http://127.0.0.1:$FOLDERS_VIEWER_PORT"
echo "== MODEL_FOLDERS with a mistake refuses to start"
if out="$(docker run --rm -e MODEL_FOLDERS="a:rx" -e MCP_TOKEN="$TOKEN" "$IMAGE" mcp 2>&1)"; then
  echo "it started"; exit 1
fi
echo "$out" | grep -q "MODEL_FOLDERS"
echo "  ok"

# ---- the viewer's login modes ----------------------------------------------------
echo "== viewer, VIEWER_AUTH_MODE=local without a password"
if out="$(docker run --rm "$IMAGE" viewer 2>&1)"; then
  echo "the viewer started without a password"; exit 1
fi
echo "$out" | grep -q "VIEWER_AUTH_MODE=none"
echo "  ok  refuses to start, and says how to open it on purpose"
"$PY" "$TESTS/smoke_auth.py" none "http://127.0.0.1:$NONE_PORT"
"$PY" "$TESTS/smoke_auth.py" proxy-untrusted "http://127.0.0.1:$PROXY_PORT"
docker run --rm --network "$net" --ip "$SUB.10" -v "$TESTS:/tests:ro" \
  --entrypoint python "$IMAGE" /tests/smoke_auth.py proxy-trusted "http://$SUB.5:8080"
"$PY" "$TESTS/smoke_auth.py" oidc "http://127.0.0.1:$OIDC_VIEWER_PORT" \
  "http://127.0.0.1:$OIDC_PORT"
users_in() {
  docker exec "$1" python -c 'import sqlite3; print([r[0] for r in sqlite3.connect("/state/users.db").execute("select name from users")])'
}
users_in "$P-viewer-oidc" | grep -q "'alice'"
users_in "$P-viewer-proxy" | grep -q "'bob'"
echo "  ok  oidc and proxy users recorded in the user list (users.db)"

# ---- Docker's health checks ------------------------------------------------------
for c in "${started[@]}"; do
  [ "$c" = "$P-oidc" ] && continue
  for _ in $(seq 1 60); do
    h="$(docker inspect -f '{{.State.Health.Status}}' "$c")"
    [ "$h" = healthy ] && break
    sleep 3
  done
  echo "== docker health of $c: $h"
  [ "$h" = healthy ]
done
echo "== smoke test passed"
