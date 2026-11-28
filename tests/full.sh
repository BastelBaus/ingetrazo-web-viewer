#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# The full test: the long end-to-end run before a release (PRs into main,
# .github/workflows/full.yml). It starts compose.yaml as shipped (both
# services, both engines, the internal network, the secrets made on first
# start) with this image and ENGINE_IMAGE, then:
#   - tests/full_viewer.py: everything of the example rendered
#     (VIEWER_PRERENDER=all) and served, MCP through the gateway, security
#     checks against the real servers;
#   - the stack's isolation: the engines publish no port and have no way
#     out, each engine has its own secret and refuses the other's, no
#     process runs as root, the services see /data read-only.
#
#   IMAGE=ingetrazo-web-viewer:dev ENGINE_IMAGE=ghcr.io/bastelbaus/ingetrazo:dev tests/full.sh
set -euo pipefail
export MSYS_NO_PATHCONV=1

IMAGE="${IMAGE:-ingetrazo-web-viewer:dev}"
ENGINE_IMAGE="${ENGINE_IMAGE:-ghcr.io/bastelbaus/ingetrazo:dev}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK="${FULL_WORKDIR:-$(mktemp -d)}"
PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null 2>&1 || PY=python
PROJECT="full-$$"
VIEWER_PORT="${FULL_VIEWER_PORT:-18180}"
MCP_PORT="${FULL_MCP_PORT:-18165}"
PASSWORD="full-admin-$(date +%s)"
TOKEN="full-token-$(date +%s)-0123456789"

mkdir -p "$WORK/data/full-out"
chmod 777 "$WORK/data" "$WORK/data/full-out"
docker run --rm --entrypoint cat "$ENGINE_IMAGE" /opt/ingetrazo/examples/arco-yanque.igz \
  > "$WORK/data/arco.igz"

cat > "$WORK/.env" <<EOF
WEB_VIEWER_IMAGE=$IMAGE
INGETRAZO_IMAGE=$ENGINE_IMAGE
INGETRAZO_DATA_DIR=$WORK/data
ADMIN_PASSWORD=$PASSWORD
MCP_TOKEN=$TOKEN
VIEWER_PORT=$VIEWER_PORT
MCP_PORT=$MCP_PORT
VIEWER_PRERENDER=all
VIEWER_SHEET_DPI=60
EOF

compose() {
  docker compose -p "$PROJECT" -f "$ROOT/compose.yaml" --env-file "$WORK/.env" \
    --profile viewer "$@"
}
c() { compose ps -q "$1"; }

cleanup() {
  status=$?
  if [ $status -ne 0 ]; then
    compose logs --no-color --tail 80 || true
  fi
  compose down -v --remove-orphans >/dev/null 2>&1 || true
  exit $status
}
trap cleanup EXIT

echo "== compose.yaml with $IMAGE and $ENGINE_IMAGE"
compose up -d --no-build --pull never

for svc in mcp-engine viewer-engine mcp viewer; do
  h=""
  for _ in $(seq 1 100); do
    h="$(docker inspect -f '{{.State.Health.Status}}' "$(c "$svc")")"
    [ "$h" = healthy ] && break
    sleep 3
  done
  echo "  $svc: $h"
  [ "$h" = healthy ]
done

echo "-- the engines publish no port, the services only on 127.0.0.1"
for svc in mcp-engine viewer-engine; do
  [ -z "$(docker port "$(c "$svc")")" ] || { echo "$svc publishes a port"; exit 1; }
done
for svc in mcp viewer; do
  docker port "$(c "$svc")" | grep -v '127.0.0.1:' && { echo "$svc is published beyond localhost"; exit 1; }
done
echo "  ok"

echo "-- the engines have no way out (internal network)"
for svc in mcp-engine viewer-engine; do
  if docker exec "$(c "$svc")" python -c \
      'import urllib.request; urllib.request.urlopen("https://github.com", timeout=8)' \
      >/dev/null 2>&1; then
    echo "$svc reached the internet"; exit 1
  fi
done
echo "  ok"

echo "-- each engine its own secret; neither takes the other's"
mt="$(docker exec "$(c mcp-engine)" cat /engine/token)"
vt="$(docker exec "$(c viewer-engine)" cat /engine/token)"
[ "${#mt}" -ge 32 ] && [ "${#vt}" -ge 32 ] && [ "$mt" != "$vt" ]
docker exec -e VT="$vt" "$(c viewer)" python - <<'PY'
import json, os, urllib.error, urllib.request
req = urllib.request.Request("http://mcp-engine:8766/call",
    json.dumps({"tool": "list_documents", "args": {}}).encode(),
    {"Authorization": "Bearer " + os.environ["VT"], "Content-Type": "application/json"})
try:
    urllib.request.urlopen(req, timeout=30)
    raise SystemExit("the viewer engine's secret opened the MCP engine")
except urllib.error.HTTPError as e:
    assert e.code == 401, e.code
PY
echo "  ok"

echo "-- nobody runs as root; the services see /data read-only"
for svc in mcp-engine viewer-engine mcp viewer; do
  [ "$(docker exec "$(c "$svc")" id -u)" != 0 ] || { echo "$svc runs as root"; exit 1; }
done
for svc in mcp viewer viewer-engine; do
  if docker exec "$(c "$svc")" sh -c 'touch /data/full-probe' 2>/dev/null; then
    echo "$svc can write /data"; exit 1
  fi
done
[ ! -e "$WORK/data/full-probe" ]
echo "  ok"

"$PY" "$HERE/full_viewer.py" "http://127.0.0.1:$VIEWER_PORT" "$PASSWORD" \
  "http://127.0.0.1:$MCP_PORT" "$TOKEN" "$WORK/data"

echo "== full test passed"
