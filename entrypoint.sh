#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Start one of the image's services. Neither runs IngeTrazo: they reach
# engines (ingetrazo-docker containers) over the network.
#   viewer  read-only live web viewer of sheets, views and 3D (default);
#           needs ENGINE_URLS
#   mcp     the MCP gateway; needs MCP_ENGINE_URL
#   shell   a shell, for debugging
set -e

service="${1:-viewer}"
shift || true

case "$service" in
  viewer) exec python -m viewer.server "$@" ;;
  mcp)    exec python -m mcp_http.server "$@" ;;
  shell)  exec /bin/sh "$@" ;;
  *)      exec "$service" "$@" ;;
esac
