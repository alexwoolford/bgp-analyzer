#!/usr/bin/env bash
# Install bgp-analyzer under /opt and enable systemd timers (Linux).
# Usage (as root): ./deploy/install.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX="${BGP_INSTALL_PREFIX:-/opt/bgp-analyzer}"
STATE="${BGP_STATE_DIR:-/var/lib/bgp-analyzer}"
USER_NAME="${BGP_RUN_USER:-bgp}"
GROUP_NAME="${BGP_RUN_GROUP:-$USER_NAME}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "run as root (or set BGP_INSTALL_PREFIX for a dry layout copy)" >&2
  exit 1
fi

echo "== build release =="
(cd "$ROOT" && cargo build -p bgp-analyzer-cli --release)

echo "== create user/dirs =="
if ! id -u "$USER_NAME" >/dev/null 2>&1; then
  useradd --system --home-dir "$STATE" --shell /usr/sbin/nologin "$USER_NAME" || true
fi
mkdir -p "$PREFIX"/{bin,scripts,fixtures,etc,docs} \
  "$STATE"/org-map \
  /etc/systemd/system

echo "== install files =="
install -m 0755 "$ROOT/target/release/bgp-analyzer" "$PREFIX/bin/bgp-analyzer"
install -m 0755 "$ROOT/scripts/run-daily-signals.sh" "$PREFIX/scripts/run-daily-signals.sh"
install -m 0755 "$ROOT/scripts/run-refresh-org-map.sh" "$PREFIX/scripts/run-refresh-org-map.sh"
install -m 0644 "$ROOT/fixtures/glue-asns.txt" "$PREFIX/fixtures/glue-asns.txt"
install -m 0644 "$ROOT/docs/DAILY_OPS.md" "$PREFIX/docs/DAILY_OPS.md"
if [[ ! -f "$PREFIX/etc/bgp-analyzer.env" ]]; then
  install -m 0644 "$ROOT/deploy/bgp-analyzer.env.example" "$PREFIX/etc/bgp-analyzer.env"
fi

# Point wrappers at installed layout when invoked from /opt.
# ROOT in scripts is parent of scripts/ → /opt/bgp-analyzer; default bin path works
# if we also place a symlink target/release for local-style defaults — instead set env.
chown -R "$USER_NAME:$GROUP_NAME" "$STATE"
chown -R root:root "$PREFIX"
chmod 0755 "$PREFIX/scripts"/*.sh

install -m 0644 "$ROOT/deploy/systemd/bgp-signals.service" /etc/systemd/system/bgp-signals.service
install -m 0644 "$ROOT/deploy/systemd/bgp-signals.timer" /etc/systemd/system/bgp-signals.timer
install -m 0644 "$ROOT/deploy/systemd/bgp-org-map.service" /etc/systemd/system/bgp-org-map.service
install -m 0644 "$ROOT/deploy/systemd/bgp-org-map.timer" /etc/systemd/system/bgp-org-map.timer

systemctl daemon-reload
systemctl enable --now bgp-org-map.timer
systemctl enable --now bgp-signals.timer

echo "== first org-map (blocking PeeringDB crawl) =="
sudo -u "$USER_NAME" env \
  BGP_ANALYZER_BIN="$PREFIX/bin/bgp-analyzer" \
  BGP_GLUE="$PREFIX/fixtures/glue-asns.txt" \
  BGP_ORG_MAP_DIR="$STATE/org-map" \
  "$PREFIX/scripts/run-refresh-org-map.sh"

echo "installed:"
echo "  prefix=$PREFIX state=$STATE"
echo "  timers: bgp-org-map.timer (weekly), bgp-signals.timer (daily)"
echo "  logs: journalctl -u bgp-signals.service -u bgp-org-map.service"
echo "  edit: $PREFIX/etc/bgp-analyzer.env"
