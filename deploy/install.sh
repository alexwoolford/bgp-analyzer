#!/usr/bin/env bash
# Install bgp-analyzer under /opt and enable systemd timers (Linux).
# Usage (as root): ./deploy/install.sh
#
# Prefer building the release binary as a normal user first:
#   cargo build -p bgp-analyzer-cli --release
#   sudo ./deploy/install.sh
# Set FORCE_REBUILD=1 to rebuild even when target/release/bgp-analyzer exists.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX="${BGP_INSTALL_PREFIX:-/opt/bgp-analyzer}"
STATE="${BGP_STATE_DIR:-/var/lib/bgp-analyzer}"
USER_NAME="${BGP_RUN_USER:-bgp}"
GROUP_NAME="${BGP_RUN_GROUP:-$USER_NAME}"
BIN_SRC="$ROOT/target/release/bgp-analyzer"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "run as root (or set BGP_INSTALL_PREFIX for a dry layout copy)" >&2
  exit 1
fi

build_release() {
  local build_user="${SUDO_USER:-}"
  if [[ -n "$build_user" && "$build_user" != "root" ]] && id -u "$build_user" >/dev/null 2>&1; then
    echo "== build release (as $build_user) =="
    sudo -u "$build_user" -H bash -lc "cd \"$ROOT\" && source \"\$HOME/.cargo/env\" 2>/dev/null || true; cargo build -p bgp-analyzer-cli --release"
    return
  fi
  echo "no release binary at $BIN_SRC and no non-root SUDO_USER to build as." >&2
  echo "build first: cargo build -p bgp-analyzer-cli --release" >&2
  echo "then re-run: sudo ./deploy/install.sh" >&2
  exit 1
}

if [[ -x "$BIN_SRC" && -z "${FORCE_REBUILD:-}" ]]; then
  echo "== using existing release binary: $BIN_SRC =="
else
  build_release
fi

test -x "$BIN_SRC" || {
  echo "missing $BIN_SRC — build with: cargo build -p bgp-analyzer-cli --release" >&2
  exit 1
}

echo "== create user/dirs =="
NLOGIN="/usr/sbin/nologin"
[[ -x "$NLOGIN" ]] || NLOGIN="/sbin/nologin"
if ! id -u "$USER_NAME" >/dev/null 2>&1; then
  useradd --system --home-dir "$STATE" --shell "$NLOGIN" "$USER_NAME" || true
fi
if getent group state-capture >/dev/null 2>&1; then
  usermod -aG state-capture "$USER_NAME" || true
  mkdir -p /var/lib/state-capture/announce
  chgrp state-capture /var/lib/state-capture/announce || true
  chmod 0775 /var/lib/state-capture/announce || true
fi
mkdir -p "$PREFIX"/{bin,scripts,fixtures,etc,docs} \
  "$STATE"/org-map \
  /etc/systemd/system

echo "== install files =="
install -m 0755 "$BIN_SRC" "$PREFIX/bin/bgp-analyzer"
install -m 0755 "$ROOT/scripts/run-daily-signals.sh" "$PREFIX/scripts/run-daily-signals.sh"
install -m 0755 "$ROOT/scripts/run-refresh-org-map.sh" "$PREFIX/scripts/run-refresh-org-map.sh"
install -m 0644 "$ROOT/fixtures/glue-asns.txt" "$PREFIX/fixtures/glue-asns.txt"
install -m 0644 "$ROOT/docs/DAILY_OPS.md" "$PREFIX/docs/DAILY_OPS.md"
install -m 0644 "$ROOT/docs/ORG_MAP.md" "$PREFIX/docs/ORG_MAP.md"
ENV_DST="$PREFIX/etc/bgp-analyzer.env"
if [[ ! -f "$ENV_DST" ]]; then
  install -m 0644 "$ROOT/deploy/bgp-analyzer.env.example" "$ENV_DST"
else
  append_env_if_missing() {
    local key="$1" value="$2"
    if ! grep -qE "^${key}=" "$ENV_DST"; then
      printf '\n%s=%s\n' "$key" "$value" >> "$ENV_DST"
    fi
  }
  append_env_if_missing STATE_CAPTURE_SOCK /run/state/collect.sock
  append_env_if_missing STATE_CAPTURE_ANNOUNCE_DIR /var/lib/state-capture/announce
fi

chown -R "$USER_NAME:$GROUP_NAME" "$STATE"
chown -R root:root "$PREFIX"
chmod 0755 "$PREFIX/scripts"/*.sh

install -m 0644 "$ROOT/deploy/systemd/bgp-signals.service" /etc/systemd/system/bgp-signals.service
install -m 0644 "$ROOT/deploy/systemd/bgp-signals.timer" /etc/systemd/system/bgp-signals.timer
install -m 0644 "$ROOT/deploy/systemd/bgp-org-map.service" /etc/systemd/system/bgp-org-map.service
install -m 0644 "$ROOT/deploy/systemd/bgp-org-map.timer" /etc/systemd/system/bgp-org-map.timer

if command -v restorecon >/dev/null 2>&1; then
  echo "== SELinux restorecon =="
  restorecon -Rv "$PREFIX" "$STATE" || true
fi

# Seed via systemd oneshot (survives SSH drop; TimeoutStartSec=2h). Do not
# block install on PeeringDB HTTP — a foreground crawl dies with the session.
systemctl daemon-reload
systemctl enable --now bgp-org-map.timer
# Do not --now the signals timer: Persistent=true would catch up before the
# seed crawl finishes. The next 02:30 UTC fire (or a manual start) is correct.
systemctl enable bgp-signals.timer
echo "== seed org-map (systemd, non-blocking PeeringDB crawl) =="
systemctl start --no-block bgp-org-map.service

echo "installed:"
echo "  prefix=$PREFIX state=$STATE"
echo "  timers: bgp-org-map.timer (weekly, enabled now), bgp-signals.timer (daily, next 02:30 UTC)"
echo "  seed: systemctl status bgp-org-map.service"
echo "  logs: journalctl -u bgp-signals.service -u bgp-org-map.service"
echo "  review: $STATE/signals/inbox.jsonl"
echo "  sqlite: $STATE/bgp-analyzer.sqlite"
echo "  edit: $PREFIX/etc/bgp-analyzer.env"
