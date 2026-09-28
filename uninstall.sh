#!/usr/bin/env bash
# حذف پنل. داده‌ها (کاربران) فقط با گزینهٔ PURGE=1 حذف می‌شوند.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "با root اجرا کنید"; exit 1; }
APP_DIR="${APP_DIR:-/opt/wg-panel}"
systemctl disable --now wg-panel 2>/dev/null || true
rm -f /etc/systemd/system/wg-panel.service /etc/nginx/sites-enabled/wg-panel /etc/nginx/sites-available/wg-panel
systemctl daemon-reload
systemctl reload nginx 2>/dev/null || true
if [ "${PURGE:-0}" = "1" ]; then
  wg-quick down wg0 2>/dev/null || true
  rm -rf "$APP_DIR" /etc/wg-panel.env /etc/wireguard/wg0.conf
  echo "همه چیز حذف شد."
else
  echo "برنامه حذف شد؛ داده‌ها در $APP_DIR/data باقی ماند. (برای حذف کامل: PURGE=1)"
fi
