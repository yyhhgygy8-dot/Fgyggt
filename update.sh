#!/usr/bin/env bash
# به‌روزرسانی پنل از سورس فعلی (بعد از git pull) - اطلاعات و کاربران حفظ می‌شوند
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "با root اجرا کنید"; exit 1; }
APP_DIR="${APP_DIR:-/opt/wg-panel}"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
rsync -a --delete --exclude 'data' --exclude 'node_modules' --exclude '.git' "$SRC_DIR"/ "$APP_DIR"/
cd "$APP_DIR" && npm install --omit=dev --no-audit --no-fund || true
systemctl restart wg-panel
echo "به‌روزرسانی انجام شد ✅"
