#!/usr/bin/env bash
# WG Panel - نصب خودکار روی Ubuntu/Debian
# استفاده:  sudo DOMAIN=cloud.stackdome.com EMAIL=you@example.com bash install.sh
set -euo pipefail

DOMAIN="${DOMAIN:-cloud.stackdome.com}"     # دامنهٔ پنل
EMAIL="${EMAIL:-}"                          # ایمیل برای گواهی SSL (اختیاری)
APP_DIR="${APP_DIR:-/opt/wg-panel}"
PANEL_PORT="${PANEL_PORT:-3000}"
SKIP_NGINX="${SKIP_NGINX:-0}"               # 1 = بدون nginx (پنل مستقیم روی پورت)
ENV_FILE="/etc/wg-panel.env"

say() { echo -e "\033[1;32m==>\033[0m $*"; }
warn() { echo -e "\033[1;33m!!\033[0m $*"; }
die() { echo -e "\033[1;31mخطا:\033[0m $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "اسکریپت را با root اجرا کنید (sudo bash install.sh)"
command -v apt-get >/dev/null || die "فقط Ubuntu/Debian پشتیبانی می‌شود"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export DEBIAN_FRONTEND=noninteractive

say "نصب پیش‌نیازها..."
apt-get update -y
apt-get install -y wireguard wireguard-tools iptables iproute2 curl ca-certificates openssl rsync

# Node.js >= 18
need_node=1
if command -v node >/dev/null; then
  [ "$(node -p 'process.versions.node.split(".")[0]')" -ge 18 ] && need_node=0
fi
if [ "$need_node" -eq 1 ]; then
  say "نصب Node.js 20..."
  if curl -fsSL https://deb.nodesource.com/setup_20.x | bash - ; then
    apt-get install -y nodejs
  else
    warn "NodeSource در دسترس نیست؛ تلاش با مخزن پیش‌فرض"
    apt-get install -y nodejs npm
  fi
fi
command -v node >/dev/null || die "نصب Node.js ناموفق بود"
command -v npm  >/dev/null || apt-get install -y npm

say "کپی برنامه در $APP_DIR ..."
mkdir -p "$APP_DIR"
rsync -a --delete --exclude 'data' --exclude 'node_modules' --exclude '.git' "$SRC_DIR"/ "$APP_DIR"/
cd "$APP_DIR"
say "نصب وابستگی‌ها (qrcode)..."
npm install --omit=dev --no-audit --no-fund || warn "npm install ناموفق بود؛ پنل بدون QR کار می‌کند"

say "فعال‌سازی IP forwarding..."
cat > /etc/sysctl.d/99-wg-panel.conf <<EOF
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF
sysctl --system >/dev/null || true

# تنظیمات محیط (فقط بار اول ساخته می‌شود)
if [ ! -f "$ENV_FILE" ]; then
  ADMIN_PASS="$(openssl rand -base64 12 | tr -d '/+=' | cut -c1-12)"
  if [ "$SKIP_NGINX" = "1" ]; then HOST_BIND="0.0.0.0"; TRUST="0"; PANEL_URL="http://$DOMAIN:$PANEL_PORT"; else HOST_BIND="127.0.0.1"; TRUST="1"; PANEL_URL="https://$DOMAIN"; fi
  cat > "$ENV_FILE" <<EOF
PORT=$PANEL_PORT
HOST=$HOST_BIND
TRUST_PROXY=$TRUST
DATA_DIR=$APP_DIR/data
PANEL_URL=$PANEL_URL
ADMIN_USER=admin
ADMIN_PASSWORD=$ADMIN_PASS
EOF
  chmod 600 "$ENV_FILE"
else
  warn "$ENV_FILE از قبل وجود دارد و حفظ شد"
fi

say "ساخت سرویس systemd ..."
cat > /etc/systemd/system/wg-panel.service <<EOF
[Unit]
Description=WG Panel (WireGuard management panel)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$(command -v node) $APP_DIR/server.js
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable wg-panel >/dev/null 2>&1
systemctl restart wg-panel

# فایروال
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  say "باز کردن پورت‌ها در ufw ..."
  ufw allow 51820/udp >/dev/null || true
  ufw allow 80/tcp >/dev/null || true
  ufw allow 443/tcp >/dev/null || true
  [ "$SKIP_NGINX" = "1" ] && ufw allow "$PANEL_PORT"/tcp >/dev/null || true
  ufw route allow in on wg0 >/dev/null 2>&1 || true
fi

# nginx + SSL
if [ "$SKIP_NGINX" != "1" ]; then
  say "نصب و تنظیم nginx برای $DOMAIN ..."
  apt-get install -y nginx
  cat > /etc/nginx/sites-available/wg-panel <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;

    location / {
        proxy_pass http://127.0.0.1:$PANEL_PORT;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        client_max_body_size 6m;
    }
}
EOF
  ln -sf /etc/nginx/sites-available/wg-panel /etc/nginx/sites-enabled/wg-panel
  rm -f /etc/nginx/sites-enabled/default
  nginx -t && systemctl reload nginx

  say "دریافت گواهی SSL (Let's Encrypt) ..."
  apt-get install -y certbot python3-certbot-nginx
  CERT_ARGS=(--nginx -d "$DOMAIN" --non-interactive --agree-tos --redirect)
  if [ -n "$EMAIL" ]; then CERT_ARGS+=(-m "$EMAIL"); else CERT_ARGS+=(--register-unsafely-without-email); fi
  if certbot "${CERT_ARGS[@]}"; then
    SCHEME="https"
  else
    SCHEME="http"
    warn "دریافت SSL ناموفق بود. مطمئن شوید رکورد A دامنه $DOMAIN به IP این سرور اشاره می‌کند (بدون پروکسی Cloudflare) و سپس اجرا کنید:  certbot --nginx -d $DOMAIN"
    sed -i "s|^PANEL_URL=.*|PANEL_URL=http://$DOMAIN|" "$ENV_FILE"
  fi
else
  SCHEME="http"
fi

sleep 2
ADMIN_USER_SHOW="$(grep '^ADMIN_USER=' "$ENV_FILE" | cut -d= -f2)"
ADMIN_PASS_SHOW="$(grep '^ADMIN_PASSWORD=' "$ENV_FILE" | cut -d= -f2)"
[ -f "$APP_DIR/data/initial-admin.txt" ] || ADMIN_PASS_SHOW="(قبلاً تغییر کرده؛ رمز فعلی خودتان)"
if [ "$SKIP_NGINX" = "1" ]; then URL="http://$DOMAIN:$PANEL_PORT"; else URL="$SCHEME://$DOMAIN"; fi

echo
say "نصب کامل شد ✅"
echo "  آدرس پنل   : $URL"
echo "  نام کاربری : $ADMIN_USER_SHOW"
echo "  رمز عبور   : $ADMIN_PASS_SHOW"
echo "  (بعد از ورود، رمز را از بخش «حساب» تغییر دهید)"
echo "  وضعیت سرویس: systemctl status wg-panel   |   لاگ: journalctl -u wg-panel -f"
