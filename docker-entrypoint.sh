#!/bin/sh
# آماده‌سازی خودکار محیط کانتینر برای وایرگارد
mkdir -p /dev/net
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200 2>/dev/null || echo "[entrypoint] /dev/net/tun در دسترس نیست (پلتفرم باید TUN را اجازه دهد)"
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "[entrypoint] فعال‌سازی ip_forward ممکن نشد"
# اگر ماژول کرنل نبود، از wireguard-go (نسخهٔ userspace) استفاده کن
if ip link add wgprobe type wireguard 2>/dev/null; then
  ip link del wgprobe 2>/dev/null
  echo "[entrypoint] WireGuard kernel module OK"
else
  export WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-go
  echo "[entrypoint] استفاده از wireguard-go (userspace)"
fi
exec node /app/server.js
