FROM node:20-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      wireguard-tools wireguard-go iptables iproute2 procps ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY . .
ENV PORT=3000 HOST=0.0.0.0 TRUST_PROXY=1 DATA_DIR=/data
VOLUME /data
EXPOSE 3000
EXPOSE 51820/udp
CMD ["sh","-c","mkdir -p /dev/net; [ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200 2>/dev/null; sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; if ip link add wgprobe type wireguard 2>/dev/null; then ip link del wgprobe; else export WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-go; fi; exec node server.js"]
