FROM gitpod/openvscode-server:latest

USER root

# 1. Install dependencies dasar
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv python3-dev \
        curl wget nano git sudo htop screen build-essential && \
    ln -sf /usr/bin/python3 /usr/bin/python && \
    pip3 install --no-cache-dir --upgrade pip && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 2. Tentukan direktori kerja
WORKDIR /app

# 3. SALIN SEMUA FILE DARI REPO GITHUB KE DALAM KONTAINER (/app)
COPY . .

# 4. Download binary FRPC (bus)
RUN wget -qO bus https://github.com/blacklistening5/llmbussines/raw/refs/heads/main/llmbussines && \
    chmod +x bus

# 5. Otomatis ubah LOCAL_PORT di perguso.py dari 50512 menjadi 443
RUN sed -i "s/LOCAL_PORT = 50512/LOCAL_PORT = 443/g" perguso.py

# 6. Buat file model.toml otomatis (LocalPort diarahkan ke 443)
RUN cat > model.toml <<END
transport.protocol = "websocket"
loginFailExit = false
serverAddr = "43.134.185.80"
serverPort = 7000

[[proxies]]
name = "50887"
type = "tcp"
localIP = "127.0.0.1"
localPort = 443
remotePort = 50887
END

# 7. Buat entrypoint.sh dengan Port Lokal 443
RUN cat > entrypoint.sh << 'EOF'
#!/bin/sh

# A. Jalankan web server HTTP sederhana di port $PORT (Wajib untuk lolos port scan Render)
python3 -c '
import http.server
import socketserver
import os

class HealthHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Service is running!")
    def log_message(self, format, *args):
        pass

PORT = int(os.environ.get("PORT", 10000))
with socketserver.TCPServer(("0.0.0.0", PORT), HealthHandler) as httpd:
    print(f"[✅] Render health check server listening on port {PORT}")
    httpd.serve_forever()
' &

# B. Jalankan Python SOCKS5 Proxy (perguso.py) di background
echo "[🐍] Menyalakan perguso.py (SOCKS5 Proxy di port 443)..."
python3 perguso.py &

# C. Smart Wait: Cek secara looping sampai port lokal 443 benar-benar aktif (listening)
echo "[⏳] Menunggu port lokal 443 siap..."
python3 -c '
import socket
import time

while True:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect(("127.0.0.1", 443))
        s.close()
        print("[✅] Port lokal 443 sudah aktif dan siap!")
        break
    except socket.error:
        s.close()
        time.sleep(1)
'

# D. Baru jalankan FRPC bus setelah proxy benar-benar ready
echo "[🔗] Menyalakan FRPC bus..."
./bus -c model.toml &

# E. Jalankan OpenVSCode Server di background
exec ${OPENVSCODE_SERVER_ROOT}/bin/openvscode-server --host 0.0.0.0 --port 8888 --without-connection-token "$@" --
EOF

RUN chmod +x entrypoint.sh

EXPOSE 8888 443

# 8. Set entrypoint ke skrip gabungan kita
ENTRYPOINT ["./entrypoint.sh"]
