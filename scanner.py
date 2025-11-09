#!/usr/bin/env python3
# local_scan.py — Eğitim / etik tarama (sadece kendi ağınızda)
# Termux uyumlu, ek paket gerekmez.

import csv
import os
import platform
import socket
import subprocess
import sys
import time
from datetime import datetime

LOGFILE = "scan_log.csv"
PING_COUNT = "1"
PING_TIMEOUT = "1"   # saniye (kısa tut)
# Eğer /24 dışında bir ağınız varsa BURAYI değiştirin (ör: "192.168.1.")
# Script otomatik local IP bulamıyorsa elle ön ek verin.
FORCE_PREFIX = None  # örn: "192.168.1."

def get_local_ip():
    # UDP socket trick to learn local IP (güvenilir)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = None
    finally:
        s.close()
    return ip

def ip_prefix_from(ip):
    # varsayılan /24
    parts = ip.split(".")
    return ".".join(parts[:3]) + "."

def ping(ip):
    system = platform.system().lower()
    try:
        if "windows" in system:
            cmd = ["ping", "-n", PING_COUNT, "-w", str(int(PING_TIMEOUT)*1000), ip]
        else:
            # Linux/Termux/macOS
            cmd = ["ping", "-c", PING_COUNT, "-W", PING_TIMEOUT, ip]
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except Exception:
        return False

def get_mac_from_arp(ip):
    system = platform.system().lower()
    try:
        if "linux" in system or "darwin" in system or "android" in system:
            # ip neigh veya arp -n
            # Önce ip neigh deneyelim
            p = subprocess.run(["ip", "neigh", "show", ip], capture_output=True, text=True)
            out = p.stdout.strip()
            if out:
                # Satır ör: "192.168.1.5 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
                parts = out.split()
                if "lladdr" in parts:
                    return parts[parts.index("lladdr")+1]
            # Fallback arp
            p2 = subprocess.run(["arp", "-n", ip], capture_output=True, text=True)
            out2 = p2.stdout.strip()
            if out2:
                # parsing basit tutalım
                for token in out2.split():
                    if ":" in token and len(token) >= 17:  # MAC ihtimali
                        return token
            return ""
        elif "windows" in system:
            p = subprocess.run(["arp", "-a", ip], capture_output=True, text=True)
            out = p.stdout
            for line in out.splitlines():
                if ip in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1]
            return ""
    except Exception:
        return ""

def append_log(row):
    header = ["timestamp","ip","mac","hostname"]
    newfile = not os.path.exists(LOGFILE)
    with open(LOGFILE, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if newfile:
            w.writerow(header)
        w.writerow(row)

def try_resolve_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""

def main():
    print("=== Local network scanner (etik amaçlı) ===")
    if FORCE_PREFIX:
        prefix = FORCE_PREFIX
        print(f"Elle belirtilen prefix kullanılıyor: {prefix}")
    else:
        local_ip = get_local_ip()
        if not local_ip:
            print("Yerel IP bulunamadı. FORCE_PREFIX ayarlayın veya ağınızı kontrol edin.")
            sys.exit(1)
        prefix = ip_prefix_from(local_ip)
        print(f"Yerel IP: {local_ip}  — tarama prefix: {prefix}0/24")

    print("Not: Bu işlem yalnızca canlılık kontrolü (ping) ve ARP tablosu okumadır.")
    print("Log dosyası:", LOGFILE)
    print("Tarama başlıyor... (1..254)")

    for i in range(1, 255):
        ip = f"{prefix}{i}"
        now = datetime.utcnow().isoformat() + "Z"
        alive = ping(ip)
        if alive:
            mac = get_mac_from_arp(ip)
            name = try_resolve_name(ip)
            print(f"[ALIVE] {ip}  MAC={mac if mac else '-'}  NAME={name if name else '-'}")
            append_log([now, ip, mac, name])
        else:
            # opsiyonel: yazdırma/veya atla — sessiz bırakmak istersen pass
            print(f"[down ] {ip}")
        # küçük bekleme ağ üzerindeki yükü hafifletir
        time.sleep(0.05)

    print("Tarama tamamlandı. Log dosyasını kontrol et:", LOGFILE)

if __name__ == "__main__":
    main()
