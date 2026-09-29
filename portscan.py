#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
portscan.py - Profesyonel Nmap Port Tarama ve IP Konum Aracı
Sadece yetkili olduğunuz sistemlerde kullanın!
"""

import nmap
import requests
import socket
import sys
import re

BANNER = r"""
 ____             _    ____                                 
|  _ \ ___  _ __| |_  / ___|  ___ __ _ _ __  _ __   ___ _ __ 
| |_) / _ \| '__| __| \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
|  __/ (_) | |  | |_   ___) | (_| (_| | | | | | | |  __/ |   
|_|   \___/|_|   \__| |____/ \___\__,_|_| |_|_| |_|\___|_|
   Port Scanner & lber4tz v1.0  
=============================================================
  UYARI: Sadece yetkili hedeflerde kullanın!
  BILGILENDIRME:
  - Tarama komutlari (scan, full, aggr, udp, vuln, stealth,
    os, subnet) arka planda GERCEK Nmap komutlarini calistirir.
    Sonuclar Nmap'in gercek ciktilaridir.
  - vuln komutu Nmap'in gercek 'vuln' script kategorisini
    kullanir; yaygin/bilinen zafiyetleri tespit eder.
  - geo komutu ip-api.com servisinden gercek konum verisi
    ceker. Konum bilgisi YAKLASIKTIR; sokak seviyesi
    kesinlik tasimaz, ozellikle VPN/mobil IP'lerde
    yanlis sehir donebilir.
  - Yerel IP'lerde (192.168.x.x vb.) Tam konum bilgisi bulunmaz.
=============================================================
  UYARI: Bu arac yalnizca SIZE AIT olan veya yazili izin
  almis oldugunuz sistemlerde kullanilmak icindir.
  Yetkisiz sistemlere tarama yapmak 5237 sayili Turk Ceza
  Kanunu 243-245. maddeler kapsaminda SUCTUR.
  Kullanicinin tüm sorumlulugu kendisine aittir.
=============================================================
"""
HELP = """
KOMUTLAR:
  scan <hedef>              Hızlı tarama (top 1000 port, TCP SYN)
  full <hedef>              Tam tarama (65535 port, servis tespiti)
  aggr <hedef>              Agresif tarama (-A: OS, servis, script)
  udp <hedef>               UDP port taraması (top 1000)
  vuln <hedef>              Zafiyet script taraması (--script vuln)
  stealth <hedef>           Gizli tarama (FIN scan, -sF)
  os <hedef>                İşletim sistemi tespiti (-O)
  subnet <hedef/sid>        Alt ağ canlı host taraması (örn: 192.168.1.0/24)
  geo <ip>                  IP konum bilgisi (ülke, şehir, ISP)
  info <ip>                 IP + konum + hızlı tarama (hepsi bir arada)
  help                      Bu yardım menüsü
  exit                      Çıkış

ÖRNEKLER:
  scan 192.168.1.10
  full example.com
  info 8.8.8.8
  subnet 192.168.1.0/24
"""

def is_ip(target):
    """Hedefin IP adresi olup olmadığını kontrol eder, değilse çözer."""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(pattern, target):
        return target
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None

def geo_lookup(ip):
    """IP konum bilgisi (ip-api.com - ücretsiz, key gerekmez)."""
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,"
                         f"country,regionName,city,zip,lat,lon,timezone,isp,org,as,reverse,query",
                         timeout=10)
        d = r.json()
        if d.get("status") != "success":
            print(f"[!] Konum bulunamadı (muhtemelen özel/yerel IP).")
            return
        print(f"\n===== IP KONUM BİLGİSİ: {ip} =====")
        print(f"  Ülke       : {d.get('country')}")
        print(f"  Bölge      : {d.get('regionName')}")
        print(f"  Şehir      : {d.get('city')}")
        print(f"  Posta Kodu : {d.get('zip')}")
        print(f"  Koordinat  : {d.get('lat')}, {d.get('lon')}")
        print(f"  Saat Dilimi: {d.get('timezone')}")
        print(f"  ISP        : {d.get('isp')}")
        print(f"  Organizasyon: {d.get('org')}")
        print(f"  AS         : {d.get('as')}")
        rev = d.get('reverse')
        if rev:
            print(f"  Reverse DNS: {rev}")
        print(f"  Google Maps: https://maps.google.com/?q={d.get('lat')},{d.get('lon')}")
        print("=" * 40)
    except requests.RequestException as e:
        print(f"[!] Konum sorgusu hatası: {e}")

def run_scan(target, arguments, scan_name):
    """Nmap taramasını çalıştırır ve sonuçları gösterir."""
    nm = nmap.PortScanner()
    print(f"\n[*] {scan_name} başlatılıyor: {target}")
    print(f"[*] Argümanlar: {arguments}\n")
    try:
        nm.scan(hosts=target, arguments=arguments)
    except nmap.PortScannerError as e:
        print(f"[!] Nmap hatası (root/sudo gerekebilir): {e}")
        return
    except Exception as e:
        print(f"[!] Hata: {e}")
        return

    for host in nm.all_hosts():
        print(f"===== HEDEF: {host} =====")
        state = nm[host].state()
        print(f"  Durum    : {state}")
        hostname = nm[host].hostname() or "-"
        print(f"  Hostname : {hostname}")
        for proto in nm[host].all_protocols():
            ports = sorted(nm[host][proto].keys())
            print(f"\n  [{proto.upper()}] {len(ports)} port bulundu:")
            print(f"  {'PORT':<8}{'DURUM':<10}{'SERVİS':<15}{'SÜRÜM/DETAY'}")
            print(f"  {'-'*60}")
            for p in ports:
                info = nm[host][proto][p]
                service = info.get('name', '?')
                product = info.get('product', '')
                version = info.get('version', '')
                extra = f"{product} {version}".strip()
                if info.get('script'):
                    extra += " | Script: " + ", ".join(info['script'].keys())
                print(f"  {p:<8}{info['state']:<10}{service:<15}{extra}")
        print()
        if not nm.all_hosts():
            print("[!] Sonuç bulunamadı, hedef kapalı olabilir veya filtreleniyor.")

def cmd_scan(target):
    ip = is_ip(target)
    if not ip: return print("[!] Hedef çözümlenemedi.")
    run_scan(ip, "-T4 -sV --top-ports 1000", "Hızlı Tarama")

def cmd_full(target):
    ip = is_ip(target)
    if not ip: return print("[!] Hedef çözümlenemedi.")
    run_scan(ip, "-T4 -sV -sC -p-", "Tam Tarama (65535 port)")

def cmd_aggr(target):
    ip = is_ip(target)
    if not ip: return print("[!] Hedef çözümlenemedi.")
    run_scan(ip, "-T4 -A --top-ports 1000", "Agresif Tarama (-A)")

def cmd_udp(target):
    ip = is_ip(target)
    if not ip: return print("[!] Hedef çözümlenemedi.")
    run_scan(ip, "-sU --top-ports 1000 -T4", "UDP Taraması")

def cmd_vuln(target):
    ip = is_ip(target)
    if not ip: return print("[!] Hedef çözümlenemedi.")
    run_scan(ip, "-sV --script vuln --top-ports 1000", "Zafiyet Taraması")

def cmd_stealth(target):
    ip = is_ip(target)
    if not ip: return print("[!] Hedef çözümlenemedi.")
    run_scan(ip, "-sF -T4", "Gizli FIN Taraması")

def cmd_os(target):
    ip = is_ip(target)
    if not ip: return print("[!] Hedef çözümlenemedi.")
    run_scan(ip, "-O -sV", "OS Tespiti")

def cmd_subnet(target):
    run_scan(target, "-sn", "Canlı Host Keşfi (Ping Scan)")

def cmd_info(target):
    ip = is_ip(target)
    if not ip: return print("[!] Hedef çözümlenemedi.")
    geo_lookup(ip)
    cmd_scan(ip)

def main():
    print(BANNER)
    while True:
        try:
            cmd_input = input("\nportscan> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[*] Çıkılıyor..."); break
        if not cmd_input:
            continue
        parts = cmd_input.split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else None

        commands = {
            "scan": cmd_scan, "full": cmd_full, "aggr": cmd_aggr,
            "udp": cmd_udp, "vuln": cmd_vuln, "stealth": cmd_stealth,
            "os": cmd_os, "subnet": cmd_subnet, "geo": lambda t: geo_lookup(is_ip(t) or t),
            "info": cmd_info,
        }
        if cmd == "help":
            print(HELP)
        elif cmd == "exit":
            print("[*] Çıkılıyor..."); break
        elif cmd in commands:
            if not arg:
                print(f"[!] Kullanım: {cmd} <hedef>")
            else:
                commands[cmd](arg)
        else:
            print(f"[!] Bilinmeyen komut: {cmd} — 'help' yazın.")

if __name__ == "__main__":
    main()