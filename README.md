# SILENT HILL

![Main menu](https://github.com/raphaelthief/SIlent-Hill/blob/main/Pic/main.png "Main menu")

**Silent Hill** is a Python-based network audit tool focused on *reconnaissance* and *passive/active analysis*. It centralizes multiple capabilities: host discovery, connectivity scans, passive traffic sniffing (DNS/HTTP/TLS), ARP MITM attacks (spy), connection interruption (kill), and a “Karma” feature to create fake open access points (fake AP) and capture ESSID probes. It can lure a target into connecting to the rogue AP, then perform ARP poisoning to intercept their traffic.

> ⚠️ **Legal Warning:** This software includes offensive functions (ARP spoofing, fake AP, traffic blocking). Only use these features on networks and systems you have explicit authorization to test. Unauthorized use is illegal and/or unethical.

---

## Main Features

- **Network Discovery (ARP / ICMP / SSDP / NetBIOS / SNMP / TCP SYN)**: Enumerate devices on a local network, retrieve MAC, OUI vendor, and hostname.
- **Connectivity Scan ("connect")**: Test connectivity on an IP range + predefined ports, detect web services, and extract `<title>` from accessible web pages.
- **Passive Listening ("listen")**: Passive sniffing to detect new hosts, display DNS requests, transport protocol, and other observable metadata.
- **Spy / MITM Mode ("spy")**: ARP spoofing to intercept target traffic, enable IP forwarding, log DNS, HTTP (headers, cookies, POST bodies), and attempt TLS SNI extraction.
- **Kill Mode ("kill")**: ARP poisoning to blackhole a target (blackhole MAC), disable IP forwarding, and optionally add ebtables rules to block forwarding.
- **Karma (fake AP)**: Create an open access point (hostapd + dnsmasq) to attract clients (inject ESSIDs from a list), sniff ESSID probes, monitor connected clients, and manage full setup/cleanup. Can be used to get a victim to connect and then run ARP poisoning.
- **Probe Scanner**: Detects ESSID probe requests for preparing or performing Karma attacks.
- **Display & Helper Mechanisms**: Banner, color highlights, keyword highlighting in requests, real-time display of detected devices.

---

## Technical Modes

### 1) `--discovery`
- ARP scan via Scapy.
- ICMP ping sweep (threaded).
- SSDP discovery, NetBIOS (nbtscan), SNMP (snmpget) if available.
- Optional TCP SYN scan on selected ports.
- Output: IP / MAC / vendor / hostname.

### 2) `--connect`
- TCP connect scan on common ports per host.
- For web ports: fetch HTTP(S) status and page title.
- Summarizes detected services.

### 3) `--listen`
- Continuous sniff with Scapy.
- Displays new hosts, OUI, DNS queries, ports, protocols.

### 4) `--spy`
- Requires: `--target`, `--router`, `--interface`.
- Steps: enable IP forwarding → continuous ARP spoof → targeted sniff.
- Analysis:
  - DNS: display queried names.
  - HTTP: capture requests (request line, host, user-agent, cookies, cleartext POST bodies).
  - TLS: attempt **SNI** extraction from ClientHello.
  - Cleartext protocols (FTP, Telnet, POP3, IMAP, NetBIOS, SNMP, etc.): display payloads.
- Highlight keywords in captures (`--highlight keyword1,keyword2`).

### 5) `--kill`
- ARP poisoning with blackhole MAC + ICMP Host Unreachable.
- Optional `ebtables` rules to block forwarding.

### 6) `--karma`, `--karma-scan`, `--karma-listen`, `--kill-karma`
- `--karma-scan`: monitor mode, sniff probe requests, list ESSIDs/clients.
- `--karma <ESSID_NAME>`: start fake AP via hostapd + dnsmasq, NAT via iptables, lure victims.
- `--karma-listen`: monitor dnsmasq leases for connected clients.
- `--kill-karma`: stop AP, restore configs, remove NAT/iptables rules.

---

## Requirements

- **OS**: Linux (requires `iw`, `airmon-ng`, `ip`, `iptables`, `hostapd`, `dnsmasq`, `systemctl`).
- **Privileges**: Most modes require **root**.
- **Recommended system tools**: `aircrack-ng`, `iw`, `iproute2`, `hostapd`, `dnsmasq`, `iptables`, `ebtables`, `nbtscan`, `snmp`, `curl`, `systemctl`.
- **Python packages**: `scapy`, `requests`, `tqdm`, `colorama`, `netifaces`.

---

## Quick Install

```bash
sudo apt update
sudo apt install python3-pip aircrack-ng iw hostapd dnsmasq iptables ebtables nbtscan snmp curl -y
pip3 install -r requirements.txt
# or
pip3 install scapy requests tqdm colorama netifaces

sudo python3 silent_hill.py -d -n 192.168.1.0/24 -i eth0
```

## Usage Examples

```bash
sudo python silent_hill.py -c -n 192.168.1.0/24
sudo python silent_hill.py -d -n 192.168.1.0/24 -i eth0
sudo python silent_hill.py -l -i wlan0
sudo python silent_hill.py -s -i wlan0 -r 192.168.1.1 -t 192.168.1.93
sudo python silent_hill.py -k -r 192.168.1.1 -i wlan0 -t 192.168.1.46
sudo python silent_hill.py --karma-scan --karma-interface wlan0
sudo python silent_hill.py --karma free_wifi --karma-interface wlan0 --karma-interface-internet wlan1 --karma-listen
sudo python silent_hill.py --kill-karma
```

![Main menu](https://github.com/raphaelthief/SIlent-Hill/blob/main/Pic/usages.png "Usage Mode")

![Main menu](https://github.com/raphaelthief/SIlent-Hill/blob/main/Pic/karma.png "Karma Mode")

![Main menu](https://github.com/raphaelthief/SIlent-Hill/blob/main/Pic/spy.png "Spy Mode")






