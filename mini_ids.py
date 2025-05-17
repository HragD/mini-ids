from scapy.all import sniff, IP, TCP

# Blacklisted IPs (example)
blacklist = ['192.168.1.100', '10.10.10.10']

# Track SYN packets per IP
syn_count = {}

def detect_packet(pkt):
    if pkt.haslayer(IP):
        ip_src = pkt[IP].src

        # 1. Blacklist detection
        if ip_src in blacklist:
            print(f"⚠️ ALERT: Packet from blacklisted IP: {ip_src}")

        if pkt.haslayer(TCP):
            tcp_layer = pkt[TCP]

            # 2. SYN flood detection (lots of SYNs, no ACKs)
            if tcp_layer.flags == 'S':
                syn_count[ip_src] = syn_count.get(ip_src, 0) + 1
                if syn_count[ip_src] > 20:
                    print(f"🚨 POSSIBLE SYN FLOOD from {ip_src} ({syn_count[ip_src]} SYNs)")

            # 3. Port scan detection (lots of ports in short time)
            if tcp_layer.dport in [21, 22, 23, 80, 443, 3389]:
                print(f"🔍 Possible Port Scan: {ip_src} → Port {tcp_layer.dport}")

print("🔐 Mini IDS is now monitoring... (press CTRL+C to stop)")
sniff(filter="ip", prn=detect_packet, store=0)
