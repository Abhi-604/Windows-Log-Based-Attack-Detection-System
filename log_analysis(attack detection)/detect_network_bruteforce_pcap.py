# detect_network_bruteforce_pcap.py
import struct, os, json, collections, sys

PCAP = sys.argv[1] if len(sys.argv) > 1 else "mixed_ddos_demo.pcap"
OUT = "alerts/network_bruteforce_alerts.json"
os.makedirs("alerts", exist_ok=True)

def parse_connections(path):
    with open(path, 'rb') as f:
        data = f.read()

    off = 24
    pkt_count = 0

    conn_attempts = collections.Counter()   # (src, dst_port) -> count
    src_dstports = collections.defaultdict(set)
    total_syn_attempts = 0

    while off + 16 <= len(data):
        # pcap record header
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', data[off:off+16])
        off += 16

        if off + incl_len > len(data):
            break

        pkt = data[off:off+incl_len]
        off += incl_len
        pkt_count += 1

        if len(pkt) < 14:
            continue

        eth_type = struct.unpack('!H', pkt[12:14])[0]

        # IPv4
        if eth_type == 0x0800:
            payload = pkt[14:]
            if len(payload) < 20:
                continue

            ihl = (payload[0] & 0x0F) * 4
            proto = payload[9]

            src = ".".join(str(x) for x in payload[12:16])

            # TCP brute-force / scan detection
            if proto == 6 and len(payload) >= ihl + 20:
                tcp_hdr = payload[ihl:ihl+20]
                sport, dport, seq, ack, off_flags = struct.unpack('!HHLLH', tcp_hdr[:14])
                flags = off_flags & 0x01FF

                SYN = bool(flags & 0x002)
                ACK = bool(flags & 0x010)

                if SYN and not ACK:
                    total_syn_attempts += 1
                    conn_attempts[(src, dport)] += 1
                    src_dstports[src].add(dport)

    return pkt_count, conn_attempts, src_dstports, total_syn_attempts


# Run parsing
pkt_count, conn_attempts, src_dstports, total_syn = parse_connections(PCAP)

alerts = []
bruteforce_count = 0
scan_count = 0

# Rule 1 → Repeated attempts to same port
for (src, dport), count in conn_attempts.items():
    if count > 10:
        bruteforce_count += 1
        alerts.append({
            "type": "bruteforce",
            "src": src,
            "dst_port": dport,
            "attempts": count
        })

# Rule 2 → Many destination ports (port scan)
for src, ports in src_dstports.items():
    if len(ports) > 20:
        scan_count += 1
        alerts.append({
            "type": "scan",
            "src": src,
            "unique_ports": len(ports)
        })

result = {
    "pcap_file": PCAP,
    "total_packets": pkt_count,
    "total_syn_attempts": total_syn,
    "conn_attempt_entries": len(conn_attempts),
    "bruteforce_alerts": bruteforce_count,
    "scan_alerts": scan_count,
    "total_alerts": len(alerts),
    "alerts": alerts
}

# Save results
with open(OUT, "w") as f:
    json.dump(result, f, indent=2)


# ------------------------------------------
# PRETTY TERMINAL OUTPUT
# ------------------------------------------
print("\n[✓] Bruteforce / Scan Analysis Complete")
print("----------------------------------")
print(f"PCAP file               : {PCAP}")
print(f"Total packets           : {pkt_count}")
print(f"Total SYN attempts      : {total_syn}")
print(f"Conn (src→dport) pairs  : {len(conn_attempts)}")
print(f"Detected bruteforce     : {bruteforce_count}")
print(f"Detected scans          : {scan_count}")
print(f"Total alerts generated  : {len(alerts)}")
print("----------------------------------")
print(f"Alerts written to       : {OUT}\n")
