# detect_ddos_pcap.py
import struct, json, collections, sys, os, statistics

PCAP = sys.argv[1] if len(sys.argv) > 1 else "mixed_ddos_demo.pcap"
OUT = "alerts/ddos_alerts.json"
os.makedirs("alerts", exist_ok=True)

def detect_ddos(path):
    with open(path, 'rb') as f:
        data = f.read()

    off = 24
    pkt_count = 0
    per_second = collections.Counter()
    syn_count = 0
    unique_srcs_per_dst = collections.defaultdict(set)

    while off + 16 <= len(data):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', data[off:off+16])
        off += 16

        if off + incl_len > len(data):
            break

        pkt = data[off:off+incl_len]
        off += incl_len
        pkt_count += 1

        # timestamps for PPS
        per_second[int(ts_sec)] += 1

        # Ethernet check
        if len(pkt) < 14:
            continue

        eth_type = struct.unpack('!H', pkt[12:14])[0]

        if eth_type == 0x0800:
            payload = pkt[14:]
            if len(payload) < 20:
                continue

            ihl = (payload[0] & 0x0F) * 4
            proto = payload[9]
            src = ".".join(str(x) for x in payload[12:16])
            dst = ".".join(str(x) for x in payload[16:20])

            # TCP (SYN flood)
            if proto == 6 and len(payload) >= ihl + 20:
                tcp_hdr = payload[ihl:ihl+20]
                sport, dport, _, _, off_reserved_flags = struct.unpack('!HHLLH', tcp_hdr[:14])
                flags = off_reserved_flags & 0x01FF

                SYN = bool(flags & 0x002)
                ACK = bool(flags & 0x010)

                if SYN and not ACK:
                    syn_count += 1
                    unique_srcs_per_dst[dst].add(src)

    # Calculate stats
    peak_pps = max(per_second.values()) if per_second else 0
    median_pps = statistics.median(per_second.values()) if per_second else 0

    # Build report
    report = {
        "pcap_file": path,
        "total_packets": pkt_count,
        "duration_seconds": len(per_second),
        "peak_pps": peak_pps,
        "median_pps": median_pps,
        "syn_count": syn_count,
        "unique_attackers_per_victim": {k: len(v) for k, v in unique_srcs_per_dst.items()},
        "alerts": []
    }

    # Detection rules
    if peak_pps >= 1000:
        report["alerts"].append({"reason": "High packets per second", "peak_pps": peak_pps})

    for dst, uniq in report["unique_attackers_per_victim"].items():
        if uniq >= 50:
            report["alerts"].append({
                "reason": "Many unique sources to single dst",
                "dst": dst,
                "unique_sources": uniq
            })

    if syn_count >= 500:
        report["alerts"].append({
            "reason": "High SYN-only packet count",
            "syn_count": syn_count
        })

    return report


# Run detection
result = detect_ddos(PCAP)

with open(OUT, "w") as f:
    json.dump(result, f, indent=2)


# ------------------------------------------
# PRETTY OUTPUT SECTION
# ------------------------------------------
print("\n[✓] DDoS Analysis Complete")
print("----------------------------------")
print(f"PCAP file             : {PCAP}")
print(f"Total packets         : {result['total_packets']}")
print(f"Duration (seconds)    : {result['duration_seconds']}")
print(f"Peak PPS              : {result['peak_pps']}")
print(f"Median PPS            : {result['median_pps']}")
print(f"Total SYN packets     : {result['syn_count']}")

# unique attackers
victim = list(result["unique_attackers_per_victim"].keys())[0]
attackers = result["unique_attackers_per_victim"][victim]
print(f"Unique attackers      : {attackers}")
print(f"Alerts generated      : {len(result['alerts'])}")
print("----------------------------------")
print(f"Alerts written to     : {OUT}\n")
