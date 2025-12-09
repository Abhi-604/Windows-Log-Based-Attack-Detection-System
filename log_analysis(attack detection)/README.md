
# Windows Log-Based Attack Detection System
### (Brute-Force Login, Ransomware, DDoS, Rogue Services & Network Bruteforce – SIEM-Level Detection)

This project implements a complete Windows host & network attack-detection framework using:

- Windows Event Logs  
- Sysmon telemetry  
- OSSEC logs  
- PCAP packet capture data  
- SIEM-style correlation rules  

It detects five major attack categories:

1. **Brute Force Login Attacks**
2. **Ransomware Behavior & Keyword Detection**
3. **DDoS Traffic Spike Detection**
4. **Rogue Service / Persistence Detection**
5. **Network-Based Bruteforce & Port Scans**

Each script generates:
- JSON alert output (`/alerts/`)
- Terminal summary
- SIEM-style categorized alerts

---

# 📂 Project Structure
```
/log_ass_nss
│
├── detect_bruteforce_ossec2.py
├── detect_ransomware_keywords.py
├── detect_rogue_service.py
├── detect_ddos_pcap.py
├── detect_network_bruteforce_pcap.py
│
├── logs_raw/
│   ├── sysmon/
│   ├── ossec/
│   └── atomic/
│
└── alerts/
    ├── ddos_alerts.json
    ├── bruteforce_siem.json
    ├── ransomware_alerts.json
    ├── service_alerts.json
    └── network_bruteforce_alerts.json
```

---

# 🚀 How to Run

## 🔹 DDoS Detection
```
python detect_ddos_pcap.py mixed_ddos_demo.pcap
```

## 🔹 Network Bruteforce / Port Scan
```
python detect_network_bruteforce_pcap.py mixed_ddos_demo.pcap
```

## 🔹 OSSEC Log-Based Brute Force
```
python detect_bruteforce_ossec2.py
```

## 🔹 Ransomware Detection
```
python detect_ransomware_keywords.py
```

## 🔹 Rogue Service Detection
```
python detect_rogue_service.py
```

---

# 🧠 Detection Logic Summary

## 1️⃣ Brute Force Login Detection
Detects:
- Failed logins  
- Login attempts per IP  
- Targeted usernames  
- Username spraying  
- Distributed brute-force  
- Fail → Success brute-force confirmation  

✔ Output: `/alerts/bruteforce_siem.json`

---

## 2️⃣ Ransomware Behavior Detection
Detects:
- Shadow copy deletion  
- Encrypted extensions (`.enc`, `.locked`, `.crypto`)  
- Ransom notes  
- Massive file writes  
- Suspicious EXEs  
- Parent-child process anomalies  

✔ Output: `/alerts/ransomware_alerts.json`

---

## 3️⃣ DDoS Detection from PCAP
Analyzes:
- PPS (Packets Per Second)
- Median PPS
- SYN flood patterns
- Unique attacker counts

Flags:
- Peak PPS ≥ 1000  
- ≥ 50 unique sources to same victim  
- SYN packet floods  

✔ Output: `/alerts/ddos_alerts.json`

---

## 4️⃣ Rogue Service Detection
Detects:
- Service installation events (4697 / 7045)
- `sc.exe create` misuse  
- Services in Temp/AppData  
- Unsigned binaries  
- Script-based service creation  
- Driver load events  

✔ Output: `/alerts/rogue_service_siem.json`

---

## 5️⃣ Network Bruteforce Detection (PCAP)
Detects:
- Repeated SYN attempts to same port  
- Multi-port scans  
- High SYN-only traffic  

✔ Output: `/alerts/network_bruteforce_alerts.json`

---

# 📊 Example Output Summaries

## Brute Force
```
Failed logins               : 15
IP brute-force              : 2
User-targeted brute-force   : 2
Fail→Success brute-force     : 1
Total SIEM alerts           : 5
```

## Ransomware
```
Files scanned: 127
Log lines scanned: 27659
Ransomware alerts: 243
```

## Rogue Services
```
Service alerts: 1433
```

## DDoS
```
Packets: 80000
Peak PPS: 1000
Unique attackers: 300
Alerts: 3
```

## Network Bruteforce
```
Total SYN attempts: 28065
Detected bruteforce: 1470
Total alerts: 1470
```

---

# ⭐ Key Features
- Works like a mini-SIEM  
- Host + network attack detection  
- JSON alerting  
- Correlation rules  
- Pure Python  
- Ideal for SOC/DFIR learning  

---

# 🧩 Use Cases
- Academic cybersecurity project  
- SOC analyst practice  
- Threat detection engineering  
- DFIR investigation labs  

---

# 📌 Future Enhancements
- MITRE ATT&CK mapping  
- Real-time streaming  
- ELK/Splunk dashboards  
- ML anomaly detection  

---

# 👤 Author
Abhishek Gour
Cybersecurity | Threat Detection  

---



