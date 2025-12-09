

# detect_ransomware_siem.py
import os, json, re
from collections import defaultdict, Counter

LOG_DIRS = [
    "logs_raw/sysmon",       # normalized Sysmon logs (JSONL)
    "logs_raw/ossec"         # OSSEC logs (JSONL)
]

OUT = "alerts/ransomware_siem.json"
os.makedirs("alerts", exist_ok=True)

# --- 1. Ransomware keyword indicators ---
KEYWORDS = [
    "ransom", "decrypt", "bitcoin", "wallet", "tor",
    "encrypt", "encrypted", "encryption", "aes", "rsa"
]

# --- 2. Shadow copy deletion commands ---
SHADOW_DELETE = [
    "vssadmin delete", "vssadmin.exe delete",
    "wmic shadowcopy delete", "powershell", "delete shadows"
]

# --- 3. Suspicious file extensions created by ransomware ---
ENCRYPT_EXT = [".locked", ".encrypted", ".enc", ".crypto", ".crypt"]

# --- 4. Ransom note file patterns ---
RANSOM_NOTES = [
    "readme.txt", "how_to_decrypt.txt",
    "decrypt_instructions", "recover_files", "ransomnote"
]

# --- 5. Suspicious processes ---
SUSPICIOUS_EXE = [
    "wannacry", "petya", "locker", "encryptor",
    "crypto", "shade", "phobos", "maze", "blackcat"
]

# --------- Counters for SIEM Detection ---------
file_write_counter = Counter()
file_ext_counter = Counter()
process_chain = defaultdict(list)

alerts = []
summary = {
    "files_scanned": 0,
    "lines_scanned": 0,
    "shadow_copy_delete": 0,
    "ransom_note_created": 0,
    "encrypted_extensions_detected": 0,
    "mass_file_encryption": 0,
    "suspicious_process": 0,
    "process_chain_alerts": 0,
    "total_alerts": 0
}

# Regex
EXT_REGEX = re.compile(r"\.(locked|encrypted|enc|crypto|crypt)")
NOTE_REGEX = re.compile(r"readme|decrypt|recover", re.I)
PROC_REGEX = re.compile(r"process|image|parent", re.I)


def add_alert(type, message, extra=None):
    global alerts
    alert = {"type": type, "message": message}
    if extra:
        alert.update(extra)
    alerts.append(alert)
    summary["total_alerts"] += 1


# --------- MAIN LOG PARSING ---------
for logdir in LOG_DIRS:
    if not os.path.exists(logdir):
        continue

    for file in os.listdir(logdir):
        if not file.endswith(".jsonl"):
            continue

        summary["files_scanned"] += 1
        path = os.path.join(logdir, file)

        with open(path, "r", errors="ignore") as fh:
            for ln in fh:
                summary["lines_scanned"] += 1

                try:
                    obj = json.loads(ln)
                except:
                    continue

                txt = obj.get("event", "").lower()

                # ---------- A) SHADOW COPY DELETION ----------
                if any(cmd in txt for cmd in SHADOW_DELETE):
                    summary["shadow_copy_delete"] += 1
                    add_alert("shadow_copy_delete", "Backup deletion detected", {"line": txt})

                # ---------- B) SUSPICIOUS FILE EXTENSIONS ----------
                m = EXT_REGEX.search(txt)
                if m:
                    ext = m.group(0)
                    file_ext_counter[ext] += 1
                    summary["encrypted_extensions_detected"] += 1
                    add_alert("encrypted_extension", "Encrypted extension found", {"extension": ext})

                # ---------- C) RANSOM NOTE CREATION ----------
                if any(note in txt for note in RANSOM_NOTES):
                    summary["ransom_note_created"] += 1
                    add_alert("ransom_note", "Ransom note file created", {"line": txt})

                # ---------- D) MASS FILE WRITES ----------
                if "file create" in txt or "write" in txt:
                    fname = obj.get("file", "unknown_file")
                    file_write_counter[fname] += 1

                # ---------- E) SUSPICIOUS PROCESS ACTIVITY ----------
                for bad in SUSPICIOUS_EXE:
                    if bad in txt:
                        summary["suspicious_process"] += 1
                        add_alert("suspicious_process", f"Suspicious EXE detected: {bad}")

                # ---------- F) PROCESS CHAIN CORRELATION ----------
                proc = obj.get("process", "")
                parent = obj.get("parent", "")

                if proc:
                    process_chain[parent].append(proc)

                    if "powershell" in parent and ("encrypt" in proc or "crypto" in proc):
                        summary["process_chain_alerts"] += 1
                        add_alert("process_chain", "Suspicious parent-child chain detected", {
                            "parent": parent,
                            "child": proc
                        })

# ----------- MASS ENCRYPTION DETECTION -----------
for fname, count in file_write_counter.items():
    if count > 20:   # threshold for "mass changes"
        summary["mass_file_encryption"] += 1
        add_alert("mass_encryption", "Mass file modification detected",
                  {"file": fname, "writes": count})

# ----------- WRITE OUTPUT JSON -----------
with open(OUT, "w") as f:
    json.dump({"summary": summary, "alerts": alerts}, f, indent=2)

# ----------- TERMINAL OUTPUT -----------
print("\n[✓] SIEM-Level Ransomware Detection Complete")
print("-------------------------------------------")
print(f"Files scanned                 : {summary['files_scanned']}")
print(f"Lines scanned                 : {summary['lines_scanned']}")
print("-------------------------------------------")
print("Detected Behaviors:")
print(f" - Shadow copy deletion       : {summary['shadow_copy_delete']}")
print(f" - Encrypted extensions       : {summary['encrypted_extensions_detected']}")
print(f" - Ransom notes created       : {summary['ransom_note_created']}")
print(f" - Mass file encryption       : {summary['mass_file_encryption']}")
print(f" - Suspicious processes       : {summary['suspicious_process']}")
print(f" - Process chain anomalies    : {summary['process_chain_alerts']}")
print("-------------------------------------------")
print(f"Total ransomware alerts       : {summary['total_alerts']}")
print(f"Alerts written to             : {OUT}\n")
