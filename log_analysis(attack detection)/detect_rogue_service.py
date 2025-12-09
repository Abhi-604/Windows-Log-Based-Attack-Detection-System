# # detect_rogue_service.py
# import os, json, glob

# OUT_DIR = "alerts"
# os.makedirs(OUT_DIR, exist_ok=True)

# base = "logs_raw"
# patterns = [
#     os.path.join(base, "ossec", "*.jsonl"),
#     os.path.join(base, "atomic", "*.jsonl")
# ]

# SERVICE_KW = ["7045", "service installed", "new service", "install service", "service created", "service"]

# alerts = []
# total_lines = 0
# total_files = 0

# for pattern in patterns:
#     for path in glob.glob(pattern):
#         total_files += 1
#         fname = os.path.basename(path)
#         with open(path, "r", encoding="utf-8", errors="ignore") as fh:
#             for ln in fh:
#                 total_lines += 1
#                 obj = json.loads(ln)
#                 txt = obj.get("event","").lower()

#                 if any(kw in txt for kw in SERVICE_KW):
#                     alerts.append({
#                         "source_file": fname,
#                         "match": next((kw for kw in SERVICE_KW if kw in txt), None),
#                         "snippet": txt[:200]
#                     })

# out_file = os.path.join(OUT_DIR, "service_alerts.json")
# with open(out_file, "w", encoding="utf-8") as f:
#     json.dump(alerts, f, indent=2)

# print("\n[INFO] Files scanned:", total_files)
# print("[INFO] Log lines scanned:", total_lines)
# print("[INFO] Service alerts:", len(alerts))
# print("[INFO] Output:", out_file)


#!/usr/bin/env python3
# detect_rogue_service_siem.py
# SIEM-level rogue service detection for Sysmon/OSSEC JSONL logs.

import os, json, re
from collections import defaultdict, Counter

# Adjust these paths if your logs are somewhere else
LOG_DIRS = [
    "logs_raw/sysmon",   # Sysmon JSONL logs
    "logs_raw/ossec"     # OSSEC JSONL logs (may contain "event" text)
]

OUT = "alerts/rogue_service_siem.json"
os.makedirs("alerts", exist_ok=True)

# Heuristics / lists
SERVICE_CREATE_KEYS = ["service installed", "service created", "4697", "7045", "sc.exe create", "new-service", "create service"]
SUSPICIOUS_BINPATH_KEYWORDS = [
    r"\\users\\", r"\\appdata\\", r"\\temp\\", r"\\downloads\\", r"\\local\\temp\\", r"\\users\/",
    r"\.zip", r"\.rar", r"\\program files\\.*\\temp", r"\\tmp\\"
]
SCRIPT_INTERPRETERS = ["powershell.exe", "powershell", "cmd.exe", "cscript.exe", "wscript.exe", "pwsh.exe"]
SUSPICIOUS_SERVICE_NAMES = [
    "updater", "update", "crypt", "svc", "service", "helper", "agent", "windowsupdate", "svchost-", "netserv"
]
ALLOWLISTED_PATHS = [r"\\windows\\system32\\", r"\\program files\\", r"\\program files \(x86\)\\"]
DRIVER_EVENTS = ["driver loaded", "service start type"]

# regexes
IP_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+)")
BINPATH_RE = re.compile(r'binpath\s*=\s*("?)([^"\r\n]+)\1', re.I)
REG_SERV_KEY = re.compile(r"HKLM\\SYSTEM\\CurrentControlSet\\Services\\", re.I)
IMAGE_RE = re.compile(r"(?:image|exe|binary|path)\s*[:=]\s*([^\s,]+)", re.I)
EVENTID_RE = re.compile(r"\b(4697|7045)\b")
SERVICE_NAME_RE = re.compile(r"(?:service|svc|name)\s*[:=]\s*([A-Za-z0-9_\-\.]+)", re.I)

# outputs & counters
alerts = []
summary = Counter()
files_scanned = 0
lines_scanned = 0

def add_alert(atype, message, info=None):
    summary["total_alerts"] += 1
    summary[atype] += 1
    a = {"type": atype, "message": message}
    if info:
        a.update(info)
    alerts.append(a)

def lower(x):
    return x.lower() if isinstance(x, str) else ""

def looks_suspicious_binpath(binpath):
    bp = lower(binpath)
    # suspicious if it contains user/temp/downloads or not in allowlisted system paths
    if any(re.search(p, bp) for p in SUSPICIOUS_BINPATH_KEYWORDS):
        return True
    # if path is not in allowlisted system paths and points to an .exe, suspect it
    if any(allow in bp for allow in ALLOWLISTED_PATHS):
        return False
    # also suspicious if it's a script or points to powershell/cmd
    if any(interp in bp for interp in SCRIPT_INTERPRETERS):
        return True
    # otherwise, if it's outside system folders and is an exe, flag
    if bp.endswith(".exe") and not any(p in bp for p in ALLOWLISTED_PATHS):
        return True
    return False

def check_suspicious_service_name(name):
    n = lower(name)
    # if name contains suspicious substrings
    for s in SUSPICIOUS_SERVICE_NAMES:
        if s in n:
            return True
    return False

# Iterate logs
for logdir in LOG_DIRS:
    if not os.path.isdir(logdir):
        continue
    for fname in os.listdir(logdir):
        if not fname.endswith(".jsonl"):
            continue
        files_scanned += 1
        path = os.path.join(logdir, fname)
        try:
            fh = open(path, "r", encoding="utf-8", errors="ignore")
        except Exception as e:
            continue

        with fh:
            for ln in fh:
                lines_scanned += 1
                try:
                    obj = json.loads(ln)
                except Exception:
                    # fallback: treat line as raw text in field 'event' if possible
                    obj = {"event": ln.strip()}

                # normalize text fields
                txt = lower(obj.get("event", "")) or lower(obj.get("message", "")) or ""
                # try to extract an "eventid" or "id"
                event_id = str(obj.get("eventid", "") or obj.get("id", "") or "")
                # try find explicit event id in text
                m_e = EVENTID_RE.search(txt)
                if m_e:
                    event_id = m_e.group(1)

                # -------------- Rule: Windows Service Events (4697 / 7045 / 7045-like) --------------
                # If event id 4697 or 7045 or explicit phrase appears
                if event_id in ("4697", "7045") or any(k in txt for k in ["a service was installed", "a service was created", "service was installed", "service was created"]):
                    svc_name = obj.get("service_name") or obj.get("target_object") or ""
                    svc_bin = obj.get("image") or obj.get("image_path") or obj.get("binary") or ""
                    # also check text for binpath
                    m_bin = BINPATH_RE.search(txt)
                    if m_bin:
                        svc_bin = svc_bin or m_bin.group(2)
                    info = {"file": fname, "event_id": event_id, "raw": txt}
                    if svc_name:
                        info["service_name"] = svc_name
                    if svc_bin:
                        info["binpath"] = svc_bin
                    add_alert("service_event", "Service install/create event detected", info)

                # -------------- Rule: sc.exe / New-Service usage --------------
                if "sc.exe create" in txt or "sc create" in txt or "new-service" in txt or "create service" in txt:
                    m_bin = BINPATH_RE.search(txt)
                    svc_bin = m_bin.group(2) if m_bin else (obj.get("image") or "")
                    svc_name_m = SERVICE_NAME_RE.search(txt)
                    svc_name_val = svc_name_m.group(1) if svc_name_m else obj.get("service_name") or ""
                    add_alert("sc_create", "sc.exe / New-Service detected", {"file": fname, "service_name": svc_name_val, "binpath": svc_bin, "raw": txt})

                # -------------- Rule: Registry change under Services key --------------
                if REG_SERV_KEY.search(txt) or ("services\\" in txt and ("add" in txt or "create" in txt or "reg add" in txt)):
                    add_alert("registry_service_mod", "Registry key under Services modified", {"file": fname, "raw": txt})

                # -------------- Rule: Suspicious binPath paths --------------
                # Look for binpath in JSON fields or text
                binpath = obj.get("binpath") or obj.get("path") or obj.get("image") or ""
                if not binpath:
                    m_bin2 = BINPATH_RE.search(txt)
                    if m_bin2:
                        binpath = m_bin2.group(2)
                if binpath and looks_suspicious_binpath(binpath):
                    add_alert("suspicious_binpath", "Service binary path looks suspicious", {"file": fname, "binpath": binpath, "raw": txt})

                # -------------- Rule: Script-based services (powershell -> service) --------------
                # If a service is being created via powershell or a script interpreter detected in the same line
                if any(interp in txt for interp in ["powershell", "pwsh", "cmd.exe", "cscript", "wscript"]):
                    # but only alert if also mentions service creation or binpath
                    if "service" in txt or "sc.exe" in txt or BINPATH_RE.search(txt):
                        add_alert("script_service_creation", "Service creation via script interpreter detected", {"file": fname, "raw": txt})

                # -------------- Rule: Suspicious service names --------------
                svc_name_text = obj.get("service_name") or ""
                if not svc_name_text:
                    m_sn = SERVICE_NAME_RE.search(txt)
                    if m_sn:
                        svc_name_text = m_sn.group(1)

                if svc_name_text:
                    lower_name = svc_name_text.lower()
                    for sn in SUSPICIOUS_SERVICE_NAMES:
                        if sn in lower_name:
                            add_alert("suspicious_service_name", "Suspicious service name detected", {
                                "file": fname,
                                "service_name": svc_name_text,
                                "raw": txt
                            })
                            break

                # -------------- Rule: Driver load / kernel persistence --------------
                if any(d in txt for d in ["driver loaded", "driver install", "kernel driver", "service start type driver"]):
                    add_alert("driver_loaded", "Driver load / kernel driver event", {"file": fname, "raw": txt})

                # -------------- Rule: Suspicious unsigned image (best-effort) --------------
                # Many Sysmon JSON exports include "signed" or "signature" fields; try to inspect if present
                signed_field = obj.get("signed") or obj.get("signature") or obj.get("signer") or ""
                if signed_field and isinstance(signed_field, str):
                    if "microsoft" not in signed_field.lower() and signed_field.strip() != "":
                        add_alert("unsigned_image", "Binary signed by non-Microsoft signer or unsigned", {"file": fname, "signer": signed_field, "raw": txt})

                # -------------- Rule: Parent-child anomaly (powershell -> installsvc exe) --------------
                parent = lower(obj.get("parent", "") or obj.get("parent_image", "") or "")
                proc = lower(obj.get("process", "") or obj.get("image", "") or obj.get("process_name", ""))
                if ("powershell" in parent or "cmd.exe" in parent) and ("service" in proc or "sc.exe" in proc or "svchost" in proc or ".exe" in proc):
                    add_alert("parent_child_anomaly", "Script parent created service-related process", {"file": fname, "parent": parent, "child": proc, "raw": txt})

# End reading logs

# Summarize and write output
result = {
    "files_scanned": files_scanned,
    "lines_scanned": lines_scanned,
    "summary": dict(summary),
    "alerts": alerts
}

with open(OUT, "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2)

# Pretty terminal output
print("\n[✓] SIEM-Level Rogue Service Detection Complete")
print("------------------------------------------------")
print(f"Files scanned      : {files_scanned}")
print(f"Lines scanned      : {lines_scanned}")
print("------------------------------------------------")
print("Alerts by category:")
for k, v in summary.items():
    if k == "total_alerts":
        continue
    print(f"  {k:25s} : {v}")
print("------------------------------------------------")
print(f"Total alerts       : {summary['total_alerts']}")
print(f"Alerts written to  : {OUT}\n")
