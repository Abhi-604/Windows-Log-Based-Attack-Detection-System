# detect_bruteforce_ossec_siem.py
import os, json, re
from collections import defaultdict

LOG_DIR = "logs_raw/ossec/"  
OUT = "alerts/bruteforce_siem.json"
os.makedirs("alerts", exist_ok=True)

FAILED_KEYWORDS = [
    "authentication failure",
    "failed password",
    "invalid user",
    "invalid password",
    "login incorrect",
    "login failed",
    "4625"
]

SUCCESS_KEYWORDS = [
    "login successful",
    "session opened",
    "accepted password",
    "authentication success"
]

IP_REGEX = re.compile(r"from\s+(\d+\.\d+\.\d+\.\d+)")
USER_REGEX = re.compile(r"user\s+([^\s,]+)", re.I)

fail_count_ip = defaultdict(int)
fail_count_user = defaultdict(int)
users_per_ip = defaultdict(set)
ips_per_user = defaultdict(set)
fail_history = defaultdict(list)

total_failures = 0
total_successes = 0
total_lines = 0
total_files = 0

alerts = []

# counters for categories
category_counts = {
    "ip_bruteforce": 0,
    "user_bruteforce": 0,
    "fail_success_bruteforce": 0,
    "username_spraying": 0,
    "distributed_bruteforce": 0
}

def extract_ip(text):
    m = IP_REGEX.search(text)
    return m.group(1) if m else "unknown_ip"

def extract_user(text):
    m = USER_REGEX.search(text)
    return m.group(1) if m else "unknown_user"


# -------- MAIN LOG PARSING ----------
for file in os.listdir(LOG_DIR):
    if not file.endswith(".jsonl"):
        continue

    total_files += 1
    path = os.path.join(LOG_DIR, file)

    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for ln in fh:
            total_lines += 1

            try:
                obj = json.loads(ln)
            except:
                continue

            txt = obj.get("event", "").lower()

            # -------- FAILED LOGIN --------
            if any(k in txt for k in FAILED_KEYWORDS):
                ip = extract_ip(txt)
                user = extract_user(txt)

                total_failures += 1
                fail_count_ip[ip] += 1
                fail_count_user[user] += 1

                users_per_ip[ip].add(user)
                ips_per_user[user].add(ip)

                fail_history[ip].append("FAIL")

            # -------- SUCCESSFUL LOGIN --------
            elif any(k in txt for k in SUCCESS_KEYWORDS):
                ip = extract_ip(txt)
                user = extract_user(txt)

                total_successes += 1

                if fail_history[ip].count("FAIL") >= 5:
                    category_counts["fail_success_bruteforce"] += 1
                    alerts.append({
                        "type": "fail_success_bruteforce",
                        "ip": ip,
                        "user": user,
                        "failed_attempts": fail_history[ip].count("FAIL"),
                    })

                fail_history[ip] = [] 


# -------- SIEM CORRELATION RULES --------

# Rule 1: IP brute force
for ip, count in fail_count_ip.items():
    if count >= 5:
        category_counts["ip_bruteforce"] += 1
        alerts.append({
            "type": "ip_bruteforce",
            "ip": ip,
            "failed_attempts": count
        })

# Rule 2: Username-targeted brute force
for user, count in fail_count_user.items():
    if count >= 5:
        category_counts["user_bruteforce"] += 1
        alerts.append({
            "type": "user_bruteforce",
            "user": user,
            "failed_attempts": count
        })

# Rule 3: Username spraying
for ip, user_set in users_per_ip.items():
    if len(user_set) >= 5:
        category_counts["username_spraying"] += 1
        alerts.append({
            "type": "username_spraying",
            "ip": ip,
            "user_count": len(user_set)
        })

# Rule 4: Distributed brute force
for user, ip_set in ips_per_user.items():
    if len(ip_set) >= 5:
        category_counts["distributed_bruteforce"] += 1
        alerts.append({
            "type": "distributed_bruteforce",
            "user": user,
            "ip_count": len(ip_set)
        })


# -------- SAVE OUTPUT --------
result = {
    "total_files_scanned": total_files,
    "total_log_lines": total_lines,
    "failed_logins": total_failures,
    "successful_logins": total_successes,
    "alert_summary": category_counts,
    "total_alerts": len(alerts),
    "alerts": alerts
}

with open(OUT, "w") as f:
    json.dump(result, f, indent=2)


# -------- TERMINAL OUTPUT --------
print("\n[✓] SIEM-Enhanced Brute Force Detection Complete")
print("------------------------------------------------")
print(f"Files scanned               : {total_files}")
print(f"Total log lines             : {total_lines}")
print(f"Failed logins               : {total_failures}")
print(f"Successful logins           : {total_successes}")
print("------------------------------------------------")
print("Bruteforce Type Breakdown:")
print("  IP brute-force            :", category_counts['ip_bruteforce'])
print("  User-targeted brute-force :", category_counts['user_bruteforce'])
print("  Fail→Success brute-force   :", category_counts['fail_success_bruteforce'])
print("  Username spraying         :", category_counts['username_spraying'])
print("  Distributed brute-force   :", category_counts['distributed_bruteforce'])
print("------------------------------------------------")
print("Total SIEM alerts           :", len(alerts))
print("Alerts written to           :", OUT, "\n")
