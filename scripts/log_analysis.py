import re
import csv
from collections import Counter
from pathlib import Path

LOG_FILE = Path("../sample_logs/syslog_sample.log")
OUTPUT_CSV = Path("../outputs/suspicious_activity.csv")

FAILED_SSH_RE = re.compile(r"Failed password .* from (?P<ip>\d+\.\d+\.\d+\.\d+)")
SUSPICIOUS_UA_RE = re.compile(r'(sqlmap|nmap|nikto)', re.IGNORECASE)
APP_FAILED_RE = re.compile(r"user=(?P<user>\w+).*status=failed ip=(?P<ip>\d+\.\d+\.\d+\.\d+)")

def analyze():
    if not LOG_FILE.exists():
        print(f"Log file not found: {LOG_FILE}")
        return

    suspicious_events = []
    ip_counter = Counter()
    failed_user_counter = Counter()

    with LOG_FILE.open() as f:
        for line in f:
            ts = line[:16].strip()

            m = FAILED_SSH_RE.search(line)
            if m:
                ip = m.group("ip")
                suspicious_events.append({"type": "failed_ssh","timestamp": ts,"ip": ip,"raw": line.strip()})
                ip_counter[ip] += 1
                continue

            if SUSPICIOUS_UA_RE.search(line):
                ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                ip = ip_match.group(1) if ip_match else ""
                suspicious_events.append({"type": "suspicious_user_agent","timestamp": ts,"ip": ip,"raw": line.strip()})
                if ip: ip_counter[ip] += 1
                continue

            m2 = APP_FAILED_RE.search(line)
            if m2:
                ip = m2.group("ip")
                user = m2.group("user")
                suspicious_events.append({"type": "app_failed_login","timestamp": ts,"ip": ip,"user": user,"raw": line.strip()})
                ip_counter[ip] += 1
                failed_user_counter[user] += 1
                continue

    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_CSV.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=["type","timestamp","ip","user","raw"])
        writer.writeheader()
        for e in suspicious_events:
            writer.writerow({"type": e.get("type",""),"timestamp": e.get("timestamp",""),"ip": e.get("ip",""),"user": e.get("user",""),"raw": e.get("raw","")})

    print("=== Summary ===")
    print(f"Total suspicious events: {len(suspicious_events)}")
    print("Top IPs by suspicious activity:")
    for ip, count in ip_counter.most_common(5):
        print(f"  {ip}: {count}")
    if failed_user_counter:
        print("Top failed usernames:")
        for user, count in failed_user_counter.most_common(5):
            print(f"  {user}: {count}")
    print(f"Saved suspicious events to: {OUTPUT_CSV}")

if __name__ == "__main__":
    analyze()
