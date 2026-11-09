#!/usr/bin/env python3
"""Lab 1: detect brute-force attempts from Windows 4625/4624 events."""
import csv
from collections import defaultdict
from datetime import datetime, timedelta

LOG_FILE = "data/security_events.csv"
THRESHOLD = 5                              # failures needed to raise an alert
MAX_GAP = timedelta(seconds=2)            # failures closer than this belong together
SUCCESS_LOOKAHEAD = timedelta(minutes=5)   # a success this soon after counts


def load_events(path):
    events = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            row["timestamp"] = datetime.fromisoformat(row["timestamp"])
            row["event_id"] = int(row["event_id"])
            events.append(row)
    return sorted(events, key=lambda e: e["timestamp"])


def find_bursts(failures):
    """Group one IP's failures into clusters; keep clusters that reach THRESHOLD."""
    bursts, current = [], []
    for event in failures:
        if current and event["timestamp"] - current[-1]["timestamp"] > MAX_GAP:
            if len(current) >= THRESHOLD:
                bursts.append(current)
            current = []
        current.append(event)
    if len(current) >= THRESHOLD:
        bursts.append(current)
    return bursts


def main():
    events = load_events(LOG_FILE)
    failures_by_ip = defaultdict(list)
    for e in events:
        if e["event_id"] == 4625:
            failures_by_ip[e["source_ip"]].append(e)

    alerts = 0
    for ip, failures in failures_by_ip.items():
        for burst in find_bursts(failures):
            alerts += 1
            first, last = burst[0]["timestamp"], burst[-1]["timestamp"]
            accounts = sorted({e["target_user"] for e in burst})
            successes = [
                e for e in events
                if e["event_id"] == 4624
                and e["source_ip"] == ip
                and e["target_user"] in accounts
                and last < e["timestamp"] <= last + SUCCESS_LOOKAHEAD
            ]
            severity = "HIGH" if successes else "MEDIUM"

            print(f"=== ALERT {alerts}: Possible brute-force attack [{severity}] ===")
            print(f"Alert:    {len(burst)} failed logons (4625) from {ip}")
            print(f"Evidence: {first} to {last} ({(last - first).seconds}s), "
                  f"logon type {burst[0]['logon_type']}, status {burst[0]['status']}")
            print(f"Scope:    accounts targeted: {', '.join(accounts)}")
            if successes:
                s = successes[0]
                gap = (s["timestamp"] - last).seconds
                print(f"          SUCCESSFUL logon (4624) for {s['target_user']} "
                      f"from {ip} {gap}s after the last failure")
                print("Decision: ESCALATE - success follows the failures; verify the account")
            else:
                print("Decision: INVESTIGATE - no success seen yet; keep monitoring")
            print()

    if alerts == 0:
        print("No brute-force patterns found.")


if __name__ == "__main__":
    main()
