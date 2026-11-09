#!/usr/bin/env python3
"""Generate synthetic Windows Security events (4624/4625) for Lab 1."""
import csv
import random
from datetime import datetime, timedelta

random.seed(42)
start = datetime(2026, 11, 9, 8, 0, 0)
users = ["thandi.m", "sipho.k", "lerato.n", "pieter.v", "naledi.d"]
internal_ips = ["10.0.2.21", "10.0.2.22", "10.0.2.23", "10.0.2.24", "10.0.2.25"]
attacker_ip = "192.168.56.101"
rows = []

# Normal activity: mostly successes, with the occasional single typo
for _ in range(60):
    t = start + timedelta(minutes=random.randint(0, 240), seconds=random.randint(0, 59))
    i = random.randrange(len(users))
    if random.random() < 0.1:
        rows.append([t, 4625, users[i], internal_ips[i], 2, "0xC000006A"])
        rows.append([t + timedelta(seconds=8), 4624, users[i], internal_ips[i], 2, "0x0"])
    else:
        rows.append([t, 4624, users[i], internal_ips[i], 2, "0x0"])

# Attack: 12 rapid failures against one account, then a success
t = start + timedelta(hours=2, minutes=14)
for i in range(12):
    rows.append([t + timedelta(seconds=i * 4), 4625, "sipho.k", attacker_ip, 3, "0xC000006A"])
rows.append([t + timedelta(seconds=52), 4624, "sipho.k", attacker_ip, 3, "0x0"])

rows.sort(key=lambda r: r[0])
with open("data/security_events.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["timestamp", "event_id", "target_user", "source_ip", "logon_type", "status"])
    for r in rows:
        w.writerow([r[0].isoformat(sep=" ")] + r[1:])
print(f"Wrote {len(rows)} events")
