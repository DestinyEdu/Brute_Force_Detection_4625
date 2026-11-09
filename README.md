# Brute-Force Detection (Windows Event ID 4625)

Part of the **AI SOC Lab**, a set of SOC and fraud-detection labs built around a simulated fintech (CubedPay).

## Objective
Detect repeated failed Windows logons (Event ID 4625) from one source, and flag when a successful logon (4624) follows them.

## What's in this repo
| Path | Purpose |
|---|---|
| `generate_logs.py` | Creates synthetic Windows Security events (normal activity plus one simulated attack) |
| `data/security_events.csv` | The generated events |
| `detections/brute_force.py` | Detector: groups failures by source IP, applies a threshold and time gap, checks for a following success |
| `reports/alert_output.txt` | Detector output |
| `reports/incident_report.md` | Full incident report (Alert, Evidence, Scope, Decision) |

## How to run
```bash
python3 generate_logs.py
python3 detections/brute_force.py
```

## Result
One HIGH alert: 12 failed logons from 192.168.56.101 against `sipho.k` in 44 seconds, followed by a successful logon 8 seconds later. Decision: escalate.

## Detector tuning
| Threshold | Gap | Result |
|---|---|---|
| 5 | 60 s | Correct: one alert for the attack |
| 5 | 2 s | False negative: attack missed |
| 1 | 60 s | False positives: every typo alerted |

## Limitations
Synthetic data and fixed thresholds. A slow or distributed attack would evade it. Real Windows logs will validate it in a later lab.

## Ethics and scope
All data is synthetic and all testing happens in an isolated lab network. No real systems or customer data are involved.

## MITRE ATT&CK
T1110.001 Brute Force: Password Guessing
