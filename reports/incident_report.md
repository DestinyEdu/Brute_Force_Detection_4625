# Incident Report: Possible Brute-Force Attack with Successful Login

**Lab:** AI SOC Lab, Lab 1 (Brute-force detection, Event ID 4625)
**Date of events:** 2026-11-09
**Data:** Synthetic Windows Security events (`data/security_events.csv`). This is a simulated scenario, not a real incident.
**Detector:** `detections/brute_force.py`
**Severity:** HIGH
**Decision:** ESCALATE

---

## 1. Alert

The detector raised a HIGH alert for a possible brute-force attack. Twelve failed logons (Event ID 4625) came from one source IP against one account within 44 seconds. A successful logon (Event ID 4624) followed from the same IP.

## 2. Evidence

| Item | Finding |
|---|---|
| Source IP | 192.168.56.101 (the Kali VM in this lab) |
| Target account | sipho.k |
| Failed logons (4625) | 12 |
| First failure | 10:14:00 |
| Last failure | 10:14:44 (44 seconds after the first) |
| Spacing | One failure about every 4 seconds |
| Successful logon (4624) | 10:14:52, same account, same IP |
| Gap from last failure to success | 8 seconds |
| Logon type | 3 (network logon, not at the keyboard) |
| Failure status | 0xC000006A (valid username, wrong password) |

**Why this pattern matters**
- The failures were too frequent and regular for a person mistyping a password.
- Status 0xC000006A shows the attacker used a real username and was guessing passwords.
- Logon type 3 shows the attempts came over the network. The other users in the data log on interactively (type 2) from internal addresses.
- A success from the same IP and account straight after repeated failures suggests the guessing may have worked.

**Baseline for comparison:** the other accounts showed only isolated single failures, each followed by a successful retry from their usual internal address. None came near the alert threshold.

## 3. Scope

- **Affected account:** one (sipho.k).
- **Source:** one IP (192.168.56.101).
- **Link between failures and success:** the successful logon came from the same IP, for the same account, 8 seconds after the last failure. The success is treated as connected to the failures.
- **Other accounts:** no failed or successful logons from this IP against any other account were found in the dataset.
- **Not yet known:** what the session did after logging in. The available log shows only authentication events, so any activity after 10:14:52 (files accessed, data moved, further logons) needs a separate investigation.

## 4. Decision

**Escalate.** Twelve failures in 44 seconds against one account, followed 8 seconds later by a successful logon from the same IP, indicates possible account compromise. The combination of volume, speed, consistency and outcome justifies escalation, not any single number alone.

## 5. Recommended actions

These are recommendations for analyst or team approval, not automatic actions.

1. Review the activity of the sipho.k session that started at 10:14:52.
2. Reset the sipho.k password and invalidate active sessions.
3. Recommend blocking or rate-limiting 192.168.56.101, pending approval.
4. Check whether any other accounts have logons from this IP.
5. Consider an account lockout policy and multi-factor authentication to make guessing less effective.

## 6. Detector tuning notes

| Setting | Result | Lesson |
|---|---|---|
| Threshold 5, gap 60 seconds (final) | One HIGH alert for the real attack, none for normal typos | Correct behaviour on this data |
| Threshold 5, gap 2 seconds | Attack missed (false negative) | Failures are 4 seconds apart, so a 2-second gap splits them into clusters too small to alert |
| Threshold 1, gap 60 seconds | Every single typo alerted, and each typo's quick successful retry made it HIGH (false positives) | A low threshold cannot separate a typo from an attack and would flood analysts |

**Overall lesson:** the threshold and the gap must be tuned together against what normal behaviour looks like in the data.

## 7. Limitations

- The data is synthetic and the attack is simple. Real attackers may slow down, spread attempts across IPs, or use many accounts (credential stuffing, covered in Lab 2).
- The detector uses fixed thresholds, so it can be evaded by a slow attack.
- Real Windows logs will be used to validate this detector in Lab 8.

## 8. MITRE ATT&CK reference

T1110.001: Brute Force, Password Guessing.

## 9. 60-90 second briefing

"At 10:14 on 9 November, our detector flagged twelve failed Windows logons against the account sipho.k, all from one IP, 192.168.56.101, in 44 seconds. The failures were network logons with a wrong-password status, which tells us the attacker knew the username and was guessing passwords. Eight seconds after the last failure there was a successful logon from the same IP for the same account. Only one account was affected, but we don't yet know what the session did afterwards. I'm escalating because the volume, speed and the success that followed point to possible compromise. I recommend resetting the password, reviewing the session, and blocking the IP pending your approval."
