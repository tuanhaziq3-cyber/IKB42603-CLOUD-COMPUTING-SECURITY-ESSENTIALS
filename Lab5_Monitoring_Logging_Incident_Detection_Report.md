# IKB42603 Cloud Computing Security Essentials
## Lab 5 — Monitoring, Logging & Incident Detection

**Course:** IKB42603 Cloud Computing Security Essentials
**Institution:** UniKL MIIT
**Topic:** Centralised logging, tamper-proof logs, threat detection & incident response (Docker & LocalStack)
**CLO Mapping:** CLO2 — Construct secure cloud operations that safeguard data integrity

---

## 1. Setup

LocalStack was started and a CloudWatch Logs group/stream were created to act as the centralised log store:

```bash
EP='--endpoint-url=http://localhost:4566'
aws $EP logs create-log-group --log-group-name /ccse/app
aws $EP logs create-log-stream --log-group-name /ccse/app --log-stream-name auth
```

<img width="624" height="45" alt="image" src="https://github.com/user-attachments/assets/cdf60c27-a736-4959-9be9-8970f427db85" />


---

## 2. Task 1 — Generate Application Logs

A sample authentication log was created, simulating a brute-force attempt followed by a successful login and a large data export:

```
2025-03-01T09:00:01 LOGIN_OK user=ahmad ip=10.0.0.5
2025-03-01T09:01:10 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:12 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:15 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:18 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:22 LOGIN_OK user=admin ip=203.0.113.9
2025-03-01T09:01:40 EXPORT_DATA user=admin ip=203.0.113.9 size=500MB
```

<img width="624" height="285" alt="image" src="https://github.com/user-attachments/assets/6669ee17-73a7-42f3-ac49-858b23f72263" />


---

## 3. Task 2 — Centralise Logs (Ship to CloudWatch)

Each line of `auth.log` was shipped to the centralised CloudWatch (LocalStack) log stream using `put-log-events`, then read back with `get-log-events` to prove centralisation worked:

```bash
TS=$(date +%s000)
while IFS= read -r line; do
  aws $EP logs put-log-events --log-group-name /ccse/app --log-stream-name auth \
    --log-events timestamp=$TS,message="$line" >/dev/null; TS=$((TS+1000));
done < auth.log
```

<img width="624" height="86" alt="image" src="https://github.com/user-attachments/assets/a1e8afc8-18b3-4151-bb44-04b387c00c73" />


**Centralised read-back (Task 2 evidence):**

```bash
aws $EP logs get-log-events --log-group-name /ccse/app --log-stream-name auth \
  --query 'events[].message' --output text
```

<img width="624" height="75" alt="image" src="https://github.com/user-attachments/assets/3ec69bd7-f252-4b9e-83c8-6b397a639dd2" />


All 7 log lines were successfully retrieved from the central store, confirming the logs were centralised rather than left only on the local host.

---

## 4. Task 3 — Query for Security-Relevant Activity

Failed logins were queried and grouped by user/IP:

```bash
grep LOGIN_FAIL auth.log | awk '{print $4, $5}' | sort | uniq -c
```

**Result:** `4 user=admin ip=203.0.113.9` — 4 failed login attempts, all from the same user/IP, indicating a probable brute-force attempt.

---

## 5. Task 4 — Tamper-Proof (Hash-Chained) Logs

A SHA-256 hash chain was built over `auth.log`, where each line's hash incorporates the previous hash — any modification to any line changes every subsequent hash:

```bash
PREV=0
while IFS= read -r line; do
  PREV=$(printf '%s%s' "$PREV" "$line" | sha256sum | cut -d' ' -f1)
  printf '%s | %s\n' "$line" "$PREV"
done < auth.log > auth.chain
```

<img width="624" height="161" alt="image" src="https://github.com/user-attachments/assets/e4b9dab7-08e5-4cb6-bb8e-b3a2f938f41c" />


**Tamper test:** The `EXPORT_DATA` line was altered (`500MB` → `5MB`) to simulate an attacker covering their tracks, and the chain was recomputed from the tampered file:

```bash
sed 's/500MB/5MB/' auth.log > auth.tampered
# recompute chain from auth.tampered ...
echo "Original Final Hash: $(tail -n1 auth.chain | awk -F'|' '{print $2}')"
echo "Tampered Final Hash: $PREV_TAMPER"
```

<img width="624" height="122" alt="image" src="https://github.com/user-attachments/assets/dbba782b-9e12-401d-806d-b666f15c7999" />


**Result:**
- Original Final Hash: `a8ba787b4bf524d9dad8dcac48e4989fc105769a6f17574f4f2cefe8f81233cf`
- Tampered Final Hash: `72f1d5377a4a938fa7bd3a88f67894e5a64054a1e07511eec53d7bd89d859b`

The two final hashes **do not match**, proving the hash chain successfully detected the tampering of the `EXPORT_DATA` line even though only a single character range was changed.

---

## 6. Task 5 — Detect the Incident (Correlation)

Individual log lines (a few failed logins, one successful login, one export) look unremarkable on their own. Correlating them across the same IP address reveals the real incident:

```bash
IP=203.0.113.9
FAILS=$(grep -c "LOGIN_FAIL.*$IP" auth.log)
SUCCESS=$(grep -c "LOGIN_OK.*$IP" auth.log)
EXPORT=$(grep -c "EXPORT_DATA.*$IP" auth.log)
echo "IP=$IP fails=$FAILS success=$SUCCESS export=$EXPORT"
if [ "$FAILS" -ge 3 ] && [ "$SUCCESS" -ge 1 ] && [ "$EXPORT" -ge 1 ]; then
  echo 'ALERT: probable brute-force -> compromise -> data exfiltration';
fi
```

<img width="624" height="106" alt="image" src="https://github.com/user-attachments/assets/db490018-394f-41a8-bb72-d5e9bd2d0a12" />


**Output:**
```
IP=203.0.113.9 fails=4 success=1 export=1
ALERT: probable brute-force -> compromise -> data exfiltration
```

This confirms the correlation logic successfully detected a multi-stage incident (brute-force → compromise → exfiltration) that no single log entry would have revealed on its own.

---

## 7. Task 6 — Incident Response

### Containment

An attempt was made to model containment by blocking the attacker's IP inside an isolated Alpine container using `iptables`:

```bash
docker run --rm --cap-add=NET_ADMIN alpine sh -c \
  'apk add -q iptables; iptables -A INPUT -s 203.0.113.9 -j DROP; iptables -L INPUT -n | tail -2'
```

<img width="624" height="114" alt="image" src="https://github.com/user-attachments/assets/5dad6004-6e41-476d-a514-752a9ec4aaca" />


**Result:** The command failed — the container could not resolve the Alpine package mirror (`dl-cdn.alpinelinux.org`) due to a DNS/network issue in the lab environment, so `iptables` could not be installed and the `DROP` rule was never applied. This is documented honestly below as a limitation of the run rather than a successful containment.

### Evidence Collection

An immutable, timestamped evidence copy of the original log was created and hashed for integrity verification:

```bash
cp auth.log evidence_$(date +%Y%m%d).log
sha256sum evidence_*.log > evidence.sha256
cat evidence.sha256
```

<img width="624" height="142" alt="image" src="https://github.com/user-attachments/assets/e9ec92da-33a1-4573-afa0-e127d9b63fd9" />


**Result:**
```
0adc5d2ac06cbbdd366099bcc0540c4c0f76946e71b52e4c9932731696a203b  evidence_20260906.log
```

Verification was then attempted:
```bash
aws $EP logs describe-log-groups
sha256sum -c evidence.sha256
```
- `aws logs describe-log-groups` returned a connection error to the LocalStack endpoint (`https://logs.us-east-1.amazonaws.com/`) — the CLI fell back to a live AWS endpoint instead of the local one, indicating the `--endpoint-url` / `$EP` variable was not applied in that shell session.
- `sha256sum -c evidence.sha256` returned **OK**, confirming the evidence file's integrity was intact and unaltered.

---

## 8. Incident Report

**Detection:**
The incident was detected through log correlation rather than a single alert. Querying `auth.log` showed 4 `LOGIN_FAIL` attempts for user `admin` from IP `203.0.113.9` within 8 seconds, followed by a `LOGIN_OK` from the same IP, followed by an `EXPORT_DATA` event of 500MB. A correlation script flagged this pattern as `fails ≥ 3 AND success ≥ 1 AND export ≥ 1`, triggering the alert: *"probable brute-force -> compromise -> data exfiltration."*

**Analysis:**
The pattern is consistent with a brute-force credential attack: repeated rapid failed logins against the `admin` account, immediately followed by a successful login from the same source IP, and then a large data export. No single log line indicated compromise — the `LOGIN_OK` and `EXPORT_DATA` events look legitimate in isolation. Only correlating events by IP and sequence revealed the attack chain.

**Containment:**
Containment was modelled by attempting to add an `iptables DROP` rule for `203.0.113.9` inside an isolated Docker container. In this run, the containment step failed due to a DNS resolution error preventing `iptables` from being installed in the container, so the block was not actually applied. In a production environment, this step would be retried using a pre-built image with `iptables` already installed, or enforced at the network/security-group layer instead of relying on package installation at response time.

**Evidence & Integrity:**
A timestamped copy of the original log (`evidence_20260906.log`) was created and hashed with SHA-256 (`evidence.sha256`). Re-verifying with `sha256sum -c evidence.sha256` returned **OK**, confirming the evidence had not been altered after collection. Separately, Task 4 demonstrated that even a single-field change (`500MB` → `5MB`) in the source log breaks the hash chain's final hash, proving the hash-chaining mechanism reliably detects tampering.

**Lesson Learned:**
Prevention controls (login attempt limits, network blocks) can fail or be delayed by operational issues (as seen with the failed `iptables` install here), so detection and evidence integrity must not depend on a single control. Centralised, hash-chained logging combined with event correlation caught the incident even though the containment step did not fully execute — reinforcing that logging/monitoring is a necessary compensating control when preventive measures fail.

---

## 9. Short-Answer Questions

**Q1. What is the difference between a log and an event? Give an example of each from this lab.**

A **log** is a durable, stored record of something that happened, kept for later review, querying, or forensic analysis. An **event** is a real-time trigger or notification fired the moment something significant occurs, meant to prompt immediate action.

- *Log example:* The line `2025-03-01T09:01:40 EXPORT_DATA user=admin ip=203.0.113.9 size=500MB` stored in `auth.log` and shipped to CloudWatch — it just sits there as a record until someone queries it.
- *Event example:* The correlation script's output `ALERT: probable brute-force -> compromise -> data exfiltration`, fired the moment the fail/success/export thresholds were met — this is an actionable, near-real-time notification rather than a passive record.

**Q2. Why must audit logs be tamper-proof, and how does a hash chain achieve this?**

Audit logs must be tamper-proof because they are often the only evidence of what an attacker did, and an attacker who gains access will frequently try to edit or delete logs to cover their tracks. If logs can be silently altered, they can no longer be trusted for detection, forensics, or as compliance evidence.

A hash chain achieves this by making each entry's hash a function of both its own content and the previous entry's hash (`PREV = SHA256(PREV + line)`). This creates a linked sequence where changing any single line — even years later, even by a single character — changes that line's hash and therefore every hash computed after it. In this lab, changing `500MB` to `5MB` in one line caused the final chain hash to change completely (`a8ba787b...` vs `72f1d537...`), immediately revealing that the log had been altered, without needing to compare every line manually.

**Q3. How did correlation detect an incident that no single log line revealed?**

No individual line in `auth.log` looks malicious by itself: a `LOGIN_FAIL` could be a typo, a `LOGIN_OK` is normal, and an `EXPORT_DATA` could be routine business activity. The incident only becomes visible when these events are correlated by a shared attribute (the source IP `203.0.113.9`) and by sequence/time. The correlation script counted failures, successes, and exports **for that specific IP** and applied a rule (`fails ≥ 3 AND success ≥ 1 AND export ≥ 1`) that matches the known brute-force → compromise → exfiltration pattern. This is exactly what a SIEM does: it aggregates and cross-references many individually-benign-looking log entries to surface a threat pattern that would be invisible if each log source or line were viewed in isolation.

**Q4. List the incident-response steps you performed and the goal of each.**

1. **Detect** — Query and correlate logs (Task 3 & 5) to identify the brute-force → login-success → data-export pattern. *Goal: confirm an incident is actually occurring, not just isolated noise.*
2. **Contain** — Attempt to block the attacker's IP address using an `iptables DROP` rule (Task 6). *Goal: stop the attacker from causing further damage or continuing access.*
3. **Collect Evidence** — Make a timestamped copy of the log and hash it with SHA-256 (Task 6). *Goal: preserve an unaltered, verifiable record of what happened for forensics and any later investigation.*
4. **Document** — Write the incident report covering detection, analysis, containment, evidence, and lessons learned (this section). *Goal: create an accountable record of the incident and drive improvements to prevent recurrence.*

**Q5. How do the same logs serve both security monitoring and compliance evidence (Weeks 6, 11)?**

The same underlying log data serves two purposes simultaneously. For **security monitoring**, logs are queried and correlated in near-real-time (or shortly after) to detect malicious patterns, such as the brute-force/exfiltration chain identified in Task 5, enabling a timely response. For **compliance evidence**, the same logs — when centralised, hash-chained, and hashed at collection time (Task 4 & Task 6) — become durable, tamper-evident proof that can be presented to auditors to demonstrate that access to systems and data was monitored, that an incident was detected and responded to, and that the record of that response has not been altered since. In short: monitoring uses the logs to *act quickly*, while compliance uses the same logs (plus their integrity proofs) to *prove, after the fact*, that appropriate controls and oversight were in place.

---

## 10. Security Best-Practices Checklist

- [x] Logs are centralised, not left scattered on each host. *(Task 2 — shipped to CloudWatch/LocalStack and read back successfully)*
- [x] Security-relevant activity (failed logins) can be queried. *(Task 3 — 4 failed logins identified for `admin`/`203.0.113.9`)*
- [x] Logs are tamper-evident (hash chain) and forwarded to a separate store. *(Task 4 — tampering detected via final-hash mismatch)*
- [x] An incident is detected by correlating multiple events. *(Task 5 — brute-force/compromise/exfiltration alert triggered)*
- [~] Incident response performed: contain, collect evidence, document. *(Evidence collection and documentation completed; containment attempted but failed due to a container DNS/package-install issue — noted as a limitation above)*

---

## 11. Verification Commands

```bash
aws --endpoint-url=http://localhost:4566 logs describe-log-groups
sha256sum -c evidence.sha256
```

- `describe-log-groups`: returned a connection error against a live AWS endpoint, indicating the LocalStack endpoint flag was not correctly applied in that shell session.
- `sha256sum -c evidence.sha256`: **OK** — confirms the collected evidence file is intact.

---

*Report generated from Lab 5 (Weeks 9–10) — IKB42603 Cloud Computing Security Essentials, UniKL MIIT.*
