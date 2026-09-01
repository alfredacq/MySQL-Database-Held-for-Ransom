[README.md](https://github.com/user-attachments/files/31388238/README.md)
# Incident Report: MySQL Database Held for Ransom

![Severity](https://img.shields.io/badge/Severity-High-red)
![Status](https://img.shields.io/badge/Status-Contained-brightgreen)
![Platform](https://img.shields.io/badge/EDR-Microsoft%20Defender%20for%20Endpoint-0078D4)
![Language](https://img.shields.io/badge/Query%20Language-KQL-blue)
![Type](https://img.shields.io/badge/Type-Database%20Extortion-orange)

**Analyst:** Alfred Acquah &nbsp;|&nbsp; **Host:** `ent-fl-123ds` &nbsp;|&nbsp; **Report ID:** IR-2026-0818-01 &nbsp;|&nbsp; **Date:** 2026-08-18

---

## 🛠️ Tools & Skills Used

- **Host:** Windows Server VM (`ent-fl-123ds`), MySQL 8.0
- **EDR Platform:** Microsoft Defender for Endpoint (Advanced Hunting)
- **Query Language:** Kusto Query Language (KQL)
- **Data Sources:** `MySQLAudit_CL` (custom log), `DeviceLogonEvents`, `DeviceNetworkEvents`, `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`

---

## 📋 The Scenario

The `ent-fl-123ds` virtual machine was a purpose-built honeypot, designed to closely resemble a legitimate corporate server. Before it was ever exposed to the internet, the environment was fully instrumented with logging and detection rules, so that any activity against it could be captured and analyzed in detail from the very first moment of contact. Once that groundwork was in place, the server was deliberately weakened and made reachable from the public internet. Everything described in this report from that point forward is real, unsolicited attacker activity against that environment — none of it was scripted or staged. You can see exactly how it was designed and built in the [Scenario Creation](https://github.com/alfredacq/Incident-Report-MySQL-Ransom-Data-Destruction/tree/main/scenarion_creation.md).

Shortly after exposure, all of the MySQL databases on the server were found to have been replaced with a single table containing a ransom note. This investigation set out to determine who discovered the environment, how they gained access, what actions they took, what data they interacted with, and whether the Windows host itself was also probed or compromised — then to walk through containment and recovery.

### High-Level Investigation Plan
- **Check `MySQLAudit_CL`** for the account/privilege change that opened the database to the internet, and for the destructive queries that followed.
- **Check `DeviceNetworkEvents`** for the external IP addresses that connected to the database.
- **Check `DeviceLogonEvents`** for signs the Windows host's admin account was also targeted.
- **Check `DeviceProcessEvents` / `DeviceFileEvents` / `DeviceRegistryEvents`** for evidence of malware, ransomware, or persistence beyond the database itself.

---

## 🕵️ Steps Taken

### 1. Confirmed the scope — was the Windows admin account also being targeted?

Searched Windows logon activity for the `administrator` and `guest` accounts on the affected host during the investigation window. This turned up 13 "successful" network logons mixed among a much larger set of failures — a sign the host was also being probed independently of the database attack.

**Query used to locate events:**

```kql
let START_TIME = todatetime("2026-08-13T20:19:32.3981809Z");
let END_TIME   = todatetime("2026-08-17T21:56:06.8759714Z");
DeviceLogonEvents
| where TimeGenerated between (START_TIME .. END_TIME)
| where DeviceName == "ent-fl-123ds"
| where ActionType in ("LogonSuccess")
| where AccountName in ("administrator","guest")
| project TimeGenerated, RemoteIP, AccountName, ActionType, LogonType
| order by TimeGenerated desc
```

<img width="2048" height="868" alt="01-admin-guest-logon-success" src="https://github.com/user-attachments/assets/223875ed-75ab-4bbb-a9ac-9a7b79373fcb" />

---

### 2. Checked what data the attacker actually looked at before deleting it

Before wiping the database, the attacker ran `SELECT *` against tables named `credentials`, `customers`, `orders`, and `payments` — meaning that data was read and returned to them over the network, even though we can't confirm from these logs whether they saved a copy.

**Query used to locate events:**

```kql
let START_TIME = todatetime("2026-08-13T20:19:32.3981809Z");
let END_TIME   = todatetime("2026-08-17T21:56:06.8759714Z");
MySQLAudit_CL
| where TimeGenerated between (START_TIME .. END_TIME)
| where RawData has "Query"
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName == "ent-fl-123ds"
| extend Query = split(RawData, "Query")[1]
| where Query has_any ("credentials", "customers", "payments", "orders")
| project TimeGenerated, Query
| order by TimeGenerated asc
```

<img width="2048" height="678" alt="02-sensitive-table-reads" src="https://github.com/user-attachments/assets/a3c2657d-ce77-4547-8d46-c70981b7c45a" />

---

### 3. Traced the known-bad IP addresses across the network logs

Pivoted on the list of IP addresses that had successfully logged in as `root`, to confirm exactly when each one connected to the server.

**Query used to locate events:**

```kql
let START_TIME = todatetime("2026-08-13T20:19:32.3981809Z");
let END_TIME   = todatetime("2026-08-17T21:56:06.8759714Z");
let IOC_IPs = dynamic(["194.32.120.197","64.89.163.164","64.89.163.90","64.89.163.93",
    "64.89.163.138","64.89.163.154","64.89.163.158","64.89.163.168","64.89.163.170",
    "213.209.159.115","34.62.5.44"]);
DeviceNetworkEvents
| where TimeGenerated between (START_TIME .. END_TIME)
| where DeviceName == "ent-fl-123ds"
| where RemoteIP in (IOC_IPs)
| project TimeGenerated, RemoteIP, ActionType, RemoteUrl
| order by TimeGenerated asc
```

<img width="1594" height="839" alt="03-ioc-network-connections" src="https://github.com/user-attachments/assets/a2702dae-198d-40f2-9aaf-2b873bc3689e" />

---

### 4. Reconstructed the destructive commands themselves

Searched for the exact moment the attacker created the wide-open `root` account, and every `DROP DATABASE` / ransom-table-creation command that followed.

**Query used to locate events:**

```kql
let START_TIME = todatetime("2026-08-13T20:19:32.3981809Z");
let END_TIME   = todatetime("2026-08-17T21:56:06.8759714Z");
MySQLAudit_CL
| where TimeGenerated between (START_TIME .. END_TIME)
| where RawData has "Query"
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName == "ent-fl-123ds"
| extend Query = split(RawData, "Query")[1]
| where Query has_any ("CREATE USER", "GRANT ALL PRIVILEGES", "DROP DATABASE", "RECOVER_YOUR_DATA")
| project TimeGenerated, Query
| order by TimeGenerated asc
```

<img width="2048" height="807" alt="04-destructive-queries-timeline" src="https://github.com/user-attachments/assets/e384bc6c-c2e6-4585-a972-bb1269e71aa7" />

---

### 5. Listed every IP address that ever successfully logged in as root

Built a canonical list of every successful `root` login across the whole window, to see how many separate outsiders found the exposed database.

**Query used to locate events:**

```kql
let START_TIME = todatetime("2026-08-13T20:19:32.3981809Z");
let END_TIME   = todatetime("2026-08-17T21:56:06.8759714Z");
MySQLAudit_CL
| where TimeGenerated between (START_TIME .. END_TIME)
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName == "ent-fl-123ds"
| where RawData has "Connect" and RawData !has "Access denied"
| extend IpAddress = replace_string(tostring(split(split(RawData,"@")[1], " ")[0]), "'", "")
| project TimeGenerated, IpAddress
| order by TimeGenerated asc
```

<img width="1879" height="842" alt="05-successful-mysql-root-logons" src="https://github.com/user-attachments/assets/3612e228-e9bb-4038-8128-cc592cd04951" />

---

### 6. Checked whether the Windows admin brute-force attempts actually succeeded

Summarized failed vs. successful logon attempts per source IP for the `administrator`/`guest` accounts, to separate background internet noise from anything that got a real foothold.

**Query used to locate events:**

```kql
let START_TIME = todatetime("2026-08-13T20:19:32.3981809Z");
let END_TIME   = todatetime("2026-08-17T21:56:06.8759714Z");
DeviceLogonEvents
| where TimeGenerated between (START_TIME .. END_TIME)
| where DeviceName == "ent-fl-123ds"
| where AccountName in~ ("administrator", "guest")
| summarize Attempts = count(), Successes = countif(ActionType == "LogonSuccess") by RemoteIP
| order by Successes desc, Attempts desc
```

<img width="2020" height="959" alt="06-admin-logon-summary-by-ip" src="https://github.com/user-attachments/assets/a14d41d0-4bc4-43b4-920b-1f40513dfb3b" />

---

### 7. Mapped where all the brute-force traffic was coming from

Plotted every source IP that racked up 5+ failed logons and then landed at least one success, worldwide — so the highest-priority sources stand out visually instead of getting lost in routine internet scanning noise.

<img width="2048" height="801" alt="07-geo-map-bruteforce-sources" src="https://github.com/user-attachments/assets/0061b7c5-40ea-4c04-9190-4a00adf025c3" />

---

## 🗓️ Timeline of Events

| Time (UTC) | Event |
|---|---|
| **2026-08-13 15:36:57** | A `root` account with a password and full privileges is created and opened up to connect from **any host on the internet**. |
| **2026-08-13 20:21:18** | A recurring, likely-legitimate client (`77.90.185.30`) connects — establishes this IP was already talking to the server before the attack. |
| **2026-08-13 20:32:27** | First hostile connection, from `194.32.120.197`, logs in as `root`. |
| **2026-08-13 20:32:28 – 20:33:49** | Attacker reads the `credentials`, `customers`, `orders`, and `payments` tables, then deletes (`DROP`) every database and replaces them with a ransom note. |
| **2026-08-14 01:29:36 – 01:30:12** | A second wave from `64.89.163.164` repeats the same routine and leaves the final ransom note (Bitcoin address, contact email, reference ID). |
| **2026-08-14 – 2026-08-16** | 8 more distinct IP addresses independently repeat the same "drop and ransom" script — consistent with automated scanning bots, not one persistent attacker. |
| **2026-08-13 – 2026-08-17 (ongoing)** | 135 failed and 3 apparently successful logon attempts against the local `administrator` account, from 49 different IP addresses. |
| **2026-08-17 ~16:41 – 16:42** | An analyst account (`root@localhost`) queries the ransom table — the approximate point of discovery. |

---

## 🧾 Indicators of Compromise

| Type | Value |
|---|---|
| BTC address | `bc1q7jps5432akuflg9flw2vu6hgmmj5hrrdu6c5gm` |
| Contact email | `ak+2bhdu@onionmail.org` |
| Reference URL | `hxxps://bit[.]ly/22mysql` |
| Reference ID | `2BHDU` |
| Ransom artifact | Database `RECOVER_YOUR_DATA`, table `RECOVER_YOUR_DATA_info` |
| Malicious source IPs | `194.32.120.197`, `64.89.163.164`, `64.89.163.90/93/138/154/158/168/170`, `213.209.159.115`, `34.62.5.44` |
| Target accounts | `root@'%'` (MySQL), `administrator` (Windows, local) |

---

## 🧩 Root Cause

The database was directly reachable from the internet, and a `root` account with **no host restriction** was created about five hours before the first hostile connection. That is the root cause — a **misconfiguration**, not a software vulnerability or clever exploit. The attacker used an ordinary MySQL client with valid-looking credentials; no malware or code-execution exploit was involved.

---

## 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Initial Access | [T1133 – External Remote Services](https://attack.mitre.org/techniques/T1133/) | MySQL (3306) and RDP/SMB were both reachable from the internet once the firewall/NSG was opened |
| Initial Access / Credential Access | [T1078 – Valid Accounts](https://attack.mitre.org/techniques/T1078/) | Every successful MySQL connection used a working `root` password rather than exploiting a vulnerability |
| Credential Access | [T1110.001 – Password Guessing](https://attack.mitre.org/techniques/T1110/001/) | 135 failed logons against `administrator`/`guest` from 49 distinct IPs, 3 apparent successes |
| Persistence / Privilege Escalation | [T1098 – Account Manipulation](https://attack.mitre.org/techniques/T1098/) | Second attacker wave issued its own `GRANT CREATE, DROP ON *.* TO root@'%'` |
| Discovery | [T1087 – Account Discovery](https://attack.mitre.org/techniques/T1087/) | `SHOW TABLES` / `SHOW DATABASES` enumeration before any destructive action |
| Collection | [T1213 – Data from Information Repositories](https://attack.mitre.org/techniques/T1213/) | `SELECT *` against `credentials`, `customers`, `orders`, `payments` |
| Impact | [T1485 – Data Destruction](https://attack.mitre.org/techniques/T1485/) | Every table in `ent_corp`, `sakila`, and `world` was dropped |
| Impact | [T1657 – Financial Theft](https://attack.mitre.org/techniques/T1657/) | BTC ransom demand and reference ID left in the `RECOVER_YOUR_DATA` table |

**Notably absent:** [T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/) does not apply — nothing was encrypted, only destroyed. No Execution, Lateral Movement, or Command and Control techniques were observed either; this was a single-stage, credential-driven attack rather than a multi-stage intrusion.

---

## 🛡️ Response & Fix

**Contained:**
- Isolated the virtual machine.
- Removed the wide-open `root` account; restricted `root` to local connections only.
- Blocked internet access to the database port (3306) at the firewall.
- Rotated all database credentials.

**Cleaned up:**
- Removed the ransom-note artifacts left behind by the attacker.
- Confirmed no other unauthorized accounts or scheduled tasks were created.
- Reset the local `administrator` password and tightened lockout rules.

**Recovered:**
- Restored the production database from the last known-good backup taken before the account was exposed.
- Did **not** pay the ransom — there was no proof the attacker could or would restore the data, and the note matched a known mass-exploitation template rather than a targeted actor.

---

## ✅ Recommendations Going Forward

1. **(Critical)** Never expose a database port directly to the internet — require a VPN or private network, and never allow `root`-style accounts to log in from "anywhere."
2. **(Critical)** Alert automatically on any `CREATE USER` / `GRANT ALL PRIVILEGES` / `DROP DATABASE` command against production databases.
3. **(High)** Test backup and restore procedures regularly so recovery from an incident like this is fast and verified.
4. **(High)** Tighten the local Windows admin account — lockout policy, MFA for admin access, and disabling the built-in admin account where possible.
5. **(Medium)** Confirm whether the recurring `77.90.185.x` clients are legitimate; rotate their credentials either way.
6. **(Medium)** Extend log retention so future investigations aren't missing the moments right before an incident starts.

---

## 📝 Summary

The Windows 11 computer (ent-fl-123ds) was purposely built to get attacked. It was set up to look like an ordinary corporate server, wired with full endpoint and database logging plus armed detection rules, then deliberately weakened — a wide-open `root` account, a weak Windows admin password, an open firewall — and put on the public internet. From that point on, everything documented in this report is genuine, unsolicited attacker behavior.

The decoy didn't stay quiet for long. Within about five hours of exposure, an opportunistic scanner found the open database, read through several tables — including one named `credentials` — and wiped every database, replacing them with a ransom note. Over the next four days, at least 11 more independent IP addresses found the same opening and left copies of the same note, consistent with automated internet-wide extortion bots rather than one persistent human attacker. In parallel, dozens of unrelated IPs hammered the Windows host's local admin account, which is normal background noise for anything left open on the internet.

Nothing here involved a clever exploit, custom malware, or a skilled adversary — the entire chain traces back to one misconfiguration (a `root` account reachable from any host) discovered by automated scanning within hours. That's arguably the most useful finding of the exercise: it didn't take a sophisticated attacker to cause real damage; it took an open door.

This project exercised the full incident-response lifecycle end to end — designing and building a monitored decoy, arming detections *before* exposure, investigating a live, unscripted breach across MySQL audit logs and Microsoft Defender for Endpoint telemetry, correlating IOCs across data sources, and documenting containment, eradication, and recovery steps a real SOC would take. See [Scenario Creation](https://github.com/alfredacq/Incident-Report-MySQL-Ransom-Data-Destruction/tree/main/scenarion_creation.md) for the full build process behind it.
