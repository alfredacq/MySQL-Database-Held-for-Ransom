# Scenario Creation: Building the MySQL Ransom Honeypot
**How the `ent-fl-123ds` environment was designed, deployed, and deliberately exposed to real internet attackers** — the incident report at the top level of this repo documents what an actual attacker did once they found it.

Unlike a scripted "bad actor" walkthrough, nothing in the [main incident report](../README.md) was staged. This VM and database were built clean, wired up to logging and detections *first*, and only then deliberately weakened and exposed — so every IP, timestamp, and query in the incident report is a real, unsolicited attacker interacting with a live decoy.

---

## 🏗️ Architecture

![Honeypot architecture: internet → NSG → Windows 11 VM (MySQL + weak accounts) → MySQL log file → Azure Monitor Agent → Log Analytics + Microsoft Defender for Endpoint](scenario-creation-images/01-honeypot-architecture.png)

- A Windows 11 VM sits behind a Network Security Group, with a MySQL 8.0 server running locally on port 3306.
- MySQL's general query log writes every connection and query to `mysql_general.log`.
- The Azure Monitor Agent ships that log file into a custom Log Analytics table (`MySQLAudit_CL`); the VM itself reports to Microsoft Defender for Endpoint (MDE) for process/file/registry/network telemetry.
- Outbound traffic is restricted by tenant egress policy, so the box is contained by design — a real breach could happen, but a breached box couldn't be used to pivot, mine, or call out to C2.

---

## 🔧 Build Process

### Phase 0 — Design
Planned around a *contained* breach: inbound attacker traffic is allowed to succeed, but outbound abuse (C2, mining, pivoting) is blocked and logged rather than allowed through. Detections were planned around **denied/attempted outbound**, not successful exfiltration.

### Phase 1 — Build the VM (locked down)
- Deployed a Windows 11 VM with a public IP, named to look like a legitimate corporate asset rather than an obvious lab box.
- Denied all inbound internet traffic while the environment was still being built.
- Onboarded the VM to Microsoft Defender for Endpoint and confirmed it appeared in the `DeviceInfo` table.

### Phase 2 — Install & populate MySQL
- Installed MySQL 8.0 Server with a strong root password (temporary — this gets deliberately weakened later).
- Created a database and imported a set of realistic dummy data (customer/order/payment/credential-style tables) so an attacker would find something worth "stealing."
- Enabled MySQL's general query log so every connection and query — successful or failed — is written to disk:
  ```sql
  SET GLOBAL general_log = 'ON';
  SET GLOBAL log_output = 'FILE';
  SHOW VARIABLES LIKE 'general_log%';
  ```
- Pointed the log output at a known file path and confirmed test queries were landing in the log.

### Phase 3 — Wire logging to Log Analytics
- Created a custom-text-log Data Collection Rule (DCR) pointing the Azure Monitor Agent at the MySQL log file, landing everything in a custom table: `MySQLAudit_CL`.

  ![DCR data source configuration — file pattern, table name, record delimiter, and timestamp format](scenario-creation-images/02-dcr-mysql-log-config.png)

  ![DCR destination set to the Log Analytics Workspace](scenario-creation-images/03-dcr-destination-law.png)

- Confirmed the Azure Monitor Agent extension installed successfully on the VM.

  ![AzureMonitorWindowsAgent extension showing as installed on the VM](scenario-creation-images/04-azure-monitor-agent-extension.png)

- Verified ingestion by running test connections/queries against MySQL and confirming they showed up in `MySQLAudit_CL`, filtered to this VM's resource ID.

  ![Query results confirming MySQLAudit_CL is receiving this VM's log data](scenario-creation-images/05-verify-mysqlaudit-ingestion.png)

### Phase 4 — Write detections (while the box was still clean)
Before any exposure, two Sentinel analytics rules were authored and confirmed *quiet* against the clean baseline — no real successes yet.

**Rule 1 — successful logon to the VM** (`DeviceLogonEvents`, `administrator`/`guest`, `LogonSuccess`):
![Entity mapping and analytics rule settings for the VM logon detection](scenario-creation-images/06-analytics-rule-vm-logon.png)

**Rule 2 — successful login to MySQL** (`MySQLAudit_CL`, parsed connect/auth-success events — the same parsing pattern used throughout the incident report):
![Entity mapping and analytics rule settings for the MySQL logon detection](scenario-creation-images/07-analytics-rule-mysql-logon.png)

### Phase 5 — Weaken & expose (deliberately, in sequence)
Only after both detections were armed:
1. Enabled the local `administrator` account with a deliberately weak password.
2. Enabled the `guest` account with a blank/weak password and allowed it to log on over the network via RDP.
3. Exposed MySQL to the network and created a wide-open `root@'%'` account with a trivially weak password.
4. Captured a baseline Defender investigation package (for later comparison against post-breach).
5. Disabled the Windows Firewall and widened the NSG to allow all inbound traffic.
6. **Recorded the exact exposure timestamp** — this becomes the start of the incident window in the report.

### Phase 6 — Detect the breach
With detections armed and the box exposed, monitored `DeviceLogonEvents` and `MySQLAudit_CL` for the analytics rules to fire, using the same rule queries as ad-hoc monitoring queries.

### Phase 7 — Analyze the breach
Once real attacker activity started appearing (in this case, within hours), the investigation shifted to log analysis — the exact process documented in the [incident report](../README.md): tracing authentication logs, query logs, and Defender telemetry to reconstruct what happened.

### Phase 8 — Contain the breach
Isolated the VM in the Defender portal and captured a second investigation package, for comparison against the Phase 5 baseline. **Recorded the exact isolation timestamp** — this closes the incident window.

### Phase 9 — Eradicate & recover
Since both the VM and the MySQL server were compromised, the environment was rebuilt clean rather than trusted going forward: hardened NSG rules, no `administrator` account, `guest` disabled, no public MySQL access, strong credentials, and the database restored from a known-good backup.

---

## 📋 Tables Used

| Table | Purpose |
|---|---|
| [`MySQLAudit_CL`](https://learn.microsoft.com/en-us/azure/azure-monitor/agents/data-collection-text-log) | Custom table receiving MySQL's general query log — every connection attempt and every query issued |
| [`DeviceLogonEvents`](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table) | Logon attempts/successes against the VM, especially the `administrator` and `guest` accounts |
| [`DeviceProcessEvents`](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) | Process execution on the VM post-breach |
| [`DeviceFileEvents`](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) | File activity on the VM post-breach |
| [`DeviceRegistryEvents`](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceregistryevents-table) | Persistence checks on the VM post-breach |
| [`DeviceNetworkEvents`](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table) | Inbound/outbound network activity to/from the VM |

---

## 🔍 Detection & Monitoring Queries

<details>
<summary>Show analytics rule + monitoring KQL</summary>

```kql
// Detection Rule 1 — successful VM logon (administrator/guest)
let MyDevice = "ent-fl-123ds";
DeviceLogonEvents
| where DeviceName == MyDevice
| where AccountName in~ ("administrator", "guest")
| where ActionType == "LogonSuccess"
| project TimeGenerated, RemoteIP, AccountName, DeviceName, ActionType, LogonType

// Detection Rule 2 — successful MySQL logon (parsed from MySQLAudit_CL)
let MyDevice = "ent-fl-123ds";
let FailedConnections =
    MySQLAudit_CL
    | extend RawData = replace_string(RawData, "\t", " ")
    | extend DeviceName = tostring(split(_ResourceId, "/")[-1])
    | where DeviceName == MyDevice
    | where RawData has "Access denied"
    | extend ConnectionId = extract(@"^\S+\s+(\d+)\s+Connect", 1, RawData)
    | distinct ConnectionId;
MySQLAudit_CL
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName == MyDevice
| where RawData has "Connect"
| extend ConnectionId = extract(@"^\S+\s+(\d+)\s+Connect", 1, RawData)
| extend ActionType = case(
    RawData has "Access denied", "LogonFailure",
    ConnectionId in (FailedConnections), "Ignore",
    "LogonSuccess")
| where ActionType == "LogonSuccess"
| extend Username  = replace_string(tostring(split(tostring(split(RawData,"@")[0]), " ")[-1]), "'", "")
| extend IpAddress = replace_string(tostring(split(split(RawData,"@")[1], " ")[0]), "'", "")
| project TimeGenerated, DeviceName, Username, IpAddress, ActionType, RawData
| order by TimeGenerated desc

// Outbound traffic denied by the tenant egress policy (contained-breach evidence)
let MyDevice = "ent-fl-123ds";
NTANetAnalytics
| where isnotempty(SrcVm)
| where SrcVm endswith MyDevice
| where DeniedOutFlows >= 1
| project TimeGenerated, DeviceName = MyDevice, FlowType, FlowStatus, SrcIp, SrcPorts, DestIp, DestPort
```

</details>

---

## Created By
- **Author:** _[Your Name]_
- **Contact:** _[Your LinkedIn/GitHub]_
- **Date:** August 2026

## Validated By
- **Reviewer:**
- **Contact:**
- **Validation Date:**

## Additional Notes
- This honeypot was built as part of a hands-on cloud/EDR security lab using Microsoft Azure, Microsoft Defender for Endpoint, and Microsoft Sentinel. Unlike a scripted CTF scenario, the attacker activity documented in the [main incident report](../README.md) was **not simulated** — it's real, unsolicited traffic from the public internet against a deliberately exposed decoy.
- Course reference material for VM/MDE onboarding and MySQL sample-data setup is intentionally omitted here since it links to private/instructor-owned resources.

## Revision History
| Version | Changes | Date | Modified By |
|---|---|---|---|
| 1.0 | Initial draft | August 2026 | _[Your Name]_ |
