# Scenario Creation: Building the MySQL Ransom Honeypot
**How the `ent-fl-123ds` environment was designed, deployed, and deliberately exposed to real internet attackers** — the incident report at the top level of this repo documents what an actual attacker did once they found it.

Unlike a scripted "bad actor" walkthrough, nothing in the [main incident report](https://github.com/alfredacq/Incident-Report-MySQL-Ransom-Data-Destruction/tree/main) was staged. This VM and database were built clean, wired up to logging and detections *first*, and only then deliberately weakened and exposed — so every IP, timestamp, and query in the incident report is a real, unsolicited attacker interacting with a live decoy.

---

## 🏗️ Architecture

<img width="1536" height="1024" alt="01-honeypot-architecture" src="https://github.com/user-attachments/assets/bdc4f71a-26dc-4ef2-89ce-bcf321e71568" />


- A Windows 11 VM sits behind a Network Security Group, with a MySQL 8.0 server running locally on port 3306.
- MySQL's general query log writes every connection and query to `mysql_general.log`.
- The Azure Monitor Agent ships that log file into a custom Log Analytics table (`MySQLAudit_CL`); the VM itself reports to Microsoft Defender for Endpoint (MDE) for process/file/registry/network telemetry.
- Outbound traffic is restricted by tenant egress policy, so the box is contained by design — a real breach could happen, but a breached box couldn't be used to pivot, mine, or call out to C2.

---

## 🔧 Build Process

### Phase 1 — Build the VM (locked down)
- Deployed a Windows 11 VM with a public IP, named to look like a legitimate corporate asset rather than an obvious lab box.
- Denied all inbound internet traffic while the environment was still being built.
- Onboarded the VM to Microsoft Defender for Endpoint and confirmed it appeared in the `DeviceInfo` table.
<img width="2894" height="1742" alt="Screenshot 2026-08-11 161936" src="https://github.com/user-attachments/assets/e286cc7a-25c9-4566-9e25-473168e12f6e" />


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
- Confirmed the Azure Monitor Agent extension installed successfully on the VM.
- Verified ingestion by running test connections/queries against MySQL and confirming they showed up in `MySQLAudit_CL`, filtered to this VM's resource ID.
<img width="2452" height="1714" alt="Logs-coming-In" src="https://github.com/user-attachments/assets/199e9f74-2c93-4bbd-8479-c5425b72e513" />


### Phase 4 — Write detections (while the box was still clean)
Before any exposure, two Sentinel analytics rules were authored and confirmed *quiet* against the clean baseline — no real successes yet.

**Rule 1 — successful logon to the VM** (`DeviceLogonEvents`, `administrator`/`guest`, `LogonSuccess`):
```kql
// Virtual Machine Logons
let MyDevice = "ent-fl-123ds"; // MDE Truncates/cuts off the device name
DeviceLogonEvents
| where DeviceName == MyDevice
| where AccountName in~ ("administrator", "guest")
| where ActionType == "LogonSuccess"
| project TimeGenerated, RemoteIP, AccountName, DeviceName, ActionType, LogonType
```

**Rule 2 — successful login to MySQL** (`MySQLAudit_CL`, parsed connect/auth-success events — the same parsing pattern used throughout the incident report):
```kql
Rule query:
// SQL Server
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
| where TimeGenerated > MyTimeframe
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName == MyDevice
| where RawData has "Connect"
| extend ConnectionId = extract(@"^\S+\s+(\d+)\s+Connect", 1, RawData)
| extend ActionType =
    case(
        RawData has "Access denied", "LogonFailure",
        ConnectionId in (FailedConnections), "Ignore",
        "LogonSuccess"
    )
| where ActionType != "Ignore"
| extend RawData = replace_string(RawData, "\t", " ")
| extend Username = replace_string(tostring(split(tostring(split(RawData,"@")[0]), " ")[-1]), "'", "")
| extend IpAddress = replace_string(tostring(split(split(RawData,"@")[1], " ")[0]), "'", "")
| where ActionType == "LogonSuccess"
| project TimeGenerated, DeviceName, Username, IpAddress, ActionType, RawData
| order by TimeGenerated desc
```


### Phase 5 — Weaken & expose (deliberately, in sequence)
Only after both detections were armed:
1. Enabled the local `administrator` account with a deliberately weak password.
<img width="2679" height="1715" alt="weakVM-1" src="https://github.com/user-attachments/assets/c901c9ad-c7b7-4fb0-b584-0dddb5a882b6" />

2. Enabled the `guest` account with a blank/weak password and allowed it to log on over the network via RDP.
3. Exposed MySQL to the network and created a wide-open `root@'%'` account with a trivially weak password.
   <img width="2763" height="1718" alt="weakVM-2 5" src="https://github.com/user-attachments/assets/4d8c2d48-b45f-4818-8d52-ce7577e7b035" />

4. Captured a baseline Defender investigation package (for later comparison against post-breach).
5. Disabled the Windows Firewall and widened the NSG to allow all inbound traffic.
6. **Recorded the exact exposure timestamp** — this becomes the start of the incident window in the report.


### Phase 6 — Detect the breach
With detections armed and the box exposed, monitored `DeviceLogonEvents` and `MySQLAudit_CL` for the analytics rules to fire, using the same rule queries as ad-hoc monitoring queries.
<img width="2710" height="1760" alt="detect-1" src="https://github.com/user-attachments/assets/647b8003-df29-46a8-b10b-fecc6074b3fd" />


### Phase 7 — Analyze the breach
Once real attacker activity started appearing (in this case, within hours), the investigation shifted to log analysis — the exact process documented in the [main incident report](https://github.com/alfredacq/Incident-Report-MySQL-Ransom-Data-Destruction/tree/main): tracing authentication logs, query logs, and Defender telemetry to reconstruct what happened.


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
- **Author:** Alfred Acquah
- **Contact:** https://github.com/alfredacq
- **Date:** August 2026


## Additional Notes
- This honeypot was built as part of a hands-on cloud/EDR security lab using Microsoft Azure, Microsoft Defender for Endpoint, and Microsoft Sentinel. Unlike a scripted CTF scenario, the attacker activity documented in the [main incident report](https://github.com/alfredacq/Incident-Report-MySQL-Ransom-Data-Destruction/tree/main) was **not simulated** — it's real, unsolicited traffic from the public internet against a deliberately exposed decoy.
- Course reference material for VM/MDE onboarding and MySQL sample-data setup is intentionally omitted here since it links to private/instructor-owned resources.

