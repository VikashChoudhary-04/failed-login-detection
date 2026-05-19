# MITRE ATT&CK Mapping

- This file documents the ATT&CK techniques related to detections and investigations performed in this project.

---

## ATT&CK Overview

- MITRE ATT&CK is a knowledge base of:
  - Adversary behaviors
  - Attack techniques
  - Threat tactics
  - Real-world attack patterns

- It helps SOC analysts:
  - Categorize detections
  - Understand attacker behavior
  - Improve visibility coverage
  - Standardize investigations

---

## Detection Mapping

| Detection Activity | ATT&CK Technique | Technique ID | Tactic |
|---|---|---|---|
| Failed Login Monitoring | Brute Force | T1110 | Credential Access |
| PowerShell Monitoring | PowerShell | T1059.001 | Execution |
| Rundll32 Monitoring | Signed Binary Proxy Execution | T1218 | Defense Evasion |
| Privileged Logon Monitoring | Valid Accounts | T1078 | Defense Evasion |
| Process Creation Monitoring | Command and Scripting Interpreter | T1059 | Execution |

---

## Technique Details

---

### T1110 — Brute Force

#### Description

- Attackers attempt repeated authentication attempts to gain unauthorized access.

#### Detection Relevance

- Failed login monitoring helps identify:
  - Password spraying
  - Credential stuffing
  - Brute force attacks

#### Relevant Telemetry

- Windows Event ID 4625
- Authentication logs
- Sign-in telemetry

---

### T1059.001 — PowerShell

#### Description

- Attackers abuse PowerShell for:
  - Payload execution
  - Persistence
  - Download cradles
  - Obfuscation

#### Detection Relevance

- Suspicious PowerShell activity may indicate:
  - Malware execution
  - Post-exploitation activity
  - Lateral movement

#### Relevant Telemetry

- Process creation logs
- PowerShell command lines
- Script execution logs

---

### T1218 — Signed Binary Proxy Execution

#### Description

- Attackers abuse legitimate Windows binaries (LOLBins) to execute malicious code.

#### Common LOLBins

- rundll32.exe
- mshta.exe
- regsvr32.exe
- certutil.exe

#### Detection Relevance

- LOLBin monitoring helps identify:
  - Defense evasion
  - Proxy execution
  - Suspicious command execution

---

### T1078 — Valid Accounts

#### Description

- Attackers use legitimate credentials to maintain access and evade detection.

#### Detection Relevance

- Privileged logon monitoring may reveal:
  - Compromised admin accounts
  - Unauthorized privileged access
  - Suspicious authentication behavior

#### Relevant Telemetry

- Event ID 4672
- Authentication logs
- Privileged account activity

---

### T1059 — Command and Scripting Interpreter

#### Description

- Attackers use scripting interpreters to execute commands and automate malicious activity.

#### Detection Relevance

- Monitoring scripting engines helps identify:
  - Malware execution
  - Automation abuse
  - Script-based attacks

#### Relevant Processes

- powershell.exe
- cmd.exe
- wscript.exe
- cscript.exe

---

## SOC Analyst Value

- ATT&CK mapping helps analysts:
  - Understand attack behavior
  - Improve detection quality
  - Build better investigations
  - Communicate findings consistently

---

## Key Lessons Learned

- Detection logic should align to attacker behavior
- ATT&CK improves detection standardization
- Authentication telemetry is critical for credential attack detection
- Process creation monitoring improves visibility
- Detection engineering requires both technical and contextual understanding

---

## Project Context

- This ATT&CK mapping was created as part of a beginner SOC detection engineering project using:
  - Splunk
  - Windows Event Logs
  - Sigma detections
  - Authentication monitoring
