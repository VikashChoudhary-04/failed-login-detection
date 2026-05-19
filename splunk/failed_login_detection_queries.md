# Splunk Failed Login Detection Queries

- This file contains Splunk SPL queries used during the failed login detection project.

---

## 1. Basic Failed Login Detection

```spl
index=main "4625"
| stats count by Account
| where count > 5
| sort - count
````

### Purpose

- Detect accounts experiencing excessive failed login attempts.

### Detection Goal

- Identify:

  * Brute force attempts
  * Password spraying
  * Authentication abuse

---

## 2. Failed Login Trend Analysis

```spl
index=main "4625"
| timechart count
```

### Purpose

- Visualize failed login activity over time.

### Detection Goal

- Identify:

  * Login spikes
  * Authentication anomalies
  * Suspicious authentication trends

---

## 3. Successful Login Monitoring

```spl
index=main "4624"
| stats count by host
| sort - count
```

### Purpose

- Review successful authentication activity by host.

### Detection Goal

- Identify:

  * Active systems
  * Authentication distribution
  * Login behavior patterns

---

## 4. Privileged Logon Monitoring

```spl
index=main "4672"
| stats count by host
| sort - count
```

### Purpose

- Monitor privileged authentication events.

### Detection Goal

- Identify:

  * Administrative activity
  * Elevated privilege usage
  * Potential privilege abuse

---

## 5. Process Creation Monitoring

```spl
index=main "4688"
| stats count by host
| sort - count
```

### Purpose

- Review process creation events.

### Detection Goal

- Identify:

  * Suspicious process activity
  * Script execution
  * Potential malicious tooling

---

## 6. Suspicious PowerShell Hunting

```spl
index=main ("powershell" OR "cmd.exe" OR "rundll32" OR "mshta")
```

### Purpose

- Hunt for potentially suspicious command execution.

### Detection Goal

- Identify:

  * LOLBin usage
  * PowerShell abuse
  * Suspicious scripting activity

---

## 7. Authentication Timeline Review

```spl
index=main "4624"
| table _time host
| sort - _time
```

### Purpose

- Review authentication activity chronologically.

### Detection Goal

- Identify:

  * Login sequences
  * Authentication timing
  * Potential anomalies

---

## Key Event IDs

| Event ID | Description      |
| -------- | ---------------- |
| 4625     | Failed Login     |
| 4624     | Successful Login |
| 4672     | Privileged Logon |
| 4688     | Process Creation |

---

## MITRE ATT&CK Mapping

| Detection         | ATT&CK Technique                      |
| ----------------- | ------------------------------------- |
| Failed Logins     | T1110 - Brute Force                   |
| PowerShell Abuse  | T1059.001 - PowerShell                |
| Rundll32 Activity | T1218 - Signed Binary Proxy Execution |
| Privileged Logons | T1078 - Valid Accounts                |

---

## Notes

- These SPL queries were created as part of a beginner SOC detection engineering learning project focused on:

  * Detection logic
  * Threat hunting
  * Splunk fundamentals
  * ATT&CK mapping
