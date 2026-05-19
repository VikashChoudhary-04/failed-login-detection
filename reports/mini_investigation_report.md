# Mini Investigation Report

## Investigation Title

- Baseline Windows Host Authentication Investigation

---

## Objective

- Investigate Windows authentication telemetry to identify suspicious failed login activity and review potential indicators of brute force behavior.

---

## Environment

| Component | Details |
|---|---|
| SIEM | Splunk Free |
| Log Source | Windows Security Logs |
| Dataset Type | Authentication + Process Events |
| Host | Vikash |
| Investigation Type | Baseline SOC Monitoring |

---

## Event IDs Reviewed

| Event ID | Description |
|---|---|
| 4625 | Failed Login |
| 4624 | Successful Login |
| 4672 | Privileged Logon |
| 4688 | Process Creation |

---

## Investigation Steps

### 1. Failed Login Review

#### SPL Query

```spl
index=main "4625"
| stats count by Account
| where count > 5
| sort - count
````

#### Purpose

- Identify accounts experiencing excessive failed authentication attempts.

#### Findings

- No excessive failed login activity was identified in the current dataset.

---

### 2. Successful Login Review

#### SPL Query

```spl
index=main "4624"
| stats count by host
| sort - count
```

#### Findings

- Successful authentication activity was observed from the Windows host:

  * Vikash

- Authentication activity appeared consistent with normal baseline behavior.

---

### 3. Authentication Timeline Analysis

#### SPL Query

```spl
index=main "4624"
| table _time host
| sort - _time
```

#### Findings

- Authentication events occurred within expected system activity periods.

- No abnormal authentication spikes or suspicious timing patterns were identified.

---

### 4. Privileged Logon Review

#### SPL Query

```spl
index=main "4672"
| stats count by host
| sort - count
```

#### Findings

- Privileged logon activity was present and consistent with expected Windows system behavior.

- No evidence of suspicious privileged escalation was identified.

---

### 5. Process Creation Analysis

#### SPL Query

```spl
index=main "4688"
| stats count by host
| sort - count
```

#### Findings

- Process creation events included legitimate Windows system processes such as:

  * smss.exe
  * wininit.exe
  * lsass.exe
  * services.exe
  * csrss.exe

- No suspicious PowerShell or LOLBin activity was identified.

---

### 6. Suspicious Process Hunting

#### SPL Query

```spl
index=main ("powershell" OR "cmd.exe" OR "rundll32" OR "mshta")
```

#### Findings

- No suspicious command execution or LOLBin abuse was identified within the dataset.

---

## MITRE ATT&CK Mapping

| Activity                | ATT&CK Technique                      |
| ----------------------- | ------------------------------------- |
| Failed Login Monitoring | T1110 - Brute Force                   |
| PowerShell Monitoring   | T1059.001 - PowerShell                |
| Rundll32 Monitoring     | T1218 - Signed Binary Proxy Execution |
| Privileged Activity     | T1078 - Valid Accounts                |

---

## Overall Assessment

- The reviewed dataset primarily reflected normal Windows operating system initialization and authentication activity.

- No confirmed malicious behavior, brute force attempts, suspicious PowerShell execution, or LOLBin abuse was identified during the investigation.

---

## Key Lessons Learned

* Authentication telemetry is foundational for SOC monitoring
* Failed login analysis helps detect brute force behavior
* Process creation logs provide valuable visibility
* Detection engineering requires understanding normal baseline activity
* ATT&CK mapping improves investigation context
* False positives must always be considered during analysis

---

## Analyst Notes

- This investigation was conducted as part of a beginner SOC detection engineering and Splunk monitoring learning project focused on authentication monitoring and foundational SIEM workflows.
