# Failed Login Detection Project (Splunk SOC Detection Engineering)

## Project Overview

- This project demonstrates a beginner SOC detection engineering workflow focused on identifying excessive failed login attempts using:

  * Splunk SPL
  * Windows Security Logs
  * Sigma rules
  * MITRE ATT&CK mapping
  * Basic SOC investigation methodology

- The project simulates how a SOC analyst or junior detection engineer would:

  1. Ingest authentication logs
  2. Detect suspicious failed login behavior
  3. Build SIEM searches
  4. Create detection logic
  5. Investigate suspicious activity
  6. Document findings professionally

---

## Project Goals

### Primary Objective

- Detect repeated failed authentication attempts that may indicate:

  * Brute force attacks
  * Password spraying
  * Credential stuffing
  * Account targeting
  * Authentication abuse

---

## Skills Demonstrated

* Splunk log analysis
* SPL querying
* Detection engineering fundamentals
* Authentication monitoring
* Sigma rule creation
* MITRE ATT&CK mapping
* SOC investigation workflow
* Security documentation

---

## Technologies Used

| Technology         | Purpose                  |
| ------------------ | ------------------------ |
| Splunk Free        | SIEM platform            |
| Windows Event Logs | Authentication telemetry |
| SPL                | Detection queries        |
| Sigma              | Portable detection rules |
| MITRE ATT&CK       | Threat mapping           |

---

## MITRE ATT&CK Mapping

| Technique   | ID    | Tactic            |
| ----------- | ----- | ----------------- |
| Brute Force | T1110 | Credential Access |

---

## Detection Logic
### Primary Detection Goal

- Identify accounts experiencing excessive failed login attempts.

---

## Windows Event IDs Used

| Event ID | Description      |
| -------- | ---------------- |
| 4625     | Failed Login     |
| 4624     | Successful Login |
| 4672     | Privileged Logon |

---

## Splunk Detection Query

```spl
index=main "4625"
| stats count by Account
| where count > 5
| sort - count
```

---

## Detection Logic Explanation

- This query:

  1. Searches failed login events (4625)
  2. Counts failed attempts per account
  3. Filters accounts with more than 5 failures
  4. Sorts highest counts first

---

## Example Investigation Workflow

### Step 1 — Review Failed Accounts

- Identify:

  * Which accounts are targeted
  * Frequency of attempts
  * Whether accounts are privileged

---

### Step 2 — Investigate Source Systems

- Review:

  * Source hosts
  * IP addresses
  * Geographic indicators
  * Login patterns

---

### Step 3 — Check for Successful Authentication

- Determine whether:

  * Failed attempts later succeeded
  * MFA was bypassed
  * Compromise may have occurred

---

### Step 4 — Determine Severity

- Questions:

  * Is this brute force?
  * Is it a user mistake?
  * Is this password spraying?
  * Is the account sensitive?

---

## Sigma Rule

```yaml
title: Excessive Failed Login Attempts
id: 11111111-1111-1111-1111-111111111111
status: experimental
description: Detects repeated failed authentication attempts
references:
  - https://attack.mitre.org/techniques/T1110/
author: Vikash Choudhary
date: 2026/05/19
logsource:
  product: windows
  service: security

detection:
  selection:
    EventID: 4625

  condition: selection

level: medium
```

---

## False Positives

- Potential benign causes:

  * User forgot password
  * Expired credentials
  * Misconfigured services
  * VPN login issues
  * Incorrect saved passwords

---

## Detection Improvements (Future Work)

- Potential future enhancements:

  * Add source IP tracking
  * Add time-window correlation
  * Detect password spraying patterns
  * Add MFA failure correlation
  * Detect successful login after failures
  * Add alert thresholds
  * Integrate threat intelligence

---

## Example Enhanced SPL Query

```spl
index=main "4625"
| stats count by Account, src_ip
| where count > 10
| sort - count
```

---

## SOC Severity Assessment

| Severity | Criteria                                |
| -------- | --------------------------------------- |
| Low      | Small number of failures                |
| Medium   | Multiple repeated failures              |
| High     | Privileged account targeted             |
| Critical | Successful compromise after brute force |

---

## Recommended SOC Response

- Possible response actions:

  * Investigate account activity
  * Review source IPs
  * Force password reset
  * Validate MFA
  * Lock compromised account
  * Escalate to incident response

---

## Sample Detection Scenario

### Scenario

- A user account receives:

  * 15 failed logins
  * From same source IP
  * Within short timeframe

---

### SOC Interpretation

- Potential:

  * Brute force attempt
  * Password spraying activity
  * Credential attack

---

### Recommended Actions

* Investigate source IP
* Review user activity
* Check for successful login events
* Validate MFA activity

---

## Repository Structure

```text
failed-login-detection/
│
├── README.md
├── sigma/
│   └── failed_login_detection.yml
│
├── splunk/
│   └── failed_login_detection_queries.md
│
├── screenshots/
│   ├── splunk_dashboard.png
│   ├── failed_login_query.png
│   └── detection_results.png
│
├── reports/
│   └── mini_investigation_report.md
│
└── mitre/
    └── attack_mapping.md
```

---

## Key Lessons Learned

  * Failed login monitoring is foundational SOC work
  * Authentication telemetry is critical in modern environments
  * Detection engineering requires understanding attacker behavior
  * ATT&CK mapping improves detection context
  * False positives must always be considered
  * SIEM queries should be actionable and explainable
