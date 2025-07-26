# MITRE ATT&CK TTP Mapping – Week 1

**Intern Name:** Sumit Dhavale  
**Intern ID:** 143  
**Internship Task:** Threat Intelligence Collection & Analysis  
**Tools Used:** ThreatView.io, MISP, YARA Rules

---

## 🔍 What is MITRE ATT&CK?

[MITRE ATT&CK](https://attack.mitre.org/) is a globally recognized knowledge base of adversary behaviors that maps real-world attacks into:

- **Tactics** – Why an attacker performs an action (e.g., Persistence)
- **Techniques** – How the action is performed (e.g., Registry Run Key)
- **Procedures** – Specific implementation seen in the wild

---

## 🧠 Purpose of TTP Mapping in This Task

In this task, I analyzed IOCs and threat indicators using:
- ✅ **ThreatView.io**: IOC feed lookup for IPs, domains, and hashes
- ✅ **MISP**: IOC sharing platform with structured exports
- ✅ **YARA**: Detection rules for malware and strings in memory/files

These tools help trace observable behaviors to real-world **MITRE techniques**.  
This mapping supports better understanding, detection, and reporting.

---

## 🧩 Mapped TTPs

| Tactic              | Technique                            | Technique ID | Observed In         | Description                                                             |
|---------------------|---------------------------------------|--------------|----------------------|-------------------------------------------------------------------------|
| Reconnaissance       | Gather Victim Identity Information   | T1589        | ThreatView / IOC     | Lookup of external email/domain IOCs                                    |
| Resource Development | Acquire Infrastructure               | T1583        | ThreatView           | Detection of attacker-controlled IPs and domains                        |
| Execution            | Command and Scripting Interpreter    | T1059.001    | YARA / Memory Dumps  | Use of PowerShell/scripting patterns in captured rules                  |
| Defense Evasion      | Obfuscated Files or Information      | T1027        | YARA / IOC content   | Use of hex/base64 strings in malware signature                          |
| Collection           | Data from Local System               | T1005        | MISP Export          | MISP IOC captures artifacts from infected systems                       |
| Exfiltration         | Exfiltration Over Web Service        | T1567.002    | ThreatView / Report  | Indicators showing use of HTTPS for exfiltrating data                   |
| Impact               | Data Destruction                     | T1485        | Use case (hypothetical) | Can be inferred from malware signatures meant to destroy logs/data    |

---

## ✅ Why This Matters

- Helps structure incident reports and threat hunting
- Standardizes indicators and behaviors across tools
- Makes reports intelligence-grade for SOCs and analysts
- Aligns your internship learning with real-world frameworks

---

## 📚 References

- [MITRE ATT&CK Official Site](https://attack.mitre.org/)
- [ThreatView.io IOC Feed](https://threatview.io/)
- [MISP Project](https://www.misp-project.org/)
- [YARA Rules Guide](https://virustotal.github.io/yara/)

---

*Prepared as part of Week 1 – Digisuraksha Cybersecurity Internship (2025)*
