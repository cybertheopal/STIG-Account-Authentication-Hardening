# Account & Authentication Hardenin

In this lab, I will perform a compliance scan using Tenable's vulnerability management tool on a Windows 10 Pro virtual machine. The focus of this lab is on Account and Authentication Hardening. I’ll specifically look for settings and configurations related to user accounts, password policies, and authentication mechanisms that do not meet compliance standards. After identifying the non-compliant checks, I will apply the necessary remediations and re-run the scan to ensure the issues have been properly addressed.

# Table of Contents 

- [ **Tools Used**](#tools-used)
- [1.  **Configuring Compliance Scan**](#1-configuring-compliance-scan)
- [2.  **Analysing Scan Results**](#2-analysing-scan-results)
- [3.  **Security Control WN10-CC-000280 Overview**](#3-security-control-wn10-cc-000280-overview)
  - [3.1 Remediating WN10-CC-000280](#31-remediating-wn10-cc-000280)
  - [3.2 Confirming WN10-CC-000280 Remediation](#32-confirming-wn10-cc-000280-remediation)

- [4.  **Security Control WN10-00-000090 Overview**](#4-security-control-wn10-00-000090-overview)
  - [4.1 Remediating WN10-00-000090](#41-remediating-wn10-00-000090)
  - [4.2 Confirming WN10-00-000090 Remediation](#42-confirming-wn10-00-000090-remediation)

- [5. **Security Control WN10-AC-000035 Overview**](#5-security-control-wn10-ac-000035-overview)
  - [5.1 Remediating WN10-AC-000035](#51-remediating-wn10-ac-000035)
  - [5.2 Confirming WN10-AC-000035 Remediation](#52-confirming-wn10-ac-000035-remediation)

- [6.  **Lab Conclusion and Lessons Learned**](#6-lab-conclusion-and-lessons-learned)
  - [6.1 Conclusion](#61-conclusion)
  - [6.2 Lessons Learned](#62-lessons-learned)

<a id="tools-used"></a>
##  Tools Used

•	Tenable Vulnerability Management<br>
•	Windows 10 Pro VM (Azure)<br>
•	Group Policy Editor<br>
•	PowerShell<br>
•	Computer Management<br>

<a id="1-configuring-compliance-scan"></a>
##  1.	Configuring Compliance Scan

<img src="https://imgur.com/oXILdFb.png">

To set up the scan, I created a new Advanced Network Scan in Tenable and configured it to target the private IP address of my Windows 10 Pro VM. I selected the internal scanner and added valid Windows credentials to enable authenticated scanning. In the Compliance tab, I enabled policy compliance checks, and under the Plugins section, I activated the “Windows Compliance Checks” plugin. This setup allowed the scan to assess the system against established policy standards for configuration and security.

<a id="2-analysing-scan-results"></a>
##  2.	Analysing Scan Results

<img src="https://imgur.com/xB1gPwo.png">

The scan returned a total of 139 failed checks, 15 warnings, and 108 passed items. Since this was a freshly spawned Windows 10 Pro VM on Azure, the high number of failed checks reflects the default configuration of a new Azure VM, which often lacks tailored security settings out of the box. 

The failed checks covered a range of issues, including weak password policies, unconfigured account lockout settings, missing security patches, and permissive access controls. Notably, many failures were related to account and authentication settings, such as inadequate password length, lack of password expiration, and insecure Remote Desktop configurations. 

For this lab, I focused on three compliance checks related to account and authentication hardening to keep the scope manageable:

•	**WN10-AC-000035** – Passwords must be at least 14 characters in length.<br>
•	**WN10-00-000090** – Accounts must be configured to enforce password expiration.<br>
•	**WN10-CC-000280** – Remote Desktop Services must always prompt users for passwords upon connection.<br>

These settings are important for improving access control, and focusing on a smaller set allowed me to properly apply and test each change.

<a id="3-security-control-wn10-cc-000280-overview"></a>
##  3.	Security Control WN10-CC-000280 Overview

<img src="https://imgur.com/ACqgXG2.png">

**What is WN10-CC-000280?**
It’s a security rule that says: “Remote Desktop Services must always prompt a client for passwords upon connection.”

**Why remediate?**
If Remote Desktop doesn’t always prompt for a password, attackers could connect using cached or saved credentials, increasing the risk of unauthorised access.

**Real-world example:**
In some ransomware campaigns, attackers gained access to systems through Remote Desktop by exploiting saved credentials left behind on shared or previously compromised machines. By disabling automatic logon and enforcing a password prompt, organisations can add a critical layer of protection against such lateral movement.

**This compliance control applies to the following key frameworks:**

•	**NIST 800-53** – Authenticator management (IA-11)<br>
•	**NIST 800-171** – Access control and authentication (03.05.01b)<br>
•	**HIPAA** – Access controls and authentication (164.312(d), 164.306(a)(1))<br>
•	**GDPR** – Security of processing (Article 32.1.b)<br>
•	**DISA STIG (Windows 10)** – Credential management (WN10-CC-000280)<br>
•	**NIST CSF (v1.1 & 2.0)** – Identity and access management (PR.AC-1, PR.AA-01)<br>

---

<a id="31-remediating-wn10-cc-000280"></a>
### 3.1 Remediating WN10-CC-000280

<img src="https://i.imgur.com/YgTmFpU.png">

I opened the Group Policy Editor and navigated to the Remote Desktop Services security settings. Then, I enabled the “Always prompt for password upon connection” policy to ensure every Remote Desktop connection requires a password. Finally, I applied the changes and ran the PowerShell command `gpupdate /force` to immediately update the group policy and enforce the new setting.

<img src="https://i.imgur.com/bEKewoB.png">

---

<a id="32-confirming-wn10-cc-000280-remediation"></a>
### 3.2	Confirming WN10-CC-000280 Remediation

<img src="https://i.imgur.com/fSmXY85.png">

After running another compliance scan, I confirmed that WN10-CC-000280 has been successfully implemented and passed the check.

<a id="4-security-control-wn10-00-000090-overview"></a>
##  4. Security Control WN10-00-000090 Overview

<img src="https://i.imgur.com/d1mLZN7.png">

**What is WN10-00-000090?**
It’s a security rule that says: “Accounts must be configured to require password expiration.”

**Why remediate?**
If passwords never expire, they’re more likely to be reused, discovered, or cracked over time. Enforcing password expiration helps limit how long a stolen password can be used, reducing the risk of unauthorised access.

**Real-world example:**
Password reuse and non-expiring credentials have played a role in many breaches. For example, during the 2012 LinkedIn breach, millions of hashed passwords were leaked. Because many users reused those credentials for years without changing them, attackers were still able to access other accounts long after the initial breach.

**This compliance control applies to the following key frameworks:**

•	**NIST 800-53** – Authenticator management and strength (IA-5(1))<br>
•	**NIST 800-171** – User identification and authentication (3.5.2, 03.05.07d)<br>
•	**ISO/IEC 27001:2022** – Access control and authentication management (A.5.16, A.5.17, A.9.4.3)<br>
•	**HIPAA** – Access control and authentication safeguards (164.312(a)(2)(i), 164.312(d))<br>
•	**GDPR** – Security of processing (Article 32.1.b)<br>
•	**DISA STIG (Windows 10)** – Authentication and credential management (WN10-00-000090)<br>
•	**NIST CSF (v1.1 & 2.0)** – Identity and access management (PR.AC-1, PR.AA-01)<br>

---

<a id="41-remediating-wn10-00-000090"></a>
### 4.1 Remediating WN10-00-000090

<img src="https://i.imgur.com/MhVhgAW.png">

<img src="https://i.imgur.com/aFdQqM4.png">

To remediate WN10-00-000090, I first reviewed all active local user accounts via Computer Management and ensured that 'Password never expires' was unchecked for each one.

Next, I verified that the 'Maximum password age' policy was already set to 42 days, confirming that password expiration is properly enforced.

---

<a id="42-confirming-wn10-00-000090-remediation"></a>
## 4.2	Confirming WN10-00-000090 Remediation

<img src="https://i.imgur.com/njTFDeq.png">

After running another compliance scan, I confirmed that WN10-00-000090 has been successfully implemented and passed the check.

<a id="5-security-control-wn10-ac-000035-overview"></a>
##  5. Security Control WN10-AC-000035 Overview

<img src="https://i.imgur.com/ma3T8bn.png">

**What is WN10-AC-000035?**
It’s a security rule that says: “Passwords must, at a minimum, be 14 characters long.”

**Why remediate?**
Short passwords are easier for attackers to crack using brute-force or dictionary attacks. Enforcing a minimum length of 14 characters makes passwords significantly harder to guess, strengthening system security and reducing the risk of unauthorised access.

**Real-world example:**
Weak and short passwords have contributed to numerous breaches. In the 2019 Citrix data breach, attackers reportedly used password spraying to gain access. Enforcing longer, more complex passwords can help prevent these types of attacks, especially when paired with account lockout policies.

**This compliance control aligns with these main frameworks:**

•	**NIST 800-53** – Authenticator management and security (IA-5(1))<br>
•	**NIST 800-171** – User authentication requirements (3.5.7, 03.05.07a)<br>
•	**ISO/IEC 27001:2022** – Access control and authentication (A.5.16, A.5.17, A.9.4.3)<br>
•	**HIPAA** – Access controls and authentication safeguards (164.312(a)(2)(i), 164.312(d))<br>
•	**GDPR** – Security of processing personal data (Article 32.1.b)<br>
•	**DISA STIG (Windows 10)** – Access control and credential management (WN10-AC-000035)<br>
•	**NIST CSF (v1.1 & 2.0)** – Identity and access management (PR.AC-1, PR.AA-01)<br>

---

<a id="51-remediating-wn10-ac-000035"></a>
### 5.1 Remediating WN10-AC-000035

<img src="https://i.imgur.com/1DK1c2J.png">

I configured the Minimum password length policy via Local Group Policy Editor, setting it to 14 characters under `Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy`. This ensures all new passwords meet the minimum length requirement.

---

<a id="52-confirming-wn10-ac-000035-remediation"></a>
### 5.2	Confirming WN10-AC-000035 Remediation

<img src="https://i.imgur.com/EuHmsew.png">

After running another compliance scan, I confirmed that WN10-AC-000035 has been successfully implemented and passed the check.

<a id="6-lab-conclusion-and-lessons-learned"></a>
##  6. Lab Conclusion and Lessons Learned

<a id="61-conclusion"></a>
### 6.1 Conclusion

This lab focused on hardening account and authentication settings on a Windows 10 Pro virtual machine using Tenable's vulnerability management tool. By conducting a compliance scan, I identified and remediated three key non-compliant settings: WN10-AC-000035 (minimum password length of 14 characters), WN10-00-000090 (password expiration enforcement), and WN10-CC-000280 (password prompt for Remote Desktop Services). Each remediation was successfully applied through Group Policy Editor and verified through follow-up scans, resulting in all three checks passing. The process strengthened the system's access controls, reducing the risk of unauthorised access and aligning the configuration with security best practices.

---

<a id="62-lessons-learned"></a>
### 6.2 Lessons Learned

**Importance of Authenticated Scanning:** Using valid Windows credentials during the scan was critical for accessing detailed system configurations. Without authenticated scanning, the compliance checks would have been incomplete, potentially missing critical vulnerabilities.<br>

**Prioritising Key Controls:** Focusing on a small, manageable set of compliance checks allowed for thorough remediation and verification. This approach is practical for real-world scenarios where time and resources may be limited.<br>

**Real-World Relevance:** The lab highlighted the practical importance of strong password policies and secure Remote Desktop configurations. Real-world examples, like the LinkedIn and Citrix breaches, underscored how weak authentication practices can lead to significant security incidents.<br>

**Group Policy Efficiency:** Using Group Policy Editor to enforce settings like password length and expiration was straightforward and effective. The gpupdate /force command ensured immediate policy application, which is valuable for rapid remediation in production environments.<br>

I**terative Validation:** Re-running scans after each remediation confirmed the effectiveness of the changes. This iterative process is essential for ensuring compliance and catching any misconfigurations that might persist.<br>

This lab reinforced the value of proactive compliance scanning and targeted remediation in maintaining a secure system. These practices are directly applicable to real-world system administration and cybersecurity tasks.
