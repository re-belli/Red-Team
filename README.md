# Offensive Security Notes: Unredacted  
**Be advised: hot takes ahead. These are the things people don’t say out loud.**

- [OSINT](#osint)  
- [Initial Access](#initial-access)  
- [Command & Control](#command--control)  
- [Credential Access](#credential-access)  
- [Lateral Movement](#lateral-movement)  
- [Privilege Escalation](#privilege-escalation)  

---

## HUMINT Collection

<table>
  <tr><td>LinkedIn</</td><td>Can Filter by company and it shows employees, also even shows people based on type of degree (allows you to profile targets) - Can use VPN and dummy account</td></tr>
  <tr><td>Employee Collection</td><td>Most companies use gmail and outlook. Also most employee emails are first.lastname@domain.com,firstname@domain.com, or <lastname><first_initial><second_initial>@domain.com. Even if you get preferred names from LinkedIn you can use sites like TruePeopleSearch to get full names, phone numbers, and addresses. You can also use IDCrawl to find social media accounts.</td></tr>
  <tr><td>Targeting</td><td>Can build a mind map on individuals, including prioritization of targeting. I’ll decide the proper way to word this later, since the real-world way this works would offend POGs and desk-job folks who’ve never done ground or in-person recon.</td></tr>
</table>

---

## Initial Access

<table>
    <tr>
    <td><b>Phishing/Smishing</b></td>
    <td>
      <a href="https://medium.com/sud0root/mastering-modern-red-teaming-infrastructure-part-7-advanced-phishing-techniques-for-2fa-bypass-85f9adc4dc3b" target="_blank">Medium: Advanced Phishing Techniques for 2FA Bypass</a>,  
      <a href="https://posts.specterops.io/phish-sticks-hate-the-smell-love-the-taste-f4db9de888f7" target="_blank">SpecterOps: Phish Sticks</a>
      Most companies don't give all employess second phones, but have them use their personal phone.  
    </td>
  </tr>
  <tr><td>MOTW bypass</td><td>tar.gz, CVE-2025-31334 - WinRar, CVE-2025-0411 - 7-zip</td></tr>
  <tr><td>Excel</td><td><a href="https://github.com/mttaggart/xllrs" target="_blank">Microsoft blocks macros in documents originating from the internet (email AND web download), XLL (Excel Add-Ins) are dlls loaded by Excel. Still get warning for no signature. Need legitimate code signing certificate to avoid this.</a></td></tr>
  <tr><td>Supply Chain</td><td>Dracula VS Code plugin was trojanized previously, <a href="https://github.com/0x-Apollyon/Malicious-VScode-Extension" target="_blank"></td></tr>
</table>

---

## Command & Control

<table>
  <tr><td><b>Subcategory</b></td><td><b>Description / Notes</b></td></tr>
  <tr><td>Beacon Profiles</td><td>Low-and-slow configs, jitter tuning, domain fronting tricks</td></tr>
  <tr><td>Frameworks & Custom Tooling</td><td>Cobalt Strike, Sliver, custom implants, OPSEC-safe builds</td></tr>
  <tr><td>Infrastructure Setup</td><td>Redirectors, staging servers, domain blending, TLS fingerprinting</td></tr>
</table>

---

## Credential Access

<table>
  <tr><td><b>Subcategory</b></td><td><b>Description / Notes</b></td></tr>
  <tr><td>Password Dumping</td><td>LSASS scraping, memory inspection, offline SAM parsing</td></tr>
  <tr><td>Token Theft / Abuse</td><td>Impersonation, delegation tokens, S4U abuse, golden tickets</td></tr>
  <tr><td>MFA / SSO Bypass</td><td>Push fatigue, token replay, OAuth abuse, conditional access gaps</td></tr>
</table>

---

## Lateral Movement

<table>
  <tr><td><b>Subcategory</b></td><td><b>Description / Notes</b></td></tr>
  <tr><td>Remote Execution</td><td>WMI, PSRemoting, scheduled tasks, service creation</td></tr>
  <tr><td>Credential Reuse</td><td>Pass-the-Hash, Pass-the-Ticket, Kerberoasting, plaintext creds</td></tr>
  <tr><td>AD / Identity Abuse</td><td>ACL abuse, shadow admin paths, group membership manipulation</td></tr>
</table>

---

## Privilege Escalation

<table>
  <tr><td><b>Subcategory</b></td><td><b>Description / Notes</b></td></tr>
  <tr><td>Local Exploits</td><td>Kernel bugs, DLL hijacking, vulnerable drivers, CVE chaining</td></tr>
  <tr><td>Misconfigurations</td><td>Unquoted service paths, writable directories, insecure permissions</td></tr>
  <tr><td>Token / Role Abuse</td><td>Privileged token impersonation, cloud role escalation, SID history tricks</td></tr>
</table>
