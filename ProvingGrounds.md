# Offsec Proving Grounds Notes

## Guide for Offsec
https://web.archive.org/web/20221126165225/https://scund00r.com/all/oscp/2018/02/25/passing-oscp.html#enumeration

## Guide for Pentesting
https://kolegite.com/EE_library/books_and_lectures/%D0%9A%D0%B8%D0%B1%D0%B5%D1%80%D1%81%D0%B8%D0%B3%D1%83%D1%80%D0%BD%D0%BE%D1%81%D1%82/RTFM%20Red%20Team%20Field%20Manual%20v2%20--%20Ben%20Clark%20%26%20Nick%20Downer.pdf


## Hash Cracking
- If a hash cannot be cracked using rockyou.txt, assume that is not the intended path.

## Bruteforcing
- If a service or login does not yield results with rockyou.txt, it is not the correct approach.

## Common Anonymous Access
- Anonymous FTP  
- Anonymous SMB

## Web Infrastructure
- 90's LAMP tech stack  
- Sysadmins making PHP administrative portals  
- Canned CMS

## Initial Access
- Try Harder Enumeration  
- Default creds (CMS/Web Apps)  
- Basic Web Vulns:  
  - SQLi login bypass  
  - LFI  
  - Command Injection (PHP)  
  - Image/File Upload Bypass (PHP)  
- CVE PoCs from GitHub / Exploit-DB

## Most Popular Ports
- 80 - HTTP  
- 22 - SSH  
- 21 - FTP  
- 139 - NetBIOS session service  
- 445 - SMB  
- 3306 - MySQL  
- 53 - DNS  
- 135 - MS RPC  
- 8080 - Alternate HTTP  
- 443 - HTTPS  
- 3389 - RDP  
- 25 - SMTP  

## Samba - Default implementation allows bruteforcing RIDs to get users

```bash
enum4linux-ng.py -u anonymous -p '' -A -R 500 <IP> | tee enum4LinuxAnonymous.txt | grep "Found user" | tee users.txt
```

## SMB - Windows

### RID Bruteforce for Users
```bash
crackmapexec smb <IP> -u 'anonymous' -p '' --server-port 445 --rid-brute 20000 | tee accounts.txt
```

### List SMB Share Permissions as Guest
```bash
smbmap -r -H <IP> -u invalid -P 445 | tee smbMapGuestSession.txt
```

### Download Anonymous SMB Share
```bash
smbclient \\\\10.10.10.10\\share -p 445 -N -Tc share.tar
tar xf share.tar -C share
```

## ngrep can give good info on protocol versions
```bash
sudo ngrep -i -d <network interface> 's.?a.?m.?b.?a.*[[:digit:]]' port 139
smbclient -U '%' -N -L \\\\10.10.10.10\\
```

## Attempt to get users via MSRPC
```bash
rpcclient -U "" -N <IP> -c enumdomusers --port 135 | tee enumDomUsers.txt
```

## Every boot2root DC allows bruteforcing pre-authentication for Kerberos to get valid users
```bash
timeout 10m kerbrute userenum /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt --dc <IP> --domain $domainName -v | grep 'VALID USERNAME:' | awk '{print $NF}' | tee users.txt
```

## Machine creators will usually make the priv esc last. Check for all file changes before the release date of the Linux VM.
```bash
find -L / -type f -newerct "2020-12-01" ! -newerct "2020-12-21" 2>/dev/null
```
