## ENUMERATION

NMAP TCP PORTS

```jsx
nmap -p- --min-rate=10000 -c 10.10.11.107 

Nmap scan report for 10.10.11.107
Host is up (0.56s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE
23/tcp open  telnet

Read data files from: /usr/share/nmap
# Nmap done at Sat Jun  7 11:20:19 2025 -- 1 IP address (1 host up) scanned in 9.08 seconds
```

After looking at the port 23 it was only asking for a password
![image](https://github.com/user-attachments/assets/7bd47c37-822c-49b2-bb08-890246fd9db3)

after trying some basic passwords i tried to scan the udp ports 

NMAP UDP PORTS

```jsx
nmap -p- --min-rate=10000 -sU 10.10.11.107

Warning: 10.10.11.107 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.11.107
Host is up (0.21s latency).
Not shown: 65455 open|filtered udp ports (no-response), 79 closed udp ports (port-unreach)
PORT    STATE SERVICE
161/udp open  snmp

Read data files from: /usr/share/nmap
# Nmap done at Sat Jun  7 11:44:09 2025 -- 1 IP address (1 host up) scanned in 74.06 seconds
```

service enumeration using snmpwalk

```jsx
snmpwalk -v2c -c public  10.10.11.107                               
iso.3.6.1.2.1 = STRING: "HTB Printer"
```

But his only return string: htb printer i tired to bruteforce the community string using onesixtyone and snmpbrute but it return the same value on any comunity string.

After some googling i found we can specify oid at the end  and get some data,if the printer is misconfigured we may get password

searched for hp hetdirect oid and found this
![image](https://github.com/user-attachments/assets/e99f22e6-8a0f-4894-9b57-bb4d241a98b9)
```jsx
└─# snmpwalk -v2c -c public  10.10.11.107 1.3.6.1.4.1.11 
iso.3.6.1.4.1.11.2.3.9.1.1.13.0 = BITS: 50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 
33 1 3 9 17 18 19 22 23 25 26 27 30 31 33 34 35 37 38 39 42 43 49 50 51 54 57 58 61 65 74 75 79 82 83 86 90 91 94 95 98 103 106 111 114 115 119 122 123 126 130 131 134 135 
iso.3.6.1.4.1.11.2.3.9.1.2.1.0 = No more variables left in this MIB View (It is past the end of the MIB tree)
```

it gave this data

The data above is in hex,

decoding this data we got the password
![image](https://github.com/user-attachments/assets/3727e3d6-2c69-4d02-bb57-4ecd7d184563)


password: P@ssw0rd@123!!123

## EXPLOITATION

Connecting to the service from the above password
![image](https://github.com/user-attachments/assets/35c96e52-b792-47f5-90b4-f93706bad6a5)
![image](https://github.com/user-attachments/assets/856628f3-f344-4a51-ab54-1f5d0f32b8f2)
after seeing the help menu we can execute system commands using exec.
![image](https://github.com/user-attachments/assets/d02aa944-8e07-477d-bc34-284da280e827)
After getting the command execution i created a [shell.sh](http://shell.sh) with a revshell at port 1337 then i started a python web server to pull the shell.sh into the attack box and then executed the shell.sh using bash.

We got our user flag.

## POST-EXPLOITATION

I tried to see the process running and ran linpeas, there is an internal port 631 running a website.
![image](https://github.com/user-attachments/assets/ccb127c9-3e67-4e81-8ded-cff75ff6f6a0)
since we dont have a ssh connection i ran chisel to forward the port to my kali machine.

(the binary on my akli machine of chisel had some issues so i installed a diffrent chisel)





![image](https://github.com/user-attachments/assets/f5232a29-830f-4c63-adcb-928f81bd489b)


After going on the port 631 it was running cups

cups is a web based printer manager

![image](https://github.com/user-attachments/assets/ec08a5f9-3492-4f75-bc07-715c4a21920e)

It was running 1.6.1 

there was a cve for the version 1.6.1 where we can read files with root privileages
![image](https://github.com/user-attachments/assets/554a5070-d4c3-41c0-806d-fe146be3e2c9)
i found a poc script https://github.com/p1ckzi/CVE-2012-5519

After running the exec it prompted for which file to read, we can specify the root.txt and get the contents of it.

![image](https://github.com/user-attachments/assets/cca39df3-f07d-4ecf-acfa-077f02ca0454)





