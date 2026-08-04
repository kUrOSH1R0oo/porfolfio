---
title: "DriftingBlues: 1"
date: 07-23-2024
excerpt: VulnHub
cover: ../uploads/cover_driftingblues2.jpg
tags: vhost-enumeration, ook-encoding, hydra-bruteforce, cron-race-condition, privilege-escalation
---

Welcome back to another CTF writeup! In this post, I’ll walk you through my step-by-step process of rooting **DriftingBlues: 1**, a vulnerable machine from VulnHub. I know it’s been a while since my last post, I’ve been tied up with school projects and other responsibilities, but I’m back and ready to dive into this challenge. This is the first installment in the **DriftingBlues** series, and I’m determined to complete the entire set soon. So buckle up, because we’re about to break down the exploitation process in detail and uncover all the flags this box has to offer.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FFkfqBRnczWze1O6BP8ea%252F222805.gif%3Falt%3Dmedia%26token%3D8a005b87-1b07-4ded-ad2c-40912baf030b&width=768&dpr=3&quality=100&sign=b2440de9&sv=2)

## Reconnaissance

First, we will scan for the open ports for potential entry points using **Nmap**

```shell
nmap -A -sC -p- -T5 -oN nmap_result.log 192.168.22.229
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FZYYUTNmLn9PoB4bYp9nz%252FScreenshot%2520%281449%29.png%3Falt%3Dmedia%26token%3D5f6e1d5b-588b-4b15-af89-5a94032c5957&width=768&dpr=3&quality=100&sign=e17ab96a&sv=2)

Port 22 (ssh) and Port 80 (http) are open

Let's visit the webpage

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FL3bSc7DEOeivfkulRV0c%252FScreenshot%2520%281450%29.png%3Falt%3Dmedia%26token%3Db5be7407-b716-4c5f-976d-63aa90cfe6cd&width=768&dpr=3&quality=100&sign=290feecc&sv=2)

Some simple Blog

## Enumeration

### Discovering Webmail Users and a Base64-Encoded Hint

As I scroll down, I noticed something that might be useful for us

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FJbiSojwIjyxBRsKEx6s7%252FScreenshot%2520%281455%29.png%3Falt%3Dmedia%26token%3D04524b56-7ebc-404f-b4b0-4c732ec13d76&width=768&dpr=3&quality=100&sign=67c63dff&sv=2)

I noticed that there are two webmail users: **sheryl** and **eric**. To proceed, I edited the `/etc/hosts` file to map the domain to **driftingblues.box**.

While inspecting the webpage’s source code, I came across something interesting — a comment containing a Base64-encoded string.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FXQMArscENd4WyShbFkij%252FScreenshot%2520%281452%29.png%3Falt%3Dmedia%26token%3D9bde04ed-e7b1-4a6a-85ad-df4c11681ed1&width=768&dpr=3&quality=100&sign=fd71d341&sv=2)

I decoded it and this is the plaintext

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FSX3v2qlXbZE7gSOMoPVO%252FScreenshot%2520%281454%29.png%3Falt%3Dmedia%26token%3D13acff1f-8f4a-4861-b2b5-817d2d4000fe&width=768&dpr=3&quality=100&sign=eb0d8d5c&sv=2)

It appears to be a path, so I appended it to the domain and here’s what the page returned.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FR6VM7wSUaQajT7aNFVxP%252FScreenshot%2520%281453%29.png%3Falt%3Dmedia%26token%3D4edb1d5a-34ed-4825-a89a-207cc1eb5181&width=768&dpr=3&quality=100&sign=f4a7ee4d&sv=2)

An Ook Programming Language, I've encountered this before.

### Decoding the Ook-Encoded Message

Next thing I did is to decode it using [dCode](https://www.dcode.fr/ook-language), and this is the plaintext.

```text
my man, i know you are new but you should know how to use host file to reach our secret location. -eric
```

The message subtly points toward the hosts file as a potential route to uncover something hidden. Given that, I turned my focus to the website and began brute-forcing directories using **Gobuster**, hoping to uncover any overlooked paths or directories that might offer valuable clues or lead to further access.

### Directory Enumeration with Gobuster

```shell
gobuster dir -u http://driftingblues.box -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 10
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FiUkGHNL7tXrw43jZ8pa9%252FScreenshot%2520%281459%29.png%3Falt%3Dmedia%26token%3D9b906df8-30f5-4d4a-bf17-e58905cda05f&width=768&dpr=3&quality=100&sign=69e20130&sv=2)

The `secret.html` captured my eyes, let's take that a visit.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FQYlkVRgGyqQsvIUm5bpm%252FScreenshot%2520%281460%29.png%3Falt%3Dmedia%26token%3D27e022aa-a496-4908-bcc0-0df81f5973cf&width=768&dpr=3&quality=100&sign=40adcbe0&sv=2)

And as always, a Rabbithole:<

### Brute-Forcing Virtual Hosts

But no worries, time to dig even deeper! Let’s try brute-forcing subdomains and see if anything useful turns up.

```shell
gobuster vhost -u driftingblues.box -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain -t 10
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FbeCKniXZ2LFBeqM3I4DD%252FScreenshot%2520%281461%29.png%3Falt%3Dmedia%26token%3D4fedfd37-9563-4b82-ad1d-aecd37ffa8e8&width=768&dpr=3&quality=100&sign=c7914b4e&sv=2)

And it has! Next thing I did is to add **test.driftingblues.box** to our `/etc/hosts` file.

When I visit the subdomain, this is the result.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FNy7YcJ0dxqpKXibwookY%252FScreenshot%2520%281463%29.png%3Falt%3Dmedia%26token%3De2650158-13f2-4f97-bd47-0466e6c1e77d&width=768&dpr=3&quality=100&sign=6d9d95f3&sv=2)

Nothing useful, so let's move on and try brute-forcing directories within this subdomain.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FoASuMt2ntYw8V8SnoDK8%252FScreenshot%2520%281464%29.png%3Falt%3Dmedia%26token%3D01f3858b-88cf-40d8-ac52-b33ada865916&width=768&dpr=3&quality=100&sign=cbad6eef&sv=2)

### Discovering ssh_cred.txt via robots.txt

I noticed a `robots.txt` file listed, let’s check it out and see if it reveals any hidden or restricted paths we can explore further.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FssgOcRmWFtOzFgo2EKtE%252FScreenshot%2520%281465%29.png%3Falt%3Dmedia%26token%3Dc469f49c-0d28-4ff4-b648-26434cbb9723&width=768&dpr=3&quality=100&sign=d53ad572&sv=2)

Inside the `robots.txt` file, there’s a disallowed path named **/ssh\_cred.txt**. While "Disallow" is meant to keep web crawlers out, it doesn’t actually prevent us from visiting it directly — so let’s go ahead and check it out.

Wait, wait, wait, before that, I'll explain the meaning of Disallow in y'all to avoid confusion.

In the context of a `robots.txt` file, **"Disallow"** is a directive used to tell web crawlers (like those from Google or Bing) **not to access or index** specific parts of a website. Here's an example.

```text
User-agent: *
Disallow: /private/
```

This tells all web crawlers not to access the `/private/` directory.

**Important Note**:

* **Disallow is not a security feature** — it only provides guidance to *well-behaved* bots.
* Anyone (including you) can still visit that path manually in a browser or using tools like `curl`.

So when you see something like `Disallow: /ssh_cred.txt`, it’s more like saying, “Hey, bots, please don’t go here,” but nothing is technically stopping you from visiting it.

Now let's visit the `/ssh_cred.txt` .

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FJRHCPFavKzdSqPCzJgUG%252FScreenshot%2520%281466%29.png%3Falt%3Dmedia%26token%3Ddc3b72e1-a05f-436d-95a3-48a591480a91&width=768&dpr=3&quality=100&sign=cb1d1d03&sv=2)

This looks promising — we’ve got an SSH password! However, the message hints that there's a numeric value at the end of it. Since I didn’t want to manually brute-force every possibility, I took a more efficient approach.

## Exploitation

### Building a Targeted Password Wordlist

```python
for i in range(10):
    print(f"1mw4ckyyucky{i}")
```

Then I pasted the output to `passw.txt` and collect the two users we saw earlier, **sheryl** and **eric** to `user.txt` .

Time to bruteforce using **Hydra.**

### Brute-Forcing SSH Credentials with Hydra

```shell
hydra -L user.txt -P passw.txt 192.168.22.229 ssh -t 10
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FyzxRp3Dd6nc11ovSBQZO%252FScreenshot%2520%281470%29.png%3Falt%3Dmedia%26token%3Df45cb54f-31f2-457f-b759-4e4bf2c267a0&width=768&dpr=3&quality=100&sign=2d126965&sv=2)

We've got eric's credentials, now let's login!

### Logging in as eric and Capturing the User Flag

```shell
ssh eric@192.168.22.229
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FBabwGJoXa9vlpMMMY9Zy%252FScreenshot%2520%281472%29.png%3Falt%3Dmedia%26token%3Dbef7b668-3629-4787-a43b-9ce2cac4d1ef&width=768&dpr=3&quality=100&sign=c553844c&sv=2)

Yes!! We're in!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fc7xjW01t8akDWfVEpivG%252FScreenshot%2520%281473%29.png%3Falt%3Dmedia%26token%3D767f0d27-e151-4ce6-a046-ce9783729f38&width=768&dpr=3&quality=100&sign=22a3c3fb&sv=2)

Got the 1st flag!

## Privilege Escalation

### Enumerating with sudo -l and linPEAS

I attempted to run `sudo -l`, but it seems that **eric** doesn’t have any elevated privileges.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FKt1iFba1RdY162yTO8Py%252FScreenshot%2520%281474%29.png%3Falt%3Dmedia%26token%3D867d81d8-b7e0-4fdb-b33e-2155af1aedcc&width=768&dpr=3&quality=100&sign=82b2494a&sv=2)

What I did next is to use **linPEAS**, but it doesn't give me anything valuable.

### Monitoring Processes with pspy64

I decided to run **pspy64**, a powerful tool designed to monitor real-time processes on a Linux system without requiring root access. It’s especially useful for spotting scheduled tasks, scripts, or unusual activity that might otherwise go unnoticed.

After a short wait, I spotted some unusual processes being executed.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FHtqowjXJIreOe8IStFwR%252FScreenshot%2520%281475%29.png%3Falt%3Dmedia%26token%3D8c1b8c42-11e1-4896-8e13-6906bd627085&width=768&dpr=3&quality=100&sign=ae61dce3&sv=2)

This sequence of commands reveals an automated backup process likely triggered by a cron job. It begins with `/usr/bin/zip` compressing the `/var/www/` directory into `/tmp/backup.zip`, followed by the execution of a script located at `/var/backups/backup.sh` via `/bin/sh`. The duplication of the command using `-c` suggests it's being run through a cron entry or another script. The presence of `/usr/sbin/CRON -f` confirms that cron is actively handling scheduled tasks. The use of `/bin/chmod` indicates that file permissions are being modified during the process, and most notably, the command `sudo /tmp/emergency` suggests that a privileged script or binary is executed at some point — potentially offering a privilege escalation vector if the `/tmp/emergency` file can be manipulated.

### Hijacking /tmp/emergency for Root

But when I checked the `/tmp` directory, the `emergency` file wasn’t there — it simply didn’t exist. This could mean that the file is either created temporarily during execution and then deleted, or it’s being generated dynamically at runtime and removed immediately after use. Either way, it suggests there's a small time window where I might be able to replace or hijack it before the system does, which opens up a potential privilege escalation opportunity if timed correctly.

The idea that came to mind was: what if I create a file named `emergency` inside `/tmp` and embed a malicious payload in it? Since the system is executing `/tmp/emergency` with root privileges, any code I place inside that file would run with the same elevated permissions — effectively giving me root access if it works.

So I went ahead and created a file named `emergency` inside `/tmp`, and here’s the payload I placed inside it.

This script changes a user's password by passing the new credentials to the `chpasswd` command. When run as root, it sets the specified user's password to the one provided.

Next thing I did to make it executable

```shell
chmod +x emergency
```

and execute `pspy64` again and wait for the modified `emergency` file to execute.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FTV2aXHgdFTOTv2H2QAtf%252FScreenshot%2520%281492%29.png%3Falt%3Dmedia%26token%3D1e74f8e3-5c8a-4a8f-afee-d21e89cf639c&width=768&dpr=3&quality=100&sign=540c7658&sv=2)

As you can see, the `chpasswd` command runs right after `sudo /tmp/emergency` — which means the exploit worked perfectly!

All we need to do is to switch to root using `su` or `su root` and type `kuro` as our password.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F0tsaJ6U1rilcJwOkxCoH%252FScreenshot%2520%281493%29.png%3Falt%3Dmedia%26token%3Dd7011cd2-a56b-4f38-b6a4-74e627e1b31d&width=768&dpr=3&quality=100&sign=932217b3&sv=2)

We are root!!

And here's the root flag

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FpDlKBQKatZi0C9IUL1EI%252FScreenshot%2520%281495%29.png%3Falt%3Dmedia%26token%3Dcbfe7acc-c5ae-404b-9d4f-827187c6a5ed&width=768&dpr=3&quality=100&sign=4b21270b&sv=2)

piece

We've successfully pwned DriftingBlues: 1!!!!

## Conclusion

This box demonstrated a clear privilege escalation path through an insecure cron job or scheduled task that executed a script from the `/tmp` directory with root privileges. By placing a custom `emergency` script containing a password-changing payload into `/tmp`, and waiting for it to be executed by the system, I was able to successfully gain root access. This highlights the dangers of running scripts from world-writable locations without proper validation or permission controls, making it a valuable lesson in system hardening and secure task scheduling.
