---
title: "DriftingBlues: 5"
date: 07-27-2024
excerpt: VulnHub
cover: ../uploads/cover_driftingblues5.jpg
tags: keepass, linpeas, cronjob
---

Welcome back to my writeup!! Today I will show how I solved the fifth part of the DriftingBlues series!! No further explanations, let's start!!

First thing that will do is always, `Nmap` scan.

```bash
nmap -A -sC -p- -T5 -oN nmap_result.log 192.168.54.174
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FLDkvXnKbhfMv8hB22yC3%252FScreenshot%2520%281672%29.png%3Falt%3Dmedia%26token%3D4f6f94c1-8606-495e-972f-d44d893771d0&width=768&dpr=3&quality=100&sign=280c1e4b&sv=2)

Port 22, and 80 are open

It's clear that the HTTP service is running WordPress. We already have an idea of how to proceed with this.

But first, let's visit the webpage.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FwEi58kDpM1Urb4r4xJv3%252FScreenshot%2520%281673%29.png%3Falt%3Dmedia%26token%3D20f2fc73-808f-453a-ac71-cd81b1d18646&width=768&dpr=3&quality=100&sign=1e76cf62&sv=2)

Just a simple webpage, what to expect in driftingblues?? xD!

Next thing I did is to enumerate all the subdirectories using `Gobuster` .

```bash
gobuster dir -u http://192.168.54.174 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html,php,txt
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FlPIx98LTAgWdOzbei0S2%252FScreenshot%2520%281674%29.png%3Falt%3Dmedia%26token%3Dbc0bcfc8-03a9-470c-83e1-14f626e453c1&width=768&dpr=3&quality=100&sign=f344ed0c&sv=2)

Nothing interesting, just normal wordpress subds

Next thing I did is to use `wpscan` to scan for any vulnerabilities in this WordPress webapp, since it has a login page, we can directly bruteforce this!

```bash
wpscan --url http://driftingblues.box --detection-mode aggressive -e -P /usr/share/wordlists/rockyou.txt
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FnjPpOCHDxMUgC8j2eFn1%252FScreenshot%2520%281676%29.png%3Falt%3Dmedia%26token%3D609d5a42-b761-4442-8f72-38cfe5521bb5&width=768&dpr=3&quality=100&sign=4f2abd8b&sv=2)

Here are the users

Since the cracking attempt using `rockyou.txt` was taking too long and most of the passwords in it are relatively short, I figured the actual password might be longer. To adapt, I used **CeWL** to crawl the target site and generate a **custom wordlist** by extracting words with at least 10 characters.

```bash
cewl http://driftingblues.box -m 10 -w passwd.txt
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Ffah32jJE8oAnCRTbGrrf%252FScreenshot%2520%281679%29.png%3Falt%3Dmedia%26token%3D16f045c3-8640-4348-a79d-4afa589c6349&width=768&dpr=3&quality=100&sign=215425cd&sv=2)

After that, I launched the wpscan and use our new wordlist.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FWvhmv0S61faQDhE7b4Py%252FScreenshot%2520%281683%29.png%3Falt%3Dmedia%26token%3Ddbfafd69-1724-4bfb-9596-e38adb47e387&width=768&dpr=3&quality=100&sign=7d018c15&sv=2)

We finally got the credential! Now let's login!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F8g1vKnEQqHori8S6sR8a%252FScreenshot%2520%281684%29.png%3Falt%3Dmedia%26token%3D91d07c31-ace5-437c-ba84-1e08e47df9a9&width=768&dpr=3&quality=100&sign=66a1ca6d&sv=2)

We're in!

While exploring I found nothing useful, but I've found some photos stored here, that might be our key.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FMVrAR09HsSyrI2rfOrEU%252FScreenshot%2520%281687%29.png%3Falt%3Dmedia%26token%3Df4142130-8c7b-4613-a868-d04fa34c9a8f&width=768&dpr=3&quality=100&sign=a4a871d&sv=2)

A DriftingBlues picpic, so I download it and check its metadata using `exiftool` .

```bash
exiftool dblogo.png
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FxZsk5EbGgQ7qF2IfArXN%252FScreenshot%2520%281688%29.png%3Falt%3Dmedia%26token%3D8651a80b-ef11-436a-b385-e8a0b71c1461&width=768&dpr=3&quality=100&sign=c14e8c9b&sv=2)

Well, would you look at that, an SSH password! Crazy how something as simple as metadata can end up being the key to breaking into a system. That’s the thing about CTFs, especially Boot2Root challenges, the tiniest details can make the biggest difference. It’s easy to overlook stuff that seems unimportant at first glance, but more often than not, that’s where the real gold is hidden. So if there’s one lesson here, it’s this: **never ignore the small stuff.** What looks like nothing could be your ticket in.

Let's login!!

```bash
ssh gill@192.168.54.174
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FssqHXG5xXnC4qv01EBgU%252FScreenshot%2520%281693%29.png%3Falt%3Dmedia%26token%3Dfb67aef6-aa0d-402c-ba46-75c064ddfdcd&width=768&dpr=3&quality=100&sign=bf6dceaf&sv=2)

We're in!!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F1zg4ZxJkvPQNASCmNsxv%252FScreenshot%2520%281697%29.png%3Falt%3Dmedia%26token%3D1a8ad90f-5f40-4288-b0fb-0302710b7e08&width=768&dpr=3&quality=100&sign=c760ec16&sv=2)

User Flag!!

Now time for the root!!

Alongside with user flag, there's a file named `keyfile.kdbx` .

In simple terms, a `.kdbx` file is a database used by **KeePass**, a password manager designed to securely store login credentials.

I started by transferring the file to my attacker machine. Since the database is protected by a master password that we don’t know yet, the next step is to extract the hash using `keepass2john` so we can attempt to crack it.

```bash
keepass2john keyfile.kdbx > hash
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FU6bvxZmKh3JY4GqB2kTC%252FScreenshot%2520%281702%29.png%3Falt%3Dmedia%26token%3D016a6672-31c2-4b59-8dc4-590395a509c0&width=768&dpr=3&quality=100&sign=36431d99&sv=2)

Now let's crack it!

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F7Ck1Ykcv1eVBN8buZ5o9%252FScreenshot%2520%281705%29.png%3Falt%3Dmedia%26token%3D82e07ee1-9ab9-4493-b91d-eb620746bcaa&width=768&dpr=3&quality=100&sign=f7a5c425&sv=2)

We got the master key, let’s check out what’s inside this `.kdbx` file. To peek into it, I’ll be using `keepassxc-cli`, which is just the command-line tool for working with KeePassXC password databases.

Before we dive in, here’s a quick rundown of what a KeePass file actually is and how it works:

**So, what’s a** `.kdbx` **file?**

Think of it like a **digital vault**. It’s used by KeePass to store things like usernames, passwords, URLs, and even notes — all safely encrypted in one place. To open it, you usually need a **master key**, which could be just a password, a special key file, or both (like a second layer of protection).

Inside the file, the saved entries are neatly organized into **groups and subfolders**, kind of like folders on your desktop. For example, you might have groups like "Emails", "SSH Logins", or "Social Media", and inside each one are entries with:

* The title of the entry (e.g., “GitHub”),
* Username,
* Password,
* Website URL,
* And maybe some notes.

All of that info is encrypted — so even if someone has the `.kdbx` file, they can't see anything without the correct master key.

Alright, back to the challenge — let’s list out all the groups in the database! To list, we will just use the `ls` parameter of `keepassxc-cli`.

```bash
keepassxc-cli ls keyfile.kdbx
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FYBm2eNKXpei0cuZpCDC4%252FScreenshot%2520%281709%29.png%3Falt%3Dmedia%26token%3Ddf348dbf-ca5b-46d1-84de-9535b9226997&width=768&dpr=3&quality=100&sign=22c30d8f&sv=2)

Here are the groups! Now let’s dive in and check out the passwords saved inside.

```bash
keepassxc-cli show keyfile.kdbx "group_name" --show-protected
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FC374bJOmvfaKmRk3ghOT%252FScreenshot%2520%281712%29.png%3Falt%3Dmedia%26token%3D58429c73-4ab5-4f57-9eb7-8bbe5183322f&width=768&dpr=3&quality=100&sign=5b3a3f82&sv=2)

But..... All of the groups has no passwords.. That's why I think that this is a rabbithole.

Let's go back to the target machine. I used `LinPEAS` to find out more about this system.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FyCoduUyKiRCyxzWdet8c%252FScreenshot%2520%281713%29.png%3Falt%3Dmedia%26token%3D6b2da290-9dc9-407f-b7e7-946ab0cc162f&width=768&dpr=3&quality=100&sign=11ab91d7&sv=2)

After the scan, I noticed a strange directory in root, the `/keyfolder` . Let's check it out.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FHz2MAftSR9M7VyefWzF1%252FScreenshot%2520%281726%29.png%3Falt%3Dmedia%26token%3Db4c46556-974e-413b-a28e-2c13d5602c1a&width=768&dpr=3&quality=100&sign=be16c5af&sv=2)

Looking at the permissions, we can see that other users have write access to this directory — even though it's owned by root! This could be our way to escalate privileges and gain root access.

When I looked inside, the directory was empty — leaving me completely unsure of what to do next.

At this point, I ran `pspy64` to monitor scheduled tasks and see if anything interesting was running via **cronjobs**.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FgmTAnPNJy9aDZsOEesNE%252FScreenshot%2520%281715%29.png%3Falt%3Dmedia%26token%3D45b5b9a7-4d22-4814-96ab-6c17bc1b1b74&width=768&dpr=3&quality=100&sign=43d60b19&sv=2)

While watching the output from `pspy64`, I noticed the system was running `/root/key.sh` using both `/bin/sh` and `/bin/bash`. That basically means there’s a script in the root directory being executed automatically.

Let’s go back for a bit. In the `/root` directory, I found a folder named `/keyfolder`, and based on the presence of the `/root/key.sh` script, I suspected it was meant to generate or process some kind of password. I figured the script might output something important — maybe the root flag — into that folder. But when I looked, it was completely empty. Earlier, I had cracked the `.kdbx` file, and if you recall, the group names inside it looked a lot like potential passwords. So I thought, maybe creating a file in `/keyfolder` using one of those group names as the filename would trigger the script. At first, nothing worked — no output, no reaction. I kept trying different group names, and just when it was starting to feel hopeless… one of them finally worked!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FR0KXx14fbp9OpTGZmFNO%252FScreenshot%2520%281718%29.png%3Falt%3Dmedia%26token%3D4f5eead2-cf9b-4036-9e60-9b1197af7e79&width=768&dpr=3&quality=100&sign=b4b8b1cf&sv=2)

After creating a directory named **fracturedocean** — which was one of the entries found in the `.kdbx` file, I waited a bit for the `key.sh` script to run. Soon after, a new file called `rootcreds.txt` was generated.

Honestly, this vulnerability was tough to spot, and it took quite a bit of trial and error to even come close to figuring it out.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fqi61LgOvvT48xO8ygHX1%252FScreenshot%2520%281720%29.png%3Falt%3Dmedia%26token%3D94ff5174-d2dd-4125-9c17-51dd1222fc01&width=768&dpr=3&quality=100&sign=814278d4&sv=2)

Root Password

Now let's login as root!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FDdFSHpZQceOt61xP4WX0%252FScreenshot%2520%281721%29.png%3Falt%3Dmedia%26token%3D5560759a-9143-4bdc-a827-2eb52c324768&width=768&dpr=3&quality=100&sign=e291006f&sv=2)

We are now root!!!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F9mnsj5X2extKR4FxJ59P%252FScreenshot%2520%281724%29.png%3Falt%3Dmedia%26token%3Decdc1665-edf5-4127-93d7-1f5b0aaeb084&width=768&dpr=3&quality=100&sign=e83df49&sv=2)

Root Flag!

We've successfully pwned DriftingBlues: 5!!

Let's check the content of `key.sh` to make it clear.

```bash
#!/bin/bash                                                                                                                                                                                  
                                                                                                                                                                                             
if [[ $(ls /keyfolder) == "fracturedocean" ]]; then                                                                                                                                          
        echo "root creds" >> /keyfolder/rootcreds.txt                                                                                                                                        
        echo "" >> /keyfolder/rootcreds.txt                                                                                                                                                  
        echo "imjustdrifting31" >> /keyfolder/rootcreds.txt                                                                                                                                  
fi
```

The `key.sh` script is a simple bash script that checks if the `/keyfolder` directory contains exactly one item named **fracturedocean**. If that condition is true, it writes a file called `rootcreds.txt` inside `/keyfolder`, containing the text "root creds" followed by the actual password `imjustdrifting31`. This explains why, after creating a directory named **fracturedocean** — which was a group name found in the `.kdbx` file — and waiting for the script to execute, the `rootcreds.txt` file was generated. The script is designed to look for that specific name, making the `.kdbx` group names a subtle hint toward the solution and showing how closely tied the cracked file and privilege escalation path are in this challenge.

This challenge was a perfect example of how Capture The Flag scenarios often test more than just technical skills — they challenge your attention to detail, creativity, and problem-solving mindset. What seemed like small or insignificant clues, like metadata or group names in a KeePass database, turned out to be key elements in solving the puzzle. By combining enumeration, password cracking, file inspection, and process monitoring, the path to privilege escalation gradually revealed itself. The solution wasn’t handed directly — it had to be pieced together from subtle hints and smart assumptions.

In the end, this challenge reinforced an important lesson: **never overlook the small stuff**. Whether it’s a file name, a group label, or a scheduled script, the smallest details can lead to the biggest breakthroughs. Stay curious, think outside the box, and always follow your instincts — they often point you in the right direction.
