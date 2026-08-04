---
title: "DriftingBlues: 6"
date: 07-28-2024
excerpt: VulnHub
cover: ../uploads/cover_driftingblues6.jpg
tags: cve-2016-5195
---

Glad to have you back for another writeup! In this one, I’ll walk you through the step-by-step process I followed to solve the sixth stage of the DriftingBlues Boot2Root challenge from VulnHub. Let’s dive in!

First off, like usual, we’ll start by using `Nmap` to scan for open ports that might serve as our entryway into the system.

```shell
nmap -A -sC -p- -T5 -oN nmap_result.log 192.168.54.188
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FDp5kEBJtp6qVnBhdZNcK%252FScreenshot%2520%281736%29.png%3Falt%3Dmedia%26token%3D2552c56d-76ea-473f-8dc7-8f69abfeb8ed&width=768&dpr=3&quality=100&sign=afe9cd20&sv=2)

Only Port 80 (HTTP)

As you can see from the Nmap scan, there's a subdirectory revealed: `/textpattern/textpattern`.

But let's visit the main webpage first.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FTCOwMDffMghFUIwwG7ql%252FScreenshot%2520%281738%29.png%3Falt%3Dmedia%26token%3D3d620a3d-a328-40b9-b9ca-bcb25d5b8344&width=768&dpr=3&quality=100&sign=5760b50f&sv=2)

Just a simple DriftingBlues webpage

Now let's visit the `/textpattern/textpattern` .

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Ft0OsLQ2ydici6gw83V6e%252FScreenshot%2520%281739%29.png%3Falt%3Dmedia%26token%3Dc8236fe0-4ca7-46bc-81b3-e8fa1aa9571e&width=768&dpr=3&quality=100&sign=f49fb1ee&sv=2)

A textpattern login page.

Textpattern is a lightweight, open-source content management system (CMS) written in PHP that uses MySQL for managing website content. It’s known for producing clean, semantic code and is favored by designers who want full control over HTML and CSS. Often installed in directories like `/textpattern/`, it includes an admin panel for managing articles, templates, and plugins.

When I visit the `robots.txt` , there's a note.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FlceewHQCzqXBOO0lZC3q%252FScreenshot%2520%281742%29.png%3Falt%3Dmedia%26token%3D47863722-fa5e-4b51-b991-33b2e4d41a36&width=768&dpr=3&quality=100&sign=5350e9eb&sv=2)

Now, based on the hint, let’s begin enumerating for any files with a `.zip` extension using `Gobuster`.

```shell
gobuster dir -u http://192.168.54.188 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x .zip
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FW45Ha9f0EZMCarfvcEOT%252FScreenshot%2520%281744%29.png%3Falt%3Dmedia%26token%3D65d2ac81-5a06-4c1a-a5e7-1d302c7a0e14&width=768&dpr=3&quality=100&sign=51647897&sv=2)

There's a zip file named, `spammer.zip` .

Let's unzip the zipfile.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FXdq6TnEDKHyEPNPKuD9n%252FScreenshot%2520%281746%29.png%3Falt%3Dmedia%26token%3D064b6c7e-dcb6-4363-91b1-335d0450a0c6&width=768&dpr=3&quality=100&sign=29d68f79&sv=2)

But there's a password, let's crack it! We will use `zip2john` to get the hash of the zipfile.

```shell
zip2john spammer.zip > hash
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FtYf7tls7R4XWBu4Mhzms%252FScreenshot%2520%281747%29.png%3Falt%3Dmedia%26token%3Dd46fe651-1f11-4280-a72f-c8e1937b5d4f&width=768&dpr=3&quality=100&sign=adfbf51b&sv=2)

Now let's crack the hash using `john`.

```shell
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FulMYBscZQitlOmsTIWdM%252FScreenshot%2520%281748%29.png%3Falt%3Dmedia%26token%3De98f91c2-d7d1-469d-8722-ec9b4a1b18f6&width=768&dpr=3&quality=100&sign=f88431d4&sv=2)

Now that we got the password for the zipfile, let's unzip it again!

After extracting the contents, a text file named `creds.txt` was revealed.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F9UpP6yjAEc76ZxTuggnv%252FScreenshot%2520%281749%29.png%3Falt%3Dmedia%26token%3D99a96e35-2710-45ab-816a-3f3f85ec5aa2&width=768&dpr=3&quality=100&sign=a3fdee76&sv=2)

Let's see what's inside.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F2xvZ4cfhlARCwICpthIj%252FScreenshot%2520%281750%29.png%3Falt%3Dmedia%26token%3Da814725f-ebd2-4877-a954-e48690c9f12f&width=768&dpr=3&quality=100&sign=79f81679&sv=2)

A username and a password, when I enter these credentials in textpattern, it works!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FvGzX1xnh7vZvY4Iv3El5%252FScreenshot%2520%281753%29.png%3Falt%3Dmedia%26token%3D8faa7cd5-57f8-43f5-aa34-20f69b245e69&width=768&dpr=3&quality=100&sign=d990bd64&sv=2)

We're in!!

Since we have administrative access, we can take advantage of a built-in feature in Textpattern that allows users with elevated privileges to upload files. This functionality is typically restricted to roles like the Publisher or site administrator for security reasons. Given our level of access, we can attempt to upload a malicious payload, such as a reverse shell payload.

Under the **Content** tab, you’ll find a **File** section—go ahead and click the **Upload** option and select your reverse shell payload to upload it.

You can opt to use [PentestMonkey’s](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) reverse shell payload, but in my case, I chose to use my [own](https://github.com/kUrOSH1R0oo/reverse-shell-payloads/blob/main/payload.php) custom PHP payload instead.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FZzHcLUYVNaOHAgdZN2Pw%252FScreenshot%2520%281754%29.png%3Falt%3Dmedia%26token%3Dbfd911cc-1edb-46af-bb1c-91de7423ac6c&width=768&dpr=3&quality=100&sign=2945f6c3&sv=2)

It's now uploaded, now to execute our payload, we should know the actual path of it, since it's in file, the path should be `http://target.com/textpattern/files/payload.php` . Bu before that, let's setup our listener for a while.

```shell
nc -lnvp 1234
```

Now we can trigger our payload.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FAnFiTshjDvKUnfKl8gYl%252FScreenshot%2520%281757%29.png%3Falt%3Dmedia%26token%3D08a8a932-bc0a-4157-9a7d-d2802be2f373&width=768&dpr=3&quality=100&sign=d2bb3748&sv=2)

We're in!!

Now, let’s upgrade our shell to a fully interactive one using a pseudo-terminal `(pty)`.

```shell
python -c 'import pty; pty.spawn("/bin/bash")'
```

After that, we’ll set our terminal type to `xterm` for better compatibility and display.

```shell
export TERM=xterm
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fkm6xvfBUjrZYgMcTRHwy%252FScreenshot%2520%281759%29.png%3Falt%3Dmedia%26token%3Dfb0b1b17-c012-47a1-9b87-48b7d97ac45c&width=768&dpr=3&quality=100&sign=c0490672&sv=2)

When I navigated to the `/home` directory to check for existing user accounts, I found it completely empty—which is quite unusual.

So, I went ahead and decided to run `LinPEAS` at this point.

During the scan, I came across something that caught my attention.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F1lB1sGVrXdw03FI0CKFt%252FScreenshot%2520%281761%29.png%3Falt%3Dmedia%26token%3D1bac3102-3e6a-4758-8f0c-702544ee96dc&width=768&dpr=3&quality=100&sign=7edfc111&sv=2)

It turns out that this machine is susceptible to the **DirtyCOW** vulnerability!

**What is DirtyCOW?**

**DirtyCOW (CVE-2016-5195)** is a privilege escalation vulnerability in the Linux kernel that takes advantage of a race condition in the way the kernel handles the **copy-on-write (COW)** mechanism. When a process requests a private, read-only mapping of a file (like `/etc/passwd`), the kernel allows it to make a private copy if it tries to write to it. However, DirtyCOW exploits a race condition where an attacker rapidly writes to memory while simultaneously using `madvise()` to trigger the kernel’s COW process, tricking it into writing to the underlying read-only file instead of a private copy. This allows an unprivileged user to overwrite protected files, potentially inserting a new root user or modifying binaries—thus gaining full root access.

We can search the exploit using `searchsploit` .

```shell
searchsploit dirty
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FjVsZoRmcJ3oug6mjwCuQ%252FScreenshot%2520%281767%29.png%3Falt%3Dmedia%26token%3D759667a4-f869-44e4-93d5-3a343919e603&width=768&dpr=3&quality=100&sign=f1ada599&sv=2)

In our case, we will use the `40839.c` .

```shell
searchsploit -m linux/local/40839.c
```

Then transfer the exploit to our target machine.

Once the exploit is transferred, we’ll compile it using `gcc`. Keep in mind that DirtyCOW relies on `pthread` and `lcrypt`, so we need to include those libraries during compilation.

```shell
gcc -pthread -lcrypt -o exploit 40839.c
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FDcQELK5LJywhoZLOl7yO%252FScreenshot%2520%281768%29.png%3Falt%3Dmedia%26token%3D87e03138-4459-4769-aac2-d87cafe323d2&width=768&dpr=3&quality=100&sign=e8a48ff4&sv=2)

Now let's execute our exploit!

```shell
./exploit
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FvsxRYYZj3W2D1Iwd2msf%252FScreenshot%2520%281769%29.png%3Falt%3Dmedia%26token%3D94a08f1f-d663-4b66-9911-d44a305b41e4&width=768&dpr=3&quality=100&sign=e188bbb8&sv=2)

It should work at this point, let's check the `/etc/passwd` .

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FbRDQOnUU4jelQ6qdzjpY%252FScreenshot%2520%281773%29.png%3Falt%3Dmedia%26token%3D17fa2d22-8ea4-4ee6-b302-8eaa53fdd94b&width=768&dpr=3&quality=100&sign=1462d90e&sv=2)

It worked perfectly! As you can see, the user **firefart** now has root access!

Now let's switch to **firefart**!

```shell
su firefart
```

And enter the password we've set during the the exploit.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FFlRsCRMJbQTjdhq2IoYA%252FScreenshot%2520%281775%29.png%3Falt%3Dmedia%26token%3Dbdb88daf-b629-4fa5-9d09-7ab65f564673&width=768&dpr=3&quality=100&sign=918868ab&sv=2)

We are root!!!!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FBFxti8qZYzm4grjIgyiC%252FScreenshot%2520%281776%29.png%3Falt%3Dmedia%26token%3Db796a837-eb03-48e3-8fdb-d53abd05fdfb&width=768&dpr=3&quality=100&sign=3df95602&sv=2)

Root Flag

We've successfully pwned DriftingBlues: 6!!!

Honestly, this machine was relatively straightforward compared to others. The steps to gain access and escalate privileges were clear, with minimal obstacles along the way. From basic enumeration and file upload to exploiting a well-known vulnerability like DirtyCOW, the entire process flowed smoothly. It’s a great box for beginners looking to practice core skills in privilege escalation and web-based exploitation.
