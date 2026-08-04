---
title: "Matrix Breakout: Morpheus"
date: 05-02-2024
excerpt: VulnHub
cover: ../uploads/cover_morpheus.jpg
tags: arbitrary-file-write, reverse-shell, dirtypipe-cve-2022-0847, suid-hijacking, privilege-escalation
---

Hey everyone, welcome back to my write-up! Today’s a special day — it’s my birthday — and to celebrate, I’ve decided to share something equally exciting: my walkthrough of the *Matrix-Breakout: 2 – Morpheus* machine from VulnHub. This is a **Boot2Root challenge**, and in this post, I’ll walk you through how I approached, enumerated, exploited, and rooted the box. Let’s dive into the rabbit hole and see what Morpheus has in store for us!

## Reconnaissance

Let's begin by scanning our target to discover open ports that could serve as potential entry points, using Nmap.

`nmap -A -sC -T5 -p- -oN nmap_result.log <target_ip>`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F3YelQc4Ntmedy5qrAG1W%252FScreenshot%2520%281240%29.png%3Falt%3Dmedia%26token%3D3605092d-4b16-4c2a-8760-8c1d03f8d8e6&width=768&dpr=3&quality=100&sign=dbc64cec&sv=2)

Port 22 (ssh), Port 80 (http), Port 81 (http/nginx)

Let's visit the webpage!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FwCTZ2KbgOSgDIp44yRfe%252FScreenshot%2520%281241%29.png%3Falt%3Dmedia%26token%3D583be360-245e-4596-af6a-99c445d54b7e&width=768&dpr=3&quality=100&sign=d9fa980b&sv=2)

## Enumeration

### Directory Enumeration with Gobuster

Next, I proceeded to enumerate all the subdirectories with **Gobuster**. I forgot to take a screenshot of the results, haha, but here’s the command I used.

`gobuster dir -u http::<target_ip>/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html,php,txt -t 10`

### Discovering graffiti.php

During the scan, a file named `graffiti.php` appeared — let’s check it out.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FBZCwoqeKbAc7y1Vsuup5%252FScreenshot%2520%281243%29.png%3Falt%3Dmedia%26token%3D3592fa0e-41c6-44de-93aa-cb12441241cf&width=768&dpr=3&quality=100&sign=c4145662&sv=2)

Graffiti Wall = Freedom Wall??? XDD

The next step was to post a message to observe how it responds.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F2k3k8RJayVhhFgadBkLU%252FScreenshot%2520%281246%29.png%3Falt%3Dmedia%26token%3D5a6f5239-3777-4d0c-b284-1cab14d5eeb3&width=768&dpr=3&quality=100&sign=f288fbfa&sv=2)

When I submitted a message(kuro), the webpage refreshed and displayed my post.

### Intercepting Traffic with Burp Suite

What’s next? Let’s take a closer look at how it functions and handles data — time to intercept the traffic using **BurpSuite**.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FRQ6SMdfVFXct2kbMUZCP%252FScreenshot%2520%281248%29.png%3Falt%3Dmedia%26token%3D2f74b508-6eb2-40e0-bc33-71aaad77a626&width=768&dpr=3&quality=100&sign=5ec0dc78&sv=2)

It seems that whatever we submit on `graffiti.php` gets saved into `graffiti.txt`. Here lies a vulnerability — what if I modify the filename? What do you think would happen?

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FZZR1HoK1kvOX054BjKvE%252FScreenshot%2520%281249%29.png%3Falt%3Dmedia%26token%3D96cc2788-499e-4cdd-97d3-254be3a1aadb&width=768&dpr=3&quality=100&sign=8c462b73&sv=2)

And it works!! As you can see, **kurokuro** is the only message posted in the response. To verify, let's visit the `kurokiri.txt`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FDRdgnvtXysJIyXZ06bz1%252FScreenshot%2520%281250%29.png%3Falt%3Dmedia%26token%3D51e66c24-76f8-4627-b6f3-bd1b57f74c9d&width=768&dpr=3&quality=100&sign=e19ca433&sv=2)

It works!!

### Identifying the Arbitrary File Write Vulnerability

Looks like the application allows full control over both the **filename** (`file` parameter) and the **content** (`message` parameter) when submitting data through `graffiti.php`. By intercepting and modifying these parameters using BurpSuite, I was able to create or overwrite arbitrary files on the server with custom content. This type of vulnerability is classified as **Arbitrary File Write** or sometimes **Unrestricted File Upload**. It’s particularly dangerous because an attacker can upload malicious files—like web shells—which may lead to **remote code execution (RCE)** if the server executes those files.

## Exploitation

### Writing a PHP Reverse Shell via Arbitrary File Write

Now it's time to abuse this vulnerability to gain a reverse shell!

Good thing that I have my own collection of payloads in my [Github](https://github.com/kUrOSH1R0oo/reverse-shell-payloads), all we need to do is to copy the PHP payload and treat as the message, modify the IP and Port, then turn the filename to a PHP file.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F3Na6V30XWJ7Yfx2US1BS%252FScreenshot%2520%281253%29.png%3Falt%3Dmedia%26token%3De2ec2cfe-ac0e-490c-8cf4-df0d89d536a6&width=768&dpr=3&quality=100&sign=3a3a928e&sv=2)

Success! Now it’s time to execute the payload through the browser — but first, let’s set up our **Netcat** listener to catch the reverse shell.

`nc -lnvp 1234`

### Catching and Upgrading the Reverse Shell

Trigger the payload in the browser, and we should receive a reverse shell connection!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FGNEwaDLDGNrPpYevCIQ4%252FScreenshot%2520%281254%29.png%3Falt%3Dmedia%26token%3D5236baaa-e12d-4ea0-b9e8-7cc8eb9c78e9&width=768&dpr=3&quality=100&sign=c8177b16&sv=2)

Time to make our shell interactive!

`python3 -c 'import pty;pty.spawn("/bin/bash")'`

then ^Z

`stty raw -echo && fg`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FQ1o0znLAGiajoDiXxVG9%252FScreenshot%2520%281256%29.png%3Falt%3Dmedia%26token%3Da2689abb-2a86-4b85-b57e-e6ffa3740779&width=768&dpr=3&quality=100&sign=2187ce4c&sv=2)

## Privilege Escalation

### Running linPEAS and Identifying DirtyPipe (CVE-2022-0847)

After looking around and finding nothing of interest, I decided to run **linPEAS** to check for any potential privilege escalation opportunities.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fw7Xt3gE3ioA57AkkYXVT%252FScreenshot%2520%281257%29.png%3Falt%3Dmedia%26token%3Dd430c772-1f58-4c48-b9c1-816d6c3d565b&width=768&dpr=3&quality=100&sign=a1d2d3a9&sv=2)

The system appears to be vulnerable to **DirtyPipe** (CVE-2022-0847), a critical Linux privilege escalation exploit discovered in 2022. It affects kernel versions 5.8 and above, allowing an unprivileged user to overwrite read-only files by abusing flaws in the way the kernel handles pipe buffers. This can be leveraged to inject malicious content into sensitive files, potentially leading to full **root access**. Given the kernel version on the target, this vulnerability presents a clear path to privilege escalation.

### Compiling and Running the DirtyPipe Exploit

I used **SearchSploit** to locate and retrieve the exploit script.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FKIaw6LWAF3CUOFBWytlv%252FScreenshot%2520%281260%29.png%3Falt%3Dmedia%26token%3D461b2dc4-fe7b-4a67-bec4-96772125a215&width=768&dpr=3&quality=100&sign=f7428b41&sv=2)

To retrieve the exploit

`searchsploit -m <exploit_path>`

Next thing we did is to transfer the exploit to our target using **wget**

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FuBN97iEyIIGX3O9NcHsW%252FScreenshot%2520%281262%29.png%3Falt%3Dmedia%26token%3Dbd60fdbc-2a19-44bb-9d3c-57c7fc693303&width=768&dpr=3&quality=100&sign=76cfaf18&sv=2)

Let's compile it using **gcc**

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FWBGnbGZxTomYFLSDmUqS%252FScreenshot%2520%281264%29.png%3Falt%3Dmedia%26token%3Dbc988d52-faab-4ffc-9e7b-a5af6af0bbe8&width=768&dpr=3&quality=100&sign=17ff7bb0&sv=2)

Now, let's execute our exploit!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FKVxijEXuexzSNc0ZIhKX%252FScreenshot%2520%281265%29.png%3Falt%3Dmedia%26token%3Ddecd3440-c3f4-451e-8cf5-b52f5d471053&width=768&dpr=3&quality=100&sign=aa1b8689&sv=2)

It seems we need to specify a SUID binary to hijack — in this case, since we're aiming for root access, we'll target `/usr/bin/su`.

### Gaining Root Access

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fpv0XVDBqocJCrkZzrVNV%252FScreenshot%2520%281267%29.png%3Falt%3Dmedia%26token%3De204d3be-8a28-4d59-b567-00a8e9f4a060&width=768&dpr=3&quality=100&sign=73f122c5&sv=2)

We are root!!!! We've successfully pwned Morpheus!!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F15KJFMBXM2XTS9Cn4hQU%252FScreenshot%2520%281268%29.png%3Falt%3Dmedia%26token%3D6abcf2c7-eb2d-47f6-8e8d-41a523fb5c6b&width=768&dpr=3&quality=100&sign=564c8812&sv=2)

Root Flag

## Conclusion

This CTF challenge showcased two impactful vulnerabilities that led to a full compromise of the target system. The first was an **Arbitrary File Write (AFW)** vulnerability, where I was able to manipulate both the filename and the file content via HTTP parameters. This flaw allowed me to write a reverse shell script directly to the server and execute it, establishing a foothold. With initial access obtained, I explored the system further and discovered that it was running a Linux kernel version vulnerable to **DirtyPipe** (CVE-2022-0847). This critical privilege escalation exploit allowed me to overwrite read-only files and hijack a SUID binary — in this case, `/usr/bin/su` — to escalate my privileges and gain full **root access**. By chaining AFW and DirtyPipe, I successfully completed the Boot2Root challenge.
