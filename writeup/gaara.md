---
title: Gaara
date: 03-23-2024
excerpt: VulnHub
cover: ../uploads/cover_gaara.jpg
tags: encoding-puzzles, hydra-bruteforce, gtfobins, privilege-escalation
---

Hello everyone! Welcome to my second Capture-the-Flag writeup. My first one was on **PWN THE TRON**, a great machine for practicing. If you’re interested, you can check it out [here](https://medium.com/@kura1yum3/pwn-the-tron-boot2root-ctf-vulnhub-590974e79c9d). Now, let’s dive into a new challenge**, Gaara** from Vulnhub. Based on what I’ve gathered, this is an easy machine to tackle. Let’s get started!

## Reconnaissance

Let’s determine the IP of our target first:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*qJmWkWO3IWo0bT5TSPT88A.png&width=768&dpr=3&quality=100&sign=13d04c1b&sv=2)

This is the IP of our target.

Now that we know, let’s use **Nmap** to scan the target’s network and identify any open ports that could serve as potential entry points.

`nmap -A -sV -p- -T4 -v 192.168.43.140`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*I8Eo7pyldRlUXeaxUS3q-w.png&width=768&dpr=3&quality=100&sign=afbc2c6c&sv=2)

As you can see here, the open ports are 22 which is ssh and 80 which is http

## Enumeration

### Exploring the Web Interface

Let’s take a quick look at the interface of our target

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*_NEi1KYkaNGosjbEg5UG5w.png&width=768&dpr=3&quality=100&sign=fadb58a&sv=2)

Not a fan of Naruto xD

### Directory Enumeration with Gobuster

It’s time for us to enumerate all the subdirectories of our target, focusing on those that may contain valuable information, vulnerabilities, or hidden resources. These could serve as potential entry points for further exploitation, whether it’s sensitive data, misconfigurations, or access points we can leverage to gain deeper access into the system. We’ll use **Gobuster** for this.

`gobuster dir -u http://192.168.43.140/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html,php,txt -t 64`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*xqat7w1787fzb5GCPOxxdQ.png&width=768&dpr=3&quality=100&sign=d5fdbab0&sv=2)

As you can see, I’ve completed the enumeration of the subdirectories, and one directory, **/Cryoserver**, caught my attention. At first, I thought it was of no value, but I found out that I can actually scroll down, at the very bottom, I noticed three additional subdirectories hidden there.

### Uncovering Hidden Subdirectories Under /Cryoserver

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*_Rd8E0_v2dSfEauI3YN_ag.png&width=768&dpr=3&quality=100&sign=504f9a3d&sv=2)

Temari, Kazekage, and iamGaara

I dug through all of them, and it’s just some wiki-style storyline crap. What’s interesting is that the storyline is the same across all the directories. There’s definitely something hidden here, I just needed to dig deeper. After carefully analyzing the storyline in iamGaara, I found this string:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*T72WBnAyYDKOeC9Tmpc7MA.png&width=768&dpr=3&quality=100&sign=5a6c7cb3&sv=2)

Some sort of encoding

### Decoding the Base58-Encoded String

I came across a string that seemed to be encoded, so I launched my own Decoder Tool, Kudo! Kudo uses a unique decoding scheme for base encodings. If you’re curious, you can check out my tool [here](https://github.com/Kuraiyume/Kudo). I went through all the base encodings and discovered that the string was encoded in base58.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*zsFHHSSRRFw8hWtfalO3VQ.png&width=768&dpr=3&quality=100&sign=4c9104e7&sv=2)

## Exploitation

### Brute-Forcing SSH Credentials with Hydra

The plaintext reveals **gaara:ismyname,** which is a clear indication that **gaara** is a user. Now that we have the username, we can brute-force our way in! Remember, when we scanned the target’s network, we saw that SSH was open, so we’ll use SSH to gain access to the system. Hydra will be our tool of choice for this attack.

`hydra -l gaara -P /usr/share/wordlists/rockyou.txt 192.168.43.140 ssh -t 64 -VVV`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*2XoADvNVP312HSmPBzc5ag.png&width=768&dpr=3&quality=100&sign=85d3667a&sv=2)

The password for user **gaara** is **iloveyou2**

### Logging in via SSH and Capturing the User Flag

Now that we have the login credential, it’s time for us to login through SSH as user **gaara.**

`ssh gaara@192.168.43.140`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*E2UGsFux0NPZpo-7bxvkFA.png&width=768&dpr=3&quality=100&sign=5484cd0e&sv=2)

User Flag!

We’re in!!! And got the user Flag!!

### Decoding the Base64-Encoded Kazekage Hint

As you noticed, there’s another file, the **Kazekage.txt.** I took a look at that file and this is the content:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*oioCVHR51AaHZ5fv5ass3A.png&width=768&dpr=3&quality=100&sign=5096fe5b&sv=2)

Probably a base64 encoded right? So I decode it using our target’s machine

`echo “base64-encoded-string” | base64 -d`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*MlX_a25hi4pgS2SL7RDRiA.png&width=768&dpr=3&quality=100&sign=def1573d&sv=2)

The plaintext points to **games** directory. I navigated to it and discovered a .txt file there. Here’s the content of the file:

### Decoding the Brainfuck-Encoded Message

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*sFrVgDF_AQokjl1iqjthzg.png&width=768&dpr=3&quality=100&sign=786c41b1&sv=2)

The file contains a BrainFuck encoded string, which we can easily decode using this [decoder](https://www.dcode.fr/brainfuck-language?__r=1.f95d2f0e7f432adeee396efdb886f6e5) here.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*puolwhW_EDHDqU1EZ6NTNQ.png&width=768&dpr=3&quality=100&sign=f2c61633&sv=2)

The result is: You think you could find something that easily? Try harder!

## Privilege Escalation

### Searching for SUID Binaries

I guess we need to dig deeper here, so I searches the entire filesystem for regular files with the setuid bit set, which allows them to execute with the owner’s privileges (often root).

`find / -type f -perm -04000 2>/dev/null`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*fwx7H0ZGZHbNXnvcitYDJg.png&width=768&dpr=3&quality=100&sign=da413505&sv=2)

### Abusing gdb via GTFOBins to Gain Root

As you can see here these are the directories that we can execute and **gdb** is included! We can use **gdb** to get root privilege so take a look at the gtfobins for gdb priv escalations, and this is the exploit: `gdb -nx -ex 'python import os; os.execl("/bin/sh", "sh", "-p")' -ex quit`

This technique utilizes a debugger to spawn a new shell with elevated privileges and then exits the debugger. It’s commonly used for privilege escalation by gaining access to a shell with root-level permissions.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*eHNL9OLtsalD78zZkFjFuQ.png&width=768&dpr=3&quality=100&sign=aff06a37&sv=2)

It works!!!! We have the root user!!

This is the Final Flag:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*QrDWm3cmL5RaBkAmZCIvHg.png&width=768&dpr=3&quality=100&sign=9a8a37a4&sv=2)

We’ve successfully completed Gaara!!

## Conclusion

Gaara is an easy machine to tackle, but it still requires players to analyze carefully. While it may seem straightforward, it challenges users to think critically and explore different techniques, such as encoding, file analysis, and privilege escalation. The machine reinforces the importance of attention to detail and persistence in uncovering hidden vulnerabilities, making it a great learning experience for those looking to sharpen their hacking skills.


Last updated 1 year ago
