---
title: "EvilBox: 1"
date: 05-04-2024
excerpt: VulnHub
cover: ../uploads/cover_evilbox.jpg
tags: local-file-inclusion, ssh-key-cracking, writable-etc-passwd, privilege-escalation
---

Welcome to my third Capture-the-Flag (CTF) writeup! Today, we’ll dive into **Evilbox: 1**, a vulnerable machine available on VulnHub. Based on my experience, this machine is relatively straightforward to tackle, making it a great choice for honing your skills. In this writeup, I’ll guide you through the steps I took to complete the challenge and achieve root privileges. Along the way, I’ll break down the process, share useful tips, and explain my thought process. Let’s get started and uncover the secrets of Evilbox: 1!

## Reconnaissance

First, we need to determine what is the IP of our target using **netdiscover**: `netdiscover -i eth0 -r 192.168.248.0/24`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*RTMsFdRrrn0Eb0hhrKXfeQ.png&width=768&dpr=3&quality=100&sign=e60540ce&sv=2)

Here, the IP Address of our target is **192.168.248.218**

The next step is to perform a network scan on our target using **Nmap** to identify open ports and potential entry points for exploitation: `nmap -A -sV -p- -T5 -oN result.log -v 192.168.248.218`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*4Dbg-rcSSgQ6kPIXzT86Bw.png&width=768&dpr=3&quality=100&sign=db6489da&sv=2)

This is the result of the scan, as you can see here, port 22 (SSH) is open and also port 80 (http)

## Enumeration

### Inspecting the Default Apache Page

Now that we have our potential entry point, we need to find a way to exploit it. First I’ve checked the HTTP of the machine and this is the result:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*2qd06iWgVErnpnn1IjhnnQ.png&width=768&dpr=3&quality=100&sign=cf51fadc&sv=2)

Just a default page of apache2 for debian, I’ve checked the source code, but nothing useful found

### Directory Enumeration with Gobuster

Since our initial investigation didn’t uncover any valuable information, the next step is to dig deeper by brute-forcing the subdirectories of the target. To accomplish this, we’ll use **Gobuster**, a powerful tool designed for directory and file enumeration. By running Gobuster, we can uncover hidden directories or files that may provide us with a foothold or additional clues to progress further in our attack: `gobuster dir -u http://192.168.248.218/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html,php,txt -t 64`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*yAwDWy-v0zGJWAtdDbNjUA.png&width=768&dpr=3&quality=100&sign=4761754d&sv=2)

As you can see here, there’s a **secret** directory that has 301 status

I visit the **/secret** directory and it has nothing just a blank directory.

### Discovering evil.php and Fuzzing for Parameters

Since the directory appears to be blank, it’s likely that there’s a hidden endpoint within it, possibly a PHP file or some other resource. To uncover this, I decided to use **Gobuster** again, this time focusing on the **/secret** path. By scanning the URL with this specific subdirectory, I aimed to reveal any concealed files or endpoints that could provide further insights or a way forward: `gobuster dir -u http://192.168.248.218/secret/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html,php,txt -t 64`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*tPvrN5P4ph-2geznB-NFAg.png&width=768&dpr=3&quality=100&sign=49ce18c7&sv=2)

And yes, there’s a PHP file hidden within it, that’s the **evil.php**

I navigated to the **evil.php** file, suspecting it might contain a hidden parameter to interact with. To confirm this, I turned to **FFUF**, a versatile fuzzing tool, to systematically test for potential parameters within the evil.php file. By fuzzing the file, I aimed to uncover any hidden query strings or inputs that could unlock further functionality or vulnerabilities. This step is crucial in identifying potential attack vectors and gaining a deeper understanding of how the file operates: `ffuf -u ‘http://192.168.248.218/secret/evil.php?FUZZ=/etc/passwd’ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -fs 0 -t 100`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*U2cV1Rvco9RBn4_UtvzIfg.png&width=768&dpr=3&quality=100&sign=9bb469f0&sv=2)

The parameter that we’re looking for is **command**!!!

### Confirming Local File Inclusion (LFI)

I tested the parameter by attempting to include the **/etc/passwd** file, as this is a common technique for detecting a **Local File Inclusion (LFI)** vulnerability. LFI occurs when a web application improperly handles user input that points to local files on the server, allowing attackers to include and read sensitive files from the server's filesystem. By targeting /etc/passwd, which contains system user information, I aimed to verify whether the application was vulnerable to LFI, potentially granting access to other critical files or enabling further exploitation.

## Exploitation

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*dyOKvIP-6pu5isGzh7aoSw.png&width=768&dpr=3&quality=100&sign=4308ece5&sv=2)

As you can see here, it works! We can access the local files of the machine through browser.

### Reading the SSH Private Key via LFI

Now that we have access to files, I began searching for any critical files that could serve as an entry point into the system. I spent a considerable amount of time exploring, and during this process, I recalled that SSH is open on this machine. This made me think there might be a private SSH key associated with a specific user, such as **mowree**, which I had seen listed in the **/**etc/passwd file. And when I check it, it’s accessible!!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*jomliXa319qrTvldesmUvA.png&width=768&dpr=3&quality=100&sign=1b74fedf&sv=2)

This is the private key of the user **mowree,** which we can use to gain remote access to the machine as user mowree without knowing mowree’s password.

### Cracking the Passphrase-Protected Key with ssh2john and John

I copied the private SSH key to my attacker machine and use it, but as always the key is passphrase-protected. In order for us to brute-force this, I used **ssh2john** to convert the SSH key to a hash that John can crack: `ssh2john priv_key.pem > hash`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*2mlcRgG837FK5LoXKcaohw.png&width=768&dpr=3&quality=100&sign=90593b88&sv=2)

Now that we have the hash we can crack it using **John:** `john hash`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*84oAH6RHs8UnisNjxkqo5g.png&width=768&dpr=3&quality=100&sign=215ae729&sv=2)

As you can see here, the passphrase of the private key is **unicorn**

### Logging in via SSH and Capturing the User Flag

Now, we can use the private key with that password to get in to the system as user **mowree:** `ssh -i priv_key.pem mowree@192.168.248.218`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*O-5BijvyEPqhxgKRGQEMtQ.png&width=768&dpr=3&quality=100&sign=d7768fd4&sv=2)

Here, said **UNPROTECTED PRIVATE KEY FILE,** it means that the private key is accessible to any user.

To avoid encountering a permission error when using an SSH private key, it’s important to ensure that the key file has the correct file permissions. By default, SSH requires that the private key file is kept secure, meaning it should be readable only by the owner to prevent unauthorized access. If the file permissions are too open (e.g., readable by others), SSH will refuse to use the key and display a permission error. To fix this, you can change the file permissions of the private key **priv\_key.pem** to **000** using the **chmod** command. Setting the permissions to 000 ensures that no other users on the system can read, write, or execute the file, making it completely restricted. Here's the command to apply this: `chmod 000 priv_key.pem`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*GKq2fpDn1SX80fIeHuMUlg.png&width=768&dpr=3&quality=100&sign=2aa52cb5&sv=2)

Now let’s try

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*1Lhq_AR8_7ULbXoXId8NNw.png&width=768&dpr=3&quality=100&sign=6721f172&sv=2)

It works!!! We’re in!! And we’ve got the user flag!!!

## Privilege Escalation

### Discovering a Writable /etc/passwd

Now, all we need is to gain the root user. The one thing that comes in my mind is that the /etc/passwd might be writable, meaning we can modify the content of the file. So I checked it by listing the **/etc/passwd** with its permissions: `ls -al /etc/passwd`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*0ZSGBqET4GrzwIyh-Nlh4Q.png&width=768&dpr=3&quality=100&sign=a8359bc8&sv=2)

And look, it’s writable to any user!!!

### Creating a Root User via openssl passwd

Now that I know I had write access to the **/etc/passwd** file, I saw an opportunity to create a new user account with root privileges. The /etc/passwd file is crucial on Linux-based systems because it stores information about user accounts, including their usernames, user IDs (UIDs), and group IDs (GIDs). By modifying this file, I could add a new user entry and assign them a UID of 0, which is the UID for the root user. This would essentially give the new account root privileges. To implement this I need to generate a UNIX hash first using **openssl:** `openssl passwd -1 kuroshiro`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*gd5CVMLQpjU9lRELeoKsYQ.png&width=768&dpr=3&quality=100&sign=6b77a23a&sv=2)

This will enable me to create a hashed version of **kuroshiro** that I can use when adding the new user entry to the file.

To add the new hash to the /etc/passwd, we need to format it with the entry that we will use like this: `echo “<username>:<hash>:0:0:root:/root:/bin/bash” >> /etc/passwd`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*1ubt59bzva82p1eQFKdoTg.png&width=768&dpr=3&quality=100&sign=c8c9c317&sv=2)

### Escalating to Root

After that, we can switch to the specified username and enter the password that we’ve hashed using openssl, and it should give us the root user: `su <username>`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*nkfpkvaNtnwWEOI7zN1Tzw.png&width=768&dpr=3&quality=100&sign=30ea2a7d&sv=2)

Now we have the root!!!!! And got the root Flag!!

We’ve successfully finished EvilBox: 1!!!!

## Conclusion

This machine is relatively simple, featuring a number of common vulnerabilities often encountered in Linux systems. Throughout the process, I was able to leverage various techniques such as file inclusion, and manipulating the /etc/passwd file to gain root access. These vulnerabilities are typical of many misconfigured or insecure systems, and this exercise provided valuable insight into common exploitation methods. By understanding these vulnerabilities and the steps to exploit them, we can better secure systems by addressing these flaws proactively.
