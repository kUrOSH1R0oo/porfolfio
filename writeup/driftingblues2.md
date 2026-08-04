---
title: "DriftingBlues: 2"
date: 07-24-2024
excerpt: VulnHub
cover: ../uploads/cover_driftingblues2.jpg
tags: wordpress-bruteforce, theme-editor-rce, ssh-key-abuse, gtfobins-nmap, privilege-escalation
---

Welcome back to another write-up!In this post, I’ll be walking you through the step-by-step process of how I successfully rooted *DriftingBlues: 2* from VulnHub. This is the second machine in the DriftingBlues series, and it continues the challenge with a slightly higher difficulty level! Let's start!

## Reconnaissance

### Scanning with Nmap and Exploring Anonymous FTP Access

We'll use **Nmap** to identify open ports that could serve as potential entry points into the system.

```shell
nmap -A -sC -p- -T5 -oN nmap_result.log 192.168.96.47
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FWK2Jqso1aVGs3Ldm6DTX%252FScreenshot%2520%281496%29.png%3Falt%3Dmedia%26token%3Da265efa9-c677-4021-b0af-ca055c5bd250&width=768&dpr=3&quality=100&sign=61de2bc&sv=2)

ftp, shh, and http are open

As shown here, the FTP service permits anonymous login—let’s go ahead and access it.

```shell
lftp -u anonymous, 192.168.96.47
```

Upon login, this is what I've found

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FBvxa9fljAhBTG2xEnAVk%252FScreenshot%2520%281499%29.png%3Falt%3Dmedia%26token%3D55f49670-0a38-4dc5-b531-044a396452a6&width=768&dpr=3&quality=100&sign=e98cd220&sv=2)

Here's the image

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fe4UIAtsBY5bxVUkH8yPt%252FScreenshot%2520%281500%29.png%3Falt%3Dmedia%26token%3D8b60ea21-f57a-4878-85a9-296d83986abe&width=768&dpr=3&quality=100&sign=4b8b2839&sv=2)

I attempted to use `steghide` and `stegcrack` to check for any hidden data within the system, but it seems like there’s nothing concealed.

### Inspecting the Website

Let's visit the website

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FTw2WNjtdFkGSFlllVJHD%252FScreenshot%2520%281501%29.png%3Falt%3Dmedia%26token%3D73689413-eff7-41b5-8c45-1f2685ee2611&width=768&dpr=3&quality=100&sign=13c79d5&sv=2)

Nothing useful

## Enumeration

### Directory Enumeration and Discovering /blog

The next step I took was to launch **Gobuster** and perform a brute-force scan to discover hidden subdirectories.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FyN1KyLn5Z8O06epAzVZD%252FScreenshot%2520%281502%29.png%3Falt%3Dmedia%26token%3D2d0adf2b-6bb3-4206-8a99-3bf60f105185&width=768&dpr=3&quality=100&sign=fe5a7a4a&sv=2)

The blog subdirectory captured my attention so the next thing I did is to visit it and here's the result

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FTSsJPVbWtObKITyKBGKr%252FScreenshot%2520%281504%29.png%3Falt%3Dmedia%26token%3D0b38d414-6a1f-4778-99e1-10aa2481cba4&width=768&dpr=3&quality=100&sign=6fdd65a2&sv=2)

Just an HTML style

At the very bottom, I noticed this

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FA7rsztfRfqKqs5ULyHCk%252FScreenshot%2520%281505%29.png%3Falt%3Dmedia%26token%3De4a98623-ace0-4264-8890-ed0930b250d0&width=768&dpr=3&quality=100&sign=6ca70d47&sv=2)

### Identifying WordPress and Scanning with WPScan

The `/blog` subdirectory is clearly running on WordPress. The first thing I did was add it to the `/etc/hosts` file. After that, I proceeded to use **WPScan** to gather more information about the site.

```shell
wpscan --url http://driftingblues.box/blog/
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FSytx3FoiKbFhdvueWUeV%252FScreenshot%2520%281507%29.png%3Falt%3Dmedia%26token%3D63f323ae-edb5-40eb-a447-dd729e94ad0c&width=768&dpr=3&quality=100&sign=ea1e4552&sv=2)

Nothing's interesting even at the very bottom

I also checked the **uploads** directory, but didn’t find anything useful there.

### Discovering wp-login.php via Targeted Enumeration

The next step I took was to re-run directory enumeration, this time specifically targeting the `/blog` subdirectory.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FwCERcRAH3dtekG3KCaXQ%252FScreenshot%2520%281510%29.png%3Falt%3Dmedia%26token%3D449ab332-fb9d-44e5-b72f-b3509ba8faf7&width=768&dpr=3&quality=100&sign=f3a3cb5&sv=2)

There's a `wp-login.php` , let's take that a visit

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FSEbCRvHqUbS5KOCgfcrj%252FScreenshot%2520%281511%29.png%3Falt%3Dmedia%26token%3D4db3b1fa-5086-4203-b4c9-bf63f3533e73&width=768&dpr=3&quality=100&sign=89b8c7fb&sv=2)

## Exploitation

### Brute-Forcing WordPress Credentials with WPScan

Since there's a wp-login, we can brute-force this using **WPscan**, **WPscan** has a bruteforce feature for wordpress logins.

```shell
wpscan --url http://driftingblues.box/blog/ -P /usr/share/wordlists/rockyou.txt --detection-mode aggressive -e
```

After spending quite some time and enjoying some coffee on a rainy day, I finally managed to obtain the credentials.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FAgdYj0Pl9EQkot518TCR%252FScreenshot%2520%281512%29.png%3Falt%3Dmedia%26token%3D51b74628-d860-4222-af31-9f761ee313e8&width=768&dpr=3&quality=100&sign=8a972af3&sv=2)

Now let's login!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FhwRoHiSUiDGyhrBFnQzX%252FScreenshot%2520%281529%29.png%3Falt%3Dmedia%26token%3D8d6effb1-2f4c-4482-b8b0-1f6f222feea3&width=768&dpr=3&quality=100&sign=48b21b06&sv=2)

We’re in! So what’s next? To get a shell, we’ll need to modify some source code under **Appearance → Theme Editor**. You can pick any PHP file from the theme, but the most effective choice is usually `404.php`, since it’s easy to trigger by simply accessing a non-existent page.

### Achieving RCE via the WordPress Theme Editor

For the payload, I used [PentestMonkey’s](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) reverse shell, but you can also use my custom version, I’ve created my [own](https://github.com/kUrOSH1R0oo/reverse-shell-payloads/blob/main/payload.php) PHP reverse shell script that works just as well.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FctNBabjaJj792JG8kocx%252FScreenshot%2520%281514%29.png%3Falt%3Dmedia%26token%3Dc12fc591-40eb-4c06-941a-12ea10a7ccc1&width=768&dpr=3&quality=100&sign=bbc9d2e3&sv=2)

Before we trigger the 404, we need to establish a listener first

```shell
nc -lnvp 1234
```

Now let's browse a subdirectory that doesn't exist and we should trigger the payload.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F9FjJSUJME2FwtOYppFfJ%252FScreenshot%2520%281513%29.png%3Falt%3Dmedia%26token%3D70dd8043-cd48-4f02-a094-f7e99210212e&width=768&dpr=3&quality=100&sign=4057ac5c&sv=2)

We're in!!

By the way, you can also achieve this using Metasploit with the `wp_admin_shell_upload` module.

### Stabilizing the Shell

The first thing I did was upgrade to a stable shell by spawning a pseudo-terminal using Python’s `pty` module.

```shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Next, we’ll set the `TERM` environment variable to `xterm`, which tells the shell or terminal emulator to function as an xterm-compatible terminal for better display and interaction.

```shell
export TERM=xterm
```

## Privilege Escalation

### Discovering the freddie User and a Readable SSH Key

Upon exploring I've found a one user at `/home`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FjCXpfmKbVyWLZh5RroIa%252FScreenshot%2520%281517%29.png%3Falt%3Dmedia%26token%3Dc56d9da1-e5f9-409e-b074-c81476b17dd3&width=768&dpr=3&quality=100&sign=a450bcce&sv=2)

Here are the files contained in the `freddie` directory.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FGgdsN01PaPgzI5EbFiW5%252FScreenshot%2520%281518%29.png%3Falt%3Dmedia%26token%3D55039970-d674-4c44-8693-6805acc080e3&width=768&dpr=3&quality=100&sign=edfa1951&sv=2)

As shown, the `user.txt` file is present, but notice the permissions — only the user `freddie` has read access. So, to view the contents of `user.txt`, we first need to gain access as the `freddie`user.

The good news is that `freddie` has a `.ssh` directory. This means if we can access the `id_rsa` file, which is the private SSH key, we can use it to log in as `freddie` via SSH.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FcLynQLx1iqrlsdw1MicV%252FScreenshot%2520%281520%29.png%3Falt%3Dmedia%26token%3D6f311b4f-d6a1-4ee0-a298-dc9297ab2eb1&width=768&dpr=3&quality=100&sign=82ad1f94&sv=2)

### Logging in as freddie via SSH and Capturing the User Flag

There it is! Now we just need to copy the private key to our attacker machine, set its permissions to `600` using `chmod`, and use it to authenticate and log in as the user `freddie` via SSH.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FubuKrXFwzFBRG11qDlzr%252FScreenshot%2520%281522%29.png%3Falt%3Dmedia%26token%3D60f95442-5159-45eb-aaf6-4e5469058a9c&width=768&dpr=3&quality=100&sign=6cdffc41&sv=2)

We're now `freddie`!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FSTkWpXkVyR5Qdm66THeF%252FScreenshot%2520%281523%29.png%3Falt%3Dmedia%26token%3Dc7549536-6141-448c-958d-64af8c24a0c4&width=768&dpr=3&quality=100&sign=6a6fd12d&sv=2)

User Flag!

### Enumerating Sudo Privileges

Now it’s time to fully take control of the system — let’s go for root access! I started by running the `sudo -l` command to check which actions `freddie` is allowed to execute with elevated privileges.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FhkIPTL2dj4eor1YWtZy5%252FScreenshot%2520%281524%29.png%3Falt%3Dmedia%26token%3Df8c1d927-a3fa-4c87-bc92-a80ebe1a4572&width=768&dpr=3&quality=100&sign=cdd9eb53&sv=2)

### Exploiting Nmap via GTFOBins to Gain Root

It turns out that `freddie` can execute `nmap` with root privileges. So, I headed over to [**GTFOBins**](https://gtfobins.github.io/gtfobins/nmap/) to find a way to exploit this, and here’s what I discovered.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FsQnoRYV3LLm2HLfmmiIQ%252FScreenshot%2520%281525%29.png%3Falt%3Dmedia%26token%3Dbb6ebae2-a955-4091-859f-aa2e0ed755f3&width=768&dpr=3&quality=100&sign=1cb6ba45&sv=2)

This exploit takes advantage of Nmap’s native support for Lua through its Nmap Scripting Engine (NSE). By creating a temporary file containing the Lua command `os.execute("/bin/sh")` and running it with `nmap --script=$TF`, the user can execute system commands directly. Lua is used because Nmap is built to interpret Lua scripts for automation and advanced scanning tasks, making it ideal for this kind of abuse. If Nmap is run with `sudo`, the script runs with root privileges, and the spawned shell (`/bin/sh`) will also be a root shell. This leads to privilege escalation by exploiting a legitimate feature in a trusted binary to execute arbitrary commands as the superuser.

Now let's try the exploit and we will try to launch nmap with sudo to see the result

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F5GSANdyIPdWrWGcGxnju%252FScreenshot%2520%281526%29.png%3Falt%3Dmedia%26token%3D743b428e-705c-49f1-a551-22bcbfd9d9b6&width=768&dpr=3&quality=100&sign=de3df491&sv=2)

Yay!

It works!!! We are root!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FE8jJu1I5l2dTfjUoo7Gh%252FScreenshot%2520%281527%29.png%3Falt%3Dmedia%26token%3D2bd81c00-05cc-427c-8c6a-06da3bafcdd1&width=768&dpr=3&quality=100&sign=cc0fb759&sv=2)

The shell is not stable hehe, but here's the root flag!

We've successfully pwned DriftingBlues: 2!!

## Conclusion

This challenge shows a common path of gaining full control over a vulnerable system. It starts by identifying a login page and using a tool like WPScan to brute-force access. After logging in, we take advantage of file editing features to upload a reverse shell and connect back to our machine. Once a basic shell is established, we stabilize it for better control and explore the system for further opportunities. Finding a private SSH key allows us to switch users, and checking for `sudo` permissions reveals a way to escalate privileges using a trusted tool. By carefully chaining each step—initial access, user escalation, and privilege escalation—we successfully gained root access, showing how small misconfigurations can lead to complete system compromise.
