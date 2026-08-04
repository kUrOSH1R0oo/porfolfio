---
title: "Deathnote"
date: 04-21-2024
excerpt: VulnHub
cover: ../uploads/cover_deathnote.jpg
tags: WordPress
---

Welcome back to my writeup! Today, I’ll show you how I solved the **Deathnote** challenge from **Vulnhub**. It’s a simple Boot2Root, and I’ll walk you through each step, the tools I used, and the techniques that made it straightforward to complete. Let's start!!!

**Reconnaissance**

First, we’ll use **Nmap** to identify open ports that could serve as potential attack vectors.

```shell
nmap -A -T5 172.29.160.38
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FNID4PNPNWtmYSxk0P0tZ%252FScreenshot%2520%28674%29.png%3Falt%3Dmedia%26token%3D3b8b57ea-d9af-4539-b69b-0d2bb698f2be&width=768&dpr=3&quality=100&sign=2738e712&sv=2)

From the **Nmap** scan results, we can see that both port 22 (commonly used for **SSH**) and port 80 (used for **HTTP**) are open on the target machine. This tells us that the system is running services on these ports, which could potentially be leveraged for further enumeration and exploitation.

Let's visit the website.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fr9VGbIZBFz3sIdvaK1Hq%252FScreenshot%2520%28676%29.png%3Falt%3Dmedia%26token%3D8dc888c8-e30c-4f3c-b41b-49b20314d915&width=768&dpr=3&quality=100&sign=54ce110d&sv=2)

The reason it didn’t work is because the service relies on a specific domain name. If you look closely at the URL, you’ll notice it uses a domain instead of just an IP address. To access it properly, we need to add that domain to our `/etc/hosts` file so the system can resolve it correctly.

After adding the entry to our `/etc/hosts` file, we simply refresh the page, and we’re now able to access the site properly

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FNbmxnrrv1KR3P9Kijp18%252FScreenshot%2520%28678%29.png%3Falt%3Dmedia%26token%3D00f70a6e-ccfc-4990-a42b-b05ad2e738b8&width=768&dpr=3&quality=100&sign=7c9af8a1&sv=2)

Woah, Kira!!! Let's take a look at the **HINT**.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F51lq1FkfCfpMO6AuxAYK%252FScreenshot%2520%28682%29.png%3Falt%3Dmedia%26token%3De2012b6a-4e65-48bb-8adc-a5dfd0e924df&width=768&dpr=3&quality=100&sign=a100cb34&sv=2)

It mentions that there’s a file called *notes.txt* somewhere on the server—but where exactly? Let’s broaden our enumeration to find out.

While going through the site, I noticed that it’s actually running **WordPress**. With that in mind, using **WPScan** seems like a logical next step to gather more information and potentially uncover vulnerabilities.

```shell
wpscan --url 172.29.160.38
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252ForzPk5T2AWqPzwwEJP4X%252FScreenshot%2520%28685%29.png%3Falt%3Dmedia%26token%3D92f7a6ad-a9a8-4046-a692-2a5d2793f0df&width=768&dpr=3&quality=100&sign=49158f1c&sv=2)

I quickly noticed the *uploads* directory. In most WordPress assessments, this is one of the first locations you should inspect, since it often contains user-uploaded files that might reveal useful information or even lead to potential footholds.

Let's visit it.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fok6AP5RMjamP9d1yHWbU%252FScreenshot%2520%28687%29.png%3Falt%3Dmedia%26token%3D647f79da-3201-4c2b-a072-409547c6f1bc&width=768&dpr=3&quality=100&sign=a3159dc8&sv=2)

After digging around, I finally found the file mentioned in the earlier hint, located inside the `2021/07/` directory.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FEIRwWrpkHUDIJHXOVG7j%252FScreenshot%2520%28688%29.png%3Falt%3Dmedia%26token%3D4777a58f-8b36-460a-8b0e-ad14de9210b6&width=768&dpr=3&quality=100&sign=a7ae02f9&sv=2)

At the bottom, I found two text files, and one of them matched the hint we saw earlier. I simply used `wget` to download both files onto my machine.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fy9Stp90N9mm4ZLHv0su3%252FScreenshot%2520%28689%29.png%3Falt%3Dmedia%26token%3D717196d8-82fa-4b9f-8c85-04b7c7aa3c71&width=768&dpr=3&quality=100&sign=1ee77ff1&sv=2)

With both files in our hands, the next step is to inspect what’s inside them.

Here's the `notes.txt`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F4286CfNQw5E7XaoVTZo0%252FScreenshot%2520%28690%29.png%3Falt%3Dmedia%26token%3Da656a106-d433-4430-b572-e20c7056740c&width=768&dpr=3&quality=100&sign=f853a0a3&sv=2)

And here's the `user.txt`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FacALb1gvcvNMYP3kc6or%252FScreenshot%2520%28691%29.png%3Falt%3Dmedia%26token%3Dc3d235b0-90bc-493d-b0c1-aef5a24551d1&width=768&dpr=3&quality=100&sign=e0c518d4&sv=2)

This looks like a wordlist. If my assumption is right, it might contain the credentials for SSH. So, let’s use these two lists and try brute-forcing SSH with **Hydra**.

In this case, we’ll brute-force both the username and the password. This is manageable because `user.txt` contains only a handful of usernames, and `note.txt` provides just a few potential passwords or phrases.

```shell
hydra -L user.txt -P notes.txt 172.29.160.38 ssh -t 20
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FTce2gp0IuA1GzqUCocly%252FScreenshot%2520%28692%29.png%3Falt%3Dmedia%26token%3D3091ffee-df42-449d-9872-9f00d7055eba&width=768&dpr=3&quality=100&sign=a5e8b00f&sv=2)

After some time, we've successfully got the SSH credential for user `l` . Now let's login to SSH as user `l` .

```shell
ssh l@172.29.160.38
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FVBrPIj4Xl5jX8JxAOsBn%252FScreenshot%2520%28694%29.png%3Falt%3Dmedia%26token%3Daca3dfe5-673c-4cfb-9cfd-281c903c91fd&width=768&dpr=3&quality=100&sign=92a2d2bf&sv=2)

We’re in! Inside the user `l` account, there’s a `user.txt` file that contains a **Brainfuck** code.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FNQc5qD5gQBD7A6kRyVb8%252FScreenshot%2520%28695%29.png%3Falt%3Dmedia%26token%3Da1b7b7b6-0575-4e43-aa6a-48a5f31c06f8&width=768&dpr=3&quality=100&sign=6dcb05be&sv=2)

When I decode it using [Dcode](https://www.dcode.fr/brainfuck-language), this is the result:

`i think u got the shell, but you won't be able to kill me -kira`

It seems that `l` is not alone here, maybe there's another user named `kira` .

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FuhkaOejxlW4iSNzY7zEd%252FScreenshot%2520%28698%29.png%3Falt%3Dmedia%26token%3D944db038-ede0-424d-a34d-57b056d21c51&width=768&dpr=3&quality=100&sign=e3979fe7&sv=2)

There it is! `kira` is here! Now let's take a look!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FGbaCB4WILd4oit83ZC7w%252FScreenshot%2520%28699%29.png%3Falt%3Dmedia%26token%3D8933dafe-f3ca-48e9-947e-2739c772d8f0&width=768&dpr=3&quality=100&sign=4d0a220&sv=2)

As you can see, there’s a file called `kira.txt`. However, if you look closely at its permissions, it’s readable only by the user `kira`. Since we’re currently logged in as user *l*, we don’t have access to it. This means we’ll need to switch from user `l` to user `kira` in order to read the file. But the question is, how? Since we don't know the password of `kira` .

Looking more closely, you’ll notice an `.ssh` directory, and inside it there’s an `authorized_keys` file and we can read it!!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fmr07V1MR6JRBBt8XVhRO%252FScreenshot%2520%28703%29.png%3Falt%3Dmedia%26token%3D60755a7c-590e-4eb5-b0fe-0dde23d2458d&width=768&dpr=3&quality=100&sign=cbc02b06&sv=2)

Given this setup, you’ll notice that the `authorized_keys` file is owned by user `l`, which is our current account. Because of that, we can SSH into the `kira` account without needing a password.

But how? Let me explain how SSH authentication logic works.

When you connect to a Linux system using SSH, the authentication process relies on a **public–private key pair**. The flow is simple:

* The **public key** goes into the target user’s `~/.ssh/authorized_keys`
* The **private key** stays with the attacker/user who wants to authenticate

During login, SSH checks:

"Does the client’s private key match any of the public keys in this user’s `authorized_keys`?"

If **yes**, access is granted.
If **no**, authentication fails.

To switch to `kira`, we'll just use ssh

```shell
ssh kira@172.29.160.38
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fd6KbOAZjnAlUUjQMMVu1%252FScreenshot%2520%28700%29.png%3Falt%3Dmedia%26token%3D39ef56b2-db5e-4ec5-a6a1-4cef271ba03c&width=768&dpr=3&quality=100&sign=4b3debcf&sv=2)

We're now `kira` ! Now let's check the `kira.txt` .

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FWz6oVE5jUZMrFuAGpgIK%252FScreenshot%2520%28705%29.png%3Falt%3Dmedia%26token%3D4d2df9f8-5b1f-4ad7-926b-4a6400ecfd91&width=768&dpr=3&quality=100&sign=769ce4fb&sv=2)

It's a **Base64** encoded string, if we decode it, this is the result:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FbVdywyxmwoOrdlhvQA65%252FScreenshot%2520%28706%29.png%3Falt%3Dmedia%26token%3D1d5dd75f-a8b9-4062-bd24-a57f15498e18&width=768&dpr=3&quality=100&sign=4d7a905d&sv=2)

Looks like there's a folder hidden inside `/opt` and `/var` . Let's visit `L` in `/opt` first.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F6MM5NimAowOV9KULvrel%252FScreenshot%2520%28707%29.png%3Falt%3Dmedia%26token%3D6dc81202-499a-4df4-a35e-e790bb2f5d27&width=768&dpr=3&quality=100&sign=82159b41&sv=2)

Now, let's visit the `fake-notebook-rule` directory first.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FN46RWgrqDx3viAQZpUQ6%252FScreenshot%2520%28708%29.png%3Falt%3Dmedia%26token%3D383115c9-ad86-440d-914b-d79262d12957&width=768&dpr=3&quality=100&sign=61554e96&sv=2)

That `case.wav` looks like a wav file but when I attempt to listen to it, it's said that it's not in correct format and when I take a look at its content, it's a hex string!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FhQ90jF4HBQaNOFUyhe8v%252FScreenshot%2520%28711%29.png%3Falt%3Dmedia%26token%3D0d2b6c77-4f20-4e5c-99ab-ae60fd603248&width=768&dpr=3&quality=100&sign=6225277b&sv=2)

Decode it and this is the result:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FjB5N3hjIqytsKrKuHrvk%252FScreenshot%2520%28712%29.png%3Falt%3Dmedia%26token%3Db7c78cec-4945-4f86-befe-8ce0eee34b7f&width=768&dpr=3&quality=100&sign=c5c33547&sv=2)

It's a Base64 string, decode it and this is the result:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FosnFbnvCS4aOKHrerhu4%252FScreenshot%2520%28713%29.png%3Falt%3Dmedia%26token%3D8aa2e918-d337-44aa-87d8-df208e2ad55f&width=768&dpr=3&quality=100&sign=b97c6521&sv=2)

So it's a password! Let's try to use this to switch to **root**.

```shell
sudo su
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FOAjVpWxvECzDVS5eKu40%252FScreenshot%2520%28714%29.png%3Falt%3Dmedia%26token%3D9ed2bf4e-6335-4064-b6e1-8ecd8d708452&width=768&dpr=3&quality=100&sign=42f9b5e4&sv=2)

We're finally root!!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FtFKbfFp2MnJf0c8gRq5r%252FScreenshot%2520%28715%29.png%3Falt%3Dmedia%26token%3D06409134-78d7-4875-80d5-c8070365b524&width=768&dpr=3&quality=100&sign=655bf988&sv=2)

We've successfully solved Deathnote!!!
