---
title: Pwn The Tron
date: 2024-08-23
excerpt: VulnHub
cover: ../uploads/cover_pwnthetron.jpg
tags: CSRF, Directory Traversal, RCE
---

Hello, everyone! Welcome to my very first write-up. Today, I’m excited to share how I successfully tackled and completed the **Pwn the Tron** challenge from Vulnhub. This write-up is a detailed walkthrough of my approach, and I hope it provides you with valuable insights and enhances your understanding of the process. Let’s dive right in and get started!

## Reconnaissance

### Identifying the Target with Netdiscover

First, let’s take a look at the IP Address of our target using **netdiscover**:
`netdiscover -i eth0 -r 192.168.43.0/24`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*WfHXBKdvk5p3mbV2jeIHZQ.png&width=768&dpr=3&quality=100&sign=dad4636f&sv=2)

So the IP is 192.168.43.40

### Port Scanning with Nmap

Second, we’ll examine the open ports to identify potential entry points using **Nmap:** `nmap -A -sV -p- -T5 -v 192.168.43.40`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*nGe0B8l-oo6-FfgrEUOAOg.png&width=768&dpr=3&quality=100&sign=491abd&sv=2)

As you can see here, the open ports are 22 (ssh) and 80 (http)

## Enumeration

### Exploring the Web Interface

Let’s take a look at the interface of our target first

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*pUStAZ7OEr1PNZds03V6dw.png&width=768&dpr=3&quality=100&sign=396d6506&sv=2)

Kinda cool XD

### Directory Enumeration with Gobuster

It’s time to enumerate the directories of our target for more potential entry points using **Gobuster:** `gobuster dir -u http://192.168.43.40/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html,php,txt -t 64`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*LTuxwrzYQ-pmwckq_968_g.png&width=768&dpr=3&quality=100&sign=6ceaef8e&sv=2)

These are the directories, so many interesting dirs there.

As you can see, most of them are 301 It indicates that the requested resource has been permanently moved to a new URL, and the client should update its references to use the new URL for future requests.

The only directory that is useful here is the **Travel,** this is the content of Travel directory, something juicy:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*F7XNHtnZjgE2hobQngXHrw.png&width=768&dpr=3&quality=100&sign=f5601b01&sv=2)

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*7AwNw9FzyxRP771o9jhNAQ.png&width=768&dpr=3&quality=100&sign=6d9b4647&sv=2)

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*ff9KyLBuaanVq47w5h8Prw.png&width=768&dpr=3&quality=100&sign=1253e023&sv=2)

Based on the hints, it indicates that we need to find something **decepticon-base** in order to get the **iacon\_code**.

### Identifying decepticon-base as a Username

Initially, I began by scanning all of the directories on the target, hoping to find something useful or interesting. However, despite my efforts, I couldn’t locate a directory named **decepticon-base**. At first, I thought it might just be an unlisted or hidden directory that I overlooked during the scan.

Later on, I considered an alternative approach. I realized that **decepticon-base** might not be a directory at all but rather a **username** or **user account** associated with the system or application. It could potentially be the name of a user profile, a service account, or even an identifier used by the target system. Sometimes, resources or files are not named in a straightforward way, and it’s possible that what I was looking for was not a directory, but something that could be related to an account or user.

To investigate further, I decided to use **Sherlock**, a popular tool for finding usernames across multiple platforms. Sherlock is designed to search for a given username across numerous websites and social media platforms, which can help uncover accounts or profiles that are associated with that name.

`sherlock — verbose decepticon-base`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*30NqifAK7ohKStPISPSIdw.png&width=768&dpr=3&quality=100&sign=7c1c244c&sv=2)

I took a look at the **GitHub account**, and I came across one that seemed potentially relevant to the challenge. The account had some repositories, activities, and possibly a few clues that suggested it might be connected to the target or the task I was working on.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*B9kIUGjcSZLtKnlhmiXqvQ.png&width=768&dpr=3&quality=100&sign=c795d876&sv=2)

### Recovering the Deleted iacon_codes via the Wayback Machine

While going through the directories, I found a folder named **iacon\_codes** within the **Projects** directory. This caught my attention because **iacon\_codes** was the very name of the code we had been searching for. Unfortunately, when I attempted to open the folder, I encountered a **<< DELETED >>** message instead of the expected contents. Not giving up, I sought an alternative method to recover the missing file. I turned to the **Wayback Machine**, knowing it archives older versions of websites and files. According to the hint we received, the file’s structure followed the pattern: **/iacon\_code/(capital\_of\_country)/Latitude\_{}.{}-Longitude\_{}.{}.txt**. To move forward, I generated a wordlist with the capitals of all countries in an attempt to identify the correct one. However, the part about **Latitude\_{}.{}-Longitude\_{}.{}.txt** remained unsolved.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*_ZWkslbb63NeKf6gddXRMA.png&width=768&dpr=3&quality=100&sign=745b6218&sv=2)

This is the content of the iacon\_codes wayback 2021, this is probably the latitude and longitude as it’s separated by hyphen also.

Now, I have 2 wordlists, the **capitals.txt** and **codes.txt**

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*NNv60q9bTYtsWfNX39owVA.png&width=768&dpr=3&quality=100&sign=ee4ccdda&sv=2)

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*pyiwB_HNbEQMhuZ5Hatt3A.png&width=768&dpr=3&quality=100&sign=6bd2e830&sv=2)

### Building a Custom Two-Wordlist Password Cracker

Now that we have the wordlists, it’s time for us to make a custom password cracker, **John the Ripper** and **Hashcat** do not natively have a built-in feature that directly supports cracking a hash using **two wordlists** where the plaintext is a combination of a word from each list. That’s why we need to build our own:> Programming time!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*s-3oA0cFBrXO5tknWLtBfQ.png&width=768&dpr=3&quality=100&sign=b9ad113b&sv=2)

This is the script that I’ve made to crack the given hash (Read the comments for better understanding of the code).

When I run the code, the output is this:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*wD2coLANZjoQdZQZY__uvw.png&width=768&dpr=3&quality=100&sign=2d63b786&sv=2)

### Capturing the First Flag

I found a path that directed me to a **.txt** file, and upon inspecting it, I saw the following:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*ZmT9ikYUeGuSeCECsg8k0w.png&width=768&dpr=3&quality=100&sign=678c3e9a&sv=2)

We now have the 1st Flag!

### Exploring the W4RSHIP Shop

Now, let’s move on to the next step by visiting the provided link /W4RSHIP\_Sh0P.php. This will take you to a shop page.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*oYZ0hiamsIBN9aUMHmSLOQ.png&width=768&dpr=3&quality=100&sign=8724968b&sv=2)

I explored the whole shop for more entry points, the only interesting here is the ‘Secret Item’ which costs 9999 coins.

And at the bottom there was a **Contact Us** prompt that looks interesting

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*evxli2KRpu-fW_Mtx7WT-Q.png&width=768&dpr=3&quality=100&sign=a3a2b2ea&sv=2)

But when I try to buy an item, the site prompt me to login first and I was redirected to a login page.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*Aa7lrO82JScVAQr7dOaCkA.png&width=768&dpr=3&quality=100&sign=dcfeadce&sv=2)

Since, I didn’t have an account, I signed up and login. After login, I was redirected to the dashboard:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*rqMUOJWKmNbpFCmFyBTqlQ.png&width=768&dpr=3&quality=100&sign=e06d7bea&sv=2)

0 Balance:<<

### Bypassing the Coin Transfer Restriction via CSRF

When I tried to buy the item again, it displayed a message saying, **Not enough Coins.** So, I decided to explore alternative methods. On the dashboard, I came across an option labeled **Transfer Coins to a Friend in need?** but it continuously returned the message, **Request cannot be entertained.** While reviewing the **About** section, I discovered a useful hint: **Only admin can transfer coins.** I made sure to note the money transfer URL.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*7xSlNE4b1JQvP2wwqoUShA.png&width=768&dpr=3&quality=100&sign=9f1fd210&sv=2)

Request cannot be entertained.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*osML8CKwWuRz5-8FMniNSw.png&width=768&dpr=3&quality=100&sign=4c6331fe&sv=2)

Remember, we need **9999** balance to be able to buy the secret item but we don’t have any. I explored other potential methods for transferring money. Remember on the shop, there is a **Contact Us** form. I’ve checked the source code, as it contains some functional elements. I tried using the form to send money, but it didn’t work and simply returned a message saying, **Thanks for contacting us.**

I checked the source code again, and I found this usernames:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*irCI0AdasT7IVZ1I9TwhaQ.png&width=768&dpr=3&quality=100&sign=2aa88052&sv=2)

Maybe the admin’s username is admin_boss?

I attempted to enter all three usernames in the username field along with the amount of 9999, but it still returned the message, **Thank you for contacting us.** It was time to think outside the box. Remembering the hint that only the admin can send the money transfer request, I decided to retrieve the request URL from the transfer amount page. The URL looked like this: [`http://192.168.43.40/W4RSHIP_Sh0P_transfer.php?to=user&amount=9999&from=user`](http://192.168.43.40/W4RSHIP_Sh0P_transfer.php?to=user&amount=9999&from=user)

To initiate the transfer, submit the request through the **Contact Us** page, leveraging a **CSRF**-like technique. Instead of providing a typical message, use the message field to send the transfer request URL. Keep in mind that only the admin has the privileges to process money transfers, so in the username field, enter **admin\_boss** (the admin’s account), and in the message section, include the transfer URL. This method takes advantage of the fact that the admin can authorize the transfer, allowing us to bypass the restrictions and potentially complete the transaction.

The payload would be: [`http://192.168.43.40/W4RSHIP_Sh0P_transfer.php?to=kuraiyume&amount=9999&from=admin_boss`](http://192.168.43.40/W4RSHIP_Sh0P_transfer.php?to=kuraiyume&amount=9999&from=admin_boss)

When I try that payload, here’s what I’ve received:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*HMUiopS-CT8Tl80jQj5bHA.png&width=768&dpr=3&quality=100&sign=3f473a54&sv=2)

**You are almost there!,** this is a good sign that our payload is working! Remember we only tried the admin\_boss, but what if other usernames?

I’ve used the **lord\_starscream** as the second user that I will put in the **from=.**

Updated payload: `http://192.168.43.40/W4RSHIP_Sh0P_transfer.php?to=kuraiyume&amount=9999&from=lord_starscreamq`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*H5Zr7847id795-LqIsGeNQ.png&width=768&dpr=3&quality=100&sign=b7c1fe5c&sv=2)

And it works!!! (Also note that in Contact Us, I changed the username to admin\_boss, since the hint is only admin can transfer money)

### Buying the Secret Item and Capturing the Second Flag

Now I decide to buy the secret item, and it gave me a login credential

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*O0WYSb1focJUqr7lt7hxKg.png&width=768&dpr=3&quality=100&sign=c33dd769&sv=2)

I signed out from my account, and login using the provided credentials and it redirect me the **Lord** user dashboard

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*nH-45WPsrXl-HLp4S9J3Qg.png&width=768&dpr=3&quality=100&sign=60874d20&sv=2)

2nd Flag!

Now that we have the 2nd Flag, we need to dig deeper into the system to retrieve the remaining flags.

### Identifying the Vulnerable PHP Version

I checked the message PHP version of the of this dashboard using **Curl**: `curl -I http://192.168.43.40/M3G4TR0N_SUPR3M3/admin.php`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*rElA_cbKf0nHEQX28nIVnw.png&width=768&dpr=3&quality=100&sign=8687f831&sv=2)

I found out that the PHP Version is **PHP/8.1.0-dev** and that version is vulnerable to **RCE (Remote Code Execution)** where an attacker can execute arbitrary code by sending the User-Agentt header.

## Exploitation

### Building a Custom RCE Exploit

You can look for the exploit on the internet, but me who loves to do stuffs from scratch, I developed the exploit myself to gain reverse shell

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*pOJAL-VRb92mVKeNFGyCwg.png&width=768&dpr=3&quality=100&sign=791a2c7a&sv=2)

This is my own version of the exploit. All I need to do is to setup my listener using **Netcat:** `nc -lnvp 1234`

### Gaining a Reverse Shell

When I run the exploit, it gave me the shell!!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*IZY16HYrD8ftxvAZE9flwg.png&width=768&dpr=3&quality=100&sign=48895911&sv=2)

I navigate to **/home** directory and found 2 users, megatron and soudwave. On the user soundwave, the 3rd Flag is there. But…

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*QN_P-H1uzel_40zxWqEmsg.png&width=768&dpr=3&quality=100&sign=420056e1&sv=2)

Permission Denied:<

This is because we are not user **soundwave,** in order to see the content of the Flag3.txt, we need to be user **soundwave** first since the Flag3.txt is owned by **soundwave** only, the other users cannot access the Flag unless it’s root.

### Discovering the SSH Private Key

When I list all the directories using *ls -al*I saw something juicy, **.ssh** is there!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*SYW5ldKtbLKwU_Yh168CmA.png&width=768&dpr=3&quality=100&sign=e1d5f546&sv=2)

So I navigate to the **.ssh** directory and found a 2 keys! an RSA (Rivest-Shamir-Adleman) which is commonly used in SSH Keys, and gladly, we can see the contents of the private key!!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*f7KCXqV6Rq06mem7OzixAw.png&width=768&dpr=3&quality=100&sign=e783589b&sv=2)

We can copy this, and use this as an authenticator to access soundwave user using SSH. So I saved the private key to my machine, and change the permissions to 000 using **chmod:** `chmod 000 priv_key.pem`*.* This will avoid the 0644 permission error in SSH.

### Logging in as soundwave via SSH (Third Flag)

All setup! now, all we need to do is to log as user **soundwave** through SSH: `ssh -i priv_key.pem soundwave@192.168.43.40`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*J_6Qv--wsRSHgOedKHmThQ.png&width=768&dpr=3&quality=100&sign=927edf1f&sv=2)

3rd Flag!

Now we’re in! got the 3rd Flag!

## Privilege Escalation

### Enumerating Sudo Privileges

Now, it’s time for us to gain root access! I used *sudo -l* to list the commands and privileges soundwave can execute with sudo. Here’s the result:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*gDiFJsApXxQDMtSOKOC6zw.png&width=768&dpr=3&quality=100&sign=8f55e4e4&sv=2)

### Abusing Directory Traversal to Edit /etc/sudoers

It turns out that we can implement **Directory Traversal** here, maybe we can access the **sudoers** file and add the soundwave user to the sudoers.

The payload will be: `sudo vim /var/Decepticon/../../etc/sudoers`

And it works!!!!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*oJuUm9AExLn-WcmIhnbwJA.png&width=768&dpr=3&quality=100&sign=662fdbc6&sv=2)

Inside sudoers file, I added soundwave with a configuration of **ALL=(ALL) NOPASSWD:ALL,** it’s a directive that grants a user or group full administrative privileges without requiring them to enter a password when using sudo commands. In our case, we need the NOPASSWD since we’ve accessed soundwave using private key from SSH and not the password of soundwave. Without this setting, our operations requiring elevated privileges would be hindered by the inability to provide a password, making this adjustment essential for achieving our goal.

It’s all setup! All you need to do is to save it! (I hope you know how to exit vim xD)

### Escalating to Root and Capturing the Final Flag

The next or I must say the final step is to switch to root user using **sudo:** `sudo su`

It should probably switch to root without prompting us for the sudo password!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*eMbIHZy_ZjBpnB86igFyyw.png&width=768&dpr=3&quality=100&sign=42e8fe64&sv=2)

It works!!!!!!

And here’s the Final Flag!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*t06IEH9zTC5Sdg4dso1S-A.png&width=768&dpr=3&quality=100&sign=e5a98c33&sv=2)

4th Flag!

We’ve successfully completed PwntheTron!!

## Conclusion

This was a well-designed Boot2Root challenge that provided a solid learning experience and tested a variety of skills. For me, the difficulty felt medium, as it required a balance of enumeration, critical thinking, and exploitation techniques. It not only reinforced my understanding of directory traversal, privilege escalation, and SSH key management but also emphasized the importance of paying attention to subtle hints and thinking creatively to solve problems. Overall, it was both challenging and rewarding, making it an excellent exercise for sharpening practical hacking skills.
