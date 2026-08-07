---
title: "Mayhem"
date: 06-25-2025
excerpt: TryHackMe Writeup
cover: ../uploads/cover_mayhem.jpg
tags: Havoc C2, Network Forensics, PCAP Analysis
---

# Mayhem — TryHackMe Writeup

Welcome back to my writeup! Today I will show you the step-by-step on how I solved **Mayhem** from TryHackMe!

## Initial File Analysis

The challenge provides a `.pcap` file, which I examined using Wireshark for network traffic analysis.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FTftOPEPxS6fNuEsQMmvz%252FScreenshot%2520%28890%29.png%3Falt%3Dmedia%26token%3D3f6c701d-b9a4-4e4e-9b8d-8ab2e19d9146&width=768&dpr=3&quality=100&sign=56684453&sv=2)

Initially, the captured network data reveals HTTP traffic, which appears to come from a Python-based web server. Upon closer inspection, we can see that two files—`Install.ps1` and `notepad.exe`—are being transferred over port 1337.

## Identifying Suspicious Traffic on Port 80

As I dug deeper into the packet data, I came across this particular traffic.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F65ywDBw3QpJPbOI975uB%252FScreenshot%2520%28892%29.png%3Falt%3Dmedia%26token%3D07f863a8-c504-4388-87c1-ab45cc4374fd&width=768&dpr=3&quality=100&sign=270482c&sv=2)

Once the transfer of `notepad.exe` is complete, additional HTTP traffic emerges—this time strictly over port 80. A series of POST requests are made at consistent intervals, and the data within these requests seems to be encrypted.

Next, I proceeded to extract the HTTP objects for a more in-depth analysis.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FVifznR1HBFthxgkK0ICw%252FScreenshot%2520%28889%29.png%3Falt%3Dmedia%26token%3Da521e66b-f6bc-4dd8-ab9e-bfb6267a2a45&width=768&dpr=3&quality=100&sign=af720753&sv=2)

## Reverse Engineering notepad.exe

I began by reverse engineering `notepad.exe`, but it didn't reveal anything useful.

Given that this is an executable file, I had a strong suspicion it might be malicious. To verify, I generated its MD5 hash using `md5sum` and then submitted it to [VirusTotal](https://www.virustotal.com/gui/) for a malware scan.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FeoSr72KQfTfJqX4NJXPY%252FScreenshot%2520%28893%29.png%3Falt%3Dmedia%26token%3Ddd76d0f5-5baa-4bc1-ad5b-62a87d5310a1&width=768&dpr=3&quality=100&sign=247586e4&sv=2)

Just as I suspected, the file was flagged as malicious. Interestingly, it's linked to **Havoc**, a command-and-control (C2) framework. This suggests that the file might function as a beacon—essentially a small, stealthy agent designed to maintain communication with a Havoc C2 server. These beacons usually run silently in the background, regularly reaching out to the server to check for new commands or deliver updates, allowing an attacker to remotely manage the compromised system.

## Understanding the Havoc C2 Traffic Format

At this stage, I wasn't sure how to analyze traffic from a Havoc beacon. Fortunately, I came across some [documentation](https://www.immersivelabs.com/resources/blog/havoc-c2-framework-a-defensive-operators-guide) that provided the answers I was looking for.

The traffic is encrypted, with Havoc using AES in CTR mode for encryption. The key material, including both the AES key and IV, is also transmitted along with the traffic. Given that we're dealing with HTTP traffic, it's likely that we have access to this data.

Additionally, a specific "magic byte" is included to help identify the beacon traffic. While reviewing the Havoc C2 GitHub repository, I discovered the definition of the 0xDEADBEEF magic value in the `Defines.h` file, which confirmed its role in recognizing the traffic.

## Decrypting the Beacon Communication

The next step involves creating a program to decrypt the communication between the C2 server and the client in order to answer the task's questions. The Havoc C2 server exchanges keys during the process, and if we manage to capture them, we can use them to decrypt the traffic. Fortunately, I found an existing script on [GitHub](https://github.com/Immersive-Labs-Sec/HavocC2-Forensics/blob/main/PacketCapture/havoc-pcap-parser.py) that is specifically designed to decrypt traffic between a Havoc C2 server and an agent, which proved to be very useful for this task.

When we execute it, this is the result we get.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FGWhLQXel6svhNAL767G0%252FScreenshot%2520%28894%29.png%3Falt%3Dmedia%26token%3Dd764ff99-1a3d-4b13-aae6-f34204cab91b&width=768&dpr=3&quality=100&sign=af2299a0&sv=2)

We got the **Key** and **IV,** and also the magic bytes `deadbeef`.

By examining the request, you'll notice these commands.

```text
COMMAND_NOJOB
COMMAND_MEM_FILE
COMMAND_PROC
```

## Building a Custom Decryption Script

The next step I took was to create my own script, one that not only reveals the key but also decrypts the entire traffic.

```python
import pyshark
from Crypto.Cipher import AES
from Crypto.Util import Counter
from binascii import unhexlify, hexlify
import struct
from colorama import init, Fore, Style

# Initialize colorama for colored terminal output
init(autoreset=True)

# Configuration
PCAP_PATH = 'traffic.pcapng'  # Path to the PCAP file
AGENT_SESSIONS = {}  # Dictionary to store agent session information, such as AES key and IV

# Mapping of command IDs to human-readable command names
COMMAND_MAP = {
    1: 'GET_JOB', 10: 'NO_JOB', 11: 'SLEEP', 12: 'PROCESS_LIST',
    15: 'FILESYSTEM', 20: 'INLINE_EXECUTE', 21: 'START_JOB',
    22: 'INJECT_DLL', 24: 'INJECT_SHELLCODE', 26: 'SPAWN_DLL',
    27: 'PPID_SPOOF', 40: 'TOKEN', 99: 'INIT', 100: 'CHECKIN',
    2100: 'NETWORK', 2500: 'CONFIG', 2510: 'SCREENSHOT',
    2520: 'PIVOT', 2530: 'TRANSFER', 2540: 'SOCKET',
    2550: 'KERBEROS', 2560: 'MEMORY_FILE', 4112: 'SHELL_COMMAND',
    4113: 'PS_IMPORT', 8193: 'INLINE_ASSEMBLY',
    8195: 'LIST_ASSEMBLY_VERSIONS'
}

# Function to convert hex string to bytes
def hex_to_bytes(hex_str):
    return unhexlify(hex_str.replace(':', ''))

# Function to decrypt data using AES CTR mode
def decrypt_data(key, iv, encrypted):
    # Set up the counter for AES CTR mode based on the IV
    counter = Counter.new(128, initial_value=int.from_bytes(iv, 'big'))
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    return cipher.decrypt(encrypted)

# Function to parse the Havoc header and extract key information
def parse_havoc_header(data):
    if len(data) < 20:
        raise ValueError("Insufficient data for header")
    size, magic, agent_id, cmd_id, mem_id = struct.unpack(">I4s4sI4s", data[:20])
    return {
        'size': size,
        'magic': hexlify(magic).decode(),
        'agent': hexlify(agent_id).decode(),
        'cmd_id': cmd_id,
        'mem_id': hexlify(mem_id).decode(),
        'command': COMMAND_MAP.get(cmd_id, f"UNKNOWN_{cmd_id}")
    }

# Function to display session keys for a new agent
def display_session_keys(agent_id, key, iv):
    print(f"{Fore.GREEN}[+] New Session Key Stored")
    print(f"    Agent ID : {agent_id}")
    print(f"    AES Key  : {hexlify(key).decode()}")
    print(f"    AES IV   : {hexlify(iv).decode()}")

# Function to process the response for a GET_JOB command
def process_job_response(response, agent_id):
    try:
        # Convert the file data to bytes
        raw_data = hex_to_bytes(response.get('file_data', ''))
        command_id = struct.unpack('<H', raw_data[:2])[0]
        decrypted = decrypt_data(
            AGENT_SESSIONS[agent_id]['key'],
            AGENT_SESSIONS[agent_id]['iv'],
            raw_data[12:]  # Skip the header portion of the raw data
        )
        output = decrypted.decode('utf-16le', errors='ignore')  # Decode the decrypted output
        print(f"{Fore.CYAN}[=] Server Response to GET_JOB")
        print(f"    Command : {COMMAND_MAP.get(command_id, f'UNKNOWN_{command_id}')}")
        print(f"    Output  : {output.strip()}")
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to process GET_JOB response for Agent {agent_id}: {e}")

# Function to analyze each HTTP stream
def analyze_stream(stream_data, stream_id):
    try:
        request = stream_data['request']
        response = stream_data['response']
        raw_packet = hex_to_bytes(request.get('file_data', ''))
        header = parse_havoc_header(raw_packet)

        # Print the stream and packet information
        print(f"{Fore.YELLOW}{'-'*60}")
        print(f"{Fore.MAGENTA}[STREAM ID: {stream_id}] Analyzing HTTP Stream")
        print(f"{Fore.BLUE}[+] Request Info")
        print(f"    URL    : {request['uri']}")
        print(f"    Method : {request['method']}")
        print(f"{Fore.BLUE}[+] Havoc Packet Info")
        print(f"    Agent ID : {header['agent']}")
        print(f"    Command  : {header['command']} (ID: {header['cmd_id']})")
        print(f"    Magic    : {header['magic']}")
        print(f"    Mem ID   : {header['mem_id']}")

        agent_id = header['agent']
        payload = raw_packet[20:]

        # Handle the INIT command and store the session key and IV
        if header['command'] == 'INIT':
            key = raw_packet[20:52]
            iv = raw_packet[52:68]
            AGENT_SESSIONS[agent_id] = {'key': key, 'iv': iv}
            display_session_keys(agent_id, key, iv)

        # Process GET_JOB command responses
        if header['command'] == 'GET_JOB' and agent_id in AGENT_SESSIONS:
            process_job_response(response, agent_id)

        # Decrypt and display ASCII payload for other commands
        if agent_id in AGENT_SESSIONS and payload:
            try:
                decrypted = decrypt_data(
                    AGENT_SESSIONS[agent_id]['key'],
                    AGENT_SESSIONS[agent_id]['iv'],
                    payload
                )
                ascii_output = decrypted[16:-16].decode('ascii', errors='ignore')
                print(f"{Fore.CYAN}[=] Decrypted ASCII Payload")
                print(ascii_output)
            except Exception as e:
                print(f"{Fore.RED}[!] Failed to decrypt ASCII payload: {e}")

    except Exception as e:
        pass

# Function to process the PCAP file and analyze HTTP traffic
def process_pcap_file():
    print(f"{Fore.CYAN}[~] Starting PCAP Analysis: {PCAP_PATH}")
    try:
        streams = {}
        capture = pyshark.FileCapture(PCAP_PATH, display_filter='http')
        for packet in capture:
            try:
                stream_id = packet.tcp.stream
                if stream_id not in streams:
                    streams[stream_id] = {'request': None, 'response': None}

                # Extract HTTP request and response data from packets
                if hasattr(packet.http, 'request_method'):
                    streams[stream_id]['request'] = {
                        'method': packet.http.request_method,
                        'uri': packet.http.request_full_uri,
                        'file_data': getattr(packet.http, 'file_data', None)
                    }

                elif hasattr(packet.http, 'response_code'):
                    streams[stream_id]['response'] = {
                        'code': packet.http.response_code,
                        'file_data': getattr(packet.http, 'file_data', None)
                    }

                # Analyze the stream if both request and response are captured
                if streams[stream_id]['request'] and streams[stream_id]['response']:
                    analyze_stream(streams[stream_id], stream_id)
                    streams[stream_id] = {'request': None, 'response': None}
            except Exception as e:
                print(f"{Fore.RED}[!] Packet processing error: {e}")
        capture.close()
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to parse PCAP file: {e}")

# Main execution
if __name__ == '__main__':
    process_pcap_file()
```

Run and we should obtain the complete decrypted traffic.

## Answering the Challenge Questions

Now, let's answer the questions based on the output generated by the script I created.

### Question 1: SID of the User the Attacker Executes Under

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FWbjTDpk5Lf8Y8QBCfpvR%252FScreenshot%2520%28895%29.png%3Falt%3Dmedia%26token%3D618eca60-bead-472f-b6bd-9e4864108819&width=768&dpr=3&quality=100&sign=1f1710ac&sv=2)

### Question 2: Link-Local IPv6 Address of the Server

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fv2EsR6vx9vyF5xxZJtwl%252FScreenshot%2520%28896%29.png%3Falt%3Dmedia%26token%3D4301941f-d4bb-421f-b762-9c0fb7545714&width=768&dpr=3&quality=100&sign=8ff69fd0&sv=2)

### Question 3: The Flag Printed by the Attacker

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FpXxwjXnqlugxA5x8X7jU%252FScreenshot%2520%28898%29.png%3Falt%3Dmedia%26token%3D38d255b4-6f72-42ac-bc05-23bbc4dd24ab&width=768&dpr=3&quality=100&sign=6c25ad1a&sv=2)

### Question 4: Persistence Account Username and Password

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FPrkuapYrnHTk3zE6RvhO%252FScreenshot%2520%28901%29.png%3Falt%3Dmedia%26token%3D1c9f8d5a-7696-4aa8-a55d-ec1167c74c13&width=768&dpr=3&quality=100&sign=d3ea00a8&sv=2)

### Question 5: Full Path of the Important File Found

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FraseHOmv5haekmDhBD22%252FScreenshot%2520%28902%29.png%3Falt%3Dmedia%26token%3D8cad09c6-0619-4d66-a9dd-b75ed1b08586&width=768&dpr=3&quality=100&sign=3d7159c8&sv=2)

### Question 6: Flag Found Inside the File from Question 5

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FkYkCTkLtubjkql2Vl08G%252FScreenshot%2520%28903%29.png%3Falt%3Dmedia%26token%3De8212648-51c3-4ae0-90c1-e8a7f6830505&width=768&dpr=3&quality=100&sign=d47607f2&sv=2)

## Conclusion

We've successfully solved the **Mayhem!**
