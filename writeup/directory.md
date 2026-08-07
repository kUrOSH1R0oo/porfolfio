---
title: "Directory"
date: 04-04-2025
excerpt: TryHackMe Writeup
cover: ../uploads/cover_directory.jpg
tags: Network Forensics, Kerberos Authentication, PCAP Analysis
---

Hey everyone, welcome back to another writeup! In this post, I'll walk you through the step-by-step process I used to solve **TryHackMe's latest room,** ***Directory***. This challenge dives deep into the realm of **forensics and analysis**, testing your investigative mindset and attention to detail. Whether you're sharpening your cyber skills or just curious about how digital clues are uncovered, this walkthrough will break it down clearly and practically. Let's get started and dissect the techniques used to crack this room open!

There are six questions to solve in this challenge, and the key to answering them lies in examining and working with the file that's been given.

## Initial Analysis

We're provided with a `.pcap` file, so naturally, the first step is to open it in Wireshark and begin analyzing the captured network traffic.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FjUZl04g5MJY0lEVNESXL%252FScreenshot%2520%281964%29.png%3Falt%3Dmedia%26token%3D40d915e8-6053-4378-af45-87bf15cc42cb&width=768&dpr=3&quality=100&sign=f884b36&sv=2)

Observing the network traffic, we can see a series of SYN requests being sent out, followed by **RST-ACK** responses from the IP address `10.0.2.74`. This kind of behavior is a classic indicator of a port scan, where the attacker probes different ports to identify which ones are open or closed based on the type of response received.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FREWJWYJO7PASN7vQtbSO%252FScreenshot%2520%281965%29.png%3Falt%3Dmedia%26token%3Db4dcce71-0fe8-45b7-83f2-d2ab222226b0&width=768&dpr=3&quality=100&sign=fc055565&sv=2)

The initial **3,610** packets in the capture are primarily associated with the port scanning activity, as indicated by the repeated SYN and RST-ACK patterns. After this sequence, we begin to observe HTTP traffic within the capture. This shift suggests that once the scanning phase was completed, the attacker may have identified an open service and proceeded to interact with it through a web-based protocol, potentially exploring or exploiting the discovered endpoint.

## Question 1: What ports did the threat actor initially find open?

*Format: from lowest to highest, separated by a comma.*

To answer the following questions, we can use **tshark**, but we opted to use **PyShark**, a Python wrapper for the popular network analysis tool Wireshark. Unlike TShark, which is CLI-based, PyShark allows us to process and analyze packet captures programmatically using Python—making it ideal for custom filtering, automation, and scripting workflows.

The current task involves identifying the **open ports** discovered by the attacker during their scanning phase. In TCP communication, an **open port** is typically indicated by a **SYN-ACK** response following a SYN request—this handshake response tells us the port is accepting connections.

From our earlier analysis using Wireshark, we observed that the **first 3,610 packets** in the capture are part of the port scanning activity. So, we limit our analysis in PyShark to just those initial packets to stay focused on the scan phase.

In our PyShark script, instead of using TShark's `-c 3610` option to read only the first 3,610 packets, we implement similar logic by manually counting packets and breaking the loop once the limit is reached. We then check for TCP layers and extract packets where **both the SYN and ACK flags are set**, which are strong indicators of open ports being probed. For each of these matching packets, we extract the TCP source port, eliminate duplicates, sort them numerically, and finally print them as a comma-separated list.

```python
import pyshark

def get_syn_ack_srcports(pcap):
    cap = pyshark.FileCapture(pcap, use_json=True)

    ports = set()
    packet_count = 0

    for pkt in cap:
        if 'TCP' in pkt:
            try:
                # Get TCP flags as a hexadecimal string and convert to integer
                flags = int(pkt.tcp.flags, 16)

                # Check if both SYN (0x02) and ACK (0x10) flags are set (SYN+ACK = 0x12)
                if flags & 0x12 == 0x12:
                    # Add the source port to the set (removes duplicates automatically)
                    ports.add(int(pkt.tcp.srcport))
            except:
                continue  # Skip any malformed or incomplete packets

        packet_count += 1
        if packet_count >= 3610:  # Stop after analyzing 3610 packets
            break

    cap.close()  # Always close the capture to release resources

    # Sort the unique ports and print them as a comma-separated string
    print(','.join(map(str, sorted(ports))))

get_syn_ack_srcports('traffic.pcap')
```

Here's the result

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FehClQJ77QO5yAxAWwPhx%252FScreenshot%2520%281966%29.png%3Falt%3Dmedia%26token%3D592f56d5-3998-444f-82e2-a1b035b74cfd&width=768&dpr=3&quality=100&sign=6e432fd5&sv=2)

## Question 2: What was the username that gave the attacker a foothold?

*The threat actor found four valid usernames, but only one username allowed the attacker to achieve a foothold on the server. What was the username?*

After analyzing the initial Nmap scan traffic, we move past it and scroll further down through the packet capture in Wireshark. Upon reaching **packet number 4667**, we begin to observe **Kerberos (KRB5)** traffic. This marks the start of a new phase in the attack, likely involving authentication attempts.

Kerberos traffic is particularly important in post-reconnaissance stages, as it can expose usernames through specific ticket exchange attempts. These usernames can provide valuable insight into which accounts the attacker is targeting—or even successfully using—to gain a foothold in the system.

Continuing down to **packet 4679**, we notice a **KRB5KDC_PREAUTH_REQUIRED** error. This indicates that a valid username was submitted, but pre-authentication is required before a TGT (Ticket Granting Ticket) can be issued. This kind of response often confirms that the username exists, making it a potential entry point for the attacker.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fe9rlMfBqYBLBdxljUezy%252FScreenshot%2520%281968%29.png%3Falt%3Dmedia%26token%3Db0b818cc-9173-4527-9df8-a1ec742e2c0a&width=768&dpr=3&quality=100&sign=6e524502&sv=2)

At **packet number 4817**, we observe an **AS-REQ (Authentication Service Request)** without any accompanying error message. This suggests that the submitted username is likely valid, and we can potentially extract it directly from this packet.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FRCMuLhaTtuHrw3OcV22E%252FScreenshot%2520%281969%29.png%3Falt%3Dmedia%26token%3Dcdc736ff-4a85-4188-bf5c-a4eac5c0bb07&width=768&dpr=3&quality=100&sign=a78d747&sv=2)

we will focus on identifying packets that include the **Kerberos client principal name** (`kerberos.CNameString`) and its corresponding **realm** (`kerberos.crealm`). These fields typically appear during Kerberos authentication attempts and can reveal usernames being used by the attacker. By scanning through the packets and extracting these specific values, we can compile a list of login attempts.

```python
import pyshark

pcap_file = "traffic.pcap"

# Create a FileCapture object with the Kerberos display filter
capture = pyshark.FileCapture(pcap_file, display_filter="kerberos")

# Iterate through packets
for packet in capture:
    try:
        # Check if both fields are present
        if hasattr(packet.kerberos, 'CNameString') and hasattr(packet.kerberos, 'crealm'):
            cname = packet.kerberos.CNameString
            crealm = packet.kerberos.crealm
            # Print in the format crealm\CNameString
            print(f"{crealm}\\{cname}")
    except AttributeError:
        # Skip packets that don't have the required fields
        continue

# Close the capture to free resources
capture.close()
```

Here's the output

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FhLkg9KzQjVYlr3T0hmiD%252FScreenshot%2520%281970%29.png%3Falt%3Dmedia%26token%3D2dd4a4f1-daca-4304-9539-59531c322d15&width=768&dpr=3&quality=100&sign=f5a8bb41&sv=2)

## Question 3: What are the last 30 characters of the captured hash?

*The threat actor captured a hash from the user in question 2. What are the last 30 characters of that hash?*

What we're trying to identify is an **encrypted data blob** used in the Kerberos authentication process—**not a simple hash**. Specifically, the **AS-REP (Authentication Service Reply)** contains this encrypted information. While it may appear similar to a hash, it's actually an **encrypted message**, typically secured using algorithms like **AES**, **RC4**, or in some cases, **public-key cryptography** through **PKINIT**.

The data we're looking for is found in the packets that carry the `kerberos.cipher` field. By filtering for these specific packets, we can isolate and extract the final **30 characters** of the cipher value.

```python
import pyshark

def extract_cipher(pcap='traffic.pcap'):
    cap = pyshark.FileCapture(pcap, display_filter='kerberos and kerberos.CNameString == "larry.doe"', use_json=True, include_raw=True, keep_packets=False)
    ciphers = []

    # Extract cipher from AS-REP packets
    for pkt in cap:
        try:
            if as_rep := getattr(pkt.kerberos, 'as_rep_element', None):
                if enc := getattr(as_rep, 'enc_part_element', None):
                    if cip := getattr(enc, 'cipher', None):
                        ciphers.append(cip.replace(':', '').replace(' ', '').lower())
        except (KeyError, AttributeError):
            continue

    cap.close()
    return ciphers[-1] if ciphers else print("No kerberos.cipher found.")

if result := extract_cipher():
    print("Extracted:", result)
```

Here's the output

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FoX1yOAQXvkIHSWa0eg0H%252FScreenshot%2520%281973%29.png%3Falt%3Dmedia%26token%3Dfc028211-13a9-4a9f-928c-5f7384bbcb17&width=768&dpr=3&quality=100&sign=b59a8f10&sv=2)

## Question 4: What is the user's password?

I'm familiar with a John the Ripper utility called `krb2john`, which is specifically designed to extract Kerberos hashes from network captures. I've used this tool before to convert Kerberos authentication data into a format that John the Ripper can crack.

To use `krb2john`, we first need to convert our `.pcap` (packet capture) file into a `.pdml` (Packet Details Markup Language) file. This is typically done using **Wireshark** or **Tshark**, which can output `.pdml` — an XML-based format containing all packet details.

Once we have the `.pdml` file, we can feed it into `krb2john`. The tool will parse the PDML file, locate the Kerberos AS-REP or TGS-REP responses (which contain encrypted data), and generate hash lines that are compatible with John the Ripper for cracking.

Now let's turn or `pcap` file to `pdml`

```shell
tshark -r traffic.pcap -T pdml > traffic.pdml
```

Now let's use `krb2john`

```shell
krb2john traffic.pdml
```

Here's the result

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FdvCd2FC89NhiefGcLUfF%252FScreenshot%2520%281975%29.png%3Falt%3Dmedia%26token%3D75cebdc7-19a9-4849-bc81-262f3c2daa14&width=768&dpr=3&quality=100&sign=d97ecd14&sv=2)

We got the hash, now let's crack it using **John**.

```shell
john --wordlist=/usr/share/wordlists/rockyou.txt hash 
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FkZ5W5dOUisltE7uSEZLu%252FScreenshot%2520%281976%29.png%3Falt%3Dmedia%26token%3D1350398d-5f56-46dd-a1ba-56b31bb0acad&width=768&dpr=3&quality=100&sign=f57e965b&sv=2)

## Question 5: What were the second and third commands executed by the threat actor?

*Format: command1,command2*

Following the successful login of `larry.doe`, network traffic appears on port 5985, which is designated for **Windows Remote Management (WinRM)**. This implies that remote administrative tasks or command execution likely took place after the user was authenticated.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FI2PSkQcsvWACST6o7cae%252FScreenshot%2520%281977%29.png%3Falt%3Dmedia%26token%3D7ea875dc-05c8-4c7b-a07d-9d9ade29100f&width=768&dpr=3&quality=100&sign=f69dea07&sv=2)

But the problem here is that, the traffic is encrypted.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FCZ0qPlEMBUtFYmJpfSi7%252FScreenshot%2520%281978%29.png%3Falt%3Dmedia%26token%3D2a173aab-cf59-425a-9c4f-8b6c0439bd06&width=768&dpr=3&quality=100&sign=bd55a237&sv=2)

I did some digging and came across this [GitHub](https://gist.githubusercontent.com/jborean93/d6ff5e87f8a9f5cb215cd49826523045/raw/0f7782d317a4e6e7830282aa7430289f7f97dabe/winrm_decrypt.py) repository that can decrypt winRM using passwords.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F6Pzex8TcKHi8jjZSZ6VP%252FScreenshot%2520%281979%29.png%3Falt%3Dmedia%26token%3D4870b266-f447-43d2-85fe-562faf392740&width=768&dpr=3&quality=100&sign=fb2743db&sv=2)

Now let's decrypt it!

```shell
python3 winrm_decrypt.py -p 'Password1!' ./traffic.pcap > decrypted_traffic.txt
```

While checking the decrypted traffic, I noticed that it was encoded with Base64.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FUIHu17EDcvMcSYCfNCEA%252FScreenshot%2520%281980%29.png%3Falt%3Dmedia%26token%3D11e1b42c-3923-4184-a8d9-c13c9d234f3b&width=768&dpr=3&quality=100&sign=b80f42cd&sv=2)

Let's extract it and save it to a new file.

```shell
grep -Poz '<rsp:Arguments>\K.*?(?=</rsp:Arguments>)' decrypted_traffic.txt > encoded_args.txt
```

Now let's decode it.

```shell
for line in $(cat encoded_args.txt); do echo "$line" | base64 --decode >> decoded_args.txt; echo >> decoded_args.txt; done
```

At this point, this challenge is finished! We just need tweak it a little to get the answers.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F9Mut63uRt3h0mnywo2qS%252FScreenshot%2520%281981%29.png%3Falt%3Dmedia%26token%3Da027981c-0639-4228-8d56-1998c63e1d0e&width=768&dpr=3&quality=100&sign=2779a73f&sv=2)

## Question 6: Extracting the Final Flag

At this stage, the challenge is complete! We just need to make it readable to extract the answers.

```shell
while read -r line; do echo "$line" | grep -a '<S N="V">' | cut -d'>' -f2 | cut -d'<' -f1; done < decoded_args.txt
```

Here's the output

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FI1Wa3yWQUUxeu491rUpc%252FScreenshot%2520%281983%29.png%3Falt%3Dmedia%26token%3Defdf777d-0d2a-4f2a-aac1-f5ca9a80c684&width=768&dpr=3&quality=100&sign=d337a7d9&sv=2)

It comes with the flag, which is the answer for **Question 6.**

We've successfully completed **Directory**!!!

## Conclusion

This challenge was about precision, patience, and the power of the right tools. With a few smart tweaks and decoding steps, we were able to uncover meaningful information from encoded data. By exploring different styles of command-line parsing using tools like `grep`, and custom loop structures, we demonstrated the flexibility available when dealing with repetitive or structured text.

Additionally, by incorporating **PyShark** to analyze PCAP traffic, we filtered and extracted Kerberos-related data efficiently — specifically targeting the `kerberos.cipher` field with filters to narrow it down to the exact packet of interest. This highlighted how powerful Python can be when paired with network analysis, allowing us to automate and parse network captures at a deeper level.

From decoding base64 strings to parsing XML-like payloads and dissecting PCAP files, this challenge showcased a multi-angle approach to problem-solving — turning raw data into real answers through sharp tools and sharper thinking.
