---
title: "Event Horizon"
date: 05-01-2025
excerpt: TryHackMe Writeup
cover: ../uploads/cover_eventhorizon.jpg
tags: Forensics, C2 Traffic Analysis
---

Welcome back to another write-up! After recently finishing 2nd place in the Trend Micro uCTF, I've decided to keep sharpening my skills by tackling more challenges on TryHackMe. This time, I'll be breaking down the **Event Horizon** room — a forensics-focused challenge that really puts your investigative skills to the test. In this write-up, I'll guide you step by step through my thought process, the tools I used, and the techniques that helped me uncover the hidden clues.

So, grab your toolkit and let's dive into Event Horizon!

For this challenge, we are given 2 files.

**powershell.DMP** and **traffic.pcapng**

Now let's analyze the pcap file using wireshark!

## Question 1: Finding the Email Credentials

*The attacker was able to find the correct pair of credentials for the email service. What were they? Format: email:password*

As I continue analyzing the network capture, we eventually come across `SMTP` traffic. Within this section, signs of a brute-force attempt become evident — meaning we can see repeated authentication attempts against the mail server, each likely trying a different password — and by the time we reach packet `4665`, a successful login can be observed.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FJKvgY1BhRC4TdmVJyvU5%252FScreenshot%2520%28245%29.png%3Falt%3Dmedia%26token%3D852b16a5-e2a1-4bb9-bce7-2abcc4822566&width=768&dpr=3&quality=100&sign=d77fba3f&sv=2)

Next thing I did is to follow the traffic in TCP. "Following the TCP stream" in Wireshark reconstructs the full back-and-forth conversation between client and server for that connection into a single readable view, rather than making us click through each individual packet one by one.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fu3zPc1EfRUanwXoZa6Ss%252FScreenshot%2520%28214%29.png%3Falt%3Dmedia%26token%3Db036275a-0aea-40fb-9a00-aeac14b10d8b&width=768&dpr=3&quality=100&sign=35381c7e&sv=2)

Here, we can see the Base64 encoded credentials. This is standard for SMTP's `AUTH LOGIN` mechanism — the protocol transmits the username and password as Base64 strings rather than encrypting them, so anyone who captures the traffic can trivially reverse it. All we need to do is decode it to reveal the email and the password.

```shell
echo "<base64_string>" | base64 -d
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FAxHuZ56dKU18PJ5w8NPX%252FScreenshot%2520%28216%29.png%3Falt%3Dmedia%26token%3D4e21277d-80da-4292-b82e-61838ed78224&width=768&dpr=3&quality=100&sign=7799e882&sv=2)

## Question 2: Recovering the Attacker's Email Body

*What was the body of the email that was sent by the attacker?*

Now that we've confirmed a successful authentication, the next logical step is to see what the attacker actually *did* with that mailbox access — in this case, sending an email. From the same analyzed TCP flow, we can scroll further down and successfully retrieve the attacker's email content, since SMTP transmits the full message (headers, body, and any attachments) in plaintext within the session once authentication succeeds.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FZLnyrluVekDbIjXgqSYQ%252FScreenshot%2520%28217%29.png%3Falt%3Dmedia%26token%3D099ec63a-597a-4cfe-b567-5b715edf5990&width=768&dpr=3&quality=100&sign=645f473c&sv=2)

## Question 3: Identifying the Malicious Download Command

*What command initiated the malicious script download?*

Beneath the email, we notice a Base64-encoded string. This is a very common technique attackers use to smuggle a PowerShell one-liner past casual inspection or simple content filters — the command is encoded so it doesn't look like an obvious script at first glance, and PowerShell can natively decode and execute Base64-encoded commands via its `-EncodedCommand` flag. To reveal the command, we first need to decode it, as this was the attacker's method of delivering the script.

```shell
echo "<base64_string>" | base64 -d
```

Here's the output

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FpqEgcwCNTiz5pBcGucxF%252FScreenshot%2520%28220%29.png%3Falt%3Dmedia%26token%3Df67f38d5-81c7-4508-89e5-a1f20cb8a122&width=768&dpr=3&quality=100&sign=58ec50c3&sv=2)

## Question 4: Extracting the Initial AES Key

*What is the initial AES key that is used for decrypting the C2 traffic?*

This is where the challenge shifts from "read the traffic" to "reverse-engineer a payload." While searching through the traffic for the malicious download referenced by the decoded command, we find it located in packet `4722`.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FdW2LVyq6tv4VtPzV9Idu%252FScreenshot%2520%28222%29.png%3Falt%3Dmedia%26token%3D17b5bf6c-fef6-4669-8afb-587938589428&width=768&dpr=3&quality=100&sign=9aee1477&sv=2)

Because the script was not readable in its raw form — it was compressed and Base64-encoded, a common way to shrink and disguise a payload before delivery — I made a small Python tool to reverse that process: decode it from Base64, then decompress it with `zlib` using raw DEFLATE (`wbits=-15`, meaning "no zlib/gzip header," which matches how many obfuscated payloads are packed to save a few extra bytes and avoid an obvious zlib magic number).

```python
import base64, zlib, pathlib

# decode + decompress
data = zlib.decompress(base64.b64decode(pathlib.Path("b64.txt").read_text().strip()), wbits=-15)
pathlib.Path("program.bin").write_bytes(data)
```

After running the script a new file named `program.bin` has been generated.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fm4MzdRqmB09geZB4XwI8%252FScreenshot%2520%28224%29.png%3Falt%3Dmedia%26token%3De76d0eb8-ac58-4239-9c66-4d8ee39b7a99&width=768&dpr=3&quality=100&sign=d7783bc3&sv=2)

Since it's a **.NET** binary — identifiable by its file signature and internal metadata structure — we can leverage specialized decompilers such as **ILSpy**, which reconstructs readable C#-like source code from compiled .NET assemblies, making the decompilation process straightforward compared to reversing native machine code.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FLUKjOgwCKLy4Hgdp7jHO%252FScreenshot%2520%28247%29.png%3Falt%3Dmedia%26token%3D9880ebc6-c4f0-486a-9456-585d13802dc2&width=768&dpr=3&quality=100&sign=cb6d4e1c&sv=2)

Next thing I did is to transfer the binary from my Linux machine to my Windows machine to reverse engineer it, since ILSpy is a Windows-native tool and generally offers a smoother decompilation and navigation experience there than under Wine or cross-platform alternatives.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FVvnugWZmeaZmskBmrNhT%252FScreenshot%2520%28225%29.png%3Falt%3Dmedia%26token%3Db78c448f-bdfb-4c33-add4-c58b30122052&width=768&dpr=3&quality=100&sign=6f382252&sv=2)

After inspecting the decompiled source, we've successfully found the key — it's typically hardcoded as a constant somewhere in the stager's initialization logic, since the malware needs it embedded locally to bootstrap its very first encrypted handshake with the C2 server.

## Question 5: Recovering the Administrator NTLM Hash

*What is the Administrator NTLM hash that the attacker found?*

This is where it's getting harder.

From my decompilation efforts, I determined that the sample I was working on was very likely a **Covenant C2** agent. Covenant is an open-source, .NET-based command-and-control (C2) framework often used in red-team engagements and, as seen here, by attackers — it manages "Grunts" (its term for implants/agents) that communicate with the C2 server over HTTP using a layered encryption handshake. While analyzing Covenant, I quickly came across a tool known as [CovenantDecryptor](https://github.com/naacbin/CovenantDecryptor), which is purpose-built to decode Covenant's network traffic by replaying its handshake logic against captured packets.

The challenge itself provided me with everything necessary to reconstruct and decrypt Covenant communications:

* Network traffic containing Covenant communication, extracted from a packet capture.
* The AES setup key, embedded inside the stage 0 binary (the one we recovered in Question 4).
* A process minidump (`powershell.DMP`) obtained from an infected host — this is a memory snapshot of a running process, which can still contain sensitive key material even after the process has moved on.

Based on the documentation of CovenantDecryptor and my own testing, the communication workflow can be broken down into three phases. Understanding this handshake is essential, because each phase produces a piece of key material we need in order to decrypt the next:

**Stage 0 — Establishing trust**

* The agent begins by sending an RSA public key, which has been encrypted using the embedded AES setup key (the one hardcoded in the binary).
* Before transmission, the data is formatted following the **GruntHTTPStager** structure with the type set to 0 — essentially a defined message format Covenant uses to tag what stage of the handshake a given HTTP request represents.
* In response, the C2 server provides a **SessionKey** that is encrypted with the RSA public key the agent just sent — meaning only the agent (holding the matching RSA private key) can decrypt it.

**Stage 1 — Proving key possession**

* The agent uses the AES setup key to decrypt the message, then applies its RSA private key to recover the SessionKey the server just sent.
* Using that SessionKey, the agent encrypts four random bytes and sends them back, again formatted as type 1 in the stager. This is essentially a "prove you have the key" challenge.
* The C2 then decrypts these bytes, appends four new random bytes of its own, and sends back the resulting eight bytes — proving *it* also holds the SessionKey, and adding fresh randomness to prevent replay attacks.

**Stage 2 — Completing the handshake**

* The agent decrypts the eight-byte message, verifies that the first four bytes matched what it had sent earlier (confirming the server is legitimate), and then sends back the remaining four bytes to the C2 using the type 2 stager format.
* The server performs the same verification on its end, completing a mutual authentication handshake.

At this point, the session is fully established, and regular encrypted data — using the shared SessionKey — can flow between the agent and the server. This is the traffic we ultimately need to decrypt to find the NTLM hash and the flag.

The next step involves applying the decryption process outlined in the repository to analyze the C2 traffic. Prior to that, it is necessary to isolate the Stage0 POST payload — the very first message in the handshake described above. This request is first observed beginning at packet `4742`.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FBTpaDv0Jd1z7oRnUVlh2%252FScreenshot%2520%28249%29.png%3Falt%3Dmedia%26token%3D20d2fb0a-5394-44cc-a0c1-53cdaadfac6c&width=768&dpr=3&quality=100&sign=bd27111f&sv=2)

Next thing I did is to save the content to a txt file, so CovenantDecryptor's CLI tools have a stable local file to work against instead of us copy-pasting from Wireshark each time.

It's time to use the CovenantDecryptor.

### Step A: Retrieve the modulus value from the Stage 0 request

Using the AESSetupKey, the modulus of the RSA private key can be identified. (The "modulus" here is one of the core numbers that makes up an RSA key pair — recovering it is the first step toward reconstructing the full private key from the memory dump.) To reach that point, the traffic must first be filtered. I relied on `grep -Po` to refine the captured data. The command is crafted to extract only the necessary values, isolating the modulus line (`i=`) and the portion that follows the *Hello World!* marker — a fixed string Covenant's stager traffic includes as a delimiter. This ensures that irrelevant HTML tags and other text are excluded, leaving only the key material exchanged between the client and the C2 server.

```shell
grep -Po '(^(i=.*))|(// Hello World! \K.*)' traffic.txt > traffic2.txt
```

Now let's extract the modulus.

```shell
python3 decrypt_covenent_traffic.py modulus -i traffic2.txt -k "Secret_hehe" -t base64
```

Here's the output.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FM7txDKIvs34tw0CwaFI3%252FScreenshot%2520%28231%29.png%3Falt%3Dmedia%26token%3D24bfba1f-fff0-4e22-bd2e-bde368d77567&width=768&dpr=3&quality=100&sign=b7296ea8&sv=2)

### Step B: Recover the RSA private key from the minidump

With the modulus in hand, we can now search the `powershell.DMP` memory dump for the matching RSA private key material. Because .NET keeps cryptographic key objects in memory while they're in use, a well-timed memory dump of the compromised process can still contain the full private key, even though it's never written to disk in plaintext.

```shell
python3 extract_privatekey.py -i powershell.DMP -m "Modulus" -o <folder_to_save_the_key>
```

Here's the output

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FLEwUVTnuzPkDPvjGwaDk%252FScreenshot%2520%28232%29.png%3Falt%3Dmedia%26token%3D3caeb7cf-3e18-40c3-87c1-c9a241f8d76c&width=768&dpr=3&quality=100&sign=fdbbcdc0&sv=2)

### Step C: Recover the SessionKey from the Stage 0 reply

Now that we have the RSA private key, we can decrypt the Stage 0 server response and recover the SessionKey — the key that actually protects the bulk of the C2 traffic, as described in the handshake breakdown above.

```shell
python3 decrypt_covenent_traffic.py key -i traffic2.txt --key <secret> -t base64 -r key/privkey1.pem -s 1
```

Here's the output

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FwmV3T0f5vQARGPqn11vk%252FScreenshot%2520%28234%29.png%3Falt%3Dmedia%26token%3D29e6214e-5498-4e72-b954-4016eed45d56&width=768&dpr=3&quality=100&sign=40c2b67&sv=2)

### Step D: Decrypt the full communication

With the SessionKey recovered, we can now decrypt every subsequent message exchanged between the agent and the C2 server — this is where the attacker's actual post-exploitation activity, including any dumped credentials, will surface.

```shell
python3 decrypt_covenent_traffic.py decrypt -i traffic2.txt -k "<secret_new_aes_key>" -t hex
```

Here's the output

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FDzDCfafE3rKcOSkF4SQc%252FScreenshot%2520%28236%29.png%3Falt%3Dmedia%26token%3D6a24cc13-154e-4822-9b00-6c75834f77bd&width=768&dpr=3&quality=100&sign=f134b814&sv=2)

Within this decrypted output, we can locate the message where the attacker ran a credential-dumping command, revealing the Administrator's NTLM hash in plaintext.

## Question 6: Uncovering the Final Flag

*What is the flag?*

The final flag is in the decrypted output as well — specifically the 15th response message. Rather than manually eyeballing it, we use **CyberChef** (a browser-based "data manipulation Swiss army knife") to decode it, since the raw bytes aren't directly human-readable.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FVYzQyKSUv1bB8IYk8zU1%252FScreenshot%2520%28239%29.png%3Falt%3Dmedia%26token%3D8e980be5-71e3-4301-821f-e36450d04584&width=768&dpr=3&quality=100&sign=14e65fb5&sv=2)

Here, we see that the magic header was PNG — the sequence of bytes (`89 50 4E 47...`) that every valid PNG file begins with, which is how file-type identification tools recognize a file's format without relying on its extension. So it's obviously a photo. All we need to do is render it.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FyPXENwEmkv65vILF1QFQ%252FScreenshot%2520%28242%29.png%3Falt%3Dmedia%26token%3Dbdade80e-2d62-461e-a6f6-a1a158d276f9&width=768&dpr=3&quality=100&sign=365ba080&sv=2)

We've successfully solved Event Horizon!!!

## Conclusion

Through careful traffic analysis, forensic investigation, and script deobfuscation, we were able to piece together the attacker's activity. By tracing SMTP traffic, we identified brute-force attempts and the eventual successful login. Following TCP streams allowed us to extract the attacker's email, where we uncovered a Base64-encoded payload that, once decoded, revealed the delivered command. Further inspection of the capture highlighted the malicious file download, which we later analyzed.

We then dealt with obfuscation by writing a Python script to unpack the attacker's code, giving us clearer insight into its behavior. Diving deeper, we retrieved critical artifacts such as the RSA private key from a Covenant process minidump and the SessionKey from Covenant C2's stage 0 response — both essential in understanding how encrypted communication was being handled.

This challenge demonstrated the importance of looking beyond surface-level indicators and leveraging forensic techniques to reconstruct the attacker's chain of actions. Event Horizon was not only a test of technical skill but also a reminder of how persistence and methodical analysis can unravel even the most concealed traces of an attack.
