---
title: "picoctf"
date: 07-26-2024
excerpt: VulnHub
cover: ../uploads/cover_driftingblues4.jpg
tags: bruteforce, crontab privesc
---

Good day, everyone! Today, I’ll be walking you through the challenges I’ve successfully solved in the Cryptography category of picoCTF 2026!

## cryptomaze - 100pts

For this challenge we are given a file called `output.txt`

```text
LFSR Initial State:
[0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1]
LFSR Taps:
[63, 61, 60, 58]
Encrypted Flag:
8f0e6d0f5b0dc1db201948b9e0cebd8f81d250455a05ee7c9e2ba57a1bc5428938338e7e04fbddef0c6260a4eb758417
```

This challenge involves recovering a hidden flag that was encrypted using a combination of a **Linear Feedback Shift Register (LFSR)** and **AES encryption**. The problem provides the initial state of the LFSR, the tap positions, and the encrypted flag in hexadecimal form. The description also hints that the LFSR output was used to generate a 128-bit AES key, which was then used to encrypt the flag in ECB mode.

A Linear Feedback Shift Register is a sequence generator that produces bits by repeatedly shifting a register and inserting a new bit computed from XOR operations on selected positions called taps. For example, if the register has 64 bits and the taps are at positions 63, 61, 60, and 58, the new bit is computed as the XOR of the bits stored in those positions. After computing the new bit, the register shifts and the new bit is inserted, producing a new state. Each iteration also produces one output bit, which can be taken either from the leftmost or the rightmost position depending on the implementation.

Each iteration:

1. Output one bit
2. XOR tap bits → new bit
3. Shift register
4. Insert new bit

Example:

```text
state = [b0 b1 b2 ... b63]
new_bit = state[t1] XOR state[t2] XOR state[t3] XOR state[t4]
shift
state = state[1:] + [new_bit]
```

Hint says: **Generate 128-bit sequence**

Why?

Because AES-128 requires:

`128 bits = 16 bytes`

So we must generate 128 bits from the LFSR. Next thing that we will do is to convert the bits to AES Key.

We group bits into 8-bit chunks:

`10101100 -> 0xAC`

Do this 16 times → 16 bytes → AES key

`key = bytes(key_bytes)`

Here's the given:

```text
Encrypted flag = hex string
Mode = ECB
Key = from LFSR
```

So:

```text
cipher = AES.new(key, AES.MODE_ECB)
flag = cipher.decrypt(ciphertext)
```

Next is the Tap Indexing:

`[63, 61, 60, 58]`

This usually means: Indexing from the **RIGHT** side (common in LFSR definitions)

So instead of:

`state[t]`

we must convert index from right side:

`state[-1 - (63 - t)]`

This aligns tap positions correctly.

Here's the solution for this written in Python:

```python
from Crypto.Cipher import AES

state = [
0,0,1,0,0,1,0,1,1,1,1,0,1,1,0,0,
1,0,0,1,0,1,1,0,1,0,0,1,0,1,0,1,
0,1,0,0,1,1,0,1,1,0,0,0,1,0,1,1,
1,1,0,0,0,1,0,0,0,1,0,1,1,0,1,1
]

taps = [63,61,60,58]

keystream = []

for _ in range(128):
    # output first bit instead of last
    keystream.append(state[0])
    # XOR taps from RIGHT side
    new_bit = 0
    for t in taps:
        new_bit ^= state[-1 - (63 - t)]
    # shift left
    state = state[1:] + [new_bit]

# build key
key_bytes = []

for i in range(0,128,8):
    byte = 0
    for j in range(8):
        byte = (byte << 1) | keystream[i+j]
    key_bytes.append(byte)

key = bytes(key_bytes)

print("AES key:", key.hex())

ciphertext = bytes.fromhex("8f0e6d0f5b0dc1db201948b9e0cebd8f81d250455a05ee7c9e2ba57a1bc5428938338e7e04fbddef0c6260a4eb758417")

cipher = AES.new(key, AES.MODE_ECB)
flag = cipher.decrypt(ciphertext)
print(flag)
```

Here's the output:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FQQhRfml4DaqHnZAvxO3O%252FScreenshot%2520%281833%29.png%3Falt%3Dmedia%26token%3D6508a463-35ec-4852-bad3-439c28576773&width=768&dpr=3&quality=100&sign=eef0f24e&sv=2)

## Shared Secrets - 100pts

For this challenge, we are given a 2 files called `message.txt` and `encryption.py`

Let's check the `message.txt`

```text
g = 2
p = 2446679304842267403903261424638695191543543507774999818596978578082983456498452621173991850171223659678925511911383466095731025632462080648780331532230378465525199714237404399536178171123172062629604465124284603814029617417176023056247595401180763313099733534107744242303713430098271374908915688916607811663834556519
A = 862422939115067914192700651276043434274373147037214152184085135733177420381110421334746838249136460921598314151059351064106082756768871288185918097008897857699312477752774190093910566976771703798558637461085185795959772853623677937752795382607265941247950142300276476844215866017207694724127897330711414528884699865
b = 179441385236892902713172352171903829494663627897925180405252254807924564944611480967228932287229192022782353336419031021778930462828769336934765450213016157866788329035364806651685545245352948937114558439400739397886120056245017687545251653085043713581753183815360623830804106147938029512226146895652104602308442422
enc = ffe6ece0ccdbc9f4ebe7d0fcbcecfdbcfbd0b9ebeeebbfb6ecebf2
```

Now let's check the `encryption.py`

```python
from Crypto.Util.number import getPrime
from random import randint

# Public parameters
g = 2
p = getPrime(1048)

# Server's secret
a = randint(2, p-2)
A = pow(g, a, p)

# Client secret
b = '???'

B = pow(g, b, p)

# Shared key
shared = pow(A, b, p)

# Encrypt flag
flag = b"picoCTF{...}"
enc = bytes([x ^ (shared % 256) for x in flag])

# Write challenge info
with open("file.txt", "w") as f:
    f.write(f"g = {g}\n")
    f.write(f"p = {p}\n")
    f.write(f"A = {A}\n")
    f.write(f"b = {b} \n")
    f.write(f"enc = {enc.hex()}\n")
```

This is a **Diffie-Hellman key exchange problem**.

From the hint: *What do you get if you combine a public key with a known private one?*

This means **we know** `b` **(client’s secret)**. Using that, we can compute the shared secret as:

$$
shared=Ab mod p\text{shared} = A^b \bmod pshared=Abmodp
$$

Then, the encryption/decryption is just a simple XOR of each byte of the message with the last 8 bits of the shared secret:

$$
flag=bytes([ x⊕(shared mod 256)  for x in enc ])\text{flag} = \text{bytes}\Big([\, x \oplus (\text{shared} \bmod 256) \;\text{for } x \text{ in enc} \,]\Big)flag=bytes([x⊕(sharedmod256)for x in enc])
$$

Here's the solution for this:

```python
from Crypto.Util.number import long_to_bytes

# Given parameters
g = 2
p = 2446679304842267403903261424638695191543543507774999818596978578082983456498452621173991850171223659678925511911383466095731025632462080648780331532230378465525199714237404399536178171123172062629604465124284603814029617417176023056247595401180763313099733534107744242303713430098271374908915688916607811663834556519
A = 862422939115067914192700651276043434274373147037214152184085135733177420381110421334746838249136460921598314151059351064106082756768871288185918097008897857699312477752774190093910566976771703798558637461085185795959772853623677937752795382607265941247950142300276476844215866017207694724127897330711414528884699865
b = 179441385236892902713172352171903829494663627897925180405252254807924564944611480967228932287229192022782353336419031021778930462828769336934765450213016157866788329035364806651685545245352948937114558439400739397886120056245017687545251653085043713581753183815360623830804106147938029512226146895652104602308442422
enc = bytes.fromhex("ffe6ece0ccdbc9f4ebe7d0fcbcecfdbcfbd0b9ebeeebbfb6ecebf2")

# Compute shared secret
shared = pow(A, b, p)

# Decrypt
flag = bytes([c ^ (shared % 256) for c in enc])
print(flag.decode())
```

And here's the output:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FMJ75ri46ovB8WOF0mtfw%252FScreenshot%2520%281834%29.png%3Falt%3Dmedia%26token%3D5fca3d68-68e4-489c-bef1-f2661fcd0d77&width=768&dpr=3&quality=100&sign=2bded43a&sv=2)

## StegoRSA - 100pts

For this challenge, we are given a file called `flag.enc` and `image.jpg`

Let's check the `image.jpg` :

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F9NJ5s3IqjqNUSVgdG7g8%252FScreenshot%2520%281835%29.png%3Falt%3Dmedia%26token%3D85b78335-0006-4928-b8f7-30ce6395390b&width=768&dpr=3&quality=100&sign=39a6d2e5&sv=2)

Just an image of a key... I checked the metadata of this image using `exiftool` and I've found this:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FuvvlrSpUaXto2AQVDAGJ%252FScreenshot%2520%281836%29.png%3Falt%3Dmedia%26token%3Dda81e6f5-3005-4d89-a807-bdca87397f7c&width=768&dpr=3&quality=100&sign=af0e1920&sv=2)

As you can see in the comment section, it has a long hexadecimal value. Let's decode it using `xxd`:

```shell
echo "hexadecimal_value" | xxd -r -p
```

And here's the result:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FjWkPmzBudCs6PdODhwFA%252FScreenshot%2520%281837%29.png%3Falt%3Dmedia%26token%3D0a0e9928-0d9a-4f89-9750-bbbf1fe70189&width=768&dpr=3&quality=100&sign=a20ec7d1&sv=2)

So the plaintext is an RSA Private Key! We can use this private key to decrypt our flag using `openssl`:

```shell
openssl pkeyutl -decrypt -inkey id.rsa -in flag.enc -out flag.txt
```

*(Copy the private key and save it to a file, mine is* `id.rsa`*)*

After we execute the command, it will generate a file called `flag.txt`:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FBKfGxeGpDM2tLMsSQ8g9%252FScreenshot%2520%281838%29.png%3Falt%3Dmedia%26token%3D0ffce553-be11-4b38-81ff-2d8d44181128&width=768&dpr=3&quality=100&sign=d56a3aca&sv=2)

## Black Cobra Pepper - 200pts

For this challenge, we are given a file called `output.txt` and `chall.py`

Let's check the `output.txt`:

```text
d7481d89f1aaf5a857f56edd2ae8994c
8c7d66558130eb5796d131beb43c9934
```

Now let's check the `chall.py`:

```python
from pwn import xor

pt = ""
key = ""

def split(full_key):
    k = full_key
    k1 = ""
    k2 = ""
    k3 = ""
    k4 = ""
    sub_keys = [k1, k2, k3, k4]
    for i in range(len(k)):
        sub_keys[i%4] = str(sub_keys[i%4]) + str(k[0])
        k = k[1:]
    return sub_keys

def glue(parts):
    k = ""
    for i in range(32):
        k = str(k) + str(parts[i%4][0])
        parts[i%4] = str(parts[i%4][1:])
    return k

def rot_word(word):
    return str(word[2:]) + str(word[0:2])

def sub_word(word):
    return word

def rcon(word):
    return word

def gen_keys(master_key):
    keys = []
    rounds = 0
    k = master_key

    while (rounds < 11):
        keys.append(k)
        sub_keys = split(k)
        sub_keys[-1] = rot_word(sub_keys[-1])
        sub_keys[-1] = sub_word(sub_keys[-1])
        sub_keys[-1] = rcon(sub_keys[-1])
        sub_keys[0] = xor(bytes.fromhex(sub_keys[0]), bytes.fromhex(sub_keys[-1])).hex()
        sub_keys[1] = xor(bytes.fromhex(sub_keys[1]), bytes.fromhex(sub_keys[0])).hex()
        sub_keys[2] = xor(bytes.fromhex(sub_keys[2]), bytes.fromhex(sub_keys[1])).hex()
        sub_keys[3] = xor(bytes.fromhex(sub_keys[3]), bytes.fromhex(sub_keys[2])).hex()
        k = glue(sub_keys)
        rounds += 1

    return keys

def to_matrix(key):
    bytes_list = [int(key[i:i+2], 16) for i in range(0, 32, 2)]

    array = [[0] * 4 for _ in range(4)]
    for i in range(16):
        row = i % 4
        col = i // 4
        array[row][col] = hex(bytes_list[i])[2:]

    return array

def from_matrix(matrix):
    reconstructed = ""
    for col in range(4):
        for row in range(4):
            reconstructed += matrix[row][col].zfill(2)
    return reconstructed

def sub_bytes(state):
    return state

def shift_rows(state):
    placeholder = state[1][0]
    state[1][0], state[1][1], state[1][2], state[1][3] = state[1][1], state[1][2], state[1][3], state[1][0]
    state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
    state[3][0], state[3][1], state[3][2], state[3][3] = state[3][3], state[3][0], state[3][1], state[3][2]
    return state

#adopted and insipred by the code from the wikipedia article Rijndael MixColumns.
def gmul(a, b):
    b = int(b, 16)
    p = 0
    for c in range(8):
        if b & 1:
            p ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11b
        b>>=1
    return p

def mix_columns(s):
    ss = [[0] * 4 for _ in range(4)]

    for c in range(4):
        ss[0][c] = hex(gmul(0x02, s[0][c]) ^ gmul(0x03, s[1][c]) ^ int(s[2][c], 16) ^ int(s[3][c], 16))[2:].zfill(2)
        ss[1][c] = hex(int(s[0][c], 16) ^ gmul(0x02, s[1][c]) ^ gmul(0x03, s[2][c]) ^ int(s[3][c], 16))[2:].zfill(2)
        ss[2][c] = hex(int(s[0][c], 16) ^ int(s[1][c], 16) ^ gmul(0x02, s[2][c]) ^ gmul(0x03, s[3][c]))[2:].zfill(2)
        ss[3][c] = hex(gmul(0x03, s[0][c]) ^ int(s[1][c], 16) ^ int(s[2][c], 16) ^ gmul(0x02, s[3][c]))[2:].zfill(2)

    for i in range(4):
        for j in range(4):
            s[i][j] = ss[i][j]
    return s

def AES(plaintext, key):
    ciphertext = plaintext
    round_keys = gen_keys(key)
    ciphertext = xor(bytes.fromhex(round_keys[0]), bytes.fromhex(ciphertext)).hex()
    for i in range(1,10):
        ciphertext = to_matrix(ciphertext)
        sub_bytes(ciphertext)
        shift_rows(ciphertext)
        mix_columns(ciphertext)
        ciphertext = from_matrix(ciphertext)
        ciphertext = xor(bytes.fromhex(round_keys[i]), bytes.fromhex(ciphertext)).hex()
    ciphertext = to_matrix(ciphertext)
    sub_bytes(ciphertext)
    shift_rows(ciphertext)
    ciphertext = from_matrix(ciphertext)
    ciphertext = xor(bytes.fromhex(round_keys[10]), bytes.fromhex(ciphertext)).hex()
    return ciphertext

flag = [redacted]
key = [redacted]
pt1 = "72616e646f6d64617461313131313131"

print((AES(pt1, key)))
print(AES(flag, key))
```

this is clearly a **broken AES implementation.**

This AES has **no S-box**, because:

```python
def sub_word(word):
    return word

def sub_bytes(state):
    return state

def rcon(word):
    return word
```

In real AES, these functions introduce non-linearity through the Substitution box, which is essential for security. Without the S-box, the cipher no longer behaves like true AES and instead becomes a purely **linear transformation** composed only of XOR operations, rotations, and matrix multiplications in GF(2^8).

Because all remaining operations are linear, the encryption function can be written in the form:

$$
Ek(x)=L(x)⊕K′E\_k(x) = L(x) \oplus K'Ek​(x)=L(x)⊕K′
$$

where L is a linear transformation and K′ is a constant derived from the key. This property makes the cipher vulnerable to known-plaintext attacks.

The challenge gives one known plaintext–ciphertext pair and another ciphertext containing the flag:

```text
pt1 = 72616e646f6d64617461313131313131
ct1 = d7481d89f1aaf5a857f56edd2ae8994c
ct2 = 8c7d66558130eb5796d131beb43c9934
```

Since the cipher is linear, XORing two ciphertexts cancels the key contribution:

$$
Ek(a)⊕Ek(b)=L(a⊕b)E\_k(a) \oplus E\_k(b) = L(a \oplus b)Ek​(a)⊕Ek​(b)=L(a⊕b)
$$

Applying this to the given values:

$$
ct1⊕ct2=L(pt1⊕flag)\text{ct}\_1 \oplus \text{ct}\_2 = L(\text{pt}\_1 \oplus \text{flag})ct1​⊕ct2​=L(pt1​⊕flag)
$$

This means the result of XORing the ciphertexts is simply the linear transformation applied to the XOR of the plaintexts, with no key involved.

Here's the solver written in Python:

```python
from pwn import xor

def split(k):
    sub_keys = ["", "", "", ""]
    for i in range(len(k)):
        sub_keys[i%4] = str(sub_keys[i%4]) + str(k[0])
        k = k[1:]
    return sub_keys

def glue(parts):
    k = ""
    for i in range(32):
        k = str(k) + str(parts[i%4][0])
        parts[i%4] = str(parts[i%4][1:])
    return k

def rot_word(word):
    return str(word[2:]) + str(word[0:2])

def gen_keys(master_key):
    keys = []
    rounds = 0
    k = master_key
    while (rounds < 11):
        keys.append(k)
        sub_keys = split(k)
        sub_keys[-1] = rot_word(sub_keys[-1])
        # sub_word and rcon were identity functions, so they are omitted
        sub_keys[0] = xor(bytes.fromhex(sub_keys[0]), bytes.fromhex(sub_keys[-1])).hex()
        sub_keys[1] = xor(bytes.fromhex(sub_keys[1]), bytes.fromhex(sub_keys[0])).hex()
        sub_keys[2] = xor(bytes.fromhex(sub_keys[2]), bytes.fromhex(sub_keys[1])).hex()
        sub_keys[3] = xor(bytes.fromhex(sub_keys[3]), bytes.fromhex(sub_keys[2])).hex()
        k = glue(sub_keys)
        rounds += 1
    return keys

def to_matrix(key_hex):
    bytes_list = [int(key_hex[i:i+2], 16) for i in range(0, 32, 2)]
    array = [[0] * 4 for _ in range(4)]
    for i in range(16):
        array[i % 4][i // 4] = hex(bytes_list[i])[2:].zfill(2)
    return array

def from_matrix(matrix):
    reconstructed = ""
    for col in range(4):
        for row in range(4):
            reconstructed += matrix[row][col].zfill(2)
    return reconstructed

def gmul(a, b):
    if isinstance(b, str): b = int(b, 16)
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        a <<= 1
        if a & 0x100: a ^= 0x11b
        b >>= 1
    return p

def inv_shift_rows(state):
    state[1][0], state[1][1], state[1][2], state[1][3] = state[1][3], state[1][0], state[1][1], state[1][2]
    state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
    state[3][0], state[3][1], state[3][2], state[3][3] = state[3][1], state[3][2], state[3][3], state[3][0]
    return state

def inv_mix_columns(s):
    ss = [[0] * 4 for _ in range(4)]
    for c in range(4):
        # Coefficients for Inverse MixColumns: 0e, 0b, 0d, 09
        ss[0][c] = hex(gmul(0x0e, s[0][c]) ^ gmul(0x0b, s[1][c]) ^ gmul(0x0d, s[2][c]) ^ gmul(0x09, s[3][c]))[2:].zfill(2)
        ss[1][c] = hex(gmul(0x09, s[0][c]) ^ gmul(0x0e, s[1][c]) ^ gmul(0x0b, s[2][c]) ^ gmul(0x0d, s[3][c]))[2:].zfill(2)
        ss[2][c] = hex(gmul(0x0d, s[0][c]) ^ gmul(0x09, s[1][c]) ^ gmul(0x0e, s[2][c]) ^ gmul(0x0b, s[3][c]))[2:].zfill(2)
        ss[3][c] = hex(gmul(0x0b, s[0][c]) ^ gmul(0x0d, s[1][c]) ^ gmul(0x09, s[2][c]) ^ gmul(0x0e, s[3][c]))[2:].zfill(2)
    for i in range(4):
        for j in range(4):
            s[i][j] = ss[i][j]
    return s

def decrypt_no_key(ciphertext_hex):
    # Use a null key (all zeros) for the linear reversal
    null_key = "0" * 32
    round_keys = gen_keys(null_key)
    
    # Reverse Round 10 (No MixColumns)
    curr = xor(bytes.fromhex(ciphertext_hex), bytes.fromhex(round_keys[10])).hex()
    state = to_matrix(curr)
    state = inv_shift_rows(state)
    curr = from_matrix(state)
    
    # Reverse Rounds 9 down to 1
    for i in range(9, 0, -1):
        curr = xor(bytes.fromhex(curr), bytes.fromhex(round_keys[i])).hex()
        state = to_matrix(curr)
        state = inv_mix_columns(state)
        state = inv_shift_rows(state)
        curr = from_matrix(state)
        
    # Reverse Round 0 (Final XOR)
    plaintext = xor(bytes.fromhex(curr), bytes.fromhex(round_keys[0]))
    return plaintext

ct1 = "d7481d89f1aaf5a857f56edd2ae8994c"
ct2 = "8c7d66558130eb5796d131beb43c9934"
pt1 = "72616e646f6d64617461313131313131"

# 1. XOR the ciphertexts to remove the key contribution
ct_diff = xor(bytes.fromhex(ct1), bytes.fromhex(ct2)).hex()

# 2. Decrypt the difference using a null key to get the plaintext difference
pt_diff = decrypt_no_key(ct_diff)

# 3. Apply the difference to the known plaintext to get the flag
flag = xor(bytes.fromhex(pt1), pt_diff)

print(f"Flag: {flag.decode()}")
```

To recover the plaintext difference, the linear transformation must be reversed. Because the transformation no longer depends on the key, it can be inverted using a **null key** (all zeros). This is exactly what the decoder does by generating round keys from a zero master key and applying the inverse AES operations:

* inverse ShiftRows
* inverse MixColumns
* XOR with round keys

Since the cipher is linear, reversing the rounds with a zero key correctly computes:

$$
pt\_diff=pt1⊕flag\text{pt\\_diff} = \text{pt}\_1 \oplus \text{flag}pt\_diff=pt1​⊕flag
$$

Once the plaintext difference is known, recovering the flag is trivial:

$$
flag=pt1⊕pt\_diff\text{flag} = \text{pt}\_1 \oplus \text{pt\\_diff}flag=pt1​⊕pt\_diff
$$

This is implemented in the final step of the script:

```python
flag = xor(bytes.fromhex(pt1), pt_diff)
```

The attack works because removing the S-box destroys the non-linearity that makes AES secure.
Without the substitution step, the cipher becomes equivalent to a linear transformation similar to a weakened version of Rijndael, allowing the key to be eliminated by XORing ciphertexts and making the encryption reversible without knowing the secret key.

Here's the result of the solution script:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FJpx4PoIsJO25r35UmwA6%252FScreenshot%2520%281839%29.png%3Falt%3Dmedia%26token%3De7f27c6e-5a8b-465b-85aa-f38f76e840e9&width=768&dpr=3&quality=100&sign=18df3aec&sv=2)

## Related Messages - 200pts

For this challenge, we are given a 2 files called `chall.py` and `output.txt`

Let's check the `output.txt`:

```text
3486364849772584627692611749053367200656673358261596068549224442954489368512244047032432842601611650021333218776410522726164792063436874469202000304563253268152374424792827960027328885841727753251809392141585739745846369791063025294100126955644910200403110681150821499366083662061254649865214441429600114378725559898580136692467180690994656443588872905046189428367989340123522629103558929469463071363053880181844717260809141934586548192492448820075030490705363082025344843861901475648208157572346004443100461870519699021342998731173352225724445397168276113254405106732294978648428026500248591322675321980719576323749
201982790559548563915678784397933493721879152787419243871599124287434576744055997870874349538398878336345269929647585648144070475012256331468688792105087899416655051702630953882466457932737483198442642588375981620937494661378586614008496182135571457352400128892078765628319466855732569272509655562943410536265866312968101366413636251672211633011159836642751480632253423529271185888171036917413867011031963618529122680143291205470937752671602494831117301480813590683791618751348224964277861127486155552153012612562009905595646626759034581358425916638671884927506025703373056113307665093346439014722219878575598308124
-3
17334845546772507565250479697360218105827285681719530148909779921509619103084219698006014339278818598859177686131922807448182102049966121282308256054696565796008642900453901629937223685292142986689576464581496406676552201407729209985216274086331582917892470955265888718120511814944341755263650688063926284195007148056359887333784052944201212155189546062807573959105963160320187551755272391293705288576724811668369745107148481856135696249862795476376097454818009481550162364943945249601744881676746859305855091288055082626399929893610275614840617858985993338556889612804266896309310999363054134373435198031731045253881
```

Now let's check the `chall.py`:

```python
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes, GCD

Message = bytes_to_long(b"[redacted]")
Message_fixed = bytes_to_long(b"[redacted]")
e = 0x11
p = getPrime(1024)
q = getPrime(1024)
phi = (p-1) * (q-1)
d = inverse(e, phi)
N = p*q

ciphertext = pow(Message, e, N)
ciphertext2 = pow(Message_fixed, e, N)

print(ciphertext, ciphertext2)
print(Message - Message_fixed)
print(N)
```

This challenge is a classic application of the **Franklin-Reiter Related Message Attack**.

Since we have two ciphertexts C1​ and C2​ where the plaintexts M1​ and M​2​ are related by a known linear function M_1 = M_2 + \Delta, we can recover the original message without knowing the private key ddd.

We have two equations in the ring ZN​[x]ZN​[x]ZN​[x]:

1. f1​(x)=xe−C1​=0(modN)f1​(x)=xe−C1​=0(modN)f1​(x)=xe−C1​=0(modN)
2. f2​(x)=(x+Δ)e−C2​=0(modN)f2​(x)=(x+Δ)e−C2​=0(modN)f2​(x)=(x+Δ)e−C2​=0(modN)

Both polynomials share a common root, which is M2​M2​M2​. By calculating the Greatest Common Divisor (GCD) of these two polynomials in SageMath, the resulting polynomial will be (x−M2​)(x−M2​)(x−M2​), revealing the message.

We will need [SageCellServer](https://sagecell.sagemath.org/) for this challenge, here's the solution:

Here's the output:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FnbGTneYANOGXmWz0IM9p%252FScreenshot%2520%281840%29.png%3Falt%3Dmedia%26token%3D8d02a3e8-24e5-4cac-877c-067447495fb2&width=768&dpr=3&quality=100&sign=960cd217&sv=2)

## shift registers - 200pts

For this challenge, we are given a 2 files called `chall.py` and `output.txt`:

Let's check the `output.txt`:

Now let's check the `chall.py`:

This is a classic Linear Feedback Shift Register (LFSR) challenge. We have the ciphertext and the encryption logic, but the `key` (and specifically the initial `lfsr` state) is missing.

The good news? This specific LFSR is only 8 bits wide (it masks the key with `0xFF`), which means there are only 256 possible starting states. This is small enough to solve with a brute-force attack in a fraction of a second.

In the `encrypt_lfsr` function, the initial state of the LFSR is derived from `key & 0xFF`. Since the LFSR state is only 8 bits:

1. There are only 256 possible initial values (0 to 255).
2. LFSRs are deterministic. If we know the starting state and the `steplfsr` function, we can generate the entire keystream.
3. We can simply try every possible 8-bit key, decrypt the ciphertext, and look for a result that looks like a flag (usually starting with `picoCTF{`).

Here's the solution for this challenge:

Here's the output:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FAUoPCxJ05gfxpZTs37hZ%252FScreenshot%2520%281841%29.png%3Falt%3Dmedia%26token%3Df5ea6188-ffa4-450b-8031-2a9b47d7e53f&width=768&dpr=3&quality=100&sign=cfbf7caa&sv=2)

## Small Trouble - 200pts

For this challenge, we are given 2 files called `message.txt` and `encryption.py`

Let's check the `message.txt`:

And this is the `encryption.py`:

This is a classic RSA challenge where the vulnerability lies in a Small Private Exponent (ddd).

While nnn and eee look massive, the `encryption.py` script reveals that ddd was generated using `getPrime(256)`. Since ddd is significantly smaller than n0.292n0.292n0.292 (in this case, d≈2256d≈2256d≈2256 while n≈22096n≈22096n≈22096), the encryption is vulnerable to the Boneh-Durfee Attack.

Standard RSA usually uses a small public exponent (like e=65537e=65537e=65537) and a large private exponent ddd. In our case, the script did the opposite: it chose a small ddd and calculated eee from it.

When d<n0.292d<n0.292d<n0.292, we can use Coppersmith’s method for finding small roots of modular polynomials to recover ddd (or the factorization of nnn).

Also we can use Wiener’s Attack because of a specific mathematical weakness that occurs when the private exponent ddd is very small relative to the modulus nnn.

Specifically, the attack works whenever:

d<13n1/4d < \frac{1}{3} n^{1/4}d<31​n1/4

In this challenge, nnn is roughly 2048 bits. A quarter of that is 512 bits. Since our ddd was generated as a 256-bit prime (`getPrime(256)`), it is significantly smaller than the threshold required for the attack to succeed.

Here's the logic behind it, RSA is defined by the equation:

ed−kϕ(n)=1ed - k\phi(n) = 1ed−kϕ(n)=1

If we divide both sides by dϕ(n)dϕ(n)dϕ(n), we get:

eϕ(n)−kd=1dϕ(n)\frac{e}{\phi(n)} - \frac{k}{d} = \frac{1}{d\phi(n)}ϕ(n)e​−dk​=dϕ(n)1​

Since nnn is very large, ϕ(n)ϕ(n)ϕ(n) is very close to nnn. When ddd is small, the fraction dk​dk​dk​ becomes an extremely good approximation of the public fraction ne​ne​ne​.

Here's the solution for this challenge (Read the comments for better understanding):

Here's the output:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FTDI7CrAY6guWCPVcLBt7%252FScreenshot%2520%281842%29.png%3Falt%3Dmedia%26token%3Dae282c6a-6dff-4857-85d8-380f0745026e&width=768&dpr=3&quality=100&sign=c19333d&sv=2)

## Timestamped Secrets - 200pts

For this challenge, we are given 2 files called `message.txt` and `encryption.py`

Let's check the `message.txt`:

Now let's check the `encryption.py`:

This is a "weak seed" cryptography challenge. The security of AES depends entirely on the secrecy of the key, but here, the key is generated using a Unix timestamp. Since we have a hint about when the encryption occurred, we can "brute-force" the time to find the exact second that produces the correct key.

In the `encryption.py` script, the key is derived like this:

1. Take the current time (e.g., `1770242597`).
2. Hash that number as a string using SHA-256.
3. Use the first 16 bytes of that hash as the AES key.

Because we know the encryption happened "around" `1770242597`, we only need to check a small window of timestamps (e.g., a few minutes before and after) to find the one that successfully decrypts the ciphertext.

Here's the solution for this challenge:

Here's the output:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FoslkuVCNtznA8BQxRtXH%252FScreenshot%2520%281843%29.png%3Falt%3Dmedia%26token%3D6ea715c4-8ca9-40f9-9ed4-8b0cacc13968&width=768&dpr=3&quality=100&sign=856c270&sv=2)

## ClusterRSA - 400pts

For this challenge, we are given a file called `message.txt`

Let's check the contents of `message.txt`:

This is a classic Multi-prime RSA challenge. Standard RSA uses two large primes (ppp and qqq), but as the challenge hint suggests ("someone got greedy"), this modulus (nnn) is composed of multiple smaller primes.

Because the primes are smaller than usual, we can factorize nnn relatively quickly using online databases or specialized algorithms.

## Step 1: Factorize nnn

The first step is to break nnn into its prime components. For numbers of this size in CTFs, the easiest tool is [factordb.com](http://factordb.com).

Input our nnn value: `8749002899132047699790752490331099938058737706735201354674975134719667510377522805717156720453193651`

We will find that nnn is composed of several primes.

## Step 2: Calculate ϕ(n)ϕ(n)ϕ(n)

In Multi-prime RSA, the Totient function ϕ(n)ϕ(n)ϕ(n) is calculated by taking each prime factor pi​pi​pi​ and multiplying (pi​−1)(pi​−1)(pi​−1) together:

ϕ(n)=(p1−1)(p2−1)⋯(pk−1)\phi(n) = (p\_1 - 1)(p\_2 - 1)\cdots(p\_k - 1)ϕ(n)=(p1​−1)(p2​−1)⋯(pk​−1)

## Step 3: Find the Private Key (ddd)

The decryption exponent ddd is the modular multiplicative inverse of eee modulo ϕ(n)ϕ(n)ϕ(n):

d≡e−1(modϕ(n))d \equiv e^{-1} \pmod{\phi(n)}d≡e−1(modϕ(n))

## Step 4: Decrypt the Message

Once we have ddd, we can recover the original message mmm:

m=ctd(modn)m = ct^d \pmod{n}m=ctd(modn)

Instead of manually searching in FactorDB, we can automate the process since Python provides a module for FactorDB.

Here's the solution for this challenge:

Here's the output:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FkA9Gzic891JEroRdSCdw%252FScreenshot%2520%281844%29.png%3Falt%3Dmedia%26token%3Dcd30dff8-b349-4fff-8aec-709621531178&width=768&dpr=3&quality=100&sign=16f78ba1&sv=2)

## Not TRUe - 400pts

For this challenge, we are given 2 files called `public.txt` and `encrypt.py`

Let's check the `public.txt`:

Now let's check the `encrypt.py`:

We're dealing with the **NTRU** (N-th degree Truncated Polynomial Ring) cryptosystem. Given the small parameters (N=48N=48N=48), this is highly vulnerable to a Lattice Attack using the **LLL** (Lenstra–Lenstra–Lovász) algorithm.

The public key hhh is defined by the relation f⋅h≡g(modq)f⋅h≡g(modq)f⋅h≡g(modq). Because fff and ggg are "short" polynomials (coefficients in −1,0,1{−1,0,1}−1,0,1), we can construct a lattice where the vector (f,g)(f,g)(f,g) is an exceptionally short vector.

We build a 2N×2N2N×2N2N×2N matrix MMM:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FLKo9wgQzWTuWE1yHBlxY%252FScreenshot%2520%281845%29.png%3Falt%3Dmedia%26token%3Df7cd278b-ca7c-4629-af12-6b0aa9abbf30&width=768&dpr=3&quality=100&sign=d96d890a&sv=2)

Where HHH is the circulant matrix representing multiplication by hhh in the ring Rq​Rq​Rq​. The shortest vector in this lattice will likely reveal the private key fff.

Here's the solution for this challenge:

Here's the output:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FzeTJEMjeUejnlJwHTbqE%252FScreenshot%2520%281846%29.png%3Falt%3Dmedia%26token%3D6a959a2b-16fe-440b-95de-ea85ecd13de4&width=768&dpr=3&quality=100&sign=5173ed16&sv=2)

This Cryptography category during picoCTF 2026 turned out to be more interesting than I expected. At first, I thought it would require manual analysis or simple calculations, but I was surprised that almost everything had to be solved through scripting. Instead of relying on tools alone, I had to write Python scripts to automate the process, which made the challenge both more difficult and more enjoyable.


Last updated 4 months ago

---


# General Skills

Source: https://kur0sh1r0.gitbook.io/ctf-writeups/picoctf-2026/general-skills

For the complete documentation index, see [llms.txt](https://kur0sh1r0.gitbook.io/ctf-writeups/llms.txt). This page is also available as [Markdown](https://kur0sh1r0.gitbook.io/ctf-writeups/picoctf-2026/general-skills.md).

Good day, everyone! Today, I’ll be walking you through the challenges I’ve successfully solved in the General Skills category of picoCTF 2026!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FdH7noiyb4suFPIxBleqg%252F200_d.gif%3Falt%3Dmedia%26token%3D8bc3d3be-2fb7-44b4-8b29-ea69969da10c&width=768&dpr=3&quality=100&sign=a5a3935a&sv=2)

## SUDO MAKE ME A SANDWICH - 50pts

For this challenge, we are given an SSH credentials we can connect on.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FQy9EUDTLsk13PObRYsS4%252FScreenshot%2520%281612%29.png%3Falt%3Dmedia%26token%3D22c954db-7fc7-4e9f-8d7a-02cb39c7af59&width=768&dpr=3&quality=100&sign=323df097&sv=2)

As you can see, the file `flag.txt` is owned by root. The question now is: how can we read it as a regular user? This is where `sudo` becomes useful. Let’s check what commands we are allowed to run as root using `sudo -l`.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FgvqPWPvRj4DCxhrdGwPY%252FScreenshot%2520%281613%29.png%3Falt%3Dmedia%26token%3D04c7432e-1b3d-4bb7-bbfe-49a92a5d4cf6&width=768&dpr=3&quality=100&sign=9e26cb78&sv=2)

Since the `sudo -l` command shows that we are allowed to run **emacs** as root, we can use it to access files that normally require root privileges. **Emacs** is a powerful text editor in Linux that can open and view files, similar to nano or vim, but with more advanced features. Because we can execute emacs using sudo, it will run with root permissions, allowing us to open the protected `flag.txt` file even as an ordinary user. By running the command `sudo emacs flag.txt`, the file will open inside emacs, and we can read the flag even though the file is owned by root.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F8V00pXj5zZpwE2oh6DAC%252FScreenshot%2520%281615%29.png%3Falt%3Dmedia%26token%3D64f5cd45-959a-449c-934f-5eaff9025352&width=768&dpr=3&quality=100&sign=5ea28ca3&sv=2)

## Piece by Piece - 50pts

For this challenge we are given an SSH credentials again that we can connect on.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FhQF4uKNqgKcwkOEs7UKp%252FScreenshot%2520%281619%29.png%3Falt%3Dmedia%26token%3D6d7aa3b6-0a03-4c18-9a57-37915a007a7a&width=768&dpr=3&quality=100&sign=4a56c15c&sv=2)

The `instructions.txt` file provides the following hints:

1. The flag is split into multiple parts as a **zipped file**.
2. We need to **combine the parts into one file** using Linux commands.
3. The zip file is **password protected**; the password is `"supersecret"`.
4. After unzipping, the extracted file will contain the flag.

From this, we know the steps: **merge → unzip → read**.

In Linux, the `cat` command can **concatenate multiple files** into a single file. Since the parts are named sequentially (`part_aa` to `part_ae`), we can merge them in order:

`cat part_aa part_ab part_ac part_ad part_ae > flag.zip`

This creates a single zip file named `flag.zip` containing all parts.

The file is protected with the password `supersecret`. To extract it, run:

`unzip flag.zip`

After extraction, a file such as `flag.txt` will appear in the directory.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FEAwOqCDgTlAHSMNJAoVp%252FScreenshot%2520%281622%29.png%3Falt%3Dmedia%26token%3Dcfa3a2b1-38f3-4b5f-a5db-b289634b3791&width=768&dpr=3&quality=100&sign=4d628c33&sv=2)

## bytemancy 0 - 50pts

For this challenge, we are given a file called `app.py` .

Take a closer look at the condition, `"\x65"` is **hexadecimal for 101 in decimal**, which corresponds to the ASCII character `'e'`. Therefore, `"\x65\x65\x65"` is the string `'eee'`. All we need to do is to type `'eee'` and the program will provide the flag. Now let's connect to the server:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F541kkxBPMDbwXYggMuBD%252FScreenshot%2520%281624%29.png%3Falt%3Dmedia%26token%3D8a099b7d-a63d-42b2-ae27-158b1f9454e1&width=768&dpr=3&quality=100&sign=e08532a2&sv=2)

## Printer Shares - 50pts

In this challenge, credentials for an SMB server were provided. After enumerating the available shares using `smbclient`, the following shares were discovered:

`smbclient -L //mysterious-sea.picoctf.net -p 63048 -N`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F1ZwfAMPlSnYsWc5uAZ5e%252FScreenshot%2520%281638%29.png%3Falt%3Dmedia%26token%3Daa622a14-a648-449c-a5bc-ffff5cc1ba55&width=768&dpr=3&quality=100&sign=baf34955&sv=2)

We found an available share from the share list, so we attempted to connect to it and check its contents.

`smbclient //mysterious-sea.picoctf.net/shares -p 63048 -N`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FNFCHKg34qkkYAXnzw0RI%252FScreenshot%2520%281639%29.png%3Falt%3Dmedia%26token%3Ddad039c9-daeb-4159-8a0a-c2935916a4c2&width=768&dpr=3&quality=100&sign=fd7a52c8&sv=2)

As you can see that there's a `flag.txt` here, next thing we did is to `get` the file to transfer it to my machine.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FVc8RnmAaX4a623WtVjpK%252FScreenshot%2520%281640%29.png%3Falt%3Dmedia%26token%3Dcb6c8eed-630d-4fb3-b9b0-671304e6ab7b&width=768&dpr=3&quality=100&sign=5d1c17e2&sv=2)

## MY GIT - 50pts

In this challenge, a Git repository is available to us, and it is accessible through an SSH connection.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FUeyxcntcXQ0sRB1Wa289%252FScreenshot%2520%281641%29.png%3Falt%3Dmedia%26token%3Dcfbed21a-2bfd-41ff-bc3a-cd23f3d80d54&width=768&dpr=3&quality=100&sign=b89e3197&sv=2)

Let's read the `README.md`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FvlPwjLphaq4zeuq7esbu%252FScreenshot%2520%281642%29.png%3Falt%3Dmedia%26token%3D3fb441af-a47c-46f5-a97e-f663b3daa76e&width=768&dpr=3&quality=100&sign=b8f74af8&sv=2)

This means the server **only accepts commits made by a user with username** `root` **and email** `root@picoctf`. So we need to **pretend to be that user locally**, push a commit with `flag.txt`, and then the server will reveal the flag.

Here's how we can get the flag:

Step 1: Set Git identity to `root:root@picoctf`

`git config user.name "root"`

`git config user.email "root@picoctf"`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FOfp46brJI2HWWAsRxXYM%252FScreenshot%2520%281643%29.png%3Falt%3Dmedia%26token%3D3e466edb-ff3d-4125-94a6-b1683269189c&width=768&dpr=3&quality=100&sign=1783c93a&sv=2)

Step 2: Create `flag.txt`

`echo "BlahBlah" > flag.txt`

`git add flag.txt`

`git commit -m "push flag.txt"`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fh41gV9zWvCteOgFyxCwo%252FScreenshot%2520%281644%29.png%3Falt%3Dmedia%26token%3D84cddd34-ba34-4104-b4e6-69de26dd6475&width=768&dpr=3&quality=100&sign=19938061&sv=2)

Even if the file is empty or contains dummy text, it doesn’t matter — the server only checks the **commit author**.

Step 3: Push to the repo

`git push origin master`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FcHUTnuze0LyPlZw5vk6d%252FScreenshot%2520%281648%29.png%3Falt%3Dmedia%26token%3D35f7880a-1d14-4131-bb5c-4b1f680e3fb7&width=768&dpr=3&quality=100&sign=7e3ad668&sv=2)

## Password Profiler - 100pts

For this challenge, we are given 3 files `userinfo.txt`, `hash.txt`, `check_password.py`

Let's check the `userinfo.txt`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FTdZ31KKOlCaWPcSHfzEw%252FScreenshot%2520%281649%29.png%3Falt%3Dmedia%26token%3D80cc83a0-6b20-4697-9e75-75b909774361&width=768&dpr=3&quality=100&sign=e66ab358&sv=2)

So it's full of credentials about `Alice`, according to the hint, we can utilize the tool `cupp` to make a wordlist. `cupp` is a wordlist generator, it uses provided credentials of the target to craft the possible passwords.

This is the `hash.txt`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F0wH6mFKKIbY8STfz9oXF%252FScreenshot%2520%281650%29.png%3Falt%3Dmedia%26token%3D916e95a4-edd8-4a10-ae87-1d83e751b095&width=768&dpr=3&quality=100&sign=100a1631&sv=2)

Now to crack this, we need a wordlist, let's use `cupp`, to generate a wordlist using the credentials provided to us

Launch `cupp` in interactive mode:

`cupp -i`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FPxDPrWuZmFogS6npXgx2%252FScreenshot%2520%281651%29.png%3Falt%3Dmedia%26token%3De7030ae4-d1a5-47a3-ba0a-84c91ed580cb&width=768&dpr=3&quality=100&sign=978bc643&sv=2)

This is all you need, leave other fields empty, only follow the `user-info.txt` .

Now this is the `check_password.py`

So it's a pre-build password cracker for us, all we need to do is to change the name of wordlist file, to the filename of our wordlist.

Now let's run it

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FKYsZFMR0oKD75ECwZU9E%252FScreenshot%2520%281653%29.png%3Falt%3Dmedia%26token%3D345aa25b-9f80-4509-98b1-7ac8eeafae9d&width=768&dpr=3&quality=100&sign=2e808d1a&sv=2)

## KSECRETS - 100pts

We are provided a file named `kubeconfig` and a server that we can connect with.

Let's check the contents of `kubeconfig`

This is a **Kubernetes secrets extraction challenge**. We already have the `kubeconfig`, so the goal is to connect to the cluster → list secrets → decode them → get the flag.

For this challenge, we will need `kubectl` for this, you can install it via `apt`

Once installed, the first thing that we do is to list the namespaces

`kubectl --kubeconfig kubeconfig --insecure-skip-tls-verify=true --server https://green-hill.picoctf.net:55327 get ns`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fzo9fMc2axDZB11OkoVAx%252FScreenshot%2520%281658%29.png%3Falt%3Dmedia%26token%3D0564e8d3-34bd-4398-b070-0c97bd050d6c&width=768&dpr=3&quality=100&sign=9ab13b5&sv=2)

So we have a `picoctf` namespace, now let's get the secrets of `picoctf` namespace

`kubectl --kubeconfig kubeconfig --insecure-skip-tls-verify=true --server https://green-hill.picoctf.net:55327 get secrets -n picoctf`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F3xUy50KyyhTx4deCHGKa%252FScreenshot%2520%281659%29.png%3Falt%3Dmedia%26token%3Dd9d2feb4-eae7-4c65-b35e-2c95a4903cf7&width=768&dpr=3&quality=100&sign=c4f00d64&sv=2)

Now all we need to do is to dump the secret named `ctf-secret`

`kubectl --kubeconfig kubeconfig --insecure-skip-tls-verify=true --server https://green-hill.picoctf.net:55327 get secret ctf-secr
et -n picoctf -o yaml`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F5haUHK6twJqZ7bv2Ipg1%252FScreenshot%2520%281656%29.png%3Falt%3Dmedia%26token%3D59fe0c73-1aad-448f-8942-723ceabf6ab5&width=768&dpr=3&quality=100&sign=c11931c1&sv=2)

There's the flag, just encoded in Base64. Let's decode it

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FXHbdXkdWO2NrWCCiVNYu%252FScreenshot%2520%281657%29.png%3Falt%3Dmedia%26token%3Dace42974-0b94-4fc9-a329-a27b569576cc&width=768&dpr=3&quality=100&sign=44ce665f&sv=2)

## ping-cmd - 100pts

For this challenge, we are given a server that we can connect with using `netcat`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F2Pb7ttAFZXEY4IfwzinD%252FScreenshot%2520%281660%29.png%3Falt%3Dmedia%26token%3Dface85be-fc87-4ebc-bb24-d5f6e6b5ec8d&width=768&dpr=3&quality=100&sign=797cdfd6&sv=2)

So it's just asking as for an IP to `ping` it, according to the hint of this challenge:

* The program uses a shell command behind the scenes.
* Sometimes, You can run more than one command at a time.

Since it's running a shell command, we can use command separators for Linux, such as `|` and `&&` in order for us to inject another command in the prompt

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FhU0aJzsaESMRVN0gGZA0%252FScreenshot%2520%281664%29.png%3Falt%3Dmedia%26token%3D9a3c5b25-b2cc-4547-ae9b-6e68b8da9240&width=768&dpr=3&quality=100&sign=c9e72f7d&sv=2)

As you can see, when I put `| ls -al`, it executes. Now we know where the flag is located, let's open the `flag.txt` using `| cat flag.txt`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FfHE9AyA5bXMiimInhfKv%252FScreenshot%2520%281665%29.png%3Falt%3Dmedia%26token%3D437bf28d-8be3-4444-a79a-e72db70a0c05&width=768&dpr=3&quality=100&sign=140d96da&sv=2)

## bytemancy 1 - 100pts

For this challenge, we are given a file named `app.py` and a server that we can connect on using `netcat`.

This is the contents of `app.py`

The core logic of this code is a simple input check: it repeatedly prompts the user to enter a string, and if that string exactly matches 1751 repetitions of the ASCII character with decimal code 101 (which is `'e'`), it prints the flag and exits; otherwise, it tells the user their input was incorrect and loops again. Essentially, the program is just testing whether you can correctly generate and provide the specific byte sequence (`"e"*1751`) that satisfies the equality check.

Since we don't want to type `e` manually 1751 times, we will automate this using `pwntools`

This will send `1751 e` to the server and get the flag

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fe6lgPFw13YJz5sBL7j5D%252FScreenshot%2520%281666%29.png%3Falt%3Dmedia%26token%3D1c7e31fa-e99e-496a-93c3-4a767cf9f3aa&width=768&dpr=3&quality=100&sign=9dbe415e&sv=2)

## Undo - 100pts

For this challenge, we are given a server that we can connect on using `nc`

Basically it's just a question-based CTF and we will Identify it how we can reverse the encoded text, here's the full answer:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FhCIJWjAn52KjDX1uwsYS%252FScreenshot%2520%281667%29.png%3Falt%3Dmedia%26token%3D9cd03571-e793-4cd4-8b53-7d1e585fd40b&width=768&dpr=3&quality=100&sign=3cafed16&sv=2)

## MultiCode - 200pts

For this challenge, we are given a file called `message.txt`

Let's open the `message.txt`

Now according to the hint given:

*The flag has been wrapped in several layers of common encodings such as ROT13, URL encoding, Hex, and Base64. Can you figure out the order to peel them back?*

So it's a multiple encoding process, we can use CyberChef for this challenge to chain the decoding process.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FQt1ahABabZz88EkPvjAn%252FScreenshot%2520%281669%29.png%3Falt%3Dmedia%26token%3Dbcb3d292-3e0d-4b6f-9bd0-7f112b74b44b&width=768&dpr=3&quality=100&sign=8efb5f6e&sv=2)

## bytemancy 2 - 200pts

For this challenge, we are given a file called `app.py` and a server that we can connect with using `netcat`

Let's check the contents of `app.py`

The core logic is that the program repeatedly prompts for input and checks whether it exactly matches **three consecutive bytes of value 0xFF** (`b"\xff\xff\xff"`). It reads input as raw bytes, not text, so ordinary characters won’t work; only the precise sequence of three `0xFF` bytes satisfies the condition, at which point it prints the flag. To solve it, we simply send those three bytes side-by-side without any extra characters or spaces, we can utilize `pwntools` again for this challenge

Here's the output

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fl2pLpNRvTcfLxqRb4j25%252FScreenshot%2520%281670%29.png%3Falt%3Dmedia%26token%3D5c38646b-1d88-4a26-a0cf-695923bd73cd&width=768&dpr=3&quality=100&sign=c1cea485&sv=2)

## Printer Shares 2 - 200pts

In this challenge, credentials for an SMB server were provided. After enumerating the available shares using `smbclient`, the following shares were discovered:

`smbclient -L //green-hill.picoctf.net -p 57305 -N`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FQapnw9XPErAw5NrRRAH3%252FScreenshot%2520%281672%29.png%3Falt%3Dmedia%26token%3Dcde26eb3-36d3-40db-827e-3a1a4c70cc40&width=768&dpr=3&quality=100&sign=8037cab8&sv=2)

So it has a `secure-shares` , I tried to access it but yeah as expected, it's restricted.

`smbclient //green-hill.picoctf.net/shares -p 57305 -N`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FTMORLQNMYskMtrwayBrH%252FScreenshot%2520%281673%29.png%3Falt%3Dmedia%26token%3Db6d245d2-a88a-4f51-926c-28235f3dcc09&width=768&dpr=3&quality=100&sign=b029e95f&sv=2)

Inside I've found `content.txt` , `kafka.txt`, `notification.txt`

Here's the content:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F74tdtfYLgwFkP5O0SgHz%252FScreenshot%2520%281674%29.png%3Falt%3Dmedia%26token%3D4d268efa-9b0c-4cd3-9aeb-cf32fa2821d9&width=768&dpr=3&quality=100&sign=e9443&sv=2)

So in the `notification.txt` , it's clear that `joe` is our user. Now according to the hint, `rockyou.txt` is being mentioned, it means `joe` has access to `secret-shares` all we need to do is to bruteforce the password. I've found a script in [Github](https://gist.github.com/shoriwe/851d5e27317ac8fec9954f00a0b8a701) that we can use for this challenge.

I only have to write the user and domain into a file and it's ready to go

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fw94keMwwbnnFYmikrJ4A%252FScreenshot%2520%281678%29.png%3Falt%3Dmedia%26token%3D1b733a8f-75fa-4ccb-98e1-885225456c21&width=768&dpr=3&quality=100&sign=cb7d2720&sv=2)

So the pasword is `popcorn`, now let's connect to the SMB again using `joe`

`smbclient //green-hill.picoctf.net/secure-shares -p 57305 -U joe`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FH9vXnGamJILylnlR9b8F%252FScreenshot%2520%281680%29.png%3Falt%3Dmedia%26token%3Df8542a9c-7f99-4e48-a2eb-a7b97b7ada7b&width=768&dpr=3&quality=100&sign=c952c7a&sv=2)

Now we can get the `flag.txt`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FG9DKDYLq3zuyqPui4Vuu%252FScreenshot%2520%281681%29.png%3Falt%3Dmedia%26token%3D34038c10-bdc2-4f17-831b-a14dd099f298&width=768&dpr=3&quality=100&sign=cf3a558f&sv=2)

## ABSOLUTE NANO - 200pts

For this challenge, we are given an SSH server that we can connect with.

When I check what we can execute as root, I saw `nano`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F0eBTYbZBkC8YaKWPi7kf%252FScreenshot%2520%281685%29.png%3Falt%3Dmedia%26token%3Daa351d09-20e5-47f7-9c0c-8d17beb587a2&width=768&dpr=3&quality=100&sign=932356e2&sv=2)

It turns out that we can edit `/etc/sudoers` file.

`sudo nano /etc/sudoers`

If you don't know, Nano can execute commands. Here's how

When you're inside `nano`, escape nano to shell.

`Ctrl + R`

`Ctrl + X`

After that, Nano will ask for a command.

Then type `reset; bash 1>&0 2>&0`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F2oOfL135B1Pa7YzNAWzC%252FScreenshot%2520%281686%29.png%3Falt%3Dmedia%26token%3D09d99c2b-ba06-44f1-ba41-e6d9f90fd348&width=768&dpr=3&quality=100&sign=865c52ff&sv=2)

And press enter

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F5PsPgu2iAZiRfPxFAQMn%252FScreenshot%2520%281687%29.png%3Falt%3Dmedia%26token%3D0dfcf52d-8a2d-4d06-9344-5d7e5c756db3&width=768&dpr=3&quality=100&sign=9669e1db&sv=2)

And we are root:>>

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FeEF6ctLAlBylz4RykPJI%252FScreenshot%2520%281688%29.png%3Falt%3Dmedia%26token%3Dc5289b16-8500-4dc6-ab05-8e9015b4de22&width=768&dpr=3&quality=100&sign=95ff1982&sv=2)

## Failure Failure - 200pts

For this challenge, we are given a file called `app.py` , `haproxy.cfg` and a web server that we can access.

Let's check the `app.py`

Now let's check the `haproxy.cfg`

The Flask application reveals that the flag is only returned when the environment variable `IS_BACKUP` is set to `"yes"`. In the normal case, the service returns `"No flag in this service"`, meaning the primary server does not contain the flag, while the backup service likely does. The application also uses a **global rate limiter** with a limit of 300 requests per minute, and once the limit is exceeded, the server returns a 503 response. Because the rate limit key is hardcoded to `"global"`, the limit applies to all users collectively instead of per‑IP, meaning repeated requests can affect the availability of the entire service. This detail suggests that the rate limiter can be abused to disrupt the primary service.

The HAProxy configuration shows that traffic is sent to server `s1` on port 8000 by default, while server `s2` on port 9000 is marked as a **backup server**. HAProxy performs health checks using `GET /`, and if the primary server fails to respond with status 200, traffic is automatically redirected to the backup server. Since the Flask code only reveals the flag when running in backup mode, the goal is to force HAProxy to consider the primary server unhealthy. This can be done by sending more than 300 requests per minute to trigger the rate limiter, causing the primary server to return errors during the health check. Once HAProxy detects the failure, it switches to the backup server, where `IS_BACKUP=yes` is set, allowing the flag to be returned in the response.

All we need to do is to flood it:>>

This exploit works perfectly because the Flask application uses a **global rate limit of 300 requests per minute**, meaning all requests share the same limit instead of being limited per user. The command sends **700 requests in parallel using** `xargs -P50`, which quickly exceeds the allowed limit and causes the primary server to return errors. Since HAProxy continuously checks the primary server with health checks, these errors make it appear unhealthy, forcing HAProxy to switch to the **backup server**, where the environment variable `IS_BACKUP=yes` is set. Once traffic is routed to the backup instance, the application reveals the flag, making this flood request the ideal way to trigger the failover and obtain the flag.

After we flood it, let's visit the website

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FByjBKS8sn0GqNfYvgHcP%252FScreenshot%2520%281692%29.png%3Falt%3Dmedia%26token%3D1ad241c9-9da9-4efb-9a6a-8626cae8f25d&width=768&dpr=3&quality=100&sign=8098f99d&sv=2)

## Printer Shares 3 - 300pts

For this challenge, we are given an SMB server that we can connect to.

`smbclient -L //dolphin-cove.picoctf.net -p 56828 -N`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FPcGQkErPeBb1xOJ7yQH3%252FScreenshot%2520%281694%29.png%3Falt%3Dmedia%26token%3Db9d0a7bd-6f3c-47fc-8de6-55a95cd5b099&width=768&dpr=3&quality=100&sign=3e3cf5a9&sv=2)

The same as Printer Share 2, let's check the `shares`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FmQDezaoFyIz8SAvLeKF5%252FScreenshot%2520%281696%29.png%3Falt%3Dmedia%26token%3D5d78e460-5b4a-4c4b-a123-4bdb1ff6160c&width=768&dpr=3&quality=100&sign=1a0e99cc&sv=2)

As you can see, there's a bash script in shares, let's get it

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fah3wxwnfi3l2Ukwthcmi%252FScreenshot%2520%281698%29.png%3Falt%3Dmedia%26token%3Dd2ca5c08-cf2b-4aa9-bfd1-8fb3eb617883&width=768&dpr=3&quality=100&sign=c5544428&sv=2)

This is the content of `script.sh`, as said in the comment, it runs every minute. So it's a cronjob kind of challenge, what we can do is to use this to our advantage. We can modify the `script.sh` and transfer it back to the SMB server. But first we must locate where the flag is.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FUz30GWBG8jNGI7gWDj0K%252FScreenshot%2520%281703%29.png%3Falt%3Dmedia%26token%3D359844ee-8268-49f6-80f3-62999e13e5c3&width=768&dpr=3&quality=100&sign=6aa326d5&sv=2)

What I did is to use `find` and analyze from the `/` directory to look for a file named `flag.txt` and save the output in `flag_loc.txt`

Next thing I did is to transfer it back to the server using `put` and after a minute, the file appears.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FHVT4UZM3CtfXL2rqfcGK%252FScreenshot%2520%281705%29.png%3Falt%3Dmedia%26token%3D8ac6f35c-1341-482a-9213-82940b198cfe&width=768&dpr=3&quality=100&sign=c7c80108&sv=2)

As you can see, the full path of the `flag.txt` is `/challenge/secure-shares/flag.txt` Next thing we can do is to copy the `flag.txt` to `/challenge/shares` where the `script.sh` is currently placed.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F32vfHD2fBYcRJ9ISn2Of%252FScreenshot%2520%281707%29.png%3Falt%3Dmedia%26token%3D57c14832-3c69-411d-9dfe-4499d9a27dfe&width=768&dpr=3&quality=100&sign=a716de9e&sv=2)

And I transfer it back to the server and wait for another minute and got the flag.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F3JDnZmLKKsdFJmvwfcXZ%252FScreenshot%2520%281710%29.png%3Falt%3Dmedia%26token%3D35c30742-c236-4986-ba8f-2a9e25c53d3b&width=768&dpr=3&quality=100&sign=a65d3e2a&sv=2)

## bytemancy 3 - 400pts

For this challenge we are given a file `app.py`, `spellbook`, and a server that we can connect to using `netcat`.

Let's check the `app.py`

The Python script asks for the addresses of these functions:

* `ember_sigil`
* `glyph_conflux`
* `astral_spark`
* `binding_word`

Now let's check the `spellbook`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FMmNrMLAYpgHh2JG03Cs8%252FScreenshot%2520%281718%29.png%3Falt%3Dmedia%26token%3Dd24b3040-8e78-454a-965e-99570024b468&width=768&dpr=3&quality=100&sign=6f31b849&sv=2)

At first, I thought it was a txt file but it turns out to be an executable file. Let's change its permission and execute it.

`chmod +x spellbook`

When I run it, it gives me nothing. Now let's use `objdump` to analyze the binary

`objump -d ./spellbook`

Look closely from our `objdump`:

Basically, the script expects **raw 4‑byte little endian**, same as `p32(addr)`.

**ember\_sigil**

`0x08049176 → 76 91 04 08`

**glyph\_conflux**

`0x0804919a → 9a 91 04 08`

**astral\_spark**

`0x080491c1 → c1 91 04 08`

**binding\_word**

`0x080491e3 → e3 91 04 08`

Now let's check the `app.py` again, this line:

Means each run picks **3 random functions**, so you must send the correct bytes depending on the question.

Example prompt:

You send raw bytes:

NOT text.

Here's the `solve.py` for this challenge:

Here's the output

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FPzRJrbsgmz0fycW827rO%252FScreenshot%2520%281719%29.png%3Falt%3Dmedia%26token%3D8002c5df-2b75-4d54-a3a3-78c3fdb1519a&width=768&dpr=3&quality=100&sign=bec61665&sv=2)

We've got the flag, the error is just EOF, because the connection closed but our script still trying to recv:>>

That's a wrap! This is all of the challenges for General Skills category of picoCTF 2026! This year's picoCTF is more fun!


Last updated 4 months ago

---
