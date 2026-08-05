---
title: "PicoCTF 2026: Cryptography"
date: 03-20-2026
excerpt: PicoCTF 2026 Writeup
cover: ../uploads/cover_picocrypto.jpg
tags: LFSR, AES, Diffie-Hellman, linear transformation, Franklin-Reiter, LLL, NTRU
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
\text{shared} = A^b \bmod p
$$

Then, the encryption/decryption is just a simple XOR of each byte of the message with the last 8 bits of the shared secret:

$$
flag=bytes([ x⊕(shared mod 256)  for x in enc ])
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
E\_k(x) = L(x) \oplus K'
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
E_k(a) \oplus E_k(b) = L(a \oplus b)
$$

Applying this to the given values:

$$
ct_1 \oplus ct_2 = L(pt_1 \oplus flag)
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
\text{pt\\_diff} = \text{pt}\_1 \oplus \text{flag}
$$

Once the plaintext difference is known, recovering the flag is trivial:

$$
\text{flag} = \text{pt}\_1 \oplus \text{pt\\_diff}
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

Since we have two ciphertexts C1​ and C2​ where the plaintexts M1​ and M​2​ are related by a known linear function 

$$
M_1 = M_2 + \Delta
$$

We can recover the original message without knowing the private key d.

We have two equations in the ring ZN​[x]:

1. $$f_1(x) = x^e - C_1 \equiv 0 \pmod{N}$$
2. $$f_2(x) = (x + \Delta)^e - C_2 \equiv 0 \pmod{N}$$

Both polynomials share a common root, which is M2​. By calculating the Greatest Common Divisor (GCD) of these two polynomials in SageMath, the resulting polynomial will be (x-M2), revealing the message.

We will need [SageCellServer](https://sagecell.sagemath.org/) for this challenge, here's the solution:

```python
C1 = 3486364849772584627692611749053367200656673358261596068549224442954489368512244047032432842601611650021333218776410522726164792063436874469202000304563253268152374424792827960027328885841727753251809392141585739745846369791063025294100126955644910200403110681150821499366083662061254649865214441429600114378725559898580136692467180690994656443588872905046189428367989340123522629103558929469463071363053880181844717260809141934586548192492448820075030490705363082025344843861901475648208157572346004443100461870519699021342998731173352225724445397168276113254405106732294978648428026500248591322675321980719576323749
C2 = 201982790559548563915678784397933493721879152787419243871599124287434576744055997870874349538398878336345269929647585648144070475012256331468688792105087899416655051702630953882466457932737483198442642588375981620937494661378586614008496182135571457352400128892078765628319466855732569272509655562943410536265866312968101366413636251672211633011159836642751480632253423529271185888171036917413867011031963618529122680143291205470937752671602494831117301480813590683791618751348224964277861127486155552153012612562009905595646626759034581358425916638671884927506025703373056113307665093346439014722219878575598308124
diff = -3
N = 17334845546772507565250479697360218105827285681719530148909779921509619103084219698006014339278818598859177686131922807448182102049966121282308256054696565796008642900453901629937223685292142986689576464581496406676552201407729209985216274086331582917892470955265888718120511814944341755263650688063926284195007148056359887333784052944201212155189546062807573959105963160320187551755272391293705288576724811668369745107148481856135696249862795476376097454818009481550162364943945249601744881676746859305855091288055082626399929893610275614840617858985993338556889612804266896309310999363054134373435198031731045253881
e = 0x11

def franklin_reiter(C1, C2, diff, e, N):
    # Create the polynomial ring over integers modulo N
    P.<x> = PolynomialRing(Zmod(N))
    
    # We define two polynomials that share a common root (the message)
    # Since Message = Message_fixed + diff
    # f1(x) = (x + diff)^e - C1 
    # f2(x) = x^e - C2
    f1 = (x + diff)^e - C1
    f2 = x^e - C2
    
    # Simple Euclidean Algorithm for polynomials in Zmod(N)
    def poly_gcd(a, b):
        while b:
            a, b = b, a % b
        return a.monic()

    common_root_poly = poly_gcd(f1, f2)
    
    # The result is (x - m), so m = -constant_term
    return -common_root_poly.coefficients()[0]

# Execute attack
message_fixed_long = franklin_reiter(C1, C2, diff, e, N)

# Convert integer to bytes manually (Sage style)
m_int = Integer(message_fixed_long)
hex_val = hex(m_int)[2:]
if len(hex_val) % 2 != 0: hex_val = '0' + hex_val
print("Flag:", bytes.fromhex(hex_val).decode('utf-8', 'ignore'))
```

Here's the output:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FnbGTneYANOGXmWz0IM9p%252FScreenshot%2520%281840%29.png%3Falt%3Dmedia%26token%3D8d02a3e8-24e5-4cac-877c-067447495fb2&width=768&dpr=3&quality=100&sign=960cd217&sv=2)

## shift registers - 200pts

For this challenge, we are given a 2 files called `chall.py` and `output.txt`:

Let's check the `output.txt`:

```text
21c1b705764e4bfdafd01e0bfdbc38d5eadf92991cdd347064e37444e517d661cea9
```

Now let's check the `chall.py`:

```python
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Random import get_random_bytes

key = bytes_to_long(get_random_bytes(126))

def steplfsr(lfsr):
    b7 = (lfsr >> 7) & 1
    b5 = (lfsr >> 5) & 1
    b4 = (lfsr >> 4) & 1
    b3 = (lfsr >> 3) & 1

    feedback = b7 ^ b5 ^ b4 ^ b3
    lfsr = (feedback << 7) | (lfsr >> 1)
    return lfsr

def encrypt_lfsr(pt_bytes):
    output = bytearray()
    lfsr = key & 0xFF
    for p in pt_bytes:
        lfsr = steplfsr(lfsr)
        ks = lfsr
        output.append(p ^ ks)
    return bytes_to_long(bytes(output))

pt = b"[redacted]"
ct = encrypt_lfsr(pt)

print(long_to_bytes(ct).hex())
```
This is a classic Linear Feedback Shift Register (LFSR) challenge. We have the ciphertext and the encryption logic, but the `key` (and specifically the initial `lfsr` state) is missing.

The good news? This specific LFSR is only 8 bits wide (it masks the key with `0xFF`), which means there are only 256 possible starting states. This is small enough to solve with a brute-force attack in a fraction of a second.

In the `encrypt_lfsr` function, the initial state of the LFSR is derived from `key & 0xFF`. Since the LFSR state is only 8 bits:

1. There are only 256 possible initial values (0 to 255).
2. LFSRs are deterministic. If we know the starting state and the `steplfsr` function, we can generate the entire keystream.
3. We can simply try every possible 8-bit key, decrypt the ciphertext, and look for a result that looks like a flag (usually starting with `picoCTF{`).

Here's the solution for this challenge:

```python
from Crypto.Util.number import long_to_bytes

ct_hex = "21c1b705764e4bfdafd01e0bfdbc38d5eadf92991cdd347064e37444e517d661cea9"
ct_bytes = bytes.fromhex(ct_hex)

def steplfsr(lfsr):
    b7 = (lfsr >> 7) & 1
    b5 = (lfsr >> 5) & 1
    b4 = (lfsr >> 4) & 1
    b3 = (lfsr >> 3) & 1

    feedback = b7 ^ b5 ^ b4 ^ b3
    lfsr = ((feedback << 7) | (lfsr >> 1)) & 0xFF # Keep it 8-bit
    return lfsr

# Brute force the 8-bit seed (0-255)
for seed in range(256):
    lfsr = seed
    pt = bytearray()
    
    for c in ct_bytes:
        lfsr = steplfsr(lfsr)
        ks = lfsr
        pt.append(c ^ ks)
    
    # Check if the result looks like a flag
    if b"pico" in pt:
        print(f"Found Key! Seed: {seed}")
        print(f"Flag: {pt.decode(errors='ignore')}")
        break
```

Here's the output:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FAUoPCxJ05gfxpZTs37hZ%252FScreenshot%2520%281841%29.png%3Falt%3Dmedia%26token%3Df5ea6188-ffa4-450b-8031-2a9b47d7e53f&width=768&dpr=3&quality=100&sign=cfbf7caa&sv=2)

## Small Trouble - 200pts

For this challenge, we are given 2 files called `message.txt` and `encryption.py`

Let's check the `message.txt`:

```text
n = 3980993015101017140353277804369745949706344223334890812840413257071044175973139291856038905399468319530362030870405443017903655374929929825011733964330181337551061274726015170805648591339935699566483704533804413902772334194671185814032757795167276567492610548489766891166023546451221494011601527912413323143640008533569546329046772124896140545774468831882189458647605131344071766512469603284171712833770168967153998797122819825938323489525196597407482515674210085730485950171311356595462370875129472210846138025654237220573246971086221110031195278019873474587710322597773432501095235059971088078096926751790014797097704337356321889
e = 3336497038614663222541921459680551835187913731404732354361770350895041393777650313575506088859422849385970294213215931070595265411244105028409623278013975724125500479919877564207207562572189315593170541926598007670763000263224010236185517132229343161667668429997117301579363090706170019283552359847390040311521617091884426220652237247589452213130475528794167610900761281292390567153221748933849959961895636324991675428047481887984343193310278137379109243220192216924968789976201537337617841164156347418356710488273730184036786730194843318185762453423678066812440979743181541976510807538521163968859836855958692325875567630213728207
c = 1826031079095822845536526213992736069835634421976077836267143793181964583083024760950942723002771287666852728279522910274806690415793596687180742873080830698626932982997385432329275546871401690500831953978994557961462780510004840010773264058566952483483889805568428664825400505121671890223584721114411827697594512296341594773601537519080793749568472726239590091904052247534142381322885597999201255135897334420626115847929127670295300664641023915921412100348810694368790829410468324587518896440574662249893060377916803644769267529820246473511018540449718324002956264174312180181563530270721168751856698020681743829723342459520727632
```

And this is the `encryption.py`:

```python
from Crypto.Util.number import getPrime, inverse, bytes_to_long
import random

# Generate two large primes (1048 bits each)
p = getPrime(1048)
q = getPrime(1048)
n = p * q
phi = (p - 1) * (q - 1)

# compute d
d = getPrime(256)

# Compute the public exponent
e = inverse(d, phi)

# Encrypt a flag
flag = b'picoCTF{...}'
m = bytes_to_long(flag)
c = pow(m, e, n)

# Output for the challenge
with open("message.txt", "w") as f:
    f.write(f"n = {n}\n")
    f.write(f"e = {e}\n")
    f.write(f"c = {c}\n")
```

This is a classic RSA challenge where the vulnerability lies in a Small Private Exponent (d).

While nnn and eee look massive, the `encryption.py` script reveals that ddd was generated using `getPrime(256)`. Since ddd is significantly smaller than n0.292 (in this case, d≈2256 while n≈22096), the encryption is vulnerable to the Boneh-Durfee Attack.

Standard RSA usually uses a small public exponent (like e=65537) and a large private exponent d. In our case, the script did the opposite: it chose a small d and calculated eee from it.

When d < n0.292d, we can use Coppersmith’s method for finding small roots of modular polynomials to recover d (or the factorization of n).

Also we can use Wiener’s Attack because of a specific mathematical weakness that occurs when the private exponent d is very small relative to the modulus n.

Specifically, the attack works whenever:

$$
d < \frac{1}{3} n^{1/4}
$$

In this challenge, n is roughly 2048 bits. A quarter of that is 512 bits. Since our d was generated as a 256-bit prime (`getPrime(256)`), it is significantly smaller than the threshold required for the attack to succeed.

Here's the logic behind it, RSA is defined by the equation:

$$
ed - k\phi(n) = 1
$$

If we divide both sides by dϕ(n), we get:

$$
\frac{e}{\phi(n)} - \frac{k}{d} = \frac{1}{d\phi(n)}
$$

Since nnn is very large, ϕ(n) is very close to n. When d is small, the fraction dk​​ becomes an extremely good approximation of the public fraction ​ne​.

Here's the solution for this challenge (Read the comments for better understanding):

```python
def int_to_bytes(n):
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')

def solve_boneh_durfee(e, n):
    delta = 0.25
    m = 3 # Lattice dimension parameter
    t = 1 # Shift parameter
    
    X = floor(n^delta)
    Y = floor(n^0.5)
    
    # Define the polynomial: f(x, y) = x*(n + 1 - y) + 1 = 0 mod e
    P.<x, y> = PolynomialRing(ZZ)
    A = n + 1
    f = x * (A - y) + 1
    
    # Build the lattice (Coppersmith's method for bivariate)
    # We generate shifts: x^i * f^j * e^(m-j)
    shifts = []
    for i in range(m + 1):
        for j in range(i + 1):
            # Simplified version of the Boneh-Durfee basis
            shifts.append(x^(i-j) * f^j * e^(m-j))
            
    # Create the matrix from the coefficients of the shifts
    # This is a bit dense, but it handles the Monomial scaling (X and Y)
    monomials = sorted(set(m for s in shifts for m in s.monomials()))
    matrix = Matrix(ZZ, len(shifts), len(monomials))
    
    for row, s in enumerate(shifts):
        s_scaled = s(x*X, y*Y)
        for col, mnt in enumerate(monomials):
            matrix[row, col] = s_scaled.monomial_coefficient(mnt)
            
    LLL_matrix = matrix.LLL()
    
    # Reconstruct the polynomial from the shortest vector
    new_pol = 0
    for col, mnt in enumerate(monomials):
        new_pol += LLL_matrix[0, col] * (mnt / mnt(X, Y))
        
    # Find the roots of the new polynomial over the Integers
    # We use a resultant to eliminate one variable
    P_uni.<x_uni> = PolynomialRing(ZZ)
    # Check if we can find y as a function of x
    res = new_pol.resultant(f, y)
    roots_x = res.univariate_polynomial().roots()
    
    if roots_x:
        k_val = abs(roots_x[0][0])
        # Recover phi: ed = 1 (mod phi) => k*phi = ed - 1
        # Since we know k, we can find phi
        # This is a simplified check:
        for k in [k_val]:
            phi = (e * d_approx - 1) // k
            # Better way: plug x back into original pol to find y
            # Then phi = n + 1 - y
            return k
    
    return None

n = 3980993015101017140353277804369745949706344223334890812840413257071044175973139291856038905399468319530362030870405443017903655374929929825011733964330181337551061274726015170805648591339935699566483704533804413902772334194671185814032757795167276567492610548489766891166023546451221494011601527912413323143640008533569546329046772124896140545774468831882189458647605131344071766512469603284171712833770168967153998797122819825938323489525196597407482515674210085730485950171311356595462370875129472210846138025654237220573246971086221110031195278019873474587710322597773432501095235059971088078096926751790014797097704337356321889
e = 3336497038614663222541921459680551835187913731404732354361770350895041393777650313575506088859422849385970294213215931070595265411244105028409623278013975724125500479919877564207207562572189315593170541926598007670763000263224010236185517132229343161667668429997117301579363090706170019283552359847390040311521617091884426220652237247589452213130475528794167610900761281292390567153221748933849959961895636324991675428047481887984343193310278137379109243220192216924968789976201537337617841164156347418356710488273730184036786730194843318185762453423678066812440979743181541976510807538521163968859836855958692325875567630213728207
c = 1826031079095822845536526213992736069835634421976077836267143793181964583083024760950942723002771287666852728279522910274806690415793596687180742873080830698626932982997385432329275546871401690500831953978994557961462780510004840010773264058566952483483889805568428664825400505121671890223584721114411827697594512296341594773601537519080793749568472726239590091904052247534142381322885597999201255135897334420626115847929127670295300664641023915921412100348810694368790829410468324587518896440574662249893060377916803644769267529820246473511018540449718324002956264174312180181563530270721168751856698020681743829723342459520727632

def wiener_attack(e, n):
    cf = continued_fraction(e/n)
    convergents = cf.convergents()
    for frac in convergents:
        k = frac.numerator()
        d = frac.denominator()
        if k == 0: continue
        if pow(pow(2, e, n), d, n) == 2:
            return d
    return None

print("Trying Wiener's Attack...")
d = wiener_attack(e, n)
if d:
    print(f"Success! d = {d}")
    print(f"Flag: {int_to_bytes(int(pow(c, d, n))).decode()}")
else:
    print("Wiener failed. Please use a full Boneh-Durfee script locally in Sage.")
```

Here's the output:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FTDI7CrAY6guWCPVcLBt7%252FScreenshot%2520%281842%29.png%3Falt%3Dmedia%26token%3Dae282c6a-6dff-4857-85d8-380f0745026e&width=768&dpr=3&quality=100&sign=c19333d&sv=2)

## Timestamped Secrets - 200pts

For this challenge, we are given 2 files called `message.txt` and `encryption.py`

Let's check the `message.txt`:

```text
Hint: The encryption was done around 1770242597 UTC
Ciphertext (hex): 77c36bef0245021f9d9b7e396b52d2efbdbe6f8e4b79146e5d87c93416453b5f
```

Now let's check the `encryption.py`:

```python
from hashlib import sha256
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def encrypt(plaintext: str, timestamp: int) -> str:
    timestamp = int(time.time())
    key = sha256(str(timestamp).encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded)
    return ciphertext.hex()

if __name__ == "__main__":

    plaintext = "picoCTF{...}"
    result = encrypt(plaintext, key)
    print(f"Hint: The encryption was done around {timestamp} UTC\n")
    print(f"Ciphertext (hex): {ciphertext.hex()}\n")
```

This is a "weak seed" cryptography challenge. The security of AES depends entirely on the secrecy of the key, but here, the key is generated using a Unix timestamp. Since we have a hint about when the encryption occurred, we can "brute-force" the time to find the exact second that produces the correct key.

In the `encryption.py` script, the key is derived like this:

1. Take the current time (e.g., `1770242597`).
2. Hash that number as a string using SHA-256.
3. Use the first 16 bytes of that hash as the AES key.

Because we know the encryption happened "around" `1770242597`, we only need to check a small window of timestamps (e.g., a few minutes before and after) to find the one that successfully decrypts the ciphertext.

Here's the solution for this challenge:

```python
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

ciphertext_hex = "77c36bef0245021f9d9b7e396b52d2efbdbe6f8e4b79146e5d87c93416453b5f"
ciphertext = bytes.fromhex(ciphertext_hex)
hint_time = 1770242597

# Define a search window (e.g., 1000 seconds before and after the hint)
for t in range(hint_time - 1000, hint_time + 1000):
    # Replicate the key generation logic
    key = sha256(str(t).encode()).digest()[:16]

    try:
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = cipher.decrypt(ciphertext)

        plaintext = unpad(decrypted, AES.block_size)

        if b"picoCTF" in plaintext:
            print(f"Success! Timestamp: {t}")
            print(f"Flag: {plaintext.decode()}")
            break
    except (ValueError, KeyError):
        # Unpadding failed, move to the next timestamp
        continue
```

Here's the output:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FoslkuVCNtznA8BQxRtXH%252FScreenshot%2520%281843%29.png%3Falt%3Dmedia%26token%3D6ea715c4-8ca9-40f9-9ed4-8b0cacc13968&width=768&dpr=3&quality=100&sign=856c270&sv=2)

## ClusterRSA - 400pts

For this challenge, we are given a file called `message.txt`

Let's check the contents of `message.txt`:

```text
n = 8749002899132047699790752490331099938058737706735201354674975134719667510377522805717156720453193651
e = 65537
ct = 3891158515405030211396309867177046660195995913985068178988858029936868358096672572274111514200511662
```

This is a classic Multi-prime RSA challenge. Standard RSA uses two large primes (p and q), but as the challenge hint suggests ("someone got greedy"), this modulus (n) is composed of multiple smaller primes.

Because the primes are smaller than usual, we can factorize N relatively quickly using online databases or specialized algorithms.

## Step 1: Factorize N

The first step is to break nnn into its prime components. For numbers of this size in CTFs, the easiest tool is [factordb.com](http://factordb.com).

Input our n value: `8749002899132047699790752490331099938058737706735201354674975134719667510377522805717156720453193651`

We will find that n is composed of several primes.

## Step 2: Calculate ϕ(n)

In Multi-prime RSA, the Totient function ϕ(n) is calculated by taking each prime factor ​pi​ and multiplying (pi​−1) together:

$$
\phi(n) = (p_1 - 1)(p_2 - 1)\cdots(p_k - 1)
$$

## Step 3: Find the Private Key (d)

The decryption exponent d is the modular multiplicative inverse of e modulo ϕ(n):

$$
d \equiv e^{-1} \pmod{\phi(n)}
$$

## Step 4: Decrypt the Message

Once we have ddd, we can recover the original message mmm:

$$
m = ct^d \pmod{n}
$$

Instead of manually searching in FactorDB, we can automate the process since Python provides a module for FactorDB.

Here's the solution for this challenge:

```python
from factordb.factordb import FactorDB
from Crypto.Util.number import long_to_bytes

n = 8749002899132047699790752490331099938058737706735201354674975134719667510377522805717156720453193651
e = 65537
ct = 3891158515405030211396309867177046660195995913985068178988858029936868358096672572274111514200511662

# 1. Fetch factors from FactorDB
f = FactorDB(n)
f.connect()
primes = f.get_factor_list()

print(f"[*] Found {len(primes)} prime factors.")

# 2. Calculate Euler's Totient phi(n)
# For multi-prime RSA: phi = (p1-1) * (p2-1) * ... * (pk-1)
phi = 1
for p in primes:
    phi *= (p - 1)

# 3. Calculate Private Key d
d = pow(e, -1, phi)

# 4. Decrypt Ciphertext
m = pow(ct, d, n)

print("[+] Flag:", long_to_bytes(m).decode())
```

Here's the output:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FkA9Gzic891JEroRdSCdw%252FScreenshot%2520%281844%29.png%3Falt%3Dmedia%26token%3Dcd30dff8-b349-4fff-8aec-709621531178&width=768&dpr=3&quality=100&sign=16f78ba1&sv=2)

## Not TRUe - 400pts

For this challenge, we are given 2 files called `public.txt` and `encrypt.py`

Let's check the `public.txt`:

```text
N = 48
p = 3
q = 509
h = [422, 471, 321, 117, 407, 173, 345, 139, 26, 480, 200, 190, 20, 213, 456, 48, 380, 162, 443, 412, 197, 185, 249, 61, 64, 156, 372, 144, 287, 473, 164, 128, 491, 287, 152, 279, 344, 100, 414, 493, 87, 130, 366, 447, 471, 19, 119, 228]
ct = [[122, 197, 234, 359, 469, 298, 207, 475, 140, 477, 470, 247, 113, 445, 90, 88, 364, 175, 242, 152, 168, 101, 161, 105, 163, 272, 131, 220, 457, 498, 10, 152, 29, 282, 115, 333, 71, 433, 135, 369, 31, 93, 53, 134, 184, 319, 322, 298], [71, 499, 266, 318, 63, 210, 276, 170, 108, 327, 396, 3, 6, 68, 25, 415, 267, 104, 96, 334, 49, 451, 343, 434, 375, 205, 464, 188, 499, 489, 220, 159, 25, 311, 228, 275, 78, 86, 333, 311, 161, 86, 74, 217, 502, 163, 242, 18], [396, 215, 362, 369, 444, 449, 87, 234, 26, 423, 316, 241, 285, 237, 462, 479, 269, 176, 212, 19, 202, 23, 83, 218, 186, 124, 440, 496, 182, 29, 444, 144, 97, 368, 380, 247, 481, 209, 207, 102, 442, 291, 398, 65, 389, 128, 55, 4], [36, 204, 19, 186, 34, 107, 142, 120, 378, 425, 57, 231, 295, 477, 25, 385, 495, 170, 123, 186, 147, 372, 147, 57, 505, 219, 450, 168, 504, 3, 175, 234, 503, 479, 440, 416, 491, 209, 48, 461, 263, 459, 98, 492, 336, 497, 86, 367], [347, 240, 298, 149, 274, 475, 12, 137, 104, 159, 273, 40, 436, 457, 145, 44, 189, 351, 139, 440, 428, 216, 58, 433, 425, 256, 221, 80, 95, 325, 309, 322, 150, 406, 398, 54, 152, 103, 381, 353, 494, 338, 150, 167, 330, 16, 373, 496], [148, 489, 70, 294, 464, 307, 125, 291, 381, 128, 131, 225, 343, 281, 497, 482, 102, 195, 279, 52, 453, 41, 449, 221, 477, 467, 88, 265, 465, 500, 271, 225, 32, 460, 64, 431, 197, 124, 162, 485, 218, 328, 445, 318, 29, 342, 225, 373]]
```

Now let's check the `encrypt.py`:

```python
from random import randint
from sage.all import *

N = 48
p = 3
q = 509

R = PolynomialRing(ZZ, 'x')
x = R.gen()
R_modq = PolynomialRing(Integers(q), 'x').quotient(x**N - 1, 'xbar')
R_modp = PolynomialRing(Integers(p), 'x').quotient(x**N - 1, 'xbar')

def gen_poly():
    return R([randint(-1,1) for _ in range(N)])

def gen_msg(text):
    binary_str = ''.join(format(ord(char), '08b') for char in text)

    padding_length = (N - (len(binary_str) % N)) % N
    binary_str += '0' * padding_length

    chunks = [binary_str[i:i+N] for i in range(0, len(binary_str), N)]

    polynomials = [
        R([int(bit) for bit in chunk])
        for chunk in chunks
    ]

    return polynomials

def encrypt(h, m):
    r = gen_poly()
    return R_modq(p*(h*r) + m)

def generate_keys():
    while True:
        # Random ternary polynomials f and g
        f = gen_poly()
        g = gen_poly()

        # Check if f is invertible modulo p and q
        try:
            f_p_inv = R_modp(f)**-1
            f_q_inv = R_modq(f)**-1
            break
        except:
            continue

    h = R_modq(p*(f_q_inv*g))

    private_key = (f, g, f_p_inv, f_q_inv)
    public_key = h
    return public_key, private_key

with open("flag.txt", "r") as f:
    flag = f.read().strip()

public_key, private_key = generate_keys()
print(f"h = {public_key.list()}")

ciphertext = []
encoded = gen_msg(flag)
for part in encoded:
    ciphertext.append(encrypt(public_key, part))
ct = [c.list() for c in ciphertext]
print(f"ct = {ct}")

with open("public.txt", "w") as f:
    f.write(f"N = {N}\n")
    f.write(f"p = {p}\n")
    f.write(f"q = {q}\n")
    f.write(f"h = {public_key.list()}\n")
    f.write(f"ct = {ct}\n")
```

We're dealing with the **NTRU** (N-th degree Truncated Polynomial Ring) cryptosystem. Given the small parameters (N=48), this is highly vulnerable to a Lattice Attack using the **LLL** (Lenstra–Lenstra–Lovász) algorithm.

The public key h is defined by the relation f⋅h≡g(modq). Because f and g are "short" polynomials (coefficients in −1,0,1), we can construct a lattice where the vector (f,g) is an exceptionally short vector.

We build a 2N×2N matrix M:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FLKo9wgQzWTuWE1yHBlxY%252FScreenshot%2520%281845%29.png%3Falt%3Dmedia%26token%3Df7cd278b-ca7c-4629-af12-6b0aa9abbf30&width=768&dpr=3&quality=100&sign=d96d890a&sv=2)

Where H is the circulant matrix representing multiplication by h in the ring Rq​. The shortest vector in this lattice will likely reveal the private key f.

Here's the solution for this challenge:

```python
from sage.all import *

N = 48
p = 3
q = 509
h_list = [422, 471, 321, 117, 407, 173, 345, 139, 26, 480, 200, 190, 20, 213, 456, 48, 380, 162, 443, 412, 197, 185, 249, 61, 64, 156, 372, 144, 287, 473, 164, 128, 491, 287, 152, 279, 344, 100, 414, 493, 87, 130, 366, 447, 471, 19, 119, 228]
ct = [[122, 197, 234, 359, 469, 298, 207, 475, 140, 477, 470, 247, 113, 445, 90, 88, 364, 175, 242, 152, 168, 101, 161, 105, 163, 272, 131, 220, 457, 498, 10, 152, 29, 282, 115, 333, 71, 433, 135, 369, 31, 93, 53, 134, 184, 319, 322, 298], [71, 499, 266, 318, 63, 210, 276, 170, 108, 327, 396, 3, 6, 68, 25, 415, 267, 104, 96, 334, 49, 451, 343, 434, 375, 205, 464, 188, 499, 489, 220, 159, 25, 311, 228, 275, 78, 86, 333, 311, 161, 86, 74, 217, 502, 163, 242, 18], [396, 215, 362, 369, 444, 449, 87, 234, 26, 423, 316, 241, 285, 237, 462, 479, 269, 176, 212, 19, 202, 23, 83, 218, 186, 124, 440, 496, 182, 29, 444, 144, 97, 368, 380, 247, 481, 209, 207, 102, 442, 291, 398, 65, 389, 128, 55, 4], [36, 204, 19, 186, 34, 107, 142, 120, 378, 425, 57, 231, 295, 477, 25, 385, 495, 170, 123, 186, 147, 372, 147, 57, 505, 219, 450, 168, 504, 3, 175, 234, 503, 479, 440, 416, 491, 209, 48, 461, 263, 459, 98, 492, 336, 497, 86, 367], [347, 240, 298, 149, 274, 475, 12, 137, 104, 159, 273, 40, 436, 457, 145, 44, 189, 351, 139, 440, 428, 216, 58, 433, 425, 256, 221, 80, 95, 325, 309, 322, 150, 406, 398, 54, 152, 103, 381, 353, 494, 338, 150, 167, 330, 16, 373, 496], [148, 489, 70, 294, 464, 307, 125, 291, 381, 128, 131, 225, 343, 281, 497, 482, 102, 195, 279, 52, 453, 41, 449, 221, 477, 467, 88, 265, 465, 500, 271, 225, 32, 460, 64, 431, 197, 124, 162, 485, 218, 328, 445, 318, 29, 342, 225, 373]]

# 1. Lattice Attack (LLL) to find f
# Construct the NTRU Lattice Matrix
M = Matrix(ZZ, 2*N, 2*N)
for i in range(N):
    M[i, i] = 1
    for j in range(N):
        M[i, N + j] = h_list[(j - i) % N]
    M[N + i, N + i] = q

print("Running LLL algorithm...")
L = M.LLL()

# The short vector in L usually represents the secret key [f | g]
f_coeffs = [int(x) for x in L[0][:N]]
print(f"Recovered f: {f_coeffs}")

# 2. Setup rings for Decryption
R_ZZ.<x> = PolynomialRing(ZZ)
# Modulo q ring
Rq.<xq> = PolynomialRing(GF(q))
R_modq = Rq.quotient(xq^N - 1)
# Modulo p ring
Rp.<xp> = PolynomialRing(GF(p))
R_modp = Rp.quotient(xp^N - 1)

# Invert f modulo p
f_p_inv = R_modp(f_coeffs)^-1

def decrypt_chunk(c_list):
    # a = f * c (mod q)
    c_poly = R_modq(c_list)
    f_poly_q = R_modq(f_coeffs)
    a_poly = f_poly_q * c_poly
    
    # Lift to ZZ and center coefficients around 0 (range [-q/2, q/2])
    # This is necessary because NTRU decryption relies on a small 'a'
    a_centered = []
    for coeff in a_poly.list():
        val = Integer(coeff)
        if val > q // 2:
            val -= q
        a_centered.append(val)
    
    # m = f_p_inv * a (mod p)
    m_poly = f_p_inv * R_modp(a_centered)
    
    # Ensure result is N-length (bits)
    res = m_poly.list()
    return [int(b) for b in res] + [0] * (N - len(res))

# 3. Decrypt all chunks and rebuild the binary string
full_bits = ""
for chunk in ct:
    decrypted_bits = decrypt_chunk(chunk)
    full_bits += "".join(map(str, decrypted_bits))

# 4. Convert binary to ASCII
flag = ""
for i in range(0, len(full_bits), 8):
    byte = full_bits[i:i+8]
    if len(byte) == 8:
        # Convert bit-string to character
        char_code = int(byte, 2)
        if char_code != 0: # Ignore trailing nulls from padding
            flag += chr(char_code)

print(f"Flag: {flag}")
```

Here's the output:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FzeTJEMjeUejnlJwHTbqE%252FScreenshot%2520%281846%29.png%3Falt%3Dmedia%26token%3D6a959a2b-16fe-440b-95de-ea85ecd13de4&width=768&dpr=3&quality=100&sign=5173ed16&sv=2)

This Cryptography category during picoCTF 2026 turned out to be more interesting than I expected. At first, I thought it would require manual analysis or simple calculations, but I was surprised that almost everything had to be solved through scripting. Instead of relying on tools alone, I had to write Python scripts to automate the process, which made the challenge both more difficult and more enjoyable.
