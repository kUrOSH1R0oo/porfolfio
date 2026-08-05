---
title: "PicoCTF 2026: General Skills"
date: 03-20-2026
excerpt: PicoCTF 2026 Writeup
cover: ../uploads/cover_picogeneralskills.jpg
tags: GTFOBins, SMB-Enumeration, Pwntools, Web-Exploitation
---

Good day, everyone! Today, I’ll be walking you through the challenges I’ve successfully solved in the General Skills category of picoCTF 2026!

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

```shell
cat part_aa part_ab part_ac part_ad part_ae > flag.zip
```

This creates a single zip file named `flag.zip` containing all parts.

The file is protected with the password `supersecret`. To extract it, run:

```shell
unzip flag.zip
```

After extraction, a file such as `flag.txt` will appear in the directory.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FEAwOqCDgTlAHSMNJAoVp%252FScreenshot%2520%281622%29.png%3Falt%3Dmedia%26token%3Dcfa3a2b1-38f3-4b5f-a5db-b289634b3791&width=768&dpr=3&quality=100&sign=4d628c33&sv=2)

## bytemancy 0 - 50pts

For this challenge, we are given a file called `app.py` .

```python
while(True):
  try:
    print('⊹──────[ BYTEMANCY-0 ]──────⊹')
    print("☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐")
    print()
    print('Send me ASCII DECIMAL 101, 101, 101, side-by-side, no space.')
    print()
    print("☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐")
    print('⊹─────────────⟡─────────────⊹')
    user_input = input('==> ')
    if user_input == "\x65\x65\x65":
      print(open("./flag.txt", "r").read())
      break
    else:
      print("That wasn't it. I got: " + str(user_input))
      print()
      print()
      print()
  except Exception as e:
    print(e)
    break
```

Take a closer look at the condition, `"\x65"` is **hexadecimal for 101 in decimal**, which corresponds to the ASCII character `'e'`. Therefore, `"\x65\x65\x65"` is the string `'eee'`. All we need to do is to type `'eee'` and the program will provide the flag. Now let's connect to the server:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F541kkxBPMDbwXYggMuBD%252FScreenshot%2520%281624%29.png%3Falt%3Dmedia%26token%3D8a099b7d-a63d-42b2-ae27-158b1f9454e1&width=768&dpr=3&quality=100&sign=e08532a2&sv=2)

## Printer Shares - 50pts

In this challenge, credentials for an SMB server were provided. After enumerating the available shares using `smbclient`, the following shares were discovered:

```shell
smbclient -L //mysterious-sea.picoctf.net -p 63048 -N
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F1ZwfAMPlSnYsWc5uAZ5e%252FScreenshot%2520%281638%29.png%3Falt%3Dmedia%26token%3Daa622a14-a648-449c-a5bc-ffff5cc1ba55&width=768&dpr=3&quality=100&sign=baf34955&sv=2)

We found an available share from the share list, so we attempted to connect to it and check its contents.

```shell
smbclient //mysterious-sea.picoctf.net/shares -p 63048 -N
```

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

```shell
git config user.name "root"
```

```shell
git config user.email "root@picoctf"
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FOfp46brJI2HWWAsRxXYM%252FScreenshot%2520%281643%29.png%3Falt%3Dmedia%26token%3D3e466edb-ff3d-4125-94a6-b1683269189c&width=768&dpr=3&quality=100&sign=1783c93a&sv=2)

Step 2: Create `flag.txt`

```shell
echo "BlahBlah" > flag.txt
```

```shell
git add flag.txt
```

```shell
git commit -m "push flag.txt"
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fh41gV9zWvCteOgFyxCwo%252FScreenshot%2520%281644%29.png%3Falt%3Dmedia%26token%3D84cddd34-ba34-4104-b4e6-69de26dd6475&width=768&dpr=3&quality=100&sign=19938061&sv=2)

Even if the file is empty or contains dummy text, it doesn’t matter — the server only checks the **commit author**.

Step 3: Push to the repo

```shell
git push origin master
```

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

```shell
cupp -i
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FPxDPrWuZmFogS6npXgx2%252FScreenshot%2520%281651%29.png%3Falt%3Dmedia%26token%3De7030ae4-d1a5-47a3-ba0a-84c91ed580cb&width=768&dpr=3&quality=100&sign=978bc643&sv=2)

This is all you need, leave other fields empty, only follow the `user-info.txt` .

Now this is the `check_password.py`

```python
#!/usr/bin/env python3
import hashlib

HASH_FILE = "hash.txt"
WORDLIST_FILE = "alice.txt" # wordlist that was generated using CUPP

def load_hash():
    with open(HASH_FILE, "r") as f:
        return f.read().strip()

def crack_password(target_hash):
    with open(WORDLIST_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for password in f:
            password = password.strip()
            if hashlib.sha1(password.encode()).hexdigest() == target_hash:
                return password
    return None

if __name__ == "__main__":
    target_hash = load_hash()
    result = crack_password(target_hash)
    if result:
        print(f"Password found: picoCTF{{{result}}}")
    else:
        print("No match found.")
```

So it's a pre-build password cracker for us, all we need to do is to change the name of wordlist file, to the filename of our wordlist.

Now let's run it

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FKYsZFMR0oKD75ECwZU9E%252FScreenshot%2520%281653%29.png%3Falt%3Dmedia%26token%3D345aa25b-9f80-4509-98b1-7ac8eeafae9d&width=768&dpr=3&quality=100&sign=2e808d1a&sv=2)

## KSECRETS - 100pts

We are provided a file named `kubeconfig` and a server that we can connect with.

Let's check the contents of `kubeconfig`

```text
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJkekNDQVIyZ0F3SUJBZ0lCQURBS0JnZ3Foa2pPUFFRREFqQWpNU0V3SHdZRFZRUUREQmhyTTNNdGMyVnkKZG1WeUxXTmhRREUzTnpNeU9Ua3dNemd3SGhjTk1qWXdNekV5TURjd016VTRXaGNOTXpZd016QTVNRGN3TXpVNApXakFqTVNFd0h3WURWUVFEREJock0zTXRjMlZ5ZG1WeUxXTmhRREUzTnpNeU9Ua3dNemd3V1RBVEJnY3Foa2pPClBRSUJCZ2dxaGtqT1BRTUJCd05DQUFRK09DeEMzYTJhYWQzUC9zNHZUeUl0bjBmNjJaQ0hGelNDLzVZM0duLy8KbjRoRVkrekZ0aG9uQUFIbEw0OXRmcTJ6K0h1NDErbk9aYTh5MjMybklmS0VvMEl3UURBT0JnTlZIUThCQWY4RQpCQU1DQXFRd0R3WURWUjBUQVFIL0JBVXdBd0VCL3pBZEJnTlZIUTRFRmdRVSs1SUU5NHV5TERqb0RXVDV1dWRmCkFFSnIzN1V3Q2dZSUtvWkl6ajBFQXdJRFNBQXdSUUloQUp5ZStuelpMNEthVGhrTWxRZHBkZ2Jyc1NxMVBOTlUKcmllbGdZdEFxVHJwQWlBUWZHY2EyVW1UY2s5ODFXa2tDbXBNNHhrQzRGY0Znc2J4WmliblBJNDVidz09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K
    server: https://127.0.0.1:6443
  name: default
contexts:
- context:
    cluster: default
    user: default
  name: default
current-context: default
kind: Config
users:
- name: default
  user:
    client-certificate-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJrVENDQVRlZ0F3SUJBZ0lJWDI2NVMzWkJLNUV3Q2dZSUtvWkl6ajBFQXdJd0l6RWhNQjhHQTFVRUF3d1kKYXpOekxXTnNhV1Z1ZEMxallVQXhOemN6TWprNU1ETTRNQjRYRFRJMk1ETXhNakEzTURNMU9Gb1hEVEkzTURNeApNakEzTURNMU9Gb3dNREVYTUJVR0ExVUVDaE1PYzNsemRHVnRPbTFoYzNSbGNuTXhGVEFUQmdOVkJBTVRESE41CmMzUmxiVHBoWkcxcGJqQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJQcnZnNlhpeGNWdFVPZmcKbE1yT3E3TkQ1KzdCSkZXS3EybkE4UFlTa1dtR1JaLzZKbW9nVjZ4ZHh2d1g1bU05NmU3VmpWcGNLdXZ4TEw1QwpYeDU4cU55alNEQkdNQTRHQTFVZER3RUIvd1FFQXdJRm9EQVRCZ05WSFNVRUREQUtCZ2dyQmdFRkJRY0RBakFmCkJnTlZIU01FR0RBV2dCUlB6ODJydEN0WkxmNVpmQ3B5M2d3dXFuQmMvakFLQmdncWhrak9QUVFEQWdOSUFEQkYKQWlBU2QwSkNnU3RCc0tlWmI3YWVvNnNyWTRTMHpxakE1MnNtbThOa0lqK2JKUUloQVB0QUlQd3BIeGg1a2FGSgo4dExSUXFaMGltVFVhcWROT1c5Zk9jNnhudzZTCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJkekNDQVIyZ0F3SUJBZ0lCQURBS0JnZ3Foa2pPUFFRREFqQWpNU0V3SHdZRFZRUUREQmhyTTNNdFkyeHAKWlc1MExXTmhRREUzTnpNeU9Ua3dNemd3SGhjTk1qWXdNekV5TURjd016VTRXaGNOTXpZd016QTVNRGN3TXpVNApXakFqTVNFd0h3WURWUVFEREJock0zTXRZMnhwWlc1MExXTmhRREUzTnpNeU9Ua3dNemd3V1RBVEJnY3Foa2pPClBRSUJCZ2dxaGtqT1BRTUJCd05DQUFUYTRrTUM4R0N2eU5rWFpHQzIwZjVTN1F2U3dkbnNPQU5kZmJ5NGZDZ3EKamxvRlAvK1dxbXZBVmJmY2F4Z05NRVVGemY1MUdBajRlWUNCYzBSbWl3andvMEl3UURBT0JnTlZIUThCQWY4RQpCQU1DQXFRd0R3WURWUjBUQVFIL0JBVXdBd0VCL3pBZEJnTlZIUTRFRmdRVVQ4L05xN1FyV1MzK1dYd3FjdDRNCkxxcHdYUDR3Q2dZSUtvWkl6ajBFQXdJRFNBQXdSUUloQUxJWHVldkNVZmE1cmFVQ0FVbjR5U2svVFp5Q1BZQkIKT2FnVXBpTUxXT040QWlBcUxXNkRZbUxKZC9MWExxZ29sNFlKTW5VRFhhOGw0RmxPd1ovb01uMFVvQT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K
    client-key-data: LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSUVNVDdiRFNURERMQ0F6OTVCYTJQbys1VUI1UGdYNnlsN1ZSS3pLQy9la1lvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFK3UrRHBlTEZ4VzFRNStDVXlzNnJzMFBuN3NFa1ZZcXJhY0R3OWhLUmFZWkZuL29tYWlCWApyRjNHL0JmbVl6M3A3dFdOV2x3cTYvRXN2a0pmSG55bzNBPT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo=
```

This is a **Kubernetes secrets extraction challenge**. We already have the `kubeconfig`, so the goal is to connect to the cluster → list secrets → decode them → get the flag.

For this challenge, we will need `kubectl` for this, you can install it via `apt`

Once installed, the first thing that we do is to list the namespaces

```shell
kubectl --kubeconfig kubeconfig --insecure-skip-tls-verify=true --server https://green-hill.picoctf.net:55327 get ns
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fzo9fMc2axDZB11OkoVAx%252FScreenshot%2520%281658%29.png%3Falt%3Dmedia%26token%3D0564e8d3-34bd-4398-b070-0c97bd050d6c&width=768&dpr=3&quality=100&sign=9ab13b5&sv=2)

So we have a `picoctf` namespace, now let's get the secrets of `picoctf` namespace

```shell
kubectl --kubeconfig kubeconfig --insecure-skip-tls-verify=true --server https://green-hill.picoctf.net:55327 get secrets -n picoctf
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F3xUy50KyyhTx4deCHGKa%252FScreenshot%2520%281659%29.png%3Falt%3Dmedia%26token%3Dd9d2feb4-eae7-4c65-b35e-2c95a4903cf7&width=768&dpr=3&quality=100&sign=c4f00d64&sv=2)

Now all we need to do is to dump the secret named `ctf-secret`

```shell
kubectl --kubeconfig kubeconfig --insecure-skip-tls-verify=true --server https://green-hill.picoctf.net:55327 get secret ctf-secr
et -n picoctf -o yaml
```

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

```python
while(True):
  try:
    print('⊹──────[ BYTEMANCY-1 ]──────⊹')
    print("☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐")
    print()
    print('Send me ASCII DECIMAL 101 1751 times, side-by-side, no space.')
    print()
    print("☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐")
    print('⊹─────────────⟡─────────────⊹')
    user_input = input('==> ')
    if user_input == "\x65"*1751:
      print(open("./flag.txt", "r").read())
      break
    else:
      print("That wasn't it. I got: " + str(user_input))
      print()
      print()
      print()
  except Exception as e:
    print(e)
    break
```

The core logic of this code is a simple input check: it repeatedly prompts the user to enter a string, and if that string exactly matches 1751 repetitions of the ASCII character with decimal code 101 (which is `'e'`), it prints the flag and exits; otherwise, it tells the user their input was incorrect and loops again. Essentially, the program is just testing whether you can correctly generate and provide the specific byte sequence (`"e"*1751`) that satisfies the equality check.

Since we don't want to type `e` manually 1751 times, we will automate this using `pwntools`

```python
from pwn import *

host = "foggy-cliff.picoctf.net"
port = 58994

r = remote(host, port)
r.recvuntil(b"==>")
payload = b"e" * 1751
r.sendline(payload)
r.interactive()
```

This will send `1751 e` to the server and get the flag

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fe6lgPFw13YJz5sBL7j5D%252FScreenshot%2520%281666%29.png%3Falt%3Dmedia%26token%3D1c7e31fa-e99e-496a-93c3-4a767cf9f3aa&width=768&dpr=3&quality=100&sign=9dbe415e&sv=2)

## Undo - 100pts

For this challenge, we are given a server that we can connect on using `nc`

Basically it's just a question-based CTF and we will Identify it how we can reverse the encoded text, here's the full answer:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FhCIJWjAn52KjDX1uwsYS%252FScreenshot%2520%281667%29.png%3Falt%3Dmedia%26token%3D9cd03571-e793-4cd4-8b53-7d1e585fd40b&width=768&dpr=3&quality=100&sign=3cafed16&sv=2)

## MultiCode - 200pts

For this challenge, we are given a file called `message.txt`

Let's open the `message.txt`

```text
NjM3NjcwNjI1MDQ3NTMyNTM3NDI2MTcyNjY2NzcyNzE1ZjcyNjE3MDMwNzE3NjYxNzQ1ZjM0MzgzMTczMzAzNjM0NzAyNTM3NDQ=
```

Now according to the hint given:

*The flag has been wrapped in several layers of common encodings such as ROT13, URL encoding, Hex, and Base64. Can you figure out the order to peel them back?*

So it's a multiple encoding process, we can use CyberChef for this challenge to chain the decoding process.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FQt1ahABabZz88EkPvjAn%252FScreenshot%2520%281669%29.png%3Falt%3Dmedia%26token%3Dbcb3d292-3e0d-4b6f-9bd0-7f112b74b44b&width=768&dpr=3&quality=100&sign=8efb5f6e&sv=2)

## bytemancy 2 - 200pts

For this challenge, we are given a file called `app.py` and a server that we can connect with using `netcat`

Let's check the contents of `app.py`

```python
import sys

while(True):
  try:
    print('⊹──────[ BYTEMANCY-2 ]──────⊹')
    print("☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐")
    print()
    print('Send me the HEX BYTE 0xFF 3 times, side-by-side, no space.')
    print()
    print("☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐")
    print('⊹─────────────⟡─────────────⊹')
    print('==> ', end='', flush=True)
    user_input = sys.stdin.buffer.readline().rstrip(b"\n")
    if user_input == b"\xff\xff\xff":
      print(open("./flag.txt", "r").read())
      break
    else:
      print("That wasn't it. I got: " + str(user_input))
      print()
      print()
      print()
  except Exception as e:
    print(e)
    break
```

The core logic is that the program repeatedly prompts for input and checks whether it exactly matches **three consecutive bytes of value 0xFF** (`b"\xff\xff\xff"`). It reads input as raw bytes, not text, so ordinary characters won’t work; only the precise sequence of three `0xFF` bytes satisfies the condition, at which point it prints the flag. To solve it, we simply send those three bytes side-by-side without any extra characters or spaces, we can utilize `pwntools` again for this challenge

```python
from pwn import *

host = "lonely-island.picoctf.net"
port = 64673

r = remote(host, port)

payload = b"\xff\xff\xff"

r.sendline(payload)
r.interactive()
```

Here's the output

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fl2pLpNRvTcfLxqRb4j25%252FScreenshot%2520%281670%29.png%3Falt%3Dmedia%26token%3D5c38646b-1d88-4a26-a0cf-695923bd73cd&width=768&dpr=3&quality=100&sign=c1cea485&sv=2)

## Printer Shares 2 - 200pts

In this challenge, credentials for an SMB server were provided. After enumerating the available shares using `smbclient`, the following shares were discovered:

```shell
smbclient -L //green-hill.picoctf.net -p 57305 -N
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FQapnw9XPErAw5NrRRAH3%252FScreenshot%2520%281672%29.png%3Falt%3Dmedia%26token%3Dcde26eb3-36d3-40db-827e-3a1a4c70cc40&width=768&dpr=3&quality=100&sign=8037cab8&sv=2)

So it has a `secure-shares` , I tried to access it but yeah as expected, it's restricted.

```shell
smbclient //green-hill.picoctf.net/shares -p 57305 -N
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FTMORLQNMYskMtrwayBrH%252FScreenshot%2520%281673%29.png%3Falt%3Dmedia%26token%3Db6d245d2-a88a-4f51-926c-28235f3dcc09&width=768&dpr=3&quality=100&sign=b029e95f&sv=2)

Inside I've found `content.txt` , `kafka.txt`, `notification.txt`

Here's the content:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F74tdtfYLgwFkP5O0SgHz%252FScreenshot%2520%281674%29.png%3Falt%3Dmedia%26token%3D4d268efa-9b0c-4cd3-9aeb-cf32fa2821d9&width=768&dpr=3&quality=100&sign=e9443&sv=2)

So in the `notification.txt` , it's clear that `joe` is our user. Now according to the hint, `rockyou.txt` is being mentioned, it means `joe` has access to `secret-shares` all we need to do is to bruteforce the password. I've found a script in [Github](https://gist.github.com/shoriwe/851d5e27317ac8fec9954f00a0b8a701) that we can use for this challenge.

I only have to write the user and domain into a file and it's ready to go

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fw94keMwwbnnFYmikrJ4A%252FScreenshot%2520%281678%29.png%3Falt%3Dmedia%26token%3D1b733a8f-75fa-4ccb-98e1-885225456c21&width=768&dpr=3&quality=100&sign=cb7d2720&sv=2)

So the pasword is `popcorn`, now let's connect to the SMB again using `joe`

```shell
smbclient //green-hill.picoctf.net/secure-shares -p 57305 -U joe
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FH9vXnGamJILylnlR9b8F%252FScreenshot%2520%281680%29.png%3Falt%3Dmedia%26token%3Df8542a9c-7f99-4e48-a2eb-a7b97b7ada7b&width=768&dpr=3&quality=100&sign=c952c7a&sv=2)

Now we can get the `flag.txt`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FG9DKDYLq3zuyqPui4Vuu%252FScreenshot%2520%281681%29.png%3Falt%3Dmedia%26token%3D34038c10-bdc2-4f17-831b-a14dd099f298&width=768&dpr=3&quality=100&sign=cf3a558f&sv=2)

## ABSOLUTE NANO - 200pts

For this challenge, we are given an SSH server that we can connect with.

When I check what we can execute as root, I saw `nano`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F0eBTYbZBkC8YaKWPi7kf%252FScreenshot%2520%281685%29.png%3Falt%3Dmedia%26token%3Daa351d09-20e5-47f7-9c0c-8d17beb587a2&width=768&dpr=3&quality=100&sign=932356e2&sv=2)

It turns out that we can edit `/etc/sudoers` file.

```shell
sudo nano /etc/sudoers
```

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

```python
from flask import Flask, render_template
from dotenv import load_dotenv
from flask_limiter import Limiter
import os

load_dotenv()

app = Flask(__name__)

# Custom key function for global rate limiting
def global_rate_limit_key():
    return "global"

# Initialize rate limiter with global key function
limiter = Limiter(
    key_func=global_rate_limit_key,
    app=app,
    default_limits=["300 per minute"]
)

# Custom error handler for rate limit exceeded
@app.errorhandler(429)
def ratelimit_exceeded(e):
    return "Service Unavailable: Rate limit exceeded", 503

@app.route('/')
@limiter.limit("300 per minute")
def home():
    print("value:", os.getenv("IS_BACKUP"))
    if os.getenv("IS_BACKUP") == "yes":
        flag = os.getenv("FLAG")
    else:
        flag = "No flag in this service"
    return render_template("index.html", flag=flag)
```

Now let's check the `haproxy.cfg`

```text
# haproxy.cfg
global
    log stdout format raw local0
    maxconn 1000

defaults
    log global
    mode http
    timeout connect 5s
    timeout client 10s
    timeout server 10s

frontend http-in
    bind *:80
    default_backend servers

backend servers
    option httpchk GET /
    http-check expect status 200
    server s1 *:8000 check inter 2s fall 2 rise 3
    server s2 *:9000 check backup inter 2s fall 2 rise 3
```

The Flask application reveals that the flag is only returned when the environment variable `IS_BACKUP` is set to `"yes"`. In the normal case, the service returns `"No flag in this service"`, meaning the primary server does not contain the flag, while the backup service likely does. The application also uses a **global rate limiter** with a limit of 300 requests per minute, and once the limit is exceeded, the server returns a 503 response. Because the rate limit key is hardcoded to `"global"`, the limit applies to all users collectively instead of per‑IP, meaning repeated requests can affect the availability of the entire service. This detail suggests that the rate limiter can be abused to disrupt the primary service.

The HAProxy configuration shows that traffic is sent to server `s1` on port 8000 by default, while server `s2` on port 9000 is marked as a **backup server**. HAProxy performs health checks using `GET /`, and if the primary server fails to respond with status 200, traffic is automatically redirected to the backup server. Since the Flask code only reveals the flag when running in backup mode, the goal is to force HAProxy to consider the primary server unhealthy. This can be done by sending more than 300 requests per minute to trigger the rate limiter, causing the primary server to return errors during the health check. Once HAProxy detects the failure, it switches to the backup server, where `IS_BACKUP=yes` is set, allowing the flag to be returned in the response.

All we need to do is to flood it:>>

```shell
seq 1 700 | xargs -P50 -I{} curl -s http://mysterious-sea.picoctf.net:54985/ > /dev/null
```

This exploit works perfectly because the Flask application uses a **global rate limit of 300 requests per minute**, meaning all requests share the same limit instead of being limited per user. The command sends **700 requests in parallel using** `xargs -P50`, which quickly exceeds the allowed limit and causes the primary server to return errors. Since HAProxy continuously checks the primary server with health checks, these errors make it appear unhealthy, forcing HAProxy to switch to the **backup server**, where the environment variable `IS_BACKUP=yes` is set. Once traffic is routed to the backup instance, the application reveals the flag, making this flood request the ideal way to trigger the failover and obtain the flag.

After we flood it, let's visit the website

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FByjBKS8sn0GqNfYvgHcP%252FScreenshot%2520%281692%29.png%3Falt%3Dmedia%26token%3D1ad241c9-9da9-4efb-9a6a-8626cae8f25d&width=768&dpr=3&quality=100&sign=8098f99d&sv=2)

## Printer Shares 3 - 300pts

For this challenge, we are given an SMB server that we can connect to.

```shell
smbclient -L //dolphin-cove.picoctf.net -p 56828 -N
```

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

```python
import os
import random
import select
import sys
from typing import Optional
from pwn import ELF, p32

BANNER = "⊹──────[ BYTEMANCY-3 ]──────⊹"
BINARY_PATH = os.path.join(os.path.dirname(__file__), "spellbook")
QUESTION_COUNT = 3

SPELLBOOK_FUNCTIONS = [
    "ember_sigil",
    "glyph_conflux",
    "astral_spark",
    "binding_word",
]


def read_exact_bytes(expected_len: int) -> Optional[bytes]:
    """Read a fixed number of bytes from stdin, trimming a trailing newline."""
    stdin_buffer = sys.stdin.buffer
    buf = stdin_buffer.read(expected_len)
    if not buf or len(buf) < expected_len:
        return None

    # Discard trailing newlines only if more bytes are immediately available
    try:
        stdin_fileno = sys.stdin.fileno()
    except (AttributeError, ValueError, OSError):
        stdin_fileno = None

    if stdin_fileno is not None:
        while True:
            readable, _, _ = select.select([stdin_fileno], [], [], 0)
            if not readable:
                break

            peek = stdin_buffer.peek(1)[:1]
            if peek in (b"\n", b"\r"):
                stdin_buffer.read(1)
                continue
            break

    return buf


def main():
    try:
        elf = ELF(BINARY_PATH, checksec=False)
    except FileNotFoundError:
        print("The spellbook is missing!")
        return

    flag = open("./flag.txt", "r").read().strip()

    while True:
        try:
            print(BANNER)
            print("☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐")
            print()
            print("I will name four procedures hidden inside spellbook.")
            print(
                f"Each round, send me their *raw* 4-byte addresses "
                f"in little-endian form. {QUESTION_COUNT} correct answers unlock the flag."
            )
            print()
            print("☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐")
            print('⊹─────────────⟡─────────────⊹')

            selections = random.sample(SPELLBOOK_FUNCTIONS, QUESTION_COUNT)
            success = True

            for idx, symbol in enumerate(selections, 1):
                target_addr = elf.symbols[symbol]
                expected_bytes = p32(target_addr)

                print(
                    f"[{idx}/{QUESTION_COUNT}] Send the 4-byte little-endian "
                    f"address for procedure '{symbol}'."
                )
                print("==> ", end='', flush=True)
                user_bytes = read_exact_bytes(len(expected_bytes))

                if user_bytes is None:
                    print("\nI needed four bytes, traveler.")
                    success = False
                    break

                if user_bytes != expected_bytes:
                    print("\nThose aren't the right runes.")
                    success = False
                    break

            if success:
                print(flag)
                break

            print()
            print("The aether rejects your incantation. Try again.\n")
        except EOFError:
            break
        except Exception as exc:
            print(exc)
            break


if __name__ == "__main__":
    main()
```

The Python script asks for the addresses of these functions:

* `ember_sigil`
* `glyph_conflux`
* `astral_spark`
* `binding_word`

Now let's check the `spellbook`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FMmNrMLAYpgHh2JG03Cs8%252FScreenshot%2520%281718%29.png%3Falt%3Dmedia%26token%3Dd24b3040-8e78-454a-965e-99570024b468&width=768&dpr=3&quality=100&sign=6f31b849&sv=2)

At first, I thought it was a txt file but it turns out to be an executable file. Let's change its permission and execute it.

```shell
chmod +x spellbook
```

When I run it, it gives me nothing. Now let's use `objdump` to analyze the binary

```shell
objump -d ./spellbook
```

```asm
Disassembly of section .init:

08049000 <_init>:
 8049000:   f3 0f 1e fb                 endbr32
 8049004:   53                          push   %ebx
 8049005:   83 ec 08                    sub    $0x8,%esp
 8049008:   e8 a3 00 00 00              call   80490b0 <__x86.get_pc_thunk.bx>
 804900d:   81 c3 07 23 00 00           add    $0x2307,%ebx
 8049013:   8b 83 fc ff ff ff           mov    -0x4(%ebx),%eax
 8049019:   85 c0                       test   %eax,%eax
 804901b:   74 02                       je     804901f <_init+0x1f>
 804901d:   ff d0                       call   *%eax
 804901f:   83 c4 08                    add    $0x8,%esp
 8049022:   5b                          pop    %ebx
 8049023:   c3                          ret

Disassembly of section .plt:

08049030 <.plt>:
 8049030:   ff 35 18 b3 04 08           push   0x804b318
 8049036:   ff 25 1c b3 04 08           jmp    *0x804b31c
 804903c:   0f 1f 40 00                 nopl   0x0(%eax)
 8049040:   f3 0f 1e fb                 endbr32
 8049044:   68 00 00 00 00              push   $0x0
 8049049:   e9 e2 ff ff ff              jmp    8049030 <.plt>
 804904e:   66 90                       xchg   %ax,%ax

Disassembly of section .plt.sec:

08049050 <__libc_start_main@plt>:
 8049050:   f3 0f 1e fb                 endbr32
 8049054:   ff 25 20 b3 04 08           jmp    *0x804b320
 804905a:   66 0f 1f 44 00 00           nopw   0x0(%eax,%eax,1)

Disassembly of section .text:

08049060 <_start>:
 8049060:   f3 0f 1e fb                 endbr32
 8049064:   31 ed                       xor    %ebp,%ebp
 8049066:   5e                          pop    %esi
 8049067:   89 e1                       mov    %esp,%ecx
 8049069:   83 e4 f0                    and    $0xfffffff0,%esp
 804906c:   50                          push   %eax
 804906d:   54                          push   %esp
 804906e:   52                          push   %edx
 804906f:   e8 23 00 00 00              call   8049097 <_start+0x37>
 8049074:   81 c3 a0 22 00 00           add    $0x22a0,%ebx
 804907a:   8d 83 ec df ff ff           lea    -0x2014(%ebx),%eax
 8049080:   50                          push   %eax
 8049081:   8d 83 7c df ff ff           lea    -0x2084(%ebx),%eax
 8049087:   50                          push   %eax
 8049088:   51                          push   %ecx
 8049089:   56                          push   %esi
 804908a:   c7 c0 14 92 04 08           mov    $0x8049214,%eax
 8049090:   50                          push   %eax
 8049091:   e8 ba ff ff ff              call   8049050 <__libc_start_main@plt>
 8049096:   f4                          hlt
 8049097:   8b 1c 24                    mov    (%esp),%ebx
 804909a:   c3                          ret
 804909b:   66 90                       xchg   %ax,%ax
 804909d:   66 90                       xchg   %ax,%ax
 804909f:   90                          nop

080490a0 <_dl_relocate_static_pie>:
 80490a0:   f3 0f 1e fb                 endbr32
 80490a4:   c3                          ret
 80490a5:   66 90                       xchg   %ax,%ax
 80490a7:   66 90                       xchg   %ax,%ax
 80490a9:   66 90                       xchg   %ax,%ax
 80490ab:   66 90                       xchg   %ax,%ax
 80490ad:   66 90                       xchg   %ax,%ax
 80490af:   90                          nop

080490b0 <__x86.get_pc_thunk.bx>:
 80490b0:   8b 1c 24                    mov    (%esp),%ebx
 80490b3:   c3                          ret
 80490b4:   66 90                       xchg   %ax,%ax
 80490b6:   66 90                       xchg   %ax,%ax
 80490b8:   66 90                       xchg   %ax,%ax
 80490ba:   66 90                       xchg   %ax,%ax
 80490bc:   66 90                       xchg   %ax,%ax
 80490be:   66 90                       xchg   %ax,%ax

080490c0 <deregister_tm_clones>:
 80490c0:   b8 30 b3 04 08              mov    $0x804b330,%eax
 80490c5:   3d 30 b3 04 08              cmp    $0x804b330,%eax
 80490ca:   74 24                       je     80490f0 <deregister_tm_clones+0x30>
 80490cc:   b8 00 00 00 00              mov    $0x0,%eax
 80490d1:   85 c0                       test   %eax,%eax
 80490d3:   74 1b                       je     80490f0 <deregister_tm_clones+0x30>
 80490d5:   55                          push   %ebp
 80490d6:   89 e5                       mov    %esp,%ebp
 80490d8:   83 ec 14                    sub    $0x14,%esp
 80490db:   68 30 b3 04 08              push   $0x804b330
 80490e0:   ff d0                       call   *%eax
 80490e2:   83 c4 10                    add    $0x10,%esp
 80490e5:   c9                          leave
 80490e6:   c3                          ret
 80490e7:   8d b4 26 00 00 00 00        lea    0x0(%esi,%eiz,1),%esi
 80490ee:   66 90                       xchg   %ax,%ax
 80490f0:   c3                          ret
 80490f1:   8d b4 26 00 00 00 00        lea    0x0(%esi,%eiz,1),%esi
 80490f8:   8d b4 26 00 00 00 00        lea    0x0(%esi,%eiz,1),%esi
 80490ff:   90                          nop

08049100 <register_tm_clones>:
 8049100:   b8 30 b3 04 08              mov    $0x804b330,%eax
 8049105:   2d 30 b3 04 08              sub    $0x804b330,%eax
 804910a:   89 c2                       mov    %eax,%edx
 804910c:   c1 e8 1f                    shr    $0x1f,%eax
 804910f:   c1 fa 02                    sar    $0x2,%edx
 8049112:   01 d0                       add    %edx,%eax
 8049114:   d1 f8                       sar    $1,%eax
 8049116:   74 20                       je     8049138 <register_tm_clones+0x38>
 8049118:   ba 00 00 00 00              mov    $0x0,%edx
 804911d:   85 d2                       test   %edx,%edx
 804911f:   74 17                       je     8049138 <register_tm_clones+0x38>
 8049121:   55                          push   %ebp
 8049122:   89 e5                       mov    %esp,%ebp
 8049124:   83 ec 10                    sub    $0x10,%esp
 8049127:   50                          push   %eax
 8049128:   68 30 b3 04 08              push   $0x804b330
 804912d:   ff d2                       call   *%edx
 804912f:   83 c4 10                    add    $0x10,%esp
 8049132:   c9                          leave
 8049133:   c3                          ret
 8049134:   8d 74 26 00                 lea    0x0(%esi,%eiz,1),%esi
 8049138:   c3                          ret
 8049139:   8d b4 26 00 00 00 00        lea    0x0(%esi,%eiz,1),%esi

08049140 <__do_global_dtors_aux>:
 8049140:   f3 0f 1e fb                 endbr32
 8049144:   80 3d 30 b3 04 08 00        cmpb   $0x0,0x804b330
 804914b:   75 1b                       jne    8049168 <__do_global_dtors_aux+0x28>
 804914d:   55                          push   %ebp
 804914e:   89 e5                       mov    %esp,%ebp
 8049150:   83 ec 08                    sub    $0x8,%esp
 8049153:   e8 68 ff ff ff              call   80490c0 <deregister_tm_clones>
 8049158:   c6 05 30 b3 04 08 01        movb   $0x1,0x804b330
 804915f:   c9                          leave
 8049160:   c3                          ret
 8049161:   8d b4 26 00 00 00 00        lea    0x0(%esi,%eiz,1),%esi
 8049168:   c3                          ret
 8049169:   8d b4 26 00 00 00 00        lea    0x0(%esi,%eiz,1),%esi

08049170 <frame_dummy>:
 8049170:   f3 0f 1e fb                 endbr32
 8049174:   eb 8a                       jmp    8049100 <register_tm_clones>

08049176 <ember_sigil>:
 8049176:   f3 0f 1e fb                 endbr32
 804917a:   55                          push   %ebp
 804917b:   89 e5                       mov    %esp,%ebp
 804917d:   e8 05 01 00 00              call   8049287 <__x86.get_pc_thunk.ax>
 8049182:   05 92 21 00 00              add    $0x2192,%eax
 8049187:   8b 55 08                    mov    0x8(%ebp),%edx
 804918a:   81 f2 37 13 37 13           xor    $0x13371337,%edx
 8049190:   8b 80 18 00 00 00           mov    0x18(%eax),%eax
 8049196:   01 d0                       add    %edx,%eax
 8049198:   5d                          pop    %ebp
 8049199:   c3                          ret

0804919a <glyph_conflux>:
 804919a:   f3 0f 1e fb                 endbr32
 804919e:   55                          push   %ebp
 804919f:   89 e5                       mov    %esp,%ebp
 80491a1:   e8 e1 00 00 00              call   8049287 <__x86.get_pc_thunk.ax>
 80491a6:   05 6e 21 00 00              add    $0x216e,%eax
 80491ab:   8b 55 08                    mov    0x8(%ebp),%edx
 80491ae:   81 c2 44 44 00 00           add    $0x4444,%edx
 80491b4:   8b 80 18 00 00 00           mov    0x18(%eax),%eax
 80491ba:   c1 e8 03                    shr    $0x3,%eax
 80491bd:   31 d0                       xor    %edx,%eax
 80491bf:   5d                          pop    %ebp
 80491c0:   c3                          ret

080491c1 <astral_spark>:
 80491c1:   f3 0f 1e fb                 endbr32
 80491c5:   55                          push   %ebp
 80491c6:   89 e5                       mov    %esp,%ebp
 80491c8:   e8 ba 00 00 00              call   8049287 <__x86.get_pc_thunk.ax>
 80491cd:   05 47 21 00 00              add    $0x2147,%eax
 80491d2:   8b 55 08                    mov    0x8(%ebp),%edx
 80491d5:   89 d0                       mov    %edx,%eax
 80491d7:   c1 e0 03                    shl    $0x3,%eax
 80491da:   29 d0                       sub    %edx,%eax
 80491dc:   05 10 aa 55 00              add    $0x55aa10,%eax
 80491e1:   5d                          pop    %ebp
 80491e2:   c3                          ret

080491e3 <binding_word>:
 80491e3:   f3 0f 1e fb                 endbr32
 80491e7:   55                          push   %ebp
 80491e8:   89 e5                       mov    %esp,%ebp
 80491ea:   83 ec 10                    sub    $0x10,%esp
 80491ed:   e8 95 00 00 00              call   8049287 <__x86.get_pc_thunk.ax>
 80491f2:   05 22 21 00 00              add    $0x2122,%eax
 80491f7:   8b 45 08                    mov    0x8(%ebp),%eax
 80491fa:   c1 e0 04                    shl    $0x4,%eax
 80491fd:   89 c2                       mov    %eax,%edx
 80491ff:   8b 45 08                    mov    0x8(%ebp),%eax
 8049202:   c1 e8 04                    shr    $0x4,%eax
 8049205:   09 d0                       or     %edx,%eax
 8049207:   89 45 fc                    mov    %eax,-0x4(%ebp)
 804920a:   8b 45 fc                    mov    -0x4(%ebp),%eax
 804920d:   35 de c0 ed fe              xor    $0xfeedc0de,%eax
 8049212:   c9                          leave
 8049213:   c3                          ret

08049214 <main>:
 8049214:   f3 0f 1e fb                 endbr32
 8049218:   55                          push   %ebp
 8049219:   89 e5                       mov    %esp,%ebp
 804921b:   83 ec 10                    sub    $0x10,%esp
 804921e:   e8 64 00 00 00              call   8049287 <__x86.get_pc_thunk.ax>
 8049223:   05 f1 20 00 00              add    $0x20f1,%eax
 8049228:   c7 45 fc 41 41 41 41        movl   $0x41414141,-0x4(%ebp)
 804922f:   8b 45 fc                    mov    -0x4(%ebp),%eax
 8049232:   50                          push   %eax
 8049233:   e8 3e ff ff ff              call   8049176 <ember_sigil>
 8049238:   83 c4 04                    add    $0x4,%esp
 804923b:   8b 55 fc                    mov    -0x4(%ebp),%edx
 804923e:   31 d0                       xor    %edx,%eax
 8049240:   89 45 fc                    mov    %eax,-0x4(%ebp)
 8049243:   8b 45 fc                    mov    -0x4(%ebp),%eax
 8049246:   50                          push   %eax
 8049247:   e8 4e ff ff ff              call   804919a <glyph_conflux>
 804924c:   83 c4 04                    add    $0x4,%esp
 804924f:   8b 55 fc                    mov    -0x4(%ebp),%edx
 8049252:   31 d0                       xor    %edx,%eax
 8049254:   89 45 fc                    mov    %eax,-0x4(%ebp)
 8049257:   8b 45 fc                    mov    -0x4(%ebp),%eax
 804925a:   50                          push   %eax
 804925b:   e8 61 ff ff ff              call   80491c1 <astral_spark>
 8049260:   83 c4 04                    add    $0x4,%esp
 8049263:   8b 55 fc                    mov    -0x4(%ebp),%edx
 8049266:   31 d0                       xor    %edx,%eax
 8049268:   89 45 fc                    mov    %eax,-0x4(%ebp)
 804926b:   8b 45 fc                    mov    -0x4(%ebp),%eax
 804926e:   50                          push   %eax
 804926f:   e8 6f ff ff ff              call   80491e3 <binding_word>
 8049274:   83 c4 04                    add    $0x4,%esp
 8049277:   8b 55 fc                    mov    -0x4(%ebp),%edx
 804927a:   31 d0                       xor    %edx,%eax
 804927c:   89 45 fc                    mov    %eax,-0x4(%ebp)
 804927f:   8b 45 fc                    mov    -0x4(%ebp),%eax
 8049282:   0f b6 c0                    movzbl %al,%eax
 8049285:   c9                          leave
 8049286:   c3                          ret

08049287 <__x86.get_pc_thunk.ax>:
 8049287:   8b 04 24                    mov    (%esp),%eax
 804928a:   c3                          ret
 804928b:   66 90                       xchg   %ax,%ax
 804928d:   66 90                       xchg   %ax,%ax
 804928f:   90                          nop

08049290 <__libc_csu_init>:
 8049290:   f3 0f 1e fb                 endbr32
 8049294:   55                          push   %ebp
 8049295:   e8 6b 00 00 00              call   8049305 <__x86.get_pc_thunk.bp>
 804929a:   81 c5 7a 20 00 00           add    $0x207a,%ebp
 80492a0:   57                          push   %edi
 80492a1:   56                          push   %esi
 80492a2:   53                          push   %ebx
 80492a3:   83 ec 0c                    sub    $0xc,%esp
 80492a6:   89 eb                       mov    %ebp,%ebx
 80492a8:   8b 7c 24 28                 mov    0x28(%esp),%edi
 80492ac:   e8 4f fd ff ff              call   8049000 <_init>
 80492b1:   8d 9d 10 ff ff ff           lea    -0xf0(%ebp),%ebx
 80492b7:   8d 85 0c ff ff ff           lea    -0xf4(%ebp),%eax
 80492bd:   29 c3                       sub    %eax,%ebx
 80492bf:   c1 fb 02                    sar    $0x2,%ebx
 80492c2:   74 29                       je     80492ed <__libc_csu_init+0x5d>
 80492c4:   31 f6                       xor    %esi,%esi
 80492c6:   8d b4 26 00 00 00 00        lea    0x0(%esi,%eiz,1),%esi
 80492cd:   8d 76 00                    lea    0x0(%esi),%esi
 80492d0:   83 ec 04                    sub    $0x4,%esp
 80492d3:   57                          push   %edi
 80492d4:   ff 74 24 2c                 push   0x2c(%esp)
 80492d8:   ff 74 24 2c                 push   0x2c(%esp)
 80492dc:   ff 94 b5 0c ff ff ff        call   *-0xf4(%ebp,%esi,4)
 80492e3:   83 c6 01                    add    $0x1,%esi
 80492e6:   83 c4 10                    add    $0x10,%esp
 80492e9:   39 f3                       cmp    %esi,%ebx
 80492eb:   75 e3                       jne    80492d0 <__libc_csu_init+0x40>
 80492ed:   83 c4 0c                    add    $0xc,%esp
 80492f0:   5b                          pop    %ebx
 80492f1:   5e                          pop    %esi
 80492f2:   5f                          pop    %edi
 80492f3:   5d                          pop    %ebp
 80492f4:   c3                          ret
 80492f5:   8d b4 26 00 00 00 00        lea    0x0(%esi,%eiz,1),%esi
 80492fc:   8d 74 26 00                 lea    0x0(%esi,%eiz,1),%esi

08049300 <__libc_csu_fini>:
 8049300:   f3 0f 1e fb                 endbr32
 8049304:   c3                          ret

08049305 <__x86.get_pc_thunk.bp>:
 8049305:   8b 2c 24                    mov    (%esp),%ebp
 8049308:   c3                          ret

Disassembly of section .fini:

0804930c <_fini>:
 804930c:   f3 0f 1e fb                 endbr32
 8049310:   53                          push   %ebx
 8049311:   83 ec 08                    sub    $0x8,%esp
 8049314:   e8 97 fd ff ff              call   80490b0 <__x86.get_pc_thunk.bx>
 8049319:   81 c3 fb 1f 00 00           add    $0x1ffb,%ebx
 804931f:   83 c4 08                    add    $0x8,%esp
 8049322:   5b                          pop    %ebx
 8049323:   c3                          ret
```

Look closely from our `objdump`:

```text
08049176 <ember_sigil>
0804919a <glyph_conflux>
080491c1 <astral_spark>
080491e3 <binding_word>
```

Basically, the script expects **raw 4‑byte little endian**, same as `p32(addr)`.

**ember_sigil**

`0x08049176 → 76 91 04 08`

**glyph_conflux**

`0x0804919a → 9a 91 04 08`

**astral_spark**

`0x080491c1 → c1 91 04 08`

**binding_word**

`0x080491e3 → e3 91 04 08`

Now let's check the `app.py` again, this line:

```python
selections = random.sample(SPELLBOOK_FUNCTIONS, QUESTION_COUNT)
```

Means each run picks **3 random functions**, so you must send the correct bytes depending on the question.

Example prompt:

```text
Send address for 'astral_spark'
```

You send raw bytes:

```text
\xC1\x91\x04\x08
```

NOT text.

Here's the `solve.py` for this challenge:

```python
from pwn import *

p = remote("green-hill.picoctf.net", 63551)

addrs = {
    b"ember_sigil": p32(0x08049176),
    b"glyph_conflux": p32(0x0804919a),
    b"astral_spark": p32(0x080491c1),
    b"binding_word": p32(0x080491e3),
}

while True:
    line = p.recvline()
    print(line)

    for k in addrs:
        if k in line:
            p.send(addrs[k])
```

Here's the output

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FPzRJrbsgmz0fycW827rO%252FScreenshot%2520%281719%29.png%3Falt%3Dmedia%26token%3D8002c5df-2b75-4d54-a3a3-78c3fdb1519a&width=768&dpr=3&quality=100&sign=bec61665&sv=2)

We've got the flag, the error is just EOF, because the connection closed but our script still trying to recv:>>

That's a wrap! This is all of the challenges for General Skills category of picoCTF 2026! This year's picoCTF is more fun!
