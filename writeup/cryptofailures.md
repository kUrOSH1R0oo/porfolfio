---
title: "Crypto Failures"
date: 03-25-2025
excerpt: TryHackMe Writeup
cover: ../uploads/cover_cryptofailures.jpg
tags: DES crypt, Hash Block Manipulation, Cookie Tampering
---

Welcome back to my Writeup!! Today, I will show the step-by-step on how I solved **Crypto Failures** from TryHackMe!! We'll dive deep into the challenge, explore the vulnerabilities, and go over the thought process and tools I used to crack them. Whether you're new to cryptography or sharpening your skills, there's something here for you to learn. Let's get started and unravel the flaws together!

## Reconnaissance

To begin, I performed a scan on the target using **Nmap** to identify any open ports and discover potential endpoints.

```shell
nmap -sV -sC -v <target_ip>
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FLSdcyBP9rowRbalMCsut%252FScreenshot%2520%28685%29.png%3Falt%3Dmedia%26token%3Dfa09e72e-df32-4a44-920e-7549c1fb52f0&width=768&dpr=3&quality=100&sign=aadb355f&sv=2)

22 and 80 are open — so we're dealing with SSH and a web server. Since we don't have credentials for SSH, the web application on port 80 is our natural starting point.

I then navigated to the web interface to begin exploring the application's behavior.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F4hMnmsrWPrchTpK7nfOY%252FScreenshot%2520%28684%29.png%3Falt%3Dmedia%26token%3D30cede35-df85-4e26-9a48-53cb6689198c&width=768&dpr=3&quality=100&sign=c95a06c0&sv=2)

Just a plain interface with the word **Crypt** highlighted — a small hint pointing us toward cryptography being the theme of this box.

As I checked the source code of the page, this is what I found.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F5jhoV33afNOJH2CZKvXH%252FScreenshot%2520%28686%29.png%3Falt%3Dmedia%26token%3D6bc574b0-091a-4f76-a275-555505e02209&width=768&dpr=3&quality=100&sign=84a9fa91&sv=2)

*TODO remember to remove .bak files*

That HTML comment is a developer's leftover note — and it's a goldmine. It tells us `.bak` (backup) files may have been left accessible on the server, which is a classic source information disclosure vulnerability.

## Discovering the Web Flag

While brute-forcing subdirectories, I discovered that the site was using **index.php**. Combined with the hint about `.bak` files, this led me to suspect there might be a backup version of that file, so I tried accessing **index.php.bak** directly in the browser.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FTOI115OZ8t7m2Lm5s7MF%252FScreenshot%2520%28687%29.png%3Falt%3Dmedia%26token%3D2f55a0fb-7155-4f6a-9683-0124be09f064&width=768&dpr=3&quality=100&sign=ef58a13&sv=2)

Because `.bak` isn't a PHP extension, the web server doesn't execute it — it just serves it as plain text. That's exactly what let us read the raw PHP source code instead of watching it run.

This is the code inside:

```php
<?php
include('config.php');

function generate_cookie($user,$ENC_SECRET_KEY) {
    $SALT=generatesalt(2);
    
    $secure_cookie_string = $user.":".$_SERVER['HTTP_USER_AGENT'].":".$ENC_SECRET_KEY;

    $secure_cookie = make_secure_cookie($secure_cookie_string,$SALT);

    setcookie("secure_cookie",$secure_cookie,time()+3600,'/','',false); 
    setcookie("user","$user",time()+3600,'/','',false);
}

function cryptstring($what,$SALT){

return crypt($what,$SALT);

}


function make_secure_cookie($text,$SALT) {

$secure_cookie='';

foreach ( str_split($text,8) as $el ) {
    $secure_cookie .= cryptstring($el,$SALT);
}

return($secure_cookie);
}


function generatesalt($n) {
$randomString='';
$characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
for ($i = 0; $i < $n; $i++) {
    $index = rand(0, strlen($characters) - 1);
    $randomString .= $characters[$index];
}
return $randomString;
}



function verify_cookie($ENC_SECRET_KEY){


    $crypted_cookie=$_COOKIE['secure_cookie'];
    $user=$_COOKIE['user'];
    $string=$user.":".$_SERVER['HTTP_USER_AGENT'].":".$ENC_SECRET_KEY;

    $salt=substr($_COOKIE['secure_cookie'],0,2);

    if(make_secure_cookie($string,$salt)===$crypted_cookie) {
        return true;
    } else {
        return false;
    }
}


if ( isset($_COOKIE['secure_cookie']) && isset($_COOKIE['user']))  {

    $user=$_COOKIE['user'];

    if (verify_cookie($ENC_SECRET_KEY)) {
        
    if ($user === "admin") {
   
        echo 'congrats: ******flag here******. Now I want the key.';

            } else {
        
        $length=strlen($_SERVER['HTTP_USER_AGENT']);
        print "<p>You are logged in as " . $user . ":" . str_repeat("*", $length) . "\n";
            print "<p>SSO cookie is protected with traditional military grade en<b>crypt</b>ion\n";    
    }

} else { 

    print "<p>You are not logged in\n";
   

}

}
  else {

    generate_cookie('guest',$ENC_SECRET_KEY);
    
    header('Location: /');


}
?>
```

## Understanding the Cookie Generation Logic

Before exploiting anything, it's worth slowing down and understanding exactly what this code does, since the whole attack depends on it.

The script starts by including **config.php**, which is not shown to us — but we can infer it defines the variable **ENC_SECRET_KEY**, since that variable is used throughout **index.php** without ever being declared locally. This secret key is essentially the "password" the whole cookie system is built around, and it's what we'll eventually be trying to steal.

**What happens on a first visit (no cookies yet)**

If neither the **secure_cookie** nor **user** cookie is set — meaning this is a fresh visitor — the server calls **generate_cookie('guest', $ENC_SECRET_KEY)**. Here's what that function does, broken into simple steps:

1. **Generate a random 2-character salt.** A "salt" is just random data mixed into a hash so that the same input doesn't always produce the same output. Here, `generatesalt(2)` picks 2 random alphanumeric characters.
2. **Build a string to hash.** It concatenates three things separated by colons: the username (`guest`), the visitor's browser **User-Agent** header, and the secret key. So it looks like:
   `guest:<User-Agent>:<SECRET_KEY>`
3. **Hash it in 8-byte chunks.** This is the critical detail. Instead of hashing the whole string at once, `make_secure_cookie()` splits it into blocks of exactly 8 characters using `str_split($text, 8)`, and hashes **each block separately** with PHP's `crypt()` function, using the *same* salt every time.
4. **Store the result.** All the individual hashed blocks are concatenated together into one long string, which becomes the value of the `secure_cookie`. The plain `user` value (`guest`) is stored in a separate cookie.

**Why splitting into 8-byte blocks matters:** PHP's traditional `crypt()` function (the DES-based variant used here) only hashes the first 8 characters of whatever you give it — anything beyond that is ignored. By pre-splitting the input into 8-character chunks, the developer worked around that limit so the *entire* string gets hashed instead of being silently truncated. Unfortunately, this "fix" introduces a much bigger flaw, which we'll exploit shortly.

**What happens on return visits (cookies already set)**

If both cookies exist, the server instead calls `verify_cookie()`. This function:

1. Reads the `secure_cookie` and `user` values sent by the browser.
2. Rebuilds the same `user:User-Agent:SECRET_KEY` string using the cookie's `user` value.
3. Extracts the salt — cleverly, it just grabs the **first 2 characters** of the existing `secure_cookie`, since every crypt() hash starts with its salt.
4. Re-runs `make_secure_cookie()` using that extracted salt and compares the result to the cookie the browser sent.
5. If they match, the user is considered authenticated **as whatever `user` cookie value they provided.**

Then, back in the main logic: if verification succeeds *and* the `user` cookie equals `"admin"`, the flag is printed. Otherwise we just get a generic "logged in as guest" message.

## Exploiting the Cookie to Become Admin

Here's the core vulnerability: **the server trusts whatever `user` value the client sends, as long as the corresponding hash checks out — and we can generate that hash ourselves**, because:

- We can see and control our own `User-Agent` header.
- We can read the salt directly from our own `secure_cookie` (it's just the first 2 characters, in plaintext).
- The only thing we *don't* know is the secret key.

But look closer at the block-splitting logic: the string being hashed is `user:User-Agent:SECRET_KEY`. The username comes **first**. So the very first 8-byte block is made up entirely of characters we already know (part of `guest` or `admin`, plus part of our own User-Agent) — **the secret key doesn't even appear in that first block**. That means we can compute the hash for that first block ourselves, entirely offline, without ever needing to know the secret key.

To illustrate: say the username is `guest` and the User-Agent is:
```text
Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
```

The server builds this string before hashing:
```text
guest:Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0:SECRET_KEY
```

And splits it into 8-byte chunks, hashing each one:
```text
"guest:Mo" = k0asAVEwgsdsw
"zilla/5." = k0fdieAfwerds
.....
```

We can verify this ourselves by manually hashing `"guest:Mo"` with the known salt and confirming it matches the first chunk of our `secure_cookie`:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FPGvAySmHueBBfnh6I3Yc%252FScreenshot%2520%28689%29.png%3Falt%3Dmedia%26token%3D40390e94-86a1-4c69-9bdd-8db246dbbeb7&width=768&dpr=3&quality=100&sign=2df66033&sv=2)

*(I blocked the flags since I already solved this challenge before writing this up.)*

**Now for the actual exploit:** since the server never re-derives the salt independently — it just reads it from *our own cookie* — and since the first block is computable without the secret key, we can simply:

1. Take our existing cookie's salt.
2. Compute a new hash for `"admin:Mo"` (swapping `guest` for `admin`, keeping the same User-Agent prefix) using that same salt.
3. Replace the *first 8-byte block* of our `secure_cookie` with this new hash.
4. Change the `user` cookie value to `admin`.
5. Send the modified cookies back to the server.

Because `verify_cookie()` rebuilds the string using whatever `user` value we send, and because the first block it compares against is exactly the one we forged, the check on that block passes — and the server now believes we're logged in as `admin`.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FCzAb2eSXUg5pRoQtTDqR%252FScreenshot%2520%28692%29.png%3Falt%3Dmedia%26token%3D3c3f86cb-2b13-4714-bae5-62e482625939&width=768&dpr=3&quality=100&sign=d5cc2fab&sv=2)

After swapping in the forged hash and sending the request, here's the result:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F8gJVBsWyIcqRCNJa6cOU%252FScreenshot%2520%28693%29.png%3Falt%3Dmedia%26token%3D2a9c38f7-aa92-4093-a9bd-205cd893280a&width=768&dpr=3&quality=100&sign=1feba543&sv=2)

**Web flag captured!** 🎉

## Cracking the Secret Key (Final Flag)

Getting the first flag proved the cookie logic could be manipulated — but the challenge wants more: it wants the **secret key itself**, which becomes the final flag.

**Why brute-forcing the whole key at once won't work:** the key could be made up of any of the 65 characters used in `crypt()` salts/output, and if it's 8 characters long, that's **65⁸ combinations** — computationally impractical to brute-force directly.

**The insight that makes this feasible:** we already established that the input string is chopped into fixed 8-byte blocks *before* hashing, and that the username sits at the very start of that string. This means we — the attacker — control exactly how much "padding" appears before the secret key even starts. If we can push the block boundaries around, we can arrange for a block to contain **mostly known characters plus exactly one unknown byte of the key**. That reduces the problem from "guess 65⁸ combinations" down to "guess 1 of 65 characters, repeated once per key byte" — a massive difference in difficulty.

**How the alignment trick works, step by step:**

1. **Start with an empty User-Agent.** The string being hashed becomes:
   `guest::SECRET_KEY`
   The first 8-byte block is `guest::X`, where `X` is just the *first character* of the secret key — everything else in that block is already known to us.
2. **Brute-force that one unknown character.** We loop through every possible character, hash `guest::<candidate>` with the known salt, and compare it against the first block of the `secure_cookie` the server returns. When it matches, we've recovered byte 1 of the key.
3. **Shift the window forward.** Once we know one (or more) characters of the key, we adjust the length of our User-Agent (padding it with junk like `A`s) so that the *next* unknown character of the key lands as the very last character of some 8-byte block, with everything before it already known. This "slides" our target one byte to the right each time.
4. **Repeat.** Each iteration reveals exactly one more byte of the secret key, until we've recovered the whole thing.

To make this concrete: suppose we set the User-Agent to `AAAAAAA` (7 A's). The full string becomes:
```text
guest:AAAAAAA:<SECRET_KEY>
```

Split into 8-byte blocks:

* **Block 1:** `guest:AA` — not useful to us, we already know this.
* **Block 2:** `AAAAA:T?` — this block contains 5 known `A`s, a known colon, the already-recovered first key character (`T` in this example), and one new unknown character we're trying to find.

We loop through every candidate character, appending it after the known prefix `AAAAA:T`, hash the result with the known salt, and compare against the **second** block of the returned cookie (since that's now our target block). When we find a match — say, the character `H` — we've just confirmed that the second character of the secret key is `H`.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FhtUJoHFxASP6saE8w3ff%252FScreenshot%2520%28696%29.png%3Falt%3Dmedia%26token%3Ddddcf420-b74a-4bcb-9e69-7f4d437465be&width=768&dpr=3&quality=100&sign=76f58cc0&sv=2)

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FYTUfkwdHCGNPCLQW86LJ%252FScreenshot%2520%28695%29.png%3Falt%3Dmedia%26token%3De6917a8f-bef6-4f9d-90cc-8303ec8e591a&width=768&dpr=3&quality=100&sign=4ca3d060&sv=2)

It matched — you can confirm this by comparing the hash directly in Burp Suite's response.

## Automating the Brute-Force with Python

Doing this one character at a time by hand works, but it's slow and error-prone. Instead, we can automate the entire "pad → request → extract block → brute-force one byte → repeat" loop with a Python script. Here's the logic in plain terms before the code:

- **Compute how much padding is needed** so the next unknown key character lands cleanly at the end of a block.
- **Send a request** with that padding in the User-Agent.
- **Pull out the correct 13-character crypt hash** from the response cookie (a `crypt()` DES hash is always 13 characters: 2 for the salt + 11 for the hash itself).
- **Try every printable character**, hash it locally with the known salt, and check for a match.
- **Append the matching character to our recovered key so far**, and loop again — until no character matches, which signals we've reached the end of the key.

```python
#!/usr/bin/env python3
# Import necessary libraries
import crypt
import requests
import urllib.parse 
import string  
import time                 

# Base URL of the target application
BASE_ENDPOINT = "http://10.10.38.32/"

# Static part of the string to be hashed (usually the username)
ACCESS_ID = "guest:"

# Separator used in the string formatting
DELIMITER = ":"

# The set of characters we'll test during brute-force (printable ASCII characters)
CHARACTER_SET = string.printable

def retrieve_protected_token(user_identifier: str) -> str:
    """
    Sends a request with the given User-Agent and retrieves the decoded secure_cookie value.
    """
    print(f"\nInitiating connection to {BASE_ENDPOINT} with User-Agent: {user_identifier}")
    
    # Create a new session for consistent cookie handling
    session = requests.Session()

    # Send GET request with custom User-Agent
    response = session.get(BASE_ENDPOINT, headers={"User-Agent": user_identifier})
    print(f"Received response with status code: {response.status_code}")

    # Extract and decode the secure_cookie from the response
    token = session.cookies.get("secure_cookie")
    decoded_token = urllib.parse.unquote(token)
    print(f"Successfully retrieved and decoded secure token: {decoded_token[:10]}... (partial)")

    return decoded_token
    
def execute():
    """
    Attempts to brute-force and recover the secret key from the secure_cookie by aligning
    one unknown character per 8-byte chunk using padding and hash comparisons.
    """
    print(f"Starting decryption process with access ID: {ACCESS_ID}")
    print(f"Using delimiter: {DELIMITER}")
    print(f"Character set for testing includes: {CHARACTER_SET[:20]}... (partial)")

    uncovered = ""      # This will store the recovered secret key
    iteration = 0       # To track how many characters we have processed

    # Continue brute-forcing until no new character is found
    while True:
        iteration += 1
        print(f"\nStarting iteration {iteration}...")
        print(f"Current progress: {uncovered}")

        # Calculate how much padding is needed to align the target character into its own 8-byte block
        padding_size = (7 - len(ACCESS_ID + DELIMITER + uncovered)) % 8
        print(f"Calculating padding size: {padding_size} characters needed")

        # Build the User-Agent with padding (e.g., "A" * padding_size)
        user_identifier = "A" * padding_size
        print(f"Constructing user identifier with padding: {user_identifier}")

        # Build the full prefix: guest + padding + : + currently discovered key portion
        prefix = ACCESS_ID + user_identifier + DELIMITER + uncovered
        print(f"Building prefix for this round: {prefix}")

        # Determine which 8-byte block of the secure_cookie we're targeting
        block_position = len(prefix) // 8
        print(f"Targeting block at position: {block_position}")

        # Retrieve the secure_cookie value using the current User-Agent
        protected_token = retrieve_protected_token(user_identifier)

        # Extract the 13-character crypt hash from the correct block
        target_segment = protected_token[block_position * 13:(block_position + 1) * 13]
        print(f"Extracted target segment from token: {target_segment}")

        # The first two characters of a crypt hash represent the salt (a.k.a. "seasoning")
        seasoning = target_segment[:2]
        print(f"Using seasoning for hash: {seasoning}")

        character_found = False  # Flag to indicate if we successfully matched a character
        print(f"Beginning character testing with {len(CHARACTER_SET)} possible characters...")

        # Brute-force one character at a time by appending to the current prefix
        for symbol in CHARACTER_SET:
            print(f"Testing character: {symbol}", end=" ")

            # Only take the last 8 characters (aligns with how the server hashes blocks)
            candidate = (prefix + symbol)[-8:]
            candidate_hash = crypt.crypt(candidate, seasoning)

            # If hashes match, we found the correct next character
            if candidate_hash == target_segment:
                uncovered += symbol
                print(f"\nSuccess! Matched hash with character: {symbol}")
                print(f"Current decryption state: {uncovered}")
                character_found = True
                time.sleep(0.5)
                break
            else:
                print(".", end="", flush=True)

        # If no match is found, we've likely reached the end of the key
        if not character_found:
            print(f"\nNo matching character found. Decryption process completed.")
            break

    # Final output of the uncovered secret key
    print(f"\nFinal decrypted result: {uncovered}")
    print("Decryption process has successfully concluded!")

# Entry point of the script
if __name__ == "__main__":
    execute()
```

Run the script and it will print each character of the secret key (the flag) one at a time until it recovers the entire string.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fv7P6vhBWuHmbL4jp1jSU%252FScreenshot%2520%28698%29.png%3Falt%3Dmedia%26token%3D2124f9f3-5210-4941-a381-3b4de7b31c2b&width=768&dpr=3&quality=100&sign=9582f6a2&sv=2)

**DONE!!** We've successfully completed the Crypto Failures Challenge!!!

## Conclusion

Throughout this process, we navigated the cryptographic challenge step by step, starting with identifying the structure of the hashing mechanism and leveraging the predictable behavior of the system. We analyzed how the secure token was generated, understood the structure of the hashed blocks, and identified key patterns in the encryption process. From there, we devised an efficient attack by exploiting the fact that the system uses fixed 8-byte blocks and a known, attacker-readable salt.

Rather than brute-forcing the entire secret key at once, we carefully padded the User-Agent to isolate and target individual 8-byte blocks — turning an infeasible 65⁸ search into a series of quick, single-character guesses. By systematically testing possible characters for each block, starting with the first character and moving through the key one step at a time, we narrowed down the solution without needing to test every possible combination. This iterative process, combined with a bit of automation through a Python script, allowed us to uncover the key far more efficiently than manual methods would have.

**Key takeaways for defenders:**

- **Never split user-controlled input and secret data into the same fixed-size hashing blocks.** Doing so lets an attacker control byte alignment and isolate individual bytes of a secret.
- **Don't let the client dictate or expose the salt** used for verification — deriving it from attacker-controlled cookie data defeats its purpose.
- **Avoid legacy hashing primitives like DES-based `crypt()`** for anything security-sensitive; modern algorithms (e.g., `bcrypt`, `argon2`) don't have the 8-byte truncation quirk that made this block-splitting "workaround" necessary — and dangerous — in the first place.
- **Never trust a client-supplied identity field** (like the `user` cookie) as the basis for authorization without cryptographically binding it to something the client cannot forge.

This challenge is a great reminder that clever-looking custom cryptography is often more dangerous than no cryptography at all — small implementation details, like how input is chunked before hashing, can completely undermine the security the code was trying to provide.
