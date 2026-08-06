---
title: "Dual-Format File Engineering: A Deep Dive into Polyglots"
date: 03-03-2026
excerpt: Polyglot Files
cover: ../uploads/cover_dualformat.jpg
tags: Cybersecurity, File Format Security
---

In cybersecurity, one of the most fascinating concepts is the idea that a single file can possess multiple identities. A file may appear harmless when viewed in one context, yet behave entirely differently when interpreted by another program. This concept is known as a **polyglot file** — a carefully crafted file that is valid under more than one format specification at the same time.

Polyglot files challenge a common assumption in computing: that a file's extension defines its behavior. In reality, programs interpret files based on internal structure, not just their names. If a file is constructed to satisfy the structural requirements of two different parsers, it can seamlessly switch roles depending on how it is opened. An image viewer may treat it as a picture, while a shell interpreter may execute it as a script. The same bytes, two completely different interpretations.

This duality makes polyglots particularly interesting in security research. They demonstrate how file validation, parser behavior, and format specifications can intersect in unexpected ways. Polyglots are often explored in red teaming exercises, CTF challenges, and file format research because they reveal the subtle gaps between how systems *store*, *recognize*, and *execute* data.

![captionless image](https://miro.medium.com/v2/resize:fit:1200/format:webp/1*5Ocd6q51BpwLIEAK2K_q4g.gif)

This writeup explores the concept of polyglots in depth — how they work, why certain file formats are more suitable for them, and what structural characteristics make dual interpretation possible. Rather than focusing on a specific programming language or implementation detail, the emphasis here is on understanding the underlying principles that allow one file to exist in two worlds at once.

For this writeup, we will use a PNG file as the foundational format.

## But before that, what exactly is a PNG?

**PNG**, or **Portable Network Graphics**, is a widely used image format that preserves high quality while compressing images **without losing data**. Unlike formats like JPEG, PNG uses *lossless* compression (via the DEFLATE algorithm) and supports **transparency** and precise pixel information, making it perfect for icons, graphics, and web images.

Think of PNG as a **container** that carefully organizes all the information an image needs — its size, color, pixels, and optional notes — into a structured layout. This "container" mental model matters a lot for polyglots: a container format's job is to hold clearly delimited pieces of data, and any format built around delimited, self-describing sections is a natural candidate for smuggling additional sections inside it.

![Example of PNG Structure](https://miro.medium.com/v2/resize:fit:1284/format:webp/1*pUBgrmHthLwf4_QZE19Qtw.jpeg)

### Binary Nature & File Signature

PNG is a **binary file**, meaning it's made up of exact bytes that programs read to understand the image, rather than human-readable text.

Every PNG starts with an **8-byte signature**:

```
89 50 4E 47 0D 0A 1A 0A
```

This signature isn't arbitrary — each byte was deliberately chosen by the format's designers to catch a specific class of file-corruption problem:

- `89` — a byte with the high bit set, so 7-bit transmission systems (which strip that bit) will visibly mangle the file, making corruption obvious.
- `50 4E 47` — the ASCII characters "PNG," a human-readable identifier.
- `0D 0A` — a CR-LF pair, which detects file transfers that "helpfully" convert line endings (a common source of corruption for text-mode FTP transfers of binary files).
- `1A` — a DOS "end of file" character, which stops naive text viewers (like `TYPE` on old DOS systems) from dumping garbage to the screen when they hit the byte.
- `0A` — a bare LF, the counterpart check to the CR-LF check above, catching systems that strip the CR.

If the signature is missing or altered, programs won't recognize the file. You can visualize it as the **front door** of the PNG house: without it, nothing inside can be accessed safely. For polyglot construction, this signature is one of the two "anchors" that must be respected exactly — you can't touch it without breaking every PNG-aware parser at once.

### Chunk-Based Architecture

After the signature, a PNG is built from **chunks**, which are like **rooms in a house**, each serving a different purpose.

Each chunk contains:

```
+------------+------------+------------+------------+
| Length (4) | Type (4)   | Data (n)   | CRC (4)    |
+------------+------------+------------+------------+
```

- **Length:** Size of the room (data field), stored as a 4-byte big-endian unsigned integer describing exactly how many bytes follow before the CRC.
- **Type:** Label of the room (what it contains), stored as 4 ASCII letters.
- **Data:** The actual content (pixels, metadata, etc.), whose length matches the Length field exactly.
- **CRC:** A guard at the door, making sure the room isn't tampered with.

Because every chunk explicitly declares its own size, a PNG parser never has to "guess" where a chunk ends — it just reads the length, skips (or reads) that many bytes, and moves to the next 4-byte type field. This design is what makes chunks *composable*: a parser can walk the entire file mechanically, chunk by chunk, without understanding the meaning of every chunk type it encounters. That mechanical, meaning-agnostic walk is exactly the property polyglot authors exploit.

The **chunk type** field also carries structural information encoded in its capitalization, defined by the PNG spec itself:

- Bit 5 of the first letter (uppercase/lowercase) marks a chunk as **critical** or **ancillary**. `IHDR` (uppercase I) is critical; `tEXt` (lowercase t) is ancillary.
- Bit 5 of the second letter marks a chunk as **public** or **private** (used by a registered organization vs. an application-specific extension).
- Bit 5 of the third letter is reserved and must always be uppercase.
- Bit 5 of the fourth letter marks whether the chunk is **safe to copy** if an editor doesn't understand it — a flag intended for image-editing software that modifies a PNG without understanding every chunk in it.

That last flag is worth sitting with: the PNG format *by design* anticipates that some programs will encounter chunks they don't understand and pass them through unmodified. Polyglot authors aren't discovering an oversight — they're using a documented behavior for an unintended purpose.

### Importance of IHDR, IDAT, and IEND

There are three essential critical chunks in every PNG:

- **IHDR (Image Header)** — The first chunk after the signature. Contains image width, height, bit depth, color type, compression method, filter method, and interlace method. Because it must appear first, it's a fixed, predictable anchor point that polyglot scripts can reliably locate and insert content after.
- **IDAT (Image Data)** — Contains the actual compressed pixel data, run through a filtering step and then DEFLATE compression. There can be multiple IDAT chunks; when there are, decoders concatenate their data streams before decompressing, as if it were one large chunk split across several.
- **IEND (Image End)** — Marks the logical end of the PNG file. It has zero-length data. No chunks should appear after this, though in practice many lenient decoders don't enforce that rule strictly — which is itself another avenue polyglot authors use (appending entirely separate file formats, like a ZIP archive, after IEND).

These chunks form the structural backbone of every PNG image, and any conforming decoder must be able to parse all three.

### Flexibility of Metadata Chunks

PNG supports ancillary metadata chunks such as:

- `tEXt` – Stores textual information as uncompressed Latin-1 text.
- `zTXt` – The same idea as tEXt, but the text is compressed with DEFLATE, useful for larger comments.
- `iTXt` – International text, supporting UTF-8 and optional compression, used for multilingual metadata like XMP.

Because ancillary chunks are optional and safely ignored by image viewers, they provide a flexible mechanism for embedding additional information inside the file without affecting its visual rendering. This extensibility is one of the reasons PNG is particularly adaptable in advanced file format experimentation — it's the same mechanism legitimate software uses to store camera EXIF-like data, copyright notices, or software attribution, just repurposed.

## What is a Polyglot File?

A **polyglot file** is a single file that is simultaneously valid under **two or more file formats**. This means the same sequence of bytes can be correctly interpreted by multiple parsers, each according to its own specification. Polyglots exploit the fact that different programs rely on different rules to process files, allowing one file to serve multiple purposes without corruption. In essence, polyglots demonstrate that a file's behavior is determined not only by its extension but by its internal structure, headers, and parser expectations.

The term is borrowed from linguistics — a person who speaks several languages — and the metaphor holds up well: the file "speaks" PNG to an image decoder and Bash to a shell, using the exact same underlying bytes, just as a bilingual sentence might parse as grammatical in two languages at once.

### How a File Can Satisfy Multiple Parsers

Polyglots work because different parsers **ignore or interpret different parts of a file**:

- Parsers follow specific structural rules or signatures (headers, markers, or magic numbers) to decide *where* meaningful data begins and ends.
- Sections of the file not recognized by a parser are often ignored rather than causing an error — this is a deliberate robustness feature in most format specs, not a bug.
- By carefully placing content, a polyglot can ensure that each parser encounters **only the bytes it expects**, allowing simultaneous validity under multiple formats.

For example:

- A shell interpreter might look for a **shebang (`#!`)** at the start to execute commands — but if it doesn't find one at byte zero, many shells will still happily execute whatever text follows, line by line, as long as it looks like valid shell syntax.
- An image viewer reads PNG critical chunks to render pixels and ignores unknown ancillary chunks, regardless of what's inside their data field.

By aligning these rules, the file can act as an **image and a script simultaneously**. The core insight generalizes: any two formats can be married into a polyglot if you can find a byte layout where format A's "ignore this" region overlaps with format B's "this is meaningful" region, or where both formats can independently locate their own anchors even when interleaved.

### Examples of Polyglot Files

Polyglots appear in many forms across different file types:

- **Image + Script:** PNG or JPEG images contain hidden shell, Python, or JavaScript code in metadata or extra bytes.
- **PDF + JavaScript:** A PDF includes embedded scripts that execute in PDF viewers supporting JS while displaying the document normally.
- **ZIP + PNG:** A PNG image with an appended ZIP archive can be opened as an image or extracted as a ZIP — this works because ZIP's central directory is read from the *end* of the file backward, while PNG is read from the *start* forward, so the two formats' anchors never collide.
- **GIF + HTML:** A GIF animation doubles as HTML code for browser execution, exploiting the fact that browsers are extremely lenient about sniffing content type from the first few bytes rather than strictly trusting the declared MIME type.
- **PDF + ZIP:** Similarly to PNG+ZIP, PDF's cross-reference table is also read from the file's tail, making PDF another common ZIP-carrier format.
- **JPEG + PHP:** Historically used in web upload vulnerabilities, where a JPEG's EXIF comment field carries PHP code that only becomes "live" if a misconfigured server executes uploaded image files as PHP.

### Interpreters vs Renderers

Polyglots depend on the difference between **renderers** and **interpreters**:

- **Renderers** (image viewers, PDF readers) process the file selectively. They only validate and render known structures and safely ignore unknown or extra data, generally trusting length fields to skip over things they don't understand.
- **Interpreters** (shells, scripting engines) process sequentially, token by token or line by line, according to execution rules. They may read the same bytes as code, treating non-executable sections as comments, string literals, or simply syntax they choke on and skip past (depending on the language's error tolerance).

This divergence — one side skipping via declared length, the other skipping via syntax — allows the same file to carry content for **multiple execution contexts** without breaking any of them. It's the mismatch between "skip by counting bytes" and "skip by parsing grammar" that polyglot authors are really engineering around.

## Parser Confusion

The technical principle behind polyglots is called **parser confusion** — sometimes also called format confusion or content-sniffing confusion in web-security contexts. It's a broader category that polyglot files are one specific manifestation of; the same underlying idea shows up in vulnerabilities like MIME-sniffing XSS or archive "zip bombs" disguised as other formats.

- Each parser expects a particular sequence of bytes to identify its format and locate the data it cares about.
- A polyglot arranges content so that **each parser is satisfied independently**, without either one needing to be aware the other format is present.
- Extra bytes or ancillary structures do not interfere with the primary interpretation, because each parser only looks at the subset of the file relevant to its own rules.

For instance:

- A PNG viewer ignores extra chunks, allowing the file to remain a valid image.
- A shell interpreter reads specific command bytes, executes them, and ignores the rest — either because they're outside the shebang's script body, or because they happen to be syntactically valid no-ops (comments, unused variable assignments, etc.) in the target shell.

This makes polyglot files extremely useful in **file format research, red teaming, and security testing**, as they demonstrate how programs handle unexpected data, and reveal gaps in validation logic. The underlying lesson — that "this file was accepted by parser A" tells you nothing about what parser B will do with it — is the reason security-conscious systems increasingly re-encode or re-render untrusted uploads rather than merely validating and passing them through.

## Why PNG Can Be Used as a Polyglot

The **PNG file format** is particularly suitable for polyglot construction due to its **structured yet flexible architecture**. Unlike many binary formats that reject unexpected data outright, PNG's design allows additional content to be safely included without breaking the image, making it an ideal carrier for hidden payloads.

### PNG Ignores Unknown Ancillary Chunks

PNG divides its data into **critical and ancillary chunks**:

- **Critical chunks** (e.g., IHDR, IDAT, IEND) are essential for image rendering; a conforming decoder must understand every critical chunk or refuse the file.
- **Ancillary chunks** (e.g., tEXt, zTXt, iTXt) are optional metadata that a conforming decoder is explicitly permitted to skip if it doesn't recognize the chunk type.

Image viewers and decoders are required to **ignore any unknown ancillary chunks**, meaning extra data placed in these chunks will not affect image rendering. This behavior allows a polyglot to embed executable content **without corrupting the visual image**. It's a case where following the specification correctly — being lenient about ancillary data — is precisely what creates the opportunity.

### Chunked Architecture Allows Safe Injection

The PNG format is inherently **modular**, composed of sequential, self-describing chunks. Each chunk has a **length, type, data, and CRC**, which makes it possible to:

- Insert new chunks at strategic positions, as long as ordering constraints (like IHDR being first) are respected.
- Preserve the integrity of existing critical chunks, since insertion doesn't require modifying their bytes at all.
- Maintain compliance with the PNG specification, because a well-formed inserted chunk is indistinguishable, structurally, from any other legitimate ancillary chunk.

This chunked design provides **safe zones for embedding payloads** that image viewers ignore but interpreters can read — the "safety" here refers to the file remaining valid PNG, not to the payload itself being benign.

### CRC Validation Ensures Integrity

Every PNG chunk includes a **Cyclic Redundancy Check (CRC)** calculated from its type and data using the standard CRC-32 algorithm. This ensures:

- Image viewers can detect accidental corruption (e.g., a chunk mangled in transit) and refuse to render a damaged file.
- Any deliberately inserted ancillary chunk must have a **valid CRC** to be accepted by the viewer — a CRC mismatch will cause strict decoders to reject the chunk or the whole file.

By computing the CRC for the injected chunk correctly, the polyglot can maintain the **appearance of a valid, unmodified PNG**, while carrying executable payloads. Note that CRC-32 is a checksum for detecting *accidental* corruption, not a cryptographic integrity mechanism — it offers no protection against a deliberate, informed modification, since anyone can recompute a correct CRC for arbitrary data. That's a good reminder that integrity checks and authenticity checks are not the same thing.

### How Metadata Chunks (tEXt) Become a Payload Carrier

Ancillary metadata chunks such as `tEXt` are intended for storing textual information (e.g., author name, description, or comments). They are ideal for polyglots because:

- Their content is **ignored by viewers** if the chunk isn't specifically parsed for display, and even when displayed, an image viewer's UI (an "info" or "properties" panel) is a very different execution context than a shell.
- They allow embedding **arbitrary bytes**, including scripts or shell commands, since the tEXt spec only lightly constrains content (technically Latin-1, though many decoders are permissive).
- They provide a **standardized container** for hidden payloads, making the polyglot file structurally compliant with the PNG spec rather than relying on any decoder-specific quirk.

By encoding executable content inside a `tEXt` chunk, the file remains visually unchanged while carrying hidden instructions — visually inert to a viewer, but semantically "live" to a shell that reads the file as its own script.

### Script Development

For the script that generates the polyglot file, we'll rely solely on Python's **built-in modules** — no additional installations are required. We won't use Pillow or any image manipulation libraries; instead, the process will be handled **manually at the byte level** (read the comments to understand how the script works):

```python
#!/usr/bin/env python3
import os
import struct
import zlib
def create_perfect_polyglot(input_png, output_png, command):
    """
    Core function responsible for generating the polyglot.
    Parameters:
    - input_png: Path to the original PNG image.
    - output_png: Name of the output polyglot file.
    - command: Shell command to embed and execute.
    The function:
    1. Reads the original PNG as raw bytes.
    2. Constructs a valid Bash script payload.
    3. Wraps the payload inside a valid PNG tEXt chunk.
    4. Injects the chunk right after the IHDR chunk.
    5. Writes the modified structure into a new file.
    """
    """
    Step 1: Read the original PNG file in binary mode.
    PNG files are binary structured files composed of
    signature + sequential chunks.
    """
    with open(input_png, 'rb') as f:
        png_data = f.read()
    """
    Step 2: Construct the Bash payload.
    The shebang (#! /bin/bash) ensures that when the file is
    executed via a shell interpreter, it will be treated as a Bash script.
    The user-supplied command is placed inside the script,
    followed by 'exit 0' to ensure clean termination.
    The triple quotes allow multi-line formatting.
    """
    bash_code = f'''
#! /bin/bash
{command}
exit 0
'''
    """
    Convert the Bash script to ASCII bytes since PNG chunks
    operate strictly at the byte level.
    Four NULL bytes are appended to prevent structural conflicts
    and ensure clean separation inside the chunk data.
    """
    bash_bytes = bash_code.encode('ascii') + b'\x00\x00\x00\x00'
    """
    Step 3: Create a valid PNG tEXt chunk.
    tEXt is an ancillary chunk designed to store metadata.
    Image viewers ignore unknown or optional metadata,
    making it a perfect container for hidden payloads.
    """
    chunk_type = b'tEXt'
    """
    PNG tEXt chunks require a keyword followed by a NULL separator.
    'Comment' is a standard keyword used for textual metadata.
    """
    keyword = b'Comment\x00'
    """
    The chunk data consists of:
    keyword + NULL separator + payload bytes
    """
    chunk_data = keyword + bash_bytes
    """
    The length field (4 bytes) must be big-endian.
    It specifies the size of the chunk data only.
    """
    length = struct.pack('>I', len(chunk_data))
    """
    PNG requires a CRC (Cyclic Redundancy Check) for every chunk.
    The CRC is calculated over: chunk_type + chunk_data.
    This ensures that the PNG remains valid and passes integrity checks.
    """
    crc = struct.pack('>I', zlib.crc32(chunk_type + chunk_data) & 0xffffffff)
    """
    Assemble the final chunk:
    [Length][Type][Data][CRC]
    """
    shell_chunk = length + chunk_type + chunk_data + crc
    """
    Step 4: Locate the IHDR chunk.
    IHDR is the first critical chunk in every PNG file.
    Inserting after IHDR ensures:
    - The image structure remains valid.
    - The payload is placed early in the file.
    """
    ihdr_pos = png_data.find(b'IHDR', 8)
    if ihdr_pos == -1:
        raise ValueError("No IHDR chunk found")
    """
    Extract the IHDR chunk length.
    The 4 bytes before 'IHDR' represent its data length.
    """
    ihdr_len = struct.unpack('>I', png_data[ihdr_pos-4:ihdr_pos])[0]
    """
    Calculate the end position of the IHDR chunk.
    4 bytes length + 4 bytes type + data length + 4 bytes CRC
    But since we start at 'IHDR', we add:
    8 (type + CRC) + ihdr_len
    """
    ihdr_end = ihdr_pos + 8 + ihdr_len
    """
    Step 5: Write the new polyglot file.
    Structure:
    - PNG Signature
    - Original IHDR chunk
    - Injected tEXt payload chunk
    - Remaining original PNG chunks
    """
    with open(output_png, 'wb') as f:
        """
        Write PNG signature manually to preserve validity.
        """
        f.write(b'\x89PNG\r\n\x1a\n')
        """
        Write original PNG data up to end of IHDR.
        """
        f.write(png_data[8:ihdr_end])
        """
        Insert our crafted payload chunk.
        """
        f.write(shell_chunk)
        """
        Append the rest of the original PNG data.
        """
        f.write(png_data[ihdr_end:])
    print(f"[+] Created polyglot: {output_png}")
def main():
    """
    Entry point of the program.
    Handles:
    - User input for PNG file
    - Command to embed
    - Output file naming
    """
    input_png = input("[+] Input PNG file: ").strip()
    """
    Validate that the input file exists before proceeding.
    """
    if not os.path.exists(input_png):
        print("[-] Input file not found!")
        return
    """
    Get the command that will be embedded into the polyglot.
    """
    command = input("[+] Command to execute: ").strip()
    """
    Generate output filename based on original name.
    """
    base = os.path.splitext(input_png)[0]
    output_png = f"{base}_polyglot.png"
    """
    Call the core function to generate the polyglot.
    """
    create_perfect_polyglot(input_png, output_png, command)
"""
Ensure the script runs only when executed directly,
not when imported as a module.
"""
if __name__ == "__main__":
    main()
```

Here's the output:

![As demonstrated in this proof of concept, the polyglot file can both be opened and viewed like a normal image while simultaneously being executable through Bash.](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*lhBLncgtPexi1LGMIDU9dA.gif)

## Where This Technique Sits in the Bigger Picture

It's worth being explicit about what a PNG/shell polyglot like this actually demonstrates and doesn't demonstrate:

- It does **not** exploit a memory-corruption bug, a parser vulnerability, or any flaw specific to a particular piece of software. It exploits the *intended, spec-compliant* leniency of two well-behaved parsers being pointed at the same bytes.
- The "attack" only succeeds if something downstream actually executes the file as a script (e.g., `bash image.png`, or a misconfigured pipeline that runs uploaded files). A polyglot sitting on disk, or opened only in an image viewer, does nothing on its own.
- This is why the primary real-world relevance is less "remote code execution" and more a **validation and defense-in-depth lesson**: file-type checks that rely only on a magic-number/extension check, without also constraining *what can ever execute a user-supplied file*, are checking the wrong thing.

### How Defenders Typically Address This Class of Issue

- **Never execute user-uploaded files directly**, regardless of their claimed or detected type — treat uploads as data, not code, unless there's a specific, sandboxed reason to run them.
- **Re-encode or re-render untrusted images** (e.g., decode and re-save through a trusted image library) rather than storing the original bytes; re-encoding strips ancillary chunks like tEXt and destroys any polyglot structure, because the re-encoder only emits the pixel data it understood.
- **Strip metadata** on ingestion using well-tested tools, and validate that a file contains *only* the chunk types expected for its use case.
- **Separate storage and execution contexts** (e.g., serve uploaded images from a domain or path with no script-execution permissions, correct `Content-Type` headers, and `X-Content-Type-Options: nosniff` to stop content-sniffing in browsers).
- **Don't trust extensions or magic numbers alone** as a security boundary — they're a UX/routing convenience, not an integrity guarantee.

Polyglot files have significant implications in cybersecurity, especially in red teaming and penetration testing. They allow a single file to behave differently depending on the parser, meaning a seemingly harmless image can simultaneously carry executable payloads. This dual nature can be used to bypass superficial file validation, evade endpoint protections, or deliver malicious scripts without triggering traditional signature-based defenses. Attackers could exploit this to deliver malware, exfiltrate data, or bypass content filters, while defenders face challenges because many scanners rely primarily on file extensions or headers, which can be misleading.

This highlights the critical importance of rigorous content validation and threat awareness. Security measures cannot rely solely on file extensions or visual inspection to determine trustworthiness; the actual structure and behavior of the file must be considered. By understanding polyglot techniques, organizations and security professionals can better anticipate stealthy attack vectors, design more robust validation mechanisms, and reinforce defenses against files that appear innocuous but carry hidden, potentially dangerous content.

That's a wrap! I hope this guide has given you a deeper understanding of polyglot files, how they operate, and the clever ways data can be manipulated across multiple parsers. Beyond the technical insight, I hope it also highlighted the security lessons these files teach us — about trusting file extensions, validating content thoroughly, and understanding how seemingly harmless files can carry hidden functionality.

As one cybersecurity expert once said: *"Security is not a product, but a process."* Exploring polyglots reminds us that true security comes from understanding the inner workings of files and systems, not just relying on surface-level assumptions. Stay curious, stay vigilant, and keep learning!
