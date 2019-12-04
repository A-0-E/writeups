# Gomium Browser

## Description

The Gomium Browser is the latest, safest browser written entirely in the memory-safe language Go. Can you break it? Prepare an exploit, put it on your USB stick and come on stage demonstrate it live pwn2own-style! We will run gomium `file:///media/usb/exploit.htm` and you should pop xcalc. The computer will be a Debian 10 buster (https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-10.1.0-amd64-netinst.iso) with Xfce and Go 1.13.3 installed (https://dl.google.com/go/go1.13.3.linux-amd64.tar.gz).

https://storage.googleapis.com/gctf-2019-attachments/fd4ab02a5c301ef666343bc10fde869baaf2f56b7534f3d0b68b427180d16a1b

## Writeup

Author: Jackyxty, Gengming Liu

This is an interesting bug in fmt component. Here is the POC of the initial issue[1], but we found something interesting. The patch of the bug just changed the depth from 100 to 250, so what if we add more recursions to the original poc? The result is as we expected, it crashed.

After some research, we found it is a type confusion bug. The very deep sliceHeader(array) will be treated as the type of the innermost object(`type pwn struct` in our exploit) and try to stringify it. So if we define a structure and its `String()` function, the sliceHeader will be passed to the function and treated as `struct pwn`(Similar to redefinition in JS, right? :)). Since the structure and function is fully controlled by us, we can make whatever changes we like to the sliceHeader. In our exploit, e.g., we change the `sliceHeader.Data` and `sliceHeader.Len`, so we have the arbitrary address access, which can be easily turned to arb r/w.

Function pointer is a structure holding a pointer to pointer to the compiled function. We can use arbitrary write to overwrite it, so that we can control the RIP register. Here we use a trick similar to JIT Spray(JS again :)). We prepared the function `runsc` with some immediates, which would be directly hardcoded into the instructions. Actually these are 6-byte shellcode(last two bytes jump to the next immediate). In our exploit, the 6-byte shellcode is used to mprotect and jump to the parameter which contains the final shellcode. Finally we have a xcalc poped up.

[1] https://go-review.googlesource.com/c/go/+/154583
