# SLTracer

A trace program for system call and library call on the 32bit linux machine. This program was a private pilot project for the PoC of dynamic analysis about mobile applications. See [Regarding of analysis methodology on the mobile applications](https://teamcrak.tistory.com/377)

### Compiling and running program
```sh
$ make && ./sl-tracer
```

### Example
```sh
$ cat open.c
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

int main(void)
{
	int fd;

	if((fd = open("passwd", O_CREAT|O_RDWR, 0666)) > 0) {
		close(fd);
		unlink("passwd");
	}
	return 0;
}
$ cc -o open open.c && ./sl-tracer ./open
[          SystemCall/LibraryCall Tracer          ]
[                                                 ]
[             Coded by 1ndr4 (indra.kr@gmail.com) ]

[*] Analyzing a ELF file: ./open
[801] Created a Process: 802
[*] Process attach successfully: 802
[S] execve("./open", ["./open"...], 00000000);  = 0 (0x00000000)
[S] brk(00000000, 0001BEF8, ["i686"...]);  = 162365440 (0x09AD8000)
[S] access("/etc/ld.so.preload", 00000004, 0001BEF8);  = -2 (0xFFFFFFFE)
[S] open("/etc/ld.so.cache", 00000000, 00000000);  = 3 (0x00000003)
[S] fstat64(00000003, 00000000, 0001BEF8);  = 0 (0x00000000)
[S] mmap2(00000000, 00009A55, 00000001);  = -1208578048 (0xB7F69000)
[S] close(00000003, 00009A55, 0001BEF8);  = 0 (0x00000000)
[S] open("/lib/libc.so.6", 00000000, 0000019F);  = 3 (0x00000003)
[S] read(00000003, 00000000, 00000200);  = 512 (0x00000200)
[S] mmap2(00000000, 00001000, 00000003);  = -1208582144 (0xB7F68000)
[S] fstat64(00000003, 464C457F, 0001BEF8);  = 0 (0x00000000)
[S] mmap2(00000000, 001585C4, 00000005);  = 14839808 (0x00E27000)
[S] mprotect(00000000, 00001000, 00000000);  = 0 (0x00000000)
[S] mmap2(0000006F, 00003000, 00000003);  = 16228352 (0x00F7A000)
[S] mmap2("1.2 20080704 (Red Hat 4.1.2-52)", 000025C4, 00000003);  = 16240640 (0x00F7D000)
[S] close(00000003, 00000003, 0001BEF8);  = 0 (0x00000000)
[S] mmap2(00000000, 00001000, 00000003);  = -1208586240 (0xB7F67000)
[S] set_thread_area(FFFFFFFF, B7F676C0, 000000F3);  = 0 (0x00000000)
[S] mprotect(00000000, 00002000, 00000001);  = 0 (0x00000000)
[S] mprotect(00000116, 00001000, 00000001);  = 0 (0x00000000)
[S] munmap("ld.so-1.7.0", 00009A55, 0001BEF8);  = 0 (0x00000000)
[F] CALL __libc_start_main(04244C8D, 00000001, ["./open"...]);
[F] CALL open("passwd", 00000042, 000001B6);
[S] open("passwd", 00000042, 000001B6);  = 3 (0x00000003)
[F] CALL close(00000003, 00000042, 000001B6);
[S] close(00000003, 00000042, 00154D9C);  = 0 (0x00000000)
[F] CALL unlink("passwd", 00000042, 000001B6);
[S] unlink("passwd", 00000042, 00154D9C);  = 0 (0x00000000)
[S] exit_group(00000000, 00000000, 00000000); Killed the child process (PID: 802)
$
```
- [S] : System Call
- [F] : Library Call
