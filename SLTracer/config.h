/*
* SystemCall/LibraryCall Tracer (config.h)
*
*    Coded by 1ndr4 (indra.kr@gmail.com)
* 
* https://github.com/indra-kr/Linux-Dynamic-Analysis/blob/master/SLTracer/config.h
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <bits/siginfo.h>
#include <string.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <elf.h>
#include <linux/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/reg.h>

#define SYSCALL_NUMBER 319

#define _DT_TYPE_IMM	0x01
#define _DT_TYPE_ADDR	0x02
#define _DT_TYPE_STR	0x03
#define _DT_TYPE_UNK	0xFF

#define MAX_BUFFER_SIZE 64
#define MAX_POINTER_NUM	3
#define MAX_ARGS_NUM 3

// XXX: Dependently MACROs
// on 32bit OSs
#define DEF_ALIGN	4
#define ADDR_LONG_MINUS	0xFFFFFFFF
#define ADDR_LONG_NULL	0x00000000
#define ADDR_WORD_MINUS	0x0000FFFF
// 0xCD 0x80 : int 0x80
#define IA32_SYSCALL_INT	0x000080CD
#define IA32_LIBCALL_INT	0x000000E8

#define SECTION_HEADER	0x01
#define SYM_TAB_ENT	0x02
#define REL_ENT		0x04

#define TYPE_SYSCALL	0x01
#define TYPE_FUNCTION	0x02

#define ERROR(fmt, ...) fprintf(stderr, "[ERROR] " fmt " (%s(): %d line)\n", ##__VA_ARGS__, __func__, __LINE__)
#define PRINT(fmt, ...) fprintf(stdout, fmt " (%s(): %d line)\n", ##__VA_ARGS__, __func__, __LINE__)

typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Shdr Elf_Shdr;
typedef Elf32_Sym Elf_Sym;
typedef Elf32_Rel Elf_Rel;

struct reloc_link {
	unsigned int addr;
	char *name;
	void *next;
};

struct _dts {
	unsigned char type;
	void *data;
	unsigned int len;
	unsigned char pnt_cnt;
};

struct syscall_table {
	int number;
	char *name;
};

struct syscall_info {
	int no;
	void *args[MAX_ARGS_NUM];
	unsigned char types[MAX_ARGS_NUM];
	unsigned char pnt_cnt[MAX_ARGS_NUM];
};

void make_syscall_table(void);
char *get_syscall_name(int);
int get_syscall_number(const char *);
