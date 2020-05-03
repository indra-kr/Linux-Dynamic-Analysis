/*
* A PoC code for hooking the send syscall by ptrace on the 32bit and 64bit machines.
*
*    Coded by 1ndr4 (indra.kr@gmail.com)
* 
* https://github.com/indra-kr/Linux-Dynamic-Analysis/blob/master/SendHookPoC/SendHookPoC.c
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/reg.h>

/*
XXX: Executing socket syscall on the 64bit machine

ORIG_RAX = syscall number
RSI = buffer address
RDX = buffer length
*/
#if defined(__x86_64__)
	#include <asm/unistd_64.h>
	#define SEND_SYSCALL_NUMBER	 __NR_sendto
	#define GET_SYSTYPE(m)		0x09 // XXX: implicit returns 0x09
	#define GET_SYSNUM(m)	  m.orig_rax
	#define GET_STACKADDR(m)	   m.rsi
	#define GET_STRLENGTH(m)	   m.rdx
	#define DEF_ALIGN	   8
#else
/*
XXX: Executing socket syscall on the 32bit machine

32비트 머신에서의 socket 관련 system call 실행방식은 64비트와 차이가 있음.
32비트 머신에서 socket(), send(), recv() 등의 시스템콜을 실행시키면,
__NR_socketcall로 define된 시스템콜을 사용하며,
__NR_socketcall 시스템콜 수행 시, 시스템콜 타입정보를 매개변수로 전달하는데,
이 때 해당 인자별로 각 socket(), send() 등의 시스템콜들을 나눠 수행함.

ORIG_EAX는 __NR_socketcall sys-call 번호
EBX는 수행할 sys-call 타입 (send 함수의 경우 0x09)
ECX는 Stack Address
Stack Address의 제일 처음 존재하는 정보는 소켓기술자이고,
그 다음은 사용자 버퍼 주소, 버퍼 길이 정보, 널 포인터, 사용자 버퍼 내용 순으로 들어간다.
*/
	#include <asm/unistd.h>
	#define SEND_SYSCALL_NUMBER	 __NR_socketcall
	#define GET_SYSTYPE(m)		m.ebx
	#define GET_SYSNUM(m)	  m.orig_eax
	#define GET_STACKADDR(m)	   m.ecx
	#define GET_STRLENGTH(m)	   m.ecx + 8 // XXX: fixed definition
	#define DEF_ALIGN	   4
#endif

#define FREE(m) { if(m != NULL) free(m); m = NULL; }

void code_print(FILE *fp, const unsigned char *data, int sz)
{
	int i = 0, j = 0, c = 0, dec = 64;
	char buf[80];
	fprintf(fp, "%08X  ", i);
	for(i = 0; i < sz; i++) {
		if((i%16 == 0) && (i != 0)) {
			fprintf(fp, "\t");
			for(j = (i - 16); j != i; j++) {
				c = *(data + j);
				fprintf(fp, "%c", isprint(c) != 0 ? c : '.');
			}
			fprintf(fp, "\n%08X  ", i);
		}
		fprintf(fp, "%02X ", *(data + i));
	}
	if(i > j) {
		dec = dec - (((i - j) * 3) + 10);
		memset(buf, 0x00, sizeof(buf));
		memset(buf, 0x20, dec);
		fprintf(fp, "%s", buf);
		for(j; j < i; j++) {
			c = *(data + j);
			fprintf(fp, "%c", isprint(c) != 0 ? c : '.');
		}
	}
	fprintf(fp, "\n\n");
	return;
}

int main(int argc, char **argv)
{
	int pid = 0, i = 0, j = 0, replaced = 0;
	struct user_regs_struct regs;
	unsigned char *mem = NULL, *new = NULL;
	unsigned long int data;
	unsigned int len;
	unsigned long int syscall_number, syscall_type, stack_addr;

	if(argc != 4) {
		fprintf(stderr, "Usage: %s <pid> <source-string> <dest-string>\n", argv[0]);
		return -1;
	}
	pid = atoi(argv[1]);
	if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
		fprintf(stderr, "[!] ptrace() error\n");
		return -1;
	}

	while(1) {
		replaced = 0;
		ptrace(PTRACE_GETREGS, pid, NULL, &regs);
		syscall_number = GET_SYSNUM(regs);
		syscall_type = GET_SYSTYPE(regs);
#if defined(__x86_64__)
		stack_addr = GET_STACKADDR(regs);
		len = GET_STRLENGTH(regs);
#else
		stack_addr = ptrace(PTRACE_PEEKDATA, pid, regs.ecx + 4, 0);
		len = ptrace(PTRACE_PEEKDATA, pid, regs.ecx + 8, 0);
#endif

		if(GET_SYSNUM(regs) == SEND_SYSCALL_NUMBER && GET_SYSTYPE(regs) == 0x09) {
			if((mem = malloc(len)) == NULL) {
				fprintf(stderr, "[!] Out of memory: %d bytes\n", len);
				goto failed;
			}
			memset(mem, 0x00, len);
			for(i = 0; i < len; i+=DEF_ALIGN) {
				data = ptrace(PTRACE_PEEKDATA, pid, stack_addr + i, 0);
				memcpy(mem + i, &data, DEF_ALIGN);
			}
			// Writing (internal-memory)
			if((new = malloc(len*2)) == NULL) {
				fprintf(stderr, "[!] Out of memory: %d bytes\n", len*2);
				goto failed;
			}
			memset(new, 0x00, len*2);
			j = 0;
			for(i = 0; i < len; i++,j++) {
				if(memcmp(mem + i, argv[2], strlen(argv[2])) == 0) {
					memcpy(new + j, argv[3], strlen(argv[3]));
					i += strlen(argv[2]) - 1;
					j += strlen(argv[3]) - 1;
					replaced = 1;
				} else {
					*(new + j) = *(mem + i);
				}
			}
			fprintf(stdout, "----- Original Memory (%d bytes)\n", len);
			code_print(stdout, mem, len);
			fprintf(stdout, "----- Original Memory\n");

			if(replaced == 1) {
				fprintf(stdout, "----- Modified Memory (%d bytes)\n", strlen(new));
				code_print(stdout, new, strlen(new));
				fprintf(stdout, "----- Modified Memory\n");

				// Writing (process-memory)
				for(i = 0; i < strlen(new); i+=DEF_ALIGN) {
					memcpy(&data, new + i, DEF_ALIGN);
					ptrace(PTRACE_POKEDATA, pid, stack_addr + i, data);
				}
#if defined(__x86_64__)
				regs.rdx = strlen(new);
				ptrace(PTRACE_SETREGS, pid, 0, &regs);
#else
				ptrace(PTRACE_POKEDATA, pid, regs.ecx + 8, strlen(new));
#endif
				
			}	
failed:
			FREE(new);
			FREE(mem);
		}
		ptrace(PTRACE_SYSCALL, pid, 1, 0);
	}
	ptrace(PTRACE_DETACH, pid, NULL, NULL);
}
