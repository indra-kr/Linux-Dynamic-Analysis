/*
* SystemCall/LibraryCall Tracer (main.c)
*
*    Coded by 1ndr4 (indra.kr@gmail.com)
* 
* https://github.com/indra-kr/Linux-Dynamic-Analysis/blob/master/SLTracer/main.c
*/
#include "config.h"

struct syscall_table syscalls[SYSCALL_NUMBER];
extern struct reloc_link *rel_link;

int is_noprintable(int s)
{
	int i = 0;
	unsigned char c = 0;

	for(i = 0; i <= 24; i+=8) {
		c = s >> i;
		// FIXME: multi-byte characters
		if(c < 0x20 || c > 0x7E)
			return 1; // no-printable
	}
	return 0;
}

#define IS_NOPRINTABLE(s) is_noprintable(s)
#if 1

int FreeData(struct _dts *dts)
{
	free(dts->data);
	return 0;
}

char *convert_special_chars(void *mem)
{
	char *ptr = (char*)mem, *newptr = NULL;
	char *ret = NULL;

	if(mem == NULL)
		return NULL;
	
	if((ret = malloc(strlen(mem)*2)) == NULL) {
		ERROR("Out of memory");
		return NULL;
	}
	memset(ret, 0x00, strlen(mem)*2);
	newptr = ret;
	while(*ptr != '\0') {
		if(*ptr == '\n') {
			*newptr = '\\'; newptr++;
			*newptr = 'n';
		} else {
			*newptr = *ptr;
		}
		ptr++;
		newptr++;
	}
	return ret;
}

struct _dts *GetData(int pid, unsigned long addr, unsigned int sz)
{
	int i = 0, j = 0, found = 0;
	unsigned long data;
	struct _dts *dts = NULL;
	void *mem = NULL, *newmem = NULL;

	if((dts = (struct _dts *)malloc(sizeof(struct _dts))) == NULL) {
		ERROR("Out of memory: %d", sizeof(struct _dts));
		goto failed;
	}
	if(addr == ADDR_LONG_MINUS || addr == ADDR_LONG_NULL || addr <= ADDR_WORD_MINUS) {
		dts->type = _DT_TYPE_IMM;
		dts->data = addr;
		dts->len = sizeof(unsigned long);
		return dts;
	}
/*
FIXME: multiple pointer problem. char *val[5] = { "a", "b", "c", "d" };
(gdb) r
Starting program: /home/indra/Project/ptrace/dp
val: BFFFEA10, val[0]: 080485BC, val[1]: 080485BE, val[2]: 080485C0

Breakpoint 1, func (val=0xbfffea10) at dp.c:6
6               fprintf(stdout, "val[0]: %s, val[1]: %s, val[2]: %s\n", val[0], val[1], val[2]);
(gdb) x/16x 0xBFFFEA10
0xbfffea10:     0x080485bc      0x080485be      0x080485c0      0x080485c2
0xbfffea20:     0x00de5750      0xbfffea40      0xbfffea98      0x0095ae9c
0xbfffea30:     0x00df2ca0      0x080484a0      0xbfffea98      0x0095ae9c
0xbfffea40:     0x00000001      0xbfffeac4      0xbfffeacc      0x00df3828
(gdb) x/16x 0x080485bc
0x80485bc <__dso_handle+96>:    0x00620061      0x00640063      0x3b031b01      0x00000018
0x80485cc <fprintf+752>:        0x00000002      0xfffffecc      0x00000034      0xfffffedc
0x80485dc <fprintf+768>:        0x00000050      0x00000014      0x00000000      0x00527a01
0x80485ec <fprintf+784>:        0x01087c01      0x04040c1b      0x00000188      0x00000018
(gdb)
*/
	for(i = 0; i <= MAX_POINTER_NUM; i++) {
		errno = 0;
		data = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
		if(errno != 0) {
			//ERROR("[%d] PEEKDATA error : %d (%s) 0x%08X", i, errno, strerror(errno), addr);
			data = addr;
			break; // XXX: access violation?
		}
		if(!IS_NOPRINTABLE(data)) {
			found++; 
			break;
		}
		addr = data;
	}

	if(found) {
		if((mem = malloc(MAX_BUFFER_SIZE)) == NULL) {
			ERROR("Out of memory: %d", MAX_BUFFER_SIZE);
			goto failed;
		}

		memset(mem, 0x00, MAX_BUFFER_SIZE);
		memcpy(mem, &data, DEF_ALIGN);

		for(j = DEF_ALIGN; j < MAX_BUFFER_SIZE; j += DEF_ALIGN) {
			errno = 0;
			data = ptrace(PTRACE_PEEKDATA, pid, addr + j, 0);
			if(errno != 0) {
				//ERROR("PEEKDATA error from 0x%08X => %s: %d (%s)", addr + j, mem, errno, strerror(errno));
				//goto failed;
				break;
			}

			memcpy(mem + j, &data, DEF_ALIGN);
		}
		if((newmem = convert_special_chars(mem)) != NULL) {
			free(mem);
			mem = NULL;
		} else {
			newmem = mem;
		}
		dts->type = _DT_TYPE_STR;
		dts->data = newmem;
		dts->len = MAX_BUFFER_SIZE;
		dts->pnt_cnt = i;
	} else {
		dts->type = _DT_TYPE_ADDR;
		dts->data = data;
		dts->len = sizeof(unsigned long);
		dts->pnt_cnt = 0;
	}
	return dts;
failed:
	if(dts != NULL)
		free(dts);
	if(mem != NULL)
		free(mem);
	return NULL;
}
#endif

struct syscall_info *GetArgsInfo(int pid, struct user_regs_struct *regs)
{
	struct _dts *dts = NULL;
	struct syscall_info *ret = NULL;
	unsigned long addr, esp;
	int i;

	if((ret = (struct syscall_info *)malloc(sizeof(struct syscall_info))) == NULL) {
		ERROR("Out of memory: %d", sizeof(struct syscall_info));
		return NULL;
	}

	memset(ret, 0x00, sizeof(struct syscall_info));
	esp = regs->esp;

	for(i = 0; i < MAX_ARGS_NUM; i++) {
		errno = 0;

		addr = ptrace(PTRACE_PEEKDATA, pid, esp, 0);
		if(errno != 0) {
			ERROR("PEEKDATA error : %d (%s) 0x%08X", errno, strerror(errno), addr);
			goto failed;
		}

		if((dts = GetData(pid, addr, MAX_BUFFER_SIZE)) == NULL) {
			ERROR("GetData error");
			goto failed;
		}

		if(dts != NULL && dts->type == _DT_TYPE_STR)
			ret->types[i] = _DT_TYPE_STR;
		else
			ret->types[i] = _DT_TYPE_IMM;
		ret->args[i] = dts->data;
		ret->pnt_cnt[i] = dts->pnt_cnt;
		esp += sizeof(int);
		free(dts); dts = NULL;
	}

	return ret;

failed:
	if(ret != NULL)
		free(ret);
	if(dts != NULL)
		free(dts);
	return NULL;
}

struct syscall_info *GetSCInfo(int pid, struct user_regs_struct *regs)
{
	struct _dts *dts = NULL;
	struct syscall_info *ret = NULL;
	unsigned long addrs[MAX_ARGS_NUM] = { regs->ebx, regs->ecx, regs->edx };
	int i;

	if((ret = (struct syscall_info *)malloc(sizeof(struct syscall_info))) == NULL) {
		ERROR("Out of memory: %d", sizeof(struct syscall_info));
		return NULL;
	}
	memset(ret, 0x00, sizeof(struct syscall_info));
	ret->no = regs->eax;
	for(i = 0; i < MAX_ARGS_NUM; i++) {
		if((dts = GetData(pid, addrs[i], MAX_BUFFER_SIZE)) == NULL) {
			ERROR("GetData Error");
			goto failed;
		}
		if(dts != NULL && dts->type == _DT_TYPE_STR)
			ret->types[i] = _DT_TYPE_STR;
		else
			ret->types[i] = _DT_TYPE_IMM;
		ret->args[i] = dts->data;
		ret->pnt_cnt[i] = dts->pnt_cnt;
		free(dts); dts = NULL;
	}
	return ret;

failed:
	if(dts != NULL)
		free(dts);
	if(ret != NULL)
		free(ret);
	return NULL;
}

void print_pseudo_code(const char *name, struct syscall_info *info, int type)
{
	int i;

	if(type == TYPE_SYSCALL)
		fprintf(stdout, "[S] %s(", name);
	else
		fprintf(stdout, "[F] CALL %s(", name);

	for(i = 0; i < MAX_ARGS_NUM; i++) {
		if(info->types[i] == _DT_TYPE_STR) {
			if(info->pnt_cnt[i] == 0)
				fprintf(stdout, "\"%s\"", info->args[i]);
			else
				fprintf(stdout, "[\"%s\"...]", info->args[i]);
			free(info->args[i]);
		} else {
			fprintf(stdout, "%08X", info->args[i]);
		}
		if(i < (MAX_ARGS_NUM - 1))
			fprintf(stdout, ", ");
		else
			fprintf(stdout, ");%s", type == TYPE_FUNCTION ? "\n" : " ");
	}
	free(info);
}

int main(int argc, char **argv)
{
	int pid = 0, ret = 0, get_return_value;
	int status, child; 
	struct user_regs_struct regs, oregs;
	struct siginfo si;
	char *args[2], *funcname;
	long data, peekdata, peekdata2, call_address, plt_address;
	struct syscall_info *sc_info;

	fprintf(stdout, 
		"[          SystemCall/LibraryCall Tracer          ]\n"
		"[                                                 ]\n"
		"[             Coded by 1ndr4 (indra.kr@gmail.com) ]\n\n");

	if(argc != 2) {
		fprintf(stdout, "Usage: %s <PROG>\n", argv[0]);
		return -1;
	}

	rel_link = NULL;

	ElfAnalysis(argv[1]);
	make_syscall_table();

	pid = fork();
	switch(pid) {
	case 0: // child
		usleep(1);
		args[0] = argv[1];
		args[1] = NULL;
		execve(args[0], args, NULL); 
		break;
	case -1:
		ERROR("fork() error");
		break;
	default: // parent
		fprintf(stdout, "[%d] Created a Process: %d\n", getpid(), pid);

		while(ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0);

		fprintf(stdout, "[*] Process attach successfully: %d\n", pid);

		get_return_value = 0;

		while(1) {
			data = 0;
			status = 0;
			child = waitpid(-1, &status, 0);

			if(child == pid && WIFEXITED(status)) {
				fprintf(stdout, "Killed the child process (PID: %d)\n", pid);
				break;
			}
			memset(&si, 0x00, sizeof(si));
			if((ret = ptrace(PTRACE_GETSIGINFO, child, NULL, &si)) < 0) {
				// ptrace_getsiginfo() in linux-x.x.x/kernel/ptrace.c
				// lock_task_sighand()'s error is -EINVAL
				if(errno != EINVAL) {
					ERROR("GETSIGINFO error: %d - %s", child, strerror(errno));
					break;
				}
			}
			if(si.si_signo != SIGTRAP && si.si_pid != 0) {
				fprintf(stdout, "[!] Got a SIGNAL! (pid: %d, %s)\n", (unsigned short)si.si_pid, signame_by_signo(si.si_signo));
				data = si.si_signo;
				goto got_signal;
			}
			if(ptrace(PTRACE_GETREGS, child, NULL, &regs) < 0) {
				ERROR("GETREGS error");
				break;
			}

			peekdata = ptrace(PTRACE_PEEKDATA, child, regs.eip, 0);
			if(errno != 0) {
				ERROR("PEEKDATA error : %d (%s)", errno, strerror(errno));
				break;
			}
			if(get_return_value) {
				fprintf(stdout, " = %ld (0x%08X)\n", regs.eax, regs.eax);
				get_return_value--;
			}

			if((0x000000FF & peekdata) == IA32_LIBCALL_INT && (regs.eip & 0xFFFFF000) >= 0x08048000) {
				peekdata2 = 0; call_address = 0; plt_address = 0;
				peekdata2 = ptrace(PTRACE_PEEKDATA, child, regs.eip + sizeof(long), 0);
				peekdata2 = htonl(peekdata2);
				// call_address = 0xFFFE1234
				call_address = (peekdata & 0xFFFFFF00) >> 8;
				call_address |= (peekdata2 & 0xFF000000);
				call_address = regs.eip + sizeof(long) - (0xFFFFFFFF - call_address);
				// if PLT && i386, JMP == 0xFF 0x25 == sizeof(short)
				plt_address = ptrace(PTRACE_PEEKDATA, child, call_address + sizeof(short), 0);
				if(plt_address >= 0x08048000) {
					funcname = SearchFuncByPLT((unsigned int)plt_address);
					if(funcname != NULL) {
						#if 1
						if((sc_info = GetArgsInfo(child, &regs)) == NULL) {
							ERROR("GetArgsInfo() error");
							return -1;
						}
						print_pseudo_code(funcname, sc_info, TYPE_FUNCTION);
						#endif
						/* Trampoline by Function name */
						if(memcmp(funcname, "ptrace", strlen("ptrace")) == 0 || memcmp(funcname, "fprintf", strlen("fprintf")) == 0 || memcmp(funcname, "fork", strlen("fork")) == 0) {
							fprintf(stdout, "[*] Found printf()! : %08X %08X %08X %08X\n", peekdata, peekdata2, call_address, regs.eip);
							if(ptrace(PTRACE_GETREGS, child, NULL, &oregs) < 0) {
								ERROR("GETREGS error");
								break;
							}
							oregs.eip += (1 + sizeof(int));
							if(ptrace(PTRACE_SETREGS, child, NULL, &oregs) < 0) {
								ERROR("SETREGS error");
								break;
							}
						}
					}
				}
				
			}
			#if 1
			if((0x0000FFFF & peekdata) == IA32_SYSCALL_INT) {
				if((sc_info = GetSCInfo(child, &regs)) == NULL) {
					ERROR("GetSCInfo() error");
					return -1;
				}
				
				print_pseudo_code(get_syscall_name(sc_info->no), sc_info, TYPE_SYSCALL);
				get_return_value++;
			}
			#endif
got_signal:
			ptrace(PTRACE_SINGLESTEP, child, 1, data);
		}
		break;
	}
	fprintf(stdout, "\n");
	return 0;
}
