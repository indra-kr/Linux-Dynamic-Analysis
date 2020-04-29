/*
* SystemCall/LibraryCall Tracer (const.h)
*
*    Coded by 1ndr4 (indra.kr@gmail.com)
* 
* https://github.com/indra-kr/Linux-Dynamic-Analysis/blob/master/SLTracer/const.h
*/

struct signos {
	int signo;
	char *signame;
};

struct signos sigs[] = {
	{ 1, "SIGHUP" },
	{ 2, "SIGINT" },
	{ 3, "SIGQUIT" },
	{ 4, "SIGILL" },
	{ 5, "SIGTRAP" },
	{ 6, "{SIGABRT or SIGIOT}" },
	{ 7, "SIGBUS" },
	{ 8, "SIGFPE" },
	{ 9, "SIGKILL" },
	{ 10, "SIGUSR1" },
	{ 11, "SIGSEGV" },
	{ 12, "SIGUSR2" },
	{ 13, "SIGPIPE" },
	{ 14, "SIGALRM" },
	{ 15, "SIGTERM" },
	{ 16, "SIGSTKFLT" },
	{ 17, "SIGCHLD" },
	{ 18, "SIGCONT" },
	{ 19, "SIGSTOP" },
	{ 20, "SIGTSTP" },
	{ 21, "SIGTTIN" },
	{ 22, "SIGTTOU" },
	{ 23, "SIGURG" },
	{ 24, "SIGXCPU" },
	{ 25, "SIGXFSZ" },
	{ 26, "SIGVTALRM" },
	{ 27, "SIGPROF" },
	{ 28, "SIGWINCH" },
	{ 29, "{SIGPOLL or SIGIO}" },
	{ 30, "SIGPWR" },
	{ 31, "SIGSYS" },
	{ 0, 0 }
};

