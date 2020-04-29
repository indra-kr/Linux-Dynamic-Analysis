/*
* SystemCall/LibraryCall Tracer (const.c)
*
*    Coded by 1ndr4 (indra.kr@gmail.com)
* 
* https://github.com/indra-kr/Linux-Dynamic-Analysis/blob/master/SLTracer/const.c
*/
#include <stdio.h>
#include <string.h>
#include "const.h"

int signo_by_signame(const char *signame)
{
	int i = 0;
	while(sigs[i++].signo != 0) {
		if(strstr(signame, sigs[i].signame) != NULL)
			return sigs[i].signo;
	}
	return -1;
}

char *signame_by_signo(int signo)
{
	int i = 0;
	while(sigs[i++].signo != 0) {
		if(sigs[i].signo == signo)
			return sigs[i].signame;
	}
	return NULL;
}
