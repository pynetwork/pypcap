/* $Id$ */

#ifndef _WIN32
# include <sys/types.h>
# include <sys/time.h>
# include <string.h>
# include <unistd.h>
#endif

#include <pcap.h>
#ifndef _WIN32
# include <pcap-int.h>
#endif
#include "pcap_ex.h"

char *
pcap_ex_name(char *name)
{
#ifdef _WIN32
	static char pcap_name[256];
        pcap_if_t *pifs, *cur, *prev, *next;
	char ebuf[128];
	int i, idx, max;

	if (strncmp(name, "eth", 3) != 0 ||
	    sscanf(name + 3, "%u", &idx) != 1 ||
	    pcap_findalldevs(&pifs, ebuf) == -1 || pifs == NULL) {
		return (name);
	}
	/* XXX - flip script like a dyslexic actor */
	for (prev = NULL, cur = pifs, max = 0; cur != NULL; max++) {
		next = cur->next;
		cur->next = prev;
		prev = cur;
		cur = next;
	}
	pifs = prev;
	for (cur = pifs, i = 0; i != idx && i < max; i++) {
		cur = cur->next;
	}
	if (i != max) {
		strncpy(pcap_name, cur->name, sizeof(pcap_name)-1);
		name = pcap_name;
	}
	pcap_freealldevs(pifs);
	return (name);
#else
	return (name);
#endif
}

int
pcap_ex_fileno(pcap_t *pcap)
{
#ifdef _WIN32
	/* XXX - how to handle savefiles? */
	return ((int)pcap_getevent(pcap));
#else
	if (pcap->sf.rfile != NULL)
		return (fileno(pcap->sf.rfile));
	return (pcap_fileno(pcap));
#endif
}

#ifdef _WIN32
static int __pcap_ex_gotsig;

static BOOL CALLBACK
__pcap_ex_ctrl(DWORD sig)
{
	__pcap_ex_gotsig = 1;
	return (TRUE);
}

int
pcap_ex_wait(int handle)
{
	DWORD ret;

	/* XXX - hrr, this sux */
	SetConsoleCtrlHandler(__pcap_ex_ctrl, TRUE);
	__pcap_ex_gotsig = 0;
	
	for (;;) {
		ret = WaitForSingleObject((HANDLE)handle, 100);
		if (ret == WAIT_FAILED) {
			return (-1);
		} else if (ret == WAIT_TIMEOUT) {
			if (__pcap_ex_gotsig)
				return (-1);
		} else break;
	}
	return (0);
}
#else
int
pcap_ex_wait(int fd)
{
	fd_set rfds;
	
	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);
	return (select(fd + 1, &rfds, NULL, NULL, NULL));
}
#endif

