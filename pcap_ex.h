/* $Id$ */

#ifndef PCAP_EX_H
#define PCAP_EX_H

char *pcap_ex_name(char *name);

int   pcap_ex_fileno(pcap_t *pcap);

int   pcap_ex_wait(int handle);

#endif /* PCAP_EX_H */
