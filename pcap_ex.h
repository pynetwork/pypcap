/* $Id$ */

#ifndef PCAP_EX_H
#define PCAP_EX_H

void  pcap_ex_immediate(pcap_t *pcap);
char *pcap_ex_name(char *name);
int   pcap_ex_fileno(pcap_t *pcap);
void  pcap_ex_setup(pcap_t *pcap);
int   pcap_ex_next(pcap_t *pcap, struct pcap_pkthdr **hdr, u_char **pkt);

#endif /* PCAP_EX_H */
