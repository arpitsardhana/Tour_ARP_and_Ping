#ifndef _UTILITY_H
#define _UTILITY_H

#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <stdlib.h>
#include <stdio.h>
#include "unp.h"
#include "hw_addrs.h"

#define ARP_FILE "/tmp/arp_temp_arpsingh"

struct ip_hw_pairs {
        struct in_addr ip;
        uint8_t hw[IF_HADDR];
};

struct hwaddr {
 int sll_ifindex; /* Interface number */
 uint16_t sll_hatype; /* Hardware type */
 uint8_t  sll_halen; /* Length of address */
 uint8_t sll_addr[8]; /* Physical layer address */
};

struct arp_local_req {
	int index;
	int type;
	int len;
	struct in_addr ip;
};
void getTempPath(char *filePath,char *fileName,int flag);
void getVMsIP(char *hostIP);
char *getVMIPaddressbyNode(char *vmip,int nodenum);
int createDomaimDGramSock(char *tempPath);
int getHostVMNo();
int getVMByIP(char *addr);
int get_pairs(struct ip_hw_pairs ip_hw_map[]);
uint16_t in_cksum(uint16_t *addr, int len);
struct in_addr *getVMIPstruct(struct in_addr *vmip,int nodenum);
char* ethoNtoP(char *addr,char *result);
char* print_time();
char *getVMbyIPaddr(struct in_addr sa);
#endif
