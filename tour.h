#ifndef _TOUR_H
#define _TOUR_H

#include "utility.h"
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#define MACLEN 6
#define PROTO_ID 177
#define ID 0x6205
#define PING_ID 0x6205
#define TTL_VAL 1

#define PORT_MULTICAST 7777
#define IP_MULTICAST "234.245.120.120"
#define IF_HADDR 6

struct ping_header{
	struct ip ip_hdr;
	struct icmp icmp_hdr;
}__attribute__((packed));

struct ping_packet {
	uint8_t dest_mac[MACLEN];
	uint8_t src_mac[MACLEN];
	uint16_t proto_id;
	struct ping_header ping_hdr;
}__attribute__((packed));

struct tour_packet {
	struct ip ip_header;
	struct in_addr ip;
	uint16_t port;
	uint16_t index;
	uint16_t end_index;
	struct in_addr vm_list[50];
}__attribute__((packed)); 
struct ping_list {
	int status ;
	struct in_addr ip;

};
//int fill_ping_packet_header(uint8_t *dst_mac,uint8_t *src_mac,struct ping_packet *packet,struct sockaddr_ll *sockAddr,uint32_t src_ip,uint32_t dst_ip);
//void proc_v4(int fd);

#endif
