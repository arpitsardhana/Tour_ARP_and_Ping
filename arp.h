#include "utility.h"

#define REQ 0 
#define REP 1  

#define ID       0x6005
#define PROTO_ID 0x1554
struct arp {
	uint16_t id;
	uint16_t htype;
	uint16_t ptype;
	uint8_t hlen;
	uint8_t plen;
	uint16_t option;
        uint8_t tha[IF_HADDR];
        struct in_addr dst_ip;
	uint8_t sha[IF_HADDR];
	struct in_addr src_ip;
};

struct frame_ethernet {
	uint8_t dst_mac[IF_HADDR];
	uint8_t src_mac[IF_HADDR];
	uint16_t proto_id;
	struct arp packet;
};

struct arp_entry {
	int valid;
	char hwaddr[IF_HADDR];
	int htype;
	int fd;
	struct in_addr ip;
	int if_index;
};

//struct ip_hw_pairs {
//	struct in_addr ip;
//	char hw[IF_HADDR];
//};

	
