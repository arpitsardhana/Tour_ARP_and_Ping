#include "tour.h"
#include "utility.h"

int pg_fd;
int rt_fd;
int pf_fd;
int udp_fd;
struct in_addr ip_multicast;
int port_multicast = PORT_MULTICAST;
struct hwaddr vm_mac_list[50];
struct in_addr vm_ip_list[50];
struct ip_hw_pairs ip_hw_map[50];
static int am_i_member_multicast = 0;
char host_ip[30];
struct in_addr host_ip_struct;
uint8_t hostmac[IF_HADDR];
char src_mac[IF_HADDR];
char dst_mac[IF_HADDR];
int total_nodes = 0;
int ping_enabled = 0;
int tour_ended = 0;
int count;
int ping_count = 5;
int fill_ping_packet_header(struct ping_packet *packet,uint32_t src_ip,uint32_t dst_ip);
void proc_v4(int fd);
void send_v4(void);
int multicast_message_sent = 0;
int ping_status[20] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
struct in_addr ping_add[20];
int exit_flag = 0;
int enable_multicating(struct in_addr ip_multicast,int port_multicast) {

	if (am_i_member_multicast == 1)
		return 1;

	
	struct sockaddr_in multisock;
	struct ip_mreq multi_req;
	uint8_t ttl = 1;
	uint8_t flag = 1;

	multisock.sin_family = AF_INET;
	multisock.sin_port = htons(port_multicast);
	multisock.sin_addr.s_addr = htonl(INADDR_ANY);
	
	int b = bind(udp_fd,(struct sockaddr *)&multisock,sizeof(multisock));

	setsockopt(udp_fd,IPPROTO_IP,IP_MULTICAST_TTL,&ttl,sizeof(ttl));
	setsockopt(udp_fd,IPPROTO_IP,IP_MULTICAST_LOOP,&flag,sizeof(flag));
	multisock.sin_addr.s_addr =ip_multicast.s_addr;

	multi_req.imr_multiaddr.s_addr = ip_multicast.s_addr;
	multi_req.imr_interface.s_addr = host_ip_struct.s_addr;

	int group_status = setsockopt(udp_fd,IPPROTO_IP,IP_ADD_MEMBERSHIP,
	(const void *)&multi_req,sizeof(struct ip_mreq ));
	am_i_member_multicast = 1;
	return 1;

}

int send_to_next_node(struct tour_packet *packet,int nodes) {

	struct ip *ip_hdr ;
	ip_hdr = (struct ip *)&(packet->ip_header); 
	struct sockaddr_in *destnode = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
        uint32_t src_addr = host_ip_struct.s_addr;		
	destnode->sin_family = AF_INET;
	packet->index++;
	struct in_addr addr_test;
	addr_test.s_addr = packet->vm_list[packet->index].s_addr;
	
         while  (getVMbyIPaddr(addr_test) == NULL) {
		printf("\n Next address not retreivable from Tour \n");
                if (packet->index == packet->end_index) {
			printf("\n Since address not accessible from packet, Ending Tour \n");
                        tour_ended = 1;
                        return 1;
                }
		packet->index++;
	}
	
	destnode->sin_addr.s_addr = packet->vm_list[packet->index].s_addr; 
	int size = sizeof(struct tour_packet);
	//calculate check sum
        uint16_t ck_sum = in_cksum((uint16_t *)packet,size);	
	ip_hdr->ip_hl  = sizeof(struct ip) >> 2;
	ip_hdr->ip_v = IPVERSION;
	ip_hdr->ip_tos = 0;

	ip_hdr->ip_len = htons(size);
	ip_hdr->ip_id  = htons(ID);
	ip_hdr->ip_off = 0;
	ip_hdr->ip_ttl = TTL_VAL;
	ip_hdr->ip_p   = PROTO_ID;
	ip_hdr->ip_src.s_addr = src_addr;
	ip_hdr->ip_dst.s_addr = packet->vm_list[packet->index].s_addr; 
	ip_hdr->ip_sum = ck_sum;
	int len = sizeof(struct tour_packet);

	int s =  sendto(rt_fd,packet,size,0,(struct sockaddr *)destnode,sizeof(struct sockaddr));
	//printf("send outputs %d \n",s);
	if (s<=0){
		perror("send error");
	}

	char *ipaddr = Sock_ntop_host((struct sockaddr *)destnode, sizeof(struct sockaddr));
	char vmip[INET_ADDRSTRLEN];
	char src_ip[INET_ADDRSTRLEN];
	struct in_addr des;
	des.s_addr = ip_hdr->ip_dst.s_addr;
	inet_ntop(AF_INET,&des,vmip,INET_ADDRSTRLEN);
	printf("\n Sending Tour socket %s dest %s src address is %s \n",ipaddr,vmip,inet_ntop(AF_INET,&ip_hdr->ip_src,src_ip,INET_ADDRSTRLEN));
	return size;

}
void print_ping_packet(struct ping_packet *p_ping) {
	struct ip *iphdr;
	struct icmp *icmphdr;

	iphdr = (struct ip *) &(p_ping->ping_hdr.ip_hdr);
	icmphdr = (struct icmp *) &(p_ping->ping_hdr.icmp_hdr);

        char src_add[20];
        char dest_add[20];
	char ip_src[20];
	char ip_dst[20];
   //ethoNtoP(sockAddr->sll_addr,sock_addr);
    ethoNtoP(p_ping->dest_mac,dest_add);
    ethoNtoP(p_ping->src_mac,src_add);
    inet_ntop(AF_INET,&(iphdr->ip_dst),ip_dst,INET_ADDRSTRLEN);
    inet_ntop(AF_INET,&(iphdr->ip_src),ip_src,INET_ADDRSTRLEN);
    printf("\n =====Printing Ping Packet======= \n");
    printf("Ethernet Header : Dest Mac %s  Src Mac %s  Proto id 0x%x",dest_add,src_add,ntohs(p_ping->proto_id));
    printf("\nIP header : Src %s Dst %s headerlen %d Ver %d TOS %d LEN %d ID 0x%x TTL %d Protocol %d Chksum 0x%x",ip_src,ip_dst,iphdr->ip_hl,iphdr->ip_v, 
iphdr->ip_tos,ntohs(iphdr->ip_len),ntohs(iphdr->ip_id),iphdr->ip_ttl,iphdr->ip_p,iphdr->ip_sum); 
       printf("\nICMP header : type %d  Code %d ID 0x%x Seq %d checksum 0x%x ",icmphdr->icmp_type,icmphdr->icmp_code,ntohs(icmphdr->icmp_id),ntohs(icmphdr->icmp_seq),ntohs(icmphdr->icmp_cksum));
    printf("\n====================================");

}
int fill_ping_packet_header(struct ping_packet *p_packet,uint32_t src_ip,uint32_t dst_ip) {

        int   len;
        struct icmp     *icmp_hdr;
        static int nsent = 1;
        memcpy(p_packet->dest_mac,dst_mac,MACLEN);
        memcpy(p_packet->src_mac, src_mac,MACLEN);
        p_packet->proto_id = htons(ETH_P_IP);

        icmp_hdr = &(p_packet->ping_hdr.icmp_hdr);

        icmp_hdr->icmp_type = ICMP_ECHO;
        icmp_hdr->icmp_code = 0;
        icmp_hdr->icmp_id = htons(PING_ID);
        icmp_hdr->icmp_seq = htons(++nsent);
        //memset(icmp_hdr->icmp_data, 0xa5, 56);
        Gettimeofday((struct timeval *) icmp_hdr->icmp_data, NULL);
        //len = 8 + datalen;             
        len = sizeof(struct icmp);
        icmp_hdr->icmp_cksum = 0;
        icmp_hdr->icmp_cksum = in_cksum((uint16_t *) icmp_hdr, len);


        struct ip *ip_hdr ;
        ip_hdr = (struct ip*)&(p_packet->ping_hdr.ip_hdr);

        ip_hdr->ip_hl  = sizeof(struct ip) >> 2;
        ip_hdr->ip_v = IPVERSION;
        ip_hdr->ip_tos = 0;
        ip_hdr->ip_len = htons(sizeof(struct ping_header));
        ip_hdr->ip_id  = htons(PING_ID);
        ip_hdr->ip_off = 0;
        ip_hdr->ip_ttl = 64;
        ip_hdr->ip_p   = IPPROTO_ICMP;
        ip_hdr->ip_src.s_addr = src_ip;
        ip_hdr->ip_dst.s_addr = dst_ip;
        int size = sizeof(struct ip);
        ip_hdr->ip_sum = in_cksum((uint16_t *)ip_hdr,size);

        return 1;

}


int send_ping_request(int pf_fd,struct in_addr src_ip,struct in_addr dest_ip) {

        struct sockaddr_in *IPaddr;
        IPaddr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
        IPaddr->sin_family = AF_INET;
        IPaddr->sin_port  = 0;
        IPaddr->sin_addr.s_addr = dest_ip.s_addr;

        struct hwaddr *HWaddr;
        HWaddr = (struct hwaddr *)malloc(sizeof(struct hwaddr));
        HWaddr->sll_halen = ETH_ALEN;
        HWaddr->sll_hatype = ARPHRD_ETHER;
        HWaddr->sll_ifindex = 2;

        int sock_len = sizeof(struct sockaddr);

        int areq_ret;
        areq_ret = areq((struct sockaddr *)IPaddr,sock_len,HWaddr);

        memcpy(dst_mac,HWaddr->sll_addr,IF_HADDR);
	memcpy(src_mac,hostmac,IF_HADDR);

        struct ping_packet p_ping;
	memset(&p_ping,'\0',sizeof(p_ping));
	
        fill_ping_packet_header(&p_ping,src_ip.s_addr,dest_ip.s_addr);

		
	    struct sockaddr_ll sockAddr;
	    memset(&sockAddr,'\0',sizeof(struct sockaddr_ll));	
	    sockAddr.sll_family   = PF_PACKET;
	    sockAddr.sll_halen    = ETH_ALEN;
   	    sockAddr.sll_ifindex  = 2;
            sockAddr.sll_addr[0] = dst_mac[0];
            sockAddr.sll_addr[1] = dst_mac[1];
            sockAddr.sll_addr[2] = dst_mac[2];
            sockAddr.sll_addr[3] = dst_mac[3];
            sockAddr.sll_addr[4] = dst_mac[4];
            sockAddr.sll_addr[5] = dst_mac[5];
            sockAddr.sll_addr[6] = 0x00;
            sockAddr.sll_addr[7] = 0x00;

	print_ping_packet(&p_ping);
	char vmip[30];
	printf("\n PING %s(%s) : %ld bytes of data \n",getVMbyIPaddr(dest_ip),inet_ntop(AF_INET,&dest_ip,vmip,INET_ADDRSTRLEN),sizeof(p_ping));
        int s = sendto(pf_fd,&p_ping,sizeof(p_ping),0,(struct sockaddr *)&sockAddr,sizeof(struct sockaddr_ll));
	if (s < 0) {
		perror("send to error");
	}
        return 1;
}

void end_multicast() {
  struct sockaddr_in multicast_socket;
  char buf[256];
  printf("\n This is node %s .Tour has ended .Group Members should identify themselves\n",getVMbyIPaddr(ip_hw_map[0].ip));
  multicast_socket.sin_family = AF_INET;
  multicast_socket.sin_addr.s_addr  = ip_multicast.s_addr;     
  multicast_message_sent = 1;
  multicast_socket.sin_port = htons(PORT_MULTICAST);
  memset(buf,'\0',100);
  sprintf(buf,"This is multicast message from %s",getVMbyIPaddr(ip_hw_map[0].ip));
  int s = sendto(udp_fd,(void *)buf,100,0,(struct sockaddr *)&multicast_socket,sizeof(struct sockaddr));
  exit_flag = 1;
  if (s<=0)
         perror("multicast error");

}
void monitor_sockets() {
	fd_set set_fd;
	fd_set set_sel;
	int mx_fd;
	struct sockaddr_in multicast_socket;
	struct timeval ping_timeout;
	FD_ZERO(&set_fd);
	struct tour_packet packet;
	char buf[100];
	struct in_addr dest_ip;
	strcpy(buf,"This is Multicast message \n");
	while(1) {

	FD_SET(rt_fd,&set_fd);
	mx_fd = rt_fd;

	if (am_i_member_multicast == 1) {
		FD_SET(udp_fd,&set_fd);
		mx_fd = max(rt_fd,udp_fd);
	}

	if (ping_enabled == 1 || exit_flag == 1) {
		FD_SET(pg_fd,&set_fd);
		mx_fd = max(mx_fd,pg_fd);
		ping_timeout.tv_sec = 1;
		ping_timeout.tv_usec = 0; 
		if (exit_flag == 1) {
			ping_timeout.tv_sec = 5;
			ping_timeout.tv_usec = 0;
			ping_enabled = 1;
		}

	}
	mx_fd = mx_fd +1;
	int s = select(mx_fd,&set_fd,NULL,NULL,ping_enabled ? &ping_timeout : NULL);
	if (s == 0)  {

	    if (exit_flag == 1) {
		exit(0);
	    }
	    if (tour_ended == 1) {
		if (ping_count >= 0)
			ping_count--;
	   } 
           if (ping_count == 0) {
		ping_enabled = 0;
	        end_multicast();
	   } else {
		int i;
		//send_ping_request(pf_fd,host_ip_struct,dest_ip);
		for (i = 1; i< 11;i++) {
			if (ping_status[i] == 1) {
				dest_ip.s_addr = ping_add[i].s_addr;
				send_ping_request(pf_fd,host_ip_struct,dest_ip);
			}

		}
	   }

	} 
	 else if (FD_ISSET(rt_fd,&set_fd)) {
			
		int len = recvfrom(rt_fd,&packet,sizeof(struct tour_packet),0,NULL,NULL);
		enable_multicating(ip_multicast,port_multicast);

                int ping_index = packet.index - 1;
                dest_ip.s_addr = packet.vm_list[ping_index].s_addr;
		printf(" \n %s Received Source Routing Packet from %s \n",print_time(),getVMbyIPaddr(dest_ip));
		ping_enabled = 1;
		char *vm_id = getVMbyIPaddr(dest_ip);
		vm_id++;
		vm_id++;
		int node_no = atoi(vm_id);
		ping_status[node_no] = 1;
		ping_add[node_no].s_addr = dest_ip.s_addr;
		send_ping_request(pf_fd,host_ip_struct,dest_ip);
	        if (packet.index == packet.end_index) {
			tour_ended = 1;	
			continue;	
		}
		send_to_next_node(&packet,count);
	} else if (FD_ISSET(udp_fd,&set_fd)) {
		char buf[100];
		int len = recvfrom(udp_fd,buf,100,0,NULL,NULL);
                printf("\n Node %s Received  %s \n",getVMbyIPaddr(ip_hw_map[0].ip),buf);
		if (multicast_message_sent == 0) {

                        multicast_socket.sin_family = AF_INET;
                        multicast_socket.sin_addr.s_addr  = ip_multicast.s_addr;     
                        multicast_socket.sin_port = htons(PORT_MULTICAST);
                        memset(buf,'\0',100);
                        sprintf(buf,"This is multicast message from %s",getVMbyIPaddr(ip_hw_map[0].ip));   
			printf("\n Node %s ,i am member of group \n",getVMbyIPaddr(ip_hw_map[0].ip));
			printf("\n Node %s Sending %s \n",getVMbyIPaddr(ip_hw_map[0].ip),buf);
                        int s = sendto(udp_fd,(void *)buf,100,0,(struct sockaddr *)&multicast_socket,sizeof(struct sockaddr));
			multicast_message_sent = 1;
			tour_ended = 1;
			ping_enabled = 0;
			exit_flag = 1;
                        //printf("Multicast packet sent %d",s);
                        if (s<=0)
                                perror("multicast error");


                        continue;
                }

	} else if (FD_ISSET(pg_fd,&set_fd)) {
		//printf("\n PING reply received \n ");
		proc_v4(pg_fd);
	}
   }
}
int main(int argc, char *argv[]) {

	int i;	
	 int get_host_name = getHostVMNo();
	getVMsIP(host_ip);
	inet_pton(AF_INET,host_ip,&host_ip_struct);
	///define this function
	get_pairs(ip_hw_map);
	memcpy((void *)hostmac,(void *)ip_hw_map[0].hw,IF_HADDR);

	struct tour_packet packet;
	int proto = htons(ETH_P_IP);
//create 4 sockets
	rt_fd = socket(AF_INET,SOCK_RAW,PROTO_ID);
	udp_fd = socket(AF_INET,SOCK_DGRAM,0);
	pf_fd  = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_IP)); 
	pg_fd   = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);

	int flag = 1;
	setsockopt(rt_fd,IPPROTO_IP,IP_HDRINCL,&flag,sizeof(flag));
	setsockopt(udp_fd,SOL_SOCKET,SO_REUSEADDR,&flag,sizeof(flag));

	//struct in_addr ip_multicast;
	inet_pton(AF_INET,IP_MULTICAST,&ip_multicast);
	int port_multicast = PORT_MULTICAST;
	struct tour_packet *packet_tour;
	char inputVM[20];
	char *Vmno;
	int j,n, input_error=0, vmno;
	packet_tour = (void *)malloc(sizeof(struct tour_packet));
	if (argc <=1) {
		printf("\nTour is running..\n");
		
	} else {
		inet_pton(AF_INET,host_ip,&vm_ip_list[0]);
     		for (i =1;i  < argc ;i ++)
			{
				strcpy(inputVM,argv[i]);
				if(inputVM[0]>= '1' && inputVM[0]<= '9')
				{
					n=atoi(inputVM);
					if(n<1 || n>10)
					{
						input_error=1;
						break;
					}
				}
				else 
				{
					for(j=0;j<3;j++)
					inputVM[j]=tolower(inputVM[j]);
							
					if(inputVM[0]=='v')
					{
						if(inputVM[1]=='m')
						{
							Vmno=inputVM+2;
							n=atoi(Vmno);
							if(n<1 || n>10)
							{
								input_error=1;
								break;
							}	
								
						}
						else
						{
							input_error=1;
							break;
						}							
					}
				
				}
				
			//int vmno = atoi(argv[i]);
			vmno=n;
			getVMIPstruct(&vm_ip_list[i],vmno);
			count++;
			//vm_ip_list[i] = get_ip(vmno)
			//make a ip list
		}
		if(input_error==1)
		{
			printf("\nImproper VM no provided.Program terminated\n");
			exit(0);
		}
			//get multicast ip address and porti
			enable_multicating(ip_multicast,port_multicast);
			//genrate tour payload
			
			packet_tour->ip = ip_multicast;
			packet_tour->port = port_multicast;
			packet_tour->index = 0;
			packet_tour->end_index = count;
			//start your tour
			memcpy(packet_tour->vm_list,vm_ip_list,sizeof(vm_ip_list));
			if (count != 0)
         			send_to_next_node(packet_tour,count);
	}

	monitor_sockets();

	return 1;
}
void
tv_sub(struct timeval *out, struct timeval *in)
{
        if ( (out->tv_usec -= in->tv_usec) < 0) {       /* out -= in */
                --out->tv_sec;
                out->tv_usec += 1000000;
        }
        out->tv_sec -= in->tv_sec;
}

void
proc_v4(int fd)
{
        struct ping_header packet;
        int                     hlen1, icmplen;
        double                  rtt;
        struct ip               *ip;
        struct icmp             *icmp;
        struct timeval  *tvsend,*tvrecv;
        char buf[INET_ADDRSTRLEN];
        tvrecv = (struct timeval *)malloc(sizeof(struct timeval));
        Gettimeofday(tvrecv,NULL);
	static nsent = 1;
        int rv = recvfrom(fd,&packet,sizeof(packet),0,NULL,NULL);
        if (rv < 0)
                perror("Error in Recvfrom");

	icmplen = rv;
        ip = &(packet.ip_hdr);
        icmp = &(packet.icmp_hdr);

        hlen1 = ip->ip_hl << 2;
        if (ip->ip_p != IPPROTO_ICMP)
                return;

        if (icmp->icmp_type == ICMP_ECHOREPLY) {
                //if (icmp->icmp_id != PING_ID)
                 //       return;
              //  if (icmplen < 16)
              //          return;

                tvsend = (struct timeval *) icmp->icmp_data;
                tv_sub(tvrecv, tvsend);
                rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;

                printf("\n PING REPLY %d bytes from %s: seq=%u, ttl=%d, rtt=%.3f ms\n",
                               icmplen,inet_ntop(AF_INET,&(ip->ip_src),buf,INET_ADDRSTRLEN),
                                ntohs(icmp->icmp_seq), ip->ip_ttl, rtt);
	}
}

