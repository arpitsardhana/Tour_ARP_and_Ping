#include "arp.h"
#include "utility.h"
#include "unp.h"
#define MACLEN 6
struct ip_hw_pairs ip_hw_map[10];
static char filepath[1024];
struct in_addr hoost_ip;
static char VMIPAddr[50];
struct arp_entry arp_cache[10];
int ARPCache_length = 0;
static void signal_handler(int signum){
	unlink(filepath);
	exit(0);

}
int pf_fd, sock_fd;
int totalIPHWPair;

void displayEthernetFrame(struct frame_ethernet *frame)
{

    char src_add[20];
    char dest_add[20];
    char src_ip[20];
    char dest_ip[20];
    ethoNtoP(frame->dst_mac,dest_add);
    ethoNtoP(frame->src_mac,src_add);

    printf ("\nEthernet frame :\n");
    printf("<================================================>");
    printf ("\nDest MAC: %s  Src MAC %s  Protocol %d", dest_add,src_add,frame->proto_id);
    if (frame->packet.option == REQ)
        printf("\n ARP Request Message ");
    else
        printf("\n ARP Reply Message ");

    printf("\n<================================================>\n ");
    printf(" ID: %x", frame->packet.id);
    printf(" Hw Type: %d\t", frame->packet.htype);
    printf(" Protocol Number: %x", frame->packet.ptype);
    printf(" Hw Length: %d", frame->packet.hlen);
    printf(" Protcol Size: %d", frame->packet.plen);
    printf(" Source IP Address: %s",inet_ntop(AF_INET,&(frame->packet.src_ip),src_ip,INET_ADDRSTRLEN));
    printf("\tSrcMAC: %s", src_add);
    printf("\tDestIP: %s",inet_ntop(AF_INET,&(frame->packet.dst_ip),src_ip,INET_ADDRSTRLEN));
    printf("\tDestMAC: %s \n", dest_add);
   printf("\n==================================================\n");
}
void print_arp_cache() {
	struct arp_entry *aRow;
	char ip_buf[30];
	char hw_buf[20];
	int i;
	printf("\n=========Printing Valid ARP enteries==============");
	for (i=0;i<10;i++) {
		aRow = &(arp_cache[i]);
		if (aRow->valid == 1) {
			ethoNtoP(aRow->hwaddr,hw_buf);
			printf(" \n IP address %s  HWaddr %s  FD %d IF_INDEX %d ",inet_ntop(AF_INET,&(aRow->ip),ip_buf,INET_ADDRSTRLEN),hw_buf,aRow->fd,aRow->if_index);
		}
	}
	printf("\n=================================================\n");
}
 int recv_ethernet_packet(struct frame_ethernet *frame,struct sockaddr_ll *sockAddr)
{
        size_t frameLen;
        socklen_t sockLen;
        sockLen = sizeof(struct sockaddr_ll);
        frameLen= sizeof(struct frame_ethernet);
    memset(sockAddr,'\0',sockLen);
    memset(frame, '\0',frameLen);

    if (recvfrom(pf_fd, frame, frameLen, 0, (struct sockaddr *) sockAddr, &sockLen) < 0)
        {
       		perror("Recv From");
           return 0;
    }


        if(frame->packet.option !=REP && frame->packet.option !=REQ)
        {
                printf("Invalid type of frame received.");
                return 0;
        }

    if (frame->packet.id != ID) {
        printf("Received invalid identification number.");
        return 0;
    } 

        printf("\nReceived Ethernet Packet.......\n");
	displayEthernetFrame(frame);

    return 1;

}

void Update_ARP_Cache(int ifIndex,uint8_t hw_type,struct in_addr *srcIP,char *srcMAC,int sockFd,int flag_force)
{
        int i, row;
	row = 0;
   if(flag_force==1)
         row = ARPCache_length;
    for (i = 0; i < ARPCache_length; i++){
        if (arp_cache[i].valid) {
            if(arp_cache[i].ip.s_addr == srcIP->s_addr) {
                row = i;
                break;
            }
        }

    }

    if ((flag_force==1) || (row != ARPCache_length))
        {

	arp_cache[row].ip.s_addr = srcIP->s_addr;
        arp_cache[row].if_index = ifIndex;
        arp_cache[row].htype  = hw_type;
	if (sockFd != -1)
        	arp_cache[row].fd  = sockFd;
        arp_cache[row].valid = 1;
	if (srcMAC != NULL)
        	memcpy(arp_cache[row].hwaddr, srcMAC, 6);

        if (row == ARPCache_length)
            ARPCache_length++;

        printf("\nCache Updated...");
	print_arp_cache();
    }

}

void setARPPacket(struct frame_ethernet *frame,char *destHWAddr, struct in_addr *destIP,char *srcHWAddr, struct in_addr *srcIP,uint16_t hw_type,uint8_t hw_len,uint16_t opt_type)
{
   size_t frameLen=sizeof(struct frame_ethernet);
    memset(frame, '\0',frameLen);
    memcpy(frame->dst_mac, destHWAddr, MACLEN);
    memcpy(frame->src_mac, srcHWAddr, MACLEN);
    frame->proto_id = htons(PROTO_ID);

    struct arp *arpPck;
    arpPck=&(frame->packet);

    arpPck->id = ID;
    arpPck->htype = hw_type;
    arpPck->ptype = PROTO_ID;
    arpPck->hlen = hw_len;
    arpPck->plen = sizeof(PROTO_ID);
    arpPck->option   = opt_type;

    arpPck->src_ip.s_addr = srcIP->s_addr;
    arpPck->dst_ip.s_addr = destIP->s_addr;
    memcpy(arpPck->sha, srcHWAddr, IF_HADDR);
    memcpy(arpPck->tha, destHWAddr, IF_HADDR); 

}

void sendPacket(struct frame_ethernet *frame,int ifIndex, uint16_t hw_type,uint8_t hw_len)
{
        struct sockaddr_ll sockAddr;
        size_t sockLen=sizeof(struct sockaddr_ll);
        size_t frameLen=sizeof(struct frame_ethernet);
    memset(&sockAddr,'\0',sockLen);

    sockAddr.sll_family   = PF_PACKET;
    sockAddr.sll_halen    = ETH_ALEN;
    sockAddr.sll_ifindex  = 2;
    sockAddr.sll_addr[0] = frame->dst_mac[0];
    sockAddr.sll_addr[1] = frame->dst_mac[1]; 
    sockAddr.sll_addr[2] = frame->dst_mac[2];
    sockAddr.sll_addr[3] = frame->dst_mac[3];
    sockAddr.sll_addr[4] = frame->dst_mac[4];
    sockAddr.sll_addr[5] = frame->dst_mac[5];

    sockAddr.sll_addr[6] = 0x00;
    sockAddr.sll_addr[7] = 0x00;
    int s = sendto(pf_fd, (void *)frame, frameLen, 0,(struct sockaddr *) &sockAddr, sockLen);
    if (s < 0)
    {
        perror("Send to error in send packet");
                return;
    } else {
	displayEthernetFrame(frame);


	}
        //displayEthernetFrame(frame);
} 

 struct arp_entry *search_ARP_Cache(struct in_addr *IP)
 {
         int i;
         for(i=0;i<ARPCache_length;i++)
         {
                 if(arp_cache[i].valid && IP->s_addr == arp_cache[i].ip.s_addr)
                         return &arp_cache[i];
         }
         return NULL;
 }


int process_arp_packet(struct frame_ethernet *frame,struct sockaddr_ll *sockAddr)
{
        int i;
        char destHWAddr[IF_HADDR];
	int flag=0;
	memset(destHWAddr,'\0',IF_HADDR);
        struct arp_entry *srcRow;
	struct frame_ethernet repPck;
        if (frame->packet.option == REQ)
        {
        	printf("\nARP packet type of REQUEST received..");
                for (i = 0; i < totalIPHWPair; i++)
                {
                        if (frame->packet.dst_ip.s_addr==ip_hw_map[i].ip.s_addr) {
				memcpy(destHWAddr,ip_hw_map[i].hw,IF_HADDR);
				flag = 1;
                                break;
			}
        	}
                //if(i!=totalIPHWPair)
                 //       strcpy(destHWAddr,ip_hw_map[i].hw);
                if(flag == 1)
                {       uint16_t hw_type = sockAddr->sll_hatype;
			uint8_t hw_len = sockAddr->sll_halen; 
			struct in_addr destIP;
			destIP.s_addr = frame->packet.src_ip.s_addr;
                        printf("\nARP packet reached destination VM");

                        Update_ARP_Cache(sockAddr->sll_ifindex,sockAddr->sll_hatype,&(frame->packet.src_ip),frame->src_mac,0,1);

                        struct frame_ethernet repPck;
			memset(&repPck,'\0',sizeof(struct frame_ethernet));
			setARPPacket(&repPck,frame->src_mac,&destIP,ip_hw_map[0].hw,&(ip_hw_map[0].ip), hw_type, hw_len,REP);
                        sendPacket(&repPck, sockAddr->sll_ifindex, hw_type,hw_len);

        	} else {
                        Update_ARP_Cache(sockAddr->sll_ifindex,sockAddr->sll_hatype,&(frame->packet.src_ip),frame->src_mac, 0, 0);
		}
    }
    // ARP Reply processing
    else if (frame->packet.option == REP)
        {
                int sockfd;
                srcRow= search_ARP_Cache(&(frame->packet.src_ip));
        	sockfd = srcRow->fd;

		if (sockfd > 0)
			Writen(sockfd,frame->src_mac,IF_HADDR);



        	Update_ARP_Cache(sockAddr->sll_ifindex,sockAddr->sll_hatype,&(frame->packet.src_ip),frame->src_mac, 0, 0);
                printf("\nARP packet of REPLY type packet sent!");
    }

    return frame->packet.option;

}
void monitor_sockets() {
        
	struct frame_ethernet frame;
	struct arp *frame_packet;
    	struct sockaddr_ll sockAddr;
	fd_set fd_sel;
        int connfd;
	int max_fd;
	FD_ZERO(&fd_sel);
	FD_SET(pf_fd,&fd_sel);
	FD_SET(sock_fd,&fd_sel);
	int fd = -1;

	connfd = -1;


        struct arp_entry *aRow;
        int ifIndex;
        struct in_addr destIP;
        uint16_t hw_type;
        uint8_t hw_len;
        struct arp_local_req data;


        while(1) {
		  max_fd = max(sock_fd,pf_fd);
		  FD_SET(pf_fd,&fd_sel);
        	  FD_SET(sock_fd,&fd_sel);

		  if (fd != -1) {
			max_fd = max(max_fd,fd);
			FD_SET(fd,&fd_sel);
		  } 
        	int s = select(max_fd+1,&fd_sel,NULL,NULL,NULL);
		//printf("select returned %d \n",s);
		if (s<=0) {
			perror("ARP:select");

		}

	if (fd != -1 && FD_ISSET(fd,&fd_sel)) {

		if ((aRow = search_ARP_Cache(&destIP)) != NULL)
                {       char buf[30];
			aRow->valid = 0;
			printf("Invalidating Entry for address %s \n ",inet_ntop(AF_INET,&destIP,buf,INET_ADDRSTRLEN));
                }


	}

        else if(FD_ISSET(pf_fd,&fd_sel)){
                if(recv_ethernet_packet(&frame,&sockAddr)==1) {
               
                                //displayEthernetFrame(&frame);
                    int result=process_arp_packet(&frame,&sockAddr);

                    if (result == REP) {
                             close(fd);
                             fd = -1;
                    } 
		} 

        }

        if(FD_ISSET(sock_fd ,&fd_sel))
        {

		int dataLen = sizeof(struct arp_local_req);

        	fd = Accept(sock_fd, NULL, NULL);
		int r = read(fd, &data,dataLen);
		if (r < 0) {
			perror("ARP:Read error");
		} else {
			printf("ARP Local request  Packet received");

		}


		destIP.s_addr = data.ip.s_addr;
        	if ((aRow = search_ARP_Cache(&destIP)) != NULL)
                {       
			printf("\n Entry found in Cache");
			print_arp_cache();
                        Writen(fd, aRow->hwaddr,IF_HADDR);
			//write_Unix_Domain_Socket(fd, aRow->hw);
            		close(fd);
			fd = -1;
                } else {
            		Update_ARP_Cache(data.index,data.type,&(data.ip),NULL,fd,1);
            		printf("ARP Cache entry Absent, sending ARP Request on Eth0 iface\n");
                	// ARP entry absent, send an ARP request on Eth0 interface
            		struct frame_ethernet reqPck;
			hw_type = data.type;
			hw_len = data.len;
			ifIndex = data.index;
			char dst_hw[IF_HADDR] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};	
                        setARPPacket(&reqPck,dst_hw,&destIP,ip_hw_map[0].hw,&(ip_hw_map[0].ip), hw_type, hw_len,REQ);
                        sendPacket(&reqPck, ifIndex, hw_type,hw_len);
                } 
        }
    }
}

void main()
{
	int HostVMNo;
	struct sockaddr_un sock_addr;

	bzero(&sock_addr,sizeof(sock_addr));
	memset(&sock_addr,'\0',sizeof(struct sockaddr_un));

	HostVMNo=getHostVMNo();
	getVMIPaddressbyNode(VMIPAddr,HostVMNo);
	totalIPHWPair=get_pairs(ip_hw_map);
	printf("ARP started on VM%d IP address: (%s)\n", HostVMNo, VMIPAddr);


//	Signal(SIGINT,signal_handler);
	pf_fd = socket(PF_PACKET,SOCK_RAW,htons(PROTO_ID));


	sock_fd  = socket(AF_LOCAL,SOCK_STREAM,0);

	sock_addr.sun_family = AF_LOCAL;
	strcpy(sock_addr.sun_path,ARP_FILE);
	unlink(ARP_FILE);

	int b = bind(sock_fd,(struct sockaddr *)&sock_addr,sizeof(struct sockaddr_un));
	if(b  < 0)
	{
        	perror("Bind");
		exit(0);
	}

	int l = listen(sock_fd,10);
	if(l < 0)
	{
        	perror("Listen");
		exit(0);
	}

	monitor_sockets();


	close(pf_fd);
	close(sock_fd);
}

