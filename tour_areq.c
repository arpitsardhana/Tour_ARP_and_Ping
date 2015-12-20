#include "utility.h"

int areq(struct sockaddr *IPaddr,int sockaddrlen,struct hwaddr *HWaddr) {


	//create_connect_socket()
	 
	struct sockaddr_un serv_addr;
	int sockfd;
	bzero(&serv_addr,sizeof(serv_addr));
	memset(&serv_addr,'\0',sizeof(struct sockaddr_un));

	sockfd = socket(AF_LOCAL,SOCK_STREAM,0);
	serv_addr.sun_family = AF_LOCAL;

	strcpy(serv_addr.sun_path,ARP_FILE);
	
	int c = connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(struct sockaddr_un));
	if (c < 0) {
		perror("AREQ:Connect error");
		exit(0);

	}
	struct arp_local_req arp_local;
	arp_local.index = HWaddr->sll_ifindex;
	arp_local.type = HWaddr->sll_hatype;
	arp_local.len  = HWaddr->sll_halen;
	arp_local.ip.s_addr = ((struct sockaddr_in *)IPaddr)->sin_addr.s_addr;
	 char ip_buf[INET_ADDRSTRLEN];
	 printf("\n AREQ requested Hardware Address of %s",inet_ntop(AF_INET,&(arp_local.ip),ip_buf,INET_ADDRSTRLEN))	;
	int w = write(sockfd,&arp_local,sizeof(struct arp_local_req));

	if  (w<=0) {

		perror("AREQ:write error");
	}

	//write_unix_socket()
	fd_set areq_set;
	struct timeval time_out;
	FD_ZERO(&areq_set);
	FD_SET(sockfd,&areq_set);
	time_out.tv_sec = 5;
	time_out.tv_usec = 0;

	int s =select(sockfd+1,&areq_set,NULL,NULL,&time_out);
	if (s <= 0){
		printf("\n AREQ timmeout occurred, Hardware Address Not available");
		close(sockfd);
		perror("AREQ:Select");
		return -1;


	}

	//read_unix_socket()
	char recv_hwaddr[IF_HADDR]; 

	int r = read(sockfd,recv_hwaddr,IF_HADDR);
	if (r <= 0) {
		perror("AREQ:Read error");

	}
	memcpy(HWaddr->sll_addr,recv_hwaddr,IF_HADDR);
	char hw_buf[20];
	ethoNtoP(HWaddr->sll_addr,hw_buf);
	printf("\n AREQ:Received Hardware Address %s",hw_buf);
	close(sockfd);
	return 1;
}
