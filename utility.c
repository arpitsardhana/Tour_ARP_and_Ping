#include "utility.h"
#include "unp.h"
#include "tour.h"

char* print_time(){
	static char curtime[64];
	memset(curtime,'\0',128);
	time_t cur_t;
	cur_t = time(NULL);
	strcpy(curtime,asctime(localtime((const time_t *)&cur_t)));
	char *temp = strchr(curtime,'\n');
	temp = '\0';
	int len = strlen(curtime);
	curtime[len -1] = '\0';
	return curtime;
}
char* ethoNtoP(char *addr,char *result)
{
        char buf[10];
        char *temp ;
        temp = result;
    int i;
        //char *result;
    temp[0] = '\0';
    for (i = 0; i < MACLEN; i++) {
        sprintf(buf, "%.2x%s", addr[i] & 0xff , i == 5 ? "" : ":");
        strcat(temp, buf);
    }
     int len = strlen(temp);
     temp[len] = '\0';
    result=temp;
        return result;

}

void getTempPath(char *filePath,char *fileName,int flag)
{
        if((getcwd(filePath,1024))==NULL)
        {
                printf("\nRandom path can not be generated!");
        }
        printf("\n automatic path:%s",filePath);
        strcat(filePath,fileName);

	if (flag != 0) { 

        	if((mkstemp(filePath))==-1)
        	{
                	printf("\n No unique filename could be found!");
                	return;
        	}
	}
}
void getVMsIP(char *hostIP)
{
        char hostName[200];
        struct hostent *HA;

        gethostname(hostName,200);
        HA = gethostbyname(hostName);
        strcpy(hostIP,inet_ntoa(*(struct in_addr*)HA->h_addr));
}
char *getVMIPaddressbyNode(char *vmip,int nodenum)
{
        char vmid[10];
        sprintf(vmid,"vm%d",nodenum);

        struct hostent *host = gethostbyname(vmid);
        inet_ntop(AF_INET,host->h_addr,vmip,INET_ADDRSTRLEN);
        if (host != NULL )
                return vmip;
        else
                return NULL;
}

struct in_addr *getVMIPstruct(struct in_addr *vmip,int nodenum)
{
        char vmid[10];
        sprintf(vmid,"vm%d",nodenum);

        struct hostent *host = gethostbyname(vmid);
        //inet_ntop(AF_INET,host->h_addr,vmip,INET_ADDRSTRLEN);
	
	//memcpy(vmip,host->h_addr,sizeof(struct in_addr));
	//*vmip = *host->h_addr;
	char vm_ip[30];
        if (host != NULL ) {
		memcpy(vmip,host->h_addr,sizeof(struct in_addr));
		printf("address added %s\n",inet_ntop(AF_INET,vmip,vm_ip,INET_ADDRSTRLEN));
                return vmip;
         } else
                return NULL;
}


int createDomaimDGramSock(char *tempPath)
{
        struct sockaddr_un localAddr;
        socklen_t localAddrLen;
        int sockfd;
	bzero(&localAddr,sizeof(localAddr));

        sockfd=Socket(AF_LOCAL,SOCK_DGRAM,0);
        if(sockfd<0)
        {
                perror("socket");
        }

        bzero(&localAddr,sizeof(localAddr));
        localAddr.sun_family=AF_LOCAL;
        printf("\n path:%s \n",tempPath);
        strcpy(localAddr.sun_path,tempPath);
        unlink(tempPath);
        localAddrLen=sizeof(localAddr);
        if((bind(sockfd,(struct sockaddr*)&localAddr,localAddrLen))<0)
        {
                perror("Bind");
        }

	return sockfd;
}

int getHostVMNo(){
    char hostName[1024];
    int hostNo;

    gethostname(hostName, 10);
    hostNo = atoi(hostName+2);
    if (hostNo < 1 || hostNo > 10) {
        err_msg("Warning: Invalid hostname '%s'", hostName);
    }
        printf(" \n node no inside function:%d \n",hostNo);
    return hostNo;
}
int getVMByIP(char *addr){
	struct in_addr sa;
	int vm_no = 0;
	struct hostent *host = NULL;

	int i = inet_pton(AF_INET,addr,&sa);
	
	if (i > 0) {
		host = gethostbyaddr(&sa,sizeof(sa),AF_INET);
		char *local = host->h_name;
		local++;
		local++;
		vm_no = atoi(local);
	}
	return vm_no;
}
char *getVMbyIPaddr(struct in_addr sa) {
        	struct hostent *host = NULL;
                host = gethostbyaddr(&sa,sizeof(sa),AF_INET);
		if (host == NULL)
			return NULL;

                char *local = host->h_name;
        	return local;
}
 
int get_pairs(struct ip_hw_pairs ip_hw_map[]) {
        struct hwa_info *hwa, *hwahead;
        struct sockaddr *sa;
        char   *ptr;
        int    i, prflag;
	int count = 0;
        printf("\n");

        for (hwahead = hwa = Get_hw_addrs(); hwa != NULL; hwa = hwa->hwa_next) {

	   if (strcmp(hwa->if_name,"eth0") == 0) {
		struct sockaddr_in *local_ip = (struct sockaddr_in *)hwa->ip_addr;	
		ip_hw_map[count].ip = local_ip->sin_addr;
		memcpy(ip_hw_map[count].hw,hwa->if_haddr,IF_HADDR);
		count += 1;

                printf("%s :%s", hwa->if_name, ((hwa->ip_alias) == IP_ALIAS) ? " (alias)\n" : "\n");

                if ( (sa = hwa->ip_addr) != NULL)
                        printf("         IP addr = %s\n", Sock_ntop_host(sa, sizeof(*sa)));

                prflag = 0;
                i = 0;
                do {
                        if (hwa->if_haddr[i] != '\0') {
                                prflag = 1;
                                break;
                        }
                } while (++i < IF_HADDR);

                if (prflag) {
                        printf("         HW addr = ");
                        ptr = hwa->if_haddr;
                        i = IF_HADDR;
                        do {
                                printf("%.2x%s", *ptr++ & 0xff, (i == 1) ? " " : ":");
                        } while (--i > 0);
                }

                printf("\n         interface index = %d\n\n", hwa->if_index);
        }

        //free_hwa_info(hwahead);
	}
	free(hwahead);
	return count;
        //exit(0);
}

 
uint16_t in_cksum(uint16_t *addr, int len)
{
         int nleft = len;
         uint16_t *w = addr;
         uint32_t sum = 0;
        uint16_t answer = 0;

       /* 
         * Our algorithm is simple, using a 32 bit accumulator (sum), we add
         * sequential 16 bit words to it, and at the end, fold back all the
         * carry bits from the top 16 bits into the lower 16 bits.
         */
        while (nleft > 1)  {
                sum += *w++;
                nleft -= 2;
        }

        /* mop up an odd byte, if necessary */
        if (nleft == 1) {
                *(uint8_t *)(&answer) = *(uint8_t *)w ;
                sum += answer;
        }

        /* add back carry outs from top 16 bits to low 16 bits */
        sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
        sum += (sum >> 16);                     /* add carry */
        answer = ~sum;                          /* truncate to 16 bits */
        return (answer);
}

