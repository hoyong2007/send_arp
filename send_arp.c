#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>


#define ARP_REQUEST 1
#define ARP_REPLY 2

struct arphdr{
	uint16_t hw_type;
	uint16_t pro_type;
	uint8_t hw_len;
	uint8_t pro_len;
	uint16_t opcode;
	uint8_t sdr_mac[6];
	uint8_t sdr_ip[4];
	uint8_t tar_mac[6];
	uint8_t tar_ip[4];
};

struct base_info{
	u_char dev[10];
	u_char sdr_ip[20];
	u_char tar_ip[20];
	uint8_t my_ip[INET_ADDRSTRLEN];
	uint8_t my_mac[6];
	uint8_t sdr_mac[6];
};


void Init_arp(struct arphdr *arp, uint16_t opcode);
int Get_my_hwaddr(struct base_info *info);
int Get_sender_hwaddr(struct base_info *info);


int main(int argc, char *argv[])
{
	struct base_info info;
	int i;

	if (argc != 4) {
		printf("Usage : ./pcap_test [interface] [sender ip] [target ip]\n");
		return 2;
	}

	strcpy(info.dev, argv[1]);
	strcpy(info.sdr_ip, argv[2]);
	strcpy(info.tar_ip, argv[3]);
	//printf("%s\n", info.sdr_ip);
	//printf("%s\n", info.tar_ip);
	if (!Get_my_hwaddr(&info))
		return -1;
	//for (i=0 ; i<6 ; i++)
	//	printf(" %02x\n", info.my_mac[i]);

	if (!Get_sender_hwaddr(&info))
		return -1;
	
	return(0);
}


void Init_arp(struct arphdr *arp, uint16_t opcode)
{
	arp->hw_type = htons(1);	/* type Ethernet */
	arp->pro_type = htons(0x0800);	/* protocol IP */
	arp->hw_len = 6;
	arp->pro_len = 4;
	arp->opcode = htons(opcode);
}


int Get_my_hwaddr(struct base_info *info)
{
	FILE *fp;
	int i;
	int fd;
	struct ifreq ifr;
	char hwaddr[20];

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, info->dev, IFNAMSIZ-1);
	ioctl(fd, SIOCGIFADDR, &ifr);	
	
	inet_ntop(AF_INET, &(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), info->my_ip, INET_ADDRSTRLEN);
	ioctl(fd, SIOCGIFHWADDR, &ifr);
	for (i=0 ; i<6 ; i++)
		info->my_mac[i] = ((unsigned char*)ifr.ifr_hwaddr.sa_data)[i];
	close(fd);
	
	//printf("%s\n", info->my_ip);
	//for (i=0 ; i<6 ; i++)
	//	printf(" %02x", info->my_mac[i]);
	//printf("\n");

	return 1;
}


int Get_sender_hwaddr(struct base_info *info)
{
	pcap_t *handle;			/* Session handle */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	struct pcap_pkthdr *header;	/* The header that pcap gives us */
	char filter_exp[] = "arp";	/* The filter expression */
	bpf_u_int32 net;		/* Our IP */
	unsigned char send[50] = {0};	/* Buffer to send */
	unsigned char *recv;		/* Buffer to recv */
	uint32_t i;
	uint32_t res;
	struct ethhdr ether;
	struct ethhdr *recv_ether;
	struct arphdr arp;
	struct arphdr *recv_arp;


	/* Open the session in promiscuous mode */
	handle = pcap_open_live(info->dev, 65536, 0, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", info->dev, errbuf);
		return(2);
	}

	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

	//printf("%d\n", (unsigned int)net);
	/* set ethernet header */
	for (i=0 ; i<6 ; i++)
		ether.h_source[i] = info->my_mac[i];
	for (i=0 ; i<6 ; i++)
		ether.h_dest[i] = 0xff;
	ether.h_proto = htons(ETHERTYPE_ARP);
	memcpy(send, (char*)&ether, 14);

	/* set arp header */
	Init_arp(&arp, ARP_REQUEST);
	inet_pton(AF_INET, info->my_ip, &arp.sdr_ip);
	inet_pton(AF_INET, info->sdr_ip, &arp.tar_ip);
	for (i=0 ; i<6 ; i++)
		arp.sdr_mac[i] = info->my_mac[i];
	for (i=0 ; i<6 ; i++)
		arp.tar_mac[i] = 0x00;
	memcpy(send+14, (void*)&arp, sizeof(struct arphdr));

	for (i=0 ; i<(sizeof(struct arphdr)+sizeof(struct ethhdr)) ; i++)
		printf("%02x%c", send[i], i%10==0 ? '\n' : ' ');
	printf("\n%d", i);

	while(1) {
		/* Send arp request to sender */
		if (pcap_sendpacket(handle, send, 42))
		{
			fprintf(stderr, "Couldn't send packet\n");
			return 0;
		}

		/* Recv arp reply */
		res = pcap_next_ex(handle, &header, (const u_char**)&recv);
		if (res==0)
			continue;
		else if (res==-1)
		{
			fprintf(stderr, "Couldn't recv packet\n");
			return 0;
		}

		recv_ether = (struct ethhdr*)recv;
		if (ntohs(recv_ether->h_proto) == ETHERTYPE_ARP)
		{
			recv_arp = (struct arphdr*)(recv + 14);
			if (ntohs(recv_arp->opcode) == ARP_REPLY)
			{
				printf("Get ARP Reply\n");
				for (i=0 ; i<6 ; i++)
					info->sdr_mac[i] = recv_arp->sdr_mac[i];
				break;
			}
		}
	}
	for (i=0 ; i<6 ; i++)
		printf(" %02x", info->sdr_mac[i]);
	printf("\n");
	pcap_close(handle);
	return 1;
}



/*
* arp request -> ether.src_mac == arp.sdr_mac == my_mac
*				 ether.dst_mac = ff:ff:ff:ff:ff:ff
*				 arp.tar_mac = 00:00:00:00:00:00
*				 sdr == my_pc
*				 tar == target
*/

