#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
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
	uint8_t src_mac[6];
	uint8_t src_ip[4];
	uint8_t dst_mac[6];
	uint8_t dst_ip[4];
};

struct base_info{
	u_char dev[10];
	u_char sdr_ip[20];
	u_char tar_ip[20];
	uint8_t my_mac[6];
	uint8_t sdr_mac[6];
};

void Init_arp(struct arphdr *arp, uint16_t opcode);
int Get_my_hwaddr(struct base_info *info);
int Get_sender_hwaddr(struct base_info *info);


int main(int argc, char *argv[])
{
	struct base_info info;

	if (argc != 4) {
		printf("Usage : ./pcap_test [interface] [sender ip] [target ip]\n");
		return 2;
	}

	strcpy(info.dev, argv[1]);
	strcpy(info.sdr_ip, argv[2]);
	strcpy(info.tar_ip, argv[3]);
	printf("%s\n", info.sdr_ip);
	printf("%s\n", info.tar_ip);
	if (!Get_my_hwaddr(&info))
		return -1;
	printf("%s\n", info.my_mac);

	if (!Get_sender_hwaddr(&info))
		return -1;
	printf("%s\n", info.sdr_mac);
	
	return(0);
}


void Init_arp(struct arphdr *arp, uint16_t opcode)
{
	arp->hw_type = htons(1);
	arp->pro_type = htons(0x0800);
	arp->hw_len = 6;
	arp->pro_len = 4;
	arp->opcode = htons(opcode);
}


int Get_my_hwaddr(struct base_info *info)
{
	FILE *fp;
	int i;
	char hwaddr[20];
	char file[30] = "/sys/class/net/";
	unsigned int mac[6];
	strcat(file, info->dev);
	strcat(file, "/address");

	printf("%s\n", file);
	fp = fopen(file, "r");
	if (!fp || (fscanf(fp, "%s", hwaddr) == -1))
	{
		fprintf(stderr, "Couldn't open file %s\n", file);
		return 0;
	}
	fclose(fp);

	sscanf(hwaddr, "%x:%x:%x:%x:%x:%x", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
	for (i=0 ; i<6 ; i++)
		info->my_mac[i] = (uint8_t)mac[i];

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


	/* set ethernet header */
	for (i=0 ; i<6 ; i++)
		ether.h_source[i] = 0xff;
	for (i=0 ; i<6 ; i++)
		ether.h_dest[i] = info->my_mac[i];
	ether.h_proto = htons(ETHERTYPE_ARP);
	memcpy(send, (char*)&ether, 14);

	/* set arp header */
	Init_arp(&arp, ARP_REQUEST);
	inet_pton(AF_INET, info->sdr_ip, &arp.src_ip);
	inet_pton(AF_INET, info->tar_ip, &arp.dst_ip);
	for (i=0 ; i<6 ; i++)
		arp.src_mac[i] = info->my_mac[i];
	for (i=0 ; i<6 ; i++)
		arp.dst_mac[i] = 0x00;
	memcpy(send+14, (char*)&arp, 28);

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
				for (i=0 ; i<6 ; i++)
					info->sdr_mac[i] = recv_arp->src_mac[i];
				break;
			}
		}
	}
	pcap_close(handle);
	return 1;
}
