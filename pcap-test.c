#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#define ETHER_ADDR_LEN 6

struct EthernetHeader
{
    u_int8_t  dest_addr[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  src_addr[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t type;                 /* protocol */
};

struct IPV4Header
{
    u_int8_t header_len:4, version:4; 
    u_int8_t service_type;
    u_int16_t total_len, id;
    u_int16_t frag_offset;
    u_int8_t ttl, protocol;
    u_int16_t checksum;
    struct in_addr src_addr, dest_addr;
};

struct TCPHeader
{
    u_int16_t src_port, dest_port;
    u_int32_t seq_num, ack_num;
    u_int8_t unused:4, data_offset:4; 
    u_int16_t window;
    u_int16_t checksum;
    u_int16_t urgent_pointer;
};

typedef struct {
	char* device;
} ProgramParam;

ProgramParam param = {
	.device = NULL
};

void display_usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

void print_mac_address(uint8_t *src_mac, uint8_t *dest_mac){
	printf("Source MAC Address : %02x:%02x:%02x:%02x:%02x:%02x\n",  src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);	
	printf("Destination MAC Address : %02x:%02x:%02x:%02x:%02x:%02x\n",  dest_mac[0], dest_mac[1], dest_mac[2], dest_mac[3], dest_mac[4], dest_mac[5]);	
}

void print_ip_address(struct IPV4Header* ipv4_hdr){
    char src_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];

    strncpy(src_ip, inet_ntoa(ipv4_hdr->src_addr), INET_ADDRSTRLEN);
    strncpy(dest_ip, inet_ntoa(ipv4_hdr->dest_addr), INET_ADDRSTRLEN);

    printf("Source IP Address : %s\nDestination IP Address : %s\n", src_ip, dest_ip);
}


void print_data(unsigned char* data, int len){
	int i = 0;
	printf("Data : ");
	while (i < len && i < 10){
		printf("%02x ", data[i]);
		i++;
	}
	printf("\n---------------------------------------------------------------------------------\n");	
}

bool parse_program_param(ProgramParam* param, int argc, char* argv[]) {
	if (argc != 2) {
		display_usage();
		return false;
	}
	param->device = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse_program_param(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.device, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.device, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		struct EthernetHeader *eth_hdr = (struct EthernetHeader *)packet;
		struct IPV4Header *ipv4_hdr = (struct IPV4Header *)(packet + 14);
		struct TCPHeader *tcp_hdr = (struct TCPHeader *)(packet + 14 + ipv4_hdr->header_len*4);
		unsigned char* data = (unsigned char *)(packet + 14 + ipv4_hdr->header_len*4 + tcp_hdr->data_offset*4);
		int payload_len = header->caplen - (14 + ipv4_hdr->header_len*4 + tcp_hdr->data_offset*4);
		if (ipv4_hdr->protocol == 6){
			print_mac_address(eth_hdr->src_addr, eth_hdr->dest_addr);
			print_ip_address(ipv4_hdr);
			printf("Source port : %d\nDestination port : %d\n", ntohs(tcp_hdr->src_port), ntohs(tcp_hdr->dest_port));
			print_data(data, payload_len);
		}
	}
	pcap_close(pcap);
}

