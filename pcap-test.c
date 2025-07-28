#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "my-libnet.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
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
		
		struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
		struct libnet_ipv4_hdr* ipv4_hdr = (struct libnet_ipv4_hdr*) (packet+14);
		struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet+14+4*(ipv4_hdr->ip_hl));
		uint8_t data[20];
		memcpy(data, packet + 14 + 4 * (ipv4_hdr->ip_hl) + 4 * (tcp_hdr->th_off), 20);

		if(ipv4_hdr->ip_p == 6){
			if(eth_hdr->ether_type == 0x0008){
				printf("src mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
				eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2],
				eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);
				printf("dst mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
				eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2],
				eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);
				printf("src ip: %s\n", inet_ntoa(ipv4_hdr->ip_src));
				printf("dst ip: %s\n", inet_ntoa(ipv4_hdr->ip_dst));
				printf("src port: %d\n", ntohs(tcp_hdr->th_sport));
				printf("dst port: %d\n", ntohs(tcp_hdr->th_dport));
				printf("data: ");
				for (int i = 0; i < 20; i++) {
					printf("%02x ", data[i]);
				}
				printf("\n");
			}
		}
	}

	pcap_close(pcap);
}
