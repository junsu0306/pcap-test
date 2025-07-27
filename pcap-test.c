#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "structures.h"
#include <arpa/inet.h>
#define SIZE_ETHERNET 14


const struct sniff_ethernet *ethernet;
const struct sniff_ip *ip; 
const struct sniff_tcp *tcp; 
const char *payload; 

u_int size_ip;
u_int size_tcp;

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

//https://www.tcpdump.org/pcap.html 구조 활용
void find_and_print_tcpinfo(const u_char* packet){
	ethernet = (struct sniff_ethernet*)(packet);
	ip=(struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip=IP_HL(ip)*4;
	if (size_ip<20)
		return;
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;

	int total_len = ntohs(ip->ip_len);
	int payload_len = total_len-(size_ip+size_tcp);
	const u_char* payload = packet + SIZE_ETHERNET + size_ip + size_tcp;

	if (size_tcp<20)
		return;
	else{
		printf("\n========== NEW PACKET ==========\n\n");
		printf("<Ethernet Header>\n");
		printf("Source: %02x:%02x:%02x:%02x:%02x:%02x\n",
				ethernet->ether_shost[0], ethernet->ether_shost[1],ethernet->ether_shost[2], ethernet->ether_shost[3],ethernet->ether_shost[4], ethernet->ether_shost[5]);
		printf("Destination: %02x:%02x:%02x:%02x:%02x:%02x\n",
				ethernet->ether_dhost[0], ethernet->ether_dhost[1],ethernet->ether_dhost[2], ethernet->ether_dhost[3],ethernet->ether_dhost[4], ethernet->ether_dhost[5]);
		printf("<IP Header>\n");
		printf("Source: %s\n", inet_ntoa(ip->ip_src));
		printf("Destination: %s\n", inet_ntoa(ip->ip_dst));
		printf("<TCP Header>\n");
		printf("Source Port: %d\n", ntohs(tcp->th_sport));
		printf("Destination Port: %d\n", ntohs(tcp->th_dport));
		printf("<Payload>\n");

		if (payload_len > 0) {
 		for (int i = 0; i < payload_len && i < 20; i++) {
        	printf("%02x ", payload[i]);
    		}
    		printf("\n");
		} else {
    		printf("No Payload\n");
		}
		
	}
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
		find_and_print_tcpinfo(packet);
	}

	pcap_close(pcap);
	return 0;
	

	
}
