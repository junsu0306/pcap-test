#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

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

void find_tcp(const u_char* packet){
	ethernet = (struct sniff_ethernet*)(packet);
	ip=(struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip=IP_HL(ip)*4;
	if (size_ip<20)
		return 0;
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp<20)
		return 0;
	else{
		return 1;
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
		if (find_tcp(packet)!= 0){

		}
	}

	pcap_close(pcap);

	
}
