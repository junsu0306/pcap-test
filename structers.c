#include <stdio.h>


#define ETHER_ADDR_LEN	6



//Ethernet header
struct sniff_ethernet{
    u_char ehter_dhost[ETHER_ADDR_LEN]; 
    u_char ether_shost[ETHER_ADDR_LEN];
    u_short ehter_type; // IP OR ARP OR RARP
}

//IP header
struct sniff_ip{
    u_char ip_vhl; // version, header length 
    u_char ip_tos; // type of service
    u_short ip_len; // total length
    u_short ip_id; // fragment offset field
    u_short ip_off; // fragment offset field
#define IP_RF 0x8000		//reserved fragment flag
#define IP_DF 0x4000		//don't
#define IP_MF 0x2000		//more
#define IP_OFFMASK 0x1fff	//mask
    u_char ip_ttl; //time to live
    u_char ip_p; // protocl
    u_short ip_sum; //checksum
    struct in_addr ip_src,ip_dst; // source and dest address
}

//TCP header
typedef u_int tcp_seq;

struct sniff_tpc{
    u_short th_sport;
    u_short th_dport;
    tcp_seq th_seq;
    tcp_seq th_ack;
    u_char th_offx2;

    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
}

