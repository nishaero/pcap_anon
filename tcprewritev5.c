#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <regex.h>
#include <pcre.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#define prefixlst  "./prefix_list.txt"
#define  PCAP_SAVEFILE "pcap_savefile"
#ifndef ETHER_HDRLEN
#define ETHER_HDRLEN 14
#endif
//#define  dumpname[80]
pcap_dumper_t *p;
pcap_t* pd;
int linkhdrlen;

/*IP Header*/
struct my_ip {
	u_int8_t ip_vhl; /* header length, version */
	//#define IP_V(ip)    (((ip)->ip_vhl & 0xf0) >> 4)
	//#define IP_HL(ip)    ((ip)->ip_vhl & 0x0f)
	u_int8_t ip_tos; /* type of service */
	u_int16_t ip_len; /* total length */
	u_int16_t ip_id; /* identification */
	u_int16_t ip_off; /* fragment offset field */
#define    IP_DF 0x4000            /* dont fragment flag */
#define    IP_MF 0x2000            /* more fragments flag */
#define    IP_OFFMASK 0x1fff        /* mask for fragmenting bits */
	u_int8_t ip_ttl; /* time to live */
	u_int8_t ip_p; /* protocol */
	u_int16_t ip_sum; /* checksum */
	u_int8_t ip_ihl; /* Ip Header length */

	struct in_addr ip_src, ip_dst; /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)
/* TCP header */
typedef u_int tcp_seq;
struct sniff_tcp {
	u_short th_sport; /* source port */
	u_short th_dport; /* destination port */
	tcp_seq th_seq; /* sequence number */
	tcp_seq th_ack; /* acknowledgement number */
	u_char th_offx2; /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win; /* window */
	u_short th_sum; /* checksum */
	u_short th_urp; /* urgent pointer */
};

struct sniff_udp {
	u_short udp_sport; /* source port */
	u_short udp_dport; /* destination port */
	u_short udp_hlen; /* Udp header length*/
	u_short udp_chksum; /* Udp Checksum */
};

//store the network part as the unsigned INT
unsigned int subnet(unsigned int prefix) {
	unsigned long mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF;

	//printf("%lu.%lu.%lu.%lu\n", mask >> 24, (mask >> 16) & 0xFF, (mask >> 8) & 0xFF, mask & 0xFF);
	return mask;
}
unsigned int a, b, c, d;
int k = 0, i;
char * list[10000][10000];
int BUFSIZE = 100000;
char* words[10000];

//Starting Packet Parsing
void parse_packet(u_char *user, struct pcap_pkthdr *packethdr,
		u_char *packetptr) {
	struct ip* iphdr;
	struct icmphdr* icmphdr;
	struct tcphdr* tcphdr;
	struct udphdr* udphdr;
	unsigned int IP_header_length;
	char iphdrInfo[256], srcip[256], dstip[256];
	unsigned short id, seq;

	const struct my_ip *ip; /* The IP header */
	// Skip the datalink layer header and get the IP header fields.
	/* define/compute ip header offset */
	ip = (struct my_ip*) (packetptr + ETHER_HDRLEN);
	iphdr = (struct ip*) packetptr;
	udphdr = (struct udphdr*) packetptr;
	int proto = iphdr->ip_p;

	printf("The UDP Port  %d \n", ip->ip_p);

	packetptr += linkhdrlen;

	IP_header_length = iphdr->ip_hl * 4;
	strcpy(srcip, inet_ntoa(iphdr->ip_src));
	strcpy(dstip, inet_ntoa(iphdr->ip_dst));
	sprintf(iphdrInfo, "ID:%d TOS:0x%x, TTL:%d IpLen:%d DgLen:%d",
			ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl, 4 * iphdr->ip_hl,
			ntohs(iphdr->ip_len));
	//Identidfying TCP or UDP packet
	if (ip->ip_p == IPPROTO_UDP || ip->ip_p == IPPROTO_TCP) {

		//Packet Anonymize

		//if condition for TCP or UDP pcakets

		const struct sniff_ethernet *ethernet; /* The ethernet header [1] */

		const struct sniff_tcp *tcp; /* The TCP header */
		const struct sniff_udp *udp; /* The UDP header */
		char *payload; /* Packet payload */
		char *payload_udp; /* UDP Payload    */
		int size_ip;
		int size_tcp;
		//int size_udp;
		int size_payload, size_payload_udp;
		int size_udp;
		/* define ethernet header */
		ethernet = (struct sniff_ethernet*) (packetptr);
		size_ip = IP_HL(ip) * 4;
		// pcap_dump(user, packethdr, packetptr - linkhdrlen);

		// Compute UDP

		if (ip->ip_p == IPPROTO_UDP) {

			//    Code for UPD packet capture on Youtube
			udphdr = (struct udphdr*) packetptr;
			size_udp = 8;
			//    Define UDP size and payload
			//    Changes are made here New UDP content.
			udp = (struct sniff_udp*) (packetptr + ETHER_HDRLEN + size_udp);
			payload_udp = (u_char *) (packetptr + ETHER_HDRLEN + size_ip
					+ size_udp);
			char *firstpos_udp = payload_udp + 12;
			printf("   UDP_Payload is : %s \n", firstpos_udp);
			size_payload_udp = ntohs(ip->ip_len) - (size_ip + size_udp);
			if (size_payload_udp > 0) {
				printf("   Size_UDP_Payload (%d bytes):\n", size_payload_udp);
			}
			//       Changes are made here New UDP content ends.

			char *filter;
			char *ch[1000];
			printf("Size_UDP_Payload: %d\n", size_payload_udp);

			if (payload_udp != NULL && size_payload_udp > 0) {
				// Checking for packet source whether if it is from video server
				if ( (strstr(payload_udp + 12, "vid2.ak.dmcdn.net") != NULL)
						|| (strstr(payload_udp + 12, "dmcdn") != NULL)
						|| (strstr(payload_udp + 12, "ak.dmcdn") != NULL)) {

					printf("The UDP Packet is captured \n");

					//Calling Anonymization Function
					printf("calling Anonymization function in UDP\n");


					printf("Starting Pcap Anon.\n");

					int src[8] = { packetptr[26], packetptr[27], packetptr[28],
							packetptr[29], packetptr[30], packetptr[31],
							packetptr[32], packetptr[33] };

					// printf("Source IP from File Read: %d %d %d %d and the Destination IP  as  %d %d %d %d \n",src[0],src[1],src[2],src[3],src[4],src[5],src[6],src[7]);
					//printf("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&\n");

					//Reading file

					FILE *f = fopen(prefixlst, "r");
					if (f == NULL) {
						printf("File Pointer is invalid\n");

					}
					//Ensure array write starts from beginning

					if (f == 0) {
						fprintf(stderr, "Error while opening\n");
						exit(1);
					}
					int i = 0;
					words[i] = malloc(BUFSIZE);
					while (fgets(words[i], BUFSIZE, f)) {
						i++;
						words[i] = malloc(BUFSIZE);

					}
					// printf("Output: \n");

					for (i = 0; words[i] != NULL; i++) {
						k++;
					}

					char *pch;
					char *A[1000];
					int j = 0;
					int l = 0;

					for (l = 0; l < k; l++) {
						pch = strtok(words[l], " ./");
						for (j = 0; pch != NULL; j++) {
							A[j] = pch;
							pch = strtok(NULL, " ./");
						}
						for (i = 0; A[i] != NULL; i++) {
							list[l][i] = A[i];
						}

					}
					unsigned long mask;
					for (i = 0; i < k; i++) {
						mask = subnet(atoi(list[i][4]));
					}
					a = mask >> 24;
					b = (mask >> 16) & 0xFF;
					c = (mask >> 8) & 0xFF;
					d = mask & 0xFF;

					int netadd[9] =
					{ src[0] & a, src[1] & b, src[2] & c, src[3] & d,
							src[4] & a, src[5] & b, src[6] & c, src[7]
																	& d };
					//     printf("Network Part of Source IP address %d %d %d %d And Destination IP Address %d %d %d %d\n",netadd[0],netadd[1],netadd[2],netadd[3],
					//             netadd[4],netadd[5],netadd[6],netadd[7]);
					//     printf("***********************************\n");

					for (i = 0; i < k; i++) {
						if (netadd[0] == atoi(list[i][0])
								&& netadd[1] == atoi(list[i][1])) {
							//        printf("Replacing IP with mask %s %s %s %s\n",list[i][5],list[i][6],list[i][7],list[i][8]);
							packetptr[26] = atoi(list[i][5]);
							packetptr[27] = atoi(list[i][6]);
							packetptr[28] = atoi(list[i][7]);
							packetptr[29] = atoi(list[i][8]);
							//                printf("***********************\n");
						}
						if (netadd[4] == atoi(list[i][0])
								&& netadd[5] == atoi(list[i][1])) {
							//      printf("Replacing IP with mask %s %s %s %s\n",list[i][5],list[i][6],list[i][7],list[i][8]);

							packetptr[30] = atoi(list[i][5]);
							packetptr[31] = atoi(list[i][6]);
							packetptr[32] = atoi(list[i][7]);
							packetptr[33] = atoi(list[i][8]);

							//      pcap_dump(pd,hdr,packet);
							//      printf("***********************\n");

						}

					}
					//Writing to dump file
					pcap_dump(user, packethdr, packetptr - linkhdrlen);

				}
			}             //Code for UPD packet capture on Youtube Ends
		}

		if (ip->ip_p == IPPROTO_TCP) {
			printf("Inside TCP\n");
			// define/compute tcp header offset
			tcp = (struct sniff_tcp*) (packetptr + ETHER_HDRLEN + size_ip);
			size_tcp = TH_OFF(tcp) * 4;
			// define/compute tcp payload (segment) offset
			payload =
					(u_char *) (packetptr + ETHER_HDRLEN + size_ip + size_tcp);
			// compute tcp payload (segment) size
			size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
			//Anonymizing IP in TCP Payload Start
			int reg;
			regex_t re;
			regmatch_t pm;
			reg = regcomp(&re, "([0-9]{1,3}(\\.[0-9]{1,3}){3})", REG_EXTENDED);
			if (reg != 0)
				printf(" -> Error: Invalid Regex");
			reg = regexec(&re, &payload[0], 1, &pm, REG_EXTENDED);
			if (reg == 0) {
				for (i = pm.rm_so; i < pm.rm_eo; i++) {
					payload[i] = 'x';
				}
			}
			//Anonymizing IP in TCP payload END
			char *filter;
			char *ch[1000];
			printf("Size_Payload: %d\n", size_payload);

			if (payload != NULL && size_payload > 0) {
				printf("Test 1\n");
				int reg, sch, sch_udp;
				regex_t re;
				regmatch_t pm;
				char *match;
				reg =
						regcomp(&re,
								("\/videoplayback", "|video", "|\(/application\/octet-stream\)", "x-flv", "webm", "mp4"),  REG_EXTENDED);
				if (reg != 0)
					printf(" -> Error: Invalid Regex");
				printf("Test 2\n");
				match = (char *) malloc(100000);
				sch = regexec(&re, &payload, 2, &pm, REG_EXTENDED);
				printf("Test 3\n");

				//strcpy(match, payload+(pm.rm_so - pm.rm_eo));
				printf("Test 4\n");
				printf("the match found is %s\n", match);
				char code[3] = { match[9], match[10], match[11] };
				int res = atoi(code);

				// if((strstr(match,"/videoplayback")!=NULL) ){
				//if(((strstr(match,"/videoplayback")!=NULL)|| ((res == 200) && (strstr(match,"application/octet-stream")!=NULL || (strstr(match,"video/")!=NULL)))|| (res >= 300 && res < 400) || (strstr(udphdr,"youtube")!=NULL) || (strstr(udphdr,"googlevideo")!=NULL)) && (strstr(udphdr,"youtube")!=NULL || strstr(udphdr,"googlevideo")!=NULL) ) {
				if ((strstr(payload, "video/mp4") != NULL) || (strstr(payload, "x-flv") != NULL) || (strstr(payload, "x-fl") != NULL) || (strstr(payload, "mp4") != NULL) || (strstr(payload, "webm") != NULL)
						|| ((res == 200)
								&& (strstr(payload, "application")
										!= NULL
										|| (strstr(payload, "video/") != NULL)))
										|| (res >= 300 && res < 400)) {
					printf("Printing response codes %s\n", code);

					printf("Starting Pcap Anon.\n");

					int src[8] = { packetptr[26], packetptr[27], packetptr[28],
							packetptr[29], packetptr[30], packetptr[31],
							packetptr[32], packetptr[33] };

					// printf("Source IP from File Read: %d %d %d %d and the Destination IP  as  %d %d %d %d \n",src[0],src[1],src[2],src[3],src[4],src[5],src[6],src[7]);
					//   printf("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&\n");
					//Reading file

					FILE *f = fopen(prefixlst, "r");
					if (f == NULL) {
						printf("File Pointer is invalid\n");

					}
					//Ensure array write starts from beginning

					if (f == 0) {
						fprintf(stderr, "Error while opening\n");
						exit(1);
					}
					int i = 0;
					words[i] = malloc(BUFSIZE);
					while (fgets(words[i], BUFSIZE, f)) {
						i++;
						words[i] = malloc(BUFSIZE);
					}
					// printf("Output: \n");

					for (i = 0; words[i] != NULL; i++) {
						k++;
					}
					char *pch;
					char *A[1000];
					int j = 0;
					int l = 0;

					for (l = 0; l < k; l++) {
						pch = strtok(words[l], " ./");
						for (j = 0; pch != NULL; j++) {
							A[j] = pch;
							pch = strtok(NULL, " ./");
						}
						for (i = 0; A[i] != NULL; i++) {
							list[l][i] = A[i];
						}

					}

					unsigned long mask;
					for (i = 0; i < k; i++) {
						mask = subnet(atoi(list[i][4]));
					}
					a = mask >> 24;
					b = (mask >> 16) & 0xFF;
					c = (mask >> 8) & 0xFF;
					d = mask & 0xFF;

					int netadd[9] =
					{ src[0] & a, src[1] & b, src[2] & c, src[3] & d,
							src[4] & a, src[5] & b, src[6] & c, src[7]
																	& d };
					//     printf("Network Part of Source IP address %d %d %d %d And Destination IP Address %d %d %d %d\n",netadd[0],netadd[1],netadd[2],netadd[3],
					//             netadd[4],netadd[5],netadd[6],netadd[7]);
					//     printf("***********************************\n");

					for (i = 0; i < k; i++) {
						if (netadd[0] == atoi(list[i][0])
								&& netadd[1] == atoi(list[i][1])) {
							//         printf("Replacing IP with mask %s %s %s %s\n",list[i][5],list[i][6],list[i][7],list[i][8]);
							packetptr[26] = atoi(list[i][5]);
							packetptr[27] = atoi(list[i][6]);
							packetptr[28] = atoi(list[i][7]);
							packetptr[29] = atoi(list[i][8]);

							//      printf("***********************\n");

						}
						if (netadd[4] == atoi(list[i][0])
								&& netadd[5] == atoi(list[i][1])) {
							//     printf("Replacing IP with mask %s %s %s %s\n",list[i][5],list[i][6],list[i][7],list[i][8]);

							packetptr[30] = atoi(list[i][5]);
							packetptr[31] = atoi(list[i][6]);
							packetptr[32] = atoi(list[i][7]);
							packetptr[33] = atoi(list[i][8]);

							//pcap_dump(pd,hdr,packet);
							//printf("***********************\n");

						}

					}
					//Writing to dump file
					pcap_dump(user, packethdr, packetptr - linkhdrlen);
				}
				printf("Test 5\n");
			}
		}                // End of TCP Anonymization
		printf(
				"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");

	}
} // END of Packet Parser
void bailout(int signo) {
	struct pcap_stat stats;

	if (pcap_stats(pd, &stats) >= 0) {
		printf("%d packets received\n", stats.ps_recv);
		printf("%d packets dropped\n\n", stats.ps_drop);
	}
	pcap_close(pd);
	exit(0);
}

int main(int argc, char **argv) { //filter string for IP and DNS with port numbers
	char interface[256] = "",
			//    bpfstr[3000] =  "((net 208.65.152.0/22 || net 64.15.112.0/20 || net 208.117.224.0/19 || net 108.170.192.0/18 || net 108.177.0.0/17 || net 142.250.0.0/15 || net 172.217.0.0/16 || net 173.194.0.0/16 || net 192.178.0.0/15 || net 199.87.241.32/27 || net 207.223.160.0/20 || net 209.85.128.0/17 || net 216.239.32.0/19 || net 216.58.192.0/19 || net 64.233.160.0/19 || net 66.102.0.0/20 || net 66.249.64.0/19 || net 70.32.128.0/19 || net 70.90.219.48/29 || net 70.90.219.72/29 || net 72.14.192.0/18 || net 74.125.0.0/16 || net 173.194.0.0/16) && port 80  || (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420 && tcp[((tcp[12:1] & 0xf0) >> 2) + 1004:4] = 0x2f766964 && tcp[((tcp[12:1] & 0xf0) >> 2) + 1008:4] = 0x656f706c && tcp[((tcp[12:1] & 0xf0) >> 2) + 1012:4] = 0x61796261 && tcp[((tcp[12:1] & 0xf0) >> 2) + 1016:2] = 0x636b && tcp[((tcp[12:1] & 0xf0) >> 2) + 1018:1] = 0x3f)  )  || port 53 ";

			//   bpfstr[3000] =  "((net 74.113.232.0/21 || net 212.201.0.0/16 || net 185.31.18.0/24 || net 23.235.32.0/20) && port 80  )  || port 53 ";
			bpfstr[3000] =  "((net 74.113.232.0/21 || net 212.201.0.0/16 || net 185.31.18.0/24 || net 23.235.32.0/20 || net 188.65.120.0/21 || net 188.65.126.0/24) && port 80  )  || port 53 ";
	int packets = 0, c, i;

	// Get the command line options, if any
	while ((c = getopt(argc, argv, "hi:n:")) != -1) {
		switch (c) {
		case 'h':
			printf("usage: %s [-h] [-i ] [-n ] []\n", argv[0]);
			exit(0);
			break;
		case 'i':
			strcpy(interface, optarg);
			break;
		case 'n':
			packets = atoi(optarg);
			break;
		}
	}

	/*  // Get the packet capture filter expression, if any.
     for (i = optind; i < argc; i++)
     {
     strcat(bpfstr, argv[i]);
     strcat(bpfstr, " ");
     }
	 */

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pd;
	uint32_t srcip, netmask;
	struct bpf_program bpf;


	// Open the interface for live capture, as opposed to reading a packet
	// capture file.
	if ((pd = pcap_open_live(interface, BUFSIZ, 1, 0, errbuf)) == NULL) {
		printf("pcap_open_live(): %s\n", errbuf);

	}

	// Get network interface source IP address and netmask.
	if (pcap_lookupnet(interface, &srcip, &netmask, errbuf) < 0) {
		printf("pcap_lookupnet: %s\n", errbuf);

	}

	// Convert the packet filter epxression into a packet
	// filter binary.
	if (pcap_compile(pd, &bpf, (char*) bpfstr, 0, netmask)) {
		printf("pcap_compile(): %s\n", pcap_geterr(pd));

	}

	// Assign the packet filter to the given libpcap socket.
	if (pcap_setfilter(pd, &bpf) < 0) {
		printf("pcap_setfilter(): %s\n", pcap_geterr(pd));

	}
	if ((p = pcap_dump_open(pd, PCAP_SAVEFILE)) == NULL) {

		fprintf(stderr, "Error opening savefile \"%s\" for writing: %s\n",
				PCAP_SAVEFILE, pcap_geterr(pd));
		exit(7);
	}

	// Start capturing packets.
	if (pcap_loop(pd, packets, parse_packet, (unsigned char *) p) < 0)
		printf("pcap_loop failed: %s\n", pcap_geterr(pd));

	// Open libpcap, set the program termination signals then start
	// processing packets.
	pcap_dump_close(p);

	pcap_close(pd);
}
