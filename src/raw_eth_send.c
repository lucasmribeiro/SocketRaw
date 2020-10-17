#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>

#define MAC_ADDR_LEN 6
#define BUFFER_SIZE 1600
#define MAX_DATA_SIZE 1500
#define MAX_ARP_PACKET_SIZE 28 

int main(int argc, char *argv[])
{
	int fd;
	struct ifreq if_idx;
	struct ifreq if_mac;
	struct sockaddr_ll socket_address;
	char ifname[IFNAMSIZ];
	int frame_len = 0;
	/* Ethernet */
	char buffer[BUFFER_SIZE];
	char dest_mac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; //broadcast
	short int ethertype = htons(0x0806); 
	/* ARP Protocol */
	int arp_len = 0;
	char arp_packet[MAX_ARP_PACKET_SIZE];
	short int hwtype = htons(0x0001);
	short int ptype  = htons(0x0800);
	char hlen = 0x06;
	char plen = 0x04;
	short int op = htons(0x0001); // 0x0001 - Request ou 0x0002 - Response
	char sender_ha[] = {0x08, 0x00, 0x27, 0x5c, 0x65, 0x26}; // mac address origin 08:00:27:5c:65:26
	char sender_ip[] = {192, 168, 15, 15}; // ip origin 192.168.15.15
	char target_ha[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; 
	char target_ip[] = {192, 168, 15, 2}; // discover ip

	if (argc != 2) {
		printf("Usage: %s iface\n", argv[0]);
		return 1;
	}
	strcpy(ifname, argv[1]);
	
	/* Cria um descritor de socket do tipo RAW */
	if ((fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror("socket");
		exit(1);
	}

	/* Obtem o indice da interface de rede */
	memset(&if_idx, 0, sizeof (struct ifreq));
	strncpy(if_idx.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFINDEX, &if_idx) < 0) {
		perror("SIOCGIFINDEX");
		exit(1);
	}

	/* Obtem o endereco MAC da interface local */
	memset(&if_mac, 0, sizeof (struct ifreq));
	strncpy(if_mac.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFHWADDR, &if_mac) < 0) {
		perror("SIOCGIFHWADDR");
		exit(1);
	}

	/* Indice da interface de rede */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;

	/* Tamanho do endereco (ETH_ALEN = 6) */
	socket_address.sll_halen = ETH_ALEN;

	/* Endereco MAC de destino */
	memcpy(socket_address.sll_addr, dest_mac, MAC_ADDR_LEN);

	/* Preenche o buffer com 0s */
	memset(buffer, 0, BUFFER_SIZE);

	/* Monta o cabecalho Ethernet */

	/* Preenche o campo de endereco MAC de destino */	
	memcpy(buffer, dest_mac, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	/* Preenche o campo de endereco MAC de origem */
	memcpy(buffer + frame_len, if_mac.ifr_hwaddr.sa_data, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	/* Preenche o campo EtherType */
	memcpy(buffer + frame_len, &ethertype, sizeof(ethertype));
	frame_len += sizeof(ethertype);

	/* Monta o Arp Packet */
	memset(arp_packet, 0, MAX_ARP_PACKET_SIZE);
    
	/* Hardware Type */
	memcpy(arp_packet + arp_len, &hwtype, sizeof(hwtype));
	arp_len += sizeof(hwtype);
 	
	/* Protocol Type */
	memcpy(arp_packet + arp_len, &ptype, sizeof(ptype));
	arp_len += sizeof(ptype);

	/* Hardware Length */
	memcpy(arp_packet + arp_len, &hlen, sizeof(hlen));
	arp_len += sizeof(hlen);

	/* Protocol Length */
	memcpy(arp_packet + arp_len, &plen, sizeof(plen));
	arp_len += sizeof(plen);

	/* Operation */
	memcpy(arp_packet + arp_len, &op, sizeof(op));
	arp_len += sizeof(op);

	/* Sender HA */
	memcpy(arp_packet + arp_len, sender_ha, sizeof(sender_ha));
	arp_len += sizeof(sender_ha);
    
	/* Sender IP */
	memcpy(arp_packet + arp_len, sender_ip, sizeof(sender_ip));
	arp_len += sizeof(sender_ip);

	/* Target HA */
	memcpy(arp_packet + arp_len, target_ha, sizeof(target_ha));
	arp_len += sizeof(target_ha);

	/* Target IP */
	memcpy(arp_packet + arp_len, target_ip, sizeof(target_ip));
	arp_len += sizeof(target_ip);

	/* Preenche o Data com Arp Packet */
	memcpy(buffer + frame_len, arp_packet, sizeof(arp_packet));
	frame_len += sizeof(arp_packet);
	
	/* Envia pacote */
	if (sendto(fd, buffer, frame_len, 0, (struct sockaddr *) &socket_address, sizeof (struct sockaddr_ll)) < 0) {
		perror("send");
		close(fd);
		exit(1);
	}

	printf("Pacote enviado.\n");

	close(fd);
	return 0;
}

