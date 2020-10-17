#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>

#define BUFFER_SIZE 1600
#define ETHERTYPE 0x0806
#define ARP_PACKET_LEN 28
#define MAC_ADDR_LEN 6
#define IP_LEN 4

const unsigned char mac_addr_src[MAC_ADDR_LEN] = { 0x54, 0x2f, 0x8a, 0x78, 0xec, 0xf0 }; // mac address src 54:2f:8a:78:ec:f0

int main(int argc, char *argv[])
{
	int fd, frame_len, arp_len;
	unsigned char buffer[BUFFER_SIZE];
	unsigned char arp_packet[ARP_PACKET_LEN];
	struct ifreq ifr;
	char ifname[IFNAMSIZ];

	/* ARP PACKET */
	short int hwtype;
	short int ptype;
	unsigned char hlen;
	unsigned char plen;
	short int op;
	unsigned char sender_ha[MAC_ADDR_LEN];
	unsigned char sender_ip[IP_LEN];
	unsigned char target_ha[MAC_ADDR_LEN];
	unsigned char target_ip[IP_LEN];
	
	if (argc != 2) {
		printf("Usage: %s iface\n", argv[0]);
		return 1;
	}
	strcpy(ifname, argv[1]);

	/* Cria um descritor de socket do tipo RAW */
	fd = socket(PF_PACKET,SOCK_RAW, htons(ETH_P_ALL));
	if(fd < 0) {
		perror("socket");
		exit(1);
	}

	/* Obtem o indice da interface de rede */
	strcpy(ifr.ifr_name, ifname);
	if(ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
		perror("ioctl");
		exit(1);
	}

	/* Obtem as flags da interface */
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0){
		perror("ioctl");
		exit(1);
	}

	/* Coloca a interface em modo promiscuo */
	ifr.ifr_flags |= IFF_PROMISC;
	if(ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
		perror("ioctl");
		exit(1);
	}

	printf("Esperando pacotes ... \n");
	while (1) {
		unsigned char mac_dst[MAC_ADDR_LEN];
		unsigned char mac_src[MAC_ADDR_LEN];
		short int ethertype;

		frame_len = 0;
		arp_len = 0;

		/* Recebe pacotes */
		if (recv(fd,(char *) &buffer, BUFFER_SIZE, 0) < 0) {
			perror("recv");
			close(fd);
			exit(1);
		}
        
		/* Copia o conteudo do cabecalho Ethernet */
		memcpy(mac_dst, buffer, sizeof(mac_dst));
		frame_len += sizeof(mac_dst);

		memcpy(mac_src, buffer+frame_len, sizeof(mac_src));
		frame_len += sizeof(mac_src);

		memcpy(&ethertype, buffer+frame_len, sizeof(ethertype));
		frame_len += sizeof(ethertype);

		ethertype = ntohs(ethertype);
		/* Copia o conteudo Arp Packet */
		memcpy(arp_packet, buffer+frame_len, sizeof(arp_packet));
		frame_len += sizeof(arp_packet);	

		/* Hardware Type */
		memcpy(&hwtype, arp_packet + arp_len, sizeof(hwtype));
		arp_len += sizeof(hwtype);
		
		/* Protocol Type */
		memcpy(&ptype, arp_packet + arp_len, sizeof(ptype));
		arp_len += sizeof(ptype);
		
		/* Hardware Length */
		memcpy(&hlen, arp_packet + arp_len, sizeof(hlen));
		arp_len += sizeof(hlen);
		
		/* Protocol Length */
		memcpy(&plen, arp_packet + arp_len, sizeof(plen));
		arp_len += sizeof(plen);

		/* Operation */
		memcpy(&op, arp_packet + arp_len, sizeof(op));
		arp_len += sizeof(op);

		/* Sender HA */
		memcpy(&sender_ha, arp_packet + arp_len, sizeof(sender_ha));
		arp_len += sizeof(sender_ha);

		/* Sender IP */
		memcpy(&sender_ip, arp_packet + arp_len, sizeof(sender_ip));
		arp_len += sizeof(sender_ip);

		/* Target HA */
		memcpy(&target_ha, arp_packet + arp_len, sizeof(target_ha));
		arp_len += sizeof(target_ha);

		/* Target IP */
		memcpy(&target_ip, arp_packet + arp_len, sizeof(target_ip));
		arp_len += sizeof(target_ip);

		if (ethertype == ETHERTYPE) {
			if ((memcmp(mac_src, mac_addr_src, sizeof(mac_src)) == 0) || 
			(memcmp(mac_dst, mac_addr_src, sizeof(mac_dst)) == 0) || (op == 256))
			{
				continue;
			}
			printf("** ARP PACKET **\n");			
			printf("  EtherType: 0x%04x\n", ethertype);			
			printf("   Operacao: 0x%02x - %s\n", ntohs(op), (op == 256) ? "Send" : "Reply");
			printf(" MAC origem: %02x:%02x:%02x:%02x:%02x:%02x\n", mac_src[0], mac_src[1], mac_src[2], mac_src[3], mac_src[4], mac_src[5]);
			printf("  IP origem: %d.%d.%d.%d\n", sender_ip[0], sender_ip[1], sender_ip[2], sender_ip[3]);
			printf("MAC destino: %02x:%02x:%02x:%02x:%02x:%02x\n", mac_dst[0], mac_dst[1], mac_dst[2], mac_dst[3], mac_dst[4], mac_dst[5]);
			printf(" IP destino: %d.%d.%d.%d\n", target_ip[0], target_ip[1], target_ip[2], target_ip[3]);
						
			printf("\n\n");		

		}
	}

	close(fd);
	return 0;
}

