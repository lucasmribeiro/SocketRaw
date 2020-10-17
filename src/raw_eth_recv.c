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
#define MAC_ADDRESS_SIZE 6
#define MAX_ARP_PACKET_SIZE 28

const unsigned char mac_add_src[MAC_ADDRESS_SIZE] = {0x54, 0x2f, 0x8a, 0x78, 0xec, 0xf0}; // mac address src 54:2f:8a:78:ec:f0

int main(int argc, char *argv[])
{
	int fd;
	unsigned char buffer[BUFFER_SIZE];
	unsigned char arp_packet[MAX_ARP_PACKET_SIZE];
	unsigned char *data;
	struct ifreq ifr;
	char ifname[IFNAMSIZ];

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
		unsigned char mac_dst[MAC_ADDRESS_SIZE];
		unsigned char mac_src[MAC_ADDRESS_SIZE];
		short int ethertype;
		int len

		/* Recebe pacotes */
		if (recv(fd,(char *) &buffer, BUFFER_SIZE, 0) < 0) {
			perror("recv");
			close(fd);
			exit(1);
		}
        
		/* Copia o conteudo do cabecalho Ethernet */
		memcpy(mac_dst, buffer, sizeof(mac_dst));
		memcpy(mac_src, buffer+sizeof(mac_dst), sizeof(mac_src));
		memcpy(&ethertype, buffer+sizeof(mac_dst)+sizeof(mac_src), sizeof(ethertype));
		ethertype = ntohs(ethertype);
		/* Copia o conteudo Arp Packet */
		memcpy(arp_packet, );
		data = (buffer+sizeof(mac_dst)+sizeof(mac_src)+sizeof(ethertype));

		if (ethertype == ETHERTYPE) {
			if(memcmp(mac_src, mac_add_src, sizeof(mac_src)) == 0)
			{
				continue;
			}	
			printf("MAC destino: %02x:%02x:%02x:%02x:%02x:%02x\n", 
                        mac_dst[0], mac_dst[1], mac_dst[2], mac_dst[3], mac_dst[4], mac_dst[5]);
			printf("MAC origem:  %02x:%02x:%02x:%02x:%02x:%02x\n", 
                        mac_src[0], mac_src[1], mac_src[2], mac_src[3], mac_src[4], mac_src[5]);
			printf("EtherType: 0x%04x\n", ethertype);
			printf("Dado: %s\n", data);
			printf("\n");
		}
	}

	close(fd);
	return 0;
}

