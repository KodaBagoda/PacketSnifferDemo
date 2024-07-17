#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ip_icmp.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <pcap.h>
#include <ifaddrs.h>
#include <iostream>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <ctype.h>

#define MAX_PACKET_SIZE 65536
#define ICMP_ECHO_REQUEST 16
#define ICMP_ECHO_REPLY 0
#define MAX_WAIT_TIME 9
#define MAX_TTL 75

#ifdef __linux__
#define LINUX
#endif

#ifdef __unix__
#define UNIX
#endif

#ifdef __APPLE__
#define MACOS
#endif

void print_mac_address(const u_char* mac) {
    for (int i = 0; i < 6; ++i) {
        printf("%02x", mac[i]);
        if (i < 5) {
            std::cout << ":";
        }
    }
    std::cout << std::endl;
}

void print_packet_data(const u_char* data, int len) {
    std::cout << "Packet data (hex): \n";
    for (int i = 0; i < len; ++i) {
        printf("%02x ", data[i]);
        if (i % 8 == 0) printf("\n");
    }
    std::cout << std::endl;

    std::cout << "Packet data (ASCII): \n";
    for (int i = 0; i < len; ++i) {
        char c = data[i];
        if (isprint(c)) {
            std::cout << c;
        } else {
            std::cout << ".";
        }
    }
    std::cout << std::endl;
}

void packet_handler(unsigned char* user_data, const struct pcap_pkthdr* pkthdr, const unsigned char* packet_data) {
    std::cout << "********** Packet Data Captured **********" << std::endl;
    std::cout << "Captured Packet Length: " << pkthdr->len << " bytes." << std::endl;

#ifdef MACOS
    if (pkthdr->len >= sizeof(struct ip)) {
        struct ip* ip_header = (struct ip*)packet_data;
        std::cout << "Source IP: " << inet_ntoa(ip_header->ip_src) << std::endl;
        std::cout << "Destination IP: " << inet_ntoa(ip_header->ip_dst) << std::endl;

        if (ip_header->ip_p == IPPROTO_TCP && pkthdr->len >= (sizeof(struct ip) + sizeof(struct tcphdr))) {
            struct tcphdr* tcp_header = (struct tcphdr*)(packet_data + ip_header->ip_hl * 4);
            std::cout << "Source Port: " << ntohs(tcp_header->th_sport) << std::endl;
            std::cout << "Destination Port: " << ntohs(tcp_header->th_dport) << std::endl;
        }
    }
#else
    int data_link_type = pcap_datalink((pcap_t*)user_data);
    if (data_link_type == DLT_EN10MB && pkthdr->len >= sizeof(struct ether_header)) {
        struct ether_header* eth_header = (struct ether_header*)packet_data;
        std::cout << "Source MAC: ";
        print_mac_address(eth_header->ether_shost);
        std::cout << "Destination MAC: ";
        print_mac_address(eth_header->ether_dhost);
    }

    if (pkthdr->len >= sizeof(struct ip)) {
        struct ip* ip_header = (struct ip*)(packet_data + sizeof(struct ether_header));
        std::cout << "Source IP: " << inet_ntoa(ip_header->ip_src) << std::endl;
        std::cout << "Destination IP: " << inet_ntoa(ip_header->ip_dst) << std::endl;

        if (ip_header->ip_p == IPPROTO_TCP && pkthdr->len >= (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr))) {
            struct tcphdr* tcp_header = (struct tcphdr*)(packet_data + sizeof(struct ether_header) + ip_header->ip_hl * 4);
            std::cout << "Source Port: " << ntohs(tcp_header->th_sport) << std::endl;
            std::cout << "Destination Port: " << ntohs(tcp_header->th_dport) << std::endl;
        }
    }
#endif

    print_packet_data(packet_data, pkthdr->len);
    std::cout << "--------------------Packet End---------------------" << std::endl;
}

int main(int argc, char* argv[]) {
    char* dev;

    if (argc >= 2) {
        std::cout << "Program name : " << argv[0] << std::endl;
        std::cout << "Device Name  : " << argv[1] << std::endl;
        dev = argv[1];

        struct ifaddrs* iadd;
        struct sockaddr_in* addr;

        if (getifaddrs(&iadd) == 0) {
            for (struct ifaddrs* ifa = iadd; ifa != nullptr; ifa = ifa->ifa_next) {
                if (ifa->ifa_addr != nullptr && ifa->ifa_addr->sa_family == AF_INET) {
                    addr = (struct sockaddr_in*)ifa->ifa_addr;
                    if (strcmp(ifa->ifa_name, dev) == 0) {
                        std::cout << "Your IP address on " << ifa->ifa_name << ": " << inet_ntoa(addr->sin_addr) << std::endl;
                    }
                }
            }
            freeifaddrs(iadd);
        } else {
            std::cerr << "Failed to get IP address." << std::endl;
        }
    } else {
        std::cout << "No additional command-line arguments provided." << std::endl;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    pcap_if_t* DEVICE_NAME;
    if (pcap_findalldevs(&DEVICE_NAME, errbuf) == -1) {
        std::cerr << "Error finding network devices: " << errbuf << std::endl;
        return 1;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Could not open device " << dev << ": " << errbuf << std::endl;
        pcap_freealldevs(DEVICE_NAME);
        return 1;
    }

    pcap_loop(handle, 0, packet_handler, (unsigned char*)handle);

    pcap_close(handle);
    pcap_freealldevs(DEVICE_NAME);

    return 0;
}