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
#include <time.h>

#define MAX_PACKET_SIZE 1000000000000000
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

/*
 * packet_handler 
 * Description: This function is used to handle the packets as they come to the 
 * application and handled internally to the function. This is where the user may pull
 * a part the packet header and content data to be processed.  
 */
void packet_handler(unsigned char* user_data, const struct pcap_pkthdr* pkthdr, const unsigned char* packet_data) {
    std::cout << "********** Packet Data Captured **********" << std::endl;
    std::cout << "Captured Packet Length: " << pkthdr->len << " bytes." << std::endl;

#ifdef MACOS
    /*
     * On macOS, Ethernet headers are not available, so we skip Ethernet parsing
     * Check if it's an IP packet
     */

    if (pkthdr->len >= sizeof(struct ip)) {
        struct ip* ip_header = (struct ip*)packet_data;
        std::cout << "Source IP: " << inet_ntoa(ip_header->ip_src) << std::endl;
        std::cout << "Destination IP: " << inet_ntoa(ip_header->ip_dst) << std::endl;

        /* Check if it's a TCP packet */
        if (ip_header->ip_p == IPPROTO_TCP && pkthdr->len >= (sizeof(struct ip) + sizeof(struct tcphdr))) {
            struct tcphdr* tcp_header = (struct tcphdr*)(packet_data + ip_header->ip_hl * 4); // Skip IP header
            std::cout << "Source Port: " << ntohs(tcp_header->th_sport) << std::endl;
            std::cout << "Destination Port: " << ntohs(tcp_header->th_dport) << std::endl;
        }
    }
#else
    /*
     * On Linux, we can parse Ethernet headers
     * Check if it's an Ethernet (DLT_EN10MB) packet
     */
    int data_link_type = pcap_datalink(nullptr);
    if (data_link_type == DLT_EN10MB) {

        /* Check if the packet is large enough to contain an Ethernet header */
        if (pkthdr->len >= sizeof(struct ether_header)) {

            /* Parse Ethernet header */
            struct ether_header* eth_header = (struct ether_header*)packet_data;
            std::cout << "Source MAC: ";
            for (int i = 0; i < 6; ++i) {
                printf("%02x", eth_header->ether_shost[i]);
                if (i < 5) {
                    std::cout << ":";
                }
            }
            std::cout << std::endl;
            std::cout << "Destination MAC: ";
            for (int i = 0; i < 6; ++i) {
                printf("%02x", eth_header->ether_dhost[i]);
                if (i < 5) {
                    std::cout << ":";
                }
            }
            std::cout << std::endl;
        }
    }

    /* Check if it's an IP packet */
    if (pkthdr->len >= sizeof(struct ip)) {
        struct ip* ip_header = (struct ip*)(packet_data + sizeof(struct ether_header)); // Skip Ethernet header
        std::cout << "Source IP: " << inet_ntoa(ip_header->ip_src) << std::endl;
        std::cout << "Destination IP: " << inet_ntoa(ip_header->ip_dst) << std::endl;

        /* Check if it's a TCP packet */
        if (ip_header->ip_p == IPPROTO_TCP && pkthdr->len >= (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr))) {
            struct tcphdr* tcp_header = (struct tcphdr*)(packet_data + sizeof(struct ether_header) + ip_header->ip_hl * 4); // Skip IP header
            std::cout << "Source Port: " << ntohs(tcp_header->th_sport) << std::endl;
            std::cout << "Destination Port: " << ntohs(tcp_header->th_dport) << std::endl;
        }
    }
#endif

    /* Print packet data (hexadecimal representation) */
    std::cout << "Packet data (hex): \n";
    for (int i = 0; i < pkthdr->len; ++i) {
        printf("%02x ", packet_data[i]);
        if (i % 8 == 0) printf("\n");
    }
    std::cout << std::endl;

    /* Print packet data (ASCII representation) */
    std::cout << "Packet data (ASCII): \n";
    for (int i = 0; i < pkthdr->len; ++i) {
        char c = packet_data[i];
        if (isprint(c)) {
            std::cout << c;
        } else {
            std::cout << ".";
        }
    }
    std::cout << std::endl;
        std::cout << "--------------------Packet End---------------------" << std::endl;
}

int main(int argc, char* argv[]) {

    // Use the first network device
    char* dev;

    /* Check if there are at least two arguments (program name and one additional argument) */
    if (argc >= 2) {
        /* 
         * We will access command line arguments below using the
         * argv array which holds argument separated by spaces 
         */
        std::cout << "Program name : " << argv[0] << std::endl;
        std::cout << "Device Name  : " << argv[1] << std::endl;

        /* We assign the device name to the device variable */
        dev = argv[1];

        struct ifaddrs* iadd;
        struct sockaddr_in* addr;

        /* 
         * Below we are checking that we can acquire our local IP
         * address and if we are successful we print it so we can 
         * compare across packets if needed.
         */
        if (getifaddrs(&iadd) == 0) {
            for (struct ifaddrs* ifa = iadd; ifa != nullptr; ifa = ifa->ifa_next) {
                if (ifa->ifa_addr != nullptr && ifa->ifa_addr->sa_family == AF_INET) {
                    addr = (struct sockaddr_in*)ifa->ifa_addr;

                    /* 
                     * Use "en0" for Ethernet/Wi-Fi interface 
                     * Note: this is assigned by argv[1] 
                     */
                    if (strcmp(ifa->ifa_name, dev) == 0) {
                        std::cout << "Your IP address on " << ifa->ifa_name << ": " << inet_ntoa(addr->sin_addr) << std::endl;
                    }
                }
            }

            /* Free the memory allocated by getifaddrs */
            freeifaddrs(iadd); 
        } else {
            std::cerr << "Failed to get IP address." << std::endl;
        }

    } else {

        /* Print a message if there are no additional arguments */
        std::cout << "No additional command-line arguments provided." << std::endl;
    }

    /* 
     * We create an error buffer to store any errors that may 
     * be thrown 
     */
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    /* 
     * Find all available network devices 
     * Note: We do not use the DEVICE_NAME in this
     * program, and is only here for reference.
     * DEVICE_NAME contains all devices on the system
     * and can access each by walking the list
     */
    pcap_if_t* DEVICE_NAME;
    if (pcap_findalldevs(&DEVICE_NAME, errbuf) == -1) {
        std::cerr << "Error finding network devices: " << errbuf << std::endl;
        return 1;
    }

    pcap_if_t* device;
    int deviceCount = 0;

    /* 1 specifies promiscuous mode - meaning all network traffic is captured */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Could not open device " << dev << ": " << errbuf << std::endl;

        /* Free all devices in the list including that stored in dev */
        pcap_freealldevs(DEVICE_NAME);
        return 1;
    }

    // Start capturing packets and call the packet_handler function for each packet
    pcap_loop(handle, 0, packet_handler, nullptr);

    // Close the capture handle when done
    pcap_close(handle);

    // Free the device list
    pcap_freealldevs(DEVICE_NAME);

    return 0;

}