#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <string.h>
#include <deque>
#include <cmath>
#include <map>
#include <set>
#include <jsoncpp/json/json.h>
#include <iostream>

const int MAX_PACKET_SIZE      = 1500;
const int PORT_SCAN_THRESHOLD  = 15;
const int SYN_FLOOD_THRESHOLD  = 100;
const int ICMP_FLOOD_THRESHOLD = 50;
const int ROLLING_WINDOW       = 100;

std::deque<int> packet_sizes;
std::map<std::string, std::set<int>> port_scan_tracker;
std::map<std::string, int> syn_counter;
std::map<std::string, int> icmp_counter;

void emit_packet_json(const struct pcap_pkthdr *pkthdr,
                      const struct ip *iph,
                      bool same_ip, bool oversized,
                      bool statdev, bool port_scan,
                      bool syn_flood, bool icmp_flood,
                      int dst_port)
{
    Json::Value pkt;
    pkt["ts"]         = (Json::UInt64)pkthdr->ts.tv_sec * 1000000 + pkthdr->ts.tv_usec;
    pkt["src"]        = inet_ntoa(iph->ip_src);
    pkt["dst"]        = inet_ntoa(iph->ip_dst);
    pkt["size"]       = (int)pkthdr->len;
    pkt["proto"]      = (int)iph->ip_p;
    pkt["dst_port"]   = dst_port;
    pkt["same_ip"]    = same_ip;
    pkt["oversize"]   = oversized;
    pkt["statdev"]    = statdev;
    pkt["port_scan"]  = port_scan;
    pkt["syn_flood"]  = syn_flood;
    pkt["icmp_flood"] = icmp_flood;

    Json::StreamWriterBuilder builder;
    builder["indentation"] = "";
    std::cout << Json::writeString(builder, pkt) << "\n";
    std::cout.flush();
}

void check_anomalies(const struct pcap_pkthdr *pkthdr,
                     const unsigned char *packet,
                     const struct ip *iph)
{
    std::string src_ip = inet_ntoa(iph->ip_src);

    bool same_ip   = (iph->ip_src.s_addr == iph->ip_dst.s_addr);
    bool oversized = (pkthdr->len > MAX_PACKET_SIZE);

    packet_sizes.push_back(pkthdr->len);
    if ((int)packet_sizes.size() > ROLLING_WINDOW)
        packet_sizes.pop_front();

    double mean = 0, sq_sum = 0;
    for (int s : packet_sizes) mean += s;
    mean /= packet_sizes.size();
    for (int s : packet_sizes) sq_sum += (s - mean) * (s - mean);
    double stdev = std::sqrt(sq_sum / packet_sizes.size());
    bool statdev  = (pkthdr->len > mean + 2*stdev || pkthdr->len < mean - 2*stdev);

    int  ip_header_len = iph->ip_hl * 4;
    bool port_scan  = false;
    bool syn_flood  = false;
    bool icmp_flood = false;
    int  dst_port   = -1;

    if (iph->ip_p == IPPROTO_TCP) {
        const struct tcphdr *tcp =
            (const struct tcphdr *)(packet + 14 + ip_header_len);
        dst_port = ntohs(tcp->th_dport);
        port_scan_tracker[src_ip].insert(dst_port);
        port_scan = (port_scan_tracker[src_ip].size() > PORT_SCAN_THRESHOLD);
        if ((tcp->th_flags & TH_SYN) && !(tcp->th_flags & TH_ACK))
            syn_flood = (++syn_counter[src_ip] > SYN_FLOOD_THRESHOLD);

    } else if (iph->ip_p == IPPROTO_UDP) {
        const struct udphdr *udp =
            (const struct udphdr *)(packet + 14 + ip_header_len);
        dst_port = ntohs(udp->uh_dport);

    } else if (iph->ip_p == IPPROTO_ICMP) {
        icmp_flood = (++icmp_counter[src_ip] > ICMP_FLOOD_THRESHOLD);
    }

    emit_packet_json(pkthdr, iph, same_ip, oversized, statdev,
                     port_scan, syn_flood, icmp_flood, dst_port);
}

void packet_handler(unsigned char *,
                    const struct pcap_pkthdr *pkthdr,
                    const unsigned char *packet)
{
    if (pkthdr->len < 14) return;
    const struct ip *iph = (const struct ip *)(packet + 14);
    if (iph->ip_v == 4)
        check_anomalies(pkthdr, packet, iph);
}

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *dev = nullptr;

    if (argc > 1) {
        dev = argv[1];
    } else {
        pcap_if_t *alldevs;
        if (pcap_findalldevs(&alldevs, errbuf) == -1 || !alldevs) {
            fprintf(stderr, "No devices found: %s\n", errbuf);
            return 1;
        }
        dev = alldevs->name;
        fprintf(stderr, "Auto-selected device: %s\n", dev);
    }

    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Cannot open device %s: %s\n", dev, errbuf);
        return 1;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Not an Ethernet device\n");
        pcap_close(handle);
        return 2;
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "ip and not broadcast", 0, PCAP_NETMASK_UNKNOWN) == 0)
        pcap_setfilter(handle, &fp);

    fprintf(stderr, "Capturing on %s ...\n", dev);
    pcap_loop(handle, 0, packet_handler, nullptr);
    pcap_close(handle);
    return 0;
}
