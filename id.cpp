#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>
#include <vector>
#include <numeric>
#include <cmath>
#include <unistd.h>
#include <jsoncpp/json/json.h>
#include<iostream>
const int MAX_PACKET_SIZE = 1500;
std::vector<int> packet_sizes;

void emit_packet_json(const struct pcap_pkthdr *pkthdr, const struct ip *ip_header,
                      bool same_ip, bool oversized, bool statdev) {
    Json::Value pkt;
    pkt["ts"] = (Json::UInt64)pkthdr->ts.tv_sec * 1000000 + pkthdr->ts.tv_usec;
    pkt["src"] = inet_ntoa(ip_header->ip_src);
    pkt["dst"] = inet_ntoa(ip_header->ip_dst);
    pkt["size"] = pkthdr->len;
    pkt["same_ip"] = same_ip;
    pkt["oversize"] = oversized;
    pkt["statdev"] = statdev;

    Json::StreamWriterBuilder builder;
    builder["indentation"] = "";
    std::string output = Json::writeString(builder, pkt);
    std::cout << output << std::endl;
    std::cout.flush();
}

void check_anomalies(const struct pcap_pkthdr *pkthdr, const struct ip *ip_header) {
    bool same_ip = (ip_header->ip_src.s_addr == ip_header->ip_dst.s_addr);
    bool oversized = (pkthdr->len > MAX_PACKET_SIZE);

    packet_sizes.push_back(pkthdr->len);
    if (packet_sizes.size() > 100) {
        packet_sizes.erase(packet_sizes.begin());
    }

    double mean = std::accumulate(packet_sizes.begin(), packet_sizes.end(), 0.0) / packet_sizes.size();
    double sq_sum = std::inner_product(packet_sizes.begin(), packet_sizes.end(), packet_sizes.begin(), 0.0);
    double stdev = std::sqrt(sq_sum / packet_sizes.size() - mean * mean);
    bool statdev = (pkthdr->len > mean + 2 * stdev || pkthdr->len < mean - 2 * stdev);

    emit_packet_json(pkthdr, ip_header, same_ip, oversized, statdev);
}

void packet_handler(unsigned char *, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    const struct ip *ip_header = (const struct ip *)(packet + 14);
    if (ip_header->ip_v == 4) {
        check_anomalies(pkthdr, ip_header);
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Could not open device eth0: %s\n", errbuf);
        return 1;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device is not Ethernet\n");
        pcap_close(handle);
        return 2;
    }

    pcap_loop(handle, 0, packet_handler, nullptr);
    pcap_close(handle);
    return 0;
}