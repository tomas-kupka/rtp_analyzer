#include <iostream>
#include <vector>
#include <map>
#include <sstream>
#include <numeric>

extern "C" {
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <sqlite3.h>
#include <pcap.h>
}

using namespace std;

struct UDP_hdr {
    u_short	uh_sport;		/* source port */
    u_short	uh_dport;		/* destination port */
    u_short	uh_ulen;		/* datagram length */
    u_short	uh_sum;			/* datagram checksum */
};

struct RTP_hdr {
    uint8_t version_p_x_cc;
    uint8_t m_pt;
    uint16_t seq;
    uint32_t ts;
    uint32_t ssrc;
};

const char *timestamp_string(struct timeval ts) {
    static char timestamp_string_buf[256];

    sprintf(timestamp_string_buf, "%d.%06d",
            (int) ts.tv_sec, (int) ts.tv_usec);

    return timestamp_string_buf;
}

int timeval_subtract(struct timeval *result, const struct timeval *x, struct timeval *y) {
    if (x->tv_usec < y->tv_usec) {
        int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
        y->tv_usec -= 1000000 * nsec;
        y->tv_sec += nsec;
    }
    if (x->tv_usec - y->tv_usec > 1000000) {
        int nsec = (x->tv_usec - y->tv_usec) / 1000000;
        y->tv_usec += 1000000 * nsec;
        y->tv_sec -= nsec;
    }

    /* Compute the time remaining to wait. tv_usec is certainly positive. */
    result->tv_sec = x->tv_sec - y->tv_sec;
    result->tv_usec = x->tv_usec - y->tv_usec;

    /* Return 1 if result is negative. */
    return x->tv_sec < y->tv_sec;
}

class Connection {
public:
    string src_ip;
    string dst_ip;
    unsigned int src_port;
    unsigned int dst_port;
    unsigned int last_seq;
    unsigned int ssrc;
    struct timeval last_ts;
    unsigned int lost_packets;
    unsigned int n_packets;
    vector<int64_t> interarrival_times;
    unsigned int rtcp_packets;
    unsigned int ts;
    unsigned int m_pt;
    Connection(string src_ip,
               string dst_ip,
               unsigned int src_port,
               unsigned int dst_port,
               unsigned int seq,
               unsigned int ssrc,
               const struct timeval &t);
    void AddPacket(unsigned int seq, const struct timeval &ts);
    void PrintStats(void);
};

Connection::Connection(string src_ip,
                       string dst_ip,
                       unsigned int src_port,
                       unsigned int dst_port,
                       unsigned int seq,
                       unsigned int ssrc,
                       const struct timeval &t) {
    this->src_ip = src_ip;
    this->dst_ip = dst_ip;
    this->src_port = src_port;
    this->dst_port = dst_port;
    this->last_seq = seq;
    this->ssrc = ssrc;
    this->last_ts.tv_sec = t.tv_sec;
    this->last_ts.tv_usec = t.tv_usec;
    this->lost_packets = 0;
    this->n_packets = 1;
    this->rtcp_packets = 0;
}

void Connection::AddPacket(unsigned int seq, const struct timeval &ts) {
    // Lost packets calculation
    unsigned int diff_seq = seq - this->last_seq;
    if (seq < this->last_seq) {
        diff_seq = this->last_seq - seq;
    }
    this->lost_packets += diff_seq > 0 ? diff_seq - 1 : 0;
    this->last_seq = seq;

    // Inter arrival time calculation
    struct timeval inter_arrival_t;
    timeval_subtract(&inter_arrival_t, &ts, &this->last_ts);
    int64_t it = inter_arrival_t.tv_sec * 1000 + inter_arrival_t.tv_usec / 1000;
    this->interarrival_times.push_back(it);
    this->last_ts = ts;

    // Increase packet counter
    this->n_packets += 1;
}

void Connection::PrintStats(void) {
    auto j_max = max_element(this->interarrival_times.begin(), this->interarrival_times.end());
    vector<int64_t> i_copy = this->interarrival_times;
    sort(i_copy.begin(), i_copy.end());
    uint64_t res = accumulate(this->interarrival_times.begin(), this->interarrival_times.end(), 0);

    printf("%s %s:%u -> %s:%u npackets:%u lpackets:%u payload:%u ssrc:0x%x firstts:0x%x nrtcp:%u"
                   " j_mean: %llu j_50:%llu\n j_98:%llu j_max:%llu\n",
           timestamp_string(this->last_ts),
           this->src_ip.c_str(),
           this->src_port,
           this->dst_ip.c_str(),
           this->dst_port,
           this->n_packets,
           this->lost_packets,
           this->m_pt,
           this->ssrc,
           this->ts,
           this->rtcp_packets,
           res/this->interarrival_times.size(),
           *(i_copy.begin()+int(i_copy.size()*.50)),
           *(i_copy.begin()+int(i_copy.size()*.98)),
           *j_max);
}

void dump_packet(const struct ip *ip, const struct UDP_hdr *udp, const struct timeval &ts) {
    char src_str[INET6_ADDRSTRLEN];
    char dst_str[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ip->ip_src.s_addr), src_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->ip_dst.s_addr), dst_str, INET_ADDRSTRLEN);

    printf("%s UDP src_ip=%s src_port=%d dst_ip=%s dst_port=%d length=%d\n",
           timestamp_string(ts),
           src_str,
           ntohs(udp->uh_sport),
           dst_str,
           ntohs(udp->uh_dport),
           ntohs(udp->uh_ulen));
}

void process_packet(map<string, Connection *> &connections,
                    const unsigned char *packet,
                    const struct timeval &ts,
                    unsigned int capture_len) {
    struct ip *ip;
    struct UDP_hdr *udp;
    struct RTP_hdr *rtp;
    unsigned int IP_header_length;

    if (capture_len < sizeof(struct ether_header)) {
        std::cout << "Packet too short for an ethernet frame" << std::endl;
        return;
    }

    packet += sizeof(struct ether_header);
    capture_len -= sizeof(struct ether_header);

    if (capture_len < sizeof(struct ip)) {
        std::cout << "Packet too short for an IP packet" << std::endl;
        return;
    }

    ip = (struct ip*) packet;
    IP_header_length = ip->ip_hl * 4;	/* ip_hl is in 4-byte words */

    if (capture_len < IP_header_length) {
        std::cout << "IP packet without options" << std::endl;
        return;
    }

    if (ip->ip_p != IPPROTO_UDP) {
        std::cout << "Not a UDP packet" << std::endl;
        return;
    }

    packet += IP_header_length;
    capture_len -= IP_header_length;

    if (capture_len < sizeof(struct UDP_hdr)) {
        std::cout << "Packet too short for an UDP packet" << std::endl;
        return;
    }

    udp = (struct UDP_hdr*) packet;

    packet += sizeof(struct UDP_hdr);
    capture_len -= sizeof(struct UDP_hdr);

    if (capture_len < sizeof(struct RTP_hdr)) {
        dump_packet(ip, udp, ts);
        std::cout << "Packet too short for an RTP/RTCP packet" << std::endl;
        return;
    }

    rtp = (struct RTP_hdr*) packet;

    char src_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->ip_src.s_addr), src_str, INET_ADDRSTRLEN);
    string ip_src = src_str;
    unsigned int port_src = ntohs(udp->uh_sport);

    char dst_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->ip_dst.s_addr), dst_str, INET_ADDRSTRLEN);
    string ip_dst = dst_str;
    unsigned int port_dst = ntohs(udp->uh_dport);

    unsigned int ssrc = ntohl(rtp->ssrc);
    unsigned int ssrc_rtcp = ntohl(rtp->ts);

    ostringstream connection_str;
    ostringstream connection_str_rtcp;
    connection_str << ip_src << ":" << port_src << ip_dst << ":" << port_dst << "-" << ssrc;
    connection_str_rtcp << ip_src << ":" << port_src << ip_dst << ":" << port_dst << "-" << ssrc_rtcp;
    string connection_id = connection_str.str();
    string connection_id_rtcp = connection_str_rtcp.str();

    map<string, Connection *>::iterator it = connections.find(connection_id);
    if (it != connections.end()) {
        it->second->AddPacket(ntohs(rtp->seq), ts);
        return;
    }

    map<string, Connection *>::iterator it_rtsp = connections.find(connection_id_rtcp);
    if (it_rtsp != connections.end()) {
        // This is probably a RTCP packet for connection with SSRC == rtp->ts
        Connection *rtcp_connection = it_rtsp->second;
        rtcp_connection->rtcp_packets++;
        return;
    }

    Connection *connection = new Connection(
            ip_src,
            ip_dst,
            port_src,
            port_dst,
            ntohs(rtp->seq),
            ntohl(rtp->ssrc),
            ts);
    connection->m_pt = rtp->m_pt;
    connection->ts = ntohl(rtp->ts);
    connections[connection_id] = connection;
}

int main(int argc, char **argv) {
    pcap_t *pcap;
    const unsigned char *packet;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;

    ++argv; --argc;

    if (argc != 1) {
        fprintf(stderr, "program requires one argument, the trace file to dump\n");
        exit(1);
    }

    pcap = pcap_open_offline(argv[0], errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "error reading pcap file: %s\n", errbuf);
        exit(1);
    }

    map<string, Connection *> connections;

    while ((packet = pcap_next(pcap, &header)) != NULL) {
        process_packet(connections, packet, header.ts, header.caplen);
    }

    for (auto const &conn : connections) {
        Connection *c = conn.second;
        if (c->n_packets > 2) {
            c->PrintStats();
        }
    }

    return 0;
}
