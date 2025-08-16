/*
 * Educational Packet Interceptor
 * For network analysis in controlled lab environments only
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <pcap.h>
#include <signal.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <syslog.h>

#define BUFFER_SIZE 4096
#define MAX_PACKET_SIZE 65535

struct packet_info {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    size_t payload_len;
    unsigned char *payload;
};

static int running = 1;
static FILE *log_file = NULL;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

void signal_handler(int sig) {
    syslog(LOG_INFO, "Received signal %d, shutting down...", sig);
    running = 0;
}

void log_packet(struct packet_info *pkt_info) {
    pthread_mutex_lock(&log_mutex);
    
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &pkt_info->src_ip, src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &pkt_info->dst_ip, dst_ip_str, INET_ADDRSTRLEN);
    
    if (log_file) {
        fprintf(log_file, "[PACKET] %s:%d -> %s:%d | Proto: %d | Len: %zu\n",
                src_ip_str, ntohs(pkt_info->src_port),
                dst_ip_str, ntohs(pkt_info->dst_port),
                pkt_info->protocol, pkt_info->payload_len);
        fflush(log_file);
    }
    
    syslog(LOG_DEBUG, "Packet: %s:%d -> %s:%d",
           src_ip_str, ntohs(pkt_info->src_port),
           dst_ip_str, ntohs(pkt_info->dst_port));
    
    pthread_mutex_unlock(&log_mutex);
}

static int packet_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                          struct nfq_data *nfa, void *data) {
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *payload;
    int payload_len;
    uint32_t id = 0;
    
    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
    }
    
    payload_len = nfq_get_payload(nfa, &payload);
    if (payload_len >= 0) {
        struct iphdr *iph = (struct iphdr *)payload;
        struct packet_info pkt_info = {0};
        
        if (iph->version == 4) {
            pkt_info.src_ip = iph->saddr;
            pkt_info.dst_ip = iph->daddr;
            pkt_info.protocol = iph->protocol;
            
            if (iph->protocol == IPPROTO_TCP) {
                struct tcphdr *tcph = (struct tcphdr *)(payload + (iph->ihl * 4));
                pkt_info.src_port = tcph->source;
                pkt_info.dst_port = tcph->dest;
            } else if (iph->protocol == IPPROTO_UDP) {
                struct udphdr *udph = (struct udphdr *)(payload + (iph->ihl * 4));
                pkt_info.src_port = udph->source;
                pkt_info.dst_port = udph->dest;
            }
            
            pkt_info.payload_len = payload_len;
            pkt_info.payload = payload;
            
            log_packet(&pkt_info);
        }
    }
    
    // Accept the packet
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv) {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[MAX_PACKET_SIZE] __attribute__ ((aligned));
    
    // Open syslog
    openlog("packet-interceptor", LOG_PID | LOG_CONS, LOG_DAEMON);
    syslog(LOG_INFO, "Educational Packet Interceptor starting...");
    
    // Open log file
    log_file = fopen("/tmp/packet-interceptor.log", "a");
    if (!log_file) {
        syslog(LOG_WARNING, "Failed to open log file");
    }
    
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Open netfilter queue
    h = nfq_open();
    if (!h) {
        syslog(LOG_ERR, "Error opening nfq");
        return 1;
    }
    
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        syslog(LOG_WARNING, "Error unbinding existing nfq handler");
    }
    
    if (nfq_bind_pf(h, AF_INET) < 0) {
        syslog(LOG_ERR, "Error binding nfq");
        nfq_close(h);
        return 1;
    }
    
    // Create queue 0
    qh = nfq_create_queue(h, 0, &packet_callback, NULL);
    if (!qh) {
        syslog(LOG_ERR, "Error creating queue");
        nfq_close(h);
        return 1;
    }
    
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        syslog(LOG_ERR, "Error setting packet copy mode");
        nfq_destroy_queue(qh);
        nfq_close(h);
        return 1;
    }
    
    fd = nfq_fd(h);
    
    syslog(LOG_INFO, "Packet interceptor ready, processing packets...");
    
    while (running) {
        rv = recv(fd, buf, sizeof(buf), 0);
        if (rv >= 0) {
            nfq_handle_packet(h, buf, rv);
        }
    }
    
    syslog(LOG_INFO, "Shutting down packet interceptor");
    
    nfq_destroy_queue(qh);
    nfq_close(h);
    
    if (log_file) {
        fclose(log_file);
    }
    
    closelog();
    
    return 0;
}