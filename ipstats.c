#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <netdb.h>

#define SNAPSHOTLEN    1514
#define PROMISCMODE    0
#define BUFFERTIME     1000

typedef struct run_t {
    uint64_t rx;
    uint64_t tx;

} run_t;

typedef struct client_t {
    run_t traffic;
    run_t lifetime;
    uint32_t rawip;
    char address[16];
    char *hostname;

} client_t;

typedef struct clients_t {
    client_t *list;
    uint64_t length;

} clients_t;

typedef struct userdata_t {
    uint32_t localnet;
    uint32_t localmask;
    uint64_t run;

    run_t lifetime;
    run_t runtotal;

    clients_t clients;

} userdata_t;

int prevCheck = 0;

void diep(char *str) {
    perror(str);
    exit(EXIT_FAILURE);
}

void diepcap(char *func, char *str) {
    fprintf(stderr, "[-] %s: %s\n", func, str);
    exit(EXIT_FAILURE);
}

//
// address tools
//
char *client_hostname(char *ipstr) {
    struct sockaddr_in sa;
    char node[NI_MAXHOST];
    int res;

    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ipstr, &sa.sin_addr);

    if((res = getnameinfo((struct sockaddr *) &sa, sizeof(sa), node, sizeof(node), NULL, 0, 0))) {
        printf("getnameinfo: %s\n", gai_strerror(res));
        return NULL;
    }

    return strdup(node);
}

unsigned char *utoip(int ip, unsigned char *buf) {
    buf[0] = ip & 0xFF;
    buf[1] = (ip >> 8) & 0xFF;
    buf[2] = (ip >> 16) & 0xFF;
    buf[3] = (ip >> 24) & 0xFF;

    return buf;
}

char *sprintip(int ip, char *buffer) {
    unsigned char tmpip[16];

    utoip(ip, tmpip);
    sprintf(buffer, "%d.%d.%d.%d", tmpip[0], tmpip[1], tmpip[2], tmpip[3]);

    return buffer;
}

//
// clients list
//
client_t *client_new(clients_t *clients, uint32_t ip, char *hostname) {
    client_t *client;

    clients->length += 1;
    if(!(clients->list = realloc(clients->list, clients->length * sizeof(client_t))))
        diep("realloc");

    client = &clients->list[clients->length - 1];
    memset(client, 0, sizeof(client_t));

    client->hostname = hostname;
    client->rawip = ip;
    sprintip(ip, client->address);

    return client;
}

client_t *client_get(clients_t *clients, uint32_t ip) {
    for(size_t i = 0; i < clients->length; i++) {
        client_t *client = &clients->list[i];

        if(client->rawip == ip)
            return client;
    }

    return NULL;
}

client_t *client_get_new(clients_t *clients, uint32_t ip) {
    client_t *client = NULL;

    if((client = client_get(clients, ip))) {
        return client;
    }

    return client_new(clients, ip, NULL);
}

void clients_dumps(clients_t *clients) {
    printf("---------------------|-----------------|-------------|-----------------\n");

    for(size_t i = 0; i < clients->length; i++) {
        client_t *client = &clients->list[i];

        float rx = client->traffic.rx / 1024.0;
        float tx = client->traffic.tx / 1024.0;
        char *hostname = (client->hostname) ? client->hostname : "(unknown)";

        printf("%-20s | %-15s | % 6.1f KB/s | % 6.1f KB/s\n", hostname, client->address, rx, tx);
    }
}

void clients_reset_pass(clients_t *clients) {
    for(size_t i = 0; i < clients->length; i++) {
        client_t *client = &clients->list[i];
        memset(&client->traffic, 0, sizeof(client->traffic));
    }
}

void clients_resolv(clients_t *clients) {
    char iptmp[32];

    for(size_t i = 0; i < clients->length; i++) {
        client_t *client = &clients->list[i];

        if(client->hostname)
            continue;

        sprintip(client->rawip, iptmp);
        client->hostname = client_hostname(iptmp);
    }
}


//
// packets handler
//
void callback(unsigned char *user, const struct pcap_pkthdr *h, const u_char *buff) {
    struct ether_header *eptr;
    u_char *packet;
    struct iphdr *ipheader;
    unsigned char src[16], dst[16];
    userdata_t *userdata = (userdata_t *) user;
    client_t *client = NULL;

    uint32_t srcip;
    uint32_t dstip;

    eptr = (struct ether_header *) buff;

    if(ntohs(eptr->ether_type) == ETHERTYPE_IP) {
        packet = (unsigned char *)(buff + sizeof(struct ether_header));
        ipheader = (struct iphdr *) packet;

        srcip = ntohl(ipheader->saddr);
        dstip = ntohl(ipheader->daddr);

        // source is in our local network
        // this is an outgoing packet
        if((srcip & userdata->localmask) == userdata->localnet) {
            client = client_get_new(&userdata->clients, ipheader->saddr);
            // client = client_get_new(&userdata->clients, ipheader->daddr);
            client->lifetime.tx += h->len;
            client->traffic.tx += h->len;
            userdata->runtotal.tx += h->len;
        }

        // destination is in our local network
        // this is an incoming packet
        if((dstip & userdata->localmask) == userdata->localnet) {
            client = client_get_new(&userdata->clients, ipheader->daddr);
            // client = client_get_new(&userdata->clients, ipheader->saddr);
            client->lifetime.rx += h->len;
            client->traffic.rx += h->len;
            userdata->runtotal.rx += h->len;
        }

        utoip(ipheader->saddr, src);
        utoip(ipheader->daddr, dst);

        /*
        printf(
            "%lu: %d.%d.%d.%d -> %d.%d.%d.%d: %d bytes\n",
            userdata->run,
            src[0], src[1], src[2], src[3],
            dst[0], dst[1], dst[2], dst[3],
            h->len
        );
        */

        fflush(stdout);
    }
}

int main(int argc, char *argv[]) {
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t *pd;
    userdata_t userdata;

    if(argc < 2) {
        fprintf(stderr, "Usage: %s interface\n", argv[0]);
        return 1;
    }

    // setting all counter to zero
    memset(&userdata, 0, sizeof(userdata_t));

    if((pd = pcap_open_live(argv[1], SNAPSHOTLEN, PROMISCMODE, BUFFERTIME, errbuff)) == NULL)
        diepcap("pcap_open_live", errbuff);

    if(pcap_lookupnet(argv[1], &userdata.localnet, &userdata.localmask, errbuff) == -1)
        diepcap("pcap_lookupnet", errbuff);

    // convert host and mask to host integer
    userdata.localnet = ntohl(userdata.localnet);
    userdata.localmask = ntohl(userdata.localmask);

    while(1) {
        // reset this run counter
        userdata.runtotal.rx = 0;
        userdata.runtotal.tx = 0;

        if(pcap_dispatch(pd, -1, callback, (u_char *) &userdata) < 0)
            diepcap("pcap_dispatch", pcap_geterr(pd));

        // printf("RUN: in: %.1f KB/s, out: %.1f KB/s\n", userdata.runtotal.rx / 1024.0, userdata.runtotal.tx / 1024.0);

        userdata.lifetime.rx += userdata.runtotal.rx;
        userdata.lifetime.tx += userdata.runtotal.tx;

        clients_resolv(&userdata.clients);
        clients_dumps(&userdata.clients);
        clients_reset_pass(&userdata.clients);

        userdata.run += 1;
    }

    return 0;
}


