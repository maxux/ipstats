#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>
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
#include <getopt.h>
#include "lantraffic.h"

static struct option long_options[] = {
    {"interface",    required_argument, 0, 'i'},
    {"redis-host",   required_argument, 0, 'r'},
    {"redis-port",   required_argument, 0, 'p'},
    {"redis-socket", required_argument, 0, 's'},
    {"jsonfile",     required_argument, 0, 'j'},
    {"numeric",      no_argument,       0, 'n'},
    {"external",     no_argument,       0, 'e'},
    {"help",         no_argument,       0, 'h'},
    {0, 0, 0, 0}
};

int prevCheck = 0;

static char *jsonbuffer = NULL;

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

char *client_json(client_t *client) {
    char *b = jsonbuffer; // shortcut
    int off = 0;

    // set initial offset
    off = 0;

    off += sprintf(b + off, "{");
    off += sprintf(b + off, "\"host\":\"%s\",", (client->hostname) ? client->hostname : "(unknown)");
    off += sprintf(b + off, "\"addr\":\"%s\",", client->address);
    off += sprintf(b + off, "\"rx\":%lu,", client->traffic.rx);
    off += sprintf(b + off, "\"tx\":%lu", client->traffic.tx);
    off += sprintf(b + off, "}");

    return jsonbuffer;
}

void clients_dumps_redis(clients_t *clients, redisContext *redis) {
#ifndef NOREDIS
    redisReply *reply;

    for(size_t i = 0; i < clients->length; i++) {
        client_t *client = &clients->list[i];
        char *json = client_json(client);

        reply = redisCommand(redis, "SET traffic-live-%s %s", client->address, json);
        if(!reply || reply->type != REDIS_REPLY_STATUS)
            fprintf(stderr, "wrong redis reply\n");

        freeReplyObject(reply);
    }
#else
    (void) clients;
    (void) redis;
#endif
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
    lantraffic_t *settings = (lantraffic_t *) user;
    userdata_t *userdata = &settings->userdata;
    struct ether_header *eptr;
    u_char *packet;
    struct iphdr *ipheader;
    unsigned char src[16], dst[16];
    client_t *client = NULL;

    // shortcut accessor
    uint32_t lmask = userdata->localmask;
    uint32_t lnet = userdata->localnet;

    uint32_t srcip;
    uint32_t dstip;

    eptr = (struct ether_header *) buff;

    if(ntohs(eptr->ether_type) == ETHERTYPE_IP) {
        packet = (unsigned char *)(buff + sizeof(struct ether_header));
        ipheader = (struct iphdr *) packet;

        srcip = ntohl(ipheader->saddr);
        dstip = ntohl(ipheader->daddr);

        // if source and destination match the monitored netmask
        // this is a inter-routing (cross-interface or explicit routing)
        // and this can be ignored via command line argument (FIXME)
        if((srcip & lmask) == lnet && (dstip & lmask) == lnet) {
            if(!settings->inrouting)
                // skip this packet
                return;
        }

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
    }
}

int lantraffic(lantraffic_t *settings) {
    char errbuff[PCAP_ERRBUF_SIZE];
    userdata_t *userdata = &settings->userdata;
    pcap_t *pd;

    // pre-allocate json buffer
    if(!(jsonbuffer = malloc(sizeof(char) * 4192)))
        diep("malloc");

    if((pd = pcap_open_live(settings->interface, SNAPSHOTLEN, PROMISCMODE, BUFFERTIME, errbuff)) == NULL)
        diepcap("pcap_open_live", errbuff);

    if(pcap_lookupnet(settings->interface, &userdata->localnet, &userdata->localmask, errbuff) == -1)
        diepcap("pcap_lookupnet", errbuff);

    // convert host and mask to host integer
    userdata->localnet = ntohl(userdata->localnet);
    userdata->localmask = ntohl(userdata->localmask);

    userdata->dumptime = time(NULL);

    while(1) {
        // reset this run counter
        userdata->runtotal.rx = 0;
        userdata->runtotal.tx = 0;

        if(pcap_dispatch(pd, -1, callback, (u_char *) settings) < 0)
            diepcap("pcap_dispatch", pcap_geterr(pd));

        userdata->lifetime.rx += userdata->runtotal.rx;
        userdata->lifetime.tx += userdata->runtotal.tx;

        if(userdata->dumptime == time(NULL))
            continue;

        if(settings->resolv)
            clients_resolv(&userdata->clients);

        clients_dumps(&userdata->clients);

        if(settings->redis)
            clients_dumps_redis(&userdata->clients, settings->redis);

        clients_reset_pass(&userdata->clients);

        userdata->dumptime = time(NULL);
        userdata->run += 1;
    }

    return 0;
}

void usage() {
    printf("Command line arguments:\n");
    printf("  --interface     interface to monitor (required)\n");
    printf("  --redis-host    redis backend host\n");
    printf("  --redis-port    redis backend port\n");
    printf("  --redis-socket  redis backend unix socket path (override host and port)\n");
    printf("  --jsonfile      filename where dumps json (better use tmpfs, lot of write)\n");
    printf("  --numeric       don't resolv hostnames\n");
    printf("  --external      ignore internal routing\n");
    printf("  --help          print this message\n");

    exit(EXIT_FAILURE);
}

int redis_connect_tcp(lantraffic_t *settings) {
#ifndef NOREDIS
    // connect redis backend unix tcp
    if(!(settings->redis = redisConnect(settings->redishost, settings->redisport)))
        diep("redis");

    if(settings->redis->err) {
        fprintf(stderr, "redis (tcp): %s\n", settings->redis->errstr);
        exit(EXIT_FAILURE);
    }
#else
    (void) settings;
    fprintf(stderr, "[-] redis support not compiled in\n");
#endif

    return 0;
}

int redis_connect_unix(lantraffic_t *settings) {
#ifndef NOREDIS
    // connect redis backend unix unix socket
    if(!(settings->redis = redisConnectUnix(settings->redisunix)))
        diep("redis");

    if(settings->redis->err) {
        fprintf(stderr, "redis: %s\n", settings->redis->errstr);
        exit(EXIT_FAILURE);
    }
#else
    (void) settings;
    fprintf(stderr, "[-] redis support not compiled in\n");
#endif

    return 0;
}

int initializer(lantraffic_t *settings) {
    if(settings->redisunix) {
        redis_connect_unix(settings);

    } else if(settings->redishost) {
        redis_connect_tcp(settings);
    }

    if(settings->jsonfile) {
        // json
    }

    return lantraffic(settings);
}

int main(int argc, char *argv[]) {
    lantraffic_t settings;

    printf("[+] initializing lantraffic\n");

    // settings default value
    memset(&settings, 0, sizeof(lantraffic_t));
    settings.resolv = 1;
    settings.inrouting = 1;

    // parsing commandline
    int option_index = 0;

    while(1) {
        int i = getopt_long_only(argc, argv, "", long_options, &option_index);

        if(i == -1)
            break;

        switch(i) {
            case 'i':
                settings.interface = optarg;
                break;

            case 'r':
                settings.redishost = optarg;
                break;

            case 'p':
                settings.redisport = atoi(optarg);
                break;

            case 's':
                settings.redisunix = optarg;
                break;

            case 'j':
                settings.jsonfile = optarg;
                break;

            case 'n':
                settings.resolv = 0;
                break;

            case 'e':
                settings.inrouting = 0;
                break;

            case 'h':
                usage();
                break;

            case '?':
            default:
               exit(EXIT_FAILURE);
        }
    }

    if(!settings.interface) {
        fprintf(stderr, "[-] missing interface name, fallback to 'lo'\n");
        settings.interface = "lo";
    }

    return initializer(&settings);
}
