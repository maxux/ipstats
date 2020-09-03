#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <linux/ipv6.h>
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
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>
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

static char *jsonbuffer = NULL;

static void diep(char *str) {
    perror(str);
    exit(EXIT_FAILURE);
}

static void diepcap(char *func, char *str) {
    fprintf(stderr, "[-] %s: %s\n", func, str);
    exit(EXIT_FAILURE);
}

//
// address tools
//
static char *client_hostname(char *ipstr) {
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

//
// clients list
//
static client_t *client_new(clients_t *clients, uint32_t ip, char *hostname, uint8_t *macaddr) {
    client_t *client;

    clients->length += 1;
    if(!(clients->list = realloc(clients->list, clients->length * sizeof(client_t))))
        diep("realloc");

    client = &clients->list[clients->length - 1];
    memset(client, 0, sizeof(client_t));

    client->hostname = hostname;
    client->rawip = ip;

    // string ipv4
    inet_ntop(AF_INET, &ip, client->address, sizeof(client->address));

    memcpy(client->macaddr, macaddr, 6);
    client->activity = time(NULL);

    return client;
}

static client_t *client_get(clients_t *clients, uint32_t ip) {
    for(size_t i = 0; i < clients->length; i++) {
        client_t *client = &clients->list[i];

        if(client->rawip == ip)
            return client;
    }

    return NULL;
}

static client_t *client_get_new(clients_t *clients, uint32_t ip, uint8_t *macaddr) {
    client_t *client = NULL;

    if((client = client_get(clients, ip)))
        return client;

    return client_new(clients, ip, NULL, macaddr);
}

static client_t *client_get_mac(clients_t *clients, uint8_t *macaddr) {
    for(size_t i = 0; i < clients->length; i++) {
        client_t *client = &clients->list[i];

        if(memcmp(client->macaddr, macaddr, 6) == 0)
            return client;
    }

    return NULL;
}

static void clients_dumps(clients_t *clients) {
    printf("---------------------|-----------------|-------------|-----------------\n");

    for(size_t i = 0; i < clients->length; i++) {
        client_t *client = &clients->list[i];

        float rx = client->traffic.rx / 1024.0;
        float tx = client->traffic.tx / 1024.0;
        char *hostname = (client->hostname) ? client->hostname : "(unknown)";

        printf("%-20s | %-15s | % 6.1f KB/s | % 6.1f KB/s\n", hostname, client->address, rx, tx);
    }
}

static char *macbin_str(char *buffer, uint8_t *m) {
    sprintf(buffer, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
    return buffer;
}


static char *client_json(client_t *client) {
    char *b = jsonbuffer; // shortcut
    char temp[32];
    int off = 0;

    macbin_str(temp, client->macaddr);

    // set initial offset
    off = 0;
    off += sprintf(b + off, "{");

    // do not append hostname if not defined
    if(client->hostname)
        off += sprintf(b + off, "\"host\":\"%s\",", client->hostname);

    off += sprintf(b + off, "\"addr\":\"%s\",", client->address);
    off += sprintf(b + off, "\"rx\":%lu,", client->traffic.rx);
    off += sprintf(b + off, "\"tx\":%lu,", client->traffic.tx);
    off += sprintf(b + off, "\"total-rx\":%lu,", client->lifetime.rx);
    off += sprintf(b + off, "\"total-tx\":%lu,", client->lifetime.tx);
    off += sprintf(b + off, "\"active\":%lu,", client->activity);
    off += sprintf(b + off, "\"macaddr\":\"%s\"", temp);
    off += sprintf(b + off, "}");

    return jsonbuffer;
}

static void clients_dumps_redis(clients_t *clients, redisContext *redis) {
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

static void clients_reset_pass(clients_t *clients) {
    for(size_t i = 0; i < clients->length; i++) {
        client_t *client = &clients->list[i];
        memset(&client->traffic, 0, sizeof(client->traffic));
    }
}

static void clients_resolv(clients_t *clients) {
    for(size_t i = 0; i < clients->length; i++) {
        client_t *client = &clients->list[i];

        if(client->hostname)
            continue;

        client->hostname = client_hostname(client->address);
    }
}

int address_match(addr_t *addr, uint8_t *input, size_t len) {
    for(size_t i = 0; i < len; i++) {
        if((input[i] & addr->mask[i]) != (addr->addr[i] & addr->mask[i]))
            return 0;
    }

    return 1;
}

int addresses_match(addrs_t *addrs, uint8_t *input, size_t len) {
    for(size_t i = 0; i < addrs->length; i++) {
        addr_t *addr = addrs->addrs[i];

        if(addr->addrlen != len)
            continue;

        if(address_match(addr, input, len))
            return 1;
    }

    return 0;
}

//
// packets handler
//
void callback(unsigned char *user, const struct pcap_pkthdr *h, const u_char *buff) {
    lantraffic_t *settings = (lantraffic_t *) user;
    userdata_t *userdata = &settings->userdata;
    struct ether_header *eptr;
    u_char *packet;
    client_t *client = NULL;

    eptr = (struct ether_header *) buff;

    if(ntohs(eptr->ether_type) == ETHERTYPE_IP) {
        packet = (unsigned char *)(buff + sizeof(struct ether_header));
        struct iphdr *iph = (struct iphdr *) packet;

        // if source and destination match the monitored netmask
        // this is a inter-routing (cross-interface or explicit routing)
        // and this can be ignored via command line argument (FIXME)
        #if 0
        if((srcip & lmask) == lnet && (dstip & lmask) == lnet) {
            if(!settings->inrouting)
                // skip this packet
                return;
        }
        #endif

        // source is in our local network
        // this is an outgoing packet
        if(addresses_match(userdata->addrs, (uint8_t *) &iph->saddr, 4)) {
            client = client_get_new(&userdata->clients, iph->saddr, eptr->ether_shost);
            client->lifetime.tx += h->len;
            client->traffic.tx += h->len;
            client->activity = time(NULL);
            userdata->runtotal.tx += h->len;
        }

        // destination is in our local network
        // this is an incoming packet
        if(addresses_match(userdata->addrs, (uint8_t *) &iph->daddr, 4)) {
            client = client_get_new(&userdata->clients, iph->daddr, eptr->ether_dhost);
            client->lifetime.rx += h->len;
            client->traffic.rx += h->len;
            client->activity = time(NULL);
            userdata->runtotal.rx += h->len;
        }
    }

    if(ntohs(eptr->ether_type) == ETHERTYPE_IPV6) {
        packet = (unsigned char *)(buff + sizeof(struct ether_header));
        struct ipv6hdr *iph = (struct ipv6hdr *) packet;

        if(addresses_match(userdata->addrs, (uint8_t *) &iph->saddr, 16)) {
            client = client_get_mac(&userdata->clients, eptr->ether_shost);

            // skip if no client found (waiting for ipv4 first)
            if(!client)
                return;

            client->lifetime.tx += h->len;
            client->traffic.tx += h->len;
            client->activity = time(NULL);
            userdata->runtotal.tx += h->len;
        }

        if(addresses_match(userdata->addrs, (uint8_t *) &iph->daddr, 16)) {
            client = client_get_mac(&userdata->clients, eptr->ether_dhost);

            // skip if no client found (waiting for ipv4 first)
            if(!client)
                return;

            client->lifetime.rx += h->len;
            client->traffic.rx += h->len;
            client->activity = time(NULL);
            userdata->runtotal.rx += h->len;
        }
    }
}

addr_t *interface_init(size_t addrlen) {
    addr_t *addr;

    if(!(addr = malloc(sizeof(addr_t))))
        return NULL;

    addr->addrlen = addrlen;

    if(!(addr->addr = calloc(addrlen, 1)))
        diep("malloc");

    if(!(addr->mask = calloc(addrlen, 1)))
        diep("malloc");

    return addr;
}

addrs_t *interface_lookup(char *interface) {
    struct ifaddrs *ifap;
    addrs_t *found = NULL;

    // initializing empty addresses list
    if(!(found = calloc(sizeof(addrs_t), 1)))
        diep("calloc");

    // fetching system information
    getifaddrs(&ifap);

    for(struct ifaddrs *ifa = ifap; ifa; ifa = ifa->ifa_next) {
        addr_t *addr = NULL;

        if(!ifa->ifa_addr)
            continue;

        // keeping only ipv4 or ipv6 interface
        if(ifa->ifa_addr->sa_family != AF_INET6 && ifa->ifa_addr->sa_family != AF_INET)
            continue;

        // skipping non-matching interface name
        if(strcmp(ifa->ifa_name, interface) != 0)
            continue;

        // we are sure it's INET or INET6 tested before
        if(ifa->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *sa;
            addr = interface_init(16); // INET6_ADDRSTRLEN

            sa = (struct sockaddr_in6 *) ifa->ifa_addr;
            memcpy(addr->addr, &sa->sin6_addr, addr->addrlen);

            sa = (struct sockaddr_in6 *) ifa->ifa_netmask;
            memcpy(addr->mask, &sa->sin6_addr, addr->addrlen);
        }

        if(ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *sa;
            addr = interface_init(4); // INET_ADDRSTRLEN

            sa = (struct sockaddr_in *) ifa->ifa_addr;
            memcpy(addr->addr, &sa->sin_addr, addr->addrlen);

            sa = (struct sockaddr_in *) ifa->ifa_netmask;
            memcpy(addr->mask, &sa->sin_addr, addr->addrlen);
        }

        found->length += 1;
        if(!(found->addrs = realloc(found->addrs, sizeof(addr_t *) * found->length)))
            diep("realloc");

        found->addrs[found->length - 1] = addr;
    }

    return found;
}

int lantraffic(lantraffic_t *settings) {
    char errbuff[PCAP_ERRBUF_SIZE];
    userdata_t *userdata = &settings->userdata;
    pcap_t *pd;

    // pre-allocate json buffer
    if(!(jsonbuffer = malloc(sizeof(char) * 4192)))
        diep("malloc");

    // initializing pcap
    if((pd = pcap_open_live(settings->interface, SNAPSHOTLEN, PROMISCMODE, BUFFERTIME, errbuff)) == NULL)
        diepcap("pcap_open_live", errbuff);

    // fetching interfaces data
    printf("[+] reading interface addresses: %s\n", settings->interface);

    userdata->addrs = interface_lookup(settings->interface);
    printf("[+] %lu addresses found\n", userdata->addrs->length);

    // monitoring
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
