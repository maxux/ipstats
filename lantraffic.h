#ifndef LANTRAFFIC_H
    #define LANTRAFFIC_H

    #ifndef NOREDIS
        #include <hiredis/hiredis.h>
    #else
        #define redisContext void
    #endif

    #define SNAPSHOTLEN    1514
    #define PROMISCMODE    0
    #define BUFFERTIME     100

    typedef struct run_t {
        uint64_t rx;
        uint64_t tx;

    } run_t;

    typedef struct addr_t {
        size_t addrlen;
        uint8_t *addr;
        uint8_t *mask;

    } addr_t;

    typedef struct addrs_t {
        addr_t **addrs;
        size_t length;

    } addrs_t;

    typedef struct client_t {
        run_t traffic;
        run_t lifetime;
        uint32_t rawip;
        char address[16];
        char *hostname;
        time_t activity;
        uint8_t macaddr[6];

    } client_t;

    typedef struct clients_t {
        client_t *list;
        uint64_t length;

    } clients_t;

    typedef struct userdata_t {
        addrs_t *addrs;
        uint64_t run;

        time_t dumptime;

        run_t lifetime;
        run_t runtotal;

        clients_t clients;

    } userdata_t;

    typedef struct lantraffic_t {
        userdata_t userdata;

        char *interface;
        redisContext *redis;

        char *redishost;
        int redisport;
        char *redisunix;

        int resolv;
        int inrouting;

        char *jsonfile;

    } lantraffic_t;
#endif

