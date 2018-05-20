#ifndef LANTRAFFIC_H
    #define LANTRAFFIC_H

    #define SNAPSHOTLEN    1514
    #define PROMISCMODE    0
    #define BUFFERTIME     100

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

        time_t dumptime;

        run_t lifetime;
        run_t runtotal;

        clients_t clients;

    } userdata_t;
#endif

