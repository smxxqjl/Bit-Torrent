/*
 * peer.c
 *
 * Authors: Ed Bardsley <ebardsle+441@andrew.cmu.edu>,
 *          Dave Andersen
 * Class: 15-441 (Spring 2005)
 *
 * Skeleton for 15-441 Project 2.
 *
 */

#include <sys/select.h>
#include <assert.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "debug.h"
#include "spiffy.h"
#include "bt_parse.h"
#include "input_buffer.h"

void peer_run(bt_config_t *config);

int main(int argc, char **argv) {
    bt_config_t config;

    bt_init(&config, argc, argv);

    DPRINTF(DEBUG_INIT, "peer.c main beginning\n");

#ifdef TESTING
    config.identity = 1; // your group number here
    strcpy(config.chunk_file, "chunkfile");
    strcpy(config.has_chunk_file, "haschunks");
#endif

    bt_parse_command_line(&config);

#ifdef DEBUG
    if (debug & DEBUG_INIT) {
        bt_dump_config(&config);
    }
#endif

    peer_run(&config);
    return 0;
}


#define WHOHAS 0
#define IHAVE 1
#define GET 2
#define DATA 3
#define ACK 4
#define DENIED 5
#define HASHSTRLEN 41
void strtohex(char *hexstring, char *dststring);
int readhash(char *fname, char **hasharray)
{
    FILE *fp = fopen(fname, "r");
    int i = 0, id;
    char strhash[HASHSTRLEN];
    while (fscanf(fp, "%d %s\n", &id, strhash) != EOF) {
        strtohex(strhash, hasharray[i]);
        i++;
    }
    return i;
}
#define MAXHASHHASNUM 300
void process_inbound_udp(int sock, bt_config_t *config) {
#define BUFLEN 1500
    struct sockaddr_in from;
    socklen_t fromlen;
    char buf[BUFLEN];
    char hashs[MAXHASHHASNUM][HASHSIZE];

    fromlen = sizeof(from);
    spiffy_recvfrom(sock, buf, BUFLEN, 0, (struct sockaddr *) &from, &fromlen);

    char type = *(buf+8);
    FILE *fp = fopen(config->has_chunk_file, "r");

    switch (type) {
        case WHOHAS:
            readhash(config->has_chunk_file, hashs);
            send_IHAVE(sock, &from, &fromlen, hash);
            break;
        default:
            printf("Not implement method type %d\n", type);
    
    printf("PROCESS_INBOUND_UDP SKELETON -- replace!\n"
            "Incoming message from %s:%d\n%s\n\n", 
            inet_ntoa(from.sin_addr),
            ntohs(from.sin_port),
            buf);

}
#define WINDOWSIZE 8
#define HASHSIZE 20
#define WHOHASPAYLOADNUM 20
#define MAXLINE 1024
#define HEADERLEN 16
#define MAXHASHNUM (1500-HEADERLEN)/HASHSIZE

typedef struct header_s {
    uint16_t magicnum;
    char version;
    char packet_type;
    uint16_t header_len;
    uint16_t packet_len;
    uint32_t seq_num;
    uint32_t ack_num;
} header_t;

typedef struct data_packet {
    header_t header;
    char data[BUFLEN];
} data_packet_t;

typedef struct whohas_packet {
    header_t header;
    char hashnum; 
    char pading[3];
    char hash[HASHSIZE*WHOHASPAYLOADNUM];
} whohas_packet_t;

void strtohex(char *hexstring, char *dststring) {
    char *pos;
    pos = hexstring;
    size_t count = 0;

    for (count = 0; count < strlen(hexstring); count++) {
        sscanf(pos, "%2hhx", &dststring[count]);
        pos += 2;
    }
}

void send_all(void *p, ssize_t len, bt_peer_t *plist)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    while (plist != NULL) {
        spiffy_sendto(sockfd, p, len, 0, (struct sockaddr *)&plist->addr, sizeof(plist->addr));
        plist = plist->next;
    }
}

void send_whohas(char *chunkfile, bt_config_t *config) {
#define MAXPEER 128
    assert(sizeof(header_t) == 16);
    whohas_packet_t whohas;
    bzero(&whohas, sizeof(whohas));
    whohas.header.magicnum = htons(15411);
    whohas.header.version = 1;
    whohas.header.packet_type = 0;
    whohas.header.header_len = htons(16);

    FILE *fp = fopen(chunkfile, "r");
    char hash[HASHSIZE*2+1];
    char hashhex[HASHSIZE+1];
    hashhex[HASHSIZE] = 0; 
    int id;

    int readall = 0, packet_len;
    unsigned asknum = 0;
    /* Open all remote peers socket, one way! */

    while(!readall) {
        if (asknum > MAXHASHNUM || (readall = (fscanf(fp, "%d %s", &id, hash) == EOF))) {
            /* Full load for udp or read all , send it now! */
            packet_len = asknum*HASHSIZE+16+4;
            whohas.header.packet_len = htons(packet_len);
            whohas.hashnum = asknum;
            printf("Ask Num %d\n", asknum);
            asknum = 0;
            send_all(&whohas, packet_len, config->peers);
            continue;
        }
        assert(strlen(hash) == HASHSIZE*2);
        strtohex(hash, hashhex);
        assert(strlen(hashhex) == HASHSIZE);
        memcpy(whohas.hash+asknum*HASHSIZE, hashhex, HASHSIZE);
        asknum++;
    }
}

void process_get(char *chunkfile, char *outputfile, bt_config_t *config) {
    send_whohas(chunkfile, config);
    printf("PROCESS GET SKELETON CODE CALLED.  Fill me in!  (%s, %s)\n", 
            chunkfile, outputfile);

}

void handle_user_input(char *line, void *cbdata, bt_config_t *config) {
    char chunkf[128], outf[128];

    bzero(chunkf, sizeof(chunkf));
    bzero(outf, sizeof(outf));

    if (sscanf(line, "GET %120s %120s", chunkf, outf)) {
        if (strlen(outf) > 0) {
            process_get(chunkf, outf, config);
        }
    }
}


void peer_run(bt_config_t *config) {
    int sock;
    struct sockaddr_in myaddr;
    fd_set readfds;
    struct user_iobuf *userbuf;

    if ((userbuf = create_userbuf()) == NULL) {
        perror("peer_run could not allocate userbuf");
        exit(-1);
    }

    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1) {
        perror("peer_run could not create socket");
        exit(-1);
    }

    bzero(&myaddr, sizeof(myaddr));
    myaddr.sin_family = AF_INET;
    myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    myaddr.sin_port = htons(config->myport);

    if (bind(sock, (struct sockaddr *) &myaddr, sizeof(myaddr)) == -1) {
        perror("peer_run could not bind socket");
        exit(-1);
    }

    spiffy_init(config->identity, (struct sockaddr *)&myaddr, sizeof(myaddr));

    while (1) {
        int nfds;
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(sock, &readfds);

        nfds = select(sock+1, &readfds, NULL, NULL, NULL);

        if (nfds > 0) {
            if (FD_ISSET(sock, &readfds)) {
                process_inbound_udp(sock, config);
            }

            if (FD_ISSET(STDIN_FILENO, &readfds)) {
                process_user_input(STDIN_FILENO, userbuf, handle_user_input,
                        "Currently unused", config);
            }
        }
    }
}
