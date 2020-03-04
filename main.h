#ifndef MAIN_H
#define MAIN_H

#include <time.h>
#include <linux/in.h>
#include "proc.h"
#include "http.h"

#define tclean() printf("\033[H\033[J")

#define tgotoxy(x, y) printf("\033[%d;%dH", x, y)

#define tsetnowrap() printf("\033[?7l")
#define tsetwrap printf("\033[?7h")

typedef unsigned char u_char;

struct tcp_udp_agg {

    unsigned short srcport;
    unsigned short dstport;
};

union proto_agg {
    struct tcp_udp_agg tcpudp;
};

struct ip_agg
{
    struct in_addr srcaddr;
    struct in_addr dstaddr;

    u_char proto;    
    union proto_agg protobuff;

    struct addr_loc * loc;
    struct prg_cache * prgp;

    unsigned long count;
    unsigned long size;
    time_t ltime;
};

enum grp {
    srcaddr     = 1,
    dstaddr     = 2,
    proto       = 4,
    tu_src_port = 8,
    tu_dst_port = 16
};

struct optbuff {

    // interface name
    const char * dev; 

    // interface address
    struct in_addr addr;

    char * squery;
    
    // group by options
    enum grp grp; 

    // download extra localization data about ip packets
    u_char localization : 1;
    // try to locate [local] process responsible for packets
    u_char process      : 1;
    // redefine meaning of src/dst ip/port from sender/receiver of packet to local - src/remote -dst
    u_char remote       : 1;
};

#endif