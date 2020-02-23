#ifndef MAIN_H
#define MAIN_H

#include <time.h>
#include <linux/in.h>

#define tclean() printf("\033[H\033[J")

#define tgotoxy(x, y) printf("\033[%d;%dH", x, y)

#define tsetnowrap() printf("\033[?7l")
#define tsetwrap printf("\033[?7h")

// location fields lengths
#define LLEN   15
#define ISPLEN 40

typedef unsigned char u_char;

struct addr_loc
{
    char country[LLEN];
    char city[LLEN];
    char isp[ISPLEN];
};

struct tcp_udp_agg {

    unsigned short srcport;
    unsigned short dstport;
};

union proto_agg {
    struct tcp_udp_agg tcpudp;
};

struct ip_agg
{
    // if gropu by ip is diabled then srcaddr will be the only field assigned
    // otherwise both
    struct in_addr srcaddr;
    struct in_addr dstaddr;

    // underlying protocol. its my sad attempt of implementing polymorphism in C
    u_char proto;    
    union proto_agg protobuff;

    struct addr_loc loc;

    unsigned long count;
    unsigned long size;
    time_t ltime;

};

enum grp {
    ip      = 1,
    ip_ext  = 2,
    proto   = 4,
    tu_src_port = 8,
    tu_dst_port = 16
};

struct optbuff {

    // interface name
    const char * dev; 

    // interface address
    struct in_addr addr;

    enum grp grp; 

    // download extra localization data about ip packets
    u_char localization : 1;
};

#endif