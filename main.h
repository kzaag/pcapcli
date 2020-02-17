#ifndef MAIN_H
#define MAIN_H

#include <time.h>
#include <linux/in.h>

#define LLEN 20

typedef unsigned char u_char;

struct addr_loc
{
    char country[LLEN];
    char city[LLEN];
    char org[LLEN];
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
    struct in_addr srcaddr;
    struct in_addr dstaddr;

    u_char proto;    
    union proto_agg protobuff;

    unsigned long count;
    time_t ltime;
    struct addr_loc loc;

};

struct optbuff {

    // interface name
    const char * dev; 
    // interface address
    struct in_addr addr;

    /* bit flags go here */

    // download extra localization data about ip
    unsigned long localization : 1;
    // group by port ( if packet is udp / tcp ... )
    unsigned long portgrp : 1;

};

#endif