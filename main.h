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

struct ip_agg
{
    struct in_addr addr;
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
    unsigned long localization : 1;

};

#endif