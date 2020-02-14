#ifndef MAIN_H
#define MAIN_H

#include <time.h>
#include <linux/in.h>

int get(const char host[], char fmt[], char * ret, int size);

#define LLEN 20

struct addr_loc
{
    char country[LLEN];
    char city[LLEN];
    char region[LLEN];
    char org[LLEN];
    char isp[LLEN];
};

int ip_api(struct in_addr addr, struct addr_loc * ret);

struct ip_agg
{
    struct in_addr addr;
    unsigned long count;
    time_t ltime;
    struct addr_loc loc;
};

struct opt_t
{
    u_char local;
};

#endif