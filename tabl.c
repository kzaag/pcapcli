#include <stdlib.h>
#include <arpa/inet.h>

#include "main.h"

// print packet header - basic info
//
void pp_hdr()
{

    printf("%-20s\x20%-5s\x20%-5s",
           "addr", "qty", "time");
}

// 
void pp_hdrc(const ip_agg *agg, rel time_t)
{
    time_t elp = rel - agg[i].ltime;
    printf("%-20s\x20%-5lu\x20%-5li",
           inet_ntoa(agg->addr),
           agg->count,
           elp);
}