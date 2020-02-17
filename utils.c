
#include <arpa/inet.h>
#include <string.h>
#include "main.h"
#include "utils.h"

void tprinth()
{
    printf("%-34s %-5s %-5s %-20s",
           "ADDR", 
                 "QTY", 
                      "TIME", 
                           "PROTO");
}

void tprintl()
{
    printf(
        "\x20%-20s\x20%-20s\x20%-20s",
        "CITY", "COUNTRY", "ORG");
}

void tprintall(struct optbuff * opt)
{
    printf("\033[47;30m");

    tprinth();

    if (opt->localization)
    {
        tprintl();
    }

    printf("\033[0m");
    printf("\n");
}

void tprinthb(const struct ip_agg *agg, const time_t rel, struct optbuff * opt)
{
    char * addr;

    char srca2[15];
    bzero(srca2, 15);
    char dsta2[15];
    bzero(dsta2, 15);

    addr = inet_ntoa(agg->srcaddr);

    strncpy(srca2, addr, 14);

    inet_ntoa(agg->dstaddr);

    strncpy(dsta2, addr, 14); 

    time_t elp = rel - agg->ltime;

    if(opt->addr.s_addr == agg->srcaddr.s_addr) {

        printf("\033[35m%-15s\033[0m -> %-15s", srca2, dsta2);

    } else if(opt->addr.s_addr == agg->dstaddr.s_addr) {

        printf("%-15s -> \033[35m%-15s\033[0m", srca2, dsta2);

    } else {

        printf("%-15s -> %-15s", srca2, dsta2);

    }

    printf(" %-5lu %-5li", agg->count, elp);

    char proto[20];
    bzero(proto, 20);

    if(agg->proto >= 0) {
        
        char porti[20];

        char spec[5];

        if(agg->proto == 6) {

            sprintf(spec, "tcp");

        } else if(agg->proto == 17) {

            sprintf(spec, "udp");

        } else {

            sprintf(spec, "%u", agg->proto);

        }

        spec[4] = 0;
        
        if(opt->portgrp && (agg->proto == 6 || agg->proto == 17)) {

            sprintf(porti, "%s %u -> %u", spec, ntohs(agg->protobuff.tcpudp.srcport), ntohs(agg->protobuff.tcpudp.dstport));

        } else {

            sprintf(porti, "%s", spec);

        }


        strncpy(proto, porti, strlen(porti));

    }

    printf(" %-20s", proto);

}

void tprintlb(const struct addr_loc *loc)
{
    printf("\x20%-20s\x20%-20s\x20%-20s",
           loc->city,
           loc->country,
           loc->org);
}

// clean row before rewriting it
void tupdateb(struct optbuff * opt)
{
    printf("%s60", " ");
    if (opt->localization)
    {
        printf("%s43", " ");
    }
    printf("\r");
}

void tprintallb(const struct ip_agg *agg, const time_t rel, struct optbuff * opt)
{
    tprinthb(agg, rel, opt);

    if (opt->localization)
    {
        tprintlb((struct addr_loc *)&(agg->loc));
    }

    printf("\n");
}
