
#include <arpa/inet.h>
#include "main.h"
#include "utils.h"

// print packet header - basic info
//
void tprinth()
{
    printf("%-20s\x20%-5s\x20%-5s",
           "addr", "qty", "time");
}

void tprintl()
{
    printf(
        "\x20%-20s\x20%-20s\x20%-20s",
        "city", "country", "org");
}

void tprintall(struct optbuff * opt)
{
    tprinth();

    if (opt->localization)
    {
        tprintl();
    }

    printf("\n");
}

void tprinthb(const struct ip_agg *agg, const time_t rel)
{
    time_t elp = rel - agg->ltime;
    printf("%-20s\x20%-5lu\x20%-5li",
           inet_ntoa(agg->addr),
           agg->count,
           elp);
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
    printf("%s32", " ");
    if (opt->localization)
    {
        printf("%s43", " ");
    }
    printf("\r");
}

void tprintallb(const struct ip_agg *agg, const time_t rel, struct optbuff * opt)
{
    tprinthb(agg, rel);

    if (opt->localization)
    {
        tprintlb((struct addr_loc *)&agg->loc);
    }

    printf("\n");
}
