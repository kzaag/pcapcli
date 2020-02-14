
#include <arpa/inet.h>
#include "main.h"
#include "tabl.h"

// print packet header - basic info
//
void hprint()
{
    printf("%-20s\x20%-5s\x20%-5s",
           "addr", "qty", "time");
}

void lprint()
{
    printf(
        "\x20%-20s\x20%-20s\x20%-20s",
        "city", "country", "org");
}

void printall(struct opt_t *opts)
{
    hprint();

    if (opts->local)
    {
        lprint();
    }

    printf("\n");
}

void hprintb(const struct ip_agg *agg, const time_t rel)
{
    time_t elp = rel - agg->ltime;
    printf("%-20s\x20%-5lu\x20%-5li",
           inet_ntoa(agg->addr),
           agg->count,
           elp);
}

void lprintb(const struct addr_loc *loc)
{
    printf("\x20%-20s\x20%-20s\x20%-20s",
           loc->city,
           loc->country,
           loc->org);
}

// clean row before rewriting it
void updateb(const struct opt_t *opts)
{
    printf("%s32", " ");
    if (opts->local)
    {
        printf("%s43", " ");
    }
    printf("\r");
}

void printallb(
    const struct ip_agg *agg,
    const struct opt_t *opts,
    const time_t rel)
{
    hprintb(agg, rel);

    if (opts->local)
    {
        lprintb((struct addr_loc *)&agg->loc);
    }

    printf("\n");
}
