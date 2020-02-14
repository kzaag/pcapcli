#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <string.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>

#include "main.h"
#include "tabl.h"

#define AGG_LEN 20

struct opt_t opts;

void init_opts()
{
    opts.local = 0;
}

struct ip_agg agg[AGG_LEN];
size_t agg_ix = 0;

// insertion sort agg
void agg_sort()
{
    for (size_t i = 1; i < agg_ix; i++)
    {
        struct ip_agg key = agg[i];
        int j = i - 1;
        while (j >= 0 && agg[j].ltime < key.ltime)
        {
            agg[j + 1] = agg[j];
            j--;
        }
        agg[j + 1] = key;
    }
}

void agg_sort_2()
{
    for (size_t i = 1; i < agg_ix; i++)
    {
        struct ip_agg key = agg[i];
        int j = i - 1;
        while (j >= 0 && agg[j].ltime == key.ltime && agg[j].count < key.count)
        {
            agg[j + 1] = agg[j];
            j--;
        }
        agg[j + 1] = key;
    }
}

void agg_draw()
{
    struct opt_t * optr = (struct opt_t*)&opts;

    struct ip_agg * aggptr = NULL;

    time_t now = time(NULL);

    for (size_t i = 0; i < agg_ix; i++)
    {
        updateb(optr);

        aggptr = (struct ip_agg*)&agg[i];

        printallb(aggptr, optr, now);
    }
}

void agg_add(struct in_addr addr)
{
    u_char found = 0;
    for (size_t i = 0; i < agg_ix; i++)
    {
        struct ip_agg a = agg[i];
        if (a.addr.s_addr == addr.s_addr)
        {
            (agg[i].count)++;
            (agg[i].ltime) = time(NULL);
            found = 1;
        }
    }

    if (found == 0)
    {
        if (agg_ix == AGG_LEN - 1)
        {
            agg_ix--;
        }
        //printf("new ip address: %s\n", inet_ntoa(saddr));
        struct ip_agg a;
        a.addr = addr;
        a.count = 1;
        a.ltime = time(NULL);

        if (opts.local)
        {
            struct addr_loc loc;
            loc.city[0] = 0;
            loc.org[0] = 0;
            loc.country[0] = 0;
            loc.region[0] = 0;
            ip_api(addr, &loc);
            a.loc = loc;
        }

        agg[agg_ix++] = a;
    }
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    bpf_u_int32 caplen = header->caplen;
    struct ethhdr *h = (struct ethhdr *)packet;
    struct iphdr *ip;

    if (ntohs(h->h_proto) != ETH_P_IP)
    {
        return;
    }

    if (caplen < (sizeof(struct ethhdr) + sizeof(struct iphdr)))
    {
        return;
    }

    ip = (struct iphdr *)(packet + sizeof(struct ethhdr));

    struct in_addr saddr;
    saddr.s_addr = ip->saddr;
    //printf("%s ", inet_ntoa(s));

    struct in_addr daddr;
    daddr.s_addr = ip->daddr;
    //printf("%s ", inet_ntoa(d));

    gotoxy(0, 0);
    printall((struct opt_t *)&opts);

    agg_add(saddr);
    agg_add(daddr);
    agg_sort();
    agg_sort_2();

    agg_draw();
}

int main(int argc, char *argv[])
{
    init_opts();
    int o;

    while ((o = getopt(argc, argv, "l")) != -1)
    {
        switch (o)
        {
        case 'l':
            opts.local = 1;
            break;
        default:
            printf("Usage: %s [-l] locations\n", argv[0]);
            exit(1);
        }
    }

    char *dev = pcap_lookupdev(NULL);
    if (dev == NULL)
    {
        fprintf(stderr, "%s", "couldnt lookup device\n");
        return 1;
    }

    char errbuff[PCAP_ERRBUF_SIZE];
    //pcap_t * handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuff);
    pcap_t *handle = pcap_create(dev, errbuff);
    if (handle == NULL)
    {
        fprintf(stderr, "Cant open device. reason: %s", errbuff);
        return 2;
    }

    if (pcap_set_snaplen(handle, 34) != 0)
    {
        fprintf(stderr, "%s", "couldnt set snaplen\n");
        return 102;
    }

    if (pcap_activate(handle) != 0)
    {
        fprintf(stderr, "%s", "couldnt activate handle\n");
        return 103;
    }

    bpf_u_int32 net;
    bpf_u_int32 mask;
    if (pcap_lookupnet(dev, &net, &mask, NULL) == -1)
    {
        fprintf(stderr, "%s", "Cant get net and mask for device");
        return 101;
    }

    struct bpf_program compiledExpr;
    if (pcap_compile(handle, &compiledExpr, "", 0, net) == -1)
    {
        fprintf(stderr, "%s", "Couldnt compile filter\n");
        return 3;
    }

    if (pcap_setfilter(handle, &compiledExpr) == -1)
    {
        fprintf(stderr, "%s", "couldnt set filter");
        return 4;
    }

    update();

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);

    return 0;
}
