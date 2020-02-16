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
#include "utils.h"
#include "http.h"

struct optbuff opt;

#define AGG_LEN 20
struct ip_agg agg[AGG_LEN];
size_t agg_ix = 0;

static char err[PCAP_ERRBUF_SIZE];

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

    struct ip_agg * aggptr = NULL;

    time_t now = time(NULL);

    for (size_t i = 0; i < agg_ix; i++)
    {
        tupdateb(&opt);

        aggptr = (struct ip_agg*)&agg[i];

        tprintallb(aggptr, now, &opt);
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

        if (opt.localization)
        {
            struct addr_loc loc;
            ip_api(addr, &loc);
            a.loc = loc;
        }

        agg[agg_ix++] = a;
    }
}

struct iphdr* pckt_ip(const u_char *packet, bpf_u_int32 len, u_char *args)
{
    struct ethhdr *h = (struct ethhdr *)packet;
    struct iphdr *ip;

    if (ntohs(h->h_proto) != ETH_P_IP)
    {
        return NULL;
    }

    if (len < (sizeof(struct ethhdr) + sizeof(struct iphdr)))
    {
        return NULL;
    }

    ip = (struct iphdr *)(packet + sizeof(struct ethhdr));

    return ip;
}

void pckt_next(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    bpf_u_int32 caplen = header->caplen;
    
    struct iphdr * ip = pckt_ip(packet, caplen, args);

    if(ip == NULL) {
        return;
    }

    struct in_addr saddr;
    saddr.s_addr = ip->saddr;

    struct in_addr daddr;
    daddr.s_addr = ip->daddr;

    tgotoxy(0, 0);
    tprintall(&opt);

    agg_add(saddr);
    agg_add(daddr);
    agg_sort();
    agg_sort_2();

    agg_draw();
}

int device_ip(const char * device, struct in_addr * addr) {
    
    pcap_if_t * devs;
    int ret = 0;
    if((ret = pcap_findalldevs(&devs, err)) != 0)
        return ret;

    for(pcap_if_t *d=devs; d!=NULL; d=d->next) {
        
        if(strcmp(d->name, device)) {
            continue;
        }

        for(pcap_addr_t *a=d->addresses; a!=NULL; a=a->next) {

            if(a->addr->sa_family != AF_INET) {
                continue;
            }

            addr->s_addr = ((struct sockaddr_in*)a->addr)->sin_addr.s_addr;
            return 0;
        
        }
    } 

    return 1;
}

int configure(int argc, char *argv[], char * device) 
{
    opt.localization = 0;

    int o;

    while ((o = getopt(argc, argv, "l")) != -1)
    {
        switch (o)
        {
        case 'l':
            opt.localization = 1;
            break;
        default:
            printf("Usage: %s [-l] with localization\n", argv[0]);
            return 1;
        }
    }

    struct in_addr addr;
    if(device_ip(device, &addr) != 0){
        fprintf(stderr, "%s", "couldnt get ip address\n");
        return 15;
    }

    opt.addr = addr;
    opt.dev = device;

    return 0;
}

int main(int argc, char *argv[])
{
    char *dev = pcap_lookupdev(NULL);
    if (dev == NULL)
    {
        fprintf(stderr, "%s", "couldnt lookup device\n");
        return 1;
    }

    if(configure(argc, argv, dev) != 0) {
        exit(1);
    }

    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    
    if ((handle = pcap_create(dev, errbuff)) == NULL)
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

    // clean screen
    tclean();

    pcap_loop(handle, -1, pckt_next, NULL);

    pcap_close(handle);

    return 0;
}
