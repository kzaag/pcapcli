#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <string.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
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

    //struct ip_agg * aggptr = NULL;

    time_t now = time(NULL);

    for (size_t i = 0; i < agg_ix; i++)
    {
        tupdateb(&opt);

        //aggptr = (struct u_ip_agg*)&agg[i];

        tprintallb(&agg[i], now, &opt);
    }
}

int agg_equal(
    struct ip_agg * agg, 
    struct in_addr src, 
    struct in_addr dst, 
    u_char iproto, 
    void *hdr) 
{
    struct ip_agg a = *agg; 
    if(a.count == -1) {
        exit(0);
    }
    if( (src.s_addr != agg->srcaddr.s_addr) || (dst.s_addr != agg->dstaddr.s_addr) || (agg->proto != iproto)) {
        return 0;
    }

    // at this point both addesses and proto must be equal

    if(opt.portgrp && hdr != NULL) {
        
        if(iproto == 6){

            struct tcphdr * tcph = (struct tcphdr *)hdr;

            if(tcph->dest != agg->protobuff.tcpudp.dstport || tcph->source != agg->protobuff.tcpudp.srcport) {
                return 0;
            }

        } else if(iproto == 17) {

            struct udphdr * udph = (struct udphdr *)hdr;

            if(udph->dest != agg->protobuff.tcpudp.dstport || udph->source != agg->protobuff.tcpudp.srcport) {
                return 0;
            }

        }
    }


    return 1;
}

void agg_creat(
    struct in_addr src, 
    struct in_addr dst, 
    u_char iproto, 
    void *hdr) 
{
    if (agg_ix == AGG_LEN - 1)
        agg_ix--;
    
    struct ip_agg a;
    a.srcaddr = src;
    a.dstaddr = dst;
    a.count = 1;
    a.proto = iproto;
    a.ltime = time(NULL);

    if(opt.portgrp && hdr != NULL) {

        if(iproto == 6){

            struct tcphdr * tcph = (struct tcphdr *)hdr;
            a.protobuff.tcpudp.dstport = tcph->dest;
            a.protobuff.tcpudp.srcport = tcph->source;

        } else if(iproto == 17) {

            struct udphdr * udp = (struct udphdr *)hdr;
            a.protobuff.tcpudp.dstport = udp->dest;
            a.protobuff.tcpudp.srcport = udp->source;

        }

    }


    if (opt.localization)
    {
        struct addr_loc loc;

        // take address from pair {src, dst} which isnt local 
        // and try to geolocalize it. 
        if(opt.addr.s_addr == src.s_addr) {
            ip_api(dst, &loc);
        } else {
            ip_api(src, &loc);
        }
        a.loc = loc;
    }

    agg[agg_ix++] = a;
}

void agg_add(struct in_addr src, struct in_addr dst, u_char iproto, void * hdr)
{
    for (size_t i = 0; i < agg_ix; i++)
    {

        if(agg_equal(agg + i, src, dst, iproto, hdr)) {
            
            (agg[i].count)++;
            (agg[i].ltime) = time(NULL);
            
            return;

        }

    }

    agg_creat(src, dst, iproto, hdr);
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

struct tcphdr * pckt_tcp(const u_char *packet, bpf_u_int32 packetlen, bpf_u_int32 offset, u_char *args) 
{
    if(packetlen < (sizeof(struct tcphdr) + offset)) {
        return NULL;
    }

    struct tcphdr *tcp;

    tcp = (struct tcphdr *)(packet + offset);

    return tcp;
}

struct udphdr * pckt_udp(const u_char *packet, bpf_u_int32 packetlen, bpf_u_int32 offset, u_char *args) 
{
    if(packetlen < (sizeof(struct udphdr) + offset)) {
        return NULL;
    }

    struct udphdr * udp;

    udp = (struct udphdr *)(packet + offset);

    return udp;
}

void pckt_next(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    bpf_u_int32 caplen = header->caplen;
    
    struct iphdr * ip;

    if((ip = pckt_ip(packet, caplen, args)) == NULL)
        return;

    if(ip->version != 4) {
        // ignoring ipv6 for now
        return;  
    } 

    int iptl = (sizeof(struct iphdr) + sizeof(struct ethhdr));
    if(ip->ihl > 5) {
        iptl += 4*(ip->ihl - 5);
    }

    struct in_addr srcip, destip;

    srcip.s_addr = ip->saddr;
    destip.s_addr = ip->daddr;

    // if localization is enabled gotta blacklist localization ip ; otherwise lots of spam is gonna happen.
    if(opt.localization) {
        in_addr_t ignoreip = 24141776;//3495915521;
        if(srcip.s_addr == ignoreip || destip.s_addr == ignoreip) {
            return;
        }
    }

    u_char iproto = ip->protocol;

    if(iproto == 6) {

        struct tcphdr * tcp;
        if((tcp = pckt_tcp(packet, caplen, iptl, args)) == NULL) {
            return;
        }

        agg_add(srcip, destip, iproto, tcp);

    } else if(iproto == 17) {

        struct udphdr * udp;
        if((udp = pckt_udp(packet, caplen, iptl, args)) == NULL) {
            return;
        }

        agg_add(srcip, destip, iproto, udp);

    } else {

        agg_add(srcip, destip, iproto, NULL);

    }

    agg_sort();
    agg_sort_2();

    tgotoxy(0, 0);
    tprintall(&opt);

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
    opt.portgrp = 0;

    int o;

    while ((o = getopt(argc, argv, "lp")) != -1)
    {
        switch (o)
        {
        case 'l':
            opt.localization = 1;
            break;
        case 'p':
            opt.portgrp = 1;
            break;
        default:
            printf("Usage: %s [-l] with localization [-p] with port grouping\n", argv[0]);
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

    if (pcap_set_snaplen(handle, 
        sizeof(struct ethhdr) // eth
        +sizeof(struct iphdr)+40 // ip
        +sizeof(struct tcphdr)
        ) != 0)
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

    tclean();
    tsetnowrap();

    pcap_loop(handle, -1, pckt_next, NULL);

    pcap_close(handle);

    return 0;
}
