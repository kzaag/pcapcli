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
#include <getopt.h>
#include <stdlib.h>

#include "main.h"
#include "http.h"

struct optbuff opt;

#define AGG_LEN 20
struct ip_agg agg_buff[AGG_LEN];
size_t agg_ix = 0;

static char err[PCAP_ERRBUF_SIZE];

// insertion sort agg
// agg sizes are relatively small ( defaults to AGG_LEN ) so insert-sort should be enough
void 
agg_sort()
{
    for (size_t i = 1; i < agg_ix; i++)
    {
        struct ip_agg key = agg_buff[i];
        int j = i - 1;
        while (j >= 0 && agg_buff[j].ltime < key.ltime)
        {
            agg_buff[j + 1] = agg_buff[j];
            j--;
        }
        agg_buff[j + 1] = key;
    }
}

void 
agg_sort_2()
{
    for (size_t i = 1; i < agg_ix; i++)
    {
        struct ip_agg key = agg_buff[i];
        int j = i - 1;
        while (j >= 0 && agg_buff[j].ltime == key.ltime && agg_buff[j].count < key.count)
        {
            agg_buff[j + 1] = agg_buff[j];
            j--;
        }
        agg_buff[j + 1] = key;
    }
}

int 
getaddrw() 
{

    int addrw = 6;

    if((opt.grp & ip_ext) != 0) {

        // {ip} -> {ip}
        //  15   4  15  = 34 chars
        addrw = 34;

    } else if((opt.grp & ip) != 0) {

        // 000.000.000.000 
        //  3 1 3 1 3 1 3  = 15 chars
        addrw = 15; 

    }

    return addrw;
    
}

int 
getprotow() 
{
    int protow = 6;

    // 00000 -> 00000 
    //   5    4    5 
    if((opt.grp & tu_port) != 0) {
        protow = 14;
    }

    return protow;

}

char* 
readable_size(double size, int blen, char *buf) {
    int i = 0;
    const char* units[] = {"B", "K", "M", "G", "T", "P", "E", "Z", "Y"};
    while (size > 1024) {
        size /= 1024;
        i++;
    }
    snprintf(buf, blen, "%.*f%s", i, size, units[i]);
    return buf;
}

void 
hdr_to_str()
{
    int addrw = getaddrw();
    int protow = getprotow();

    printf("\033[47;30m");

    printf("%*.*s %6.6s %8.8s %5.5s %5.5s %*.*s",
            addrw, addrw, "ADDR", 
                  "COUNT",
                        "SIZE", 
                               "LTIME", 
                                     "PROTO",
                                          protow, protow, "PROTOB");

    if(opt.localization) {

        printf(" %*.*s %*.*s %*.*s",
                 LLEN, LLEN, "COUNTRY",
                       LLEN, LLEN, "CITY",
                             ISPLEN, ISPLEN, "ISP");

    }

    printf("\033[0m");
    printf("\n");
}

#define PBLEN 30
char pbuff[PBLEN];

void 
agg_to_str(struct ip_agg * agg, const time_t rel) 
{
    int sp = 0;

    if(opt.grp & ip_ext) {
        
        if(IP_API_I == agg->srcaddr.s_addr || IP_API_I == agg->dstaddr.s_addr) {
        
            printf("\033[44m");
            sp = 1;
        
        }

    } else if(opt.grp & ip) {

        if(opt.addr.s_addr == agg->srcaddr.s_addr) {
            
            printf("\033[41m");
            sp = 1;

        } else if(IP_API_I == agg->srcaddr.s_addr) {
        
            printf("\033[44m");
            sp = 1;
        
        }

    }

    if(opt.grp & ip) {
        
        printf("%15.15s", inet_ntoa(agg->srcaddr));
        
        if(opt.grp & ip_ext) {

            printf(" -> %15.15s", inet_ntoa(agg->dstaddr));

        }

    } else {
        printf("%6.6s", " ");
    }

    printf(" ");

    snprintf(pbuff, 6, "%lu", agg->count);
    printf("%6.6s ", pbuff);

    readable_size(agg->size, 8, pbuff);
    printf("%8.8s ", pbuff);

    time_t elp = rel - agg->ltime;
    snprintf(pbuff, 5, "%li", elp);
    printf("%5.5s ", pbuff);

    if(opt.grp & proto) {

        if(agg->proto == 6) {

            printf("  tcp");

        } else if(agg->proto == 17) {

            printf("  udp");

        } else {
            
            printf("  %3.3u", agg->proto);

        }
    } else {
        printf("%5.5s", " ");
    }
    
    printf(" ");

    if(opt.grp & tu_port) {

        snprintf(pbuff, 5, "%d", ntohs(agg->protobuff.tcpudp.srcport));
        printf("%5.5s -> ", pbuff);
        snprintf(pbuff, 5, "%d", ntohs(agg->protobuff.tcpudp.dstport));
        printf("%5.5s", pbuff);

    } else {
        printf("%6.6s", " ");
    }

    printf(" ");

    if(opt.localization) {

        printf(" %*.*s %*.*s %*.*s",
                 LLEN, LLEN, agg->loc.country,
                       LLEN, LLEN, agg->loc.city,
                             ISPLEN, ISPLEN, agg->loc.isp);

    }

    if(sp == 1) {
        printf("\033[0m");
    }

    printf("\n");

}

void 
agg_draw()
{

    time_t now = time(NULL);

    for (size_t i = 0; i < agg_ix; i++)
    {
        agg_to_str(&agg_buff[i], now);
    }

}

int 
agg_equals(
    struct ip_agg * src_agg, 
    struct ip_agg * dst_agg) 
{

    if( (opt.grp & ip) && src_agg->srcaddr.s_addr != dst_agg->srcaddr.s_addr) {
        return 0;
    }

    if((opt.grp & ip_ext) && src_agg->dstaddr.s_addr != dst_agg->dstaddr.s_addr) {
        return 0;
    }

    if((opt.grp & proto) && src_agg->proto != dst_agg->proto) {
        return 0;
    }

    if(opt.grp & tu_port) {

        if(src_agg->proto == 6 || src_agg->proto == 17) {

            if(src_agg->protobuff.tcpudp.dstport != dst_agg->protobuff.tcpudp.dstport ||
            src_agg->protobuff.tcpudp.srcport != dst_agg->protobuff.tcpudp.srcport) {
                
                return 0;
            
            }

        }

    }

    return 1;

}

void
set_localization(struct ip_agg * a) 
{
    struct addr_loc loc;

    if(opt.grp & ip_ext) {

        // take address from pair {src, dst} which isnt local 
        // and try to geolocalize it. 
        if(opt.addr.s_addr == a->srcaddr.s_addr) {

            ip_api(a->dstaddr, &loc);
        } else {
            ip_api(a->srcaddr, &loc);
        }

        a->loc = loc;

    } else if(opt.grp & ip) {

        ip_api(a->srcaddr, &loc);
        a->loc = loc;

    } 
}

struct ip_agg 
agg_creat(
    struct in_addr src, 
    struct in_addr dst, 
    u_char iproto, 
    void *hdr,
    long size) 
{
    
    struct ip_agg a;
    a.srcaddr = src;
    a.dstaddr = dst;
    a.count = 1;
    a.proto = iproto;
    a.ltime = time(NULL);
    a.size = size;

    if(hdr != NULL) {

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

    return a;
}

void agg_add(struct ip_agg * a)
{
    for (size_t i = 0; i < agg_ix; i++)
    {

        if(agg_equals(agg_buff + i, a)) {
            
            (agg_buff[i].count)++;
            (agg_buff[i].ltime) = time(NULL);
            (agg_buff[i].size) += a->size;
            
            return;

        }

    }

    if (agg_ix == AGG_LEN - 1)
        agg_ix--;
    
    set_localization(a);

    agg_buff[agg_ix++] = *a;

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

    u_char iproto = ip->protocol;

    if(iproto == 6) {

        struct tcphdr * tcp;
        if((tcp = pckt_tcp(packet, caplen, iptl, args)) == NULL) {
            return;
        }

        struct ip_agg a = agg_creat(srcip, destip, iproto, tcp, header->len);
        agg_add(&a);

    } else if(iproto == 17) {

        struct udphdr * udp;
        if((udp = pckt_udp(packet, caplen, iptl, args)) == NULL) {
            return;
        }

        struct ip_agg a = agg_creat(srcip, destip, iproto, udp, header->len);
        agg_add(&a);

    } else {

        struct ip_agg a = agg_creat(srcip, destip, iproto, NULL, header->len);
        agg_add(&a);

    }

    agg_sort();
    agg_sort_2();

    tgotoxy(0, 0);
    
    hdr_to_str();

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
    opt.grp = 0;

    int o;

    u_char force = 0;

    while ((o = getopt(argc, argv, "?liepuf")) != -1)
    {
        switch (o)
        {
        case 'l':
            opt.localization = 1;
            break;
        case 'i':
            opt.grp |= ip;
            break;
        case 'e':
            opt.grp |= (ip | ip_ext);
        case 'p':
            opt.grp |= (proto);
            break;
        case 'u':
            opt.grp |= tu_port;
            break;
        case 'f':
            force = 1;
            break;
        case '?':
        default:
            printf("See README.txt for usage\n");
            return 1;
        }
    }

    if(!force) {
        
        if(opt.localization && opt.grp > 1) {
            printf("User specified localization with alot group by options.\nThat could cause a flood of http requests to geolocalization api\nIf you know what you are doing use -f (force) flag\n");
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
