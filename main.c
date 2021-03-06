#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <string.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

#include "proc.h"
#include "main.h"
#include "http.h"
#include "proc.h"

struct optbuff opt;

#define SQLEN 100
char squery[SQLEN];

#define AGG_LEN 40
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
    int addrw = 0;

    // 000.000.000.000 
    //  3 1 3 1 3 1 3  = 15 chars

    // {ip} -> {ip}
    //  15   4  15  = 34 chars

    if(opt.grp & srcaddr) {

        addrw += 15;

    } 
    
    if(opt.grp & dstaddr) {

        if(addrw != 0) {
            
            addrw+=4;

        }

        addrw += 15; 

    }

    return addrw;
    
}

int 
getprotobw() 
{
    int protow = 0;

    // 00000 -> 00000 
    //   5    4    5 
    if(opt.grp & tu_src_port) {

        protow += 5;

    }

    if(opt.grp & tu_dst_port) {

        if(protow != 0) {

            protow += 4;

        }

        protow += 5;

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
    int protobw = getprotobw();

    int protow = 0;
    if(opt.grp & proto) {
        protow = 5;
    }

    printf("\033[47;30m");

    printf("%*.*s %6.6s %8.8s %5.5s %*.*s %*.*s ",
            addrw, addrw, "ADDR", 
                  "COUNT",
                        "SIZE", 
                               "LTIME", 
                                     protow, protow, "PROTO",
                                          protobw, protobw, "PB");

    if(opt.localization) {

        printf(" %*.*s %*.*s %*.*s",
                 LLEN, LLEN, "COUNTRY",
                       LLEN, LLEN, "CITY",
                             ISPLEN, ISPLEN, "ISP");

    }

    if(opt.process) {

        printf(" %*.*s",
                 PRG_WIDTH, PRG_WIDTH, "PID/NAME");

    }

    printf("\033[0m");
    printf("\n");
}

#define PBLEN 30
char pbuff[PBLEN];

int 
agg_set_sp(struct ip_agg * agg) 
{
    int sp = 0;

    if((opt.grp & srcaddr) && (opt.grp & dstaddr)) {
        
        if(IP_API_I == agg->srcaddr.s_addr || IP_API_I == agg->dstaddr.s_addr) {
        
            printf("\033[35m");
            sp = 1;
        
        }

    } else if(opt.grp & (srcaddr | dstaddr)) {

        in_addr_t caddr;

        if(opt.grp & srcaddr) {
            caddr = agg->srcaddr.s_addr;
        } else {
            caddr = agg->dstaddr.s_addr;
        }
        
        // if(opt.addr.s_addr == caddr) {
        //     printf("\033[41m");
        //     sp = 1;
        // } else if(IP_API_I == caddr) {
        //     printf("\033[44m");
        //     sp = 1;
        // }

        if(IP_API_I == caddr) {
            printf("\033[35m");
            sp = 1;
        }
        
    }

    return sp;
}

void 
agg_to_str(struct ip_agg * agg, const time_t rel) 
{
    int sp = agg_set_sp(agg);

    int ipwr = 0;

    if(opt.grp & srcaddr) {
        
        printf("%15.15s", inet_ntoa(agg->srcaddr));
        ipwr += 15;
        
    } 

    if(opt.grp & dstaddr) {

        if(ipwr) {
            printf(" -> ");
        }

        printf("%15.15s", inet_ntoa(agg->dstaddr));
    }
    
    // if(!ipwr) {
    //     printf("%6.6s", " ");
    // }
    
    printf(" ");

    snprintf(pbuff, 7, "%lu", agg->count);
    printf("%6.6s ", pbuff);

    readable_size(agg->size, 8, pbuff);
    printf("%8.8s ", pbuff);

    time_t elp = rel - agg->ltime;
    snprintf(pbuff, 6, "%li", elp);
    printf("%5.5s ", pbuff);

    if(opt.grp & proto) {

        if(agg->proto == 6) {

            printf("  tcp");

        } else if(agg->proto == 17) {

            printf("  udp");

        } else {
            
            printf("  %3.3u", agg->proto);

        }
    } 
    // else {
    //     printf("%5.5s", " ");
    // }
    
    printf(" ");

    int pbwritten = 0;

    if(opt.grp & tu_src_port) {

        snprintf(pbuff, 6, "%d", ntohs(agg->protobuff.tcpudp.srcport));
        printf("%5.5s", pbuff);
        pbwritten+=5;

    }

    if(opt.grp & tu_dst_port) {

        if(pbwritten != 0) {
            printf(" -> ");
        }

        snprintf(pbuff, 6, "%d", ntohs(agg->protobuff.tcpudp.dstport));
        printf("%5.5s", pbuff);
        pbwritten+=5;

    } 
    
    // if(pbwritten == 0) {
    //     printf("%6.6s", " ");
    // }

    printf(" ");

    if(opt.localization && agg->loc != NULL) {

        printf(" %*.*s %*.*s %*.*s",
                 LLEN, LLEN, agg->loc->country,
                       LLEN, LLEN, agg->loc->city,
                             ISPLEN, ISPLEN, agg->loc->isp);

    }

    if(opt.process) {

        if(agg->prgp != NULL) {
            printf(" %*.*s",
                    PRG_WIDTH, PRG_WIDTH, agg->prgp->name);
        } else {
            printf(" %*.*s", PRG_WIDTH, PRG_WIDTH, " ");
        }

    }

    if(sp == 1) {
        printf("\033[0m");
    }

    printf("\n");

}

void 
agg_draw()
{
    int offset = 2;
    time_t now = time(NULL);
    struct winsize s;

    ioctl(STDOUT_FILENO, TIOCGWINSZ, &s);

    for (size_t i = 0; i < agg_ix && i < s.ws_row - offset; i++)
    {
        agg_to_str(&agg_buff[i], now);
    }

}

int 
agg_equals(
    struct ip_agg * src_agg, 
    struct ip_agg * dst_agg) 
{

    if( (opt.grp & srcaddr) && src_agg->srcaddr.s_addr != dst_agg->srcaddr.s_addr) {
        return 0;
    }

    if((opt.grp & dstaddr) && src_agg->dstaddr.s_addr != dst_agg->dstaddr.s_addr) {
        return 0;
    }

    if((opt.grp & proto) && src_agg->proto != dst_agg->proto) {
        return 0;
    }

    if(src_agg->proto == 6 || src_agg->proto == 17) {
    
        if(opt.grp & tu_src_port) {

            if(src_agg->protobuff.tcpudp.srcport != dst_agg->protobuff.tcpudp.srcport) {
                return 0;
            }

        }

        if(opt.grp & tu_dst_port) {

            if(src_agg->protobuff.tcpudp.dstport != dst_agg->protobuff.tcpudp.dstport) {
                return 0;
            }

        }

    }

    return 1;

}

void
set_proc(struct ip_agg * a)
{
    unsigned short port = -1;

    if(opt.grp & tu_src_port) {
        if(a->srcaddr.s_addr == opt.addr.s_addr) {
            port = a->protobuff.tcpudp.srcport;
        }
    }

    if(opt.grp & tu_dst_port) {
        if(a->dstaddr.s_addr == opt.addr.s_addr) {
            port = a->protobuff.tcpudp.dstport;
        }
    }

    if(port == -1) {
        return;
    }

    a->prgp = proc_get(port);

    // possibly very cpu-consuming op.
    // if we didnt find process that means maybe new is listening? so refill cache and try again. 
    if(!a->prgp) {
        proc_reset();
        proc_load();
        a->prgp = proc_get(port);
    }

}

void
set_localization(struct ip_agg * a) 
{
    //struct addr_loc loc;

    if((opt.grp & srcaddr) && (opt.grp & dstaddr)) {
        
        // take address from pair {src, dst} which isnt local 
        // and try to geolocalize it. 
        if(opt.addr.s_addr == a->srcaddr.s_addr) {
            a->loc = geolocalize(a->dstaddr);
            //ip_api(a->dstaddr, &loc);
        } else {
            a->loc = geolocalize(a->srcaddr);
            //ip_api(a->srcaddr, &loc);
        }

        //a->loc = loc;

    } else if(opt.grp & (srcaddr | dstaddr)) {

        if(opt.grp & srcaddr) {
            a->loc = geolocalize(a->srcaddr);
            // ip_api(a->srcaddr, &loc);
            // a->loc = loc;
        } else if(opt.grp & dstaddr) {
            a->loc = geolocalize(a->dstaddr);
            // ip_api(a->dstaddr, &loc);
            // a->loc = loc;
        }

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
    in_addr_t local = opt.addr.s_addr;

    // TODO: simplify this ( like ports below )
    do {

        if(opt.remote) {

            if(src.s_addr == local) {
                a.srcaddr = src;
                a.dstaddr = dst;
                break;
            } else if(dst.s_addr == local) {
                a.dstaddr = src;
                a.srcaddr = dst;
                break;
            }
        }
    
        a.srcaddr = src;
        a.dstaddr = dst;

    } while(0);

    a.count = 1;
    a.proto = iproto;
    a.ltime = time(NULL);
    a.size = size;

    if(hdr != NULL) {

        unsigned short srcp, dstp, tmp;

        if(iproto == 6){

            struct tcphdr * tcph = (struct tcphdr *)hdr;
            dstp = tcph->dest;
            srcp = tcph->source;

        } else if(iproto == 17) {

            struct udphdr * udp = (struct udphdr *)hdr;
            dstp = udp->dest;
            srcp = udp->source;

        }

        if(opt.remote && (dst.s_addr == local)) {
            tmp = srcp;
            srcp = dstp;
            dstp = tmp;
        }

        a.protobuff.tcpudp.srcport = srcp;
        a.protobuff.tcpudp.dstport = dstp;

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
    
    if(opt.localization) {
        set_localization(a);
    }

    if(opt.process) {
        set_proc(a);
    }

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

volatile int i = 0;

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
    opt.process = 0;
    opt.remote = 0;
    opt.grp = 0;
    bzero(squery, SQLEN);
    opt.squery = squery;

    int o;

    u_char force = 0;

    while ((o = getopt(argc, argv, "?liepsdfq:nr0")) != -1)
    {
        switch (o)
        {
        case '0':
            opt.grp |= dstaddr;
            opt.grp |= proto;
            opt.grp |= tu_dst_port;
            opt.localization = 1;
            opt.remote = 1;
            break;
        case 'l':
            opt.localization = 1;
            break;
        case 'i':
            opt.grp |= srcaddr;
            break;
        case 'e':
            opt.grp |= dstaddr;
            break;
        case 'p':
            opt.grp |= proto;
            break;
        case 's':
            opt.grp |= tu_src_port;
            break;
        case 'd':
            opt.grp |= tu_dst_port;
            break;
        case 'f':
            force = 1;
            break;
        case 'q':
            strncpy(squery, optarg, SQLEN);
            break;
        case 'n':
            opt.process = 1;
            break;
        case 'r':
            opt.remote = 1;
            break;
        case '?':
        default:
            printf("See README.txt for usage\n");
            return 1;
        }
    }

    if(!force) {
        
        // after ip caching this chaeck is no longer neccessary
        // if(opt.localization && opt.grp > 1) {
        //     printf("User specified localization with alot group by options.\nThat could cause a flood of http requests to geolocalization api\nIf you know what you are doing use -f (force) flag\n");
        //     return 1;
        // }

        if(opt.process && !( opt.grp & (tu_dst_port | tu_src_port)) ) {
            printf("you try to locate process but you do not group by ports.\nThat means no process can be possibly found.\nProvide -s or -d flag or both to include port info or\nif you know what you are doing use -f (force) flag\n");
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

    proc_load();

    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    
    if ((handle = pcap_create(dev, errbuff)) == NULL)
    {
        fprintf(stderr, "Cant open device. reason: %s", errbuff);
        return 2;
    }

    if (pcap_set_snaplen(handle, 
        sizeof(struct ethhdr)    // eth
        +sizeof(struct iphdr)+40 // ip
        +sizeof(struct tcphdr)   // tcp-hdr ( udp should be included - ports )
        ) != 0)
    {
        fprintf(stderr, "%s", "couldnt set snaplen\n");
        return 102;
    }
    
    pcap_set_immediate_mode(handle, 1);

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
    if (pcap_compile(handle, &compiledExpr, opt.squery, SQLEN, net) == -1)
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
