#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <string.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include <time.h>
#include "http.h"

#define termgoto(x, y) printf("\033[%d;%dH", (y), (x))

struct ip_agg
{
    struct in_addr addr;
    unsigned long count;
    time_t ltime;
};

#define AGG_LEN 50

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

void agg_draw()
{
    time_t now = time(NULL);
    for (size_t i = 0; i < agg_ix; i++)
    {
        time_t elp = now - agg[i].ltime;
        printf("%45s\r", " ");
        printf("%-20s | %-5lu | %-5li |\n", inet_ntoa(agg[i].addr), agg[i].count, elp);
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
        if (agg_ix >= AGG_LEN - 1)
        {
            printf("buffer overflow\n");
            return;
        }
        //printf("new ip address: %s\n", inet_ntoa(saddr));
        struct ip_agg a;
        a.addr = addr;
        a.count = 1;
        a.ltime = time(NULL);
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

    agg_add(saddr);
    agg_add(daddr);
    agg_sort();

    termgoto(3, 3);
    agg_draw();
}

int main()
{
    
    const char http[] =
"GET /json/24.48.0.1 HTTP/1.1\r\n\
Host: ip-api.com\r\n\
Connection: keep-alive\r\n\
Cache-Control: max-age=0\r\n\
Upgrade-Insecure-Requests: 1\r\n\
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36\r\n\
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n\
Accept-Encoding: gzip, deflate\r\n\
Accept-Language: en,en-US;q=0.9,es;q=0.8\r\n\
\r\n";
    
    get("ip-api.com", http);

    return 0;

    printf("\e[1;1H\e[2J");

    char *dev = pcap_lookupdev(NULL);
    if (dev == NULL)
    {
        fprintf(stderr, "%s", "couldnt lookup device\n");
        return 1;
    }

    printf("%s\n", dev);
    printf("%-20s | %-5s | %-5s |\n", "addr", "qty", "time");

    bpf_u_int32 net;
    bpf_u_int32 mask;
    if (pcap_lookupnet(dev, &net, &mask, NULL) == -1)
    {
        fprintf(stderr, "%s", "Cant get net and mask for device");
        return 101;
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
        fprintf(stderr, "%s", "couldnt pcap activate");
        return 103;
    }

    struct bpf_program compiledExpr;
    if (pcap_compile(handle, &compiledExpr, "", 0, net) == -1)
    {
        fprintf(stderr, "%s", "Couldnt compile filter");
        return 3;
    }

    if (pcap_setfilter(handle, &compiledExpr) == -1)
    {
        fprintf(stderr, "%s", "couldnt set filter");
        return 4;
    }

    int loopret = pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);

    return 0;
}
