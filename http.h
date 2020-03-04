
#define IP_API "208.95.112.1"
#define IP_API_I 24141776

#ifndef HTTP_H
#define HTTP_H

// location fields lengths
#define LLEN   15
#define ISPLEN 40

struct addr_loc
{
    char country[LLEN];
    char city[LLEN];
    char isp[ISPLEN];
};

struct addr_loc_c {
    struct in_addr addr;
    struct addr_loc loc;
};

int ip_api(struct in_addr addr, struct addr_loc * ret);

struct addr_loc * geolocalize(struct in_addr addr);

int get(const char host[], char fmt[], char * ret, int size);

#endif
