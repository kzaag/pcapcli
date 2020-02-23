
#define IP_API "208.95.112.1"
#define IP_API_I 24141776

#ifndef HTTP_H
#define HTTP_H

int ip_api(struct in_addr addr, struct addr_loc * ret);

int get(const char host[], char fmt[], char * ret, int size);

#endif
