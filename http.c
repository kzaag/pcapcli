#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <netdb.h>
#include <errno.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include "http.h"

#define ERR 1
#define RET_SIZE 1024


int get(const char host[], char fmt[], char * ret, int size) {
    int tcp = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp <= 0) {
        printf("%s\n", strerror(errno));
        return ERR;
    }

    struct hostent *h;
    h = gethostbyname(host);

    struct sockaddr_in addr;
    //memset(&addr,0,sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);
    addr.sin_addr = *((struct in_addr *) h->h_addr);
    bzero(&(addr.sin_zero), 8);
    
    if (connect(tcp, (struct sockaddr *)&addr, sizeof(struct sockaddr)) == -1) {
        printf("%s\n", strerror(errno));
        return ERR;
    }

    write(tcp, fmt, strlen(fmt));
    
    shutdown(tcp, SHUT_WR);

    int total = size - 1;

    int r = read(tcp, ret, total);
    if(r == -1) {
        printf("%s\n", strerror(errno));
        return ERR;
    }

    ret[r] = 0;

    shutdown(tcp, SHUT_RDWR);
    close(tcp);

    return 0;
}

int jsonkey(const char * haystack, const char * needle, char * buff, int bsize) {
    const char * ktempl = "\"%s\":";
    char * key = malloc(strlen(ktempl) + strlen(needle) + 1);
    sprintf(key, ktempl, needle);
    char * start = strstr(haystack, key);
    if(start == NULL) {
        return ERR;
    }

    char * sstart = strchr(start + strlen(key), '"');
    if(sstart == NULL) {
        return ERR;
    }

    sstart++;

    char * send = strchr(sstart, '"');

    size_t rlen = send - sstart;

    int i = 0;
    // no need if last character is set to \0
    bzero(buff, bsize);
    while(sstart < send && i < bsize - 1) {
        buff[i++] = *sstart;
        sstart++;
    }
    //buff[i] = 0;

    return 0;
}

// remember to free returned buff
char * mjsonkey(const char * haystack, const char * needle) {
    const char * ktempl = "\"%s\":";
    char * key = malloc(strlen(ktempl) + strlen(needle) + 1);
    sprintf(key, ktempl, needle);
    char * start = strstr(haystack, key);
    if(start == NULL) {
        return NULL;
    }

    char * sstart = strchr(start + strlen(key), '"');
    if(sstart == NULL) {
        return NULL;
    }

    sstart++;

    char * send = strchr(sstart, '"');

    size_t rlen = send - sstart;

    char * ret = malloc(rlen + 1);

    int i = 0;
    while(sstart <= send) {
        ret[i++] = *sstart;
        sstart++;
    }
    ret[rlen] = 0;

    return ret;
}

#define GEO_DOMAIN ""
#define IPAPI_DOMAIN "ip-api.com"

int ip_api(struct in_addr addr, struct addr_loc * ret) {

    if(ret == NULL) {
        return ERR;
    }

    const char fmt[] = "GET /json/%s HTTP/1.1\r\nHost: ip-api.com\r\n\r\n";
    char * addrstr = inet_ntoa(addr);
    char * http = malloc(strlen(fmt) + strlen(addrstr) + 1);
    sprintf(http, fmt, inet_ntoa(addr));

    char response[RET_SIZE];

    if(get(IPAPI_DOMAIN, http, response, RET_SIZE) != 0) {
        return ERR;
    }

    char buff[LLEN];

    bzero(ret, sizeof(struct addr_loc));

    if (jsonkey(response, "country", buff, LLEN) == 0) {
        strcpy(ret->country, buff);
    }
 
    if (jsonkey(response, "city", buff, LLEN) == 0) {
        strcpy(ret->city, buff);
    }

    if (jsonkey(response, "regionName", buff, LLEN) == 0) {
        strcpy(ret->region, buff);
    }

    if (jsonkey(response, "org", buff, LLEN) == 0) {
        strcpy(ret->org, buff);
    }

    if (jsonkey(response, "isp", buff, LLEN) == 0) {
        strcpy(ret->isp, buff);
    }

    free(http);

    return 0;
}
