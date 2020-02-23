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

#include "main.h"
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
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);
    addr.sin_addr = *((struct in_addr *) h->h_addr_list[0]);
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
        goto retErr;
    }

    char * sstart = strchr(start + strlen(key), '"');
    if(sstart == NULL) {
        goto retErr;
    }

    sstart++;

    char * send = strchr(sstart, '"');

    int i = 0;

    while(sstart < send && i < bsize) {
        buff[i++] = *sstart;
        sstart++;
    }

    buff[bsize-1] = 0;

    free(key);
    return 0;

retErr:
    free(key);
    return 1;

}

int ip_api(struct in_addr addr, struct addr_loc * ret) {

    if(ret == NULL) {
        return 1;
    }

    const char fmt[] = "GET /json/%s HTTP/1.1\r\nHost: ip-api.com\r\n\r\n";
    char * addrstr = inet_ntoa(addr);
    char * http = malloc(strlen(fmt) + strlen(addrstr) + 1);
    sprintf(http, fmt, inet_ntoa(addr));

    char response[RET_SIZE];

    if(get(IP_API, http, response, RET_SIZE) != 0) {
        free(http);
        return 1;
    }

    char buff[ISPLEN];

    bzero(ret, sizeof(struct addr_loc));

    bzero(buff, LLEN);
    jsonkey(response, "country", buff, LLEN);
    strcpy(ret->country, buff);
 
    bzero(buff, LLEN);
    jsonkey(response, "city", buff, LLEN);
    strcpy(ret->city, buff);

    bzero(buff, ISPLEN);
    jsonkey(response, "isp", buff, ISPLEN);
    strcpy(ret->isp, buff);

    free(http);

    return 0;
}
