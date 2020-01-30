#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>

#define ERR -1

#define RES_SIZE (4096)

int get(const char host[], const char fmt[])
{
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

    char res[RES_SIZE];
    memset(res, 0, sizeof(res));
    int total = RES_SIZE - 1;
    //int rec = 0, tmprec = 0;

    int r = read(tcp, res, total);
    if(r == -1) {
        printf("%s\n", strerror(errno));
        return ERR;
    }

    shutdown(tcp, SHUT_RDWR);
    close(tcp);

    printf("%d\n%s\n",r, res);

    return 0;
}