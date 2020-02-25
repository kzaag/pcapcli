/*

get process by port
reading processes is based on netstat source code

*/

#include <dirent.h>
#include <ctype.h>
#include "main.h"

#define PROC "/proc"

#define NAMEL 20

struct proc_info {
    unsigned short listen_port;
    int address;
    int pid;
    char name[NAMEL];
};

inline int isproc(const char *p) {
        
    while(p != 0) {
        if(!isdigit(p)) {
            return 0;
        }
        p++;
    }

    if(*p) {
        return 0;
    }

    return 1;

}

int fill_cache() {
    
    DIR * d = NULL;
    struct dirent * p = NULL;
    const char *tmpc;
    int procfdlen;

    if((d = opendir(PROC)) == NULL) {
        return 1;
    }

    while(p = readdir(d)) {
        
        tmpc = p->d_name;
        
        if(!isproc(tmpc)) {
            continue;
        }

        // interesting lines : 396 1098 190 <- netstat.c

        // open fd subdir

        // ... get inode

        // open /proc/net/tcp. find inodes matching inode found in fd part.

        // thats it - youve got inode, pid, name, local address, remote address. 

        // call it once - to fill cache.
        // if request appears with local port which is unspecified - then try to refill cache. ( new process )
        // if that wont work then maybe someone is probing?

    }

}
