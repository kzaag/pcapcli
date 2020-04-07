/*

get process by port
reading processes is based on netstat source code

*/

#include <dirent.h>
#include <ctype.h>
#include "string.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include "proc.h"

#define PRG_SOCKET_PFX "socket:["
#define PRG_SOCKET_PFXl (strlen(PRG_SOCKET_PFX))
#define PRG_SOCKET_PFX2 "[0000]:"
#define PRG_SOCKET_PFX2l (strlen(PRG_SOCKET_PFX2))
#define PCMD "cmdline"
#define PATH_PROC "/proc"
#define PATH_FD_SUFF "fd"
#define PATH_FD_SUFFl strlen(PATH_FD_SUFF)
#define PATH_NET_TCP PATH_PROC "/net/tcp"
#define PATH_PROC_X_FD PATH_PROC "/%s/" PATH_FD_SUFF
#define PATH_CMDLINE "cmdline"
#define PATH_CMDLINEl strlen(PATH_CMDLINE)
#define BUFF_LEN 4096
#define PRG_CACHE_LEN 300

static struct net_cache {
    unsigned long inode;
    struct in_addr local_addr;
    unsigned short local_port;
    //unsigned short remote_port;
} net_cache[PRG_CACHE_LEN];

int net_cache_ix = 0;
#define HASH_FN(x) ((x) % PRG_CACHE_LEN)

static struct prg_cache prg_cache[PRG_CACHE_LEN];

int prg_cache_ix = 0;

char *safe_strncpy(char *dst, const char *src, size_t size)
{
    dst[size-1] = '\0';
    return strncpy(dst,src,size-1);
}

void net_cache_add(unsigned long inode, struct in_addr local_ip, unsigned short local_port) {
    
    if(net_cache_ix >= PRG_CACHE_LEN) {
        return;
    }

    for(int i = 0; i < net_cache_ix; i++) {
        if(net_cache[i].inode == inode) {
            return;
        }
    }

    net_cache[net_cache_ix].inode = inode;
    net_cache[net_cache_ix].local_addr = local_ip;
    net_cache[net_cache_ix].local_port = ntohs(local_port);

    net_cache_ix++;

}

void prg_cache_add(unsigned long inode, char * name, int pid, struct net_cache * net_ptr) {

    // this could be hash table but since premature optimization is source of all troubles
    // im putting it as todo
    // long hash = HASH_FN(inode);
    struct prg_cache * c;
    // for(c = prg_cache + hash; c; c = c->next);
    
    if(prg_cache_ix >= PRG_CACHE_LEN) {
        return;
    }
 
    int pr_ix = 0;
    
    for(pr_ix = 0; pr_ix < prg_cache_ix; pr_ix++) {
        if(prg_cache[pr_ix].inode == inode) {
            return;
        }
    }

    c = &prg_cache[pr_ix];
    c->pid = pid;
    c->inode = inode;
    c->netp = net_ptr;
    safe_strncpy(c->name, name, PRG_WIDTH);

    prg_cache_ix++;

}

int extract_type_1_socket_inode(const char lname[], unsigned long * inode_p) {

    /* If lname is of the form "socket:[12345]", extract the "12345"
       as *inode_p.  Otherwise, return -1 as *inode_p.
       */

    if (strlen(lname) < PRG_SOCKET_PFXl+3) return(-1);

    if (memcmp(lname, PRG_SOCKET_PFX, PRG_SOCKET_PFXl)) return(-1);
    if (lname[strlen(lname)-1] != ']') return(-1);

    {
        char inode_str[strlen(lname + 1)];  /* e.g. "12345" */
        const int inode_str_len = strlen(lname) - PRG_SOCKET_PFXl - 1;
        char *serr;

        strncpy(inode_str, lname+PRG_SOCKET_PFXl, inode_str_len);
        inode_str[inode_str_len] = '\0';
        *inode_p = strtoul(inode_str, &serr, 0);
        if (!serr || *serr || *inode_p == ~0)
            return(-1);
    }
    return(0);
}

int extract_type_2_socket_inode(const char lname[], unsigned long * inode_p) {

    /* If lname is of the form "[0000]:12345", extract the "12345"
       as *inode_p.  Otherwise, return -1 as *inode_p.
       */

    if (strlen(lname) < PRG_SOCKET_PFX2l+1) return(-1);
    if (memcmp(lname, PRG_SOCKET_PFX2, PRG_SOCKET_PFX2l)) return(-1);

    {
        char *serr;

        *inode_p = strtoul(lname + PRG_SOCKET_PFX2l, &serr, 0);
        if (!serr || *serr || *inode_p == ~0)
            return(-1);
    }
    return(0);
}

// null terminated line pointer
int tcpline_load(char * line) {

    unsigned long rxq, txq, time_len, retr, inode;
    int num, local_port, rem_port, d, state, uid, timer_run, timeout;
    char rem_addr[128], local_addr_s[128];

    struct in_addr local_addr;

#pragma GCC diagnostic ignored "-Wformat"
    num = sscanf(line,
    "%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %lu %*s",
		 &d, local_addr_s, &local_port, rem_addr, &rem_port, &state,
		 &txq, &rxq, &timer_run, &time_len, &retr, &uid, &timeout, &inode);
#pragma GCC diagnostic error "-Wformat"

	sscanf(local_addr_s, "%X", &local_addr.s_addr);

    if(num < 0) {
        return 1;
    }

    net_cache_add(inode, local_addr, local_port);

    return 0;
}

int prg_net_load() {

    char lines[BUFF_LEN];

    int f = open(PATH_NET_TCP, O_RDONLY);
    if(f < 0) {
        return 1;
    }

    int i = 0, lastb = 0;

    int linelen = read(f, lines, BUFF_LEN);
    close(f);

    if(linelen == 0) {
        return 1;
    }

    while(i < linelen) {
        if(lines[i] == '\n') {
            lines[i] = 0;
            // here line always begins at line + lastb and ends at i ( null terminator ) 
            
            // skip first - its header
            if(lastb == 0){
                lastb = i + 1;
                continue;
            }

            if(tcpline_load(lines + lastb) != 0)
                return 1;
            //printf("line: %s\n", lines + lastb);

            lastb = i + 1;
        }
        i++;
    }
    return 0;

}

void prg_cache_load()
{
    char line[4096];
    int procfdlen, fd, cmdllen, lnamelen, pid;
    char lname[30], cmdlbuf[512], finbuf[300];
    unsigned long inode;
    const char *cs, *cmdlp;
    DIR *dirproc = NULL, *dirfd = NULL;
    struct dirent *direproc, *direfd;

    cmdlbuf[sizeof(cmdlbuf) - 1] = '\0';

    if (!(dirproc=opendir(PATH_PROC))) 
        return;

    while ((direproc = readdir(dirproc))) {

        for (cs = direproc->d_name; *cs; cs++)
            if (!isdigit(*cs))
                break;

        if (*cs) {
            continue;
        }
        
        pid = atoi(direproc->d_name);

	    procfdlen = snprintf(line, sizeof(line), PATH_PROC_X_FD, direproc->d_name);
        if (procfdlen <= 0 || procfdlen >= sizeof(line) - 5)
            continue;

        dirfd = opendir(line);
        if (! dirfd) {
            continue;
        }

        line[procfdlen] = '/';
        cmdlp = NULL;

        while ((direfd = readdir(dirfd))) {
            
            if (!isdigit(direfd->d_name[0]))
                continue;

            if (procfdlen + 1 + strlen(direfd->d_name) + 1 > sizeof(line))
                continue;

            memcpy(line + procfdlen - PATH_FD_SUFFl, PATH_FD_SUFF "/", PATH_FD_SUFFl + 1);
            safe_strncpy(line + procfdlen + 1, direfd->d_name, sizeof(line) - procfdlen - 1);
            lnamelen = readlink(line, lname, sizeof(lname) - 1);

            if (lnamelen == -1) {
                continue;
            }

            lname[lnamelen] = '\0';  /*make it a null-terminated string*/

            if (extract_type_1_socket_inode(lname, &inode) < 0)
                if (extract_type_2_socket_inode(lname, &inode) < 0)
                    continue;

            if (!cmdlp) {

                if (procfdlen - PATH_FD_SUFFl + PATH_CMDLINEl >= sizeof(line) - 5)
                    continue;
                    
                safe_strncpy(line + procfdlen - PATH_FD_SUFFl, PATH_CMDLINE, sizeof(line) - procfdlen + PATH_FD_SUFFl);

                fd = open(line, 00);
                if (fd < 0)
                    continue;
                cmdllen = read(fd, cmdlbuf, sizeof(cmdlbuf) - 1);
                if (close(fd))
                    continue;
                if (cmdllen == -1)
                    continue;
                if (cmdllen < sizeof(cmdlbuf) - 1)
                    cmdlbuf[cmdllen]='\0';
                if (cmdlbuf[0] == '/' && (cmdlp = strrchr(cmdlbuf, '/')))
                    cmdlp++;
                else
                    cmdlp = cmdlbuf;
            }

            snprintf(finbuf, sizeof(finbuf), "%s/%s", direproc->d_name, cmdlp);
            
            int netix = -1; 

            for(int i = 0; i < net_cache_ix; i++) {
                if(net_cache[i].inode == inode)
                    netix = i;
            }

            if(netix == -1) {
                continue;
            }

	        prg_cache_add(inode, finbuf, pid, &net_cache[netix]);
        }
        
        closedir(dirfd);
        dirfd = NULL;
    }
    
    if (dirproc)
	    closedir(dirproc);
    if (dirfd)
	    closedir(dirfd);
    
}

void proc_reset() {
    prg_cache_ix = 0;
    net_cache_ix = 0;
}

void proc_load() {
    prg_net_load();
    prg_cache_load();
}

struct prg_cache * proc_get(unsigned short port) {

    for(int i = 0; i < prg_cache_ix; i++) {
        if(prg_cache[i].netp->local_port == port)
            return &prg_cache[i];
    }

    return NULL;
}