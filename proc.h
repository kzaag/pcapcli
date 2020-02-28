#ifndef PROC_H
#define PROC_H

#define PRG_WIDTH 30

struct prg_cache {
    unsigned long inode;
    unsigned short pid;
    char name[PRG_WIDTH];
    struct net_cache * netp;
    // this could be hash table but since premature optimization is source of all troubles
    // im putting it as todo
    //struct prg_port_cache * next;
};

void proc_reset();
void proc_load();
struct prg_cache * proc_get(unsigned short port);

#endif
