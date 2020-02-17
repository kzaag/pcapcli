#ifndef TABL_H
#define TABL_H

#include "main.h"
#include <stdio.h>
#include <time.h>

#define tclean() printf("\033[H\033[J")

#define tgotoxy(x, y) printf("\033[%d;%dH", x, y)

#define tsetnowrap() printf("\033[?7l")
#define tsetwrap printf("\033[?7h")

void tprinth();

void tprintl();

void tprintall(struct optbuff * opt);

void tprinthb(const struct ip_agg *agg, const time_t rel, struct optbuff * opt);

void tprintlb(const struct addr_loc *loc);

void tupdateb(struct optbuff * opt);

void tprintallb(const struct ip_agg *agg, const time_t rel, struct optbuff * opt);

#endif