#ifndef TABL_H
#define TABL_H

#include "main.h"
#include <stdio.h>
#include <time.h>

#define update() printf("\033[H\033[J")

#define gotoxy(x, y) printf("\033[%d;%dH", x, y)

#define HPRINTL "52"
#define LPRINTL "105"

void hprint();

void lprint();

void printall(struct opt_t *opts);

void hprintb(const struct ip_agg *agg, const time_t rel);

void lprintb(const struct addr_loc * loc) ;

void updateb(const struct opt_t *opts);

void printallb(
    const struct ip_agg *agg,
    const struct opt_t *opts,
    const time_t rel);

#endif