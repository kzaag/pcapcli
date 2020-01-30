int get(const char host[], char fmt[], char * ret, int size);

#define LLEN 20

struct addr_loc
{
    char country[LLEN];
    char city[LLEN];
    char region[LLEN];
    char org[LLEN];
    char isp[LLEN];
};

int ip_api(struct in_addr addr, struct addr_loc * ret);