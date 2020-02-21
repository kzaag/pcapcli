[ ] more parsing for tcp -> syn / ack floding detection
[*] more human cli params
[ ] colors for special rows ( such as local )
[ ] colors for internal requests ( ip_api )
[ ] remove ip_api dns call -> move to direct ip request
[ ] make it 2 threads -> one which refreshes io and 2nd which refreshes buffer. 
    do not refresh io each request because performance hurts.
[ ] add proper entry to linux man and properly handle -? option
[ ] dont display columns if group by is not specified
