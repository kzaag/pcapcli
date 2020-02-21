NAME
    pcapcli

SYNOPSIS
    pcapcli -?
    pcapcli [OPTIONS]

DESCRIPTION
    
    generating simple analitic cube ( number, last time, total size transfered ) of ip packets

    -l    add localization
    -i    group results by ip
    -e    group results by srcip - dstip pairs ( this will override -i option )
    -p    group by ip.protocol
    -u    group by [tcp|udp].port
    -f    force execution and suppress any warnings / errors

    returned columns:

    ADDR
        ip address / pair
    COUNT 
        number of packets passed since begin
    SIZE
        total size of packets passed since begin
    LTIME
        last time of detecting packet in seconds.
    PROTO
        underlying ip protocol ( like tcp )
    PROTOB
        additional proto data ( like port )

    data is ordered by LTIME, SIZE;

    maximum number of rows is specified during compilalation by AGG_LEN
    if more than AGG_LEN rows is encountered last row will be removed and new one will be added.

EXAMPLES

    ./pcapcli -il
        group by ip address of packets passing through network interface
        both with ip geololocalization data
    ./pcapcli -iep
    ./pcapcli -ep
        group by ip address pairs of ip packets and underlying protocols
    ./pcapcli -pu 
        group by protocol and port pairs ( if tcp | udp packet ) 
