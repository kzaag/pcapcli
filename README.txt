NAME
    pcapcli

SYNOPSIS
    pcapcli -?
    pcapcli [OPTIONS] [-q query]

DESCRIPTION
    
    generating simple analitic cube ( number, last time, total size transfered ) of ip packets

    -l    add localization
    -i    group results by source ip address
    -e    group results by des ip address
          if both -i and -e flags are specified results will be grouped by srcip-dstip pairs
    -p    group by ip.protocol
    -s    group by source tcp/udp port
    -d    group by target tcp/udp port
    -n    add process identification
    -f    force execution and suppress any warnings / errors

    -q    pcap filter query

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
    PB
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
    ./pcapcli -psd
        group by protocol and port pairs ( if tcp | udp packet ) 
    ./pcapcli -iepsn
        try to locate process for packets
    ./pcapcli -q tcp dest port 443
        only packages with dst port = 443
