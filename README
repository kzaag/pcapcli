NAME
    pcapcli

SYNOPSIS
    pcapcli -?
    pcapcli [OPTIONS] [-q query]

DESCRIPTION
    
    generating simple analitic cube ( number, last time, total size transfered ) of ip packets

    -l    add localization ( row with blue background represents geolocalization api call which by itself is captured traffic )
    -i    group results by source ip address
    -e    group results by des ip address
          if both -i and -e flags are specified results will be grouped by srcip-dstip pairs
    -p    group by ip.protocol
    -s    group by source tcp/udp port
    -d    group by target tcp/udp port
    -r    switch meaning of source/dst port/ip from packet meaning (sender/receiver) to network meaning (src=local address, dst=remote)
    -n    add process identification
    -f    force execution and suppress any warnings / errors

    -q    pcap filter query

    -0    same as -edrpl

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
    if more than AGG_LEN rows is encountered last row will be removed and new one will be added to prevent buffer overflow.

EXAMPLES

    ./pcapcli -erlf
        -e get destination ip for packages
        -r by destination ip mean only remote server ip
        -l use geolocalization of ip addresses
        -f suppress warnings / errors
    ./pcapcli -0
        -e get destination ip for packages
        -d get destination port for packages
        -r by destination ip/port mean only remote server ip/port
        -l use geolocalization of ip addresses
        -p get protocol
    ./pcapcli -esrln
        -e get destination ip for packages
        -s get source port
        -r by destination ip mean only remote server and by source port mean local port
        -l use geolocalization of ip addresses
        -n find process listening on local port
