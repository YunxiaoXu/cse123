# PA 3 Simple Router

Name: Yunxiao Xu  
PID: A15906610

## sr_router.c

### `void sr_handlepacket(struct sr_instance*, unint8_t*, unsigned int, char*)`

Each time a packet is received, first check if its ethernet header
- If it is an ARP packet
    - If it is an ARP request
        - If target ip is the ip of the interface
            - reply ARP request
        - Otherwise
            - ignore
    - If it is an ARP reply
        - If target ip is the ip of the interface
            - set ethernet header and forward all queued packets of the source ip
        - Otherwise
            - ignore
- If it is an IP packet
    - If checksum failed
        - ignore
    - If its destination is the router
        - find the router interface correspond to the dst ip
        - If icmp type 8 (echo request)
            - reply with icmp type 0 (echo reply)
        - Otherwise
            - ignore
    - If its destination is other hosts in routing table
        - find the interface and gateway in routing table
        - If ttl == 0
            - reply ICMP time exceeded
        - modify IP header then queued for forwarding
    - Otherwise
        - reply ICMP destination unreachable

## sr_router.c

### `void sr_arpcache_sweepreqs(struct sr_instance*)`

Each time executed, for each arpreq
- If the last ARP request is not received in 1s
    - If 5 ARP requests have been sent
        - reply queued packets in arpreq with ICMP host unreachable
    - send another ARP request to the ip
