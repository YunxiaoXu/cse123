#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_rt.h"
#include "sr_utils.h"

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    /* Fill this in */
    time_t curtime;

    struct sr_arpreq *req, *next_req;
    for (req = sr->cache.requests; req; req = next_req) {
        next_req = req->next;
        curtime = time(NULL);
        if (difftime(curtime, req->sent) > 1.0) {
            if (req->times_sent >= 5) {
                #if defined IP_DEBUG || defined ARP_DEBUG
                fprintf(stderr, "\nhost %s unreachable\n", inet_ntoa((struct in_addr){req->ip}));
                #endif
                struct sr_packet *pkt, *next_pkt, *reverse = NULL;
                /* reverse the packet list */
                for (pkt = req->packets; pkt; pkt = next_pkt) {
                    next_pkt = pkt->next;
                    pkt->next = reverse;
                    reverse = pkt;
                }
                /* send ICMP host unreachable packets */
                for (pkt = reverse; pkt; pkt = pkt->next) {
                    /* send ICMP host unreachable */
                    uint8_t *buf = (uint8_t *)malloc(
                        sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
                    /* new packet headers */
                    sr_ethernet_hdr_t *eth_hdr = (void *)buf;
                    sr_ip_hdr_t *ip_hdr = (void *)eth_hdr + sizeof(sr_ethernet_hdr_t);
                    sr_icmp_t3_hdr_t *icmp_hdr = (void *)ip_hdr + sizeof(sr_ip_hdr_t);
                    /* queued packet headers */
                    sr_ethernet_hdr_t *pkt_eth_hdr = (void *)pkt->buf;
                    sr_ip_hdr_t *pkt_ip_hdr = (void *)pkt_eth_hdr + sizeof(sr_ethernet_hdr_t);
                    /* set ICMP header */
                    icmp_hdr->icmp_type = 3;
                    icmp_hdr->icmp_code = icmp_host_unreachable;
                    icmp_hdr->icmp_sum = 0;
                    icmp_hdr->unused = 0;
                    icmp_hdr->next_mtu = 0;
                    memcpy(icmp_hdr->data, pkt_ip_hdr, ICMP_DATA_SIZE);
                    icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
                    /* set IP header */
                    ip_hdr->ip_hl = 5;
                    ip_hdr->ip_v = 4;
                    ip_hdr->ip_tos = 0;
                    ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
                    ip_hdr->ip_id = 0;
                    ip_hdr->ip_off = 0;
                    ip_hdr->ip_ttl = 255;
                    ip_hdr->ip_p = ip_protocol_icmp;
                    ip_hdr->ip_sum = 0;
                    /* longest prefix match */
                    struct sr_rt *rt_entry, *longest_prefix_entry = NULL;
                    in_addr_t longest_prefix = 0;
                    for (rt_entry = sr->routing_table; rt_entry; rt_entry = rt_entry->next) {
                        in_addr_t rt_mask = rt_entry->mask.s_addr;
                        in_addr_t rt_dest = rt_entry->dest.s_addr;
                        if ((pkt_ip_hdr->ip_src & rt_mask) == (rt_dest & rt_mask)) {
                            if (rt_mask > longest_prefix || longest_prefix_entry == NULL) {
                                longest_prefix = rt_mask;
                                longest_prefix_entry = rt_entry;
                            }
                        }
                    }
                    if ((rt_entry = longest_prefix_entry)) {
                        #if defined IP_DEBUG || defined ARP_DEBUG
                        fprintf(stderr, "Found route %s (%s)\n", rt_entry->interface,
                            inet_ntoa((struct in_addr){sr_get_interface(sr, rt_entry->interface)->ip})
                        );
                        #endif
                        ip_hdr->ip_dst = ip_hdr->ip_src;
                        ip_hdr->ip_src = sr_get_interface(sr, rt_entry->interface)->ip;
                    } else {
                        #if defined IP_DEBUG || defined ARP_DEBUG
                        fprintf(stderr, "No route found for IP %s", inet_ntoa((struct in_addr){pkt_ip_hdr->ip_src}));
                        #endif
                        free(buf);
                        buf = NULL;
                        continue;
                    }
                    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
                    /* set Ethernet header */
                    memcpy(eth_hdr->ether_dhost, pkt_eth_hdr->ether_shost, ETHER_ADDR_LEN);
                    memcpy(eth_hdr->ether_shost, sr_get_interface(sr, rt_entry->interface)->addr, ETHER_ADDR_LEN);
                    eth_hdr->ether_type = htons(ethertype_ip);
                    /* send packet */
                    sr_send_packet(sr, buf,
                        sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t),
                        rt_entry->interface);
                    #if defined IP_DEBUG || defined ARP_DEBUG
                    fprintf(stderr, "Sent ICMP host unreachable to %s\n", inet_ntoa((struct in_addr){ip_hdr->ip_dst}));
                    #endif
                    free(buf);
                    buf = NULL;
                }
                sr_arpreq_destroy(&sr->cache, req);
                req = NULL;
            } else {
                /* send ARP request to ip */
                uint8_t *buf = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
                /* set ARP header */
                sr_arp_hdr_t *arp_hdr = (void *)buf + sizeof(sr_ethernet_hdr_t);
                arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
                arp_hdr->ar_pro = htons(ethertype_ip);
                arp_hdr->ar_hln = ETHER_ADDR_LEN;
                arp_hdr->ar_pln = 4;
                arp_hdr->ar_op = htons(arp_op_request);
                memcpy(arp_hdr->ar_sha, sr_get_interface(sr, req->packets->iface)->addr, ETHER_ADDR_LEN);
                arp_hdr->ar_sip = sr_get_interface(sr, req->packets->iface)->ip;
                memset(arp_hdr->ar_tha, 0, ETHER_ADDR_LEN);
                arp_hdr->ar_tip = req->ip;
                /* set Ethernet header */
                sr_ethernet_hdr_t *eth_hdr = (void *)buf;
                memset(eth_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
                memcpy(eth_hdr->ether_shost, sr_get_interface(sr, req->packets->iface)->addr, ETHER_ADDR_LEN);
                eth_hdr->ether_type = htons(ethertype_arp);
                /* send packet */
                sr_send_packet(sr, (uint8_t *)buf, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), req->packets->iface);
                req->sent = curtime;
                req->times_sent++;
                #if defined ARP_DEBUG
                fprintf(stderr, "\nSent ARP request to %s\n", inet_ntoa((struct in_addr){arp_hdr->ar_tip}));
                #endif
                free(buf);
                buf = NULL;
            }
        }
    }
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

