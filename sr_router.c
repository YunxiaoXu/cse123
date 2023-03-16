/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
  #if defined ARP_DEBUG || defined IP_DEBUG
  fprintf(stderr, "\n");
  print_hdr_eth(packet);
  #endif
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;

  if (ethertype(packet) == ethertype_arp) {
    /* process ARP packet */
    #ifdef ARP_DEBUG
    fprintf(stderr, "ARP packet received\n");
    #endif

    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    #ifdef ARP_DEBUG
    print_hdr_arp((uint8_t *)arp_hdr);
    #endif

    if (ntohs(arp_hdr->ar_op) == arp_op_request) {
      /* reply ARP request */
      #ifdef ARP_DEBUG
      fprintf(stderr, "ARP request received\n");
      #endif

      if (arp_hdr->ar_tip == sr_get_interface(sr, interface)->ip) {
        #ifdef ARP_DEBUG
        fprintf(stderr, "ARP request for this router received\n");
        #endif
        /* set ARP header */
        arp_hdr->ar_op = htons(arp_op_reply);
        memcpy(arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
        arp_hdr->ar_tip = arp_hdr->ar_sip;
        memcpy(arp_hdr->ar_sha, sr_get_interface(sr, interface)->addr, ETHER_ADDR_LEN);
        arp_hdr->ar_sip = sr_get_interface(sr, interface)->ip;
        /* set ethernet header */
        memcpy(eth_hdr->ether_shost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_dhost, arp_hdr->ar_tha, ETHER_ADDR_LEN);
        sr_send_packet(sr, packet, len, interface);
        #ifdef ARP_DEBUG
        fprintf(stderr, "ARP reply sent\n");
        #endif
      #ifdef ARP_DEBUG
      } else {
        fprintf(stderr, "ARP request for other host received\n");
        return;
      #endif
      }

    } else if (ntohs(arp_hdr->ar_op) == arp_op_reply) {
      #ifdef ARP_DEBUG
      fprintf(stderr, "ARP reply received\n");
      #endif

      if (arp_hdr->ar_tip == sr_get_interface(sr, interface)->ip) {
        #ifdef ARP_DEBUG
        fprintf(stderr, "ARP reply for this router received\n");
        #endif
        /* update ARP cache */
        struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
        #ifdef ARP_DEBUG
        fprintf(stderr, "ARP cache updated for %s: %02x:%02x:%02x:%02x:%02x:%02x\n",
          inet_ntoa((struct in_addr){arp_hdr->ar_sip}),
          arp_hdr->ar_sha[0], arp_hdr->ar_sha[1], arp_hdr->ar_sha[2],
          arp_hdr->ar_sha[3],arp_hdr->ar_sha[4], arp_hdr->ar_sha[5]
        );
        #endif
        /* forward queued packets */
        if (req) {
          struct sr_packet *pkt;
          for (pkt = req->packets; pkt; pkt = pkt->next) {
            sr_ethernet_hdr_t *pkt_eth_hdr = (sr_ethernet_hdr_t *)pkt->buf;
            memcpy(pkt_eth_hdr->ether_shost, sr_get_interface(sr, pkt->iface)->addr, ETHER_ADDR_LEN);
            memcpy(pkt_eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
            sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);
            #ifdef ARP_DEBUG
            fprintf(stderr, "Packet forwarded\n");
            #endif
          }
          sr_arpreq_destroy(&(sr->cache), req);
          req = NULL;
          #ifdef ARP_DEBUG
          fprintf(stderr, "ARP request destroyed\n");
          #endif
        }
      } else {
        #ifdef ARP_DEBUG
        fprintf(stderr, "ARP reply for other host received\n");
        return;
        #endif
      }
    }

    return;

  } else if (ethertype(packet) == ethertype_ip) {
    /* IP packet */
    #ifdef IP_DEBUG
    fprintf(stderr, "IP packet received\n");
    #endif

    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    #ifdef IP_DEBUG
    print_hdr_ip((uint8_t *)ip_hdr);
    #endif

    /* verify checksum */
    uint16_t sum = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0;
    if (cksum(ip_hdr, sizeof(sr_ip_hdr_t)) != sum) {
      #ifdef IP_DEBUG
      fprintf(stderr, "IP packet checksum error: %u, %u\n", sum, cksum(ip_hdr, sizeof(sr_ip_hdr_t)));
      #endif
      return;
    }
    #ifdef IP_DEBUG
    fprintf(stderr, "IP packet checksum correct\n");
    #endif

    /* process packet if ip is router's */
    struct sr_if *router_if;
    for (router_if = sr->if_list; router_if; router_if = router_if->next) {
      if (ip_hdr->ip_dst == router_if->ip) {
        #ifdef IP_DEBUG
        fprintf(stderr, "IP packet for this router received\n");
        #endif

        if (ip_hdr->ip_p == ip_protocol_icmp) {
          #ifdef IP_DEBUG
          fprintf(stderr, "ICMP packet received\n");
          #endif

          sr_icmp_t11_hdr_t *icmp_hdr = (sr_icmp_t11_hdr_t *)((void *)ip_hdr + sizeof(sr_ip_hdr_t));
          #ifdef IP_DEBUG
          print_hdr_icmp((uint8_t *)icmp_hdr);
          #endif

          if (icmp_hdr->icmp_type == 8) {
            /* reply echo request */
            #ifdef IP_DEBUG
            fprintf(stderr, "ICMP echo request received\n");
            #endif

            /* verify ICMP checksum */
            sum = icmp_hdr->icmp_sum;
            icmp_hdr->icmp_sum = 0;
            uint16_t icmp_hdr_len = ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t);
            if (cksum(icmp_hdr, icmp_hdr_len) != sum) {
              #ifdef IP_DEBUG
              fprintf(stderr, "ICMP packet checksum error: %u, %u\n", sum, cksum(icmp_hdr, icmp_hdr_len));
              #endif
              return;
            }
            #ifdef IP_DEBUG
            fprintf(stderr, "ICMP packet checksum correct\n");
            #endif

            /* set ICMP header */
            icmp_hdr->icmp_type = 0;
            icmp_hdr->icmp_code = 0;
            icmp_hdr->icmp_sum = 0;
            icmp_hdr->icmp_sum = cksum(icmp_hdr, icmp_hdr_len);
            /* set IP header */
            ip_hdr->ip_dst = ip_hdr->ip_src;
            ip_hdr->ip_src = router_if->ip;
            ip_hdr->ip_ttl = 64;
            ip_hdr->ip_sum = 0;
            ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
            /* set ethernet header */
            memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
            memcpy(eth_hdr->ether_shost, sr_get_interface(sr, interface)->addr, ETHER_ADDR_LEN);
            sr_send_packet(sr, packet, len, interface);
            #ifdef IP_DEBUG
            fprintf(stderr, "ICMP echo reply sent\n");
            #endif
            return;
          } else {
            #ifdef IP_DEBUG
            fprintf(stderr, "Non-echo request ICMP packet received\n");
            #endif
            return;
          }
        } else if (ip_hdr->ip_p == ip_protocol_tcp || ip_hdr->ip_p == ip_protocol_udp) {
          #ifdef IP_DEBUG
          fprintf(stderr, "TCP/UDP packet received\n");
          #endif
          
          /* send ICMP destination port unreachable type 3 code 3 */
          uint8_t *buf = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
          /* new packet headers */
          sr_ethernet_hdr_t *buf_eth_hdr = (void *)buf;
          sr_ip_hdr_t *buf_ip_hdr = (void *)buf_eth_hdr + sizeof(sr_ethernet_hdr_t);
          sr_icmp_t3_hdr_t *buf_icmp_hdr = (void *)buf_ip_hdr + sizeof(sr_ip_hdr_t);
          /* set ICMP header */
          *buf_icmp_hdr = (sr_icmp_t3_hdr_t){
            .icmp_type = 3,
            .icmp_code = 3,
            .unused = 0,
            .next_mtu = 0,
            .icmp_sum = 0,
          };
          memcpy(buf_icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);
          buf_icmp_hdr->icmp_sum = cksum(buf_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
          /* set IP header */
          *buf_ip_hdr = (sr_ip_hdr_t){
            .ip_hl = 5,
            .ip_v = 4,
            .ip_tos = 0,
            .ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t)),
            .ip_id = 0,
            .ip_off = 0,
            .ip_ttl = 64,
            .ip_p = ip_protocol_icmp,
            .ip_sum = 0,
            .ip_src = sr_get_interface(sr, interface)->ip, /* FIXME */
            .ip_dst = ip_hdr->ip_src,
          };
          buf_ip_hdr->ip_sum = cksum(buf_ip_hdr, sizeof(sr_ip_hdr_t));
          /* set Ethernet header */
          memcpy(buf_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
          memcpy(buf_eth_hdr->ether_shost, sr_get_interface(sr, interface)->addr, ETHER_ADDR_LEN);
          buf_eth_hdr->ether_type = htons(ethertype_ip);
          /* send packet */
          sr_send_packet(sr, buf,
            sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), interface);
          return;
        } else {
          #ifdef IP_DEBUG
          fprintf(stderr, "Unkown IP packect sent to router: ip_p %u\n", ip_hdr->ip_p);
          #endif
          return;
        }
      }
    }

    #ifdef IP_DEBUG
    fprintf(stderr, "IP packet for other host received\n");
    #endif

    /* forward IP packet */
    struct sr_rt *rt_entry, *longest_prefix_entry = NULL;
    in_addr_t longest_prefix = 0;
    /* longest prefix match */
    for (rt_entry = sr->routing_table; rt_entry; rt_entry = rt_entry->next) {
      in_addr_t rt_mask = rt_entry->mask.s_addr;
      in_addr_t rt_dest = rt_entry->dest.s_addr;
      if ((ip_hdr->ip_dst & rt_mask) == (rt_dest & rt_mask)) {
        if (rt_mask > longest_prefix || longest_prefix_entry == NULL) {
          longest_prefix = rt_mask;
          longest_prefix_entry = rt_entry;
        }
      }
    }
    if ((rt_entry = longest_prefix_entry)) {
      #ifdef IP_DEBUG
      fprintf(stderr, "Found route %s (%s)\n", rt_entry->interface, 
        inet_ntoa((struct in_addr){sr_get_interface(sr, rt_entry->interface)->ip})
      );
      #endif

      /* decrement TTL */
      ip_hdr->ip_ttl--;
      if (ip_hdr->ip_ttl == 0) {
        ip_hdr->ip_ttl++;
        #ifdef IP_DEBUG
        fprintf(stderr, "IP packet TTL expired\n");
        #endif
        /* send ICMP time exceeded */
        uint8_t *buf = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t));
        /* new packet headers */
        sr_ethernet_hdr_t *buf_eth_hdr = (void *)buf;
        sr_ip_hdr_t *buf_ip_hdr = (void *)buf_eth_hdr + sizeof(sr_ethernet_hdr_t);
        sr_icmp_t11_hdr_t *buf_icmp_hdr = (void *)buf_ip_hdr + sizeof(sr_ip_hdr_t);
        /* set ICMP header */
        buf_icmp_hdr->icmp_type = 11;
        buf_icmp_hdr->icmp_code = 0;
        buf_icmp_hdr->icmp_sum = 0;
        buf_icmp_hdr->unused = 0;
        memcpy(buf_icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);
        buf_icmp_hdr->icmp_sum = cksum(buf_icmp_hdr, sizeof(sr_icmp_t11_hdr_t));
        /* set IP header */
        buf_ip_hdr->ip_hl = 5;
        buf_ip_hdr->ip_v = 4;
        buf_ip_hdr->ip_tos = 0;
        buf_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t));
        buf_ip_hdr->ip_id = 0;
        buf_ip_hdr->ip_off = 0;
        buf_ip_hdr->ip_ttl = 255;
        buf_ip_hdr->ip_p = ip_protocol_icmp;
        buf_ip_hdr->ip_src = sr_get_interface(sr, interface)->ip;
        buf_ip_hdr->ip_dst = ip_hdr->ip_src;
        buf_ip_hdr->ip_sum = 0;
        buf_ip_hdr->ip_sum = cksum(buf_ip_hdr, sizeof(sr_ip_hdr_t));
        /* set Ethernet header */
        memcpy(buf_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
        memcpy(buf_eth_hdr->ether_shost, sr_get_interface(sr, interface)->addr, ETHER_ADDR_LEN);
        buf_eth_hdr->ether_type = htons(ethertype_ip);
        /* send packet */
        sr_send_packet(sr, buf,
          sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t), interface);
        #ifdef IP_DEBUG
        fprintf(stderr, "Sent ICMP time exceeded to %s\n", inet_ntoa((struct in_addr){ip_hdr->ip_src}));
        #endif
        free(buf);
        buf = NULL;
        return;
      }

      /* set ip header */
      ip_hdr->ip_sum = 0;
      ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
      /* send packet if mac addr in arp cache */
      struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, rt_entry->gw.s_addr);
      if (arp_entry) {
        #ifdef ARP_DEBUG
        fprintf(stderr, "Found ARP entry for %s\n", inet_ntoa((struct in_addr){rt_entry->gw.s_addr}));
        #endif
        /* set ethernet header */
        memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_shost, sr_get_interface(sr, rt_entry->interface)->addr, ETHER_ADDR_LEN);
        /* send packet */
        sr_send_packet(sr, packet, len, rt_entry->interface);
        #ifdef IP_DEBUG
        fprintf(stderr, "IP packet forwarded to %s\n", inet_ntoa((struct in_addr){rt_entry->gw.s_addr}));
        #endif
        free(arp_entry);
        arp_entry = NULL;
        return;
      }
      /* queue packet */
      sr_arpcache_queuereq((&sr->cache), rt_entry->gw.s_addr, packet, len, rt_entry->interface);
      #ifdef IP_DEBUG
      fprintf(stderr, "IP packet queued for forwarding\n");
      #endif
      return;
    }
  
    #ifdef IP_DEBUG
    fprintf(stderr, "IP packet destination not found\n");
    #endif
    /* send ICMP destination net unreachable */
    uint8_t *buf = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    /* new packet headers */
    sr_ethernet_hdr_t *buf_eth_hdr = (void *)buf;
    sr_ip_hdr_t *buf_ip_hdr = (void *)buf_eth_hdr + sizeof(sr_ethernet_hdr_t);
    sr_icmp_t3_hdr_t *buf_icmp_hdr = (void *)buf_ip_hdr + sizeof(sr_ip_hdr_t);
    /* set ICMP header */
    buf_icmp_hdr->icmp_type = 3;
    buf_icmp_hdr->icmp_code = icmp_net_unreachable;
    buf_icmp_hdr->icmp_sum = 0;
    buf_icmp_hdr->unused = 0;
    buf_icmp_hdr->next_mtu = 0;
    memcpy(buf_icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);
    buf_icmp_hdr->icmp_sum = cksum(buf_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
    /* set IP header */
    buf_ip_hdr->ip_hl = 5;
    buf_ip_hdr->ip_v = 4;
    buf_ip_hdr->ip_tos = 0;
    buf_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    buf_ip_hdr->ip_id = 0;
    buf_ip_hdr->ip_off = 0;
    buf_ip_hdr->ip_ttl = 255;
    buf_ip_hdr->ip_p = ip_protocol_icmp;
    buf_ip_hdr->ip_sum = 0;
    buf_ip_hdr->ip_src = sr_get_interface(sr, interface)->ip;
    buf_ip_hdr->ip_dst = ip_hdr->ip_src;
    buf_ip_hdr->ip_sum = cksum(buf_ip_hdr, sizeof(sr_ip_hdr_t));
    /* set Ethernet header */
    memcpy(buf_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(buf_eth_hdr->ether_shost, sr_get_interface(sr, interface)->addr, ETHER_ADDR_LEN);
    buf_eth_hdr->ether_type = htons(ethertype_ip);
    /* send packet */
    sr_send_packet(sr, buf,
      sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), interface);
    #ifdef IP_DEBUG
    fprintf(stderr, "Sent ICMP net unreachable to %s\n", inet_ntoa((struct in_addr){ip_hdr->ip_src}));
    #endif
    free(buf);
    buf = NULL;
  }


}/* end sr_ForwardPacket */

