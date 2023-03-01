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
      if (arp_hdr->ar_tip == sr_get_interface(sr, interface)->ip) {
        fprintf(stderr, "ARP reply for this router received\n");
      } else {
        fprintf(stderr, "ARP reply for other host received\n");
        return;
      }
      #endif
    }

    return;

  } else if (ethertype(packet) == ethertype_ip) {
    /* IP packet */
    #ifdef IP_DEBUG
    fprintf(stderr, "IP packet received\n");
    #endif

    /* TODO: process IP packet */
  }

}/* end sr_ForwardPacket */

