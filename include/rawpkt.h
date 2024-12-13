#ifndef RAWPKT_H
#define RAWPKT_H

#define ETH_ALEN          6
#define ETHERTYPE_IP      0x0800
#define ETHERTYPE_IPv6    0x86DD

#define IPVERSION         4
#define MAXTTL            255
#define IPDEFTTL          64
#define IPv4_HDR_LEN      0x45   /* IPv4 + 20 bytes of IP header */

#define IPTOS_TOS_MASK    0x1E
#define IPTOS_TOS(tos)    ((tos)&IPTOS_TOS_MASK)

#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY    0x10
#define IPTOS_THROUGHPUT  0x08
#define IPTOS_RELIABILITY 0x04
#define IPTOS_MINCOST     0x02
#endif

/* IP flags. */
#ifndef IP_CE
#define IP_CE             0x8000  /* Flag: "Congestion"		*/
#define IP_DF             0x4000  /* Flag: "Don't Fragment"	*/
#define IP_MF             0x2000  /* Flag: "More Fragments"	*/
#define IP_OFFSET         0x1FFF  /* "Fragment Offset" part	*/
#endif

#define IP_FRAG_TIME      (30 * HZ)  /* fragment lifetime	*/

/* TCP flags */
#define TH_FIN    0x0100
#define TH_SYN    0x0200
#define TH_RST    0x0400
#define TH_PUSH   0x0800
#define TH_ACK    0x1000
#define TH_URG    0x2000
#define TH_ECN    0x4000
#define TH_CWR    0x8000
#define TH_NS     0x0001
#define TH_RES    0x000E /* 3 reserved bits */
#define TH_MASK   0xFF0F


#pragma pack( push, 1 )

typedef struct {
  BYTE   h_dest[ETH_ALEN];      /* destination eth addr */
  BYTE   h_source[ETH_ALEN];    /* source ether addr    */
  WORD   h_proto;               /* packet type ID field */
} eth_packet_t;

typedef struct {
  BYTE   ver_ihl;
  BYTE   tos;
  WORD   tot_len;
  WORD   id;
  WORD   frag_off;
  BYTE   ttl;
  BYTE   protocol;
  WORD   check;
  DWORD  saddr;
  DWORD  daddr;
} ip_packet_t;

typedef struct {
  WORD   source;
  WORD   dest;
  DWORD  seq;
  DWORD  ack_seq;
  union {
    uint16_t   flags;
    struct {
      uint16_t res1:4;
      uint16_t doff:4;
      uint16_t fin:1;
      uint16_t syn:1;
      uint16_t rst:1;
      uint16_t psh:1;
      uint16_t ack:1;
      uint16_t urg:1;
      uint16_t ece:1;
      uint16_t cwr:1;
    };
  };
  WORD   window;
  WORD   check;
  WORD   urg_ptr; 
} tcp_packet_t;

typedef struct {
  WORD   source;
  WORD   dest;
  WORD   len;
  WORD   check;
} udp_packet_t;

typedef struct {
  BYTE   type;
  BYTE   code;
  WORD   check;
  WORD   identifier;
  WORD   seq;
} icmp_packet_t;

#pragma pack(pop)

#define RAWPKT_ICMP_ECHO_REQUEST   8
#define RAWPKT_ICMP_ECHO_REPLY     0

#define RAWPKT_ETHER_HDR_SIZE      14
#define RAWPKT_IP_HDR_SIZE         20
#define RAWPKT_UDP_HDR_SIZE        8
#define RAWPKT_ICMP_HDR_SIZE       8

#define RAWPKT_IP_HDR_LEN          (sizeof(ip_packet_t))
#define RAWPKT_RAW_IP_HDR_LEN      (sizeof(eth_packet_t) + RAWPKT_IP_HDR_LEN)

#define ut_ntohs(_x_)    ( (((uint16_t)(_x_) & 0xff) << 8) | ((uint16_t)(_x_) >> 8) )
#define ut_htons         ut_ntohs


#endif /* RAWPKT_H */
