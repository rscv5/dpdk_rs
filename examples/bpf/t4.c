#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#include <rte_config.h>
#include <rte_mbuf_core.h>
#include <rte_mbuf.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

uint64_t
entry(const void *pkt)
{
        const struct rte_mbuf *mb;
        const struct ether_header *eth;
        //struct ether_header *eth = (struct ether_header *) rte_pktmbuf_mtod(mb, const struct ether_header *);

        /*
         * struct ether_header{
         *      uint8_t ether_dhost[ETH_ALEN]; // 目标mac地址，ETH_ALEN一般为6
         *      uint8_t ether_shost[ETH_ALEN]; // 源..
         *      uint6_t ether_type; // 包裹的数据帧类型：IP，ARP，RARP。判断时用htons(nums)将nums转成网络字节顺序
         * }
         *
         *  #define    ETHERTYPE_IP      0x0800
         */
        mb = pkt;
        eth = rte_pktmbuf_mtod(mb, const struct ether_header *);

        // struct ether_header *eth_header = (void *)pkt;
        // 0x0806 是ARP协议 0x0800 是IP协议
        if(eth_header->ether_type != htons(0x0806)) //如果不是ARP协议
        {
                // not IP
                // ....

                return 1; // 返回 
        }

        // 如果是ip：
        // get struct iphdr
        /* struct iphdr{
                __u8 version:4, //ip协议 4bit
                     ihl:4;  // 头部长度 4bit 单位为字节（max_len=4*ihl)
                __u8 tos; 
                __u16 tot_len; // 16bit 整个IP数据包的长度，包括数据与IP头部
                __u16 id;  // 
                __u16 frag_off;
                __u8 ttl; // 生存期（TTL），8bit
                __u8 protocol; // 上层协议 8bit 如TCP、UDP
                __u16 check;  // 校验和 16bit
                __u32 saddr; // 源IP地址
                __u32 daddr; // 目标IP地址
                // The options start here./
                }
        */
        // struct iphdr * iphdr = (void *)(eth_header + 1);
        // if(ip->protocol)
        // get protocol
        // int protocol = iphdr->protocol;

        // get src IP address
        // uint32_t saddr = iphdr->saddr;
        
        // get dst IP address
        // uint32_t daddr = iphdr->daddr;
        
        
        return 0; // 丢包
}