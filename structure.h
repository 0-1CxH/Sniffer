#ifndef STRUCTURE_H
#define STRUCTURE_H

#define PROTO_ICMP 1
#define PROTO_TCP 6
#define PROTO_UDP 17
#include <QString>

/* 4字节的IP地址 */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 首部 */
typedef struct ip_header{
    u_char  ver_ihl;        // 版本 (4 bits) + 首部长度 (4 bits)
    u_char  tos;            // 服务类型(Type of service)
    u_short tlen;           // 总长(Total length)
    u_short identification; // 标识(Identification)
    u_short flags_fo;       // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
    u_char  ttl;            // 存活时间(Time to live)
    u_char  proto;          // 协议(Protocol)
    u_short crc;            // 首部校验和(Header checksum)
    ip_address  saddr;      // 源地址(Source address)
    ip_address  daddr;      // 目的地址(Destination address)
    u_int   op_pad;         // 选项与填充(Option + Padding)
}ip_header;

/* UDP 首部*/
typedef struct udp_header{
    u_short sport;          // 源端口(Source port)
    u_short dport;          // 目的端口(Destination port)
    u_short len;            // UDP数据包长度(Datagram length)
    u_short crc;            // 校验和(Checksum)
}udp_header;

/* TCP 首部*/
typedef struct tcp_header
{
    u_short srcPort;
    u_short destPort;
    u_int seq;
    u_int ack_sql;
    u_char th_offx2;    //data offset, rsvd

    #define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)   //得到前4位，即包首部长度
    u_char th_flags;

    u_short wnd_size;     //窗口大小，16位
    u_short checksum;   //校验和,16位
    u_short urg_ptr;    //紧急指针
}tcp_header;



/* ICMP 首部*/
typedef struct icmp_header
{
    u_char type;        //类型字段，占8位
    u_char code;        //代码字段，占8位
    u_short chk_sum;    //校验和字段，占16位
    u_short identification; //标识符字段，占16位
    u_short seq;    //序列号字段，占16位
}icmp_header;

typedef struct dataLabel
{
    int len;
    int offset;
}dataLabel;

//MAC帧头
typedef struct eth_header
{
    u_char dest[6];     //6个字节，目标MAC地址
    u_char src[6];      //6个字节，源MAC地址
    u_short type;   //2个字节 类型
}eth_header;

#define PROTO_IP 0x0800
#define PROTO_ARP 0X0806

//链路层帧的首部长度为14字节
#define ETHERNET_SIZE 14

//ARP头
typedef struct arp_header
{
    u_short htype;   //2个字节，硬件类型，以太网是0x0001
    u_short prtype;     //2个字节，协议类型，0x0800表示使用ARP的协议类型为IPV4
    u_char hsize;   //硬件地址长度，ARP为6
    u_char prsize;   //协议地址长度，ARP为4
    u_short opcode;     //操作码，1为ARP请求报文，2为ARP回复报文
    u_char senderMac[6];    //发送方MAC地址
    u_char senderIp[4];     //发送方IP地址
    u_char destMac[6];      //接收方MAC地址
    u_char destIp[4];       //接收方IP地址
}arp_header;

//ARP包
#pragma pack(1)
typedef struct arp_packet
{
    unsigned char dest_mac[6];	//以太网目的地址
    unsigned char src_mac[6];	//以太网源地址
    unsigned short eh_type;		//以太网帧类型

    unsigned short hardware_type;	//硬件类型：以太网接口类型为1
    unsigned short protocol_type;	//协议类型：IP协议类型为0x0800
    unsigned char add_len;			//硬件地址长度
    unsigned char pro_len;			//协议地址长度
    unsigned short option;			//操作
    unsigned char sour_addr[6];		//源MAC地址：发送方的MAC地址
    unsigned long sour_ip;			//源IP地址：发送方的IP地址
    unsigned char dest_addr[6];		//目的Mac地址
    unsigned long dest_ip;			//目的IP地址
}arp_packet;
#pragma pack()

#endif // STRUCTURE_H
