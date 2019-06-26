#include "capture.h"
#include "structure.h"
#include <QTextStream>
#include <QDebug>

CaptureThread::CaptureThread(pcap_t *adhandle)//:datapktLink(datapktLLink), dataCharLink(dataCharLLink)
{

    stopped = false;
    this->adhandle = adhandle;
    total=0;
    ipCnt=0;
    tcpCnt=0;
    udpCnt=0;
    arpCnt=0;

}

int CaptureThread::httpTest(u_char *content)
{
    u_char * hhdr=NULL;
    char headBuf[16];
    for(int i=0; i<sizeof(headBuf); i++)
    {
        if(i==sizeof(headBuf)-1)
        headBuf[i] = 0;
        if(content+i)
        headBuf[i] = (char)content[i];
        else
        {
            headBuf[i] = 0;
            break;
        }
    }
    string hdbuf = headBuf;
    //QRegExp httpRE(tr("[GET|POST|HEAD|PUT|DELETE|OPTIONS|TRACE|CONNECT] (\S)* HTTP"));
    char * method[]={"GET","POST","HEAD","PUT","DELETE","OPTIONS","HTTP"};
    for(int i = 0 ; i < 7 ; i ++)
    {
               if(strstr((char *)content,method[i]))
               return 1;
    }

    return 0;
}

void CaptureThread::run()
{
    int res;
    struct tm *ltime;
    time_t local_tv_sec;
    char timestr[64];
    QString protoType="x";
    QString otherInfo;

    struct pcap_pkthdr *header;     //数据包头
    const u_char * pkt_data; //包数据


    ip_header *ih;
    udp_header *uh;
    tcp_header *th;
    icmp_header *imh;
    arp_header *ah;
    u_int ip_len;
    u_short sport,dport;
    char src_ip_port[64];
    char dest_ip_port[64];
    char src_mac[64];
    char dest_mac[64];

    QString flagNames[] = {
        "FIN","SYN","RST","PUSH",
        "ACK","URG","ECE","CWR"
    };


    dataLabel tempDL;
    int offset = 0;
    FILE * recFile  = NULL;


    while(stopped != true && (res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
    {
        if(res == 0)     //读取数据包超时
            continue;
        /*存储捕获的数据包中的信息*/
        tempDL.len = header->len;

        recFile = fopen("tempfile","ab");
        fseek(recFile,offset,SEEK_SET);
        fwrite(pkt_data,sizeof(u_char),tempDL.len,recFile);
        fclose(recFile);

        offset+= tempDL.len;
        tempDL.offset = offset;
        dtlb.push_back(tempDL);

        //Analyze
        eth_header * eh  = (eth_header *)pkt_data;
        eh->type = ntohs(eh->type);
        total++;
        switch(eh->type)
        {
           case PROTO_IP:
            /* 获得IP数据包头部的位置 */
            ih = (ip_header *) (pkt_data +
                    14); //以太网头部长度
            otherInfo = "";
            protoType = "IP";
            ipCnt++;

                    switch(ih->proto)
                    {
                        case PROTO_TCP:
                        /* 获得TCP首部的位置 */
                        ip_len = (ih->ver_ihl & 0xf) * 4;
                        th = (tcp_header *) ((u_char*)ih + ip_len);
                       /* 将网络字节序列转换成主机字节序列 */
                       sport = ntohs( th->srcPort );
                       dport = ntohs( th->destPort );
                       otherInfo = "SEQ=0x"+QString::number(ntohl(th->seq),16)+
                               ",ACK=0x"+ QString::number(ntohl(th->ack_sql),16)+
                               ",Flag=0x" + QString::number(th->th_flags,16);
                       for(int tib=0; tib<8; tib++)
                       {
                           if((th->th_flags)&(1<<tib))
                           {
                               otherInfo += QString(" [") + flagNames[tib] + QString("]");
                           }
                       }
                       protoType = "TCP";
                       tcpCnt++;
                       /* 打印IP地址和端口 */
                   sprintf(src_ip_port,"%d.%d.%d.%d:%d",
                           ih->saddr.byte1,
                           ih->saddr.byte2,
                           ih->saddr.byte3,
                           ih->saddr.byte4,
                           sport);
                   sprintf(dest_ip_port, "%d.%d.%d.%d:%d",
                           ih->daddr.byte1,
                           ih->daddr.byte2,
                           ih->daddr.byte3,
                           ih->daddr.byte4,
                           dport);

                      // u_char * payload = (u_char *)(th+20); //TCP header >= 20
                       if((th->destPort==80||th->srcPort==80)&&httpTest((u_char *)th))
                           protoType ="HTTP";
                       /*

                       */

                       //QString
                       //qDebug()<<;






                        break;


                        case PROTO_UDP:
                        /* 获得UDP首部的位置 */
                        ip_len = (ih->ver_ihl & 0xf) * 4;
                        uh = (udp_header *) ((u_char*)ih + ip_len);
                        /* 将网络字节序列转换成主机字节序列 */
                        sport = ntohs( uh->sport );
                        dport = ntohs( uh->dport );
                        otherInfo = "";
                        otherInfo += "Checksum:" + QString::number(uh->crc);
                        protoType = "UDP";
                        udpCnt++;
                        /* 打印IP地址和端口 */
                    sprintf(src_ip_port,"%d.%d.%d.%d:%d",
                            ih->saddr.byte1,
                            ih->saddr.byte2,
                            ih->saddr.byte3,
                            ih->saddr.byte4,
                            sport);
                    sprintf(dest_ip_port, "%d.%d.%d.%d:%d",
                            ih->daddr.byte1,
                            ih->daddr.byte2,
                            ih->daddr.byte3,
                            ih->daddr.byte4,
                            dport);
                         break;

                    case PROTO_ICMP:
                        ip_len = (ih->ver_ihl & 0xf) * 4;
                        imh = (icmp_header *)((u_char*)ih + ip_len);
                        otherInfo ="";
                        protoType = "ICMP";
                        int t = imh->type;
                        otherInfo += "Type:" + QString::number(t);
                        /* 打印IP地址和端口 */
                    sprintf(src_ip_port,"%d.%d.%d.%d",
                            ih->saddr.byte1,
                            ih->saddr.byte2,
                            ih->saddr.byte3,
                            ih->saddr.byte4);
                    sprintf(dest_ip_port, "%d.%d.%d.%d",
                            ih->daddr.byte1,
                            ih->daddr.byte2,
                            ih->daddr.byte3,
                            ih->daddr.byte4
                            );
                        break;
                        //default :
                       //  break;
                        }



                        //Analyze MAC address
                        sprintf(src_mac,"%2x-%2x-%2x-%2x-%2x-%2x",
                                eh->src[0],
                                eh->src[1],
                                eh->src[2],
                                eh->src[3],
                                eh->src[4],
                                eh->src[5]
                                );
                        sprintf(dest_mac,"%2x-%2x-%2x-%2x-%2x-%2x",
                                eh->dest[0],
                                eh->dest[1],
                                eh->dest[2],
                                eh->dest[3],
                                eh->dest[4],
                                eh->dest[5]
                                );




                        /* 将时间戳转换成可识别的格式 */
                       local_tv_sec = header->ts.tv_sec;
                       ltime=localtime(&local_tv_sec);
                       strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

                       emit packetCaptured(QString(timestr),QString::number(header->len,10),protoType,
                                           QString(src_ip_port),QString(dest_ip_port),
                                           ((QString)src_mac).toUpper(),((QString)dest_mac).toUpper(),otherInfo);


                                break;


            case PROTO_ARP:
            /* 获得ARP数据包头部的位置 */
            ah = (arp_header *) (pkt_data +
                    14); //以太网头部长度
            otherInfo = "";
            if(ah->opcode==1)
            {
               otherInfo+= "request(1)"; //1为ARP请求报文，2为ARP回复报文
            }
            else
            {
                otherInfo +="reply(2)";
            }
            protoType = "ARP";
            arpCnt++;
            /* 打印IP地址 */
        sprintf(src_ip_port,"%d.%d.%d.%d",
                ah->senderIp[0],
                ah->senderIp[1],
                ah->senderIp[2],
                ah->senderIp[3]
                );
        sprintf(dest_ip_port, "%d.%d.%d.%d",
                ah->destIp[0],
                ah->destIp[1],
                ah->destIp[2],
                ah->destIp[3]
                );
        //Analyze MAC address
        sprintf(src_mac,"%2x-%2x-%2x-%2x-%2x-%2x",
                eh->src[0],
                eh->src[1],
                eh->src[2],
                eh->src[3],
                eh->src[4],
                eh->src[5]
                );
        sprintf(dest_mac,"%2x-%2x-%2x-%2x-%2x-%2x",
                eh->dest[0],
                eh->dest[1],
                eh->dest[2],
                eh->dest[3],
                eh->dest[4],
                eh->dest[5]
                );

         /* 将时间戳转换成可识别的格式 */
       local_tv_sec = header->ts.tv_sec;
       ltime=localtime(&local_tv_sec);
       strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

       emit packetCaptured(QString(timestr),QString::number(header->len,10),protoType,
                           QString(src_ip_port),QString(dest_ip_port),
                           ((QString)src_mac).toUpper(),((QString)dest_mac).toUpper(),otherInfo);


            break;


            default:
             break;
        }

    }
}

void CaptureThread::stop()
{
    QMutexLocker locker(&m_lock);
    stopped = true;
}
