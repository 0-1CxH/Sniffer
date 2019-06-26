#ifndef ARPSPOOF_H
#define ARPSPOOF_H

#define WPCAP
#define HAVE_REMOTE
#include <pcap.h>

#include <QThread>
#include <QMutex>
#include <Packet32.h>
#include <synchapi.h>
#include <structure.h>
using namespace std;


class SpoofThread : public QThread
{
    Q_OBJECT
public:
    SpoofThread(pcap_t *adhandle, pcap_if_t *dev, u_long gate_ip, u_long victim_ip, u_char * gate_mac, u_char * victim_mac);
    void makeSpoofpacket(arp_packet &product,u_long tellee_ip, u_long victim_ip, u_char * tellee_mac);
    pcap_if_t * dev; pcap_t *adhandle;
    u_long gate_ip; u_long victim_ip; u_char gate_mac[6]; u_char victim_mac[6];
    int getMac();
    arp_packet arppacket_HOST;
    arp_packet arppacket_GATE;
    u_char selfMac[6];
    void stop();
protected:
    void run();
private:
    QMutex m_lock;
    volatile bool stopped;
signals:
    void spoofSent(QString);
};

#endif // ARPSPOOF_H
