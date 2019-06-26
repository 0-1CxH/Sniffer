#ifndef CAPTURE_H
#define CAPTURE_H

#define WPCAP
#define HAVE_REMOTE
#include <pcap.h>

#include <QThread>
#include <QMutex>
#include <vector>
#include <QRegExp>
#include "structure.h"
using namespace std;

class CaptureThread: public QThread
{
    Q_OBJECT
public:
    CaptureThread(pcap_t *adhandle);
    vector<dataLabel> dtlb;
    int httpTest(u_char * content);

    int ipCnt;
    int arpCnt;
    int total;
    int tcpCnt;
    int udpCnt;

    void stop();
protected:
    void run();
private:
    QMutex m_lock;
    volatile bool stopped;
    pcap_t *adhandle;

signals:
    void packetCaptured(QString, QString, QString, QString, QString, QString, QString, QString);
};




#endif // CAPTURE_H
