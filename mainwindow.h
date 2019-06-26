#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#define WPCAP
#define HAVE_REMOTE
#include <pcap.h>

#include <capture.h>
#include <arpspoof.h>
#include <QMessageBox>

#include <QDebug>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    pcap_if_t *alldevs;
    pcap_if_t *dev;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int interface_opted;
    int interface_amount;
    //u_int netmask;

    struct bpf_program fcode;
    bpf_u_int32 NetMask;
    char *filter=NULL;

    CaptureThread * capthread;
    SpoofThread * spfthread;

    int ip_translate(QString IPin, u_long &IPout);
    int mac_translate(QString MACin, u_char * MACout);



private slots:
    void on_startBtn_clicked();
    void addTableLine(QString timestr, QString len, QString protoType, QString srcIP, QString dstIP, QString srcMac, QString destMac, QString otherInfo);
    void setPackbin(int r,int c);
    void on_stopBtn_clicked();
    void spoofPacket(QString);

    void on_stat_Btn_clicked();

    void on_spoof_btn_clicked();

    void on_spf_start_btn_clicked();

    void on_spf_stop_btn_clicked();

private:
    Ui::MainWindow *ui;
};

#endif // MAINWINDOW_H
