#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    ui->startBtn->setEnabled(true);
    ui->stopBtn->setEnabled(false);
    ui->stat_Btn->setEnabled(false);
    ui->packBin->setFontPointSize(12);
    ui->packBin->setFontFamily(tr("Times New Roman"));
    ui->textDisplay->setFontPointSize(12);
    ui->textDisplay->setFontFamily(tr("Times New Roman"));
    ui->gate_ip->setVisible(false);
    ui->gate_mac->setVisible(false);
    ui->victim_ip->setVisible(false);
    ui->victim_mac->setVisible(false);
    ui->spf_start_btn->setVisible(false);
    ui->spf_stop_btn->setVisible(false);
    ui->gate_ip->setPlaceholderText("<Gateway> IP");
    ui->gate_mac->setPlaceholderText("<Gateway> MAC");
    ui->victim_ip->setPlaceholderText("<Victim> IP");
    ui->victim_mac->setPlaceholderText("<Victim> MAC");

//INIT PACKET TABLE
    ui->packTable->setColumnCount(9);
    ui->packTable->setHorizontalHeaderLabels(QStringList() << tr("No.") << tr("Time")
                                              << tr("Len") << tr("Prt")
                                              << tr("Source IP") << tr("Destination IP")
                                              << tr("Source MAC") << tr("Destination MAC") <<tr("Info"));

    ui->packTable->setSelectionBehavior(QAbstractItemView::SelectRows); //设置为单行选中
    ui->packTable->setSelectionMode(QAbstractItemView::SingleSelection); //设置选择模式，即选择单行
    ui->packTable->setEditTriggers(QAbstractItemView::NoEditTriggers); //设置为禁止修改
    ui->packTable->setColumnWidth(0, 60);
    ui->packTable->setColumnWidth(1, 100);
    ui->packTable->setColumnWidth(2, 60);
    ui->packTable->setColumnWidth(3, 60);
    ui->packTable->setColumnWidth(4, 200);
    ui->packTable->setColumnWidth(5, 200);
    ui->packTable->setColumnWidth(6, 200);
    ui->packTable->setColumnWidth(7, 200);
    ui->packTable->setColumnWidth(8, 600);
  //  connect(ui->packTable, SIGNAL(cellClicked(int,int)), this, SLOT(showProtoTree(int,int)));

    connect(
                ui->packTable,
                SIGNAL(cellClicked(int,int)),
                this,
                SLOT(setPackbin(int,int))
                );

    ui->packTable->verticalHeader()->setVisible(false);    //隐藏列表头


//INIT NIC COMBO
    interface_amount = 0;
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
        ui->NICOption->addItem("No Adapter Found");
    }
    else
    {
        ui->NICOption->addItem("----Select An Interface----");
        for(dev=alldevs; dev; dev=dev->next)
        {
            if(dev->description)
                ui->NICOption->addItem(QString(dev->description));
            ++interface_amount;
        }
    }







}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_startBtn_clicked()
{
    ui->startBtn->setEnabled(false);
    ui->stopBtn->setEnabled(true);
    ui->stat_Btn->setEnabled(false);
    //获得选中的网卡接口
    interface_opted = ui->NICOption->currentIndex();
    if(interface_opted <= 0 || interface_opted >=interface_amount){
        QMessageBox::warning(this, "Warning from mySniffer", tr("Invalid Choice"), QMessageBox::Ok);
        ui->startBtn->setEnabled(true);
        ui->stopBtn->setEnabled(false);
        return;
    }
    dev = alldevs;
    for(int count = 0; count < interface_opted - 1; count++){
        dev = dev->next;
    }

    qDebug() << "NIC Opted: " << dev->name << endl;

    if((adhandle = pcap_open_live(dev->name,    //设备名
                                  65536,    //捕获数据包长度
                                  1,    //设置成混杂模式
                                  1000,    //读超时设置
                                  errbuf  //错误信息缓冲
                                  )) == NULL)
    {
        QMessageBox::warning(this, "Warning", tr("Access to NIC Denied"), QMessageBox::Ok);
        pcap_freealldevs(alldevs);
        alldevs = NULL;
        ui->startBtn->setEnabled(true);
        ui->stopBtn->setEnabled(false);
        return;
    }
    /* 检查数据链路层，为了简单，我们只考虑以太网 */
    if(pcap_datalink(adhandle) != DLT_EN10MB)
        {
            QMessageBox::warning(this, "Warning", tr("Only Works on Ethernet"), QMessageBox::Ok);
            /* 释放设备列表 */
            pcap_freealldevs(alldevs);

            ui->startBtn->setEnabled(true);
            ui->stopBtn->setEnabled(false);
            return;
        }

    if(dev->addresses != NULL)
         /* 获得接口第一个地址的掩码 */
         NetMask=((struct sockaddr_in *)(dev->addresses->netmask))->sin_addr.S_un.S_addr;
     else
         /* 如果接口没有地址，那么我们假设一个C类的掩码 */
         NetMask=0xffffff;
    //compile the filter
    QString lineContent = ui->lineEdit->text();
    QByteArray lcBA = lineContent.toLatin1(); // must
    filter=lcBA.data();
     if(pcap_compile(adhandle, &fcode, filter, 1, NetMask) < 0)
     {
         //fprintf(stderr,"\nError compiling filter: wrong syntax.\n");
         QMessageBox::critical(this,"Error",tr("Occured when Compiling Filter: Wrong Syntax"),QMessageBox::Ok);
         ui->startBtn->setEnabled(true);
         ui->stopBtn->setEnabled(false);
         return;
     }

     //set the filter
     if(pcap_setfilter(adhandle, &fcode)<0)
     {
         fprintf(stderr,"\nError setting the filter\n");
         ui->startBtn->setEnabled(true);
         ui->stopBtn->setEnabled(false);
         return;
     }


    capthread = new CaptureThread(adhandle);

    qDebug()<<"capthread Started" <<endl;

   ui->packTable->clearContents();
   ui->packTable->setRowCount(0);

    ui->packBin->clear();

    connect(capthread,
            SIGNAL(packetCaptured(QString, QString, QString, QString,QString, QString, QString,QString)),
            this,
            SLOT(addTableLine(QString, QString, QString, QString, QString, QString, QString,QString))
            );
    capthread->start();

}

void MainWindow::addTableLine(QString timestr, QString len, QString protoType, QString srcIP, QString dstIP, QString srcMac, QString destMac, QString otherInfo)
{
    qDebug()<<QString(timestr)<<QString(len)<<QString(protoType)<<QString(srcIP)<<QString(dstIP)<<srcMac<<destMac;
    int rowCnt = ui->packTable->rowCount();
    ui->packTable->insertRow(rowCnt);
    ui->packTable->setItem(rowCnt, 0, new QTableWidgetItem(QString::number(rowCnt, 10)));
    ui->packTable->setItem(rowCnt, 1, new QTableWidgetItem(timestr));
    ui->packTable->setItem(rowCnt, 2, new QTableWidgetItem(len));
    ui->packTable->setItem(rowCnt, 3, new QTableWidgetItem(protoType));
    ui->packTable->setItem(rowCnt, 4, new QTableWidgetItem(srcIP));
    ui->packTable->setItem(rowCnt, 5, new QTableWidgetItem(dstIP));
    ui->packTable->setItem(rowCnt, 6, new QTableWidgetItem(srcMac));
    ui->packTable->setItem(rowCnt, 7, new QTableWidgetItem(destMac));
    ui->packTable->setItem(rowCnt, 8, new QTableWidgetItem(otherInfo));
    if(rowCnt > 1)
    {
        ui->packTable->scrollToItem(ui->packTable->item(rowCnt, 0), QAbstractItemView::PositionAtBottom);
    }
}

void MainWindow::on_stopBtn_clicked()
{
    ui->startBtn->setEnabled(true);
    ui->stopBtn->setEnabled(false);
    ui->stat_Btn->setEnabled(true);
    //停止线程
    if(capthread)
    capthread->stop();
    //关闭winpcap会话句柄，并释放其资源
    pcap_close(adhandle);
}

void MainWindow::spoofPacket(QString m)
{
    ui->packBin->append(m);
}

void MainWindow::setPackbin(int r,int c)
{
    ui->packBin->clear();

   int rlen = capthread->dtlb[r].len;
   int roffset = capthread->dtlb[r].offset;
   u_char binData[2048];

   FILE * recFile = fopen("tempfile","rb");
   fseek(recFile,roffset,SEEK_SET);
   fread(binData,sizeof(u_char),rlen,recFile);
   fclose(recFile);

   QString tempnum;
   QString hex=" ",pchr="";
   int i;
   for(i = 0 ; i < rlen ; i ++){
       hex += tempnum.sprintf("%02x ",binData[i]);
       if(isprint(binData[i])){     //判断是否为可打印字符
           pchr += binData[i];
       }
       else{
           pchr += ".";
       }

       if((i+1)%16 == 0){
           ui->packBin->append(hex + pchr);
           pchr = "  ";
           hex = "";
       }
   }
   i %= 16;
   for(; i < 16 ; i ++){
       hex += "     ";
   }
   ui->packBin->append(hex + pchr);


}




void MainWindow::on_stat_Btn_clicked()
{
    ui->textDisplay->setVisible(true);
    ui->textDisplay->setEnabled(true);
    ui->gate_ip->setVisible(false);
    ui->gate_mac->setVisible(false);
    ui->victim_ip->setVisible(false);
    ui->victim_mac->setVisible(false);
    ui->spf_start_btn->setVisible(false);
    ui->spf_stop_btn->setVisible(false);
    QString statisticStr = "Total: " + QString::number(capthread->total,10) + " Packet(s)\t\t"+
                           "\n-->IP: " + QString::number(capthread->ipCnt,10) + " Packet(s)\t\t"+
                           "\n---->TCP: " + QString::number(capthread->tcpCnt,10) + " Packet(s)\t\t"+
                           "\n---->UDP: " + QString::number(capthread->udpCnt,10) +" Packet(s)\t\t"+
                           "\n-->ARP: " + QString::number(capthread->arpCnt,10)+ " Packet(s)\t\t";

    //QMessageBox::information(this,"Statistic Results",statisticStr, QMessageBox::Ok);
    ui->textDisplay->setText(statisticStr);
}

void MainWindow::on_spoof_btn_clicked()
{
    //获得选中的网卡接口
    interface_opted = ui->NICOption->currentIndex();
    if(interface_opted <= 0 || interface_opted >=interface_amount){
        QMessageBox::warning(this, "Warning", tr("Invalid Choice of NIC"), QMessageBox::Ok);
        return;
    }
    dev = alldevs;
    for(int count = 0; count < interface_opted - 1; count++){
        dev = dev->next;
    }

    qDebug() << "NIC Opted: " << dev->name << endl;

    if((adhandle = pcap_open_live(dev->name,    //设备名
                                  65536,    //捕获数据包长度
                                  1,    //设置成混杂模式
                                  1000,    //读超时设置
                                  errbuf  //错误信息缓冲
                                  )) == NULL)
    {
        QMessageBox::warning(this, "Warning", tr("Access to NIC Denied"), QMessageBox::Ok);
        pcap_freealldevs(alldevs);
        alldevs = NULL;
        ui->startBtn->setEnabled(true);
        ui->stopBtn->setEnabled(false);
        return;
    }
    /* 检查数据链路层，为了简单，我们只考虑以太网 */
    if(pcap_datalink(adhandle) != DLT_EN10MB)
        {
            QMessageBox::warning(this, "Warning", tr("Only Works on Ethernet"), QMessageBox::Ok);
            /* 释放设备列表 */
            pcap_freealldevs(alldevs);

            ui->startBtn->setEnabled(true);
            ui->stopBtn->setEnabled(false);
            return;
        }

    ui->textDisplay->setVisible(false);
    ui->textDisplay->setEnabled(false);
    ui->gate_ip->setVisible(true);
    ui->gate_mac->setVisible(true);
    ui->victim_ip->setVisible(true);
    ui->victim_mac->setVisible(true);
    ui->spf_start_btn->setVisible(true);
    ui->spf_stop_btn->setVisible(true);
    ui->spf_stop_btn->setEnabled(false);

}


int MainWindow::ip_translate(QString IPin, u_long &IPout)
{
    const char * destipStr;
    QByteArray ba = IPin.toLatin1();
    destipStr = ba.data();
    IPout = inet_addr(destipStr);
    if(IPout == INADDR_NONE){
        return -1;
    }
    else return 0;
}

int switchChar(char chStr, u_char &n)
{
    if (chStr >= '0' && chStr <= '9')
       {
           n =  (chStr - '0');
           return 0;
       }
       else if (chStr >= 'A' && chStr <= 'f')
       {
           n = (chStr - 'A' + 10);
           return 0;
       }
       else if (chStr >= 'a' && chStr <= 'f')
       {
           n= (chStr - 'a' + 10);
           return 0;
       }
       else
       {
           return -1;
       }
}

int MainWindow::mac_translate(QString MACin, u_char *MACout)
{
    const char * destmacStr;
    QByteArray ba = MACin.toLatin1();
    destmacStr = ba.data();


    u_char h_b, l_b;
    for(int i=0; i<6; i++)
    {
        if(-1==switchChar(destmacStr[i*3],h_b))
        {
            //MACout = "";
            return -1;
        }
        if(-1==switchChar(destmacStr[i*3+1],l_b))
        {
            //MACout = "";
            return -1;
        }


        MACout[i] = (h_b<<4 & 0xf0) | (l_b& 0x0f);

    }

    return 0;




}

void MainWindow::on_spf_start_btn_clicked()
{
    u_long gate_ip, victim_ip;
    QString gip = ui->gate_ip->text();
    QString vip = ui->victim_ip->text();
    if(ip_translate(gip,gate_ip)==-1)
    {
        QMessageBox::warning(this,"Warning","Wrong Gate IP");
        return;
    }
    if(ip_translate(vip,victim_ip)==-1)
    {
        QMessageBox::warning(this,"Warning","Wrong Victim IP");
        return;
    }

/*char  dbgstr[128];
sprintf(dbgstr,"%x, %x",tellee_ip, victim_ip);
qDebug()<<dbgstr;*/

    u_char gate_mac[6], victim_mac[6];
    QString gmac = ui->gate_mac->text();
    QString vmac = ui->victim_mac->text();
    if(mac_translate(gmac,gate_mac)==-1)
    {
        QMessageBox::warning(this,"Warning","Wrong Gate MAC");
        return;
    }
    if(mac_translate(vmac,victim_mac)==-1)
    {
        QMessageBox::warning(this,"Warning","Wrong Victim MAC");
        return;
    }

/*sprintf(dbgstr,"%2x-%2x-%2x-%2x-%2x-%2x, %2x-%2x-%2x-%2x-%2x-%2x",
        tellee_mac[0],tellee_mac[1],tellee_mac[2],
        tellee_mac[3],tellee_mac[4],tellee_mac[5],
        victim_mac[0],victim_mac[1],victim_mac[2],
        victim_mac[3],victim_mac[4],victim_mac[5]);
qDebug()<<dbgstr;*/

    spfthread = new SpoofThread(adhandle, dev, gate_ip, victim_ip, gate_mac, victim_mac);
    connect(spfthread, SIGNAL(spoofSent(QString)),
            this, SLOT(spoofPacket(QString)));
    ui->packBin->clear();
    ui->spf_start_btn->setEnabled(false);
    ui->spf_stop_btn->setEnabled(true);

    spfthread->start();



}

void MainWindow::on_spf_stop_btn_clicked()
{
    if(!spfthread) return ;
    ui->spf_start_btn->setEnabled(true);
    ui->spf_stop_btn->setEnabled(false);
    spfthread->stop();
}
