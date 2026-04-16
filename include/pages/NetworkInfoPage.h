#pragma once
#ifndef NETWORKINFOPAGE_H
#define NETWORKINFOPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
#include <QLabel>
#include <QFont>
namespace Ui { class NetworkInfoPage; }

class NetworkInfoPage : public BasePage {
    Q_OBJECT
public:
    explicit NetworkInfoPage(QWidget *p=nullptr);
    void refreshData() override;
private:
    Ui::NetworkInfoPage *ui{nullptr};
    void loadNicData();
    void loadDnsData();
    void loadRouteData();
    QTableWidget *m_tblNic{nullptr};    // 网卡与IP配置
    QTableWidget *m_tblDns{nullptr};    // DNS配置
    QTableWidget *m_tblRoute{nullptr};  // 路由表
    QLabel       *m_lblStatus{nullptr};
};
#endif
