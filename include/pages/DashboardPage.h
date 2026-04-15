#pragma once
#ifndef DASHBOARDPAGE_H
#define DASHBOARDPAGE_H

#include "pages/BasePage.h"
#include <QTableWidget>
#include <QLabel>
#include <QGroupBox>

namespace Ui { class DashboardPage; }

class DashboardPage : public BasePage
{
    Q_OBJECT
public:
    explicit DashboardPage(QWidget *parent = nullptr);
    void refreshData() override;

private:
    Ui::DashboardPage *ui{nullptr};
    void setupUi();
    void updateStatCards();
    void updateRecentAlerts();
    void updateSystemInfo();

    // 统计卡片
    QLabel *m_lblHighRisk;
    QLabel *m_lblMedRisk;
    QLabel *m_lblLowRisk;
    QLabel *m_lblTotalDays;
    QLabel *m_lblVirusDb;

    // 最新告警表
    QTableWidget *m_tblAlerts;

    // 系统信息
    QLabel *m_lblOS;
    QLabel *m_lblHost;
    QLabel *m_lblVersion;
    QLabel *m_lblDbVer;
    QLabel *m_lblAuthStatus;
    QLabel *m_lblAuthExpiry;
    QLabel *m_lblLastScan;
};

#endif // DASHBOARDPAGE_H
