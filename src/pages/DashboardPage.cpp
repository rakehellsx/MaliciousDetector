#include "pages/DashboardPage.h"
#include "ui_DashboardPage.h"

#include "DatabaseManager.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QGroupBox>
#include <QScrollArea>

DashboardPage::DashboardPage(QWidget *parent)
    : BasePage("系统概览", parent)
{
    ui = new Ui::DashboardPage();
    ui->setupUi(this);
    postSetupUi();
    m_lblHighRisk = findChild<QLabel*>("m_lblHighRisk");
    m_lblMedRisk = findChild<QLabel*>("m_lblMedRisk");
    m_lblLowRisk = findChild<QLabel*>("m_lblLowRisk");
    m_lblTotalDays = findChild<QLabel*>("m_lblTotalDays");
    m_lblVirusDb = findChild<QLabel*>("m_lblVirusDb");
    m_tblAlerts = ui->m_tblAlerts;
    m_lblOS = findChild<QLabel*>("m_lblOS");
    m_lblHost = findChild<QLabel*>("m_lblHost");
    m_lblVersion = findChild<QLabel*>("m_lblVersion");
    m_lblDbVer = findChild<QLabel*>("m_lblDbVer");
    m_lblAuthStatus = findChild<QLabel*>("m_lblAuthStatus");
    m_lblAuthExpiry = findChild<QLabel*>("m_lblAuthExpiry");
    m_lblLastScan = ui->m_lblLastScan;
    refreshData();
}

void DashboardPage::refreshData()
{
    updateStatCards();
    updateRecentAlerts();
    updateSystemInfo();
    m_lblStatus->setText("已刷新：" + QDateTime::currentDateTime().toString("HH:mm:ss"));
}

void DashboardPage::updateStatCards()
{
    auto *db = DatabaseManager::instance();
    QVariantMap stats = db->queryDashboardStats();
    m_lblHighRisk->setText(stats.value("high", 0).toString());
    m_lblMedRisk->setText(stats.value("medium", 0).toString());
    m_lblLowRisk->setText(stats.value("low", 0).toString());
    m_lblTotalDays->setText(stats.value("protect_days", 0).toString());
    m_lblVirusDb->setText(stats.value("db_version", "--").toString());
}

void DashboardPage::updateRecentAlerts()
{
    auto *db = DatabaseManager::instance();
    QVariantList alerts = db->queryRecentAlerts(20);

    m_tblAlerts->setRowCount(0);
    for (const QVariant &v : alerts) {
        QVariantMap row = v.toMap();
        int r = m_tblAlerts->rowCount();
        m_tblAlerts->insertRow(r);

        QString timeStr = row["time"].toString();
        if (timeStr.length() > 16) timeStr = timeStr.mid(11, 5);
        m_tblAlerts->setItem(r, 0, new QTableWidgetItem(timeStr));
        m_tblAlerts->setItem(r, 1, new QTableWidgetItem(row["name"].toString()));

        QString level = row["risk_level"].toString();
        QTableWidgetItem *lvlItem = new QTableWidgetItem(level == "high" ? "高危" : "中危");
        lvlItem->setForeground(level == "high" ? QColor("#ef5350") : QColor("#ff9800"));
        lvlItem->setTextAlignment(Qt::AlignCenter);
        m_tblAlerts->setItem(r, 2, lvlItem);

        QString status = row["status"].toString();
        QTableWidgetItem *stItem = new QTableWidgetItem(status);
        stItem->setForeground(status == "已隔离" ? QColor("#4caf50") : QColor("#ff9800"));
        stItem->setTextAlignment(Qt::AlignCenter);
        m_tblAlerts->setItem(r, 3, stItem);
    }
}

void DashboardPage::updateSystemInfo()
{
    auto *db = DatabaseManager::instance();
    QVariantMap stats = db->queryDashboardStats();

    m_lblOS->setText(stats.value("os", "--").toString());
    m_lblHost->setText(stats.value("hostname", "--").toString());
    m_lblVersion->setText(stats.value("version", "V3.0.20251120").toString());
    m_lblDbVer->setText(stats.value("db_version", "--").toString() + "（最新）");
    m_lblAuthStatus->setText("<span style='color:#4caf50;font-weight:bold;'>正式授权</span>");
    m_lblAuthExpiry->setText(db->getSetting("auth_expiry", "2026-12-31"));

    // 上次扫描时间：取最新静态检测记录
    QVariantList files = db->queryStaticScanFiles();
    if (!files.isEmpty()) {
        QString lastTime = files.last().toMap().value("scan_time", "--").toString();
        if (lastTime.length() > 16) lastTime = lastTime.left(16);
        m_lblLastScan->setText(lastTime);
    } else {
        m_lblLastScan->setText("尚未扫描");
    }
}
