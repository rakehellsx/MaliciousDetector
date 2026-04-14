#include "pages/DashboardPage.h"
#include "DatabaseManager.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QGroupBox>
#include <QScrollArea>

DashboardPage::DashboardPage(QWidget *parent)
    : BasePage("系统概览", parent)
{
    setupUi();
    refreshData();
}

void DashboardPage::setupUi()
{
    // ── 顶部快捷操作按钮 ──────────────────────────────────────
    QHBoxLayout *btnRow = new QHBoxLayout;
    auto makeQuickBtn = [&](const QString &text, const QString &objName) {
        QPushButton *b = new QPushButton(text);
        b->setObjectName(objName);
        b->setFixedHeight(32);
        btnRow->addWidget(b);
    };
    makeQuickBtn("静态检测", "btnQuickStatic");
    makeQuickBtn("动态检测", "btnQuickDynamic");
    makeQuickBtn("生成报告", "btnQuickReport");
    btnRow->addStretch();
    m_mainLayout->addLayout(btnRow);

    // ── 统计卡片行 ────────────────────────────────────────────
    QHBoxLayout *cardRow = new QHBoxLayout;
    cardRow->setSpacing(12);

    auto makeCard = [&](const QString &label, const QString &color,
                        QLabel *&valLbl) -> QWidget* {
        QWidget *card = new QWidget;
        card->setObjectName("statCard");
        card->setFixedHeight(80);
        card->setStyleSheet(QString("QWidget#statCard{background:#1a2a3e;border:1px solid #2a4a6e;border-radius:4px;}"
                                    "QWidget#statCard:hover{border:1px solid %1;}").arg(color));
        QVBoxLayout *cl = new QVBoxLayout(card);
        cl->setAlignment(Qt::AlignCenter);
        valLbl = new QLabel("0");
        valLbl->setAlignment(Qt::AlignCenter);
        valLbl->setStyleSheet(QString("font-size:28px;font-weight:bold;color:%1;").arg(color));
        QLabel *nameLbl = new QLabel(label);
        nameLbl->setAlignment(Qt::AlignCenter);
        nameLbl->setStyleSheet("font-size:12px;color:#90caf9;");
        cl->addWidget(valLbl);
        cl->addWidget(nameLbl);
        return card;
    };

    cardRow->addWidget(makeCard("高危威胁",   "#ef5350", m_lblHighRisk));
    cardRow->addWidget(makeCard("中危威胁",   "#ff9800", m_lblMedRisk));
    cardRow->addWidget(makeCard("低危威胁",   "#42a5f5", m_lblLowRisk));
    cardRow->addWidget(makeCard("累计保护天数","#26c6da", m_lblTotalDays));
    cardRow->addWidget(makeCard("病毒库版本", "#66bb6a", m_lblVirusDb));
    m_mainLayout->addLayout(cardRow);

    // ── 中部：告警列表 + 系统信息 ────────────────────────────
    QHBoxLayout *midRow = new QHBoxLayout;
    midRow->setSpacing(12);

    // 左：最新告警
    QGroupBox *alertBox = new QGroupBox("最新告警");
    alertBox->setObjectName("dashGroup");
    QVBoxLayout *alertLay = new QVBoxLayout(alertBox);
    m_tblAlerts = new QTableWidget(0, 4);
    m_tblAlerts->setHorizontalHeaderLabels({"时间", "威胁名称", "等级", "状态"});
    styleTable(m_tblAlerts);
    m_tblAlerts->setColumnWidth(0, 80);
    m_tblAlerts->setColumnWidth(2, 60);
    m_tblAlerts->setColumnWidth(3, 70);
    alertLay->addWidget(m_tblAlerts);
    midRow->addWidget(alertBox, 3);

    // 右：系统信息
    QGroupBox *sysBox = new QGroupBox("系统信息");
    sysBox->setObjectName("dashGroup");
    QVBoxLayout *sysLay = new QVBoxLayout(sysBox);
    auto makeKV = [&](const QString &key, QLabel *&valLbl) {
        QHBoxLayout *row = new QHBoxLayout;
        QLabel *kLbl = new QLabel(key);
        kLbl->setObjectName("kvKey");
        kLbl->setFixedWidth(90);
        valLbl = new QLabel("--");
        valLbl->setObjectName("kvVal");
        row->addWidget(kLbl);
        row->addWidget(valLbl, 1);
        sysLay->addLayout(row);
    };
    makeKV("操作系统",   m_lblOS);
    makeKV("主机名称",   m_lblHost);
    makeKV("产品版本",   m_lblVersion);
    makeKV("病毒库",     m_lblDbVer);
    makeKV("授权状态",   m_lblAuthStatus);
    makeKV("授权到期",   m_lblAuthExpiry);
    makeKV("上次扫描",   m_lblLastScan);
    sysLay->addStretch();

    QPushButton *btnScan   = new QPushButton("立即扫描");
    btnScan->setObjectName("btnPrimary");
    QPushButton *btnSysInfo = new QPushButton("查看系统信息");
    btnSysInfo->setObjectName("btnSecondary");
    QPushButton *btnReport  = new QPushButton("生成检测报告");
    btnReport->setObjectName("btnSecondary");
    sysLay->addWidget(btnScan);
    sysLay->addWidget(btnSysInfo);
    sysLay->addWidget(btnReport);
    midRow->addWidget(sysBox, 2);

    m_mainLayout->addLayout(midRow, 1);
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
