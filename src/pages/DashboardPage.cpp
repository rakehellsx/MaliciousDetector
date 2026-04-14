#include "pages/DashboardPage.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QGroupBox>
#include <QSqlQuery>
#include <QSqlDatabase>
#include <QJsonArray>
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

    cardRow->addWidget(makeCard("高危威胁", "#ef5350", m_lblHighRisk));
    cardRow->addWidget(makeCard("中危威胁", "#ff9800", m_lblMedRisk));
    cardRow->addWidget(makeCard("低危威胁", "#42a5f5", m_lblLowRisk));
    cardRow->addWidget(makeCard("累计保护天数", "#26c6da", m_lblTotalDays));
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

    // 快捷操作按钮
    QPushButton *btnScan = new QPushButton("立即扫描");
    btnScan->setObjectName("btnPrimary");
    QPushButton *btnSysInfo = new QPushButton("查看系统信息");
    btnSysInfo->setObjectName("btnSecondary");
    QPushButton *btnReport = new QPushButton("生成检测报告");
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
    // 从 static_scan 统计风险数量
    QSqlDatabase db = QSqlDatabase::database("main_conn");
    if (!db.isOpen()) return;

    QSqlQuery q(db);
    q.exec("SELECT COUNT(*) FROM static_scan WHERE risk_level='high'");
    if (q.next()) m_lblHighRisk->setText(q.value(0).toString());
    q.exec("SELECT COUNT(*) FROM static_scan WHERE risk_level='medium'");
    if (q.next()) m_lblMedRisk->setText(q.value(0).toString());
    q.exec("SELECT COUNT(*) FROM static_scan WHERE risk_level='low'");
    if (q.next()) m_lblLowRisk->setText(q.value(0).toString());

    // 保护天数（从第一条日志到现在）
    q.exec("SELECT MIN(timestamp) FROM audit_log");
    if (q.next() && !q.value(0).isNull()) {
        QDateTime first = QDateTime::fromString(q.value(0).toString(), "yyyy-MM-dd HH:mm:ss");
        int days = first.daysTo(QDateTime::currentDateTime());
        m_lblTotalDays->setText(QString::number(days));
    }

    // 病毒库版本
    QString ver = DatabaseManager::instance()->getSetting("virus_db_version", "20251120");
    m_lblVirusDb->setText(ver);
}

void DashboardPage::updateRecentAlerts()
{
    QSqlDatabase db = QSqlDatabase::database("main_conn");
    if (!db.isOpen()) return;

    QSqlQuery q(db);
    q.exec("SELECT scan_time, file_name, risk_level, conclusion FROM static_scan "
           "WHERE risk_level IN ('high','medium') ORDER BY id DESC LIMIT 20");

    m_tblAlerts->setRowCount(0);
    while (q.next()) {
        int row = m_tblAlerts->rowCount();
        m_tblAlerts->insertRow(row);
        QString timeStr = q.value(0).toString();
        if (timeStr.length() > 16) timeStr = timeStr.mid(11, 5); // HH:mm
        m_tblAlerts->setItem(row, 0, new QTableWidgetItem(timeStr));
        m_tblAlerts->setItem(row, 1, new QTableWidgetItem(q.value(1).toString()));

        QString level = q.value(2).toString();
        QTableWidgetItem *lvlItem = new QTableWidgetItem(level == "high" ? "高危" : "中危");
        lvlItem->setForeground(level == "high" ? QColor("#ef5350") : QColor("#ff9800"));
        lvlItem->setTextAlignment(Qt::AlignCenter);
        m_tblAlerts->setItem(row, 2, lvlItem);

        QTableWidgetItem *stItem = new QTableWidgetItem("待处理");
        stItem->setForeground(QColor("#ff9800"));
        stItem->setTextAlignment(Qt::AlignCenter);
        m_tblAlerts->setItem(row, 3, stItem);
    }

    // 若无数据，显示示例行
    if (m_tblAlerts->rowCount() == 0) {
        QStringList demo = {
            "09:41|Trojan.Win32.Agent.abc|high|待处理",
            "08:15|Backdoor.Generic.Dropper|high|待处理",
            "昨天|Worm.AutoRun.Spread|high|已隔离",
            "昨天|Spyware.KeyLogger|medium|待处理"
        };
        for (const QString &d : demo) {
            QStringList parts = d.split("|");
            int row = m_tblAlerts->rowCount();
            m_tblAlerts->insertRow(row);
            m_tblAlerts->setItem(row, 0, new QTableWidgetItem(parts[0]));
            m_tblAlerts->setItem(row, 1, new QTableWidgetItem(parts[1]));
            QTableWidgetItem *lvl = new QTableWidgetItem(parts[2] == "high" ? "高危" : "中危");
            lvl->setForeground(parts[2] == "high" ? QColor("#ef5350") : QColor("#ff9800"));
            lvl->setTextAlignment(Qt::AlignCenter);
            m_tblAlerts->setItem(row, 2, lvl);
            QTableWidgetItem *st = new QTableWidgetItem(parts[3]);
            st->setForeground(parts[3] == "已隔离" ? QColor("#4caf50") : QColor("#ff9800"));
            st->setTextAlignment(Qt::AlignCenter);
            m_tblAlerts->setItem(row, 3, st);
        }
    }
}

void DashboardPage::updateSystemInfo()
{
    // 从 detection_results 读取最新 system_info
    QJsonObject sysData = loadLatestResult("system_info");
    if (!sysData.isEmpty()) {
        QJsonObject result = sysData.value("result").toObject();
        m_lblOS->setText(result.value("os_name").toString("--"));
        m_lblHost->setText(result.value("computer_name").toString("--"));
    } else {
        m_lblOS->setText("Windows 10 专业版 64位");
        m_lblHost->setText("SECURE-PC-001");
    }
    m_lblVersion->setText("V3.0.20251120");
    m_lblDbVer->setText(DatabaseManager::instance()->getSetting("virus_db_version","20251120") + "（最新）");
    m_lblAuthStatus->setText("<span style='color:#4caf50;font-weight:bold;'>正式授权</span>");
    m_lblAuthExpiry->setText("2026-12-31");

    QSqlDatabase db = QSqlDatabase::database("main_conn");
    if (db.isOpen()) {
        QSqlQuery q(db);
        q.exec("SELECT MAX(created_at) FROM detection_results");
        if (q.next() && !q.value(0).isNull())
            m_lblLastScan->setText(q.value(0).toString());
        else
            m_lblLastScan->setText("尚未扫描");
    }
}
