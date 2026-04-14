#include "pages/AutorunPage.h"
#include "DatabaseManager.h"
#include <QJsonArray>
#include <QJsonDocument>
#include <QVBoxLayout>
#include <QHeaderView>
#include <QDateTime>
#include <QFont>

static QTableWidget* makeTable(const QStringList &headers) {
    QTableWidget *t = new QTableWidget(0, headers.size());
    t->setHorizontalHeaderLabels(headers);
    t->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    t->horizontalHeader()->setStretchLastSection(true);
    t->verticalHeader()->setVisible(false);
    t->setEditTriggers(QAbstractItemView::NoEditTriggers);
    t->setSelectionBehavior(QAbstractItemView::SelectRows);
    t->setAlternatingRowColors(true);
    t->setStyleSheet(
        "QTableWidget{border:1px solid #d0d7e3;font-size:12px;}"
        "QHeaderView::section{background:#e8ecf4;padding:5px 8px;font-weight:600;border:1px solid #d0d7e3;}"
        "QTableWidget::item{padding:5px 8px;}"
        "QTableWidget::item:alternate{background:#fafbfd;}");
    return t;
}

static void setRiskItem(QTableWidget *t, int row, int col, const QString &text, const QString &level) {
    QTableWidgetItem *item = new QTableWidgetItem(text);
    QFont f = item->font(); f.setBold(true); item->setFont(f);
    if (level == "high") {
        item->setForeground(QColor("#f5222d"));
        for (int c = 0; c < t->columnCount(); c++)
            if (t->item(row, c)) t->item(row, c)->setBackground(QColor("#fff1f0"));
    } else if (level == "medium") {
        item->setForeground(QColor("#fa8c16"));
        for (int c = 0; c < t->columnCount(); c++)
            if (t->item(row, c)) t->item(row, c)->setBackground(QColor("#fffbe6"));
    } else {
        item->setForeground(QColor("#52c41a"));
    }
    t->setItem(row, col, item);
}

AutorunPage::AutorunPage(QWidget *parent)
    : BasePage("自启动项", parent)
{
    setupUi();
    refreshData();
}

void AutorunPage::setupUi()
{
    m_tabs = new QTabWidget;
    m_tabs->setStyleSheet(
        "QTabWidget::pane{border:1px solid #d0d7e3;}"
        "QTabBar::tab{padding:6px 16px;font-size:12px;background:#f0f3fa;border:1px solid #d0d7e3;}"
        "QTabBar::tab:selected{background:#fff;color:#1a3a6a;font-weight:600;border-bottom:2px solid #1a3a6a;}");

    // Tab1: 注册表启动项
    QWidget *wReg = new QWidget;
    QVBoxLayout *lReg = new QVBoxLayout(wReg);
    lReg->setContentsMargins(4,8,4,4);
    m_tblReg = makeTable({"名称","注册表路径","值（执行路径）","发行商","授信状态","风险"});
    m_lblRegSummary = new QLabel;
    m_lblRegSummary->setStyleSheet("font-size:11px;color:#8c8c8c;padding:3px 2px;");
    lReg->addWidget(m_tblReg);
    lReg->addWidget(m_lblRegSummary);
    m_tabs->addTab(wReg, "注册表启动项");

    // Tab2: 启动文件夹
    QWidget *wFolder = new QWidget;
    QVBoxLayout *lFolder = new QVBoxLayout(wFolder);
    lFolder->setContentsMargins(4,8,4,4);
    m_tblFolder = makeTable({"文件名","路径","发行商","风险"});
    lFolder->addWidget(m_tblFolder);
    m_tabs->addTab(wFolder, "启动文件夹");

    // Tab3: 右键菜单
    QWidget *wRight = new QWidget;
    QVBoxLayout *lRight = new QVBoxLayout(wRight);
    lRight->setContentsMargins(4,8,4,4);
    m_tblRightClick = makeTable({"菜单项","注册表路径","命令","风险"});
    lRight->addWidget(m_tblRightClick);
    m_tabs->addTab(wRight, "右键菜单");

    // Tab4: 系统调试器（IFEO）
    QWidget *wDbg = new QWidget;
    QVBoxLayout *lDbg = new QVBoxLayout(wDbg);
    lDbg->setContentsMargins(4,8,4,4);
    m_tblDebugger = makeTable({"目标程序","调试器路径","风险"});
    lDbg->addWidget(m_tblDebugger);
    m_tabs->addTab(wDbg, "系统调试器（IFEO）");

    m_mainLayout->addWidget(m_tabs);
}

void AutorunPage::refreshData()
{
    QJsonObject data;
    if (m_loader && m_loader->isLoaded()) {
        data = m_loader->getAutorunInfo();
        DatabaseManager::instance()->saveScanResult("autorun_info", "{}", QJsonDocument(data).toJson());
    } else {
        data = loadLatestResult("autorun_info");
        if (!data.isEmpty()) data = data.value("result").toObject();
    }

    if (data.isEmpty()) {
        data = QJsonDocument::fromJson(R"({
            "reg_items": [
                {"name":"OneDrive","reg_path":"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run","value":"C:\\Users\\user01\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe","publisher":"Microsoft","is_trusted":true,"risk":"low"},
                {"name":"WindowsUpdate","reg_path":"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run","value":"C:\\Windows\\Temp\\svchost32.exe -s","publisher":"未知","is_trusted":false,"risk":"high"},
                {"name":"SecurityHealth","reg_path":"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run","value":"C:\\Windows\\System32\\SecurityHealthSystray.exe","publisher":"Microsoft","is_trusted":true,"risk":"low"}
            ],
            "folder_items": [
                {"name":"desktop.ini","path":"C:\\Users\\user01\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup","publisher":"Microsoft","risk":"low"}
            ],
            "rightclick_items": [
                {"menu":"Open with Notepad","reg_path":"HKCR\\*\\shell\\Open with Notepad","command":"notepad.exe %1","risk":"low"}
            ],
            "debugger_items": []
        })").object();
    }

    populateRegTab(data.value("reg_items").toArray());
    populateFolderTab(data.value("folder_items").toArray());
    populateRightClickTab(data.value("rightclick_items").toArray());
    populateDebuggerTab(data.value("debugger_items").toArray());

    m_lblStatus->setText("已刷新：" + QDateTime::currentDateTime().toString("HH:mm:ss"));
}

void AutorunPage::populateRegTab(const QJsonArray &items)
{
    m_tblReg->setRowCount(0);
    int highCount = 0;
    for (const QJsonValue &v : items) {
        QJsonObject a = v.toObject();
        int row = m_tblReg->rowCount();
        m_tblReg->insertRow(row);
        m_tblReg->setItem(row, 0, new QTableWidgetItem(a.value("name").toString()));
        QTableWidgetItem *regItem = new QTableWidgetItem(a.value("reg_path").toString());
        regItem->setFont(QFont("Consolas", 11));
        m_tblReg->setItem(row, 1, regItem);
        QTableWidgetItem *valItem = new QTableWidgetItem(a.value("value").toString());
        valItem->setFont(QFont("Consolas", 11));
        m_tblReg->setItem(row, 2, valItem);
        m_tblReg->setItem(row, 3, new QTableWidgetItem(a.value("publisher").toString()));
        bool trusted = a.value("is_trusted").toBool(true);
        QTableWidgetItem *ti = new QTableWidgetItem(trusted ? "已签名" : "未签名");
        ti->setForeground(trusted ? QColor("#52c41a") : QColor("#f5222d"));
        QFont tf = ti->font(); tf.setBold(true); ti->setFont(tf);
        m_tblReg->setItem(row, 4, ti);
        QString risk = a.value("risk").toString("low");
        QString riskText = (risk == "high") ? "高危（持久化）" : (risk == "medium") ? "注意" : "正常";
        if (risk == "high") highCount++;
        setRiskItem(m_tblReg, row, 5, riskText, risk);
    }
    QString summary = QString("共 %1 条").arg(items.size());
    if (highCount > 0)
        summary += QString(" ｜ %1 条高危项").arg(highCount);
    m_lblRegSummary->setText(summary);
}

void AutorunPage::populateFolderTab(const QJsonArray &items)
{
    m_tblFolder->setRowCount(0);
    for (const QJsonValue &v : items) {
        QJsonObject a = v.toObject();
        int row = m_tblFolder->rowCount();
        m_tblFolder->insertRow(row);
        m_tblFolder->setItem(row, 0, new QTableWidgetItem(a.value("name").toString()));
        QTableWidgetItem *pathItem = new QTableWidgetItem(a.value("path").toString());
        pathItem->setFont(QFont("Consolas", 11));
        m_tblFolder->setItem(row, 1, pathItem);
        m_tblFolder->setItem(row, 2, new QTableWidgetItem(a.value("publisher").toString()));
        QString risk = a.value("risk").toString("low");
        QString riskText = (risk == "high") ? "高危" : (risk == "medium") ? "注意" : "正常";
        setRiskItem(m_tblFolder, row, 3, riskText, risk);
    }
    if (m_tblFolder->rowCount() == 0) {
        m_tblFolder->insertRow(0);
        QTableWidgetItem *empty = new QTableWidgetItem("未检测到启动文件夹项");
        empty->setForeground(QColor("#8c8c8c"));
        empty->setTextAlignment(Qt::AlignCenter);
        m_tblFolder->setItem(0, 0, empty);
        m_tblFolder->setSpan(0, 0, 1, 4);
    }
}

void AutorunPage::populateRightClickTab(const QJsonArray &items)
{
    m_tblRightClick->setRowCount(0);
    for (const QJsonValue &v : items) {
        QJsonObject a = v.toObject();
        int row = m_tblRightClick->rowCount();
        m_tblRightClick->insertRow(row);
        m_tblRightClick->setItem(row, 0, new QTableWidgetItem(a.value("menu").toString()));
        QTableWidgetItem *regItem = new QTableWidgetItem(a.value("reg_path").toString());
        regItem->setFont(QFont("Consolas", 11));
        m_tblRightClick->setItem(row, 1, regItem);
        QTableWidgetItem *cmdItem = new QTableWidgetItem(a.value("command").toString());
        cmdItem->setFont(QFont("Consolas", 11));
        m_tblRightClick->setItem(row, 2, cmdItem);
        QString risk = a.value("risk").toString("low");
        QString riskText = (risk == "high") ? "高危" : (risk == "medium") ? "注意" : "正常";
        setRiskItem(m_tblRightClick, row, 3, riskText, risk);
    }
}

void AutorunPage::populateDebuggerTab(const QJsonArray &items)
{
    m_tblDebugger->setRowCount(0);
    for (const QJsonValue &v : items) {
        QJsonObject a = v.toObject();
        int row = m_tblDebugger->rowCount();
        m_tblDebugger->insertRow(row);
        m_tblDebugger->setItem(row, 0, new QTableWidgetItem(a.value("target").toString()));
        QTableWidgetItem *dbgItem = new QTableWidgetItem(a.value("debugger").toString());
        dbgItem->setFont(QFont("Consolas", 11));
        m_tblDebugger->setItem(row, 1, dbgItem);
        QString risk = a.value("risk").toString("high");
        QString riskText = (risk == "high") ? "高危（IFEO劫持）" : "注意";
        setRiskItem(m_tblDebugger, row, 2, riskText, risk);
    }
    if (m_tblDebugger->rowCount() == 0) {
        m_tblDebugger->insertRow(0);
        QTableWidgetItem *empty = new QTableWidgetItem("未检测到系统调试器（IFEO）劫持项");
        empty->setForeground(QColor("#8c8c8c"));
        empty->setTextAlignment(Qt::AlignCenter);
        m_tblDebugger->setItem(0, 0, empty);
        m_tblDebugger->setSpan(0, 0, 1, 3);
    }
}
