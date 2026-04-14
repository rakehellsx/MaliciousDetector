#include "pages/BrowserPluginPage.h"
#include "DatabaseManager.h"
#include <QJsonArray>
#include <QJsonDocument>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QComboBox>
#include <QDateTime>
#include <QFont>

BrowserPluginPage::BrowserPluginPage(QWidget *parent)
    : BasePage("浏览器插件", parent)
{
    setupUi();
    refreshData();
}

void BrowserPluginPage::setupUi()
{
    // 筛选工具栏
    QHBoxLayout *filterLayout = new QHBoxLayout;
    filterLayout->setContentsMargins(0,0,0,6);
    QLabel *lblFilter = new QLabel("浏览器：");
    lblFilter->setStyleSheet("font-size:12px;");
    m_cmbBrowser = new QComboBox;
    m_cmbBrowser->addItems({"全部浏览器", "Chrome", "Edge", "Firefox", "IE"});
    m_cmbBrowser->setFixedWidth(130);
    m_cmbBrowser->setStyleSheet("QComboBox{font-size:12px;padding:3px 6px;border:1px solid #d0d7e3;border-radius:3px;}");
    connect(m_cmbBrowser, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &BrowserPluginPage::filterByBrowser);
    filterLayout->addWidget(lblFilter);
    filterLayout->addWidget(m_cmbBrowser);
    filterLayout->addStretch();
    m_mainLayout->insertLayout(0, filterLayout);

    m_tbl = new QTableWidget(0, 7);
    m_tbl->setHorizontalHeaderLabels({"浏览器", "插件名称", "状态", "版本", "修改时间", "路径", "风险"});
    m_tbl->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_tbl->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
    m_tbl->verticalHeader()->setVisible(false);
    m_tbl->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_tbl->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_tbl->setAlternatingRowColors(true);
    m_tbl->setStyleSheet(
        "QTableWidget{border:1px solid #d0d7e3;font-size:12px;}"
        "QHeaderView::section{background:#e8ecf4;padding:5px 8px;font-weight:600;border:1px solid #d0d7e3;}"
        "QTableWidget::item{padding:5px 8px;}"
        "QTableWidget::item:alternate{background:#fafbfd;}");

    m_lblSummary = new QLabel;
    m_lblSummary->setStyleSheet("font-size:11px;color:#8c8c8c;padding:3px 2px;");

    m_mainLayout->addWidget(m_tbl);
    m_mainLayout->addWidget(m_lblSummary);
}

void BrowserPluginPage::refreshData()
{
    QJsonObject data;
    if (m_loader && m_loader->isLoaded()) {
        data = m_loader->getBrowserPlugins();
        DatabaseManager::instance()->saveScanResult("browser_plugins", "{}", QJsonDocument(data).toJson());
    } else {
        data = loadLatestResult("browser_plugins");
        if (!data.isEmpty()) data = data.value("result").toObject();
    }

    if (data.isEmpty()) {
        data = QJsonDocument::fromJson(R"({
            "plugins": [
                {"browser":"Chrome","name":"Google Docs Offline","status":"启用","version":"1.72.0","modified_time":"2025-10-01","path":"C:\\Users\\user01\\AppData\\Local\\Google\\Chrome\\Extensions\\ghbmnnjooekpmoecnnnilnnbdlolhkhi","risk":"low"},
                {"browser":"Chrome","name":"Flash Player Helper","status":"启用","version":"0.1.0","modified_time":"2025-11-18","path":"C:\\Users\\user01\\AppData\\Local\\Google\\Chrome\\Extensions\\aabbccddeeff","risk":"high"},
                {"browser":"Edge","name":"Microsoft Editor","status":"启用","version":"3.0.0","modified_time":"2025-09-15","path":"C:\\Users\\user01\\AppData\\Local\\Microsoft\\Edge\\Extensions\\...","risk":"low"}
            ]
        })").object();
    }

    m_allPlugins = data.value("plugins").toArray();
    populateTable(m_allPlugins);
    m_lblStatus->setText("已刷新：" + QDateTime::currentDateTime().toString("HH:mm:ss"));
}

void BrowserPluginPage::populateTable(const QJsonArray &plugins)
{
    m_tbl->setRowCount(0);
    int highCount = 0;

    for (const QJsonValue &v : plugins) {
        QJsonObject p = v.toObject();
        int row = m_tbl->rowCount();
        m_tbl->insertRow(row);

        m_tbl->setItem(row, 0, new QTableWidgetItem(p.value("browser").toString()));
        m_tbl->setItem(row, 1, new QTableWidgetItem(p.value("name").toString()));

        QString status = p.value("status").toString();
        QTableWidgetItem *statusItem = new QTableWidgetItem(status);
        statusItem->setForeground(status == "启用" ? QColor("#52c41a") : QColor("#8c8c8c"));
        m_tbl->setItem(row, 2, statusItem);

        m_tbl->setItem(row, 3, new QTableWidgetItem(p.value("version").toString()));
        m_tbl->setItem(row, 4, new QTableWidgetItem(p.value("modified_time").toString()));

        QTableWidgetItem *pathItem = new QTableWidgetItem(p.value("path").toString());
        pathItem->setFont(QFont("Consolas", 11));
        m_tbl->setItem(row, 5, pathItem);

        QString risk = p.value("risk").toString("low");
        QString riskText = (risk == "high") ? "高危（伪装插件）" : (risk == "medium") ? "注意" : "正常";
        QTableWidgetItem *riskItem = new QTableWidgetItem(riskText);
        QFont rf = riskItem->font(); rf.setBold(true); riskItem->setFont(rf);
        if (risk == "high") {
            riskItem->setForeground(QColor("#f5222d"));
            highCount++;
            for (int c = 0; c < 7; c++)
                if (m_tbl->item(row, c)) m_tbl->item(row, c)->setBackground(QColor("#fff1f0"));
        } else {
            riskItem->setForeground(QColor("#52c41a"));
        }
        m_tbl->setItem(row, 6, riskItem);
    }

    QString summary = QString("共 %1 个插件").arg(plugins.size());
    if (highCount > 0) summary += QString(" ｜ %1 个可疑插件").arg(highCount);
    m_lblSummary->setText(summary);
}

void BrowserPluginPage::filterByBrowser(int index)
{
    if (index == 0) { populateTable(m_allPlugins); return; }
    QStringList browsers = {"", "Chrome", "Edge", "Firefox", "IE"};
    QString filter = browsers[index];
    QJsonArray filtered;
    for (const QJsonValue &v : m_allPlugins)
        if (v.toObject().value("browser").toString() == filter)
            filtered.append(v);
    populateTable(filtered);
}
