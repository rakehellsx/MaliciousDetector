#include "pages/DriverInfoPage.h"
#include "DatabaseManager.h"
#include <QJsonArray>
#include <QJsonDocument>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QComboBox>
#include <QDateTime>
#include <QFont>

DriverInfoPage::DriverInfoPage(QWidget *parent)
    : BasePage("驱动信息", parent)
{
    setupUi();
    refreshData();
}

void DriverInfoPage::setupUi()
{
    // 筛选工具栏
    QHBoxLayout *filterLayout = new QHBoxLayout;
    filterLayout->setContentsMargins(0,0,0,6);
    QLabel *lblFilter = new QLabel("类型筛选：");
    lblFilter->setStyleSheet("font-size:12px;");
    m_cmbType = new QComboBox;
    m_cmbType->addItems({"全部类型", "实体硬件", "虚拟硬件"});
    m_cmbType->setFixedWidth(120);
    m_cmbType->setStyleSheet("QComboBox{font-size:12px;padding:3px 6px;border:1px solid #d0d7e3;border-radius:3px;}");
    connect(m_cmbType, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &DriverInfoPage::filterByType);
    filterLayout->addWidget(lblFilter);
    filterLayout->addWidget(m_cmbType);
    filterLayout->addStretch();
    m_mainLayout->insertLayout(0, filterLayout);

    m_tbl = new QTableWidget(0, 7);
    m_tbl->setHorizontalHeaderLabels({"驱动名称", "类型", "发行商", "修改时间", "映像路径", "授信状态", "风险"});
    m_tbl->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_tbl->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
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

void DriverInfoPage::refreshData()
{
    QJsonObject data;
    if (m_loader && m_loader->isLoaded()) {
        data = m_loader->getDriverInfo();
        DatabaseManager::instance()->saveScanResult("driver_info", "{}", QJsonDocument(data).toJson());
    } else {
        data = loadLatestResult("driver_info");
        if (!data.isEmpty()) data = data.value("result").toObject();
    }

    if (data.isEmpty()) {
        data = QJsonDocument::fromJson(R"({
            "drivers": [
                {"name":"ntfs.sys","type":"实体硬件","publisher":"Microsoft","modified_time":"2024-01-15","image_path":"C:\\Windows\\System32\\drivers\\ntfs.sys","is_trusted":true,"risk":"low"},
                {"name":"tcpip.sys","type":"虚拟硬件","publisher":"Microsoft","modified_time":"2024-01-15","image_path":"C:\\Windows\\System32\\drivers\\tcpip.sys","is_trusted":true,"risk":"low"},
                {"name":"hiddrv.sys","type":"虚拟硬件","publisher":"未知","modified_time":"2025-11-18","image_path":"C:\\Windows\\System32\\drivers\\hiddrv.sys","is_trusted":false,"risk":"high"},
                {"name":"vmbus.sys","type":"虚拟硬件","publisher":"Microsoft","modified_time":"2024-01-15","image_path":"C:\\Windows\\System32\\drivers\\vmbus.sys","is_trusted":true,"risk":"low"}
            ]
        })").object();
    }

    m_allDrivers = data.value("drivers").toArray();
    populateTable(m_allDrivers);
    m_lblStatus->setText("已刷新：" + QDateTime::currentDateTime().toString("HH:mm:ss"));
}

void DriverInfoPage::populateTable(const QJsonArray &drivers)
{
    m_tbl->setRowCount(0);
    int highCount = 0;

    for (const QJsonValue &v : drivers) {
        QJsonObject d = v.toObject();
        int row = m_tbl->rowCount();
        m_tbl->insertRow(row);

        m_tbl->setItem(row, 0, new QTableWidgetItem(d.value("name").toString()));
        m_tbl->setItem(row, 1, new QTableWidgetItem(d.value("type").toString()));

        QString publisher = d.value("publisher").toString();
        QTableWidgetItem *pubItem = new QTableWidgetItem(publisher);
        if (publisher == "未知") pubItem->setForeground(QColor("#f5222d"));
        m_tbl->setItem(row, 2, pubItem);

        m_tbl->setItem(row, 3, new QTableWidgetItem(d.value("modified_time").toString()));

        QTableWidgetItem *pathItem = new QTableWidgetItem(d.value("image_path").toString());
        pathItem->setFont(QFont("Consolas", 11));
        m_tbl->setItem(row, 4, pathItem);

        bool trusted = d.value("is_trusted").toBool(true);
        QTableWidgetItem *ti = new QTableWidgetItem(trusted ? "已签名" : "未签名");
        ti->setForeground(trusted ? QColor("#52c41a") : QColor("#f5222d"));
        QFont tf = ti->font(); tf.setBold(true); ti->setFont(tf);
        m_tbl->setItem(row, 5, ti);

        QString risk = d.value("risk").toString("low");
        QString riskText = (risk == "high") ? "高危（Rootkit）" : (risk == "medium") ? "注意" : "正常";
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

    QString summary = QString("共 %1 条").arg(drivers.size());
    if (highCount > 0) summary += QString(" ｜ %1 条高危驱动").arg(highCount);
    m_lblSummary->setText(summary);
}

void DriverInfoPage::filterByType(int index)
{
    if (index == 0) {
        populateTable(m_allDrivers);
        return;
    }
    QString typeFilter = (index == 1) ? "实体硬件" : "虚拟硬件";
    QJsonArray filtered;
    for (const QJsonValue &v : m_allDrivers) {
        if (v.toObject().value("type").toString() == typeFilter)
            filtered.append(v);
    }
    populateTable(filtered);
}
