#include "pages/SharedResourcePage.h"
#include "DatabaseManager.h"
#include <QJsonArray>
#include <QJsonDocument>
#include <QHeaderView>
#include <QDateTime>
#include <QFont>

SharedResourcePage::SharedResourcePage(QWidget *parent)
    : BasePage("共享资源", parent)
{
    setupUi();
    refreshData();
}

void SharedResourcePage::setupUi()
{
    m_tbl = new QTableWidget(0, 6);
    m_tbl->setHorizontalHeaderLabels({"共享名称", "种类", "当前连接用户", "映像路径", "权限", "风险"});
    m_tbl->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_tbl->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    m_tbl->verticalHeader()->setVisible(false);
    m_tbl->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_tbl->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_tbl->setAlternatingRowColors(true);
    m_tbl->setStyleSheet(
        "QTableWidget{border:1px solid #d0d7e3;font-size:12px;}"
        "QHeaderView::section{background:#e8ecf4;padding:5px 8px;font-weight:600;border:1px solid #d0d7e3;}"
        "QTableWidget::item{padding:5px 8px;}"
        "QTableWidget::item:alternate{background:#fafbfd;}");
    m_mainLayout->addWidget(m_tbl);
}

void SharedResourcePage::refreshData()
{
    QJsonObject data;
    if (m_loader && m_loader->isLoaded()) {
        data = m_loader->getSharedResources();
        DatabaseManager::instance()->saveScanResult("shared_resources", "{}", QJsonDocument(data).toJson());
    } else {
        data = loadLatestResult("shared_resources");
        if (!data.isEmpty()) data = data.value("result").toObject();
    }

    if (data.isEmpty()) {
        data = QJsonDocument::fromJson(R"({
            "shares": [
                {"name":"ADMIN$","type":"磁盘","current_users":0,"path":"C:\\Windows","permission":"管理员","risk":"low"},
                {"name":"C$","type":"磁盘","current_users":0,"path":"C:\\","permission":"管理员","risk":"low"},
                {"name":"IPC$","type":"IPC","current_users":1,"path":"—","permission":"所有人","risk":"medium"},
                {"name":"SharedDocs","type":"磁盘","current_users":0,"path":"C:\\Users\\Public\\Documents","permission":"所有人","risk":"low"}
            ]
        })").object();
    }

    m_tbl->setRowCount(0);
    QJsonArray shares = data.value("shares").toArray();

    for (const QJsonValue &v : shares) {
        QJsonObject s = v.toObject();
        int row = m_tbl->rowCount();
        m_tbl->insertRow(row);

        m_tbl->setItem(row, 0, new QTableWidgetItem(s.value("name").toString()));
        m_tbl->setItem(row, 1, new QTableWidgetItem(s.value("type").toString()));
        m_tbl->setItem(row, 2, new QTableWidgetItem(QString::number(s.value("current_users").toInt())));

        QTableWidgetItem *pathItem = new QTableWidgetItem(s.value("path").toString());
        pathItem->setFont(QFont("Consolas", 11));
        m_tbl->setItem(row, 3, pathItem);

        m_tbl->setItem(row, 4, new QTableWidgetItem(s.value("permission").toString()));

        QString risk = s.value("risk").toString("low");
        QString riskText = (risk == "high") ? "高危" : (risk == "medium") ? "注意" : "正常";
        QTableWidgetItem *riskItem = new QTableWidgetItem(riskText);
        QFont rf = riskItem->font(); rf.setBold(true); riskItem->setFont(rf);
        if (risk == "high") {
            riskItem->setForeground(QColor("#f5222d"));
            for (int c = 0; c < 6; c++)
                if (m_tbl->item(row, c)) m_tbl->item(row, c)->setBackground(QColor("#fff1f0"));
        } else if (risk == "medium") {
            riskItem->setForeground(QColor("#fa8c16"));
            for (int c = 0; c < 6; c++)
                if (m_tbl->item(row, c)) m_tbl->item(row, c)->setBackground(QColor("#fffbe6"));
        } else {
            riskItem->setForeground(QColor("#52c41a"));
        }
        m_tbl->setItem(row, 5, riskItem);
    }

    m_lblStatus->setText("已刷新：" + QDateTime::currentDateTime().toString("HH:mm:ss"));
}
