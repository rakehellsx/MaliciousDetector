#include "pages/ScheduledTaskPage.h"
#include "DatabaseManager.h"
#include <QJsonArray>
#include <QJsonDocument>
#include <QHeaderView>
#include <QLabel>
#include <QVBoxLayout>
#include <QDateTime>
#include <QFont>

ScheduledTaskPage::ScheduledTaskPage(QWidget *parent)
    : BasePage("计划任务", parent)
{
    setupUi();
    refreshData();
}

void ScheduledTaskPage::setupUi()
{
    m_tbl = new QTableWidget(0, 7);
    m_tbl->setHorizontalHeaderLabels({"任务名称", "路径", "触发条件", "执行程序", "状态", "上次运行", "风险"});
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

    m_lblSummary = new QLabel;
    m_lblSummary->setStyleSheet("font-size:11px;color:#8c8c8c;padding:3px 2px;");

    m_mainLayout->addWidget(m_tbl);
    m_mainLayout->addWidget(m_lblSummary);
}

void ScheduledTaskPage::refreshData()
{
    QJsonObject data;
    if (m_loader && m_loader->isLoaded()) {
        data = m_loader->getScheduledTasks();
        DatabaseManager::instance()->saveScanResult("scheduled_tasks", "{}", QJsonDocument(data).toJson());
    } else {
        data = loadLatestResult("scheduled_tasks");
        if (!data.isEmpty()) data = data.value("result").toObject();
    }

    if (data.isEmpty()) {
        data = QJsonDocument::fromJson(R"({
            "tasks": [
                {"name":"MicrosoftEdgeUpdateTask","path":"\\Microsoft\\Edge\\","trigger":"每天 06:00","action":"C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe","status":"就绪","last_run":"2025-11-20","risk":"low"},
                {"name":"UpdateTask","path":"\\","trigger":"每5分钟","action":"C:\\Windows\\Temp\\payload.exe","status":"就绪","last_run":"2025-11-20 09:40","risk":"high"},
                {"name":"GoogleUpdateTask","path":"\\Google\\","trigger":"每天 09:00","action":"C:\\Program Files\\Google\\Update\\GoogleUpdate.exe","status":"就绪","last_run":"2025-11-20","risk":"low"},
                {"name":"WindowsDefender","path":"\\Microsoft\\Windows\\","trigger":"空闲时","action":"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MsMpEng.exe","status":"已禁用","last_run":"—","risk":"medium"}
            ]
        })").object();
    }

    m_tbl->setRowCount(0);
    QJsonArray tasks = data.value("tasks").toArray();
    int highCount = 0;

    for (const QJsonValue &v : tasks) {
        QJsonObject t = v.toObject();
        int row = m_tbl->rowCount();
        m_tbl->insertRow(row);

        m_tbl->setItem(row, 0, new QTableWidgetItem(t.value("name").toString()));

        QTableWidgetItem *pathItem = new QTableWidgetItem(t.value("path").toString());
        pathItem->setFont(QFont("Consolas", 11));
        m_tbl->setItem(row, 1, pathItem);

        m_tbl->setItem(row, 2, new QTableWidgetItem(t.value("trigger").toString()));

        QTableWidgetItem *actionItem = new QTableWidgetItem(t.value("action").toString());
        actionItem->setFont(QFont("Consolas", 11));
        m_tbl->setItem(row, 3, actionItem);

        QString status = t.value("status").toString();
        QTableWidgetItem *statusItem = new QTableWidgetItem(status);
        if (status == "就绪") statusItem->setForeground(QColor("#52c41a"));
        else if (status == "运行中") statusItem->setForeground(QColor("#1890ff"));
        else statusItem->setForeground(QColor("#8c8c8c"));
        m_tbl->setItem(row, 4, statusItem);

        m_tbl->setItem(row, 5, new QTableWidgetItem(t.value("last_run").toString()));

        QString risk = t.value("risk").toString("low");
        QString riskText = (risk == "high") ? "高危（可疑）" : (risk == "medium") ? "注意" : "正常";
        QTableWidgetItem *riskItem = new QTableWidgetItem(riskText);
        QFont rf = riskItem->font(); rf.setBold(true); riskItem->setFont(rf);
        if (risk == "high") {
            riskItem->setForeground(QColor("#f5222d"));
            highCount++;
            for (int c = 0; c < 7; c++)
                if (m_tbl->item(row, c)) m_tbl->item(row, c)->setBackground(QColor("#fff1f0"));
        } else if (risk == "medium") {
            riskItem->setForeground(QColor("#fa8c16"));
            for (int c = 0; c < 7; c++)
                if (m_tbl->item(row, c)) m_tbl->item(row, c)->setBackground(QColor("#fffbe6"));
        } else {
            riskItem->setForeground(QColor("#52c41a"));
        }
        m_tbl->setItem(row, 6, riskItem);
    }

    QString summary = QString("共 %1 条").arg(tasks.size());
    if (highCount > 0) summary += QString(" ｜ %1 条高危任务").arg(highCount);
    m_lblSummary->setText(summary);
    m_lblStatus->setText("已刷新：" + QDateTime::currentDateTime().toString("HH:mm:ss"));
}
