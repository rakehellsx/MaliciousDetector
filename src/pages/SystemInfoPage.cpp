#include "pages/SystemInfoPage.h"
#include <QJsonArray>
#include <QHeaderView>

SystemInfoPage::SystemInfoPage(QWidget *parent)
    : BasePage("系统基本信息", parent)
{
    setupUi();
    refreshData();
}

void SystemInfoPage::setupUi()
{
    m_tbl = new QTableWidget(0, 2);
    m_tbl->setHorizontalHeaderLabels({"属性", "值"});
    styleTable(m_tbl);
    m_tbl->setColumnWidth(0, 200);
    m_tbl->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Fixed);
    m_tbl->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_mainLayout->addWidget(m_tbl);
}

// 通用：向KV表添加一行
static void addKVRow(QTableWidget *t, const QString &key, const QString &val)
{
    int row = t->rowCount();
    t->insertRow(row);
    QTableWidgetItem *k = new QTableWidgetItem(key);
    k->setForeground(QColor("#90caf9"));
    t->setItem(row, 0, k);
    t->setItem(row, 1, new QTableWidgetItem(val));
}

void SystemInfoPage::refreshData()
{
    m_tbl->setRowCount(0);

    // 优先从 basic.dll 获取，否则从 SQLite 读取
    QJsonObject data;
    if (m_loader && m_loader->isLoaded()) {
        data = m_loader->getSystemInfo();
        // 同时保存到数据库
        QJsonDocument doc(data);
        DatabaseManager::instance()->saveScanResult("system_info", "{}", doc.toJson());
        DatabaseManager::instance()->writeLog(m_role, m_username, "采集系统信息", "调用GetSystemInfo", "success");
    } else {
        data = loadLatestResult("system_info");
        if (!data.isEmpty()) data = data.value("result").toObject();
    }

    if (data.isEmpty()) {
        // 显示占位提示
        addKVRow(m_tbl, "提示", "暂无数据，请加载 basic.dll 或等待数据写入");
        m_lblStatus->setText("无数据");
        return;
    }

    // 展示各字段
    QStringList keys = {
        "os_name","os_version","os_build","os_arch","install_time",
        "computer_name","domain","workgroup","system_dir","windows_dir",
        "processor","total_memory","free_memory","uptime"
    };
    QStringList labels = {
        "操作系统名称","系统版本","内部版本号","系统架构","安装时间",
        "计算机名称","域名","工作组","系统目录","Windows目录",
        "处理器","总内存","可用内存","运行时长"
    };
    for (int i = 0; i < keys.size(); ++i) {
        QString val = data.value(keys[i]).toString();
        if (!val.isEmpty()) addKVRow(m_tbl, labels[i], val);
    }

    // 账户列表
    QJsonArray accounts = data.value("accounts").toArray();
    for (int i = 0; i < accounts.size(); ++i) {
        QJsonObject acc = accounts[i].toObject();
        addKVRow(m_tbl, QString("账户[%1]").arg(i+1),
                 acc.value("name").toString() + "  " + acc.value("type").toString());
    }

    m_lblStatus->setText("已刷新：" + QDateTime::currentDateTime().toString("HH:mm:ss"));
}
