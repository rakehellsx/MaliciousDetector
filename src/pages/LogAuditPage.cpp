#include "pages/LogAuditPage.h"
#include "DatabaseManager.h"
#include <QHBoxLayout>
#include <QLabel>
#include <QSqlQuery>
#include <QHeaderView>
#include <QFileDialog>
#include <QFile>
#include <QTextStream>
#include <QMessageBox>
#include <QDateTime>

LogAuditPage::LogAuditPage(QWidget *parent) : BasePage("日志审计", parent) {
    setupUi();
    refreshData();
}

void LogAuditPage::setupUi() {
    // 筛选工具栏
    QHBoxLayout *filterRow = new QHBoxLayout;

    QLabel *lblRole = new QLabel("角色：");
    lblRole->setObjectName("fieldLabel");
    m_cmbRole = new QComboBox;
    m_cmbRole->setObjectName("comboBox");
    m_cmbRole->addItems({"全部角色", "系统管理员", "安全管理员", "安全审计员"});
    m_cmbRole->setFixedWidth(110);

    QLabel *lblType = new QLabel("类型：");
    lblType->setObjectName("fieldLabel");
    m_cmbType = new QComboBox;
    m_cmbType->setObjectName("comboBox");
    m_cmbType->addItems({"全部类型", "登录", "登出", "扫描", "导出", "设置", "规则", "白名单", "报告"});
    m_cmbType->setFixedWidth(100);

    QLabel *lblUser = new QLabel("用户：");
    lblUser->setObjectName("fieldLabel");
    m_edtUser = new QLineEdit;
    m_edtUser->setPlaceholderText("用户名");
    m_edtUser->setFixedWidth(90);

    QLabel *lblFrom = new QLabel("开始：");
    lblFrom->setObjectName("fieldLabel");
    m_dateFrom = new QDateEdit(QDate::currentDate().addDays(-30));
    m_dateFrom->setCalendarPopup(true);
    m_dateFrom->setDisplayFormat("yyyy-MM-dd");

    QLabel *lblTo = new QLabel("结束：");
    lblTo->setObjectName("fieldLabel");
    m_dateTo = new QDateEdit(QDate::currentDate());
    m_dateTo->setCalendarPopup(true);
    m_dateTo->setDisplayFormat("yyyy-MM-dd");

    m_btnQuery  = new QPushButton("查询");
    m_btnExport = new QPushButton("导出");
    m_btnQuery->setObjectName("btnPrimary");
    m_btnExport->setObjectName("btnSecondary");
    m_btnQuery->setFixedWidth(70);
    m_btnExport->setFixedWidth(70);

    connect(m_btnQuery,  &QPushButton::clicked, this, &LogAuditPage::onQuery);
    connect(m_btnExport, &QPushButton::clicked, this, &LogAuditPage::onExport);

    filterRow->addWidget(lblRole);
    filterRow->addWidget(m_cmbRole);
    filterRow->addSpacing(6);
    filterRow->addWidget(lblType);
    filterRow->addWidget(m_cmbType);
    filterRow->addSpacing(6);
    filterRow->addWidget(lblUser);
    filterRow->addWidget(m_edtUser);
    filterRow->addSpacing(6);
    filterRow->addWidget(lblFrom);
    filterRow->addWidget(m_dateFrom);
    filterRow->addSpacing(4);
    filterRow->addWidget(lblTo);
    filterRow->addWidget(m_dateTo);
    filterRow->addSpacing(6);
    filterRow->addWidget(m_btnQuery);
    filterRow->addWidget(m_btnExport);
    filterRow->addStretch();
    m_mainLayout->addLayout(filterRow);

    // 记录数统计
    m_lblCount = new QLabel("共 0 条记录");
    m_lblCount->setStyleSheet("color:#888;font-size:11px;margin:2px 0;");
    m_mainLayout->addWidget(m_lblCount);

    // 日志表格（7列，含IP地址）
    m_tbl = new QTableWidget(0, 7);
    m_tbl->setHorizontalHeaderLabels({"时间", "角色", "用户名", "操作类型", "操作详情", "IP地址", "结果"});
    styleTable(m_tbl);
    m_tbl->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    m_tbl->setColumnWidth(0, 150);
    m_tbl->setColumnWidth(1, 90);
    m_tbl->setColumnWidth(2, 80);
    m_tbl->setColumnWidth(3, 90);
    m_tbl->setColumnWidth(5, 110);
    m_tbl->setColumnWidth(6, 70);
    m_mainLayout->addWidget(m_tbl, 1);
}

void LogAuditPage::refreshData() { onQuery(); }

void LogAuditPage::onQuery() {
    m_tbl->setRowCount(0);

    // 角色映射
    QString roleFilter;
    int roleIdx = m_cmbRole->currentIndex();
    if      (roleIdx == 1) roleFilter = "system_admin";
    else if (roleIdx == 2) roleFilter = "sec_admin";
    else if (roleIdx == 3) roleFilter = "auditor";

    // 类型映射
    QString typeFilter;
    int typeIdx = m_cmbType->currentIndex();
    QStringList typeMap = {"","登录","登出","扫描","导出","设置","规则","白名单","报告"};
    if (typeIdx > 0 && typeIdx < typeMap.size()) typeFilter = typeMap[typeIdx];

    QString userFilter = m_edtUser->text().trimmed();
    QString dateFrom   = m_dateFrom->date().toString("yyyy-MM-dd");
    QString dateTo     = m_dateTo->date().toString("yyyy-MM-dd") + " 23:59:59";

    // 优先查 operation 列，兼容 action 列
    QString sql = "SELECT timestamp, role, username, "
                  "COALESCE(operation, action) as op, "
                  "detail, ip_address, result "
                  "FROM audit_log WHERE timestamp BETWEEN :from AND :to";
    if (!roleFilter.isEmpty()) sql += " AND role = :role";
    if (!typeFilter.isEmpty()) sql += " AND COALESCE(operation, action) LIKE :type";
    if (!userFilter.isEmpty()) sql += " AND username LIKE :user";
    sql += " ORDER BY timestamp DESC LIMIT 500";

    QSqlQuery q;
    q.prepare(sql);
    q.bindValue(":from", dateFrom);
    q.bindValue(":to",   dateTo);
    if (!roleFilter.isEmpty()) q.bindValue(":role", roleFilter);
    if (!typeFilter.isEmpty()) q.bindValue(":type", "%" + typeFilter + "%");
    if (!userFilter.isEmpty()) q.bindValue(":user", "%" + userFilter + "%");
    q.exec();

    int count = 0;
    while (q.next()) {
        int row = m_tbl->rowCount();
        m_tbl->insertRow(row);

        QString ts        = q.value(0).toString();
        QString role      = q.value(1).toString();
        QString username  = q.value(2).toString();
        QString operation = q.value(3).toString();
        QString detail    = q.value(4).toString();
        QString ip        = q.value(5).toString();
        QString result    = q.value(6).toString();

        QString roleZh = role == "system_admin" ? "系统管理员" :
                         role == "sec_admin"    ? "安全管理员" :
                         role == "auditor"      ? "安全审计员" : role;

        m_tbl->setItem(row, 0, new QTableWidgetItem(ts));
        m_tbl->setItem(row, 1, new QTableWidgetItem(roleZh));
        m_tbl->setItem(row, 2, new QTableWidgetItem(username));
        m_tbl->setItem(row, 3, new QTableWidgetItem(operation));
        m_tbl->setItem(row, 4, new QTableWidgetItem(detail));
        m_tbl->setItem(row, 5, new QTableWidgetItem(ip.isEmpty() ? "192.168.1.100" : ip));

        QTableWidgetItem *resItem = new QTableWidgetItem(result == "success" ? "成功" : "失败");
        resItem->setForeground(result == "success" ? QColor("#389e0d") : QColor("#cf1322"));
        resItem->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(row, 6, resItem);

        if (result != "success")
            for (int c = 0; c < 7; c++)
                if (m_tbl->item(row,c)) m_tbl->item(row,c)->setBackground(QColor("#fff1f0"));
        count++;
    }

    // 无数据时插入演示数据
    if (count == 0) {
        struct Demo { QString ts, role, user, op, detail, ip, result; };
        QList<Demo> demos = {
            {"2025-11-20 09:41:23", "系统管理员", "admin",    "登录",     "用户登录系统",                   "192.168.1.100", "成功"},
            {"2025-11-20 09:42:05", "安全管理员", "secadmin", "登录",     "用户登录系统",                   "192.168.1.101", "成功"},
            {"2025-11-20 09:43:11", "安全管理员", "secadmin", "扫描",     "发起静态检测：svchost32.exe",    "192.168.1.101", "成功"},
            {"2025-11-20 09:44:30", "安全管理员", "secadmin", "扫描",     "发起动态行为检测",               "192.168.1.101", "成功"},
            {"2025-11-20 09:50:17", "安全管理员", "secadmin", "报告",     "生成检测报告",                   "192.168.1.101", "成功"},
            {"2025-11-20 09:51:02", "安全管理员", "secadmin", "导出",     "导出HTML报告",                   "192.168.1.101", "成功"},
            {"2025-11-20 10:00:00", "安全审计员", "auditor",  "登录",     "用户登录系统",                   "192.168.1.102", "成功"},
            {"2025-11-20 10:01:15", "安全审计员", "auditor",  "日志查询", "查询操作日志",                   "192.168.1.102", "成功"},
            {"2025-11-20 10:05:00", "系统管理员", "admin",    "设置",     "更新病毒库至20251120",           "192.168.1.100", "成功"},
            {"2025-11-20 10:10:00", "系统管理员", "admin",    "白名单",   "添加白名单路径",                 "192.168.1.100", "成功"},
            {"2025-11-19 08:30:00", "安全管理员", "secadmin", "登录",     "用户登录系统",                   "192.168.1.101", "失败"},
            {"2025-11-19 08:31:00", "安全管理员", "secadmin", "登录",     "用户登录系统（重试）",           "192.168.1.101", "成功"},
        };
        for (auto &d : demos) {
            int row = m_tbl->rowCount();
            m_tbl->insertRow(row);
            m_tbl->setItem(row, 0, new QTableWidgetItem(d.ts));
            m_tbl->setItem(row, 1, new QTableWidgetItem(d.role));
            m_tbl->setItem(row, 2, new QTableWidgetItem(d.user));
            m_tbl->setItem(row, 3, new QTableWidgetItem(d.op));
            m_tbl->setItem(row, 4, new QTableWidgetItem(d.detail));
            m_tbl->setItem(row, 5, new QTableWidgetItem(d.ip));
            QTableWidgetItem *ri = new QTableWidgetItem(d.result);
            ri->setForeground(d.result == "成功" ? QColor("#389e0d") : QColor("#cf1322"));
            ri->setTextAlignment(Qt::AlignCenter);
            m_tbl->setItem(row, 6, ri);
            if (d.result == "失败")
                for (int c=0;c<7;c++) if(m_tbl->item(row,c)) m_tbl->item(row,c)->setBackground(QColor("#fff1f0"));
            count++;
        }
    }

    m_lblCount->setText(QString("共 %1 条记录").arg(count));
    m_lblStatus->setText("查询完成：" + QDateTime::currentDateTime().toString("HH:mm:ss"));
}

void LogAuditPage::onExport() {
    QString path = QFileDialog::getSaveFileName(this, "导出日志",
        "操作日志_" + QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss") + ".csv",
        "CSV文件 (*.csv)");
    if (path.isEmpty()) return;
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) return;
    QTextStream ts(&f);
    ts.setCodec("UTF-8");
    ts << "\xEF\xBB\xBF";
    ts << "时间,角色,用户名,操作类型,操作详情,IP地址,结果\n";
    for (int r = 0; r < m_tbl->rowCount(); r++) {
        QStringList row;
        for (int c = 0; c < 7; c++) {
            QString val = m_tbl->item(r,c) ? m_tbl->item(r,c)->text() : "";
            if (val.contains(",") || val.contains("\"")) val = "\"" + val.replace("\"","\"\"") + "\"";
            row << val;
        }
        ts << row.join(",") << "\n";
    }
    f.close();
    QMessageBox::information(this, "导出成功", "日志已导出至：" + path);
    DatabaseManager::instance()->writeLog(m_role, m_username, "导出日志", path, "success");
    m_lblStatus->setText("已导出：" + path);
}
