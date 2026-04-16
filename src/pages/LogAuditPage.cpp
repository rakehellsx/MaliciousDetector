#include "pages/LogAuditPage.h"
#include "ui_LogAuditPage.h"

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
    ui = new Ui::LogAuditPage();
    ui->setupUi(this);
    postSetupUi();
    m_cmbRole = ui->m_cmbRole;
    m_cmbType = ui->m_cmbType;
    m_edtUser = ui->m_edtUser;
    m_dateFrom = ui->m_dateFrom;
    m_dateTo = ui->m_dateTo;
    m_btnQuery = ui->m_btnQuery;
    m_btnExport = ui->m_btnExport;
    m_tbl = ui->m_tbl;
    m_lblCount = ui->m_lblCount;
    refreshData();
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

    QSqlQuery q(QSqlDatabase::database("main_conn"));
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
        m_tbl->setItem(row, 5, new QTableWidgetItem(ip));

        QTableWidgetItem *resItem = new QTableWidgetItem(result == "success" ? "成功" : "失败");
        resItem->setForeground(result == "success" ? QColor("#389e0d") : QColor("#cf1322"));
        resItem->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(row, 6, resItem);

        if (result != "success")
            for (int c = 0; c < 7; c++)
                if (m_tbl->item(row,c)) m_tbl->item(row,c)->setBackground(QColor("#fff1f0"));
        count++;
    }

    // 无数据时加载演示数据
    if (count == 0) {
        struct DemoLog { QString ts, role, user, op, detail, ip, result; };
        QList<DemoLog> demos = {
            {"2025-04-16 09:00:01","系统管理员","admin","用户登录","用户 admin 登录系统","192.168.1.100","success"},
            {"2025-04-16 09:05:22","安全管理员","sec_admin","启动扫描","对 svchost32.exe 发起动态行为扫描","192.168.1.101","success"},
            {"2025-04-16 09:12:34","安全管理员","sec_admin","查看报告","查看检测报告 RPT-20250416-001","192.168.1.101","success"},
            {"2025-04-16 09:15:00","安全审计员","auditor","导出日志","导出操作日志 2025-04-16.csv","192.168.1.102","success"},
            {"2025-04-16 09:18:45","系统管理员","admin","添加用户","新增用户 analyst01，角色：安全管理员","192.168.1.100","success"},
            {"2025-04-16 09:22:10","安全管理员","sec_admin","样本提取","提取样本 payload.exe，MD5: a1b2c3d4","192.168.1.101","success"},
            {"2025-04-16 09:30:05","安全审计员","auditor","用户登录","用户 auditor 登录失败，密码错误","192.168.1.103","fail"},
            {"2025-04-16 09:31:00","安全审计员","auditor","用户登录","用户 auditor 登录系统","192.168.1.103","success"},
            {"2025-04-16 09:45:18","系统管理员","admin","修改设置","修改检测规则：新增 YARA 规则 rule_0042","192.168.1.100","success"},
            {"2025-04-16 10:00:00","安全管理员","sec_admin","漏洞监测","检测到 CVE-2017-0144 利用行为，进程 lsass.exe","192.168.1.101","success"}
        };
        for (const auto &d : demos) {
            int row = m_tbl->rowCount(); m_tbl->insertRow(row);
            m_tbl->setItem(row, 0, new QTableWidgetItem(d.ts));
            m_tbl->setItem(row, 1, new QTableWidgetItem(d.role));
            m_tbl->setItem(row, 2, new QTableWidgetItem(d.user));
            m_tbl->setItem(row, 3, new QTableWidgetItem(d.op));
            m_tbl->setItem(row, 4, new QTableWidgetItem(d.detail));
            m_tbl->setItem(row, 5, new QTableWidgetItem(d.ip));
            QTableWidgetItem *ri = new QTableWidgetItem(d.result=="success" ? "成功" : "失败");
            ri->setForeground(d.result=="success" ? QColor("#389e0d") : QColor("#cf1322"));
            ri->setTextAlignment(Qt::AlignCenter);
            m_tbl->setItem(row, 6, ri);
            if (d.result != "success")
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
