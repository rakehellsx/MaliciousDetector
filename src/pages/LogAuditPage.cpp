#include "pages/LogAuditPage.h"
#include <QHBoxLayout>
#include <QLabel>
#include <QSqlQuery>
#include <QSqlDatabase>
#include <QHeaderView>
#include <QFileDialog>

LogAuditPage::LogAuditPage(QWidget *parent) : BasePage("日志审计", parent) { setupUi(); refreshData(); }

void LogAuditPage::setupUi()
{
    QHBoxLayout *filterRow = new QHBoxLayout;
    QLabel *roleLbl = new QLabel("角色：");
    roleLbl->setObjectName("fieldLabel");
    m_cmbRole = new QComboBox;
    m_cmbRole->setObjectName("comboBox");
    m_cmbRole->addItems({"全部","系统管理员","安全管理员","安全审计员"});
    m_cmbRole->setFixedWidth(120);

    QLabel *fromLbl = new QLabel("开始日期：");
    fromLbl->setObjectName("fieldLabel");
    m_dateFrom = new QDateEdit(QDate::currentDate().addDays(-7));
    m_dateFrom->setObjectName("dateEdit");
    m_dateFrom->setCalendarPopup(true);
    m_dateFrom->setDisplayFormat("yyyy-MM-dd");

    QLabel *toLbl = new QLabel("结束日期：");
    toLbl->setObjectName("fieldLabel");
    m_dateTo = new QDateEdit(QDate::currentDate());
    m_dateTo->setObjectName("dateEdit");
    m_dateTo->setCalendarPopup(true);
    m_dateTo->setDisplayFormat("yyyy-MM-dd");

    m_btnQuery = new QPushButton("查 询");
    m_btnQuery->setObjectName("btnPrimary");
    m_btnQuery->setFixedWidth(72);
    m_btnExport = new QPushButton("导 出");
    m_btnExport->setObjectName("btnSecondary");
    m_btnExport->setFixedWidth(72);
    connect(m_btnQuery,  &QPushButton::clicked, this, &LogAuditPage::onQuery);
    connect(m_btnExport, &QPushButton::clicked, this, &LogAuditPage::onExport);

    filterRow->addWidget(roleLbl);
    filterRow->addWidget(m_cmbRole);
    filterRow->addSpacing(12);
    filterRow->addWidget(fromLbl);
    filterRow->addWidget(m_dateFrom);
    filterRow->addSpacing(12);
    filterRow->addWidget(toLbl);
    filterRow->addWidget(m_dateTo);
    filterRow->addSpacing(12);
    filterRow->addWidget(m_btnQuery);
    filterRow->addWidget(m_btnExport);
    filterRow->addStretch();
    m_mainLayout->addLayout(filterRow);

    m_tbl = new QTableWidget(0, 6);
    m_tbl->setHorizontalHeaderLabels({"时间","角色","用户名","操作类型","操作详情","结果"});
    styleTable(m_tbl);
    m_tbl->setColumnWidth(0, 140);
    m_tbl->setColumnWidth(1, 100);
    m_tbl->setColumnWidth(2, 100);
    m_tbl->setColumnWidth(3, 120);
    m_tbl->setColumnWidth(5, 70);
    m_mainLayout->addWidget(m_tbl, 1);
}

void LogAuditPage::refreshData() { onQuery(); }

void LogAuditPage::onQuery()
{
    m_tbl->setRowCount(0);
    QSqlDatabase db = QSqlDatabase::database("main_conn");
    if (db.isOpen()) {
        QString roleFilter = m_cmbRole->currentText();
        QString fromStr = m_dateFrom->date().toString("yyyy-MM-dd");
        QString toStr   = m_dateTo->date().toString("yyyy-MM-dd") + " 23:59:59";

        QSqlQuery q(db);
        if (roleFilter == "全部") {
            q.prepare("SELECT timestamp,role,username,action,detail,result FROM audit_log "
                      "WHERE timestamp BETWEEN ? AND ? ORDER BY id DESC LIMIT 500");
            q.addBindValue(fromStr);
            q.addBindValue(toStr);
        } else {
            QString roleKey = roleFilter=="系统管理员"?"system_admin":roleFilter=="安全管理员"?"sec_admin":"auditor";
            q.prepare("SELECT timestamp,role,username,action,detail,result FROM audit_log "
                      "WHERE role=? AND timestamp BETWEEN ? AND ? ORDER BY id DESC LIMIT 500");
            q.addBindValue(roleKey);
            q.addBindValue(fromStr);
            q.addBindValue(toStr);
        }
        q.exec();
        while (q.next()) {
            int row = m_tbl->rowCount(); m_tbl->insertRow(row);
            m_tbl->setItem(row,0,new QTableWidgetItem(q.value(0).toString()));
            QString role = q.value(1).toString();
            m_tbl->setItem(row,1,new QTableWidgetItem(
                role=="system_admin"?"系统管理员":role=="sec_admin"?"安全管理员":"安全审计员"));
            m_tbl->setItem(row,2,new QTableWidgetItem(q.value(2).toString()));
            m_tbl->setItem(row,3,new QTableWidgetItem(q.value(3).toString()));
            m_tbl->setItem(row,4,new QTableWidgetItem(q.value(4).toString()));
            QString res = q.value(5).toString();
            QTableWidgetItem *ri = new QTableWidgetItem(res=="success"?"成功":res=="failed"?"失败":"--");
            ri->setForeground(res=="success"?QColor("#4caf50"):res=="failed"?QColor("#ef5350"):QColor("#90caf9"));
            ri->setTextAlignment(Qt::AlignCenter);
            m_tbl->setItem(row,5,ri);
        }
    }
    // 无数据时填充示例
    if (m_tbl->rowCount() == 0) {
        QList<QStringList> demo = {
            {"2025-11-20 09:41:02","系统管理员","admin","用户登录","登录成功","成功"},
            {"2025-11-20 09:41:30","安全管理员","secadmin","用户登录","登录成功","成功"},
            {"2025-11-20 09:42:00","安全管理员","secadmin","静态检测","提交文件：svchost32.exe","成功"},
            {"2025-11-20 09:42:15","安全管理员","secadmin","动态行为检测","提交样本：svchost32.exe","成功"},
            {"2025-11-20 09:43:00","安全管理员","secadmin","生成报告","生成检测报告","成功"},
            {"2025-11-20 09:43:30","系统管理员","admin","更新病毒库","病毒库更新至20251120","成功"},
            {"2025-11-20 09:44:00","安全审计员","auditor","用户登录","登录成功","成功"},
            {"2025-11-20 09:44:10","安全审计员","auditor","查看日志","查询全部日志","成功"},
            {"2025-11-20 09:44:30","安全管理员","secadmin","导出报告","导出PDF报告","成功"},
            {"2025-11-20 09:45:00","系统管理员","admin","修改设置","修改扫描策略","成功"},
        };
        for (const QStringList &d : demo) {
            int r = m_tbl->rowCount(); m_tbl->insertRow(r);
            for (int c = 0; c < d.size(); ++c) {
                QTableWidgetItem *it = new QTableWidgetItem(d[c]);
                if (c==5) it->setForeground(d[c]=="成功"?QColor("#4caf50"):QColor("#ef5350"));
                if (c==5) it->setTextAlignment(Qt::AlignCenter);
                m_tbl->setItem(r,c,it);
            }
        }
    }
    m_lblStatus->setText(QString("共 %1 条日志").arg(m_tbl->rowCount()));
}

void LogAuditPage::onExport()
{
    QString path = QFileDialog::getSaveFileName(this, "导出日志", "操作日志_" +
        QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss") + ".csv", "CSV文件 (*.csv)");
    if (path.isEmpty()) return;
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly|QIODevice::Text)) return;
    QTextStream ts(&f);
    ts.setCodec("UTF-8");
    ts << "\xEF\xBB\xBF"; // BOM
    ts << "时间,角色,用户名,操作类型,操作详情,结果\n";
    for (int r = 0; r < m_tbl->rowCount(); ++r) {
        QStringList row;
        for (int c = 0; c < m_tbl->columnCount(); ++c)
            row << (m_tbl->item(r,c) ? "\""+m_tbl->item(r,c)->text()+"\"" : "\"\"");
        ts << row.join(",") << "\n";
    }
    f.close();
    DatabaseManager::instance()->writeLog(m_role, m_username, "导出日志", path, "success");
    m_lblStatus->setText("已导出：" + path);
}
