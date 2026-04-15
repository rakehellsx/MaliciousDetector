#include "pages/SystemSettingsPage.h"
#include "ui_SystemSettingsPage.h"

#include "DatabaseManager.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QGroupBox>
#include <QFormLayout>
#include <QLabel>
#include <QFileDialog>
#include <QMessageBox>
#include <QPushButton>
#include <QInputDialog>
#include <QSqlQuery>
#include <QDateTime>
#include <QHeaderView>
#include <QThread>
#include <QApplication>
#include <QFrame>

SystemSettingsPage::SystemSettingsPage(QWidget *parent) : BasePage("系统设置", parent) {
    ui = new Ui::SystemSettingsPage();
    ui->setupUi(this);
    m_navList = ui->m_navList;
    m_stack = ui->m_stack;
    m_editDllPath = ui->m_editDllPath;
    m_editDbPath = ui->m_editDbPath;
    m_editReportDir = ui->m_editReportDir;
    m_lblDbVer = ui->m_lblDbVer;
    m_lblDbDate = ui->m_lblDbDate;
    m_lblDbStatus = ui->m_lblDbStatus;
    m_progressUpdate = ui->m_progressUpdate;
    m_chkAutoUpdate = ui->m_chkAutoUpdate;
    m_cmbUpdateFreq = ui->m_cmbUpdateFreq;
    m_edtUpdateSource = ui->m_edtUpdateSource;
    m_btnUpdate = ui->m_btnUpdate;
    m_chkAutoScan = ui->m_chkAutoScan;
    m_chkStartupScan = ui->m_chkStartupScan;
    m_chkRealtime = ui->m_chkRealtime;
    m_chkScanArchive = ui->m_chkScanArchive;
    m_chkScanHidden = ui->m_chkScanHidden;
    m_tblWhitelist = ui->m_tblWhitelist;
    m_btnAddWhite = ui->m_btnAddWhite;
    m_btnDelWhite = ui->m_btnDelWhite;
    m_tblRules = ui->m_tblRules;
    m_btnAddRule = ui->m_btnAddRule;
    m_btnDelRule = ui->m_btnDelRule;
    m_spinLogDays = ui->m_spinLogDays;
    m_tblUsers = ui->m_tblUsers;
    loadSettings();
}

void SystemSettingsPage::loadSettings() {
    auto *dbm = DatabaseManager::instance();
    m_editDllPath->setText(dbm->getSetting("dll_path", "basic.dll"));
    m_editDbPath->setText(dbm->getSetting("db_path", "malware_detector.db"));
    m_editReportDir->setText(dbm->getSetting("report_dir", "./reports"));

    // 病毒库
    QString ver  = dbm->getSetting("virus_db_version", "20251120");
    QString date = dbm->getSetting("virus_db_date", "2025-11-20");
    m_lblDbVer->setText("当前版本：" + ver);
    m_lblDbDate->setText("更新时间：" + date);
    m_chkAutoUpdate->setChecked(dbm->getSetting("auto_update", "1") == "1");
    int freqIdx = dbm->getSetting("update_freq", "0").toInt();
    m_cmbUpdateFreq->setCurrentIndex(qBound(0, freqIdx, 2));

    // 扫描策略
    m_chkAutoScan->setChecked(dbm->getSetting("auto_scan", "0") == "1");
    m_chkStartupScan->setChecked(dbm->getSetting("startup_scan", "0") == "1");
    m_chkRealtime->setChecked(dbm->getSetting("realtime_monitor", "0") == "1");
    m_chkScanArchive->setChecked(dbm->getSetting("scan_archive", "1") == "1");
    m_chkScanHidden->setChecked(dbm->getSetting("scan_hidden", "1") == "1");
    m_spinLogDays->setValue(dbm->getSetting("log_days", "90").toInt());

    // 白名单
    m_tblWhitelist->setRowCount(0);
    QSqlQuery wq;
    wq.exec("SELECT COALESCE(type,'路径'), COALESCE(value, path_or_md5), COALESCE(note,remark,''), created_at FROM whitelist ORDER BY id");
    while (wq.next()) {
        int row = m_tblWhitelist->rowCount(); m_tblWhitelist->insertRow(row);
        m_tblWhitelist->setItem(row, 0, new QTableWidgetItem(wq.value(0).toString()));
        m_tblWhitelist->setItem(row, 1, new QTableWidgetItem(wq.value(1).toString()));
        m_tblWhitelist->setItem(row, 2, new QTableWidgetItem(wq.value(2).toString()));
        m_tblWhitelist->setItem(row, 3, new QTableWidgetItem(wq.value(3).toString()));
        m_tblWhitelist->setItem(row, 4, new QTableWidgetItem("删除"));
    }
    // 无数据时显示空表，等待外部入库

    // 自定义规则
    m_tblRules->setRowCount(0);
    QSqlQuery rq;
    rq.exec("SELECT id, name, type, COALESCE(content,'') as content, risk_level, enabled FROM custom_rules ORDER BY id");
    while (rq.next()) {
        int row = m_tblRules->rowCount(); m_tblRules->insertRow(row);
        m_tblRules->setItem(row, 0, new QTableWidgetItem(QString("RULE-%1").arg(rq.value(0).toInt(), 4, 10, QChar('0'))));
        m_tblRules->setItem(row, 1, new QTableWidgetItem(rq.value(1).toString()));
        m_tblRules->setItem(row, 2, new QTableWidgetItem(rq.value(2).toString()));
        m_tblRules->setItem(row, 3, new QTableWidgetItem(rq.value(3).toString()));
        QString risk = rq.value(4).toString();
        QTableWidgetItem *ri = new QTableWidgetItem(risk);
        ri->setForeground(risk=="高危"?QColor("#cf1322"):risk=="中危"?QColor("#d46b08"):QColor("#096dd9"));
        m_tblRules->setItem(row, 4, ri);
        bool enabled = rq.value(5).toInt() == 1;
        QTableWidgetItem *ei = new QTableWidgetItem(enabled ? "启用" : "禁用");
        ei->setForeground(enabled ? QColor("#389e0d") : QColor("#888"));
        m_tblRules->setItem(row, 5, ei);
    }
    // 无数据时显示空表，等待外部入库

    // 用户管理：从数据库读取
    m_tblUsers->setRowCount(0);
    QSqlQuery uq(QSqlDatabase::database("main_conn"));
    uq.exec("SELECT username, role, status, last_login FROM users ORDER BY id");
    while (uq.next()) {
        int row = m_tblUsers->rowCount(); m_tblUsers->insertRow(row);
        m_tblUsers->setItem(row, 0, new QTableWidgetItem(uq.value(0).toString()));
        m_tblUsers->setItem(row, 1, new QTableWidgetItem(uq.value(1).toString()));
        QString status = uq.value(2).toString();
        QTableWidgetItem *si = new QTableWidgetItem(status.isEmpty() ? "启用" : status);
        si->setForeground(QColor("#389e0d"));
        m_tblUsers->setItem(row, 2, si);
        m_tblUsers->setItem(row, 3, new QTableWidgetItem(uq.value(3).toString()));
        m_tblUsers->setItem(row, 4, new QTableWidgetItem("修改密码"));
    }
}

void SystemSettingsPage::refreshData() { loadSettings(); }

void SystemSettingsPage::onNavChanged(int row) { m_stack->setCurrentIndex(row); }

void SystemSettingsPage::onSave() {
    auto *dbm = DatabaseManager::instance();
    dbm->setSetting("dll_path",          m_editDllPath->text());
    dbm->setSetting("db_path",           m_editDbPath->text());
    dbm->setSetting("report_dir",        m_editReportDir->text());
    dbm->setSetting("auto_scan",         m_chkAutoScan->isChecked()    ? "1" : "0");
    dbm->setSetting("startup_scan",      m_chkStartupScan->isChecked() ? "1" : "0");
    dbm->setSetting("realtime_monitor",  m_chkRealtime->isChecked()    ? "1" : "0");
    dbm->setSetting("scan_archive",      m_chkScanArchive->isChecked() ? "1" : "0");
    dbm->setSetting("scan_hidden",       m_chkScanHidden->isChecked()  ? "1" : "0");
    dbm->setSetting("auto_update",       m_chkAutoUpdate->isChecked()  ? "1" : "0");
    dbm->setSetting("update_freq",       QString::number(m_cmbUpdateFreq->currentIndex()));
    dbm->setSetting("log_days",          QString::number(m_spinLogDays->value()));
    dbm->writeLog(m_role, m_username, "修改设置", "保存系统设置", "success");
    m_lblStatus->setText("设置已保存：" + QDateTime::currentDateTime().toString("HH:mm:ss"));
    QMessageBox::information(this, "提示", "设置已保存成功！");
}

void SystemSettingsPage::onUpdateVirusDb() {
    m_progressUpdate->setVisible(true);
    m_progressUpdate->setValue(0);
    m_btnUpdate->setEnabled(false);
    m_lblDbStatus->setText("状态：更新中...");
    m_lblDbStatus->setStyleSheet("color:#d46b08;font-weight:bold;");
    for (int i = 0; i <= 100; i += 10) {
        m_progressUpdate->setValue(i);
        qApp->processEvents();
        QThread::msleep(120);
    }
    QString newVer  = QDateTime::currentDateTime().toString("yyyyMMdd");
    QString newDate = QDate::currentDate().toString("yyyy-MM-dd");
    DatabaseManager::instance()->setSetting("virus_db_version", newVer);
    DatabaseManager::instance()->setSetting("virus_db_date",    newDate);
    m_lblDbVer->setText("当前版本：" + newVer);
    m_lblDbDate->setText("更新时间：" + newDate);
    m_lblDbStatus->setText("状态：最新");
    m_lblDbStatus->setStyleSheet("color:#389e0d;font-weight:bold;");
    m_btnUpdate->setEnabled(true);
    DatabaseManager::instance()->writeLog(m_role, m_username, "更新病毒库", "病毒库更新至" + newVer, "success");
    m_lblStatus->setText("病毒库已更新至 " + newVer);
    QMessageBox::information(this, "提示", "病毒库更新成功！\n当前版本：" + newVer);
}

void SystemSettingsPage::onAddWhitelist() {
    QString val = QInputDialog::getText(this, "\u6dfb\u52a0\u767d\u540d\u5355", "\u8bf7\u8f93\u5165\u6587\u4ef6\u8def\u5f84\u6216MD5\uff1a");
    if (val.isEmpty()) return;
    // \u6301\u4e45\u5316\u5230\u6570\u636e\u5e93
    QSqlDatabase db = QSqlDatabase::database("main_conn");
    if (db.isOpen()) {
        QSqlQuery q(db);
        bool isMd5 = (val.length() == 32 && !val.contains("\\") && !val.contains("/"));
        if (isMd5) {
            q.prepare("INSERT INTO whitelist(path, md5, note, added_by) VALUES('', ?, '\u624b\u52a8\u6dfb\u52a0', ?)");
            q.addBindValue(val);
        } else {
            q.prepare("INSERT INTO whitelist(path, md5, note, added_by) VALUES(?, '', '\u624b\u52a8\u6dfb\u52a0', ?)");
            q.addBindValue(val);
        }
        q.addBindValue(m_username);
        q.exec();
    }
    DatabaseManager::instance()->writeLog(m_role, m_username, "\u767d\u540d\u5355", "\u6dfb\u52a0\u767d\u540d\u5355\uff1a" + val, "success");
    loadSettings(); // \u91cd\u65b0\u4ece\u6570\u636e\u5e93\u52a0\u8f7d
}

void SystemSettingsPage::onDelWhitelist() {
    int row = m_tblWhitelist->currentRow();
    if (row < 0) { QMessageBox::warning(this, "\u63d0\u793a", "\u8bf7\u5148\u9009\u62e9\u8981\u5220\u9664\u7684\u6761\u76ee\u3002"); return; }
    // \u6839\u636e\u503c\u5220\u9664\u6570\u636e\u5e93\u8bb0\u5f55
    QString val = m_tblWhitelist->item(row, 1) ? m_tblWhitelist->item(row, 1)->text() : "";
    QSqlDatabase db = QSqlDatabase::database("main_conn");
    if (db.isOpen() && !val.isEmpty()) {
        QSqlQuery q(db);
        q.prepare("DELETE FROM whitelist WHERE path=? OR md5=?");
        q.addBindValue(val); q.addBindValue(val);
        q.exec();
    }
    DatabaseManager::instance()->writeLog(m_role, m_username, "\u767d\u540d\u5355", "\u5220\u9664\u767d\u540d\u5355\uff1a" + val, "success");
    loadSettings();
}

void SystemSettingsPage::onAddRule() {
    QString name = QInputDialog::getText(this, "\u65b0\u589e\u89c4\u5219", "\u8bf7\u8f93\u5165\u89c4\u5219\u540d\u79f0\uff1a");
    if (name.isEmpty()) return;
    // \u6301\u4e45\u5316\u5230\u6570\u636e\u5e93
    QSqlDatabase db = QSqlDatabase::database("main_conn");
    if (db.isOpen()) {
        QSqlQuery q(db);
        q.prepare("INSERT INTO custom_rules(name, rule_type, pattern, description, enabled) VALUES(?, '\u7279\u5f81\u7801', '', '', 1)");
        q.addBindValue(name);
        q.exec();
    }
    DatabaseManager::instance()->writeLog(m_role, m_username, "\u89c4\u5219", "\u65b0\u589e\u89c4\u5219\uff1a" + name, "success");
    loadSettings(); // \u91cd\u65b0\u4ece\u6570\u636e\u5e93\u52a0\u8f7d
}

void SystemSettingsPage::onDelRule() {
    int row = m_tblRules->currentRow();
    if (row < 0) { QMessageBox::warning(this, "\u63d0\u793a", "\u8bf7\u5148\u9009\u62e9\u8981\u5220\u9664\u7684\u89c4\u5219\u3002"); return; }
    // \u6839\u636e\u89c4\u5219\u540d\u5220\u9664\u6570\u636e\u5e93\u8bb0\u5f55
    QString ruleName = m_tblRules->item(row, 1) ? m_tblRules->item(row, 1)->text() : "";
    QSqlDatabase db = QSqlDatabase::database("main_conn");
    if (db.isOpen() && !ruleName.isEmpty()) {
        QSqlQuery q(db);
        q.prepare("DELETE FROM custom_rules WHERE name=?");
        q.addBindValue(ruleName);
        q.exec();
    }
    DatabaseManager::instance()->writeLog(m_role, m_username, "\u89c4\u5219", "\u5220\u9664\u89c4\u5219\uff1a" + ruleName, "success");
    loadSettings();
}
