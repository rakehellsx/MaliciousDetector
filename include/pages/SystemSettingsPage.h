#pragma once
#ifndef SYSTEMSETTINGSPAGE_H
#define SYSTEMSETTINGSPAGE_H
#include "pages/BasePage.h"
#include <QListWidget>
#include <QStackedWidget>
#include <QLineEdit>
#include <QCheckBox>
#include <QSpinBox>
#include <QPushButton>
#include <QTableWidget>
#include <QLabel>
class SystemSettingsPage : public BasePage {
    Q_OBJECT
public:
    explicit SystemSettingsPage(QWidget *p=nullptr);
    void refreshData() override;
private slots:
    void onNavChanged(int row);
    void onSave();
    void onUpdateVirusDb();
private:
    void setupUi();
    void loadSettings();
    QListWidget    *m_navList;
    QStackedWidget *m_stack;
    // DLL设置
    QLineEdit  *m_editDllPath;
    QLineEdit  *m_editDbPath;
    // 病毒库
    QLabel     *m_lblDbVer;
    QLabel     *m_lblDbDate;
    QPushButton *m_btnUpdate;
    // 扫描策略
    QCheckBox  *m_chkAutoScan;
    QCheckBox  *m_chkStartupScan;
    QCheckBox  *m_chkRealtime;
    // 白名单
    QTableWidget *m_tblWhitelist;
    QPushButton  *m_btnAddWhite;
    QPushButton  *m_btnDelWhite;
    // 自定义规则
    QTableWidget *m_tblRules;
    QPushButton  *m_btnAddRule;
    QPushButton  *m_btnDelRule;
    // 日志保留
    QSpinBox   *m_spinLogDays;
    // 报告输出
    QLineEdit  *m_editReportDir;
};
#endif
