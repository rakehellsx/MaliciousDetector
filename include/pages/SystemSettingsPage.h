#pragma once
#ifndef SYSTEMSETTINGSPAGE_H
#define SYSTEMSETTINGSPAGE_H
#include "pages/BasePage.h"
#include <QListWidget>
#include <QStackedWidget>
#include <QLineEdit>
#include <QComboBox>
#include <QCheckBox>
#include <QTimeEdit>
#include <QSpinBox>
#include <QTableWidget>
#include <QPushButton>
#include <QLabel>
#include <QProgressBar>

class SystemSettingsPage : public BasePage {
    Q_OBJECT
public:
    explicit SystemSettingsPage(QWidget *p=nullptr);
    void refreshData() override;

private slots:
    void onNavChanged(int row);
    void onSave();
    void onUpdateVirusDb();
    void onAddWhitelist();
    void onDelWhitelist();
    void onAddRule();
    void onDelRule();

private:
    void setupUi();
    void loadSettings();

    QListWidget    *m_navList;
    QStackedWidget *m_stack;

    // 基础配置
    QLineEdit      *m_editDllPath;
    QLineEdit      *m_editDbPath;
    QLineEdit      *m_editReportDir;

    // 病毒库管理
    QLabel         *m_lblDbVer;
    QLabel         *m_lblDbDate;
    QLabel         *m_lblDbStatus;
    QProgressBar   *m_progressUpdate;
    QCheckBox      *m_chkAutoUpdate;
    QComboBox      *m_cmbUpdateFreq;
    QLineEdit      *m_edtUpdateSource;
    QPushButton    *m_btnUpdate;

    // 扫描策略
    QCheckBox      *m_chkAutoScan;
    QCheckBox      *m_chkStartupScan;
    QCheckBox      *m_chkRealtime;
    QCheckBox      *m_chkScanArchive;
    QCheckBox      *m_chkScanHidden;

    // 白名单
    QTableWidget   *m_tblWhitelist;
    QPushButton    *m_btnAddWhite;
    QPushButton    *m_btnDelWhite;

    // 自定义规则
    QTableWidget   *m_tblRules;
    QPushButton    *m_btnAddRule;
    QPushButton    *m_btnDelRule;

    // 日志设置
    QSpinBox       *m_spinLogDays;

    // 用户管理
    QTableWidget   *m_tblUsers;
};
#endif
