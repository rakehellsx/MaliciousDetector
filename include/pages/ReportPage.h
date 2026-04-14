#pragma once
#ifndef REPORTPAGE_H
#define REPORTPAGE_H

#include "pages/BasePage.h"
#include <QTableWidget>
#include <QTextEdit>
#include <QLineEdit>
#include <QComboBox>
#include <QPushButton>
#include <QLabel>
#include <QTabWidget>
#include <QTimer>
#include <QDateTime>
#include <QVariantMap>
#include <QGroupBox>
#include <QSpinBox>
#include <QCheckBox>

class ReportPage : public BasePage {
    Q_OBJECT
public:
    explicit ReportPage(QWidget *p = nullptr);
    ~ReportPage() override;
    void refreshData() override;

private slots:
    void onGenerateReport();
    void onExportDoc();
    void onExportPdf();
    void onExportHtml();
    void onQueryThreats();
    void onTimerToggle(bool checked);
    void onTimerFired();

private:
    void setupUi();
    void setupOverviewTab(QWidget *tab);
    void setupThreatTab(QWidget *tab);
    void setupHostTab(QWidget *tab);
    void setupPreviewTab(QWidget *tab);
    void setupScheduleTab(QWidget *tab);

    // ── 报告数据结构 ──────────────────────────────────────────────────────
    struct ThreatItem {
        QString name, riskLevel, category, filePath, detail, scanTime, status;
    };
    struct ReportData {
        // 主机信息
        QString hostname, os, cpu, memory, ip, mac, collectTime;
        // 风险统计
        int totalHigh{0}, totalMedium{0}, totalLow{0}, totalClean{0};
        // 各模块统计 [high, medium, low, total]
        QMap<QString, QList<int>> moduleStat;
        // 威胁列表
        QList<ThreatItem> threats;
        // 处置建议
        QStringList suggestions;
        // 报告元数据
        QString reportId, reportTime, analyst;
    };

    void collectData(ReportData &d);
    void fillOverview(const ReportData &d);
    void fillThreatTable(const ReportData &d);
    void fillHostTable(const ReportData &d);
    void buildPreview(const ReportData &d);
    QString buildHtmlReport(const ReportData &d);
    QString buildRtfReport(const ReportData &d);
    // escHtml 在 cpp 中定义为 static 自由函数，无需成员声明

    // ── 概览 Tab ──────────────────────────────────────────────────────────
    QLabel       *m_lblReportId{nullptr};
    QLabel       *m_lblReportTime{nullptr};
    QLabel       *m_lblHostname{nullptr};
    QLabel       *m_lblOs{nullptr};
    QLabel       *m_lblIp{nullptr};
    QLabel       *m_lblCollectTime{nullptr};
    QLabel       *m_cardHighCount{nullptr};
    QLabel       *m_cardMediumCount{nullptr};
    QLabel       *m_cardLowCount{nullptr};
    QLabel       *m_cardCleanCount{nullptr};
    QTableWidget *m_tblModuleStat{nullptr};

    // ── 威胁详情 Tab ──────────────────────────────────────────────────────
    QLineEdit    *m_edtThreatKw{nullptr};
    QComboBox    *m_cmbThreatRisk{nullptr};
    QComboBox    *m_cmbThreatCat{nullptr};
    QLabel       *m_lblThreatCount{nullptr};
    QTableWidget *m_tblThreats{nullptr};

    // ── 主机信息 Tab ──────────────────────────────────────────────────────
    QTableWidget *m_tblSysInfo{nullptr};
    QTableWidget *m_tblNetInfo{nullptr};
    QTableWidget *m_tblDiskInfo{nullptr};
    QTableWidget *m_tblProcRisk{nullptr};
    QTableWidget *m_tblPortRisk{nullptr};

    // ── 报告预览 Tab ──────────────────────────────────────────────────────
    QTextEdit    *m_txtPreview{nullptr};

    // ── 定时生成 Tab ──────────────────────────────────────────────────────
    QCheckBox    *m_chkTimerEnable{nullptr};
    QComboBox    *m_cmbTimerMode{nullptr};
    QSpinBox     *m_spnTimerHour{nullptr};
    QLabel       *m_lblNextTime{nullptr};
    QLabel       *m_lblTimerStatus{nullptr};
    QTimer       *m_timer{nullptr};
    QDateTime     m_nextFireTime;

    // ── 操作按钮 ──────────────────────────────────────────────────────────
    QPushButton  *m_btnGenerate{nullptr};
    QPushButton  *m_btnExportDoc{nullptr};
    QPushButton  *m_btnExportPdf{nullptr};
    QPushButton  *m_btnExportHtml{nullptr};
    QLabel       *m_lblStatus{nullptr};

    // ── 主 Tab ───────────────────────────────────────────────────────────
    QTabWidget   *m_tabMain{nullptr};

    // ── 缓存 ──────────────────────────────────────────────────────────────
    ReportData    m_lastData;
    bool          m_dataReady{false};
};

#endif // REPORTPAGE_H
