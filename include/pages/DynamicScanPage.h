#pragma once
#ifndef DYNAMICSCANPAGE_H
#define DYNAMICSCANPAGE_H

#include "pages/BasePage.h"
#include <QComboBox>
#include <QLineEdit>
#include <QTabWidget>
#include <QTableWidget>
#include <QTreeWidget>
#include <QPushButton>
#include <QLabel>
#include <QSplitter>
#include <QFrame>
#include <QScrollArea>

namespace Ui { class DynamicScanPage; }

class DynamicScanPage : public BasePage {
    Q_OBJECT
public:
    explicit DynamicScanPage(QWidget *p = nullptr);
    void refreshData() override;

private slots:
    // 全局行为监测
    void onBrowseFile();
    void onStartScan();
    void onStopScan();
    // 各子Tab独立查询
    void onQueryRegistry();
    void onQueryFile();
    void onQueryProcess();
    void onQueryNetwork();
    void onQuerySsdt();
    void onQueryAutorun();
    void onQueryTask();
    void onQueryPlugin();
    void onQueryFileAssoc();
    void onQueryRctrl();
    // 进程链行为分析
    void onRefreshProcessChain();
    void onProcessTreeItemClicked(QTreeWidgetItem *item, int col);

private:
    Ui::DynamicScanPage *ui{nullptr};
    bool eventFilter(QObject *obj, QEvent *event) override;

    void queryAndFillTable(QTableWidget *tbl,
                           const QString &type,
                           const QString &kw,
                           const QString &risk,
                           const QString &extraFilter = QString());
    void loadProcessCards();
    void buildProcessTree(int rootPid);
    void loadBehaviorForPid(int pid, const QString &procName);
    QFrame* makeProcessCard(int pid, const QString &name,
                            const QString &createTime, const QString &risk);

    // ── 外层 Tab ─────────────────────────────────────────────────────────────
    QTabWidget   *m_tabMain{nullptr};

    // ── 全局行为监测 扫描控制 ─────────────────────────────────────────────────
    QLineEdit    *m_editPath{nullptr};
    QPushButton  *m_btnBrowse{nullptr};
    QPushButton  *m_btnStart{nullptr};
    QPushButton  *m_btnStop{nullptr};
    QLabel       *m_lblMonitorStatus{nullptr};
    QLabel       *m_lblStatus{nullptr};

    // ── 内层行为 Tab ──────────────────────────────────────────────────────────
    QTabWidget   *m_tabBehavior{nullptr};

    // 注册表操作
    QComboBox    *m_cmbRegOp{nullptr};
    QComboBox    *m_cmbRegRisk{nullptr};
    QLineEdit    *m_edtRegKw{nullptr};
    QPushButton  *m_btnRegQuery{nullptr};
    QTableWidget *m_tblRegistry{nullptr};

    // 文件行为
    QComboBox    *m_cmbFileOp{nullptr};
    QComboBox    *m_cmbFileRisk{nullptr};
    QLineEdit    *m_edtFileKw{nullptr};
    QPushButton  *m_btnFileQuery{nullptr};
    QTableWidget *m_tblFile{nullptr};

    // 进程行为
    QComboBox    *m_cmbProcOp{nullptr};
    QComboBox    *m_cmbProcRisk{nullptr};
    QLineEdit    *m_edtProcKw{nullptr};
    QPushButton  *m_btnProcQuery{nullptr};
    QTableWidget *m_tblProcess{nullptr};

    // 网络行为
    QComboBox    *m_cmbNetProto{nullptr};
    QComboBox    *m_cmbNetRisk{nullptr};
    QLineEdit    *m_edtNetKw{nullptr};
    QPushButton  *m_btnNetQuery{nullptr};
    QTableWidget *m_tblNetwork{nullptr};

    // SSDT操作
    QComboBox    *m_cmbSsdtRisk{nullptr};
    QLineEdit    *m_edtSsdtKw{nullptr};
    QPushButton  *m_btnSsdtQuery{nullptr};
    QTableWidget *m_tblSsdt{nullptr};

    // 启动项操作
    QComboBox    *m_cmbAutorunOp{nullptr};
    QComboBox    *m_cmbAutorunRisk{nullptr};
    QLineEdit    *m_edtAutorunKw{nullptr};
    QPushButton  *m_btnAutorunQuery{nullptr};
    QTableWidget *m_tblAutorun{nullptr};

    // 计划任务操作
    QComboBox    *m_cmbTaskOp{nullptr};
    QComboBox    *m_cmbTaskRisk{nullptr};
    QLineEdit    *m_edtTaskKw{nullptr};
    QPushButton  *m_btnTaskQuery{nullptr};
    QTableWidget *m_tblTask{nullptr};

    // 浏览器插件操作
    QComboBox    *m_cmbPluginOp{nullptr};
    QComboBox    *m_cmbPluginRisk{nullptr};
    QLineEdit    *m_edtPluginKw{nullptr};
    QPushButton  *m_btnPluginQuery{nullptr};
    QTableWidget *m_tblBrowserPlugin{nullptr};

    // 文件关联检测（内嵌子Tab）
    QComboBox    *m_cmbFileAssocStatus{nullptr};
    QComboBox    *m_cmbFileAssocRisk{nullptr};
    QLineEdit    *m_edtFileAssocKw{nullptr};
    QPushButton  *m_btnFileAssocQuery{nullptr};
    QTableWidget *m_tblFileAssoc{nullptr};

    // 远控行为分析
    QComboBox    *m_cmbRctrlType{nullptr};
    QComboBox    *m_cmbRctrlRisk{nullptr};
    QLineEdit    *m_edtRctrlKw{nullptr};
    QPushButton  *m_btnRctrlQuery{nullptr};
    QTableWidget *m_tblRctrl{nullptr};

    // ── 进程链行为分析 ────────────────────────────────────────────────────────
    QScrollArea  *m_scrollCards{nullptr};
    QWidget      *m_cardContainer{nullptr};
    QTreeWidget  *m_chainTree{nullptr};
    QTableWidget *m_tblProcessDetail{nullptr};
    QLabel       *m_lblChainBehaviorTitle{nullptr};
    QPushButton  *m_btnRefreshChain{nullptr};
    int          m_selectedRootPid{-1};
};

#endif // DYNAMICSCANPAGE_H
