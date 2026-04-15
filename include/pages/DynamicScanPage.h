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
    void onQueryBehavior();
    // 进程链行为分析
    void onRefreshProcessChain();
    void onProcessTreeItemClicked(QTreeWidgetItem *item, int col);

private:
    Ui::DynamicScanPage *ui{nullptr};
    void setupUi();
    bool eventFilter(QObject *obj, QEvent *event) override;
    // ── 全局行为监测 Tab ─────────────────────────────────────────────────────
    QWidget* buildGlobalTab();
    void queryAndFill(QTableWidget *tbl, const QString &type,
                      const QString &kw, const QString &risk);

    // ── 进程链行为分析 Tab ───────────────────────────────────────────────────
    QWidget* buildChainTab();
    void loadProcessCards();
    void buildProcessTree(int rootPid);
    void loadBehaviorForPid(int pid, const QString &procName);
    QFrame* makeProcessCard(int pid, const QString &name,
                            const QString &createTime, const QString &risk);

    // ── 外层 Tab ─────────────────────────────────────────────────────────────
    QTabWidget   *m_tabOuter{nullptr};

    // ── 全局行为监测 ──────────────────────────────────────────────────────────
    QLineEdit    *m_editPath{nullptr};
    QPushButton  *m_btnBrowse{nullptr};
    QPushButton  *m_btnStart{nullptr};
    QPushButton  *m_btnStop{nullptr};
    QLabel       *m_lblMonitorStatus{nullptr};
    QLabel       *m_lblStatus{nullptr};
    QLineEdit    *m_edtBehaviorKw{nullptr};
    QComboBox    *m_cmbBehaviorRisk{nullptr};
    QTabWidget   *m_tabBehavior{nullptr};
    QTableWidget *m_tblRegistry{nullptr};
    QTableWidget *m_tblFile{nullptr};
    QTableWidget *m_tblNetwork{nullptr};
    QTableWidget *m_tblSsdt{nullptr};
    QTableWidget *m_tblAutorun{nullptr};
    QTableWidget *m_tblTask{nullptr};
    QTableWidget *m_tblBrowserPlugin{nullptr};
    QTableWidget *m_tblProcessDetail{nullptr};

    // ── 进程链行为分析 ────────────────────────────────────────────────────────
    QScrollArea  *m_scrollCards{nullptr};   // 左：进程卡片滚动区
    QWidget      *m_cardContainer{nullptr}; // 左：卡片容器
    QTreeWidget  *m_chainTree{nullptr};     // 中：进程树
    QTableWidget *m_chainBehavior{nullptr}; // 右：行为信息表
    QLabel       *m_lblChainBehaviorTitle{nullptr};
    QPushButton  *m_btnRefreshChain{nullptr};
    int          m_selectedRootPid{-1};
};

#endif
