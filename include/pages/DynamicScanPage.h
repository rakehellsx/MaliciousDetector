#pragma once
#ifndef DYNAMICSCANPAGE_H
#define DYNAMICSCANPAGE_H
#include "pages/BasePage.h"
#include <QLineEdit>
#include <QTabWidget>
#include <QTableWidget>
#include <QTreeWidget>
#include <QPushButton>
class DynamicScanPage : public BasePage {
    Q_OBJECT
public:
    explicit DynamicScanPage(QWidget *p=nullptr);
    void refreshData() override;
private slots:
    void onBrowseFile();
    void onStartScan();
    void onStopScan();
private:
    void setupUi();
    void loadBehaviorData(const QString &type);
    QLineEdit    *m_editPath;
    QPushButton  *m_btnBrowse;
    QPushButton  *m_btnStart;
    QPushButton  *m_btnStop;
    QTabWidget   *m_tabBehavior;
    QTableWidget *m_tblRegistry;
    QTableWidget *m_tblFile;
    QTreeWidget  *m_treeProcess;
    QTableWidget *m_tblProcessDetail;
    QTableWidget *m_tblNetwork;
    QTableWidget *m_tblSsdt;
    QTableWidget *m_tblAutorun;
    QTableWidget *m_tblTask;
    QTableWidget *m_tblBrowserPlugin;
};
#endif
