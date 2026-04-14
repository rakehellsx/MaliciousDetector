#pragma once
#ifndef MEMORYIMAGEPAGE_H
#define MEMORYIMAGEPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
#include <QLineEdit>
#include <QComboBox>
#include <QLabel>
#include <QPushButton>
#include <QSplitter>
#include <QJsonObject>
#include <QVariantMap>
#include <QVariantList>

class MemoryImagePage : public BasePage {
    Q_OBJECT
public:
    explicit MemoryImagePage(QWidget *p = nullptr);
    void refreshData() override;

private slots:
    void onQueryKernel();
    void onQueryProc();

private:
    void setupUi();
    void populateMemoryStatus(const QJsonObject &data);
    void populateKernelModules(const QJsonObject &data);
    void populateProcessMemory(const QJsonObject &data);
    void populateMemoryStatusFromDB(const QVariantMap &row);
    void populateKernelModulesFromDB(const QVariantList &rows);
    void populateProcessMemoryFromDB(const QVariantList &rows);

    // 内存运行状态
    QTableWidget *m_tblStatus   = nullptr;
    // 内核模块列表（带查询栏）
    QTableWidget *m_tblKernel   = nullptr;
    QLineEdit    *m_edtKernelKw = nullptr;
    QComboBox    *m_cmbKernelTrusted = nullptr;
    // 进程内存映射（带查询栏）
    QTableWidget *m_tblProc     = nullptr;
    QLineEdit    *m_edtProcKw   = nullptr;
    QComboBox    *m_cmbProcSuspect = nullptr;
    // 摘要标签
    QLabel *m_lblKernelSummary  = nullptr;
    QLabel *m_lblProcSummary    = nullptr;
    QPushButton *m_btnSave      = nullptr;
};
#endif
