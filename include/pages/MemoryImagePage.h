#pragma once
#ifndef MEMORYIMAGEPAGE_H
#define MEMORYIMAGEPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
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

private:
    void setupUi();
    // 从 basic.dll QJsonObject 填充
    void populateMemoryStatus(const QJsonObject &data);
    void populateKernelModules(const QJsonObject &data);
    void populateProcessMemory(const QJsonObject &data);
    // 从 DatabaseManager QVariantMap/QVariantList 填充
    void populateMemoryStatusFromDB(const QVariantMap &row);
    void populateKernelModulesFromDB(const QVariantList &rows);
    void populateProcessMemoryFromDB(const QVariantList &rows);

    // 内存运行状态
    QTableWidget *m_tblStatus   = nullptr;
    // 内核模块列表
    QTableWidget *m_tblKernel   = nullptr;
    // 进程内存映射
    QTableWidget *m_tblProc     = nullptr;
    // 摘要标签
    QLabel *m_lblKernelSummary  = nullptr;
    QLabel *m_lblProcSummary    = nullptr;
    // 保存按钮
    QPushButton *m_btnSave      = nullptr;
};
#endif
