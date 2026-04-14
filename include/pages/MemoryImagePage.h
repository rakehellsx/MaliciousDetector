#pragma once
#ifndef MEMORYIMAGEPAGE_H
#define MEMORYIMAGEPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
#include <QLabel>
#include <QPushButton>
#include <QSplitter>

class MemoryImagePage : public BasePage {
    Q_OBJECT
public:
    explicit MemoryImagePage(QWidget *p = nullptr);
    void refreshData() override;

private:
    void setupUi();
    void populateMemoryStatus(const QJsonObject &data);
    void populateKernelModules(const QJsonObject &data);
    void populateProcessMemory(const QJsonObject &data);

    // 内存运行状态
    QTableWidget *m_tblStatus;
    // 内核模块列表
    QTableWidget *m_tblKernel;
    // 进程内存映射
    QTableWidget *m_tblProc;
    // 摘要标签
    QLabel *m_lblKernelSummary;
    QLabel *m_lblProcSummary;
    // 保存按钮
    QPushButton *m_btnSave;
};
#endif
