#pragma once
#ifndef PROCESSINFOPAGE_H
#define PROCESSINFOPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
#include <QLineEdit>
#include <QComboBox>
#include <QLabel>
class ProcessInfoPage : public BasePage {
    Q_OBJECT
public:
    explicit ProcessInfoPage(QWidget *p=nullptr);
    void refreshData() override;
private slots:
    void onQuery();
private:
    void setupUi();
    void fillTable(const QVariantList &rows);
    QTableWidget *m_tbl{nullptr};
    QLineEdit    *m_edtKeyword{nullptr};  // 进程名/路径/用户
    QComboBox    *m_cmbRisk{nullptr};     // 风险等级
    QComboBox    *m_cmbStatus{nullptr};   // 进程状态
    QLabel       *m_lblStatus{nullptr};
};
#endif
