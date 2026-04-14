#pragma once
#ifndef PORTINFOPAGE_H
#define PORTINFOPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
#include <QComboBox>
#include <QLineEdit>
#include <QLabel>
class PortInfoPage : public BasePage {
    Q_OBJECT
public:
    explicit PortInfoPage(QWidget *p=nullptr);
    void refreshData() override;
private slots:
    void onQuery();
private:
    void setupUi();
    void fillTable(const QVariantList &rows);
    QTableWidget *m_tbl{nullptr};
    QLineEdit    *m_edtKeyword{nullptr};  // 本地IP/端口/远程地址/进程名
    QComboBox    *m_cmbProto{nullptr};    // 协议
    QComboBox    *m_cmbRisk{nullptr};     // 风险等级
    QLabel       *m_lblStatus{nullptr};
};
#endif
