#pragma once
#ifndef NETWORKINFOPAGE_H
#define NETWORKINFOPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
#include <QLineEdit>
#include <QComboBox>
#include <QLabel>
namespace Ui { class NetworkInfoPage; }

class NetworkInfoPage : public BasePage {
    Q_OBJECT
public:
    explicit NetworkInfoPage(QWidget *p=nullptr);
    void refreshData() override;
private slots:
    void onQuery();
private:
    Ui::NetworkInfoPage *ui{nullptr};
    void setupUi();
    void fillTable(const QVariantList &rows);
    QTableWidget *m_tbl{nullptr};
    QLineEdit    *m_edtKeyword{nullptr};  // 关键字：适配器名/IP/MAC
    QComboBox    *m_cmbStatus{nullptr};   // 状态筛选
    QLabel       *m_lblStatus{nullptr};
};
#endif
