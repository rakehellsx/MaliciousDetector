#pragma once
#ifndef PROCESSINFOPAGE_H
#define PROCESSINFOPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
#include <QLineEdit>
#include <QComboBox>
#include <QLabel>
namespace Ui { class ProcessInfoPage; }

class ProcessInfoPage : public BasePage {
    Q_OBJECT
public:
    explicit ProcessInfoPage(QWidget *p=nullptr);
    void refreshData() override;
private slots:
    void onQuery();
    void onDetailClicked();
private:
    Ui::ProcessInfoPage *ui{nullptr};
    void loadDemoData();
    void fillTable(const QVariantList &rows);
    QTableWidget *m_tbl{nullptr};
    QLineEdit    *m_edtKeyword{nullptr};
    QComboBox    *m_cmbRisk{nullptr};
    QComboBox    *m_cmbStatus{nullptr};
    QLabel       *m_lblStatus{nullptr};
};
#endif
