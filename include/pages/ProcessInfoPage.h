#pragma once
#ifndef PROCESSINFOPAGE_H
#define PROCESSINFOPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
#include <QLineEdit>
#include <QLabel>
#include <QVariantMap>
class ProcessInfoPage : public BasePage {
    Q_OBJECT
public:
    explicit ProcessInfoPage(QWidget *p=nullptr);
    void refreshData() override;
private slots:
    void filterTable(const QString &kw);
private:
    void setupUi();
    QTableWidget       *m_tbl{nullptr};
    QLineEdit          *m_edtSearch{nullptr};
    QLabel             *m_lblStatus{nullptr};
    QList<QVariantMap>  m_allRows;
};
#endif
