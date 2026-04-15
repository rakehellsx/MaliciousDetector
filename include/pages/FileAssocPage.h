#pragma once
#ifndef FILEASSOCPAGE_H
#define FILEASSOCPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
#include <QLineEdit>
#include <QComboBox>
#include <QPushButton>
#include <QLabel>

namespace Ui { class FileAssocPage; }

class FileAssocPage : public BasePage {
    Q_OBJECT
public:
    explicit FileAssocPage(QWidget *p = nullptr);
    void refreshData() override;
private slots:
    void onQuery();
private:
    Ui::FileAssocPage *ui{nullptr};
    void setupUi();
    void fillTable(const QVariantList &rows);
    QTableWidget *m_tbl{nullptr};
    QPushButton  *m_btnScan{nullptr};
    QLineEdit    *m_edtKeyword{nullptr};
    QComboBox    *m_cmbRisk{nullptr};
    QLabel       *m_lblSummary{nullptr};
    QLabel       *m_lblStatus{nullptr};
};
#endif
