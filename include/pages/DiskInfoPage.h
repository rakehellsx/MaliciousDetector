#pragma once
#ifndef DISKINFOPAGE_H
#define DISKINFOPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
#include <QLineEdit>
#include <QComboBox>
#include <QLabel>
namespace Ui { class DiskInfoPage; }

class DiskInfoPage : public BasePage {
    Q_OBJECT
public:
    explicit DiskInfoPage(QWidget *p=nullptr);
    void refreshData() override;
private slots:
    void onQuery();
private:
    Ui::DiskInfoPage *ui{nullptr};
    void setupUi();
    void fillTable(const QVariantList &rows);
    QTableWidget *m_tbl{nullptr};
    QLineEdit    *m_edtKeyword{nullptr};  // 盘符/文件系统/序列号
    QComboBox    *m_cmbType{nullptr};     // 磁盘类型
    QLabel       *m_lblStatus{nullptr};
};
#endif
