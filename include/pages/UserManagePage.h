#pragma once
#ifndef USERMANAGEPAGE_H
#define USERMANAGEPAGE_H

#include "pages/BasePage.h"
#include <QTableWidget>
#include <QLineEdit>
#include <QComboBox>
#include <QPushButton>
#include <QLabel>

namespace Ui { class UserManagePage; }

class UserManagePage : public BasePage {
    Q_OBJECT
public:
    explicit UserManagePage(QWidget *parent = nullptr);
    ~UserManagePage();
    void refreshData() override;

private slots:
    void onAddUser();
    void onEditUser();
    void onDeleteUser();
    void onResetPassword();
    void onSearch();

private:
    void loadUsers();
    void showUserDialog(bool isEdit, int row = -1);

    Ui::UserManagePage *ui{nullptr};

    // 从 ui 绑定的控件指针（方便代码访问）
    QLineEdit    *m_edtSearch{nullptr};
    QComboBox    *m_cmbRole{nullptr};
    QComboBox    *m_cmbStatus{nullptr};
    QPushButton  *m_btnSearch{nullptr};
    QPushButton  *m_btnAdd{nullptr};
    QPushButton  *m_btnEdit{nullptr};
    QPushButton  *m_btnDelete{nullptr};
    QPushButton  *m_btnReset{nullptr};
    QTableWidget *m_tblUsers{nullptr};
};

#endif // USERMANAGEPAGE_H
