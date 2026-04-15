#pragma once
#ifndef LOGINDIALOG_H
#define LOGINDIALOG_H

#include <QDialog>
#include <QButtonGroup>

namespace Ui { class LoginDialog; }

class LoginDialog : public QDialog
{
    Q_OBJECT
public:
    explicit LoginDialog(QWidget *parent = nullptr);
    ~LoginDialog();

    QString selectedRole()    const;
    QString enteredUsername() const;

private slots:
    void onLoginClicked();
    void onRoleChanged(int id);

private:
    Ui::LoginDialog *ui;
    QButtonGroup    *m_roleGroup;
    QString          m_currentRole;
};

#endif // LOGINDIALOG_H
