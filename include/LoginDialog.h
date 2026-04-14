#pragma once
#ifndef LOGINDIALOG_H
#define LOGINDIALOG_H

#include <QDialog>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QButtonGroup>
#include <QTimer>

class LoginDialog : public QDialog
{
    Q_OBJECT
public:
    explicit LoginDialog(QWidget *parent = nullptr);

    QString selectedRole()    const;
    QString enteredUsername() const;

private slots:
    void onLoginClicked();
    void onRoleChanged(int id);

private:
    void setupUi();
    void applyStyle();

    QButtonGroup *m_roleGroup;
    QPushButton  *m_btnSysAdmin;
    QPushButton  *m_btnSecAdmin;
    QPushButton  *m_btnAuditor;
    QLineEdit    *m_editUser;
    QLineEdit    *m_editPass;
    QPushButton  *m_btnLogin;
    QLabel       *m_lblUsbStatus;
    QLabel       *m_lblVersion;
    QLabel       *m_lblError;

    QString m_currentRole;
};

#endif // LOGINDIALOG_H
