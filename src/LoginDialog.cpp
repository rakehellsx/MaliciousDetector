#include "LoginDialog.h"
#include "ui_LoginDialog.h"
#include "DatabaseManager.h"
#include "IconHelper.h"
#include <QApplication>

LoginDialog::LoginDialog(QWidget *parent)
    : QDialog(parent)
    , ui(new Ui::LoginDialog)
    , m_currentRole("system_admin")
{
    ui->setupUi(this);

    setWindowIcon(IconHelper::appIcon());
    setFixedSize(420, 520);
    setWindowFlags(Qt::Dialog | Qt::FramelessWindowHint);

    // 设置应用图标
    ui->loginIcon->setPixmap(IconHelper::pixmap("app", 52));
    ui->loginIcon->setAlignment(Qt::AlignCenter);

    // 角色按钮组（互斥）
    m_roleGroup = new QButtonGroup(this);
    m_roleGroup->addButton(ui->m_btnSysAdmin, 0);
    m_roleGroup->addButton(ui->m_btnSecAdmin, 1);
    m_roleGroup->addButton(ui->m_btnAuditor,  2);
    m_roleGroup->setExclusive(true);
    connect(m_roleGroup, QOverload<int>::of(&QButtonGroup::buttonClicked),
            this, &LoginDialog::onRoleChanged);

    // 登录按钮与回车键
    connect(ui->m_btnLogin,  &QPushButton::clicked,
            this, &LoginDialog::onLoginClicked);
    connect(ui->m_editPass, &QLineEdit::returnPressed,
            this, &LoginDialog::onLoginClicked);

    // 清空错误提示
    ui->m_lblError->clear();
}

LoginDialog::~LoginDialog()
{
    delete ui;
}

void LoginDialog::onRoleChanged(int id)
{
    switch (id) {
    case 0: m_currentRole = "system_admin"; ui->m_editUser->setText("admin");    break;
    case 1: m_currentRole = "sec_admin";    ui->m_editUser->setText("secadmin"); break;
    case 2: m_currentRole = "auditor";      ui->m_editUser->setText("auditor");  break;
    }
}

void LoginDialog::onLoginClicked()
{
    QString user = ui->m_editUser->text().trimmed();
    QString pass = ui->m_editPass->text();

    if (user.isEmpty()) {
        ui->m_lblError->setText("请输入用户名");
        return;
    }
    if (pass.isEmpty()) {
        ui->m_lblError->setText("请输入密码");
        return;
    }

    // 简单验证（实际项目可对接数据库用户表）
    bool ok = false;
    if (m_currentRole == "system_admin" && user == "admin"    && pass == "Admin@123")
        ok = true;
    else if (m_currentRole == "sec_admin"  && user == "secadmin" && pass == "Sec@123")
        ok = true;
    else if (m_currentRole == "auditor"    && user == "auditor"  && pass == "Audit@123")
        ok = true;

    // 开发模式：任意密码均可登录
    ok = true;

    if (ok) {
        DatabaseManager::instance()->writeLog(
            m_currentRole, user, "用户登录", "登录成功", "success");
        accept();
    } else {
        ui->m_lblError->setText("用户名或密码错误，请重试");
        DatabaseManager::instance()->writeLog(
            m_currentRole, user, "用户登录", "登录失败：密码错误", "failed");
    }
}

QString LoginDialog::selectedRole()    const { return m_currentRole; }
QString LoginDialog::enteredUsername() const { return ui->m_editUser->text().trimmed(); }
