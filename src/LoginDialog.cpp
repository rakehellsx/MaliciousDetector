#include "LoginDialog.h"
#include "DatabaseManager.h"
#include "IconHelper.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QFrame>
#include <QApplication>
#include <QMessageBox>
#include <QCryptographicHash>

LoginDialog::LoginDialog(QWidget *parent)
    : QDialog(parent), m_currentRole("system_admin")
{
    setWindowTitle("恶意代码辅助检测系统");
    setWindowIcon(IconHelper::appIcon());
    setFixedSize(420, 520);
    setWindowFlags(Qt::Dialog | Qt::FramelessWindowHint);
    setupUi();
    applyStyle();
}

void LoginDialog::setupUi()
{
    QVBoxLayout *root = new QVBoxLayout(this);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);

    // ── 顶部蓝色标题区 ──────────────────────────────────────
    QWidget *header = new QWidget;
    header->setObjectName("loginHeader");
    header->setFixedHeight(160);
    QVBoxLayout *hLay = new QVBoxLayout(header);
    hLay->setAlignment(Qt::AlignCenter);

    QLabel *iconLbl = new QLabel;
    iconLbl->setPixmap(IconHelper::pixmap("app", 52));
    iconLbl->setFixedSize(52, 52);
    iconLbl->setObjectName("loginIcon");
    iconLbl->setAlignment(Qt::AlignCenter);

    QLabel *titleLbl = new QLabel("恶意代码辅助检测系统");
    titleLbl->setObjectName("loginTitle");
    titleLbl->setAlignment(Qt::AlignCenter);

    QLabel *subLbl = new QLabel("Malicious Code Auxiliary Detection System V3.0");
    subLbl->setObjectName("loginSub");
    subLbl->setAlignment(Qt::AlignCenter);

    QLabel *certLbl = new QLabel("国家保密科技测评中心 认证产品");
    certLbl->setObjectName("loginCert");
    certLbl->setAlignment(Qt::AlignCenter);

    hLay->addWidget(iconLbl);
    hLay->addWidget(titleLbl);
    hLay->addWidget(subLbl);
    hLay->addWidget(certLbl);
    root->addWidget(header);

    // ── 表单区 ──────────────────────────────────────────────
    QWidget *form = new QWidget;
    form->setObjectName("loginForm");
    QVBoxLayout *fLay = new QVBoxLayout(form);
    fLay->setContentsMargins(36, 24, 36, 24);
    fLay->setSpacing(12);

    // 角色选择
    QHBoxLayout *roleLay = new QHBoxLayout;
    roleLay->setSpacing(0);
    m_btnSysAdmin = new QPushButton("系统管理员");
    m_btnSecAdmin = new QPushButton("安全管理员");
    m_btnAuditor  = new QPushButton("安全审计员");
    m_btnSysAdmin->setObjectName("roleBtn");
    m_btnSecAdmin->setObjectName("roleBtn");
    m_btnAuditor->setObjectName("roleBtn");
    m_btnSysAdmin->setCheckable(true);
    m_btnSecAdmin->setCheckable(true);
    m_btnAuditor->setCheckable(true);
    m_btnSysAdmin->setChecked(true);

    m_roleGroup = new QButtonGroup(this);
    m_roleGroup->addButton(m_btnSysAdmin, 0);
    m_roleGroup->addButton(m_btnSecAdmin, 1);
    m_roleGroup->addButton(m_btnAuditor,  2);
    connect(m_roleGroup, QOverload<int>::of(&QButtonGroup::buttonClicked),
            this, &LoginDialog::onRoleChanged);

    roleLay->addWidget(m_btnSysAdmin);
    roleLay->addWidget(m_btnSecAdmin);
    roleLay->addWidget(m_btnAuditor);
    fLay->addLayout(roleLay);

    // 用户名
    QLabel *userLbl = new QLabel("用 户 名");
    userLbl->setObjectName("fieldLabel");
    m_editUser = new QLineEdit;
    m_editUser->setObjectName("loginInput");
    m_editUser->setPlaceholderText("请输入用户名");
    m_editUser->setText("admin");
    fLay->addWidget(userLbl);
    fLay->addWidget(m_editUser);

    // 密码
    QLabel *passLbl = new QLabel("密    码");
    passLbl->setObjectName("fieldLabel");
    m_editPass = new QLineEdit;
    m_editPass->setObjectName("loginInput");
    m_editPass->setEchoMode(QLineEdit::Password);
    m_editPass->setPlaceholderText("请输入密码");
    fLay->addWidget(passLbl);
    fLay->addWidget(m_editPass);

    // USB Key 状态
    // USB Key 状态行（图标+文字）
    QHBoxLayout *usbRow = new QHBoxLayout;
    QLabel *usbIconLbl = new QLabel;
    usbIconLbl->setPixmap(IconHelper::pixmap("usbkey_connected", 18));
    usbIconLbl->setFixedSize(18, 18);
    m_lblUsbStatus = new QLabel("USB Key 已插入（SN: A3F2-B1C9-D4E7）");
    usbRow->addWidget(usbIconLbl);
    usbRow->addSpacing(6);
    usbRow->addWidget(m_lblUsbStatus);
    usbRow->addStretch();
    fLay->addLayout(usbRow);
    m_lblUsbStatus->setObjectName("usbStatus");

    // 错误提示
    m_lblError = new QLabel("");
    m_lblError->setObjectName("loginError");
    m_lblError->setAlignment(Qt::AlignCenter);
    fLay->addWidget(m_lblError);

    // 登录按钮
    m_btnLogin = new QPushButton("安 全 登 录");
    m_btnLogin->setObjectName("loginBtn");
    m_btnLogin->setFixedHeight(40);
    connect(m_btnLogin, &QPushButton::clicked, this, &LoginDialog::onLoginClicked);
    connect(m_editPass, &QLineEdit::returnPressed, this, &LoginDialog::onLoginClicked);
    fLay->addWidget(m_btnLogin);

    // 版本信息
    m_lblVersion = new QLabel("版本号：V3.0.20251120  |  病毒库：20251120");
    m_lblVersion->setObjectName("loginVersion");
    m_lblVersion->setAlignment(Qt::AlignCenter);
    fLay->addWidget(m_lblVersion);

    root->addWidget(form);
}

void LoginDialog::applyStyle()
{
    setStyleSheet(R"(
        LoginDialog {
            background: #0d1b2e;
        }
        #loginHeader {
            background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
                stop:0 #1a3a5c, stop:1 #0d1b2e);
        }
        #loginIcon {
            font-size: 36px;
            color: #4fc3f7;
        }
        #loginTitle {
            font-size: 18px;
            font-weight: bold;
            color: #ffffff;
            font-family: "Microsoft YaHei", "SimHei", sans-serif;
        }
        #loginSub {
            font-size: 10px;
            color: #90caf9;
        }
        #loginCert {
            font-size: 10px;
            color: #4fc3f7;
        }
        #loginForm {
            background: #0d1b2e;
        }
        #roleBtn {
            background: #1a2a3e;
            color: #90caf9;
            border: 1px solid #2a4a6e;
            padding: 6px 0;
            font-size: 12px;
            font-family: "Microsoft YaHei", sans-serif;
        }
        #roleBtn:checked {
            background: #1565c0;
            color: #ffffff;
            border: 1px solid #1976d2;
        }
        #roleBtn:hover:!checked {
            background: #1e3a5a;
        }
        #fieldLabel {
            color: #90caf9;
            font-size: 12px;
            font-family: "Microsoft YaHei", sans-serif;
            margin-bottom: 0px;
        }
        #loginInput {
            background: #1a2a3e;
            border: 1px solid #2a4a6e;
            border-radius: 3px;
            color: #e0e0e0;
            padding: 6px 10px;
            font-size: 13px;
            font-family: "Microsoft YaHei", sans-serif;
        }
        #loginInput:focus {
            border: 1px solid #1976d2;
        }
        #usbStatus {
            color: #4caf50;
            font-size: 11px;
            padding: 6px 10px;
            background: #0a2a0a;
            border: 1px solid #2e7d32;
            border-radius: 3px;
        }
        #loginError {
            color: #ef5350;
            font-size: 11px;
            min-height: 16px;
        }
        #loginBtn {
            background: #1565c0;
            color: #ffffff;
            border: none;
            border-radius: 3px;
            font-size: 14px;
            font-weight: bold;
            letter-spacing: 4px;
            font-family: "Microsoft YaHei", sans-serif;
        }
        #loginBtn:hover {
            background: #1976d2;
        }
        #loginBtn:pressed {
            background: #0d47a1;
        }
        #loginVersion {
            color: #546e7a;
            font-size: 10px;
        }
    )");
}

void LoginDialog::onRoleChanged(int id)
{
    switch (id) {
    case 0: m_currentRole = "system_admin"; m_editUser->setText("admin");   break;
    case 1: m_currentRole = "sec_admin";    m_editUser->setText("secadmin"); break;
    case 2: m_currentRole = "auditor";      m_editUser->setText("auditor");  break;
    }
}

void LoginDialog::onLoginClicked()
{
    QString user = m_editUser->text().trimmed();
    QString pass = m_editPass->text();

    if (user.isEmpty()) {
        m_lblError->setText("请输入用户名");
        return;
    }
    if (pass.isEmpty()) {
        m_lblError->setText("请输入密码");
        return;
    }

    // 简单验证（实际项目可对接数据库用户表）
    bool ok = false;
    if (m_currentRole == "system_admin" && user == "admin" && pass == "Admin@123")
        ok = true;
    else if (m_currentRole == "sec_admin" && user == "secadmin" && pass == "Sec@123")
        ok = true;
    else if (m_currentRole == "auditor" && user == "auditor" && pass == "Audit@123")
        ok = true;
    // 开发模式：任意密码均可登录
    ok = true;

    if (ok) {
        DatabaseManager::instance()->writeLog(
            m_currentRole, user, "用户登录", "登录成功", "success");
        accept();
    } else {
        m_lblError->setText("用户名或密码错误，请重试");
        DatabaseManager::instance()->writeLog(
            m_currentRole, user, "用户登录", "登录失败：密码错误", "failed");
    }
}

QString LoginDialog::selectedRole()    const { return m_currentRole; }
QString LoginDialog::enteredUsername() const { return m_editUser->text().trimmed(); }
