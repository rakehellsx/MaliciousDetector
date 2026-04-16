#include "pages/UserManagePage.h"
#include "ui_UserManagePage.h"
#include "DatabaseManager.h"
#include <QHBoxLayout>
#include <QHeaderView>
#include <QMessageBox>
#include <QInputDialog>
#include <QDialog>
#include <QFormLayout>
#include <QLineEdit>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QSqlQuery>
#include <QDateTime>
#include <QCryptographicHash>
#include <QLabel>

static QString hashPwd(const QString &pwd) {
    return QCryptographicHash::hash(pwd.toUtf8(), QCryptographicHash::Sha256).toHex();
}

UserManagePage::UserManagePage(QWidget *parent)
    : BasePage("用户管理", parent)
{
    ui = new Ui::UserManagePage();
    ui->setupUi(this);
    postSetupUi();

    // 绑定控件
    m_edtSearch  = ui->m_edtSearch;
    m_cmbRole    = ui->m_cmbRole;
    m_cmbStatus  = ui->m_cmbStatus;
    m_btnSearch  = ui->m_btnSearch;
    m_btnAdd     = ui->m_btnAdd;
    m_btnEdit    = ui->m_btnEdit;
    m_btnDelete  = ui->m_btnDelete;
    m_btnReset   = ui->m_btnReset;
    m_tblUsers   = ui->m_tblUsers;

    // 表格配置
    m_tblUsers->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_tblUsers->horizontalHeader()->setStretchLastSection(true);
    m_tblUsers->verticalHeader()->setVisible(false);
    m_tblUsers->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_tblUsers->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_tblUsers->setAlternatingRowColors(true);

    // 按钮样式
    m_btnAdd->setStyleSheet(
        "QPushButton{background:#52c41a;color:#fff;border:none;border-radius:3px;padding:4px 12px;}"
        "QPushButton:hover{background:#73d13d;}");
    m_btnEdit->setStyleSheet(
        "QPushButton{background:#1890ff;color:#fff;border:none;border-radius:3px;padding:4px 12px;}"
        "QPushButton:hover{background:#40a9ff;}");
    m_btnReset->setStyleSheet(
        "QPushButton{background:#fa8c16;color:#fff;border:none;border-radius:3px;padding:4px 12px;}"
        "QPushButton:hover{background:#ffa940;}");
    m_btnDelete->setStyleSheet(
        "QPushButton{background:#f5222d;color:#fff;border:none;border-radius:3px;padding:4px 12px;}"
        "QPushButton:hover{background:#ff4d4f;}");
    m_btnSearch->setStyleSheet(
        "QPushButton{background:#1a3a6a;color:#fff;border:none;border-radius:3px;padding:4px 12px;}"
        "QPushButton:hover{background:#2a5a9a;}");

    // 信号连接
    connect(m_btnSearch, &QPushButton::clicked, this, &UserManagePage::onSearch);
    connect(m_btnAdd,    &QPushButton::clicked, this, &UserManagePage::onAddUser);
    connect(m_btnEdit,   &QPushButton::clicked, this, &UserManagePage::onEditUser);
    connect(m_btnDelete, &QPushButton::clicked, this, &UserManagePage::onDeleteUser);
    connect(m_btnReset,  &QPushButton::clicked, this, &UserManagePage::onResetPassword);
    connect(m_edtSearch, &QLineEdit::returnPressed, this, &UserManagePage::onSearch);

    refreshData();
}

UserManagePage::~UserManagePage() { delete ui; }

void UserManagePage::refreshData() { loadUsers(); }

void UserManagePage::loadUsers()
{
    m_tblUsers->setRowCount(0);
    QString kw    = m_edtSearch->text().trimmed();
    int roleIdx   = m_cmbRole->currentIndex();
    int statusIdx = m_cmbStatus->currentIndex();

    static const QStringList roleMap   = {"", "system_admin", "sec_admin", "auditor"};
    static const QStringList statusMap = {"", "启用", "禁用"};
    static const QMap<QString,QString> roleDisplay = {
        {"system_admin","系统管理员"}, {"sec_admin","安全管理员"}, {"auditor","安全审计员"}
    };

    QString sql = "SELECT username, role, status, last_login, created_at, COALESCE(note,'') "
                  "FROM users WHERE 1=1";
    QVariantList binds;
    if (!kw.isEmpty())  { sql += " AND username LIKE ?"; binds << "%" + kw + "%"; }
    if (roleIdx > 0)    { sql += " AND role=?";   binds << roleMap[roleIdx]; }
    if (statusIdx > 0)  { sql += " AND status=?"; binds << statusMap[statusIdx]; }
    sql += " ORDER BY id";

    auto rows = DatabaseManager::instance()->execSelect(sql, binds);
    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        int row = m_tblUsers->rowCount();
        m_tblUsers->insertRow(row);
        m_tblUsers->setItem(row, 0, new QTableWidgetItem(m["username"].toString()));
        m_tblUsers->setItem(row, 1, new QTableWidgetItem(
            roleDisplay.value(m["role"].toString(), m["role"].toString())));
        QString st = m["status"].toString();
        if (st.isEmpty()) st = "启用";
        auto *si = new QTableWidgetItem(st);
        si->setForeground(st == "启用" ? QColor("#389e0d") : QColor("#f5222d"));
        QFont sf = si->font(); sf.setBold(true); si->setFont(sf);
        m_tblUsers->setItem(row, 2, si);
        m_tblUsers->setItem(row, 3, new QTableWidgetItem(m["last_login"].toString()));
        m_tblUsers->setItem(row, 4, new QTableWidgetItem(m["created_at"].toString()));
        m_tblUsers->setItem(row, 5, new QTableWidgetItem(m["note"].toString()));
    }
    if (m_lblStatus)
        m_lblStatus->setText(QString("共 %1 名用户  |  已刷新：%2")
            .arg(m_tblUsers->rowCount())
            .arg(QDateTime::currentDateTime().toString("HH:mm:ss")));
}

void UserManagePage::onSearch() { loadUsers(); }

void UserManagePage::showUserDialog(bool isEdit, int row)
{
    QDialog dlg(this);
    dlg.setWindowTitle(isEdit ? "编辑用户" : "新增用户");
    dlg.setFixedWidth(380);
    auto *form = new QFormLayout(&dlg);
    form->setContentsMargins(20, 20, 20, 20);
    form->setSpacing(12);

    auto *edtUser   = new QLineEdit;
    auto *edtPwd    = new QLineEdit;
    edtPwd->setEchoMode(QLineEdit::Password);
    edtPwd->setPlaceholderText(isEdit ? "留空则不修改密码" : "请输入密码");
    auto *cmbRole   = new QComboBox;
    cmbRole->addItems({"系统管理员", "安全管理员", "安全审计员"});
    auto *cmbStatus = new QComboBox;
    cmbStatus->addItems({"启用", "禁用"});

    if (isEdit && row >= 0) {
        edtUser->setText(m_tblUsers->item(row, 0)->text());
        edtUser->setReadOnly(true);
        QString rt = m_tblUsers->item(row, 1)->text();
        cmbRole->setCurrentIndex(rt == "系统管理员" ? 0 : rt == "安全管理员" ? 1 : 2);
        cmbStatus->setCurrentText(m_tblUsers->item(row, 2)->text());
    }

    form->addRow("用户名：", edtUser);
    form->addRow("密码：",   edtPwd);
    form->addRow("角色：",   cmbRole);
    form->addRow("状态：",   cmbStatus);

    auto *btns = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    btns->button(QDialogButtonBox::Ok)->setText("确定");
    btns->button(QDialogButtonBox::Cancel)->setText("取消");
    form->addRow(btns);
    connect(btns, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(btns, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);

    if (dlg.exec() != QDialog::Accepted) return;

    QString username = edtUser->text().trimmed();
    QString pwd      = edtPwd->text();
    static const QStringList roleKeys = {"system_admin","sec_admin","auditor"};
    QString roleKey  = roleKeys[cmbRole->currentIndex()];
    QString status   = cmbStatus->currentText();

    QSqlDatabase db = QSqlDatabase::database("main_conn");
    if (!db.isOpen()) return;
    QSqlQuery q(db);

    if (isEdit) {
        if (!pwd.isEmpty()) {
            q.prepare("UPDATE users SET role=?, status=?, password=? WHERE username=?");
            q.addBindValue(roleKey); q.addBindValue(status);
            q.addBindValue(hashPwd(pwd)); q.addBindValue(username);
        } else {
            q.prepare("UPDATE users SET role=?, status=? WHERE username=?");
            q.addBindValue(roleKey); q.addBindValue(status); q.addBindValue(username);
        }
        q.exec();
        DatabaseManager::instance()->writeLog(m_role, m_username, "用户管理", "编辑用户：" + username, "success");
    } else {
        if (username.isEmpty() || pwd.isEmpty()) {
            QMessageBox::warning(this, "提示", "用户名和密码不能为空！"); return;
        }
        q.prepare("INSERT INTO users(username,password,role,status,created_at) VALUES(?,?,?,?,?)");
        q.addBindValue(username); q.addBindValue(hashPwd(pwd));
        q.addBindValue(roleKey);  q.addBindValue(status);
        q.addBindValue(QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss"));
        if (!q.exec()) {
            QMessageBox::warning(this, "错误", "新增失败，用户名可能已存在！"); return;
        }
        DatabaseManager::instance()->writeLog(m_role, m_username, "用户管理", "新增用户：" + username, "success");
    }
    loadUsers();
}

void UserManagePage::onAddUser()  { showUserDialog(false); }
void UserManagePage::onEditUser() {
    int row = m_tblUsers->currentRow();
    if (row < 0) { QMessageBox::warning(this, "提示", "请先选择要编辑的用户。"); return; }
    showUserDialog(true, row);
}

void UserManagePage::onDeleteUser()
{
    int row = m_tblUsers->currentRow();
    if (row < 0) { QMessageBox::warning(this, "提示", "请先选择要删除的用户。"); return; }
    QString username = m_tblUsers->item(row, 0)->text();
    if (username == m_username) {
        QMessageBox::warning(this, "提示", "不能删除当前登录用户！"); return;
    }
    if (QMessageBox::question(this, "确认", "确定要删除用户 " + username + " 吗？",
            QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes) return;
    QSqlQuery q(QSqlDatabase::database("main_conn"));
    q.prepare("DELETE FROM users WHERE username=?");
    q.addBindValue(username); q.exec();
    DatabaseManager::instance()->writeLog(m_role, m_username, "用户管理", "删除用户：" + username, "success");
    loadUsers();
}

void UserManagePage::onResetPassword()
{
    int row = m_tblUsers->currentRow();
    if (row < 0) { QMessageBox::warning(this, "提示", "请先选择要重置密码的用户。"); return; }
    QString username = m_tblUsers->item(row, 0)->text();
    QString newPwd = QInputDialog::getText(this, "重置密码",
        "请输入用户 " + username + " 的新密码：", QLineEdit::Password);
    if (newPwd.isEmpty()) return;
    QSqlQuery q(QSqlDatabase::database("main_conn"));
    q.prepare("UPDATE users SET password=? WHERE username=?");
    q.addBindValue(hashPwd(newPwd)); q.addBindValue(username); q.exec();
    DatabaseManager::instance()->writeLog(m_role, m_username, "用户管理", "重置密码：" + username, "success");
    QMessageBox::information(this, "提示", "密码已重置成功！");
}
