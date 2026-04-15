#include <QApplication>
#include <QFont>
#include "LoginDialog.h"
#include "MainWindow.h"
#include "DatabaseManager.h"
#include "BasicLibLoader.h"
#include "StyleManager.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName("恶意代码辅助检测系统");
    app.setApplicationVersion("3.0.20251120");
    app.setOrganizationName("SecureDetect");

    // 设置全局字体
    QFont font("Microsoft YaHei", 9);
    app.setFont(font);

    // 加载全局主题样式（从 styles/main.qss）
    StyleManager::applyGlobal(app);

    // 初始化数据库
    if (!DatabaseManager::instance()->init()) {
        return -1;
    }

    // 尝试加载 basic.dll
    BasicLibLoader *loader = new BasicLibLoader();
    QString dllPath = DatabaseManager::instance()->getSetting("dll_path", "basic.dll");
    loader->load(dllPath);

    // 显示登录对话框（应用登录界面专属样式）
    LoginDialog login;
    StyleManager::applyTo(&login, "login");
    if (login.exec() != QDialog::Accepted) {
        return 0;
    }

    // 创建主窗口
    MainWindow *mainWin = new MainWindow(login.selectedRole(), login.enteredUsername());
    mainWin->setLibLoader(loader);
    mainWin->show();

    int ret = app.exec();

    delete loader;
    DatabaseManager::instance()->close();
    return ret;
}
