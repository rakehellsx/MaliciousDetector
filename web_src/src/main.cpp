#include <QApplication>
#include <QWebEngineSettings>
#include <QWebEngineProfile>
#include "MainWindow.h"

int main(int argc, char *argv[])
{
    // Qt 5.6+ 在 Win7 32位下需要设置此属性
    QCoreApplication::setAttribute(Qt::AA_EnableHighDpiScaling, false);
    QCoreApplication::setAttribute(Qt::AA_UseHighDpiPixmaps, false);

    // WebEngine 需要在 QApplication 之前设置
    QCoreApplication::setAttribute(Qt::AA_ShareOpenGLContexts);

    QApplication app(argc, argv);
    app.setApplicationName("恶意代码辅助检测系统");
    app.setApplicationVersion("3.0");
    app.setOrganizationName("MalwareDetector");

    // 全局 WebEngine 设置（兼容 Win7）
    QWebEngineSettings::defaultSettings()->setAttribute(
        QWebEngineSettings::LocalContentCanAccessRemoteUrls, true);
    QWebEngineSettings::defaultSettings()->setAttribute(
        QWebEngineSettings::LocalContentCanAccessFileUrls, true);
    QWebEngineSettings::defaultSettings()->setAttribute(
        QWebEngineSettings::JavascriptEnabled, true);
    QWebEngineSettings::defaultSettings()->setAttribute(
        QWebEngineSettings::JavascriptCanOpenWindows, false);
    QWebEngineSettings::defaultSettings()->setAttribute(
        QWebEngineSettings::PluginsEnabled, false);

    MainWindow w;
    w.show();

    return app.exec();
}
