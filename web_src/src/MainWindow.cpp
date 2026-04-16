#include "MainWindow.h"
#include <QWebEngineSettings>
#include <QWebEnginePage>
#include <QWebEngineScript>
#include <QWebEngineScriptCollection>
#include <QFile>
#include <QDebug>
#include <QCloseEvent>
#include <QScreen>
#include <QApplication>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , m_webView(nullptr)
    , m_channel(nullptr)
    , m_bridge(nullptr)
{
    setWindowTitle("恶意代码辅助检测系统 V3.0");
    setMinimumSize(1280, 768);

    // 居中显示
    QScreen *screen = QApplication::primaryScreen();
    if (screen) {
        QRect sg = screen->geometry();
        resize(qMin(1600, sg.width() - 100), qMin(900, sg.height() - 80));
        move((sg.width() - width()) / 2, (sg.height() - height()) / 2);
    } else {
        resize(1440, 900);
    }

    setupWebEngine();
}

MainWindow::~MainWindow()
{
}

void MainWindow::setupWebEngine()
{
    // 创建 Bridge 和 Channel
    m_bridge  = new AppBridge(this);
    m_channel = new QWebChannel(this);
    m_channel->registerObject("bridge", m_bridge);

    // 创建 WebView
    m_webView = new QWebEngineView(this);
    m_webView->page()->setWebChannel(m_channel);

    // WebEngine 设置
    m_webView->settings()->setAttribute(QWebEngineSettings::JavascriptEnabled, true);
    m_webView->settings()->setAttribute(QWebEngineSettings::LocalContentCanAccessRemoteUrls, true);
    m_webView->settings()->setAttribute(QWebEngineSettings::LocalContentCanAccessFileUrls, true);
    m_webView->settings()->setAttribute(QWebEngineSettings::ScrollAnimatorEnabled, true);

    // 注入 qwebchannel.js（Qt 内置）
    injectQWebChannelJs();

    // 连接加载完成信号
    connect(m_webView, &QWebEngineView::loadFinished,
            this, &MainWindow::onLoadFinished);

    // 加载主页面（内嵌资源）
    m_webView->load(QUrl("qrc:/web/index.html"));

    setCentralWidget(m_webView);
}

void MainWindow::injectQWebChannelJs()
{
    // 读取 Qt 内置的 qwebchannel.js
    QFile f(":/qtwebchannel/qwebchannel.js");
    if (!f.open(QIODevice::ReadOnly)) {
        qWarning() << "Cannot open qwebchannel.js";
        return;
    }
    QString jsContent = QString::fromUtf8(f.readAll());
    f.close();

    // 注入初始化脚本（在页面加载前执行）
    QString initScript = jsContent + R"JS(
// 初始化 QWebChannel，建立 C++ Bridge 连接
(function() {
    new QWebChannel(qt.webChannelTransport, function(channel) {
        window.bridge = channel.objects.bridge;
        // 通知页面 Bridge 已就绪
        if (typeof window.onBridgeReady === 'function') {
            window.onBridgeReady(window.bridge);
        }
        // 触发自定义事件
        var evt = document.createEvent('Event');
        evt.initEvent('bridgeReady', true, true);
        document.dispatchEvent(evt);
    });
})();
)JS";

    QWebEngineScript script;
    script.setName("qwebchannel_init");
    script.setSourceCode(initScript);
    script.setInjectionPoint(QWebEngineScript::DocumentCreation);
    script.setWorldId(QWebEngineScript::MainWorld);
    script.setRunsOnSubFrames(false);

    m_webView->page()->scripts().insert(script);
}

void MainWindow::onLoadFinished(bool ok)
{
    if (!ok) {
        qWarning() << "Page load failed";
        return;
    }
    qDebug() << "Page loaded successfully";
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    event->accept();
}
