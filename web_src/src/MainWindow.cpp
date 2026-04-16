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
#include <QDir>
#include <QFileInfo>
#include <QStandardPaths>

// ─────────────────────────────────────────────────────────────────────────────
// 查找 basic_test.db 的候选路径列表
// ─────────────────────────────────────────────────────────────────────────────
static QString findDatabase()
{
    QStringList candidates;

    // 1. 可执行文件同目录
    QString exeDir = QApplication::applicationDirPath();
    candidates << exeDir + "/basic_test.db";
    candidates << exeDir + "/data/basic_test.db";

    // 2. 当前工作目录
    candidates << QDir::currentPath() + "/basic_test.db";
    candidates << QDir::currentPath() + "/data/basic_test.db";

    // 3. 用户文档目录
    QString docDir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    candidates << docDir + "/MalwareDetector/basic_test.db";

    // 4. Windows: %APPDATA%\MalwareDetector
#ifdef Q_OS_WIN
    QString appData = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    candidates << appData + "/basic_test.db";
#endif

    for (const QString &p : candidates) {
        if (QFileInfo::exists(p)) {
            qDebug() << "[MainWindow] Found DB:" << p;
            return p;
        }
    }
    qWarning() << "[MainWindow] basic_test.db not found in any candidate path";
    return QString();
}

// ─────────────────────────────────────────────────────────────────────────────
// 构造函数
// ─────────────────────────────────────────────────────────────────────────────

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , m_webView(nullptr)
    , m_channel(nullptr)
    , m_bridge(nullptr)
{
    setWindowTitle("\xe6\x81\xb6\xe6\x84\x8f\xe4\xbb\xa3\xe7\xa0\x81\xe8\xbe\x85\xe5\x8a\xa9\xe6\xa3\x80\xe6\xb5\x8b\xe7\xb3\xbb\xe7\xbb\x9f V3.0");
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

// ─────────────────────────────────────────────────────────────────────────────
// WebEngine 初始化
// ─────────────────────────────────────────────────────────────────────────────

void MainWindow::setupWebEngine()
{
    // 创建 Bridge
    m_bridge = new AppBridge(this);

    // 初始化数据库（查找 basic_test.db）
    QString dbPath = findDatabase();
    if (!dbPath.isEmpty()) {
        if (m_bridge->initDatabase(dbPath))
            qDebug() << "[MainWindow] Database loaded:" << dbPath;
        else
            qWarning() << "[MainWindow] Failed to load database:" << dbPath;
    } else {
        qWarning() << "[MainWindow] No database found, running without real data";
    }

    // 创建 WebChannel 并注册 Bridge
    m_channel = new QWebChannel(this);
    m_channel->registerObject("bridge", m_bridge);

    // 创建 WebView
    m_webView = new QWebEngineView(this);
    m_webView->page()->setWebChannel(m_channel);

    // WebEngine 设置
    QWebEngineSettings *settings = m_webView->settings();
    settings->setAttribute(QWebEngineSettings::JavascriptEnabled, true);
    settings->setAttribute(QWebEngineSettings::LocalContentCanAccessRemoteUrls, true);
    settings->setAttribute(QWebEngineSettings::LocalContentCanAccessFileUrls, true);
    settings->setAttribute(QWebEngineSettings::ScrollAnimatorEnabled, true);

    // 注入 qwebchannel.js（Qt 内置）
    injectQWebChannelJs();

    // 连接加载完成信号
    connect(m_webView, &QWebEngineView::loadFinished,
            this, &MainWindow::onLoadFinished);

    // 加载主页面（内嵌资源）
    m_webView->load(QUrl("qrc:/web/index.html"));

    setCentralWidget(m_webView);
}

// ─────────────────────────────────────────────────────────────────────────────
// 注入 QWebChannel JS
// ─────────────────────────────────────────────────────────────────────────────

void MainWindow::injectQWebChannelJs()
{
    QFile f(":/qtwebchannel/qwebchannel.js");
    if (!f.open(QIODevice::ReadOnly)) {
        qWarning() << "Cannot open qwebchannel.js";
        return;
    }
    QString jsContent = QString::fromUtf8(f.readAll());
    f.close();

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

// ─────────────────────────────────────────────────────────────────────────────
// 事件处理
// ─────────────────────────────────────────────────────────────────────────────

void MainWindow::onLoadFinished(bool ok)
{
    if (!ok) {
        qWarning() << "[MainWindow] Page load failed";
        return;
    }
    qDebug() << "[MainWindow] Page loaded successfully";
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    event->accept();
}
