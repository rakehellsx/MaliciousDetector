#pragma once
#include <QMainWindow>
#include <QWebEngineView>
#include <QWebChannel>
#include <QVBoxLayout>
#include "AppBridge.h"

/**
 * MainWindow — 应用主窗口
 *
 * 使用 QWebEngineView 加载内嵌 HTML 应用（qrc://web/index.html），
 * 通过 QWebChannel 与前端 JavaScript 双向通信。
 *
 * 架构说明：
 *   C++ MainWindow
 *     └── QWebEngineView
 *           └── QWebEnginePage (Chromium 内核)
 *                 └── HTML/CSS/JS (prototype_v5 适配版)
 *                       └── QWebChannel ↔ AppBridge (C++ 数据/操作)
 */
class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

protected:
    void closeEvent(QCloseEvent *event) override;

private slots:
    void onLoadFinished(bool ok);

private:
    void setupWebEngine();
    void injectQWebChannelJs();

    QWebEngineView *m_webView;
    QWebChannel    *m_channel;
    AppBridge      *m_bridge;
};
