#pragma once
#ifndef STYLEMANAGER_H
#define STYLEMANAGER_H

#include <QString>
#include <QApplication>
#include <QFile>
#include <QDir>
#include <QDebug>

/**
 * @brief StyleManager — 样式文件加载器
 *
 * 负责从 resources/styles/ 目录加载 QSS 文件，
 * 支持运行时热替换主题，便于统一管理全局样式。
 *
 * 使用方式：
 *   // 应用全局主题（在 main.cpp 中调用一次）
 *   StyleManager::applyGlobal(app);
 *
 *   // 应用登录界面样式
 *   StyleManager::applyTo(&loginDialog, "login");
 */
class StyleManager
{
public:
    /**
     * @brief 加载指定 QSS 文件内容
     * @param name  样式文件名（不含 .qss 后缀），如 "main"、"login"
     * @return QSS 字符串，失败时返回空字符串
     */
    static QString load(const QString &name)
    {
        // 优先从可执行文件同级目录的 styles/ 子目录加载
        QStringList searchPaths = {
            QDir(QApplication::applicationDirPath()).filePath("styles"),
            QDir(QApplication::applicationDirPath()).filePath("resources/styles"),
            ":/styles"   // Qt 资源系统（如果将 .qss 加入 .qrc）
        };

        for (const QString &dir : searchPaths) {
            QString path = QDir(dir).filePath(name + ".qss");
            QFile f(path);
            if (f.open(QIODevice::ReadOnly | QIODevice::Text)) {
                QString css = QString::fromUtf8(f.readAll());
                f.close();
                return css;
            }
        }

        qWarning() << "[StyleManager] 未找到样式文件:" << name << ".qss";
        return QString();
    }

    /**
     * @brief 将全局主题应用到整个 QApplication
     * @param app  QApplication 实例
     */
    static void applyGlobal(QApplication &app)
    {
        QString css = load("main");
        if (!css.isEmpty())
            app.setStyleSheet(css);
    }

    /**
     * @brief 将指定样式应用到单个控件
     * @param widget  目标控件
     * @param name    样式文件名（不含 .qss 后缀）
     */
    static void applyTo(QWidget *widget, const QString &name)
    {
        if (!widget) return;
        QString css = load(name);
        if (!css.isEmpty())
            widget->setStyleSheet(css);
    }
};

#endif // STYLEMANAGER_H
