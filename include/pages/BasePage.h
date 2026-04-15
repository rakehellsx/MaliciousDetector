#pragma once
#ifndef BASEPAGE_H
#define BASEPAGE_H

#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QTableWidget>
#include <QHeaderView>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonDocument>
#include <QDateTime>
#include <QSqlQuery>
#include <QSqlDatabase>
#include "BasicLibLoader.h"
#include "DatabaseManager.h"

/**
 * @brief BasePage - 所有功能页面的基类
 *
 * 提供统一的页面标题栏、刷新按钮、状态标签，
 * 以及从 SQLite 读取最新数据的通用接口。
 */
class BasePage : public QWidget
{
    Q_OBJECT
public:
    explicit BasePage(const QString &title, QWidget *parent = nullptr)
        : QWidget(parent), m_title(title)
    {
        // 布局由子类 setupUi(this) 负责创建，BasePage 不在 this 上创建布局
        // 子类在 setupUi(this) 之后调用 postSetupUi() 绑定 m_lblStatus/m_btnRefresh
    }

    // 子类在 ui->setupUi(this) 之后调用，绑定 m_lblStatus 和 m_btnRefresh
    void postSetupUi() {
        m_lblStatus  = findChild<QLabel*>("m_lblStatus");
        m_btnRefresh = findChild<QPushButton*>("m_btnRefresh");
        if (m_btnRefresh)
            connect(m_btnRefresh, &QPushButton::clicked, this, &BasePage::refreshData);
    }

    virtual ~BasePage() = default;

    void setLoader(BasicLibLoader *loader) { m_loader = loader; }
    void setRole(const QString &role)      { m_role = role; }
    void setUsername(const QString &user)  { m_username = user; }

    // 子类重写此方法来刷新页面数据
    virtual void refreshData() {}

signals:
    void statusMessage(const QString &msg);

protected:
    // setupHeader() 已废弃，由 postSetupUi() 替代

    // 通用：从 detection_results 表读取最新一条指定模块的结果
    QJsonObject loadLatestResult(const QString &moduleName) {
        QSqlQuery q(QSqlDatabase::database("main_conn"));
        q.prepare("SELECT result_json FROM detection_results WHERE module=? ORDER BY id DESC LIMIT 1");
        q.bindValue(0, moduleName);
        if (!q.exec() || !q.next()) return QJsonObject{};
        QJsonParseError err;
        auto doc = QJsonDocument::fromJson(q.value(0).toString().toUtf8(), &err);
        if (err.error != QJsonParseError::NoError) return QJsonObject{};
        return doc.object();
    }

    // 通用：设置 QTableWidget 样式
    void styleTable(QTableWidget *t) {
        t->setAlternatingRowColors(true);
        t->setSelectionBehavior(QAbstractItemView::SelectRows);
        t->setEditTriggers(QAbstractItemView::NoEditTriggers);
        t->horizontalHeader()->setStretchLastSection(true);
        t->verticalHeader()->setVisible(false);
        t->setShowGrid(false);
        t->setFocusPolicy(Qt::NoFocus);
    }

    // 通用：创建风险等级标签
    QLabel* makeRiskLabel(const QString &level) {
        QLabel *lbl = new QLabel(level == "high"   ? "高危" :
                                  level == "medium" ? "中危" :
                                  level == "low"    ? "低危" : "正常");
        lbl->setAlignment(Qt::AlignCenter);
        lbl->setFixedWidth(48);
        QString color = level == "high"   ? "#c62828" :
                        level == "medium" ? "#e65100" :
                        level == "low"    ? "#1565c0" : "#2e7d32";
        lbl->setStyleSheet(QString("background:%1;color:#fff;border-radius:2px;font-size:11px;padding:1px 0;").arg(color));
        return lbl;
    }

    QLabel         *m_lblStatus  = nullptr;
    QPushButton    *m_btnRefresh = nullptr;
    BasicLibLoader *m_loader     = nullptr;
    QString         m_role;
    QString         m_username;
    QString         m_title;
};

#endif // BASEPAGE_H
