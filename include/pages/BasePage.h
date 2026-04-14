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
        m_mainLayout = new QVBoxLayout(this);
        m_mainLayout->setContentsMargins(12, 8, 12, 8);
        m_mainLayout->setSpacing(8);
        setupHeader();
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
    void setupHeader() {
        QHBoxLayout *hdr = new QHBoxLayout;
        QLabel *titleLbl = new QLabel(m_title);
        titleLbl->setObjectName("pageTitle");
        m_lblStatus = new QLabel("就绪");
        m_lblStatus->setObjectName("pageStatus");
        m_btnRefresh = new QPushButton("刷 新");
        m_btnRefresh->setObjectName("btnRefresh");
        m_btnRefresh->setFixedWidth(72);
        connect(m_btnRefresh, &QPushButton::clicked, this, &BasePage::refreshData);
        hdr->addWidget(titleLbl);
        hdr->addStretch();
        hdr->addWidget(m_lblStatus);
        hdr->addWidget(m_btnRefresh);
        m_mainLayout->addLayout(hdr);

        // 分割线
        QFrame *line = new QFrame;
        line->setFrameShape(QFrame::HLine);
        line->setObjectName("divider");
        m_mainLayout->addWidget(line);
    }

    // 通用：从 detection_results 表读取最新一条指定模块的结果
    QJsonObject loadLatestResult(const QString &moduleName) {
        auto records = DatabaseManager::instance()->queryScanHistory(moduleName, 1);
        if (records.isEmpty()) return QJsonObject{};
        QJsonParseError err;
        auto doc = QJsonDocument::fromJson(records.first().resultJson.toUtf8(), &err);
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

    QVBoxLayout    *m_mainLayout;
    QLabel         *m_lblStatus  = nullptr;
    QPushButton    *m_btnRefresh = nullptr;
    BasicLibLoader *m_loader     = nullptr;
    QString         m_role;
    QString         m_username;
    QString         m_title;
};

#endif // BASEPAGE_H
