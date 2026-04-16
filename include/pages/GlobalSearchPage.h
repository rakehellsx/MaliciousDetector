#pragma once
#ifndef GLOBALSEARCHPAGE_H
#define GLOBALSEARCHPAGE_H

#include "pages/BasePage.h"
#include <QCheckBox>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QListWidget>
#include <QTableWidget>
#include <QSplitter>
#include <QGroupBox>
#include <QMap>
#include <QStringList>
#include <QList>
#include <QVariantMap>

namespace Ui { class GlobalSearchPage; }

class GlobalSearchPage : public BasePage {
    Q_OBJECT
public:
    explicit GlobalSearchPage(QWidget *parent = nullptr);
    ~GlobalSearchPage();
    void refreshData() override;

private slots:
    void onSearch();
    void onClear();
    void onModuleSelected(QListWidgetItem *item);
    void onAllToggled(bool checked);

private:
    struct ModuleResult {
        QString moduleId;
        QString moduleName;
        QList<QVariantMap> rows;
    };

    void doSearch(const QStringList &keywords);
    void showModuleResult(const ModuleResult &mr, const QStringList &keywords);
    QString highlightText(const QString &text, const QStringList &keywords);
    QList<QVariantMap> searchTable(const QString &sql,
                                   const QStringList &fields,
                                   const QStringList &keywords,
                                   const QVariantList &extraBinds = {});

    Ui::GlobalSearchPage *ui{nullptr};

    QLineEdit    *m_edtKeyword{nullptr};
    QPushButton  *m_btnSearch{nullptr};
    QPushButton  *m_btnClear{nullptr};
    QGroupBox    *m_gbModules{nullptr};
    QCheckBox    *m_chkAll{nullptr};
    QCheckBox    *m_chkSysinfo{nullptr};
    QCheckBox    *m_chkNetwork{nullptr};
    QCheckBox    *m_chkDisk{nullptr};
    QCheckBox    *m_chkProcess{nullptr};
    QCheckBox    *m_chkPort{nullptr};
    QCheckBox    *m_chkAutorun{nullptr};
    QCheckBox    *m_chkTask{nullptr};
    QCheckBox    *m_chkDriver{nullptr};
    QCheckBox    *m_chkShared{nullptr};
    QCheckBox    *m_chkPlugin{nullptr};
    QCheckBox    *m_chkMemory{nullptr};
    QCheckBox    *m_chkStatic{nullptr};
    QCheckBox    *m_chkDynamic{nullptr};
    QLabel       *m_lblSummary{nullptr};
    QListWidget  *m_lstModules{nullptr};
    QLabel       *m_lblModuleTitle{nullptr};
    QTableWidget *m_tblResult{nullptr};

    QList<ModuleResult> m_results;
};

#endif // GLOBALSEARCHPAGE_H
