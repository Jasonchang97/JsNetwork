#pragma once

#include <QWidget>
#include <QTableWidget>
#include <QPushButton>
#include <QComboBox>
#include <QLineEdit>
#include <QCheckBox>
#include "core/mock_engine.h"

class MockPanel : public QWidget
{
    Q_OBJECT
public:
    explicit MockPanel(MockEngine *engine, QWidget *parent = nullptr);

signals:
    void ruleChanged();

private slots:
    void onAddRule();
    void onRemoveRule();
    void onCellChanged(int row, int column);

private:
    void setupUi();
    void refreshTable();

    MockEngine *m_engine;
    QTableWidget *m_table;
    QPushButton *m_addBtn;
    QPushButton *m_removeBtn;
};
