#pragma once

#include <QWidget>
#include <QTableWidget>
#include <QLineEdit>
#include "model/request_item.h"

class TrafficListWidget : public QWidget
{
    Q_OBJECT
public:
    explicit TrafficListWidget(QWidget *parent = nullptr);

    void addRequest(const RequestItem &item);
    void clear();
    QList<RequestItem> allItems() const { return m_items; }

signals:
    void itemSelected(const RequestItem &item);

private slots:
    void onFilterChanged(const QString &text);
    void onCellClicked(int row, int column);

private:
    void setupUi();

    static const int MAX_ITEMS = 10000;

    QTableWidget *m_table;
    QLineEdit *m_filterEdit;
    QList<RequestItem> m_items;
    QList<RequestItem> m_filteredItems;
};
