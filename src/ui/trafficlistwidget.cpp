#include "trafficlistwidget.h"
#include "app/translator.h"
#include <QVBoxLayout>
#include <QHeaderView>

TrafficListWidget::TrafficListWidget(QWidget *parent)
    : QWidget(parent)
{
    setupUi();
}

void TrafficListWidget::setupUi()
{
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);

    m_filterEdit = new QLineEdit(this);
    m_filterEdit->setPlaceholderText(Translator::t("Filter by host, path, method..."));
    m_filterEdit->setClearButtonEnabled(true);
    layout->addWidget(m_filterEdit);

    m_table = new QTableWidget(this);
    m_table->setColumnCount(7);
    m_table->setHorizontalHeaderLabels({"#", "Method", "Host", "Path", "Status", "Size", "Time"});
    m_table->horizontalHeader()->setStretchLastSection(false);
    m_table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Interactive);
    m_table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Interactive);
    m_table->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(6, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->resizeSection(2, 250);  // Host
    m_table->horizontalHeader()->resizeSection(3, 350);  // Path
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->verticalHeader()->setVisible(false);
    m_table->setAlternatingRowColors(true);

    layout->addWidget(m_table);

    connect(m_filterEdit, &QLineEdit::textChanged,
            this, &TrafficListWidget::onFilterChanged);
    connect(m_table, &QTableWidget::cellClicked,
            this, &TrafficListWidget::onCellClicked);

    connect(&Translator::instance(), &Translator::languageChanged, this, [this]() {
        m_filterEdit->setPlaceholderText(Translator::t("Filter by host, path, method..."));
        QStringList headers = {"#", Translator::t("Method"), Translator::t("Host"),
                               Translator::t("Path"), Translator::t("Status"),
                               Translator::t("Size"), Translator::t("Time")};
        m_table->setHorizontalHeaderLabels(headers);
    });
}

void TrafficListWidget::addRequest(const RequestItem &item)
{
    m_items.append(item);

    // Enforce max item limit - remove oldest
    if (m_items.size() > MAX_ITEMS) {
        int excess = m_items.size() - MAX_ITEMS;
        m_items.erase(m_items.begin(), m_items.begin() + excess);
        // Rebuild table if filter is active
        if (!m_filterEdit->text().isEmpty() || m_filteredItems.size() > MAX_ITEMS) {
            onFilterChanged(m_filterEdit->text());
            return;
        }
        // Remove oldest rows from table
        m_table->setUpdatesEnabled(false);
        for (int i = 0; i < excess && m_table->rowCount() > 0; ++i) {
            m_table->removeRow(0);
        }
        m_filteredItems.erase(m_filteredItems.begin(),
                              m_filteredItems.begin() + qMin(excess, m_filteredItems.size()));
        m_table->setUpdatesEnabled(true);
    }

    // Check filter
    if (!m_filterEdit->text().isEmpty()) {
        QString filter = m_filterEdit->text().toLower();
        if (!item.host.toLower().contains(filter) &&
            !item.path.toLower().contains(filter) &&
            !item.method.toLower().contains(filter)) {
            return;
        }
    }

    m_filteredItems.append(item);
    int row = m_table->rowCount();
    m_table->insertRow(row);

    auto *idItem = new QTableWidgetItem(QString::number(item.id));
    auto *methodItem = new QTableWidgetItem(item.method);
    auto *hostItem = new QTableWidgetItem(item.host);
    auto *pathItem = new QTableWidgetItem(item.path);
    auto *statusItem = new QTableWidgetItem(QString::number(item.statusCode));
    auto *sizeItem = new QTableWidgetItem(QString::number(item.responseSize));
    auto *timeItem = new QTableWidgetItem(QString("%1ms").arg(item.duration));

    // Color code status
    QColor statusColor;
    if (item.statusCode >= 200 && item.statusCode < 300) statusColor = Qt::darkGreen;
    else if (item.statusCode >= 300 && item.statusCode < 400) statusColor = Qt::blue;
    else if (item.statusCode >= 400 && item.statusCode < 500) statusColor = QColor(255, 165, 0);
    else if (item.statusCode >= 500) statusColor = Qt::red;
    statusItem->setForeground(statusColor);

    m_table->setItem(row, 0, idItem);
    m_table->setItem(row, 1, methodItem);
    m_table->setItem(row, 2, hostItem);
    m_table->setItem(row, 3, pathItem);
    m_table->setItem(row, 4, statusItem);
    m_table->setItem(row, 5, sizeItem);
    m_table->setItem(row, 6, timeItem);

    // Auto-scroll to bottom
    m_table->scrollToBottom();
}

void TrafficListWidget::clear()
{
    m_table->setRowCount(0);
    m_items.clear();
    m_filteredItems.clear();
}

void TrafficListWidget::onFilterChanged(const QString &text)
{
    m_table->setUpdatesEnabled(false);
    m_table->setRowCount(0);
    m_filteredItems.clear();

    QString filter = text.toLower();
    for (const auto &item : qAsConst(m_items)) {
        if (filter.isEmpty() ||
            item.host.toLower().contains(filter) ||
            item.path.toLower().contains(filter) ||
            item.method.toLower().contains(filter)) {
            m_filteredItems.append(item);
            int row = m_table->rowCount();
            m_table->insertRow(row);
            m_table->setItem(row, 0, new QTableWidgetItem(QString::number(item.id)));
            m_table->setItem(row, 1, new QTableWidgetItem(item.method));
            m_table->setItem(row, 2, new QTableWidgetItem(item.host));
            m_table->setItem(row, 3, new QTableWidgetItem(item.path));
            m_table->setItem(row, 4, new QTableWidgetItem(QString::number(item.statusCode)));
            m_table->setItem(row, 5, new QTableWidgetItem(QString::number(item.responseSize)));
            m_table->setItem(row, 6, new QTableWidgetItem(QString("%1ms").arg(item.duration)));
        }
    }
    m_table->setUpdatesEnabled(true);
}

void TrafficListWidget::onCellClicked(int row, int /*column*/)
{
    if (row >= 0 && row < m_filteredItems.size()) {
        emit itemSelected(m_filteredItems.at(row));
    }
}
