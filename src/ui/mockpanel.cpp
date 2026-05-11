#include "mockpanel.h"
#include "app/translator.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QFileDialog>

MockPanel::MockPanel(MockEngine *engine, QWidget *parent)
    : QWidget(parent)
    , m_engine(engine)
{
    setupUi();
    connect(&Translator::instance(), &Translator::languageChanged, this, [this]() {
        m_addBtn->setText(Translator::t("+ Add Rule"));
        m_removeBtn->setText(Translator::t("- Remove"));
        refreshTable();
    });
}

void MockPanel::setupUi()
{
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(4, 4, 4, 4);

    // Toolbar
    auto *toolbar = new QHBoxLayout;
    m_addBtn = new QPushButton(Translator::t("+ Add Rule"), this);
    m_removeBtn = new QPushButton(Translator::t("- Remove"), this);
    toolbar->addWidget(m_addBtn);
    toolbar->addWidget(m_removeBtn);
    toolbar->addStretch();
    layout->addLayout(toolbar);

    // Table
    m_table = new QTableWidget(this);
    m_table->setColumnCount(5);
    m_table->setHorizontalHeaderLabels({
        Translator::t("On"), Translator::t("Match"),
        Translator::t("Pattern"), Translator::t("Action"),
        Translator::t("Target")
    });
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setEditTriggers(QAbstractItemView::DoubleClicked);
    m_table->verticalHeader()->setVisible(false);
    layout->addWidget(m_table);

    connect(m_addBtn, &QPushButton::clicked, this, &MockPanel::onAddRule);
    connect(m_removeBtn, &QPushButton::clicked, this, &MockPanel::onRemoveRule);
    connect(m_table, &QTableWidget::cellChanged, this, &MockPanel::onCellChanged);
}

void MockPanel::onAddRule()
{
    MockRule rule;
    rule.name = "New Rule";
    rule.pattern = "example.com";
    rule.matchType = MatchType::Contains;
    rule.action = MockAction::AutoResponder;
    rule.statusCode = 200;
    rule.contentType = "application/json";
    rule.responseBody = "{\"mock\": true}";
    m_engine->addRule(rule);
    refreshTable();
    emit ruleChanged();
}

void MockPanel::onRemoveRule()
{
    int row = m_table->currentRow();
    if (row < 0) return;

    auto rules = m_engine->rules();
    if (row < rules.size()) {
        m_engine->removeRule(rules[row].id);
        refreshTable();
        emit ruleChanged();
    }
}

void MockPanel::onCellChanged(int row, int column)
{
    auto rules = m_engine->rules();
    if (row >= rules.size()) return;

    MockRule rule = rules[row];

    if (column == 0) {
        auto *check = qobject_cast<QCheckBox*>(m_table->cellWidget(row, 0));
        if (check) rule.enabled = check->isChecked();
    } else if (column == 2) {
        rule.pattern = m_table->item(row, 2)->text();
    }

    m_engine->updateRule(rule);
    emit ruleChanged();
}

void MockPanel::refreshTable()
{
    m_table->setRowCount(0);
    m_table->setHorizontalHeaderLabels({
        Translator::t("On"), Translator::t("Match"),
        Translator::t("Pattern"), Translator::t("Action"),
        Translator::t("Target")
    });

    auto rules = m_engine->rules();
    for (const auto &rule : rules) {
        int row = m_table->rowCount();
        m_table->insertRow(row);

        // On/Off
        auto *check = new QCheckBox(this);
        check->setChecked(rule.enabled);
        m_table->setCellWidget(row, 0, check);

        // Match type
        auto *matchCombo = new QComboBox(this);
        matchCombo->addItems({
            Translator::t("Exact"), Translator::t("Contains"),
            Translator::t("Wildcard"), Translator::t("Regex")
        });
        matchCombo->setCurrentIndex(static_cast<int>(rule.matchType));
        m_table->setCellWidget(row, 1, matchCombo);

        // Pattern
        m_table->setItem(row, 2, new QTableWidgetItem(rule.pattern));

        // Action
        QString actionStr = (rule.action == MockAction::MapLocal)
                            ? Translator::t("MapLocal")
                            : Translator::t("AutoResponder");
        m_table->setItem(row, 3, new QTableWidgetItem(actionStr));

        // Target
        QString target = (rule.action == MockAction::MapLocal)
                         ? rule.localFilePath
                         : QString("[%1] %2").arg(rule.statusCode).arg(rule.contentType);
        m_table->setItem(row, 4, new QTableWidgetItem(target));
    }
}
