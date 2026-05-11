#include "mainwindow.h"
#include "trafficlistwidget.h"
#include "detailpanel.h"
#include "mockpanel.h"
#include "composerwidget.h"
#include "theme.h"
#include "app/translator.h"
#include "core/mock_engine.h"
#include "core/traffic_storage.h"
#include "core/har_exporter.h"
#include <QSplitter>
#include <QStatusBar>
#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QToolBar>
#include <QFileDialog>
#include <QActionGroup>

MainWindow::MainWindow(MockEngine *mockEngine, Theme *theme,
                         TrafficStorage *storage, HarExporter *harExporter,
                         QWidget *parent)
    : QMainWindow(parent)
    , m_mockPanel(new MockPanel(mockEngine, this))
    , m_theme(theme)
    , m_storage(storage)
    , m_harExporter(harExporter)
{
    setupUi();
    setupToolBar();
    setupStatusBar();
    retranslateUi();
    resize(1200, 800);

    connect(&Translator::instance(), &Translator::languageChanged,
            this, &MainWindow::retranslateUi);
}

MainWindow::~MainWindow() = default;

void MainWindow::setupUi()
{
    auto *central = new QWidget(this);
    auto *mainLayout = new QHBoxLayout(central);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(0);

    // Sidebar
    m_sidebar = new QListWidget(this);
    m_sidebar->setObjectName("sidebar");
    m_sidebar->setFixedWidth(120);
    m_sidebar->setIconSize(QSize(20, 20));
    m_sidebar->setMovement(QListView::Static);
    m_sidebar->setSpacing(2);

    auto *trafficItem = new QListWidgetItem("Traffic");
    auto *mockItem = new QListWidgetItem("Mock");
    auto *composerItem = new QListWidgetItem("Composer");

    m_sidebar->addItem(trafficItem);
    m_sidebar->addItem(mockItem);
    m_sidebar->addItem(composerItem);
    m_sidebar->setCurrentRow(0);

    // Pages
    m_pages = new QStackedWidget(this);

    // --- Traffic page ---
    m_trafficPage = new QWidget(this);
    auto *trafficLayout = new QVBoxLayout(m_trafficPage);
    trafficLayout->setContentsMargins(0, 0, 0, 0);

    auto *splitter = new QSplitter(Qt::Vertical, m_trafficPage);
    m_trafficList = new TrafficListWidget(splitter);
    m_detailPanel = new DetailPanel(splitter);
    splitter->addWidget(m_trafficList);
    splitter->addWidget(m_detailPanel);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);
    trafficLayout->addWidget(splitter);

    connect(m_trafficList, &TrafficListWidget::itemSelected,
            m_detailPanel, &DetailPanel::setRequest);

    // --- Mock page ---
    m_mockPage = m_mockPanel;

    // --- Composer page ---
    m_composer = new ComposerWidget(this);
    m_composerPage = m_composer;

    m_pages->addWidget(m_trafficPage);
    m_pages->addWidget(m_mockPage);
    m_pages->addWidget(m_composerPage);

    // Connect sidebar to pages
    connect(m_sidebar, &QListWidget::currentRowChanged,
            m_pages, &QStackedWidget::setCurrentIndex);

    mainLayout->addWidget(m_sidebar);
    mainLayout->addWidget(m_pages);

    setCentralWidget(central);
}

void MainWindow::setupToolBar()
{
    QToolBar *toolbar = addToolBar("Main");
    toolbar->setMovable(false);
    toolbar->setIconSize(QSize(16, 16));

    m_clearAction = toolbar->addAction(tr("Clear"));
    connect(m_clearAction, &QAction::triggered, this, [this]() {
        m_trafficList->clear();
        m_totalRequests = 0;
        m_statusLabel->setText(QString("%1 | %2: 0")
            .arg(Translator::t("Cleared"), Translator::t("Captured")));
    });
    connect(m_clearAction, &QAction::triggered, this, &MainWindow::clearRequested);

    toolbar->addSeparator();

    m_mitmAction = toolbar->addAction(tr("HTTPS Decrypt"));
    m_mitmAction->setCheckable(true);
    m_mitmAction->setChecked(false);
    connect(m_mitmAction, &QAction::toggled, this, &MainWindow::mitmToggled);

    toolbar->addSeparator();

    m_exportAction = toolbar->addAction(tr("Export HAR"));
    connect(m_exportAction, &QAction::triggered, this, [this]() {
        QString filePath = QFileDialog::getSaveFileName(
            this, tr("Export HAR"), "capture.har", "HAR Files (*.har);;All Files (*)");
        if (!filePath.isEmpty()) {
            auto items = m_trafficList->allItems();
            if (m_harExporter->exportToFile(items, filePath)) {
                m_statusLabel->setText(QString("%1 %2 %3")
                    .arg(Translator::t("Exported"))
                    .arg(items.size())
                    .arg(Translator::t("requests to"))
                    .arg(filePath));
            }
        }
    });

    toolbar->addSeparator();

    // Theme toggle
    m_themeAction = toolbar->addAction(tr("Theme"));
    connect(m_themeAction, &QAction::triggered, m_theme, &Theme::toggleTheme);
    connect(m_theme, &Theme::themeChanged, this, [this](ThemeMode mode) {
        Q_UNUSED(mode);
        m_theme->savePreference();
        retranslateUi();
    });

    toolbar->addSeparator();

    // Language toggle
    m_langAction = toolbar->addAction(tr("Language"));
    connect(m_langAction, &QAction::triggered, this, [this]() {
        auto &t = Translator::instance();
        t.setLanguage(t.currentLanguage() == Language::Chinese
                      ? Language::English : Language::Chinese);
    });

    toolbar->addSeparator();

    m_proxyLabel = new QLabel(this);
    toolbar->addWidget(m_proxyLabel);
}

void MainWindow::setupStatusBar()
{
    m_statusLabel = new QLabel(this);
    m_mitmLabel = new QLabel(this);

    statusBar()->addWidget(m_statusLabel);
    statusBar()->addPermanentWidget(m_mitmLabel);
}

void MainWindow::retranslateUi()
{
    auto &t = Translator::instance();

    // Sidebar
    m_sidebar->item(0)->setText(t.translate("Traffic"));
    m_sidebar->item(1)->setText(t.translate("Mock"));
    m_sidebar->item(2)->setText(t.translate("Composer"));

    // Toolbar
    if (m_clearAction) m_clearAction->setText(t.translate("Clear"));
    if (m_mitmAction) m_mitmAction->setText(t.translate("HTTPS Decrypt"));
    if (m_exportAction) m_exportAction->setText(t.translate("Export HAR"));
    if (m_themeAction) {
        m_themeAction->setText(m_theme->currentMode() == ThemeMode::Dark
                               ? t.translate("Light") : t.translate("Dark"));
    }
    if (m_langAction) {
        m_langAction->setText(t.currentLanguage() == Language::Chinese
                              ? "English" : "中文");
    }
    if (m_proxyLabel) {
        m_proxyLabel->setText(QString("  %1  ").arg(t.translate("Proxy: localhost:9527")));
    }

    // Status bar
    m_statusLabel->setText(QString("%1 | %2: %3")
        .arg(t.translate("Ready"), t.translate("Captured")).arg(m_totalRequests));
    setMitmStatus(m_mitmAction && m_mitmAction->isChecked());
}

void MainWindow::onRequestCaptured(const RequestItem &item)
{
    m_trafficList->addRequest(item);
    m_totalRequests++;
    m_statusLabel->setText(QString("%1: %2")
        .arg(Translator::t("Captured")).arg(m_totalRequests));
}

void MainWindow::setMitmStatus(bool enabled)
{
    auto &t = Translator::instance();
    m_mitmLabel->setText(enabled ? t.translate("MITM: on") : t.translate("MITM: off"));
    m_mitmLabel->setStyleSheet(enabled
        ? "color: #4ec9b0; font-weight: bold; padding: 0 8px;"
        : "color: #808080; padding: 0 8px;");
    if (m_mitmAction) m_mitmAction->setChecked(enabled);
}
