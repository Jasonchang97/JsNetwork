#pragma once

#include <QMainWindow>
#include <QLabel>
#include <QAction>
#include <QListWidget>
#include <QStackedWidget>
#include "model/request_item.h"

class TrafficListWidget;
class DetailPanel;
class MockPanel;
class ComposerWidget;
class MockEngine;
class Theme;
class TrafficStorage;
class HarExporter;

class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit MainWindow(MockEngine *mockEngine, Theme *theme,
                        TrafficStorage *storage, HarExporter *harExporter,
                        QWidget *parent = nullptr);
    ~MainWindow();

public slots:
    void onRequestCaptured(const RequestItem &item);
    void setMitmStatus(bool enabled);

signals:
    void clearRequested();
    void mitmToggled(bool enabled);
    void languageToggled();

private:
    void setupUi();
    void setupToolBar();
    void setupStatusBar();
    void retranslateUi();

    // Sidebar
    QListWidget *m_sidebar;

    // Pages
    QStackedWidget *m_pages;
    QWidget *m_trafficPage;
    QWidget *m_mockPage;
    QWidget *m_composerPage;

    // Traffic page
    TrafficListWidget *m_trafficList;
    DetailPanel *m_detailPanel;

    // Mock page
    MockPanel *m_mockPanel;

    // Composer page
    ComposerWidget *m_composer;

    // Status
    QLabel *m_statusLabel;
    QLabel *m_mitmLabel;
    QLabel *m_captureLabel;
    QAction *m_mitmAction = nullptr;
    QAction *m_themeAction = nullptr;
    QAction *m_langAction = nullptr;
    QAction *m_clearAction = nullptr;
    QAction *m_exportAction = nullptr;
    QLabel *m_proxyLabel = nullptr;
    Theme *m_theme;
    TrafficStorage *m_storage;
    HarExporter *m_harExporter;
    int m_totalRequests = 0;
};
