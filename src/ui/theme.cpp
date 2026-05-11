#include "theme.h"
#include <QApplication>
#include <QSettings>

Theme::Theme(QObject *parent)
    : QObject(parent)
{
}

void Theme::applyTheme(ThemeMode mode)
{
    m_mode = mode;
    qApp->setStyleSheet(mode == ThemeMode::Dark ? darkStyleSheet() : lightStyleSheet());
    emit themeChanged(mode);
}

void Theme::toggleTheme()
{
    applyTheme(m_mode == ThemeMode::Dark ? ThemeMode::Light : ThemeMode::Dark);
}

void Theme::savePreference()
{
    QSettings settings;
    settings.setValue("theme", m_mode == ThemeMode::Dark ? "dark" : "light");
}

void Theme::loadPreference()
{
    QSettings settings;
    QString mode = settings.value("theme", "dark").toString();
    applyTheme(mode == "light" ? ThemeMode::Light : ThemeMode::Dark);
}

QString Theme::darkStyleSheet()
{
    return R"(
        QMainWindow, QWidget {
            background-color: #1a1a2e;
            color: #e0e0e0;
            font-family: -apple-system, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
        }
        QMenuBar {
            background-color: #16213e;
            color: #e0e0e0;
            border-bottom: 1px solid #2a2a4a;
        }
        QMenuBar::item:selected {
            background-color: #0f3460;
        }
        QMenu {
            background-color: #16213e;
            color: #e0e0e0;
            border: 1px solid #2a2a4a;
            border-radius: 6px;
            padding: 4px;
        }
        QMenu::item {
            padding: 6px 24px;
            border-radius: 3px;
        }
        QMenu::item:selected {
            background-color: #0f3460;
        }
        QToolBar {
            background-color: #16213e;
            border-bottom: 1px solid #2a2a4a;
            spacing: 6px;
            padding: 4px 8px;
        }
        QToolButton {
            background-color: #1a1a2e;
            color: #e0e0e0;
            border: 1px solid #2a2a4a;
            border-radius: 4px;
            padding: 5px 14px;
            font-weight: 500;
        }
        QToolButton:hover {
            background-color: #0f3460;
            border-color: #533483;
        }
        QToolButton:checked {
            background-color: #e94560;
            color: #ffffff;
            border-color: #e94560;
        }
        QStatusBar {
            background-color: #0f3460;
            color: #e0e0e0;
            font-size: 12px;
        }
        QLabel {
            color: #e0e0e0;
        }
        QTableWidget {
            background-color: #1a1a2e;
            alternate-background-color: #16213e;
            color: #e0e0e0;
            gridline-color: #2a2a4a;
            selection-background-color: #0f3460;
            border: none;
            font-size: 13px;
        }
        QTableWidget::item {
            padding: 3px 8px;
        }
        QTableWidget::item:selected {
            background-color: #0f3460;
            color: #ffffff;
        }
        QHeaderView::section {
            background-color: #16213e;
            color: #a0a0c0;
            border: none;
            border-bottom: 2px solid #533483;
            border-right: 1px solid #2a2a4a;
            padding: 6px 8px;
            font-weight: 600;
            font-size: 12px;
        }
        QTabWidget::pane {
            border: 1px solid #2a2a4a;
            background-color: #1a1a2e;
            border-radius: 0 0 4px 4px;
        }
        QTabBar::tab {
            background-color: #16213e;
            color: #808090;
            padding: 8px 18px;
            border: 1px solid #2a2a4a;
            border-bottom: none;
            margin-right: 2px;
        }
        QTabBar::tab:selected {
            background-color: #1a1a2e;
            color: #e0e0e0;
            border-bottom: 2px solid #e94560;
        }
        QTabBar::tab:hover:!selected {
            background-color: #1e1e38;
            color: #c0c0d0;
        }
        QTextEdit, QPlainTextEdit {
            background-color: #0d1117;
            color: #c9d1d9;
            border: 1px solid #2a2a4a;
            font-family: 'JetBrains Mono', 'SF Mono', 'Consolas', monospace;
            font-size: 13px;
            border-radius: 4px;
        }
        QLineEdit {
            background-color: #16213e;
            color: #e0e0e0;
            border: 1px solid #2a2a4a;
            border-radius: 4px;
            padding: 5px 10px;
            font-size: 13px;
        }
        QLineEdit:focus {
            border-color: #533483;
        }
        QComboBox {
            background-color: #16213e;
            color: #e0e0e0;
            border: 1px solid #2a2a4a;
            border-radius: 4px;
            padding: 5px 10px;
        }
        QComboBox::drop-down {
            border: none;
            width: 20px;
        }
        QComboBox QAbstractItemView {
            background-color: #16213e;
            color: #e0e0e0;
            selection-background-color: #0f3460;
            border: 1px solid #2a2a4a;
        }
        QPushButton {
            background-color: #e94560;
            color: #ffffff;
            border: none;
            border-radius: 4px;
            padding: 7px 18px;
            font-weight: 600;
        }
        QPushButton:hover {
            background-color: #ff6b81;
        }
        QPushButton:pressed {
            background-color: #c23152;
        }
        QSplitter::handle {
            background-color: #2a2a4a;
            height: 2px;
        }
        QScrollBar:vertical {
            background-color: #1a1a2e;
            width: 10px;
        }
        QScrollBar::handle:vertical {
            background-color: #3a3a5a;
            border-radius: 5px;
            min-height: 20px;
        }
        QScrollBar::handle:vertical:hover {
            background-color: #533483;
        }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            height: 0;
        }
        QScrollBar:horizontal {
            background-color: #1a1a2e;
            height: 10px;
        }
        QScrollBar::handle:horizontal {
            background-color: #3a3a5a;
            border-radius: 5px;
            min-width: 20px;
        }
        QScrollBar::handle:horizontal:hover {
            background-color: #533483;
        }
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
            width: 0;
        }
        QListWidget#sidebar {
            background-color: #16213e;
            color: #c0c0d0;
            border: none;
            outline: none;
            font-size: 13px;
        }
        QListWidget#sidebar::item {
            padding: 12px 16px;
            border-left: 3px solid transparent;
            border-bottom: 1px solid #1a1a2e;
        }
        QListWidget#sidebar::item:selected {
            background-color: #1a1a2e;
            color: #ffffff;
            border-left: 3px solid #e94560;
            font-weight: 600;
        }
        QListWidget#sidebar::item:hover:!selected {
            background-color: #1e1e38;
            border-left: 3px solid #533483;
        }
        QGroupBox {
            border: 1px solid #2a2a4a;
            border-radius: 6px;
            margin-top: 10px;
            padding-top: 18px;
            color: #e0e0e0;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 12px;
            padding: 0 6px;
        }
        QCheckBox {
            color: #e0e0e0;
            spacing: 8px;
        }
        QCheckBox::indicator {
            width: 16px;
            height: 16px;
            border: 1px solid #3a3a5a;
            border-radius: 3px;
            background-color: #16213e;
        }
        QCheckBox::indicator:checked {
            background-color: #e94560;
            border-color: #e94560;
        }
        QToolTip {
            background-color: #16213e;
            color: #e0e0e0;
            border: 1px solid #533483;
            padding: 4px 8px;
            border-radius: 4px;
        }
    )";
}

QString Theme::lightStyleSheet()
{
    return R"(
        QMainWindow, QWidget {
            background-color: #f5f5f5;
            color: #333333;
            font-family: -apple-system, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
        }
        QMenuBar {
            background-color: #ffffff;
            color: #333333;
            border-bottom: 1px solid #e0e0e0;
        }
        QMenuBar::item:selected {
            background-color: #e8f0fe;
        }
        QMenu {
            background-color: #ffffff;
            color: #333333;
            border: 1px solid #e0e0e0;
            border-radius: 6px;
            padding: 4px;
        }
        QMenu::item {
            padding: 6px 24px;
            border-radius: 3px;
        }
        QMenu::item:selected {
            background-color: #e8f0fe;
        }
        QToolBar {
            background-color: #ffffff;
            border-bottom: 1px solid #e0e0e0;
            spacing: 6px;
            padding: 4px 8px;
        }
        QToolButton {
            background-color: #f0f0f0;
            color: #333333;
            border: 1px solid #d0d0d0;
            border-radius: 4px;
            padding: 5px 14px;
            font-weight: 500;
        }
        QToolButton:hover {
            background-color: #e8f0fe;
            border-color: #4a90d9;
        }
        QToolButton:checked {
            background-color: #e94560;
            color: #ffffff;
            border-color: #e94560;
        }
        QStatusBar {
            background-color: #4a90d9;
            color: #ffffff;
            font-size: 12px;
        }
        QLabel {
            color: #333333;
        }
        QTableWidget {
            background-color: #ffffff;
            alternate-background-color: #f8f9fa;
            color: #333333;
            gridline-color: #e8e8e8;
            selection-background-color: #e8f0fe;
            border: none;
            font-size: 13px;
        }
        QTableWidget::item {
            padding: 3px 8px;
        }
        QTableWidget::item:selected {
            background-color: #e8f0fe;
            color: #1a1a2e;
        }
        QHeaderView::section {
            background-color: #f5f5f5;
            color: #555555;
            border: none;
            border-bottom: 2px solid #4a90d9;
            border-right: 1px solid #e0e0e0;
            padding: 6px 8px;
            font-weight: 600;
            font-size: 12px;
        }
        QTabWidget::pane {
            border: 1px solid #e0e0e0;
            background-color: #ffffff;
            border-radius: 0 0 4px 4px;
        }
        QTabBar::tab {
            background-color: #f5f5f5;
            color: #888888;
            padding: 8px 18px;
            border: 1px solid #e0e0e0;
            border-bottom: none;
            margin-right: 2px;
        }
        QTabBar::tab:selected {
            background-color: #ffffff;
            color: #333333;
            border-bottom: 2px solid #e94560;
        }
        QTabBar::tab:hover:!selected {
            background-color: #eef3fa;
            color: #555555;
        }
        QTextEdit, QPlainTextEdit {
            background-color: #fafafa;
            color: #333333;
            border: 1px solid #e0e0e0;
            font-family: 'JetBrains Mono', 'SF Mono', 'Consolas', monospace;
            font-size: 13px;
            border-radius: 4px;
        }
        QLineEdit {
            background-color: #ffffff;
            color: #333333;
            border: 1px solid #d0d0d0;
            border-radius: 4px;
            padding: 5px 10px;
            font-size: 13px;
        }
        QLineEdit:focus {
            border-color: #4a90d9;
        }
        QComboBox {
            background-color: #ffffff;
            color: #333333;
            border: 1px solid #d0d0d0;
            border-radius: 4px;
            padding: 5px 10px;
        }
        QPushButton {
            background-color: #e94560;
            color: #ffffff;
            border: none;
            border-radius: 4px;
            padding: 7px 18px;
            font-weight: 600;
        }
        QPushButton:hover {
            background-color: #ff6b81;
        }
        QPushButton:pressed {
            background-color: #c23152;
        }
        QSplitter::handle {
            background-color: #e0e0e0;
            height: 2px;
        }
        QListWidget#sidebar {
            background-color: #ffffff;
            color: #555555;
            border: none;
            outline: none;
            font-size: 13px;
        }
        QListWidget#sidebar::item {
            padding: 12px 16px;
            border-left: 3px solid transparent;
            border-bottom: 1px solid #f0f0f0;
        }
        QListWidget#sidebar::item:selected {
            background-color: #f5f5f5;
            color: #1a1a2e;
            border-left: 3px solid #e94560;
            font-weight: 600;
        }
        QListWidget#sidebar::item:hover:!selected {
            background-color: #f0f4fa;
            border-left: 3px solid #4a90d9;
        }
        QGroupBox {
            border: 1px solid #e0e0e0;
            border-radius: 6px;
            margin-top: 10px;
            padding-top: 18px;
            color: #333333;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 12px;
            padding: 0 6px;
        }
        QCheckBox {
            color: #333333;
            spacing: 8px;
        }
        QCheckBox::indicator {
            width: 16px;
            height: 16px;
            border: 1px solid #d0d0d0;
            border-radius: 3px;
            background-color: #ffffff;
        }
        QCheckBox::indicator:checked {
            background-color: #e94560;
            border-color: #e94560;
        }
        QToolTip {
            background-color: #ffffff;
            color: #333333;
            border: 1px solid #4a90d9;
            padding: 4px 8px;
            border-radius: 4px;
        }
    )";
}
