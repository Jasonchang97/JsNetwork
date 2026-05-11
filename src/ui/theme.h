#pragma once

#include <QObject>
#include <QString>

enum class ThemeMode { Dark, Light };

class Theme : public QObject
{
    Q_OBJECT
public:
    explicit Theme(QObject *parent = nullptr);

    void applyTheme(ThemeMode mode);
    void toggleTheme();
    ThemeMode currentMode() const { return m_mode; }

    // Persist preference
    void savePreference();
    void loadPreference();

signals:
    void themeChanged(ThemeMode mode);

private:
    static QString darkStyleSheet();
    static QString lightStyleSheet();

    ThemeMode m_mode = ThemeMode::Dark;
};
