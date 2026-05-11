#pragma once

#include <QObject>
#include <QMap>
#include <QString>

enum class Language { English, Chinese };

class Translator : public QObject
{
    Q_OBJECT
public:
    static Translator &instance();

    void setLanguage(Language lang);
    Language currentLanguage() const { return m_lang; }
    QString translate(const char *key) const;

    // Convenience
    static QString t(const char *key) { return instance().translate(key); }

signals:
    void languageChanged();

private:
    explicit Translator(QObject *parent = nullptr);
    void loadTranslations();

    Language m_lang = Language::Chinese;
    QMap<QString, QString> m_translations;  // key -> translated text
};
