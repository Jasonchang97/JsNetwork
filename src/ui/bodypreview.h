#pragma once

#include <QWidget>
#include <QTabWidget>
#include <QTextEdit>
#include <QLabel>
#include <QByteArray>

class BodyPreview : public QWidget
{
    Q_OBJECT
public:
    explicit BodyPreview(QWidget *parent = nullptr);

    // Set body data with content type hint
    void setBody(const QByteArray &data, const QString &contentType);

private:
    void setupUi();
    void showJson(const QByteArray &data);
    void showFormUrlEncoded(const QByteArray &data);
    void showMultipart(const QByteArray &data, const QString &contentType);
    void showXml(const QByteArray &data);
    void showHtml(const QByteArray &data);
    void showImage(const QByteArray &data, const QString &mimeType);
    void showBinaryInfo(const QByteArray &data, const QString &contentType);
    void showRaw(const QByteArray &data);
    void showHex(const QByteArray &data);
    static bool isBinaryData(const QByteArray &data);

    // JSON syntax highlighting
    static QString highlightJson(const QString &json);

    QTabWidget *m_tabs;
    QTextEdit *m_formattedView;
    QTextEdit *m_rawView;
    QTextEdit *m_hexView;
    QLabel *m_imageView;
};
