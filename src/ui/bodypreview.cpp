#include "bodypreview.h"
#include "app/translator.h"
#include <QVBoxLayout>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonParseError>
#include <QPixmap>
#include <QScrollArea>
#include <QUrlQuery>

BodyPreview::BodyPreview(QWidget *parent)
    : QWidget(parent)
{
    setupUi();
}

void BodyPreview::setupUi()
{
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);

    m_tabs = new QTabWidget(this);

    m_formattedView = new QTextEdit(this);
    m_formattedView->setReadOnly(true);
    m_formattedView->setLineWrapMode(QTextEdit::NoWrap);
    m_formattedView->setFontFamily("monospace");

    m_rawView = new QTextEdit(this);
    m_rawView->setReadOnly(true);
    m_rawView->setLineWrapMode(QTextEdit::WidgetWidth);

    m_hexView = new QTextEdit(this);
    m_hexView->setReadOnly(true);
    m_hexView->setLineWrapMode(QTextEdit::NoWrap);
    m_hexView->setFontFamily("monospace");

    m_imageView = new QLabel(this);
    m_imageView->setAlignment(Qt::AlignCenter);
    auto *scrollArea = new QScrollArea(this);
    scrollArea->setWidget(m_imageView);
    scrollArea->setWidgetResizable(true);

    m_tabs->addTab(m_formattedView, Translator::t("Formatted"));
    m_tabs->addTab(m_rawView, Translator::t("Raw"));
    m_tabs->addTab(m_hexView, Translator::t("Hex"));
    m_tabs->addTab(scrollArea, Translator::t("Preview"));

    layout->addWidget(m_tabs);
}

void BodyPreview::setBody(const QByteArray &data, const QString &contentType)
{
    if (data.isEmpty()) {
        m_formattedView->setText(Translator::t("(empty)"));
        m_rawView->clear();
        m_hexView->clear();
        m_imageView->clear();
        return;
    }

    QString ct = contentType.toLower();

    if (ct.contains("json")) {
        showJson(data);
    } else if (ct.contains("x-www-form-urlencoded")) {
        showFormUrlEncoded(data);
    } else if (ct.contains("multipart/form-data")) {
        showMultipart(data, contentType);
    } else if (ct.contains("html")) {
        showHtml(data);
    } else if (ct.contains("xml")) {
        showXml(data);
    } else if (ct.contains("image/png") || ct.contains("image/jpeg") ||
               ct.contains("image/gif") || ct.contains("image/webp") ||
               ct.contains("image/svg")) {
        showImage(data, ct);
    } else if (isBinaryData(data)) {
        showBinaryInfo(data, ct);
    } else {
        // Try JSON first (many APIs don't set Content-Type correctly)
        QJsonParseError err;
        QJsonDocument::fromJson(data, &err);
        if (err.error == QJsonParseError::NoError) {
            showJson(data);
        } else {
            showRaw(data);
        }
    }

    showHex(data);
}

void BodyPreview::showJson(const QByteArray &data)
{
    QJsonParseError err;
    QJsonDocument doc = QJsonDocument::fromJson(data, &err);

    if (!doc.isNull()) {
        QByteArray formatted = doc.toJson(QJsonDocument::Indented);
        m_formattedView->setHtml(highlightJson(QString::fromUtf8(formatted)));
        m_tabs->setTabText(0, "JSON");
    } else {
        m_formattedView->setText(QString("JSON Parse Error: %1\n\n%2")
            .arg(err.errorString(), QString::fromUtf8(data)));
        m_tabs->setTabText(0, "JSON");
    }

    m_rawView->setText(QString::fromUtf8(data));
}

void BodyPreview::showFormUrlEncoded(const QByteArray &data)
{
    QString decoded = QString::fromUtf8(data);
    QUrlQuery query(decoded);
    QPair<QString, QString> pair;

    QString html;
    html += "<pre style='font-family:monospace;font-size:13px;'>";
    html += "<b>Form Data:</b>\n\n";

    for (const auto &item : query.queryItems()) {
        html += QString("<span style='color:#9CDCFE'>%1</span>"
                       " = <span style='color:#CE9178'>%2</span>\n")
            .arg(item.first.toHtmlEscaped(), item.second.toHtmlEscaped());
    }
    html += "</pre>";

    m_formattedView->setHtml(html);
    m_rawView->setText(QString::fromUtf8(data));
    m_tabs->setTabText(0, "Form");
}

void BodyPreview::showMultipart(const QByteArray &data, const QString &contentType)
{
    // Extract boundary
    QString boundary;
    int bIdx = contentType.indexOf("boundary=");
    if (bIdx >= 0) {
        boundary = contentType.mid(bIdx + 9).trimmed();
        if (boundary.startsWith('"') && boundary.endsWith('"')) {
            boundary = boundary.mid(1, boundary.size() - 2);
        }
    }

    if (boundary.isEmpty()) {
        showRaw(data);
        return;
    }

    QByteArray delimiter = "--" + boundary.toUtf8();
    QString html;
    html += "<pre style='font-family:monospace;font-size:13px;'>";
    html += "<b>Multipart Form Data:</b>\n";
    html += QString("Boundary: <span style='color:#CE9178'>%1</span>\n\n").arg(boundary.toHtmlEscaped());

    int pos = 0;
    int partNum = 0;
    while (pos < data.size()) {
        int partStart = data.indexOf(delimiter, pos);
        if (partStart < 0) break;

        int contentStart = data.indexOf("\r\n\r\n", partStart);
        if (contentStart < 0) break;
        contentStart += 4;

        QByteArray partHeaders = data.mid(partStart + delimiter.size() + 2,
                                          contentStart - partStart - delimiter.size() - 6);

        int partEnd = data.indexOf(delimiter, contentStart);
        if (partEnd < 0) partEnd = data.size();

        QByteArray partBody = data.mid(contentStart, partEnd - contentStart - 2); // -2 for \r\n before delimiter

        // Parse part headers
        QString name;
        QString filename;
        QString partContentType = "text/plain";
        for (const auto &line : partHeaders.split('\n')) {
            QByteArray trimmed = line.trimmed();
            if (trimmed.toLower().startsWith("content-disposition:")) {
                int nIdx = trimmed.indexOf("name=\"");
                if (nIdx >= 0) {
                    int nEnd = trimmed.indexOf("\"", nIdx + 6);
                    name = QString::fromUtf8(trimmed.mid(nIdx + 6, nEnd - nIdx - 6));
                }
                int fIdx = trimmed.indexOf("filename=\"");
                if (fIdx >= 0) {
                    int fEnd = trimmed.indexOf("\"", fIdx + 10);
                    filename = QString::fromUtf8(trimmed.mid(fIdx + 10, fEnd - fIdx - 10));
                }
            } else if (trimmed.toLower().startsWith("content-type:")) {
                partContentType = QString::fromUtf8(trimmed.mid(13)).trimmed();
            }
        }

        partNum++;
        html += QString("<b>--- Part #%1 ---</b>\n").arg(partNum);
        if (!name.isEmpty()) html += QString("Name: <span style='color:#9CDCFE'>%1</span>\n").arg(name.toHtmlEscaped());
        if (!filename.isEmpty()) html += QString("Filename: <span style='color:#CE9178'>%1</span>\n").arg(filename.toHtmlEscaped());
        html += QString("Content-Type: %1\n").arg(partContentType.toHtmlEscaped());

        if (partContentType.contains("json")) {
            QJsonParseError err;
            QJsonDocument doc = QJsonDocument::fromJson(partBody, &err);
            if (!doc.isNull()) {
                html += QString("Body:\n%1\n").arg(QString::fromUtf8(doc.toJson(QJsonDocument::Indented)));
            } else {
                html += QString("Body: (%1 bytes)\n").arg(partBody.size());
            }
        } else if (partContentType.contains("image")) {
            html += QString("Body: (binary image data, %1 bytes)\n").arg(partBody.size());
        } else {
            QString bodyStr = QString::fromUtf8(partBody);
            if (bodyStr.size() > 500) {
                bodyStr = bodyStr.left(500) + "...";
            }
            html += QString("Body:\n%1\n").arg(bodyStr.toHtmlEscaped());
        }
        html += "\n";

        pos = partEnd;
    }

    html += "</pre>";
    m_formattedView->setHtml(html);
    m_rawView->setText(QString::fromUtf8(data));
    m_tabs->setTabText(0, "Multipart");
}

void BodyPreview::showXml(const QByteArray &data)
{
    QString xmlStr = QString::fromUtf8(data);

    // Simple XML formatting with indentation
    QString formatted;
    int indent = 0;
    bool inTag = false;
    for (int i = 0; i < xmlStr.size(); ++i) {
        QChar c = xmlStr[i];
        if (c == '<') {
            if (xmlStr.mid(i, 2) == "</") {
                indent = qMax(0, indent - 1);
            }
            formatted += "\n" + QString(indent * 2, ' ') + "<";
            inTag = true;
            if (xmlStr.mid(i + 1, 1) != "/" && xmlStr.mid(i + 1, 1) != "!" &&
                !xmlStr.mid(i).contains("</") && xmlStr.mid(i).indexOf("/>") > 0) {
                // Self-closing or opening tag
            }
        } else if (c == '>') {
            formatted += ">";
            inTag = false;
            if (!xmlStr.mid(i - 1, 2).contains("/>") && !xmlStr.mid(i - 1, 1).contains("/")) {
                if (xmlStr.mid(i + 1, 1) != "<") {
                    indent++;
                }
            }
        } else {
            formatted += c;
        }
    }

    m_formattedView->setPlainText(formatted.trimmed());
    m_rawView->setText(xmlStr);
    m_tabs->setTabText(0, "XML");
}

void BodyPreview::showHtml(const QByteArray &data)
{
    m_imageView->setText(QString::fromUtf8(data));
    m_formattedView->setPlainText(QString::fromUtf8(data));
    m_rawView->setText(QString::fromUtf8(data));
    m_tabs->setTabText(0, "HTML");
}

void BodyPreview::showImage(const QByteArray &data, const QString &mimeType)
{
    QPixmap pixmap;
    pixmap.loadFromData(data);

    if (!pixmap.isNull()) {
        m_imageView->setPixmap(pixmap.scaled(
            m_imageView->size(), Qt::KeepAspectRatio, Qt::SmoothTransformation));
        m_formattedView->setText(QString("Image: %1 x %2 %3")
            .arg(pixmap.width()).arg(pixmap.height()).arg(mimeType));
    } else {
        m_imageView->setText("Failed to load image");
        m_formattedView->setText(QString("Image data (%1 bytes, %2)")
            .arg(data.size()).arg(mimeType));
    }

    m_rawView->setText(QString("(Binary image data, %1 bytes)").arg(data.size()));
    m_tabs->setTabText(0, "Image");
}

void BodyPreview::showBinaryInfo(const QByteArray &data, const QString &contentType)
{
    QString info;
    info += "<pre style='font-family:monospace;font-size:13px;'>";
    info += "<b>Binary Data</b>\n\n";
    info += QString("Size: %1 bytes\n").arg(data.size());
    if (!contentType.isEmpty()) {
        info += QString("Content-Type: %1\n").arg(contentType);
    }
    info += "\nHex preview:\n";
    info += data.left(256).toHex(' ');
    if (data.size() > 256) {
        info += "\n... (truncated)";
    }
    info += "</pre>";

    m_formattedView->setHtml(info);
    m_rawView->setText(QString("(Binary data, %1 bytes)").arg(data.size()));
    m_tabs->setTabText(0, "Binary");
}

bool BodyPreview::isBinaryData(const QByteArray &data)
{
    // Check first 512 bytes for null bytes or high concentration of non-printable chars
    int checkLen = qMin(data.size(), 512);
    int nonPrintable = 0;
    for (int i = 0; i < checkLen; ++i) {
        char c = data[i];
        if (c == '\0') return true;  // Null byte = definitely binary
        if (c != '\r' && c != '\n' && c != '\t' && (c < 32 || c > 126)) {
            nonPrintable++;
        }
    }
    return (nonPrintable * 100 / checkLen) > 30;  // >30% non-printable = binary
}

void BodyPreview::showRaw(const QByteArray &data)
{
    m_formattedView->setPlainText(QString::fromUtf8(data));
    m_rawView->setText(QString::fromUtf8(data));
    m_tabs->setTabText(0, "Text");
}

void BodyPreview::showHex(const QByteArray &data)
{
    QString hex;
    for (int i = 0; i < data.size(); i += 16) {
        hex += QString("%1  ").arg(i, 8, 16, QChar('0'));

        for (int j = 0; j < 16; ++j) {
            if (i + j < data.size()) {
                hex += QString("%1 ").arg(static_cast<quint8>(data[i + j]), 2, 16, QChar('0'));
            } else {
                hex += "   ";
            }
            if (j == 7) hex += " ";
        }

        hex += " |";
        for (int j = 0; j < 16 && i + j < data.size(); ++j) {
            char c = data[i + j];
            hex += (c >= 32 && c < 127) ? QChar(c) : QChar('.');
        }
        hex += "|\n";
    }
    m_hexView->setText(hex);
}

QString BodyPreview::highlightJson(const QString &json)
{
    QString html;
    html.reserve(json.size() * 2);

    for (int i = 0; i < json.size(); ++i) {
        QChar c = json[i];

        if (c == '"') {
            int end = json.indexOf('"', i + 1);
            while (end > 0 && json[end - 1] == '\\') {
                end = json.indexOf('"', end + 1);
            }
            if (end < 0) end = json.size() - 1;

            QString str = json.mid(i, end - i + 1);
            int nextNonSpace = end + 1;
            while (nextNonSpace < json.size() && json[nextNonSpace].isSpace()) nextNonSpace++;

            if (nextNonSpace < json.size() && json[nextNonSpace] == ':') {
                html += "<span style=\"color:#9CDCFE\">" + str.toHtmlEscaped() + "</span>";
            } else {
                html += "<span style=\"color:#CE9178\">" + str.toHtmlEscaped() + "</span>";
            }
            i = end;
        } else if (c.isDigit() || (c == '-' && i + 1 < json.size() && json[i + 1].isDigit())) {
            int start = i;
            while (i < json.size() && (json[i].isDigit() || json[i] == '.' || json[i] == '-')) i++;
            html += "<span style=\"color:#B5CEA8\">" + json.mid(start, i - start) + "</span>";
            i--;
        } else if (json.mid(i, 4) == "true") {
            html += "<span style=\"color:#569CD6\">true</span>";
            i += 3;
        } else if (json.mid(i, 5) == "false") {
            html += "<span style=\"color:#569CD6\">false</span>";
            i += 4;
        } else if (json.mid(i, 4) == "null") {
            html += "<span style=\"color:#569CD6\">null</span>";
            i += 3;
        } else {
            if (c == '<') html += "&lt;";
            else if (c == '>') html += "&gt;";
            else if (c == '&') html += "&amp;";
            else html += c;
        }
    }

    return "<pre style=\"font-family:'JetBrains Mono',monospace;font-size:13px;\">"
           + html + "</pre>";
}
