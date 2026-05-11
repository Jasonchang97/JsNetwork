#include "composerwidget.h"
#include "app/translator.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QGroupBox>
#include <QNetworkRequest>

ComposerWidget::ComposerWidget(QWidget *parent)
    : QWidget(parent)
    , m_nam(new QNetworkAccessManager(this))
{
    setupUi();
    connect(m_nam, &QNetworkAccessManager::finished,
            this, &ComposerWidget::onReplyFinished);
    connect(&Translator::instance(), &Translator::languageChanged, this, [this]() {
        m_sendBtn->setText(Translator::t("Send"));
        m_reqGroup->setTitle(Translator::t("Request"));
        m_reqHeadersLabel->setText(Translator::t("Headers") + ":");
        m_reqBodyLabel->setText(Translator::t("Body") + ":");
        m_respGroup->setTitle(Translator::t("Response"));
        if (m_sendBtn->isEnabled()) {
            m_statusLabel->setText(Translator::t("Status: -"));
        }
    });
}

void ComposerWidget::setupUi()
{
    auto &t = Translator::instance();
    auto *layout = new QVBoxLayout(this);

    // URL bar
    auto *urlLayout = new QHBoxLayout;
    m_methodCombo = new QComboBox(this);
    m_methodCombo->addItems({"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"});
    m_methodCombo->setFixedWidth(100);
    m_urlEdit = new QLineEdit(this);
    m_urlEdit->setPlaceholderText("https://api.example.com/endpoint");
    m_sendBtn = new QPushButton(t.translate("Send"), this);
    m_sendBtn->setFixedWidth(80);

    urlLayout->addWidget(m_methodCombo);
    urlLayout->addWidget(m_urlEdit);
    urlLayout->addWidget(m_sendBtn);
    layout->addLayout(urlLayout);

    // Splitter: request / response
    auto *splitter = new QSplitter(Qt::Vertical, this);

    // Request section
    m_reqGroup = new QGroupBox(t.translate("Request"), this);
    auto *reqLayout = new QVBoxLayout(m_reqGroup);

    m_headersEdit = new QTextEdit(this);
    m_headersEdit->setPlaceholderText("Header-Name: value\nAnother-Header: value");
    m_headersEdit->setMaximumHeight(120);
    m_headersEdit->setFontFamily("monospace");
    m_reqHeadersLabel = new QLabel(t.translate("Headers") + ":", this);
    reqLayout->addWidget(m_reqHeadersLabel);
    reqLayout->addWidget(m_headersEdit);

    m_bodyEdit = new QTextEdit(this);
    m_bodyEdit->setPlaceholderText("Request body...");
    m_bodyEdit->setFontFamily("monospace");
    m_reqBodyLabel = new QLabel(t.translate("Body") + ":", this);
    reqLayout->addWidget(m_reqBodyLabel);
    reqLayout->addWidget(m_bodyEdit);

    splitter->addWidget(m_reqGroup);

    // Response section
    m_respGroup = new QGroupBox(t.translate("Response"), this);
    auto *respLayout = new QVBoxLayout(m_respGroup);

    m_statusLabel = new QLabel(t.translate("Status: -"), this);
    respLayout->addWidget(m_statusLabel);

    m_responseView = new QTextEdit(this);
    m_responseView->setReadOnly(true);
    m_responseView->setFontFamily("monospace");
    respLayout->addWidget(m_responseView);

    splitter->addWidget(m_respGroup);
    splitter->setStretchFactor(0, 1);
    splitter->setStretchFactor(1, 1);

    layout->addWidget(splitter);

    connect(m_sendBtn, &QPushButton::clicked, this, &ComposerWidget::onSend);
    connect(m_urlEdit, &QLineEdit::returnPressed, this, &ComposerWidget::onSend);
}

void ComposerWidget::setRequest(const QString &method, const QString &url,
                                  const QString &headers, const QString &body)
{
    m_methodCombo->setCurrentText(method);
    m_urlEdit->setText(url);
    m_headersEdit->setPlainText(headers);
    m_bodyEdit->setPlainText(body);
}

void ComposerWidget::onSend()
{
    QString url = m_urlEdit->text().trimmed();
    if (url.isEmpty()) return;

    QNetworkRequest request(url);

    // Parse headers
    QString headersText = m_headersEdit->toPlainText();
    for (const QString &line : headersText.split('\n')) {
        int colon = line.indexOf(':');
        if (colon > 0) {
            QString key = line.left(colon).trimmed();
            QString value = line.mid(colon + 1).trimmed();
            request.setRawHeader(key.toUtf8(), value.toUtf8());
        }
    }

    QString method = m_methodCombo->currentText();
    QByteArray body = m_bodyEdit->toPlainText().toUtf8();

    m_sendBtn->setEnabled(false);
    m_statusLabel->setText(Translator::t("Status: Sending..."));
    m_responseView->clear();

    QNetworkReply *reply = nullptr;
    if (method == "GET") reply = m_nam->get(request);
    else if (method == "POST") reply = m_nam->post(request, body);
    else if (method == "PUT") reply = m_nam->put(request, body);
    else if (method == "DELETE") reply = m_nam->deleteResource(request);
    else if (method == "PATCH") {
        request.setRawHeader("Content-Type", "application/json");
        reply = m_nam->sendCustomRequest(request, "PATCH", body);
    }
    else if (method == "HEAD") reply = m_nam->head(request);
    else if (method == "OPTIONS") reply = m_nam->sendCustomRequest(request, "OPTIONS");

    if (reply) {
        emit requestSent(method, url);
    }
}

void ComposerWidget::onReplyFinished(QNetworkReply *reply)
{
    m_sendBtn->setEnabled(true);

    int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    QString reason = reply->attribute(QNetworkRequest::HttpReasonPhraseAttribute).toString();
    m_statusLabel->setText(Translator::t("Status: %1 %2").arg(status).arg(reason));

    // Show response headers
    QString headersStr;
    for (const auto &pair : reply->rawHeaderPairs()) {
        headersStr += QString("%1: %2\n").arg(
            QString::fromUtf8(pair.first), QString::fromUtf8(pair.second));
    }

    // Show response body
    QByteArray responseData = reply->readAll();
    QString bodyStr = QString::fromUtf8(responseData);

    m_responseView->setPlainText(
        QString("%1\n%2\n%3\n%4")
            .arg(Translator::t("--- Headers ---"), headersStr,
                 Translator::t("--- Body ---"), bodyStr));

    reply->deleteLater();
}
