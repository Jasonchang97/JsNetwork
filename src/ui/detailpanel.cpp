#include "detailpanel.h"
#include "bodypreview.h"
#include "timelinewidget.h"
#include "app/translator.h"
#include <QVBoxLayout>
#include <QJsonDocument>

DetailPanel::DetailPanel(QWidget *parent)
    : QWidget(parent)
{
    setupUi();
    connect(&Translator::instance(), &Translator::languageChanged, this, [this]() {
        if (m_hasItem) {
            setRequest(m_currentItem);
        }
    });
}

void DetailPanel::setupUi()
{
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);

    m_tabs = new QTabWidget(this);

    m_overviewText = new QTextEdit(this);
    m_overviewText->setReadOnly(true);

    m_requestHeadersText = new QTextEdit(this);
    m_requestHeadersText->setReadOnly(true);

    m_requestBodyPreview = new BodyPreview(this);

    m_responseHeadersText = new QTextEdit(this);
    m_responseHeadersText->setReadOnly(true);

    m_responseBodyPreview = new BodyPreview(this);

    m_timeline = new TimelineWidget(this);

    m_tabs->addTab(m_overviewText, "Overview");
    m_tabs->addTab(m_requestHeadersText, "Request Headers");
    m_tabs->addTab(m_requestBodyPreview, "Request Body");
    m_tabs->addTab(m_responseHeadersText, "Response Headers");
    m_tabs->addTab(m_responseBodyPreview, "Response Body");
    m_tabs->addTab(m_timeline, "Timeline");

    layout->addWidget(m_tabs);
}

void DetailPanel::setRequest(const RequestItem &item)
{
    m_currentItem = item;
    m_hasItem = true;

    auto &t = Translator::instance();
    m_tabs->setTabText(0, t.translate("Overview"));
    m_tabs->setTabText(1, t.translate("Request Headers"));
    m_tabs->setTabText(2, t.translate("Request Body"));
    m_tabs->setTabText(3, t.translate("Response Headers"));
    m_tabs->setTabText(4, t.translate("Response Body"));
    m_tabs->setTabText(5, t.translate("Timeline"));

    updateOverview(item);
    updateRequestTab(item);
    updateResponseTab(item);
    updateTimeline(item);
}

void DetailPanel::updateOverview(const RequestItem &item)
{
    auto &t = Translator::instance();
    QString text;
    text += "<pre style='font-family:monospace;font-size:13px;'>";
    text += QString("<b>%1:</b>      %2\n").arg(t.translate("URL"), item.url.toHtmlEscaped());
    text += QString("<b>%1:</b>   %2\n").arg(t.translate("Method"), item.method.toHtmlEscaped());
    text += QString("<b>%1:</b>   <span style='color:%3;'>%2</span>\n")
        .arg(t.translate("Status")).arg(item.statusCode).arg(item.statusColor());
    text += QString("<b>%1:</b> %2\n").arg(t.translate("Protocol"), item.protocol.toHtmlEscaped());
    text += QString("<b>%1:</b>     %2\n").arg(t.translate("Host"), item.host.toHtmlEscaped());
    text += QString("<b>%1:</b>     %2\n").arg(t.translate("Path"), item.path.toHtmlEscaped());
    text += "\n";
    text += QString("<b>%1:</b>  %2 bytes\n").arg(t.translate("Request Size")).arg(item.requestSize);
    text += QString("<b>%1:</b> %2 bytes\n").arg(t.translate("Response Size")).arg(item.responseSize);
    text += QString("<b>%1:</b>      %2ms\n").arg(t.translate("Duration")).arg(item.duration);
    text += QString("<b>%1:</b>          %2\n").arg(t.translate("Time"), item.timestamp.toString(Qt::ISODate));
    text += "</pre>";
    m_overviewText->setHtml(text);
}

void DetailPanel::updateRequestTab(const RequestItem &item)
{
    auto &t = Translator::instance();
    // Headers
    QString headers;
    for (auto it = item.requestHeaders.constBegin(); it != item.requestHeaders.constEnd(); ++it) {
        headers += QString("<b>%1:</b> %2\n").arg(it.key().toHtmlEscaped(), it.value().toHtmlEscaped());
    }
    m_requestHeadersText->setHtml("<pre style='font-family:monospace;font-size:13px;'>" + headers + "</pre>");

    // Body
    QString contentType = item.requestHeaders.value("Content-Type");
    m_requestBodyPreview->setBody(item.requestBody, contentType);
}

void DetailPanel::updateResponseTab(const RequestItem &item)
{
    // Headers
    QString headers;
    for (auto it = item.responseHeaders.constBegin(); it != item.responseHeaders.constEnd(); ++it) {
        headers += QString("<b>%1:</b> %2\n").arg(it.key().toHtmlEscaped(), it.value().toHtmlEscaped());
    }
    m_responseHeadersText->setHtml("<pre style='font-family:monospace;font-size:13px;'>" + headers + "</pre>");

    // Body
    QString contentType = item.responseHeaders.value("Content-Type");
    m_responseBodyPreview->setBody(item.responseBody, contentType);
}

void DetailPanel::updateTimeline(const RequestItem &item)
{
    m_timeline->setTiming(item.dnsTime, item.connectTime, item.tlsTime,
                          item.ttfb, item.downloadTime);
    m_timeline->setTotalTime(item.duration);
}
