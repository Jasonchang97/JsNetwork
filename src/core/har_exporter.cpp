#include "har_exporter.h"
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QCoreApplication>
#include <QUrl>

HarExporter::HarExporter(QObject *parent)
    : QObject(parent)
{
}

bool HarExporter::exportToFile(const QList<RequestItem> &items, const QString &filePath)
{
    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly)) return false;

    QByteArray json = exportToJson(items);
    file.write(json);
    file.close();
    return true;
}

QByteArray HarExporter::exportToJson(const QList<RequestItem> &items)
{
    QJsonObject root;

    // HAR version
    QJsonObject log;
    log["version"] = "1.2";

    // Creator
    QJsonObject creator;
    creator["name"] = QCoreApplication::applicationName();
    creator["version"] = QCoreApplication::applicationVersion();
    log["creator"] = creator;

    // Entries
    QJsonArray entries;
    for (const auto &item : items) {
        QJsonObject entry;
        entry["startedDateTime"] = dateTimeToIso(item.timestamp);
        entry["time"] = static_cast<double>(item.duration);

        // Request
        QJsonObject request;
        request["method"] = item.method;
        request["url"] = item.url;
        request["httpVersion"] = item.protocol;
        request["bodySize"] = item.requestSize;

        // Request headers
        QJsonArray reqHeaders;
        for (auto it = item.requestHeaders.constBegin(); it != item.requestHeaders.constEnd(); ++it) {
            QJsonObject h;
            h["name"] = it.key();
            h["value"] = it.value();
            reqHeaders.append(h);
        }
        request["headers"] = reqHeaders;

        // Query string (parsed from URL)
        QJsonArray queryString;
        QUrl url(item.url);
        QString queryStr = url.query();
        if (!queryStr.isEmpty()) {
            QStringList pairs = queryStr.split('&', QString::SkipEmptyParts);
            for (const auto &pair : pairs) {
                QStringList kv = pair.split('=');
                QJsonObject q;
                q["name"] = QUrl::fromPercentEncoding(kv.value(0).toUtf8());
                q["value"] = kv.size() > 1 ? QUrl::fromPercentEncoding(kv.value(1).toUtf8()) : "";
                queryString.append(q);
            }
        }
        request["queryString"] = queryString;

        // Request body
        QJsonObject reqBody;
        reqBody["size"] = item.requestSize;
        reqBody["text"] = QString::fromUtf8(item.requestBody);
        request["body"] = reqBody;

        // Request cookies
        QJsonArray reqCookies;
        request["cookies"] = reqCookies;

        entry["request"] = request;

        // Response
        QJsonObject response;
        response["status"] = item.statusCode;
        response["statusText"] = item.statusText;
        response["httpVersion"] = item.protocol;
        response["bodySize"] = item.responseSize;

        // Response headers
        QJsonArray respHeaders;
        for (auto it = item.responseHeaders.constBegin(); it != item.responseHeaders.constEnd(); ++it) {
            QJsonObject h;
            h["name"] = it.key();
            h["value"] = it.value();
            respHeaders.append(h);
        }
        response["headers"] = respHeaders;

        // Response body
        QJsonObject respBody;
        respBody["size"] = item.responseSize;
        respBody["text"] = QString::fromUtf8(item.responseBody);
        response["content"] = respBody;

        // Response cookies
        QJsonArray respCookies;
        response["cookies"] = respCookies;

        entry["response"] = response;

        // Timings
        QJsonObject timings;
        timings["dns"] = item.dnsTime;
        timings["connect"] = item.connectTime;
        timings["ssl"] = item.tlsTime;
        timings["send"] = 0;
        timings["wait"] = item.ttfb;
        timings["receive"] = item.downloadTime;
        entry["timings"] = timings;

        entries.append(entry);
    }

    log["entries"] = entries;
    root["log"] = log;

    QJsonDocument doc(root);
    return doc.toJson(QJsonDocument::Indented);
}

QString HarExporter::dateTimeToIso(const QDateTime &dt)
{
    return dt.toString(Qt::ISODate);
}
