#pragma once

#include <QString>
#include <QByteArray>
#include <QDateTime>
#include <QMap>
#include <QMetaType>

struct RequestItem {
    int id = 0;
    QString method;
    QString url;
    QString host;
    QString path;
    QString protocol;
    int statusCode = 0;
    QString statusText;
    qint64 requestSize = 0;
    qint64 responseSize = 0;
    qint64 duration = 0; // ms

    QMap<QString, QString> requestHeaders;
    QMap<QString, QString> responseHeaders;
    QByteArray requestBody;
    QByteArray responseBody;

    QDateTime timestamp;

    // Process info (WFP driver)
    QString source;

    // Timing
    qint64 dnsTime = 0;
    qint64 connectTime = 0;
    qint64 tlsTime = 0;
    qint64 ttfb = 0;
    qint64 downloadTime = 0;

    QString statusColor() const {
        if (statusCode >= 200 && statusCode < 300) return "green";
        if (statusCode >= 300 && statusCode < 400) return "blue";
        if (statusCode >= 400 && statusCode < 500) return "orange";
        if (statusCode >= 500) return "red";
        return "gray";
    }
};

Q_DECLARE_METATYPE(RequestItem)
