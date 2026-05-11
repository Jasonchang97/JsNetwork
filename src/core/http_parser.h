#pragma once

#include <QObject>
#include <QByteArray>
#include "model/request_item.h"

class HttpParser : public QObject
{
    Q_OBJECT
public:
    explicit HttpParser(QObject *parent = nullptr);

    // Parse HTTP request from raw bytes
    static bool parseRequest(const QByteArray &data, RequestItem &item);

    // Parse HTTP response from raw bytes
    static bool parseResponse(const QByteArray &data, RequestItem &item);

private:
    static QMap<QString, QString> parseHeaders(const QByteArray &headerBlock);
};
