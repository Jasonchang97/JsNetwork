#pragma once

#include <QObject>
#include <QList>
#include <QString>
#include "model/request_item.h"

class HarExporter : public QObject
{
    Q_OBJECT
public:
    explicit HarExporter(QObject *parent = nullptr);

    // Export requests to HAR 1.2 format
    bool exportToFile(const QList<RequestItem> &items, const QString &filePath);

    // Export as JSON byte array
    QByteArray exportToJson(const QList<RequestItem> &items);

private:
    static QString dateTimeToIso(const QDateTime &dt);
};
