#pragma once

#include <QObject>
#include <QSqlDatabase>
#include <QList>
#include "model/request_item.h"

class TrafficStorage : public QObject
{
    Q_OBJECT
public:
    explicit TrafficStorage(QObject *parent = nullptr);
    ~TrafficStorage();

    bool open(const QString &dbPath);
    void close();
    bool isOpen() const;

    // CRUD
    bool saveRequest(const RequestItem &item);
    QList<RequestItem> loadRequests(int limit = 1000, int offset = 0);
    QList<RequestItem> searchRequests(const QString &keyword, int limit = 100);
    int requestCount() const;

    // Cleanup
    bool clearAll();
    bool clearOlderThan(int days);

private:
    bool createTables();

    QSqlDatabase m_db;
};
