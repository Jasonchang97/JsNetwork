#include "traffic_storage.h"
#include <QSqlQuery>
#include <QSqlError>
#include <QVariant>
#include <QDebug>

TrafficStorage::TrafficStorage(QObject *parent)
    : QObject(parent)
{
}

TrafficStorage::~TrafficStorage()
{
    close();
}

bool TrafficStorage::open(const QString &dbPath)
{
    m_db = QSqlDatabase::addDatabase("QSQLITE", "traffic");
    m_db.setDatabaseName(dbPath);

    if (!m_db.open()) {
        qWarning() << "Failed to open database:" << m_db.lastError().text();
        return false;
    }

    return createTables();
}

void TrafficStorage::close()
{
    if (m_db.isOpen()) {
        m_db.close();
    }
}

bool TrafficStorage::isOpen() const
{
    return m_db.isOpen();
}

bool TrafficStorage::createTables()
{
    QSqlQuery query(m_db);
    return query.exec(
        "CREATE TABLE IF NOT EXISTS requests ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  timestamp TEXT,"
        "  method TEXT,"
        "  url TEXT,"
        "  host TEXT,"
        "  path TEXT,"
        "  protocol TEXT,"
        "  status_code INTEGER,"
        "  status_text TEXT,"
        "  request_size INTEGER,"
        "  response_size INTEGER,"
        "  duration INTEGER,"
        "  request_headers TEXT,"
        "  response_headers TEXT,"
        "  request_body BLOB,"
        "  response_body BLOB"
        ")"
    );
}

bool TrafficStorage::saveRequest(const RequestItem &item)
{
    QSqlQuery query(m_db);
    query.prepare(
        "INSERT INTO requests (timestamp, method, url, host, path, protocol,"
        "  status_code, status_text, request_size, response_size, duration,"
        "  request_headers, response_headers, request_body, response_body)"
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    );
    query.addBindValue(item.timestamp.toString(Qt::ISODate));
    query.addBindValue(item.method);
    query.addBindValue(item.url);
    query.addBindValue(item.host);
    query.addBindValue(item.path);
    query.addBindValue(item.protocol);
    query.addBindValue(item.statusCode);
    query.addBindValue(item.statusText);
    query.addBindValue(item.requestSize);
    query.addBindValue(item.responseSize);
    query.addBindValue(item.duration);

    // Serialize headers as JSON-like string
    QString reqHeaders;
    for (auto it = item.requestHeaders.constBegin(); it != item.requestHeaders.constEnd(); ++it) {
        if (!reqHeaders.isEmpty()) reqHeaders += "\n";
        reqHeaders += it.key() + ": " + it.value();
    }
    query.addBindValue(reqHeaders);

    QString respHeaders;
    for (auto it = item.responseHeaders.constBegin(); it != item.responseHeaders.constEnd(); ++it) {
        if (!respHeaders.isEmpty()) respHeaders += "\n";
        respHeaders += it.key() + ": " + it.value();
    }
    query.addBindValue(respHeaders);

    query.addBindValue(item.requestBody);
    query.addBindValue(item.responseBody);

    if (!query.exec()) {
        qWarning() << "Failed to save request:" << query.lastError().text();
        return false;
    }
    return true;
}

QList<RequestItem> TrafficStorage::loadRequests(int limit, int offset)
{
    QList<RequestItem> items;
    QSqlQuery query(m_db);
    query.prepare("SELECT * FROM requests ORDER BY id DESC LIMIT ? OFFSET ?");
    query.addBindValue(limit);
    query.addBindValue(offset);

    if (!query.exec()) return items;

    while (query.next()) {
        RequestItem item;
        item.id = query.value("id").toInt();
        item.timestamp = QDateTime::fromString(query.value("timestamp").toString(), Qt::ISODate);
        item.method = query.value("method").toString();
        item.url = query.value("url").toString();
        item.host = query.value("host").toString();
        item.path = query.value("path").toString();
        item.protocol = query.value("protocol").toString();
        item.statusCode = query.value("status_code").toInt();
        item.statusText = query.value("status_text").toString();
        item.requestSize = query.value("request_size").toLongLong();
        item.responseSize = query.value("response_size").toLongLong();
        item.duration = query.value("duration").toLongLong();
        item.requestBody = query.value("request_body").toByteArray();
        item.responseBody = query.value("response_body").toByteArray();

        // Parse headers
        QString reqH = query.value("request_headers").toString();
        for (const QString &line : reqH.split('\n')) {
            int colon = line.indexOf(':');
            if (colon > 0) {
                item.requestHeaders[line.left(colon).trimmed()] = line.mid(colon + 1).trimmed();
            }
        }
        QString respH = query.value("response_headers").toString();
        for (const QString &line : respH.split('\n')) {
            int colon = line.indexOf(':');
            if (colon > 0) {
                item.responseHeaders[line.left(colon).trimmed()] = line.mid(colon + 1).trimmed();
            }
        }

        items.append(item);
    }

    return items;
}

QList<RequestItem> TrafficStorage::searchRequests(const QString &keyword, int limit)
{
    QList<RequestItem> items;
    QSqlQuery query(m_db);
    query.prepare("SELECT * FROM requests WHERE url LIKE ? OR host LIKE ? OR path LIKE ? "
                  "ORDER BY id DESC LIMIT ?");
    QString pattern = "%" + keyword + "%";
    query.addBindValue(pattern);
    query.addBindValue(pattern);
    query.addBindValue(pattern);
    query.addBindValue(limit);

    if (!query.exec()) return items;

    while (query.next()) {
        RequestItem item;
        item.id = query.value("id").toInt();
        item.method = query.value("method").toString();
        item.url = query.value("url").toString();
        item.host = query.value("host").toString();
        item.path = query.value("path").toString();
        item.statusCode = query.value("status_code").toInt();
        item.duration = query.value("duration").toLongLong();
        items.append(item);
    }

    return items;
}

int TrafficStorage::requestCount() const
{
    QSqlQuery query(m_db);
    query.exec("SELECT COUNT(*) FROM requests");
    if (query.next()) return query.value(0).toInt();
    return 0;
}

bool TrafficStorage::clearAll()
{
    QSqlQuery query(m_db);
    return query.exec("DELETE FROM requests");
}

bool TrafficStorage::clearOlderThan(int days)
{
    QSqlQuery query(m_db);
    query.prepare("DELETE FROM requests WHERE timestamp < datetime('now', ?)");
    query.addBindValue(QString("-%1 days").arg(days));
    return query.exec();
}
