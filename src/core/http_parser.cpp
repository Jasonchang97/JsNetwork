#include "http_parser.h"
#include <QUrl>
#include <zlib.h>

static QByteArray gunzip(const QByteArray &data)
{
    if (data.size() < 2) return QByteArray();

    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    // 15 + 32 = automatic gzip/deflate detection
    if (inflateInit2(&strm, 15 + 32) != Z_OK) return QByteArray();

    strm.next_in = (Bytef *)data.constData();
    strm.avail_in = data.size();

    QByteArray out;
    char buf[16384];
    int ret;
    do {
        strm.next_out = (Bytef *)buf;
        strm.avail_out = sizeof(buf);
        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret == Z_OK || ret == Z_STREAM_END) {
            out.append(buf, sizeof(buf) - strm.avail_out);
        }
    } while (ret == Z_OK);

    inflateEnd(&strm);
    return (ret == Z_STREAM_END) ? out : QByteArray();
}

static QByteArray decodeChunked(const QByteArray &data)
{
    QByteArray decoded;
    int pos = 0;
    while (pos < data.size()) {
        int lineEnd = data.indexOf("\r\n", pos);
        if (lineEnd < 0) break;
        bool ok;
        int chunkSize = data.mid(pos, lineEnd - pos).toInt(&ok, 16);
        if (!ok || chunkSize == 0) break;
        pos = lineEnd + 2;
        if (pos + chunkSize > data.size()) break;
        decoded.append(data.mid(pos, chunkSize));
        pos += chunkSize + 2;
    }
    return decoded.isEmpty() ? data : decoded;
}

static QByteArray decompressBody(const QByteArray &body, const QString &encoding)
{
    QString enc = encoding.toLower();
    if (enc == "gzip" || enc == "deflate" || enc == "x-gzip") {
        QByteArray decompressed = gunzip(body);
        if (!decompressed.isEmpty()) return decompressed;
    }
    if (enc == "br") {
        // Brotli - not supported without libbrotli, return as-is
    }
    return body;
}

HttpParser::HttpParser(QObject *parent)
    : QObject(parent)
{
}

bool HttpParser::parseRequest(const QByteArray &data, RequestItem &item)
{
    int headerEnd = data.indexOf("\r\n\r\n");
    if (headerEnd < 0) return false;

    QByteArray headerBlock = data.left(headerEnd);
    QList<QByteArray> lines = headerBlock.split('\n');
    if (lines.isEmpty()) return false;

    // Parse request line: GET /path HTTP/1.1
    QByteArray requestLine = lines.first().trimmed();
    QList<QByteArray> parts = requestLine.split(' ');
    if (parts.size() < 3) return false;

    item.method = QString::fromLatin1(parts[0]);
    item.path = QString::fromLatin1(parts[1]);
    item.protocol = QString::fromLatin1(parts[2]);

    // Parse headers
    item.requestHeaders = parseHeaders(headerBlock);
    item.host = item.requestHeaders.value("Host");

    // Build full URL
    if (item.path.startsWith("http://") || item.path.startsWith("https://")) {
        item.url = item.path;
    } else {
        item.url = "http://" + item.host + item.path;
    }

    // Parse body
    QByteArray body = data.mid(headerEnd + 4);
    item.requestSize = body.size();

    // Decode chunked transfer encoding
    QString te = item.requestHeaders.value("Transfer-Encoding").toLower();
    if (te.contains("chunked")) {
        body = decodeChunked(body);
    }

    // Decompress if Content-Encoding is gzip/deflate
    QString encoding = item.requestHeaders.value("Content-Encoding");
    body = decompressBody(body, encoding);

    item.requestBody = body;

    return true;
}

bool HttpParser::parseResponse(const QByteArray &data, RequestItem &item)
{
    int headerEnd = data.indexOf("\r\n\r\n");
    if (headerEnd < 0) return false;

    QByteArray headerBlock = data.left(headerEnd);
    QList<QByteArray> lines = headerBlock.split('\n');
    if (lines.isEmpty()) return false;

    // Parse status line: HTTP/1.1 200 OK
    QByteArray statusLine = lines.first().trimmed();
    QList<QByteArray> parts = statusLine.split(' ');
    if (parts.size() < 2) return false;

    item.protocol = QString::fromLatin1(parts[0]);
    item.statusCode = parts[1].toInt();
    if (parts.size() > 2) {
        item.statusText = QString::fromLatin1(parts.mid(2).join(' '));
    }

    // Parse headers
    item.responseHeaders = parseHeaders(headerBlock);

    // Parse body
    QByteArray body = data.mid(headerEnd + 4);
    item.responseSize = body.size();

    // Decode chunked transfer encoding
    QString te = item.responseHeaders.value("Transfer-Encoding").toLower();
    if (te.contains("chunked")) {
        body = decodeChunked(body);
    }

    // Decompress if Content-Encoding is gzip/deflate
    QString encoding = item.responseHeaders.value("Content-Encoding");
    body = decompressBody(body, encoding);

    item.responseBody = body;

    return true;
}

QMap<QString, QString> HttpParser::parseHeaders(const QByteArray &headerBlock)
{
    QMap<QString, QString> headers;
    QList<QByteArray> lines = headerBlock.split('\n');

    for (int i = 1; i < lines.size(); ++i) {
        QByteArray line = lines[i].trimmed();
        int colonPos = line.indexOf(':');
        if (colonPos > 0) {
            QString key = QString::fromLatin1(line.left(colonPos)).trimmed();
            QString value = QString::fromLatin1(line.mid(colonPos + 1)).trimmed();
            headers[key] = value;
        }
    }
    return headers;
}
