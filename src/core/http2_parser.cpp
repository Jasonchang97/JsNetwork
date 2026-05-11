#include "http2_parser.h"
#include <QBuffer>

// HPACK static table (RFC 7541 Appendix A) - common entries
const QVector<QPair<QByteArray, QByteArray>> Http2Parser::s_hpackStaticTable = {
    {"", ""},                                        // 0 (unused)
    {":authority", ""},                              // 1
    {":method", "GET"},                              // 2
    {":method", "POST"},                             // 3
    {":path", "/"},                                  // 4
    {":path", "/index.html"},                        // 5
    {":scheme", "http"},                             // 6
    {":scheme", "https"},                            // 7
    {":status", "200"},                              // 8
    {":status", "204"},                              // 9
    {":status", "206"},                              // 10
    {":status", "304"},                              // 11
    {":status", "400"},                              // 12
    {":status", "404"},                              // 13
    {":status", "500"},                              // 14
    {"accept-charset", ""},                          // 15
    {"accept-encoding", "gzip, deflate"},            // 16
    {"accept-language", ""},                         // 17
    {"accept-ranges", ""},                           // 18
    {"accept", ""},                                  // 19
    {"access-control-allow-origin", ""},             // 20
    {"age", ""},                                     // 21
    {"allow", ""},                                   // 22
    {"authorization", ""},                           // 23
    {"cache-control", ""},                           // 24
    {"content-disposition", ""},                     // 25
    {"content-encoding", ""},                        // 26
    {"content-language", ""},                        // 27
    {"content-length", ""},                          // 28
    {"content-location", ""},                        // 29
    {"content-range", ""},                           // 30
    {"content-type", ""},                            // 31
    {"cookie", ""},                                  // 32
    {"date", ""},                                    // 33
    {"etag", ""},                                    // 34
    {"expect", ""},                                  // 35
    {"expires", ""},                                 // 36
    {"from", ""},                                    // 37
    {"host", ""},                                    // 38
    {"if-match", ""},                                // 39
    {"if-modified-since", ""},                       // 40
    {"if-none-match", ""},                           // 41
    {"if-range", ""},                                // 42
    {"if-unmodified-since", ""},                     // 43
    {"last-modified", ""},                           // 44
    {"link", ""},                                    // 45
    {"location", ""},                                // 46
    {"max-forwards", ""},                            // 47
    {"proxy-authenticate", ""},                      // 48
    {"proxy-authorization", ""},                     // 49
    {"range", ""},                                   // 50
    {"referer", ""},                                 // 51
    {"refresh", ""},                                 // 52
    {"retry-after", ""},                             // 53
    {"server", ""},                                  // 54
    {"set-cookie", ""},                              // 55
    {"strict-transport-security", ""},               // 56
    {"transfer-encoding", ""},                       // 57
    {"user-agent", ""},                              // 58
    {"vary", ""},                                    // 59
    {"via", ""},                                     // 60
    {"www-authenticate", ""},                        // 61
};

// ============================================================================
// Http2Frame
// ============================================================================

QString Http2Frame::typeName() const
{
    switch (type) {
    case Http2FrameType::Data:         return "DATA";
    case Http2FrameType::Headers:      return "HEADERS";
    case Http2FrameType::Priority:     return "PRIORITY";
    case Http2FrameType::RstStream:    return "RST_STREAM";
    case Http2FrameType::Settings:     return "SETTINGS";
    case Http2FrameType::PushPromise:  return "PUSH_PROMISE";
    case Http2FrameType::Ping:         return "PING";
    case Http2FrameType::GoAway:       return "GOAWAY";
    case Http2FrameType::WindowUpdate: return "WINDOW_UPDATE";
    case Http2FrameType::Continuation: return "CONTINUATION";
    default:                           return "UNKNOWN";
    }
}

// ============================================================================
// Http2Parser
// ============================================================================

Http2Parser::Http2Parser(QObject *parent)
    : QObject(parent)
{
}

QVector<Http2Frame> Http2Parser::feed(const QByteArray &data)
{
    m_buffer.append(data);
    QVector<Http2Frame> frames;

    while (m_buffer.size() >= 9) {
        Http2Frame frame;
        int consumed = parseFrame(m_buffer, frame);
        if (consumed <= 0) break;

        m_buffer = m_buffer.mid(consumed);
        frames.append(frame);

        // Update stream tracking
        if (frame.streamId > 0) {
            Http2Stream *stream = getStream(frame.streamId);

            if (frame.type == Http2FrameType::Headers) {
                bool isRequest = frame.headers.contains(":method");
                if (isRequest) {
                    stream->requestHeaders = frame.headers;
                    stream->requestComplete = frame.endStream;
                } else {
                    stream->responseHeaders = frame.headers;
                    stream->responseComplete = frame.endStream;
                }
            } else if (frame.type == Http2FrameType::Data) {
                bool hasRequest = !stream->requestHeaders.isEmpty();
                if (hasRequest && !stream->requestComplete) {
                    stream->requestData.append(frame.data);
                } else {
                    stream->responseData.append(frame.data);
                }
                if (frame.endStream) {
                    if (!stream->requestComplete) {
                        stream->requestComplete = true;
                    } else {
                        stream->responseComplete = true;
                    }
                }
            }
        }
    }

    return frames;
}

int Http2Parser::parseFrame(const QByteArray &buffer, Http2Frame &frame)
{
    if (buffer.size() < 9) return 0;

    // Frame header: 3 bytes length + 1 byte type + 1 byte flags + 4 bytes stream ID
    quint32 length = (static_cast<quint8>(buffer[0]) << 16) |
                     (static_cast<quint8>(buffer[1]) << 8) |
                      static_cast<quint8>(buffer[2]);

    // Check for connection preface (PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n)
    if (buffer.startsWith("PRI * HTTP/2.0")) {
        int prefaceEnd = buffer.indexOf("\r\n\r\n");
        if (prefaceEnd >= 0) {
            frame.type = Http2FrameType::Unknown;
            frame.payload = buffer.left(prefaceEnd + 4);
            return prefaceEnd + 4;
        }
        return 0;
    }

    // Total frame size
    int totalSize = 9 + length;
    if (buffer.size() < totalSize) return 0; // incomplete

    frame.length = length;
    frame.type = static_cast<Http2FrameType>(static_cast<quint8>(buffer[3]));
    frame.flags = static_cast<quint8>(buffer[4]);
    frame.streamId = (static_cast<quint8>(buffer[5]) & 0x7F) << 24 |
                     (static_cast<quint8>(buffer[6]) & 0xFF) << 16 |
                     (static_cast<quint8>(buffer[7]) & 0xFF) << 8 |
                     (static_cast<quint8>(buffer[8]) & 0xFF);

    frame.payload = buffer.mid(9, length);
    frame.endStream = (frame.flags & 0x01) != 0;
    frame.endHeaders = (frame.flags & 0x04) != 0;

    // Parse specific frame types
    switch (frame.type) {
    case Http2FrameType::Headers:
        frame.headers = parseHeadersPayload(frame.payload);
        break;
    case Http2FrameType::Data:
        frame.data = parseDataPayload(frame.payload);
        break;
    case Http2FrameType::Settings:
        frame.settings = parseSettingsPayload(frame.payload);
        break;
    default:
        break;
    }

    return totalSize;
}

QMap<QByteArray, QByteArray> Http2Parser::parseHeadersPayload(const QByteArray &payload)
{
    QMap<QByteArray, QByteArray> headers;

    // Skip Pad Length (1 byte if PADDED flag) and Priority (5 bytes if PRIORITY flag)
    // For simplicity, we'll try to decode the HPACK block directly
    // In a real implementation, we'd check flags for PADDED and PRIORITY

    int pos = 0;
    // Try to detect if there's a pad length byte (flags & 0x08)
    // We'll skip this for now and try direct HPACK decoding

    while (pos < payload.size()) {
        quint8 first = static_cast<quint8>(payload[pos]);

        if (first & 0x80) {
            // Indexed Header Field
            int index = first & 0x7F;
            if (index > 0 && index < s_hpackStaticTable.size()) {
                headers[s_hpackStaticTable[index].first] = s_hpackStaticTable[index].second;
            }
            pos++;
        } else if ((first & 0xC0) == 0x40) {
            // Literal Header Field with Incremental Indexing - New Name
            pos++;
            // Read name
            if (pos >= payload.size()) break;
            int nameLen = static_cast<quint8>(payload[pos]) & 0x7F;
            pos++;
            if (pos + nameLen > payload.size()) break;
            QByteArray name = payload.mid(pos, nameLen);
            pos += nameLen;
            // Read value
            if (pos >= payload.size()) break;
            int valueLen = static_cast<quint8>(payload[pos]) & 0x7F;
            pos++;
            if (pos + valueLen > payload.size()) break;
            QByteArray value = payload.mid(pos, valueLen);
            pos += valueLen;
            headers[name] = value;
        } else if ((first & 0xF0) == 0x00) {
            // Literal Header Field without Indexing - New Name
            pos++;
            if (pos >= payload.size()) break;
            int nameLen = static_cast<quint8>(payload[pos]) & 0x7F;
            pos++;
            if (pos + nameLen > payload.size()) break;
            QByteArray name = payload.mid(pos, nameLen);
            pos += nameLen;
            if (pos >= payload.size()) break;
            int valueLen = static_cast<quint8>(payload[pos]) & 0x7F;
            pos++;
            if (pos + valueLen > payload.size()) break;
            QByteArray value = payload.mid(pos, valueLen);
            pos += valueLen;
            headers[name] = value;
        } else if ((first & 0xF0) == 0x10) {
            // Literal Header Field without Indexing - Indexed Name
            int index = first & 0x0F;
            pos++;
            if (pos >= payload.size()) break;
            int valueLen = static_cast<quint8>(payload[pos]) & 0x7F;
            pos++;
            if (pos + valueLen > payload.size()) break;
            QByteArray value = payload.mid(pos, valueLen);
            pos += valueLen;
            if (index > 0 && index < s_hpackStaticTable.size()) {
                headers[s_hpackStaticTable[index].first] = value;
            }
        } else {
            // Unknown encoding, skip
            pos++;
        }
    }

    return headers;
}

QMap<quint16, quint32> Http2Parser::parseSettingsPayload(const QByteArray &payload)
{
    QMap<quint16, quint32> settings;

    // Each setting is 6 bytes: 2 bytes ID + 4 bytes value
    for (int i = 0; i + 6 <= payload.size(); i += 6) {
        quint16 id = (static_cast<quint8>(payload[i]) << 8) |
                      static_cast<quint8>(payload[i + 1]);
        quint32 value = (static_cast<quint8>(payload[i + 2]) << 24) |
                        (static_cast<quint8>(payload[i + 3]) << 16) |
                        (static_cast<quint8>(payload[i + 4]) << 8) |
                         static_cast<quint8>(payload[i + 5]);
        settings[id] = value;
    }

    return settings;
}

QByteArray Http2Parser::parseDataPayload(const QByteArray &payload)
{
    // DATA frame payload may have pad length prefix
    // For simplicity, return raw payload
    return payload;
}

Http2Stream *Http2Parser::getStream(quint32 streamId)
{
    if (!m_streams.contains(streamId)) {
        Http2Stream stream;
        stream.streamId = streamId;
        m_streams[streamId] = stream;
    }
    return &m_streams[streamId];
}
