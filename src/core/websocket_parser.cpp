#include "websocket_parser.h"
#include <QMap>

WebSocketParser::WebSocketParser(QObject *parent)
    : QObject(parent)
{
}

bool WebSocketParser::isWebSocketUpgrade(const QMap<QString, QString> &requestHeaders,
                                          const QMap<QString, QString> &responseHeaders)
{
    // Check request: Connection: Upgrade, Upgrade: websocket
    QString reqConnection = requestHeaders.value("Connection", "").toLower();
    QString reqUpgrade = requestHeaders.value("Upgrade", "").toLower();

    // Check response: 101 Switching Protocols
    // Status is not in headers, but we can check response headers
    QString respConnection = responseHeaders.value("Connection", "").toLower();
    QString respUpgrade = responseHeaders.value("Upgrade", "").toLower();

    bool reqOk = reqConnection.contains("upgrade") && reqUpgrade == "websocket";
    bool respOk = respConnection.contains("upgrade") && respUpgrade == "websocket";

    return reqOk && respOk;
}

QVector<WebSocketFrame> WebSocketParser::feedClient(const QByteArray &data)
{
    m_clientBuffer.append(data);
    QVector<WebSocketFrame> frames;

    while (!m_clientBuffer.isEmpty()) {
        WebSocketFrame frame;
        int consumed = parseFrame(m_clientBuffer, frame);
        if (consumed <= 0) break;

        m_clientBuffer = m_clientBuffer.mid(consumed);

        // Unmask payload
        if (frame.masked && !frame.maskKey.isEmpty()) {
            frame.payload = unmask(frame.payload, frame.maskKey);
        }

        frames.append(frame);

        // Assemble messages
        if (frame.fin) {
            WebSocketMessage msg;
            msg.direction = WebSocketMessage::ClientToServer;
            msg.opcode = (frame.opcode == WebSocketOpcode::Continuation)
                         ? m_currentOpcode : frame.opcode;
            msg.payload = m_currentMessage + frame.payload;
            m_messages.append(msg);
            m_currentMessage.clear();
        } else {
            if (frame.opcode != WebSocketOpcode::Continuation) {
                m_currentOpcode = frame.opcode;
                m_currentMessage = frame.payload;
            } else {
                m_currentMessage.append(frame.payload);
            }
        }
    }

    return frames;
}

QVector<WebSocketFrame> WebSocketParser::feedServer(const QByteArray &data)
{
    m_serverBuffer.append(data);
    QVector<WebSocketFrame> frames;

    while (!m_serverBuffer.isEmpty()) {
        WebSocketFrame frame;
        int consumed = parseFrame(m_serverBuffer, frame);
        if (consumed <= 0) break;

        m_serverBuffer = m_serverBuffer.mid(consumed);
        // Server frames are typically not masked
        frames.append(frame);

        // Assemble messages
        if (frame.fin) {
            WebSocketMessage msg;
            msg.direction = WebSocketMessage::ServerToClient;
            msg.opcode = (frame.opcode == WebSocketOpcode::Continuation)
                         ? m_currentOpcode : frame.opcode;
            msg.payload = m_currentMessage + frame.payload;
            m_messages.append(msg);
            m_currentMessage.clear();
        } else {
            if (frame.opcode != WebSocketOpcode::Continuation) {
                m_currentOpcode = frame.opcode;
                m_currentMessage = frame.payload;
            } else {
                m_currentMessage.append(frame.payload);
            }
        }
    }

    return frames;
}

int WebSocketParser::parseFrame(const QByteArray &buffer, WebSocketFrame &frame)
{
    if (buffer.size() < 2) return 0;

    quint8 first = static_cast<quint8>(buffer[0]);
    quint8 second = static_cast<quint8>(buffer[1]);

    frame.fin = (first & 0x80) != 0;
    frame.masked = (second & 0x80) != 0;
    frame.opcode = static_cast<WebSocketOpcode>(first & 0x0F);

    quint64 payloadLen = second & 0x7F;
    int offset = 2;

    if (payloadLen == 126) {
        if (buffer.size() < 4) return 0;
        payloadLen = (static_cast<quint8>(buffer[2]) << 8) |
                      static_cast<quint8>(buffer[3]);
        offset = 4;
    } else if (payloadLen == 127) {
        if (buffer.size() < 10) return 0;
        payloadLen = 0;
        for (int i = 0; i < 8; ++i) {
            payloadLen = (payloadLen << 8) | static_cast<quint8>(buffer[2 + i]);
        }
        offset = 10;
    }

    frame.payloadLength = payloadLen;

    if (frame.masked) {
        if (buffer.size() < offset + 4) return 0;
        frame.maskKey = buffer.mid(offset, 4);
        offset += 4;
    }

    int totalSize = offset + payloadLen;
    if (buffer.size() < totalSize) return 0;

    frame.payload = buffer.mid(offset, payloadLen);
    return totalSize;
}

QByteArray WebSocketParser::unmask(const QByteArray &data, const QByteArray &maskKey)
{
    if (maskKey.size() != 4) return data;

    QByteArray result = data;
    for (int i = 0; i < result.size(); ++i) {
        result[i] = result[i] ^ maskKey[i % 4];
    }
    return result;
}

QVector<WebSocketMessage> WebSocketParser::takeMessages()
{
    QVector<WebSocketMessage> msgs = m_messages;
    m_messages.clear();
    return msgs;
}
