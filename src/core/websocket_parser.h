#pragma once

#include <QObject>
#include <QByteArray>
#include <QVector>

enum class WebSocketOpcode : quint8 {
    Continuation = 0x0,
    Text         = 0x1,
    Binary       = 0x2,
    Close        = 0x8,
    Ping         = 0x9,
    Pong         = 0xA,
    Unknown      = 0xFF
};

struct WebSocketFrame {
    bool fin = true;
    bool masked = false;
    WebSocketOpcode opcode = WebSocketOpcode::Unknown;
    quint64 payloadLength = 0;
    QByteArray maskKey;    // 4 bytes if masked
    QByteArray payload;    // decoded payload (unmasked)

    QString opcodeName() const {
        switch (opcode) {
        case WebSocketOpcode::Continuation: return "Continuation";
        case WebSocketOpcode::Text:         return "Text";
        case WebSocketOpcode::Binary:       return "Binary";
        case WebSocketOpcode::Close:        return "Close";
        case WebSocketOpcode::Ping:         return "Ping";
        case WebSocketOpcode::Pong:         return "Pong";
        default:                            return "Unknown";
        }
    }

    bool isText() const { return opcode == WebSocketOpcode::Text; }
    bool isControl() const { return static_cast<quint8>(opcode) >= 0x8; }
};

struct WebSocketMessage {
    enum Direction { ClientToServer, ServerToClient };
    Direction direction;
    WebSocketOpcode opcode;
    QByteArray payload;
    QString text() const { return QString::fromUtf8(payload); }
};

class WebSocketParser : public QObject
{
    Q_OBJECT
public:
    explicit WebSocketParser(QObject *parent = nullptr);

    // Detect WebSocket upgrade handshake in HTTP request/response
    static bool isWebSocketUpgrade(const QMap<QString, QString> &requestHeaders,
                                    const QMap<QString, QString> &responseHeaders);

    // Feed raw bytes from client (to server)
    QVector<WebSocketFrame> feedClient(const QByteArray &data);

    // Feed raw bytes from server (to client)
    QVector<WebSocketFrame> feedServer(const QByteArray &data);

    // Parse a single frame from buffer
    static int parseFrame(const QByteArray &buffer, WebSocketFrame &frame);

    // Get accumulated messages
    QVector<WebSocketMessage> takeMessages();

private:
    static QByteArray unmask(const QByteArray &data, const QByteArray &maskKey);

    QByteArray m_clientBuffer;
    QByteArray m_serverBuffer;
    QVector<WebSocketMessage> m_messages;

    // Message assembly (for fragmented messages)
    QByteArray m_currentMessage;
    WebSocketOpcode m_currentOpcode = WebSocketOpcode::Text;
};
