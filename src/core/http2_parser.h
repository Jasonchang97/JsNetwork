#pragma once

#include <QObject>
#include <QByteArray>
#include <QMap>
#include <QVector>

// HTTP/2 frame types (RFC 7540)
enum class Http2FrameType : quint8 {
    Data          = 0x00,
    Headers       = 0x01,
    Priority      = 0x02,
    RstStream     = 0x03,
    Settings      = 0x04,
    PushPromise   = 0x05,
    Ping          = 0x06,
    GoAway        = 0x07,
    WindowUpdate  = 0x08,
    Continuation  = 0x09,
    Unknown       = 0xFF
};

struct Http2Frame {
    quint32 length = 0;
    Http2FrameType type = Http2FrameType::Unknown;
    quint8 flags = 0;
    quint32 streamId = 0;
    QByteArray payload;

    // Parsed fields (for HEADERS)
    QMap<QByteArray, QByteArray> headers;
    bool endStream = false;
    bool endHeaders = false;

    // Parsed fields (for DATA)
    QByteArray data;

    // Parsed fields (for SETTINGS)
    QMap<quint16, quint32> settings;

    QString typeName() const;
};

struct Http2Stream {
    quint32 streamId = 0;
    QMap<QByteArray, QByteArray> requestHeaders;
    QMap<QByteArray, QByteArray> responseHeaders;
    QByteArray requestData;
    QByteArray responseData;
    bool requestComplete = false;
    bool responseComplete = false;
};

class Http2Parser : public QObject
{
    Q_OBJECT
public:
    explicit Http2Parser(QObject *parent = nullptr);

    // Feed raw bytes, returns parsed frames
    QVector<Http2Frame> feed(const QByteArray &data);

    // Parse a single frame from buffer (returns bytes consumed, 0 if incomplete)
    int parseFrame(const QByteArray &buffer, Http2Frame &frame);

    // Parse HEADERS frame payload (with HPACK-like basic decoding)
    static QMap<QByteArray, QByteArray> parseHeadersPayload(const QByteArray &payload);

    // Parse SETTINGS frame payload
    static QMap<quint16, quint32> parseSettingsPayload(const QByteArray &payload);

    // Parse DATA frame payload
    static QByteArray parseDataPayload(const QByteArray &payload);

    // Track streams
    Http2Stream *getStream(quint32 streamId);

private:
    QByteArray m_buffer;
    QMap<quint32, Http2Stream> m_streams;

    // HPACK static table (subset of common headers)
    static const QVector<QPair<QByteArray, QByteArray>> s_hpackStaticTable;
};
