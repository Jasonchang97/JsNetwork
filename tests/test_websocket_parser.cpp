#include <gtest/gtest.h>
#include "core/websocket_parser.h"

class WebSocketParserTest : public ::testing::Test {
protected:
    WebSocketParser parser;
};

TEST_F(WebSocketParserTest, ParseUnmaskedTextFrame)
{
    // FIN=1, opcode=Text(0x1), mask=0, length=5, payload="Hello"
    QByteArray frame;
    frame.append('\x81'); // FIN + Text
    frame.append('\x05'); // length=5, no mask
    frame.append("Hello");

    WebSocketFrame wsFrame;
    int consumed = WebSocketParser::parseFrame(frame, wsFrame);

    EXPECT_EQ(consumed, 7);
    EXPECT_TRUE(wsFrame.fin);
    EXPECT_EQ(wsFrame.opcode, WebSocketOpcode::Text);
    EXPECT_FALSE(wsFrame.masked);
    EXPECT_EQ(wsFrame.payload, "Hello");
}

TEST_F(WebSocketParserTest, ParseMaskedTextFrame)
{
    // FIN=1, opcode=Text(0x1), mask=1, length=5, mask-key, payload (masked)
    QByteArray frame;
    frame.append('\x81'); // FIN + Text
    frame.append('\x85'); // mask=1, length=5
    frame.append("\x12\x34\x56\x78"); // mask key

    // Mask "Hello" with key 0x12345678
    QByteArray masked("Hello");
    for (int i = 0; i < masked.size(); ++i) {
        masked[i] = masked[i] ^ "\x12\x34\x56\x78"[i % 4];
    }
    frame.append(masked);

    WebSocketFrame wsFrame;
    int consumed = WebSocketParser::parseFrame(frame, wsFrame);

    EXPECT_EQ(consumed, 11);
    EXPECT_TRUE(wsFrame.masked);
    EXPECT_EQ(wsFrame.maskKey, QByteArray("\x12\x34\x56\x78", 4));

    // Manually unmask
    QByteArray payload = wsFrame.payload;
    for (int i = 0; i < payload.size(); ++i) {
        payload[i] = payload[i] ^ "\x12\x34\x56\x78"[i % 4];
    }
    EXPECT_EQ(payload, "Hello");
}

TEST_F(WebSocketParserTest, ParseCloseFrame)
{
    QByteArray frame;
    frame.append('\x88'); // FIN + Close
    frame.append('\x02'); // length=2
    frame.append('\x03'); frame.append('\xE8'); // status code 1000

    WebSocketFrame wsFrame;
    int consumed = WebSocketParser::parseFrame(frame, wsFrame);

    EXPECT_EQ(consumed, 4);
    EXPECT_EQ(wsFrame.opcode, WebSocketOpcode::Close);
    EXPECT_TRUE(wsFrame.isControl());
}

TEST_F(WebSocketParserTest, ParsePingFrame)
{
    QByteArray frame;
    frame.append('\x89'); // FIN + Ping
    frame.append('\x04'); // length=4
    frame.append("ping");

    WebSocketFrame wsFrame;
    int consumed = WebSocketParser::parseFrame(frame, wsFrame);

    EXPECT_EQ(consumed, 6);
    EXPECT_EQ(wsFrame.opcode, WebSocketOpcode::Ping);
    EXPECT_EQ(wsFrame.payload, "ping");
}

TEST_F(WebSocketParserTest, ParsePongFrame)
{
    QByteArray frame;
    frame.append('\x8A'); // FIN + Pong
    frame.append('\x04');
    frame.append("pong");

    WebSocketFrame wsFrame;
    int consumed = WebSocketParser::parseFrame(frame, wsFrame);

    EXPECT_EQ(consumed, 6);
    EXPECT_EQ(wsFrame.opcode, WebSocketOpcode::Pong);
}

TEST_F(WebSocketParserTest, Parse16BitLength)
{
    // Payload > 125 bytes
    QByteArray payload(300, 'A');
    QByteArray frame;
    frame.append('\x81'); // FIN + Text
    frame.append('\x7E'); // 16-bit length
    frame.append('\x01'); frame.append('\x2C'); // 300 in big-endian
    frame.append(payload);

    WebSocketFrame wsFrame;
    int consumed = WebSocketParser::parseFrame(frame, wsFrame);

    EXPECT_EQ(consumed, 4 + 300);
    EXPECT_EQ(wsFrame.payloadLength, 300u);
    EXPECT_EQ(wsFrame.payload.size(), 300);
}

TEST_F(WebSocketParserTest, IncompleteFrame)
{
    // Only header, no payload
    QByteArray frame("\x81\x05", 2);

    WebSocketFrame wsFrame;
    int consumed = WebSocketParser::parseFrame(frame, wsFrame);

    EXPECT_EQ(consumed, 0); // incomplete
}

TEST_F(WebSocketParserTest, OpcodeName)
{
    WebSocketFrame f;
    f.opcode = WebSocketOpcode::Text;
    EXPECT_EQ(f.opcodeName(), "Text");

    f.opcode = WebSocketOpcode::Binary;
    EXPECT_EQ(f.opcodeName(), "Binary");

    f.opcode = WebSocketOpcode::Close;
    EXPECT_EQ(f.opcodeName(), "Close");

    f.opcode = WebSocketOpcode::Ping;
    EXPECT_EQ(f.opcodeName(), "Ping");
}

TEST_F(WebSocketParserTest, FeedAndAssembleMessages)
{
    // Send an unmasked text frame through feedServer
    QByteArray frame;
    frame.append('\x81'); // FIN + Text
    frame.append('\x0B'); // length=11
    frame.append("Hello World");

    parser.feedServer(frame);

    auto messages = parser.takeMessages();
    ASSERT_EQ(messages.size(), 1);
    EXPECT_EQ(messages[0].direction, WebSocketMessage::ServerToClient);
    EXPECT_EQ(messages[0].text(), "Hello World");
    EXPECT_EQ(messages[0].opcode, WebSocketOpcode::Text);
}
