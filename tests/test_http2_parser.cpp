#include <gtest/gtest.h>
#include "core/http2_parser.h"

class Http2ParserTest : public ::testing::Test {
protected:
    Http2Parser parser;
};

TEST_F(Http2ParserTest, ParseSettingsFrame)
{
    // SETTINGS frame: length=12, type=0x04, flags=0x00, stream=0
    // 2 settings: SETTINGS_MAX_CONCURRENT_STREAMS(3)=100, SETTINGS_INITIAL_WINDOW_SIZE(4)=65535
    QByteArray frame;
    frame.append('\x00'); frame.append('\x00'); frame.append('\x0C'); // length = 12
    frame.append('\x04'); // type = SETTINGS
    frame.append('\x00'); // flags
    frame.append('\x00'); frame.append('\x00'); frame.append('\x00'); frame.append('\x00'); // stream 0

    // Setting 1: MAX_CONCURRENT_STREAMS = 100
    frame.append('\x00'); frame.append('\x03'); // id = 3
    frame.append('\x00'); frame.append('\x00'); frame.append('\x00'); frame.append('\x64'); // value = 100

    // Setting 2: INITIAL_WINDOW_SIZE = 65535
    frame.append('\x00'); frame.append('\x04'); // id = 4
    frame.append('\x00'); frame.append('\x00'); frame.append('\xFF'); frame.append('\xFF'); // value = 65535

    auto frames = parser.feed(frame);

    ASSERT_GE(frames.size(), 1);
    EXPECT_EQ(frames[0].type, Http2FrameType::Settings);
    EXPECT_EQ(frames[0].streamId, 0u);
    EXPECT_EQ(frames[0].settings[3], 100u);
    EXPECT_EQ(frames[0].settings[4], 65535u);
}

TEST_F(Http2ParserTest, ParseDataFrame)
{
    // DATA frame: length=5, type=0x00, flags=0x01 (END_STREAM), stream=1
    QByteArray frame;
    frame.append('\x00'); frame.append('\x00'); frame.append('\x05'); // length = 5
    frame.append('\x00'); // type = DATA
    frame.append('\x01'); // flags = END_STREAM
    frame.append('\x00'); frame.append('\x00'); frame.append('\x00'); frame.append('\x01'); // stream 1
    frame.append("Hello"); // data

    auto frames = parser.feed(frame);

    ASSERT_GE(frames.size(), 1);
    EXPECT_EQ(frames[0].type, Http2FrameType::Data);
    EXPECT_EQ(frames[0].streamId, 1u);
    EXPECT_TRUE(frames[0].endStream);
    EXPECT_EQ(frames[0].data, "Hello");
}

TEST_F(Http2ParserTest, ParsePingFrame)
{
    // PING frame: length=8, type=0x06, flags=0x00, stream=0
    QByteArray frame;
    frame.append('\x00'); frame.append('\x00'); frame.append('\x08'); // length = 8
    frame.append('\x06'); // type = PING
    frame.append('\x00'); // flags
    frame.append('\x00'); frame.append('\x00'); frame.append('\x00'); frame.append('\x00'); // stream 0
    frame.append("\x01\x02\x03\x04\x05\x06\x07\x08"); // opaque data

    auto frames = parser.feed(frame);

    ASSERT_GE(frames.size(), 1);
    EXPECT_EQ(frames[0].type, Http2FrameType::Ping);
    EXPECT_EQ(frames[0].payload, QByteArray("\x01\x02\x03\x04\x05\x06\x07\x08", 8));
}

TEST_F(Http2ParserTest, IncompleteFrame)
{
    // Only 5 bytes of a frame header (need 9)
    QByteArray data("\x00\x00\x0C\x04\x00", 5);
    auto frames = parser.feed(data);
    EXPECT_EQ(frames.size(), 0);
}

TEST_F(Http2ParserTest, FrameTypeName)
{
    Http2Frame frame;
    frame.type = Http2FrameType::Headers;
    EXPECT_EQ(frame.typeName(), "HEADERS");

    frame.type = Http2FrameType::Data;
    EXPECT_EQ(frame.typeName(), "DATA");

    frame.type = Http2FrameType::WindowUpdate;
    EXPECT_EQ(frame.typeName(), "WINDOW_UPDATE");
}

TEST_F(Http2ParserTest, ParseMultipleFrames)
{
    QByteArray data;

    // Frame 1: SETTINGS
    data.append('\x00'); data.append('\x00'); data.append('\x06');
    data.append('\x04'); data.append('\x00');
    data.append('\x00'); data.append('\x00'); data.append('\x00'); data.append('\x00');
    data.append('\x00'); data.append('\x03'); // MAX_CONCURRENT_STREAMS
    data.append('\x00'); data.append('\x00'); data.append('\x00'); data.append('\x0A'); // = 10

    // Frame 2: PING
    data.append('\x00'); data.append('\x00'); data.append('\x08');
    data.append('\x06'); data.append('\x00');
    data.append('\x00'); data.append('\x00'); data.append('\x00'); data.append('\x00');
    data.append("12345678");

    auto frames = parser.feed(data);

    ASSERT_EQ(frames.size(), 2);
    EXPECT_EQ(frames[0].type, Http2FrameType::Settings);
    EXPECT_EQ(frames[1].type, Http2FrameType::Ping);
}
