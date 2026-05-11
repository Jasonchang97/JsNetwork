#include <gtest/gtest.h>
#include "core/http_parser.h"
#include "model/request_item.h"

class HttpParserTest : public ::testing::Test {};

TEST_F(HttpParserTest, ParseSimpleGetRequest)
{
    QByteArray data = "GET /api/users HTTP/1.1\r\n"
                      "Host: example.com\r\n"
                      "Accept: application/json\r\n"
                      "\r\n";

    RequestItem item;
    bool ok = HttpParser::parseRequest(data, item);

    ASSERT_TRUE(ok);
    EXPECT_EQ(item.method, "GET");
    EXPECT_EQ(item.path, "/api/users");
    EXPECT_EQ(item.host, "example.com");
    EXPECT_EQ(item.protocol, "HTTP/1.1");
    EXPECT_EQ(item.requestHeaders["Host"], "example.com");
    EXPECT_EQ(item.requestHeaders["Accept"], "application/json");
}

TEST_F(HttpParserTest, ParsePostRequestWithBody)
{
    QByteArray data = "POST /api/login HTTP/1.1\r\n"
                      "Host: example.com\r\n"
                      "Content-Type: application/json\r\n"
                      "Content-Length: 27\r\n"
                      "\r\n"
                      "{\"user\":\"test\",\"pass\":\"123\"}";

    RequestItem item;
    bool ok = HttpParser::parseRequest(data, item);

    ASSERT_TRUE(ok);
    EXPECT_EQ(item.method, "POST");
    EXPECT_EQ(item.path, "/api/login");
    EXPECT_EQ(item.requestBody, "{\"user\":\"test\",\"pass\":\"123\"}");
}

TEST_F(HttpParserTest, Parse200Response)
{
    QByteArray data = "HTTP/1.1 200 OK\r\n"
                      "Content-Type: application/json\r\n"
                      "Content-Length: 13\r\n"
                      "\r\n"
                      "{\"ok\": true}";

    RequestItem item;
    bool ok = HttpParser::parseResponse(data, item);

    ASSERT_TRUE(ok);
    EXPECT_EQ(item.statusCode, 200);
    EXPECT_EQ(item.statusText, "OK");
    EXPECT_EQ(item.protocol, "HTTP/1.1");
    EXPECT_EQ(item.responseHeaders["Content-Type"], "application/json");
    EXPECT_EQ(item.responseBody, "{\"ok\": true}");
}

TEST_F(HttpParserTest, Parse404Response)
{
    QByteArray data = "HTTP/1.1 404 Not Found\r\n"
                      "Content-Length: 0\r\n"
                      "\r\n";

    RequestItem item;
    bool ok = HttpParser::parseResponse(data, item);

    ASSERT_TRUE(ok);
    EXPECT_EQ(item.statusCode, 404);
    EXPECT_EQ(item.statusText, "Not Found");
}

TEST_F(HttpParserTest, ParseIncompleteRequest)
{
    QByteArray data = "GET /api HTTP/1.1\r\n";

    RequestItem item;
    bool ok = HttpParser::parseRequest(data, item);

    EXPECT_FALSE(ok);
}

TEST_F(HttpParserTest, ParseMalformedRequest)
{
    QByteArray data = "INVALID\r\n\r\n";

    RequestItem item;
    bool ok = HttpParser::parseRequest(data, item);

    EXPECT_FALSE(ok);
}

TEST_F(HttpParserTest, MultipleHeaders)
{
    QByteArray data = "GET / HTTP/1.1\r\n"
                      "Host: example.com\r\n"
                      "User-Agent: JsNetwork/1.0\r\n"
                      "Accept: text/html\r\n"
                      "Accept-Language: en-US\r\n"
                      "Connection: keep-alive\r\n"
                      "\r\n";

    RequestItem item;
    bool ok = HttpParser::parseRequest(data, item);

    ASSERT_TRUE(ok);
    EXPECT_EQ(item.requestHeaders.size(), 5);
    EXPECT_EQ(item.requestHeaders["User-Agent"], "JsNetwork/1.0");
    EXPECT_EQ(item.requestHeaders["Connection"], "keep-alive");
}
