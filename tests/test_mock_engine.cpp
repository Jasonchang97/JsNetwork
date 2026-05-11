#include <gtest/gtest.h>
#include "core/mock_engine.h"

class MockEngineTest : public ::testing::Test {
protected:
    MockEngine engine;
};

TEST_F(MockEngineTest, AddAndRetrieveRule)
{
    MockRule rule;
    rule.name = "Test Rule";
    rule.pattern = "api.example.com";
    rule.action = MockAction::AutoResponder;

    int id = engine.addRule(rule);
    EXPECT_GT(id, 0);

    auto rules = engine.rules();
    ASSERT_EQ(rules.size(), 1);
    EXPECT_EQ(rules[0].name, "Test Rule");
    EXPECT_EQ(rules[0].pattern, "api.example.com");
}

TEST_F(MockEngineTest, RemoveRule)
{
    MockRule rule;
    rule.pattern = "test";
    int id = engine.addRule(rule);

    EXPECT_EQ(engine.rules().size(), 1);

    engine.removeRule(id);
    EXPECT_EQ(engine.rules().size(), 0);
}

TEST_F(MockEngineTest, ToggleRule)
{
    MockRule rule;
    rule.pattern = "test";
    rule.enabled = true;
    int id = engine.addRule(rule);

    engine.toggleRule(id, false);
    EXPECT_FALSE(engine.rules()[0].enabled);

    engine.toggleRule(id, true);
    EXPECT_TRUE(engine.rules()[0].enabled);
}

TEST_F(MockEngineTest, MatchContains)
{
    MockRule rule;
    rule.pattern = "api.example.com";
    rule.matchType = MatchType::Contains;
    rule.action = MockAction::AutoResponder;
    engine.addRule(rule);

    MockRule matched;
    EXPECT_TRUE(engine.matchRequest("https://api.example.com/users", "GET", matched));
    EXPECT_FALSE(engine.matchRequest("https://other.com/path", "GET", matched));
}

TEST_F(MockEngineTest, MatchExact)
{
    MockRule rule;
    rule.pattern = "https://api.example.com/v1";
    rule.matchType = MatchType::Exact;
    rule.action = MockAction::AutoResponder;
    engine.addRule(rule);

    MockRule matched;
    EXPECT_TRUE(engine.matchRequest("https://api.example.com/v1", "GET", matched));
    EXPECT_FALSE(engine.matchRequest("https://api.example.com/v1/extra", "GET", matched));
}

TEST_F(MockEngineTest, MatchWildcard)
{
    // Wildcard uses QRegularExpression::wildcardToRegularExpression (fully anchored).
    MockRule rule;
    rule.pattern = "*.json";
    rule.matchType = MatchType::Wildcard;
    rule.action = MockAction::AutoResponder;
    engine.addRule(rule);

    MockRule matched;
    EXPECT_TRUE(engine.matchRequest("data.json", "GET", matched));
    EXPECT_FALSE(engine.matchRequest("data.xml", "GET", matched));
}

TEST_F(MockEngineTest, MatchRegex)
{
    MockRule rule;
    rule.pattern = R"(api\d+\.example\.com)";
    rule.matchType = MatchType::Regex;
    rule.action = MockAction::AutoResponder;
    engine.addRule(rule);

    MockRule matched;
    EXPECT_TRUE(engine.matchRequest("https://api123.example.com/v1", "GET", matched));
    EXPECT_FALSE(engine.matchRequest("https://apiabc.example.com/v1", "GET", matched));
}

TEST_F(MockEngineTest, DisabledRuleNotMatched)
{
    MockRule rule;
    rule.pattern = "example.com";
    rule.matchType = MatchType::Contains;
    rule.enabled = false;
    rule.action = MockAction::AutoResponder;
    engine.addRule(rule);

    MockRule matched;
    EXPECT_FALSE(engine.matchRequest("https://example.com/path", "GET", matched));
}

TEST_F(MockEngineTest, ApplyAutoResponderRule)
{
    MockRule rule;
    rule.action = MockAction::AutoResponder;
    rule.statusCode = 201;
    rule.statusText = "Created";
    rule.contentType = "application/json";
    rule.responseBody = "{\"id\": 1}";
    rule.responseHeaders["X-Custom"] = "test";

    QByteArray body;
    QMap<QString, QString> headers;
    int statusCode;
    QString statusText;

    bool ok = engine.applyRule(rule, body, headers, statusCode, statusText);

    ASSERT_TRUE(ok);
    EXPECT_EQ(statusCode, 201);
    EXPECT_EQ(statusText, "Created");
    EXPECT_EQ(body, "{\"id\": 1}");
    EXPECT_EQ(headers["Content-Type"], "application/json");
    EXPECT_EQ(headers["X-Custom"], "test");
    EXPECT_EQ(headers["X-JsNetwork-Mock"], "AutoResponder");
}

TEST_F(MockEngineTest, UpdateRule)
{
    MockRule rule;
    rule.pattern = "old.com";
    int id = engine.addRule(rule);

    MockRule updated;
    updated.id = id;
    updated.pattern = "new.com";
    engine.updateRule(updated);

    EXPECT_EQ(engine.rules()[0].pattern, "new.com");
}

TEST_F(MockEngineTest, ClearRules)
{
    engine.addRule(MockRule{});
    engine.addRule(MockRule{});
    engine.addRule(MockRule{});

    EXPECT_EQ(engine.rules().size(), 3);

    engine.clearRules();
    EXPECT_EQ(engine.rules().size(), 0);
}

TEST_F(MockEngineTest, MultipleRulesFirstMatch)
{
    MockRule rule1;
    rule1.pattern = "api.example.com";
    rule1.matchType = MatchType::Contains;
    rule1.action = MockAction::AutoResponder;
    rule1.statusCode = 200;
    engine.addRule(rule1);

    MockRule rule2;
    rule2.pattern = "api.example.com";
    rule2.matchType = MatchType::Contains;
    rule2.action = MockAction::AutoResponder;
    rule2.statusCode = 201;
    engine.addRule(rule2);

    MockRule matched;
    ASSERT_TRUE(engine.matchRequest("https://api.example.com/test", "GET", matched));
    // First matching rule wins
    EXPECT_EQ(matched.statusCode, 200);
}
