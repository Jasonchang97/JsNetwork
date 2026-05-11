#pragma once

#include <QObject>
#include <QList>
#include <QString>
#include <QByteArray>
#include <QMap>

enum class MockAction {
    MapLocal,       // Redirect to local file
    AutoResponder,  // Return preset response
    NoOp            // Disabled rule
};

enum class MatchType {
    Exact,          // Exact URL match
    Contains,       // URL contains pattern
    Wildcard,       // Wildcard match (* and ?)
    Regex           // Regular expression
};

struct MockRule {
    int id = 0;
    QString name;
    bool enabled = true;
    MatchType matchType = MatchType::Contains;
    QString pattern;           // URL pattern to match
    MockAction action = MockAction::AutoResponder;

    // For MapLocal
    QString localFilePath;

    // For AutoResponder
    int statusCode = 200;
    QString statusText = "OK";
    QMap<QString, QString> responseHeaders;
    QByteArray responseBody;
    QString contentType = "application/json";
    int delayMs = 0;           // Artificial delay
};

class MockEngine : public QObject
{
    Q_OBJECT
public:
    explicit MockEngine(QObject *parent = nullptr);

    // Rule management
    int addRule(const MockRule &rule);
    void removeRule(int ruleId);
    void updateRule(const MockRule &rule);
    void toggleRule(int ruleId, bool enabled);
    QList<MockRule> rules() const;
    MockRule *findRule(int ruleId);
    void clearRules();

    // Check if a request matches any rule and get the mock response
    bool matchRequest(const QString &url, const QString &method,
                      MockRule &matchedRule) const;

    // Apply the matched rule to generate a response
    bool applyRule(const MockRule &rule, QByteArray &responseBody,
                   QMap<QString, QString> &responseHeaders,
                   int &statusCode, QString &statusText) const;

private:
    bool matchPattern(const QString &url, const MockRule &rule) const;
    QByteArray loadLocalFile(const QString &path) const;

    QList<MockRule> m_rules;
    int m_nextId = 1;
};
