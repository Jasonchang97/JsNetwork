#include "mock_engine.h"
#include <QFile>
#include <QRegularExpression>
#include <QUrl>

MockEngine::MockEngine(QObject *parent)
    : QObject(parent)
{
}

int MockEngine::addRule(const MockRule &rule)
{
    MockRule r = rule;
    r.id = m_nextId++;
    m_rules.append(r);
    return r.id;
}

void MockEngine::removeRule(int ruleId)
{
    for (int i = 0; i < m_rules.size(); ++i) {
        if (m_rules[i].id == ruleId) {
            m_rules.removeAt(i);
            return;
        }
    }
}

void MockEngine::updateRule(const MockRule &rule)
{
    for (int i = 0; i < m_rules.size(); ++i) {
        if (m_rules[i].id == rule.id) {
            m_rules[i] = rule;
            return;
        }
    }
}

void MockEngine::toggleRule(int ruleId, bool enabled)
{
    for (auto &r : m_rules) {
        if (r.id == ruleId) {
            r.enabled = enabled;
            return;
        }
    }
}

QList<MockRule> MockEngine::rules() const
{
    return m_rules;
}

MockRule *MockEngine::findRule(int ruleId)
{
    for (auto &r : m_rules) {
        if (r.id == ruleId) return &r;
    }
    return nullptr;
}

void MockEngine::clearRules()
{
    m_rules.clear();
}

bool MockEngine::matchRequest(const QString &url, const QString &method,
                               MockRule &matchedRule) const
{
    Q_UNUSED(method);

    for (const auto &rule : m_rules) {
        if (!rule.enabled) continue;
        if (rule.action == MockAction::NoOp) continue;

        if (matchPattern(url, rule)) {
            matchedRule = rule;
            return true;
        }
    }
    return false;
}

bool MockEngine::matchPattern(const QString &url, const MockRule &rule) const
{
    switch (rule.matchType) {
    case MatchType::Exact:
        return url == rule.pattern;

    case MatchType::Contains:
        return url.contains(rule.pattern, Qt::CaseInsensitive);

    case MatchType::Wildcard: {
        QRegularExpression re(QRegularExpression::wildcardToRegularExpression(rule.pattern));
        return re.match(url).hasMatch();
    }

    case MatchType::Regex: {
        QRegularExpression re(rule.pattern, QRegularExpression::CaseInsensitiveOption);
        return re.match(url).hasMatch();
    }
    }

    return false;
}

bool MockEngine::applyRule(const MockRule &rule, QByteArray &responseBody,
                            QMap<QString, QString> &responseHeaders,
                            int &statusCode, QString &statusText) const
{
    switch (rule.action) {
    case MockAction::MapLocal: {
        QByteArray data = loadLocalFile(rule.localFilePath);
        if (data.isEmpty()) return false;

        responseBody = data;
        statusCode = 200;
        statusText = "OK";
        responseHeaders["Content-Type"] = rule.contentType;
        responseHeaders["Content-Length"] = QString::number(data.size());
        responseHeaders["X-JsNetwork-Mock"] = "MapLocal";
        break;
    }

    case MockAction::AutoResponder: {
        responseBody = rule.responseBody;
        statusCode = rule.statusCode;
        statusText = rule.statusText;
        responseHeaders = rule.responseHeaders;
        if (!responseHeaders.contains("Content-Type")) {
            responseHeaders["Content-Type"] = rule.contentType;
        }
        responseHeaders["Content-Length"] = QString::number(responseBody.size());
        responseHeaders["X-JsNetwork-Mock"] = "AutoResponder";
        break;
    }

    case MockAction::NoOp:
        return false;
    }

    return true;
}

QByteArray MockEngine::loadLocalFile(const QString &path) const
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) return QByteArray();
    return file.readAll();
}
