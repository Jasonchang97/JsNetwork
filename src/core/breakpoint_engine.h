#pragma once

#include <QObject>
#include <QList>
#include <QMap>
#include <QByteArray>
#include <QMutex>
#include <QWaitCondition>

enum class BreakpointType {
    Request,    // Pause before sending request to server
    Response    // Pause before sending response to client
};

struct BreakpointRule {
    int id = 0;
    QString name;
    bool enabled = true;
    BreakpointType type = BreakpointType::Request;
    QString urlPattern;        // URL pattern to match (contains)
    bool matchAll = false;     // Match all requests
};

struct BreakpointHit {
    int ruleId;
    int requestId;
    BreakpointType type;
    QString url;
    QString method;
    int statusCode = 0;

    // Editable data
    QMap<QString, QString> headers;
    QByteArray body;

    // Control
    bool released = false;
    bool modified = false;
};

class BreakpointEngine : public QObject
{
    Q_OBJECT
public:
    explicit BreakpointEngine(QObject *parent = nullptr);

    // Rule management
    int addRule(const BreakpointRule &rule);
    void removeRule(int ruleId);
    void updateRule(const BreakpointRule &rule);
    void toggleRule(int ruleId, bool enabled);
    QList<BreakpointRule> rules() const;
    void clearRules();

    // Check if a request should be paused
    bool shouldBreak(const QString &url, BreakpointType type, int &matchedRuleId) const;

    // Pause and wait for release (called from proxy thread)
    // Returns true if data was modified
    bool pauseAndWait(BreakpointHit &hit);

    // Release a breakpoint (called from UI thread)
    void releaseBreakpoint(int requestId, bool applyChanges = false,
                           const QMap<QString, QString> &newHeaders = {},
                           const QByteArray &newBody = {});

signals:
    void breakpointHit(const BreakpointHit &hit);
    void breakpointReleased(int requestId);

private:
    QList<BreakpointRule> m_rules;
    int m_nextId = 1;

    // Active breakpoint state
    QMap<int, BreakpointHit> m_activeHits;
    QMutex m_mutex;
    QWaitCondition m_waitCondition;
    int m_nextRequestId = 1;
};
