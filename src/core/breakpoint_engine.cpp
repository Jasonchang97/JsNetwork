#include "breakpoint_engine.h"
#include <QRegularExpression>

BreakpointEngine::BreakpointEngine(QObject *parent)
    : QObject(parent)
{
}

int BreakpointEngine::addRule(const BreakpointRule &rule)
{
    BreakpointRule r = rule;
    r.id = m_nextId++;
    m_rules.append(r);
    return r.id;
}

void BreakpointEngine::removeRule(int ruleId)
{
    for (int i = 0; i < m_rules.size(); ++i) {
        if (m_rules[i].id == ruleId) {
            m_rules.removeAt(i);
            return;
        }
    }
}

void BreakpointEngine::updateRule(const BreakpointRule &rule)
{
    for (int i = 0; i < m_rules.size(); ++i) {
        if (m_rules[i].id == rule.id) {
            m_rules[i] = rule;
            return;
        }
    }
}

void BreakpointEngine::toggleRule(int ruleId, bool enabled)
{
    for (auto &r : m_rules) {
        if (r.id == ruleId) {
            r.enabled = enabled;
            return;
        }
    }
}

QList<BreakpointRule> BreakpointEngine::rules() const
{
    return m_rules;
}

void BreakpointEngine::clearRules()
{
    m_rules.clear();
}

bool BreakpointEngine::shouldBreak(const QString &url, BreakpointType type,
                                     int &matchedRuleId) const
{
    for (const auto &rule : m_rules) {
        if (!rule.enabled) continue;
        if (rule.type != type) continue;

        if (rule.matchAll) {
            matchedRuleId = rule.id;
            return true;
        }

        if (url.contains(rule.urlPattern, Qt::CaseInsensitive)) {
            matchedRuleId = rule.id;
            return true;
        }
    }
    return false;
}

bool BreakpointEngine::pauseAndWait(BreakpointHit &hit)
{
    QMutexLocker locker(&m_mutex);

    int requestId = m_nextRequestId++;
    hit.requestId = requestId;
    m_activeHits[requestId] = hit;

    // Notify UI
    emit breakpointHit(hit);

    // Wait until released
    while (!m_activeHits[requestId].released) {
        m_waitCondition.wait(&m_mutex);
    }

    // Get the (possibly modified) data
    BreakpointHit &released = m_activeHits[requestId];
    hit = released;
    m_activeHits.remove(requestId);

    emit breakpointReleased(requestId);
    return hit.modified;
}

void BreakpointEngine::releaseBreakpoint(int requestId, bool applyChanges,
                                           const QMap<QString, QString> &newHeaders,
                                           const QByteArray &newBody)
{
    QMutexLocker locker(&m_mutex);

    if (!m_activeHits.contains(requestId)) return;

    BreakpointHit &hit = m_activeHits[requestId];
    if (applyChanges) {
        hit.headers = newHeaders;
        hit.body = newBody;
        hit.modified = true;
    }
    hit.released = true;
    m_waitCondition.wakeAll();
}
