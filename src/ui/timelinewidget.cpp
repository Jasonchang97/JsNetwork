#include "timelinewidget.h"
#include <QPainter>
#include <QFontMetrics>

TimelineWidget::TimelineWidget(QWidget *parent)
    : QWidget(parent)
{
    setMinimumHeight(180);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
}

void TimelineWidget::setTiming(qint64 dnsMs, qint64 connectMs, qint64 tlsMs,
                                 qint64 ttfbMs, qint64 downloadMs)
{
    m_phases.clear();

    qint64 offset = 0;

    m_phases.append({"DNS Lookup", offset, dnsMs, QColor(79, 195, 247)});      // blue
    offset += dnsMs;

    m_phases.append({"TCP Connect", offset, connectMs, QColor(129, 199, 132)}); // green
    offset += connectMs;

    if (tlsMs > 0) {
        m_phases.append({"TLS Handshake", offset, tlsMs, QColor(255, 183, 77)}); // orange
        offset += tlsMs;
    }

    m_phases.append({"TTFB", offset, ttfbMs, QColor(206, 147, 216)});          // purple
    offset += ttfbMs;

    m_phases.append({"Download", offset, downloadMs, QColor(255, 138, 128)});   // red

    m_totalMs = offset + downloadMs;
    update();
}

void TimelineWidget::setTotalTime(qint64 totalMs)
{
    m_totalMs = totalMs;
    update();
}

void TimelineWidget::paintEvent(QPaintEvent *)
{
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);

    // Background
    painter.fillRect(rect(), QColor(30, 30, 30));

    if (m_phases.isEmpty() || m_totalMs <= 0) {
        painter.setPen(QColor(150, 150, 150));
        painter.drawText(rect(), Qt::AlignCenter, "No timing data");
        return;
    }

    int marginLeft = 120;
    int marginRight = 60;
    int marginTop = 20;
    int rowHeight = 28;
    int rowSpacing = 4;

    int barWidth = width() - marginLeft - marginRight;
    double msPerPixel = static_cast<double>(m_totalMs) / barWidth;

    // Title
    painter.setPen(QColor(200, 200, 200));
    painter.setFont(QFont("monospace", 11, QFont::Bold));
    painter.drawText(marginLeft, marginTop - 6, "Timeline");

    // Draw each phase
    int y = marginTop + 10;
    for (const auto &phase : m_phases) {
        drawPhase(painter, phase, y, rowHeight, msPerPixel);
        y += rowHeight + rowSpacing;
    }

    // Total time
    y += 10;
    painter.setPen(QColor(180, 180, 180));
    painter.setFont(QFont("monospace", 10));
    painter.drawText(marginLeft, y, QString("Total: %1ms").arg(m_totalMs));
}

void TimelineWidget::drawPhase(QPainter &painter, const TimingPhase &phase,
                                int y, int rowHeight, double msPerPixel)
{
    int marginLeft = 120;
    int barWidth = width() - marginLeft - 60;

    // Phase name (left side)
    painter.setPen(QColor(200, 200, 200));
    painter.setFont(QFont("monospace", 10));
    painter.drawText(10, y + rowHeight / 2 + 4, phase.name);

    // Bar background (light gray track)
    painter.fillRect(marginLeft, y, barWidth, rowHeight, QColor(50, 50, 50));

    // Phase bar
    int barX = marginLeft + static_cast<int>(phase.startMs / msPerPixel);
    int barW = qMax(2, static_cast<int>(phase.durationMs / msPerPixel));
    barW = qMin(barW, barWidth - (barX - marginLeft));

    painter.fillRect(barX, y, barW, rowHeight, phase.color);

    // Duration label on bar (or after bar if too small)
    QString label = QString("%1ms").arg(phase.durationMs);
    QFontMetrics fm(painter.font());
    int labelWidth = fm.horizontalAdvance(label);

    if (barW > labelWidth + 8) {
        // Label on bar
        painter.setPen(Qt::white);
        painter.drawText(barX + 4, y + rowHeight / 2 + 4, label);
    } else {
        // Label after bar
        painter.setPen(phase.color);
        painter.drawText(barX + barW + 4, y + rowHeight / 2 + 4, label);
    }
}
