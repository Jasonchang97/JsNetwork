#pragma once

#include <QWidget>
#include <QVector>

struct TimingPhase {
    QString name;
    qint64 startMs;  // start offset from request begin
    qint64 durationMs;
    QColor color;
};

class TimelineWidget : public QWidget
{
    Q_OBJECT
public:
    explicit TimelineWidget(QWidget *parent = nullptr);

    // Set timing data
    void setTiming(qint64 dnsMs, qint64 connectMs, qint64 tlsMs,
                   qint64 ttfbMs, qint64 downloadMs);

    // Set total request time
    void setTotalTime(qint64 totalMs);

protected:
    void paintEvent(QPaintEvent *event) override;
    QSize sizeHint() const override { return QSize(400, 180); }

private:
    void drawPhase(QPainter &painter, const TimingPhase &phase,
                   int y, int rowHeight, double msPerPixel);

    QVector<TimingPhase> m_phases;
    qint64 m_totalMs = 0;
};
