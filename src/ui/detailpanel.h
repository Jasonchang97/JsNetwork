#pragma once

#include <QWidget>
#include <QTabWidget>
#include <QTextEdit>
#include "model/request_item.h"

class BodyPreview;
class TimelineWidget;

class DetailPanel : public QWidget
{
    Q_OBJECT
public:
    explicit DetailPanel(QWidget *parent = nullptr);

public slots:
    void setRequest(const RequestItem &item);

private:
    void setupUi();
    void updateOverview(const RequestItem &item);
    void updateRequestTab(const RequestItem &item);
    void updateResponseTab(const RequestItem &item);
    void updateTimeline(const RequestItem &item);

    QTabWidget *m_tabs;
    QTextEdit *m_overviewText;
    QTextEdit *m_requestHeadersText;
    BodyPreview *m_requestBodyPreview;
    QTextEdit *m_responseHeadersText;
    BodyPreview *m_responseBodyPreview;
    TimelineWidget *m_timeline;
    RequestItem m_currentItem;
    bool m_hasItem = false;
};
