#pragma once

#include <QWidget>
#include <QComboBox>
#include <QLineEdit>
#include <QTextEdit>
#include <QPushButton>
#include <QLabel>
#include <QGroupBox>
#include <QNetworkAccessManager>
#include <QNetworkReply>

class ComposerWidget : public QWidget
{
    Q_OBJECT
public:
    explicit ComposerWidget(QWidget *parent = nullptr);

    // Pre-fill from existing request
    void setRequest(const QString &method, const QString &url,
                    const QString &headers, const QString &body);

signals:
    void requestSent(const QString &method, const QString &url);

private slots:
    void onSend();
    void onReplyFinished(QNetworkReply *reply);

private:
    void setupUi();

    QComboBox *m_methodCombo;
    QLineEdit *m_urlEdit;
    QTextEdit *m_headersEdit;
    QTextEdit *m_bodyEdit;
    QTextEdit *m_responseView;
    QLabel *m_statusLabel;
    QPushButton *m_sendBtn;
    QGroupBox *m_reqGroup;
    QGroupBox *m_respGroup;
    QLabel *m_reqHeadersLabel;
    QLabel *m_reqBodyLabel;
    QNetworkAccessManager *m_nam;
};
