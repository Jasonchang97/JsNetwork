#pragma once

#include <QObject>
#include <QString>
#include <QMap>
#include <QByteArray>
#include <mutex>
#include <thread>

// Forward declarations for OpenSSL types
struct x509_st;
struct evp_pkey_st;
struct ssl_ctx_st;
typedef struct x509_st X509;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct ssl_ctx_st SSL_CTX;

class CertManager : public QObject
{
    Q_OBJECT
public:
    explicit CertManager(QObject *parent = nullptr);
    ~CertManager();

    // Initialize CA: load existing or generate new
    bool initialize(const QString &certDir);

    // Generate or get cached SSL_CTX for a domain
    SSL_CTX *createSslContextForDomain(const QString &domain);

    // Export CA certificate for installation
    QString caCertPath() const;

    // Pre-generate certs for common domains
    void preGenerateCerts(const QStringList &domains);

    // Check if CA is ready
    bool isReady() const;

    // Get CA cert as PEM bytes (for installation)
    QByteArray caCertPem() const;

private:
    bool generateCA();
    bool loadCA();
    X509 *generateDomainCert(const QString &domain, EVP_PKEY *caKey, X509 *caCert);
    SSL_CTX *buildSslContext(X509 *domainCert, EVP_PKEY *domainKey);

    QString m_certDir;
    QString m_caCertPath;
    QString m_caKeyPath;

    X509 *m_caCert = nullptr;
    EVP_PKEY *m_caKey = nullptr;

    // Cache: domain -> SSL_CTX
    QMap<QString, SSL_CTX*> m_domainContexts;
    std::mutex m_mutex;
    std::thread m_preGenThread;
};
