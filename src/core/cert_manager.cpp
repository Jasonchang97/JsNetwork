#include "cert_manager.h"
#include <QDir>
#include <QFile>
#ifndef Q_OS_WIN
#include <sys/stat.h>
#endif
#include <thread>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// ALPN callback for server-side: only accept http/1.1
static int alpnSelectCallback(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                               const unsigned char *in, unsigned int inlen, void *arg)
{
    // Try to select "http/1.1" from client's list
    // Client ALPN format: 1-byte-len + proto-name repeated
    const unsigned char *p = in;
    const unsigned char *end = in + inlen;
    while (p < end) {
        unsigned char protoLen = *p++;
        if (p + protoLen > end) break;
        if (protoLen == 8 && memcmp(p, "http/1.1", 8) == 0) {
            *out = p;
            *outlen = protoLen;
            return SSL_TLSEXT_ERR_OK;
        }
        p += protoLen;
    }
    // No http/1.1 found — reject (client will retry with HTTP/1.1 or fail)
    *out = nullptr;
    *outlen = 0;
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

CertManager::CertManager(QObject *parent)
    : QObject(parent)
{
}

CertManager::~CertManager()
{
    if (m_caCert) X509_free(m_caCert);
    if (m_caKey) EVP_PKEY_free(m_caKey);

    for (auto *ctx : m_domainContexts) {
        SSL_CTX_free(ctx);
    }
}

bool CertManager::initialize(const QString &certDir)
{
    m_certDir = certDir;
    m_caCertPath = certDir + "/ca.pem";
    m_caKeyPath = certDir + "/ca.key";

    QDir dir(certDir);
    if (!dir.exists()) {
        dir.mkpath(".");
    }

    // Try to load existing CA, or generate new one
    if (QFile::exists(m_caCertPath) && QFile::exists(m_caKeyPath)) {
        return loadCA();
    }
    return generateCA();
}

bool CertManager::generateCA()
{
    // Generate RSA 2048 key for CA
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) return false;

    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    BN_set_word(bn, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, bn, nullptr);
    EVP_PKEY_assign_RSA(pkey, rsa);
    BN_free(bn);

    // Create self-signed CA certificate
    X509 *cert = X509_new();
    if (!cert) {
        EVP_PKEY_free(pkey);
        return false;
    }

    // Must set version to v3 (0-indexed: 2) before adding extensions
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    // Valid for 10 years
    X509_gmtime_adj(X509_get_notAfter(cert), 10L * 365 * 24 * 3600);
    X509_set_pubkey(cert, pkey);

    X509_NAME *name = const_cast<X509_NAME*>(X509_get_subject_name(cert));
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
        (const unsigned char *)"CN", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
        (const unsigned char *)"JsNetwork", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (const unsigned char *)"JsNetwork CA", -1, -1, 0);
    X509_set_issuer_name(cert, name);

    // Add CA extensions
    X509V3_CTX v3ctx;
    X509V3_set_ctx_nodb(&v3ctx);
    X509V3_set_ctx(&v3ctx, cert, cert, nullptr, nullptr, 0);

    X509_EXTENSION *ext = X509V3_EXT_conf_nid(nullptr, &v3ctx,
        NID_basic_constraints, "critical,CA:TRUE");
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);

    ext = X509V3_EXT_conf_nid(nullptr, &v3ctx,
        NID_key_usage, "critical,keyCertSign,cRLSign");
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);

    ext = X509V3_EXT_conf_nid(nullptr, &v3ctx,
        NID_subject_key_identifier, "hash");
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);

    // Sign with own key (self-signed)
    if (!X509_sign(cert, pkey, EVP_sha256())) {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return false;
    }

    // Save CA cert to disk (use BIO to avoid OPENSSL_Applink requirement)
    BIO *bio = BIO_new_file(m_caCertPath.toUtf8().constData(), "w");
    if (bio) {
        PEM_write_bio_X509(bio, cert);
        BIO_free(bio);
    }

    // Save CA key to disk
    bio = BIO_new_file(m_caKeyPath.toUtf8().constData(), "w");
    if (bio) {
        PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        BIO_free(bio);
    }

    // Set permissions on key file
#ifndef Q_OS_WIN
    chmod(m_caKeyPath.toUtf8().constData(), 0600);
#endif

    m_caCert = cert;
    m_caKey = pkey;
    return true;
}

bool CertManager::loadCA()
{
    // Load CA certificate (use BIO to avoid OPENSSL_Applink requirement)
    BIO *bio = BIO_new_file(m_caCertPath.toUtf8().constData(), "r");
    if (!bio) return false;
    m_caCert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!m_caCert) return false;

    // Load CA private key
    bio = BIO_new_file(m_caKeyPath.toUtf8().constData(), "r");
    if (!bio) return false;
    m_caKey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!m_caKey) return false;

    return true;
}

X509 *CertManager::generateDomainCert(const QString &domain, EVP_PKEY *caKey, X509 *caCert)
{
    // Generate RSA 2048 key for domain
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) return nullptr;

    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    BN_set_word(bn, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, bn, nullptr);
    EVP_PKEY_assign_RSA(pkey, rsa);
    BN_free(bn);

    // Create certificate
    X509 *cert = X509_new();
    if (!cert) {
        EVP_PKEY_free(pkey);
        return nullptr;
    }

    // Random serial number
    ASN1_INTEGER *serial = X509_get_serialNumber(cert);
    ASN1_INTEGER_set(serial, qHash(domain) % 0x7FFFFFFF);

    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 365L * 24 * 3600); // 1 year
    X509_set_pubkey(cert, pkey);

    // Subject: CN=domain
    X509_NAME *name = const_cast<X509_NAME*>(X509_get_subject_name(cert));
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (const unsigned char *)domain.toUtf8().constData(), -1, -1, 0);
    X509_set_issuer_name(cert, const_cast<X509_NAME*>(X509_get_subject_name(caCert)));

    // Add SAN (Subject Alternative Name) with the domain
    X509V3_CTX v3ctx;
    X509V3_set_ctx_nodb(&v3ctx);
    X509V3_set_ctx(&v3ctx, caCert, cert, nullptr, nullptr, 0);

    QString sanStr = QString("DNS:%1,DNS:*.%1").arg(domain);
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(nullptr, &v3ctx,
        NID_subject_alt_name, sanStr.toUtf8().constData());
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);

    // Sign with CA key
    if (!X509_sign(cert, caKey, EVP_sha256())) {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return nullptr;
    }

    // We need to keep pkey alive with the cert
    // Store pkey in a temporary location or attach it
    // For simplicity, we'll build the SSL_CTX immediately and free cert+pkey after
    // But first we need to return both - let's use a different approach
    // Actually, we'll create the SSL_CTX right here
    // Return cert, caller must handle cleanup

    // Attach key to cert using ex_data (simplified: just return cert, key handled separately)
    // For now, we leak pkey intentionally - it's cached in SSL_CTX
    Q_UNUSED(pkey);
    return cert;
}

SSL_CTX *CertManager::buildSslContext(X509 *domainCert, EVP_PKEY *domainKey)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    if (!ctx) return nullptr;

    SSL_CTX_use_certificate(ctx, domainCert);
    SSL_CTX_use_PrivateKey(ctx, domainKey);

    if (!SSL_CTX_check_private_key(ctx)) {
        SSL_CTX_free(ctx);
        return nullptr;
    }

    // Server-side ALPN: only accept http/1.1 so we can parse plaintext HTTP
    // SSL_CTX_set_alpn_select_cb is the SERVER API (vs set_alpn_protos for client)
    SSL_CTX_set_alpn_select_cb(ctx, alpnSelectCallback, nullptr);

    return ctx;
}

SSL_CTX *CertManager::createSslContextForDomain(const QString &domain)
{
    // Fast path: check cache under lock
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_domainContexts.contains(domain)) {
            return m_domainContexts[domain];
        }
        if (!m_caCert || !m_caKey) return nullptr;
    }

    // Slow path: generate cert OUTSIDE the lock so other domains can proceed in parallel
    // Copy CA cert/key refs under lock (they live as long as CertManager)
    X509 *caCert;
    EVP_PKEY *caKey;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        caCert = m_caCert;
        caKey = m_caKey;
    }
    if (!caCert || !caKey) return nullptr;

    // Generate RSA 2048 key for domain (1024 rejected by modern browsers)
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) return nullptr;

    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    BN_set_word(bn, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, bn, nullptr);
    EVP_PKEY_assign_RSA(pkey, rsa);
    BN_free(bn);

    // Create certificate
    X509 *cert = X509_new();
    if (!cert) {
        EVP_PKEY_free(pkey);
        return nullptr;
    }

    // Must set version to v3 (0-indexed: 2) before adding extensions
    X509_set_version(cert, 2);

    // Serial number: ensure it's always > 0
    quint32 serial = (qHash(domain) % 0x7FFFFFFE) + 1;
    ASN1_INTEGER_set(X509_get_serialNumber(cert), serial);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 365L * 24 * 3600);
    X509_set_pubkey(cert, pkey);

    X509_NAME *name = const_cast<X509_NAME*>(X509_get_subject_name(cert));
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (const unsigned char *)domain.toUtf8().constData(), -1, -1, 0);
    X509_set_issuer_name(cert, const_cast<X509_NAME*>(X509_get_subject_name(caCert)));

    // Extensions
    X509V3_CTX v3ctx;
    X509V3_set_ctx_nodb(&v3ctx);
    X509V3_set_ctx(&v3ctx, caCert, cert, nullptr, nullptr, 0);

    // Basic Constraints: not a CA
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(nullptr, &v3ctx,
        NID_basic_constraints, "critical,CA:FALSE");
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);

    // Key Usage
    ext = X509V3_EXT_conf_nid(nullptr, &v3ctx,
        NID_key_usage, "digitalSignature,keyEncipherment");
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);

    // Extended Key Usage
    ext = X509V3_EXT_conf_nid(nullptr, &v3ctx,
        NID_ext_key_usage, "serverAuth");
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);

    // Subject Alternative Name
    QString sanStr = QString("DNS:%1").arg(domain);
    // Add wildcard only if domain doesn't start with wildcard
    if (!domain.startsWith("*.")) {
        // Also add wildcard for subdomains
        int dotIdx = domain.indexOf('.');
        if (dotIdx >= 0) {
            sanStr += QString(",DNS:*%1").arg(domain.mid(dotIdx));
        }
    }
    ext = X509V3_EXT_conf_nid(nullptr, &v3ctx,
        NID_subject_alt_name, sanStr.toUtf8().constData());
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);

    if (!X509_sign(cert, caKey, EVP_sha256())) {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return nullptr;
    }

    // Build SSL context
    SSL_CTX *ctx = buildSslContext(cert, pkey);

    X509_free(cert);
    EVP_PKEY_free(pkey);

    // Store in cache under lock (another thread may have raced and stored first - that's fine)
    if (ctx) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_domainContexts.contains(domain)) {
            // Another thread already generated this domain's context
            SSL_CTX_free(ctx);
            return m_domainContexts[domain];
        }
        m_domainContexts[domain] = ctx;
    }

    return ctx;
}

void CertManager::preGenerateCerts(const QStringList &domains)
{
    // Run in background thread to avoid blocking UI
    std::thread([this, domains]() {
        for (const QString &domain : domains) {
            createSslContextForDomain(domain);
        }
    }).detach();
}

QString CertManager::caCertPath() const
{
    return m_caCertPath;
}

bool CertManager::isReady() const
{
    return m_caCert != nullptr && m_caKey != nullptr;
}

QByteArray CertManager::caCertPem() const
{
    if (!m_caCert) return QByteArray();

    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, m_caCert);

    char *data;
    long len = BIO_get_mem_data(bio, &data);
    QByteArray result(data, len);
    BIO_free(bio);

    return result;
}
