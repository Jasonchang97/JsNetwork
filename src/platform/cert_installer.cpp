#include "cert_installer.h"
#include <QProcess>
#include <QDir>
#include <QDebug>
#include <QThread>
#include <QFile>
#include <QStandardPaths>

#ifdef Q_OS_MAC
// Refresh macOS trust cache so newly installed certs take effect immediately.
// Kill trustd + syspolicyd to force full reload.
static void refreshTrustCache()
{
    qInfo() << "Refreshing macOS trust cache...";
    QProcess proc;
    proc.start("killall", {"trustd"});
    proc.waitForFinished(5000);
    QThread::msleep(500);
    proc.start("killall", {"syspolicyd"});
    proc.waitForFinished(5000);
    QThread::msleep(1000);
    qInfo() << "Trust cache refreshed";
}

// Check if cert is in a specific keychain
static bool certInKeychain(const QString &cn, const QString &keychainPath)
{
    QProcess proc;
    proc.start("security", {"find-certificate", "-c", cn, keychainPath});
    proc.waitForFinished(10000);
    return !proc.readAllStandardOutput().isEmpty();
}
#endif

CertInstaller::CertInstaller(QObject *parent)
    : QObject(parent)
{
}

bool CertInstaller::installCaCert(const QString &certPath)
{
#ifdef Q_OS_MAC
    return installMac(certPath);
#elif defined(Q_OS_WIN)
    return installWin(certPath);
#else
    m_lastError = "Unsupported platform";
    return false;
#endif
}

bool CertInstaller::uninstallCaCert()
{
#ifdef Q_OS_MAC
    return uninstallMac();
#elif defined(Q_OS_WIN)
    return uninstallWin();
#else
    return false;
#endif
}

bool CertInstaller::isInstalled() const
{
#ifdef Q_OS_MAC
    return isInstalledMac();
#elif defined(Q_OS_WIN)
    return isInstalledWin();
#else
    return false;
#endif
}

QString CertInstaller::lastError() const
{
    return m_lastError;
}

// ============================================================================
// macOS implementation
// ============================================================================
#ifdef Q_OS_MAC

bool CertInstaller::installMac(const QString &certPath)
{
    if (!QFile::exists(certPath)) {
        m_lastError = "Certificate file not found: " + certPath;
        qWarning() << m_lastError;
        return false;
    }

    qInfo() << "Installing CA cert:" << certPath;

    // Method 1: Direct security command
    {
        QProcess proc;
        proc.start("security", {
            "add-trusted-cert", "-d",
            "-r", "trustRoot",
            "-k", "/Library/Keychains/System.keychain",
            certPath
        });
        proc.waitForFinished(30000);

        QString stderr = QString::fromUtf8(proc.readAllStandardError());
        if (proc.exitCode() == 0) {
            qInfo() << "Method 1: installed to System keychain";
            refreshTrustCache();
            if (certInKeychain(CA_CN, "/Library/Keychains/System.keychain")) {
                qInfo() << "Verification: cert found in System keychain";
                return true;
            }
            qWarning() << "Method 1: install reported success but cert not found after verification";
        } else {
            qWarning() << "Method 1 failed:" << stderr.trimmed();
        }
    }

    // Method 2: osascript admin prompt
    {
        QString script = QString(
            "do shell script \"security add-trusted-cert -d -r trustRoot "
            "-k /Library/Keychains/System.keychain '%1'\" with administrator privileges"
        ).arg(certPath);

        QProcess proc;
        proc.start("osascript", {"-e", script});
        proc.waitForFinished(60000);

        QString stderr = QString::fromUtf8(proc.readAllStandardError());
        if (proc.exitCode() == 0) {
            qInfo() << "Method 2: installed via osascript";
            refreshTrustCache();
            if (certInKeychain(CA_CN, "/Library/Keychains/System.keychain")) {
                qInfo() << "Verification: cert found in System keychain";
                return true;
            }
            qWarning() << "Method 2: install reported success but cert not found after verification";
        } else {
            qWarning() << "Method 2 failed:" << stderr.trimmed();
        }
    }

    // Method 3: Login keychain fallback (no admin needed)
    {
        QString loginKeychain = QDir::homePath() + "/Library/Keychains/login.keychain-db";
        QProcess proc;
        proc.start("security", {
            "add-trusted-cert", "-d",
            "-r", "trustRoot",
            "-k", loginKeychain,
            certPath
        });
        proc.waitForFinished(30000);

        QString stderr = QString::fromUtf8(proc.readAllStandardError());
        if (proc.exitCode() == 0) {
            qInfo() << "Method 3: installed to Login keychain";
            refreshTrustCache();
            if (certInKeychain(CA_CN, loginKeychain)) {
                qInfo() << "Verification: cert found in Login keychain";
                return true;
            }
            qWarning() << "Method 3: install reported success but cert not found after verification";
        } else {
            qWarning() << "Method 3 failed:" << stderr.trimmed();
        }
    }

    m_lastError = "All installation methods failed. Please install manually.";
    qWarning() << m_lastError;
    return false;
}

bool CertInstaller::uninstallMac()
{
    QProcess proc;
    proc.start("security", {
        "find-certificate", "-c", CA_CN, "-Z",
        "/Library/Keychains/System.keychain"
    });
    proc.waitForFinished(10000);

    QString output = QString::fromUtf8(proc.readAllStandardOutput());
    if (output.isEmpty()) {
        m_lastError = "Certificate not found in keychain";
        return false;
    }

    QString hash;
    for (const QString &line : output.split('\n')) {
        if (line.contains("SHA-256 hash:")) {
            hash = line.split(':').last().trimmed();
            break;
        }
    }

    if (hash.isEmpty()) {
        m_lastError = "Could not find certificate hash";
        return false;
    }

    proc.start("security", {
        "delete-certificate", "-Z", hash,
        "/Library/Keychains/System.keychain"
    });
    proc.waitForFinished(10000);

    if (proc.exitCode() != 0) {
        m_lastError = QString::fromUtf8(proc.readAllStandardError());
        return false;
    }
    return true;
}

bool CertInstaller::isInstalledMac() const
{
    // Check if cert exists in keychain AND the cert file on disk matches
    // This handles the case where user deleted cert from Keychain Access
    // but a stale reference remains

    // Step 1: Check if cert is in any keychain
    bool inSystem = certInKeychain(CA_CN, "/Library/Keychains/System.keychain");
    bool inLogin = certInKeychain(CA_CN, QDir::homePath() + "/Library/Keychains/login.keychain-db");

    if (!inSystem && !inLogin) {
        qInfo() << "isInstalled: cert not found in any keychain";
        return false;
    }

    qInfo() << "isInstalled: cert found in" << (inSystem ? "System" : "") << (inLogin ? "Login" : "");

    // Step 2: Verify the cert file on disk matches what's in keychain
    // Get SHA-256 of cert in keychain
    QString keychain = inSystem ? "/Library/Keychains/System.keychain"
                                : QDir::homePath() + "/Library/Keychains/login.keychain-db";
    QProcess proc;
    proc.start("security", {"find-certificate", "-c", CA_CN, "-p", keychain});
    proc.waitForFinished(10000);
    QByteArray keychainPem = proc.readAllStandardOutput();

    // Get SHA-256 of cert file on disk
    QString certDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
                      + "/certificates";
    QString caCertPath = certDir + "/ca.pem";
    if (!QFile::exists(caCertPath)) {
        qInfo() << "isInstalled: cert file missing on disk, need reinstall";
        return false;
    }

    // Compare using DER format (binary) to avoid PEM formatting differences
    QProcess shaProc;
    shaProc.start("sh", {"-c",
        QString("security find-certificate -c '%1' -p '%2' | openssl x509 -outform DER | openssl dgst -sha256")
            .arg(CA_CN, keychain)
    });
    shaProc.waitForFinished(10000);
    QString keychainHash = QString::fromUtf8(shaProc.readAllStandardOutput()).trimmed();

    QProcess shaProc2;
    shaProc2.start("sh", {"-c",
        QString("openssl x509 -in '%1' -outform DER | openssl dgst -sha256").arg(caCertPath)
    });
    shaProc2.waitForFinished(10000);
    QString fileHash = QString::fromUtf8(shaProc2.readAllStandardOutput()).trimmed();

    if (keychainHash.isEmpty() || fileHash.isEmpty()) {
        qWarning() << "isInstalled: could not compute cert hashes";
        // Fall back to just checking keychain presence
        return inSystem || inLogin;
    }

    if (keychainHash == fileHash) {
        qInfo() << "isInstalled: cert file matches keychain";
        return true;
    }

    qInfo() << "isInstalled: cert file differs from keychain (file:" << fileHash << "keychain:" << keychainHash << ")";
    return false;
}

#endif // Q_OS_MAC

// ============================================================================
// Windows implementation
// ============================================================================

bool CertInstaller::installWin(const QString &certPath)
{
#ifdef Q_OS_WIN
    // Use PowerShell Start-Process with RunAs verb to trigger UAC prompt
    QString cmd = QString(
        "Start-Process -FilePath 'certutil' -ArgumentList '-addstore','Root','%1' -Verb RunAs -Wait"
    ).arg(certPath);

    QProcess proc;
    proc.start("powershell", {"-Command", cmd});
    proc.waitForFinished(60000);

    // Verify installation
    if (isInstalledWin()) {
        return true;
    }

    // Fallback: try without elevation (may work if already running as admin)
    QProcess proc2;
    proc2.start("certutil", {"-addstore", "Root", certPath});
    proc2.waitForFinished(30000);

    if (proc2.exitCode() == 0) {
        return true;
    }

    m_lastError = "Failed to install CA certificate. Please run as administrator or install manually:\n"
                  "certutil -addstore Root \"" + certPath + "\"";
    return false;
#else
    Q_UNUSED(certPath);
    return false;
#endif
}

bool CertInstaller::uninstallWin()
{
#ifdef Q_OS_WIN
    QProcess proc;
    proc.start("certutil", {"-delstore", "Root", CA_CN});
    proc.waitForFinished(10000);

    if (proc.exitCode() != 0) {
        m_lastError = QString::fromUtf8(proc.readAllStandardError());
        return false;
    }
    return true;
#else
    return false;
#endif
}

bool CertInstaller::isInstalledWin() const
{
#ifdef Q_OS_WIN
    QProcess proc;
    proc.start("certutil", {"-verifystore", "Root", CA_CN});
    proc.waitForFinished(10000);

    QString output = QString::fromUtf8(proc.readAllStandardOutput());
    // If cert is found, output will contain certificate details
    return output.contains("CN = JsNetwork CA") || output.contains("CN=JsNetwork CA");
#else
    return false;
#endif
}
