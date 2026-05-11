#include "cert_installer.h"
#include <QProcess>
#include <QDir>

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

bool CertInstaller::installMac(const QString &certPath)
{
    // Use security command to add trusted cert to System keychain
    // This requires admin privileges (will prompt for password)
    QProcess proc;
    proc.start("security", {
        "add-trusted-cert",
        "-d",                       // Add to admin cert store
        "-r", "trustRoot",          // Trust as root
        "-k", "/Library/Keychains/System.keychain",
        certPath
    });
    proc.waitForFinished(30000);

    if (proc.exitCode() != 0) {
        m_lastError = QString::fromUtf8(proc.readAllStandardError());
        return false;
    }
    return true;
}

bool CertInstaller::uninstallMac()
{
    // Find and remove our CA cert from keychain
    QProcess proc;
    proc.start("security", {
        "find-certificate",
        "-c", CA_CN,
        "-Z",
        "/Library/Keychains/System.keychain"
    });
    proc.waitForFinished(10000);

    QString output = QString::fromUtf8(proc.readAllStandardOutput());
    if (output.isEmpty()) {
        m_lastError = "Certificate not found in keychain";
        return false;
    }

    // Extract SHA-256 hash (look for "SHA-256 hash:" line)
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

    // Delete by hash
    proc.start("security", {
        "delete-certificate",
        "-Z", hash,
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
    // Check both System and Login keychains
    QProcess proc;
    proc.start("security", {
        "find-certificate",
        "-c", CA_CN,
        "/Library/Keychains/System.keychain"
    });
    proc.waitForFinished(10000);
    if (!proc.readAllStandardOutput().isEmpty()) return true;

    proc.start("security", {
        "find-certificate",
        "-c", CA_CN,
        QString("%1/Library/Keychains/login.keychain-db")
            .arg(QDir::homePath())
    });
    proc.waitForFinished(10000);
    return !proc.readAllStandardOutput().isEmpty();
}

// ============================================================================
// Windows implementation
// ============================================================================

bool CertInstaller::installWin(const QString &certPath)
{
#ifdef Q_OS_WIN
    QProcess proc;
    proc.start("certutil", {"-addstore", "Root", certPath});
    proc.waitForFinished(30000);

    if (proc.exitCode() != 0) {
        m_lastError = QString::fromUtf8(proc.readAllStandardError());
        return false;
    }
    return true;
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
