#include "cert_installer.h"
#include <QProcess>
#include <QDir>
#include <QDebug>

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
    // Method 1: Direct security command (triggers macOS GUI password dialog)
    QProcess proc;
    proc.start("security", {
        "add-trusted-cert",
        "-d",
        "-r", "trustRoot",
        "-k", "/Library/Keychains/System.keychain",
        certPath
    });
    proc.waitForFinished(30000);

    if (proc.exitCode() == 0) {
        qInfo() << "CA cert installed to System keychain";
        return true;
    }

    QString err1 = QString::fromUtf8(proc.readAllStandardError());
    qWarning() << "System keychain install failed:" << err1;

    // Method 2: Use osascript to request admin and run via sudo
    QString script = QString(
        "do shell script \"security add-trusted-cert -d -r trustRoot "
        "-k /Library/Keychains/System.keychain '%1'\" with administrator privileges"
    ).arg(certPath);

    QProcess proc2;
    proc2.start("osascript", {"-e", script});
    proc2.waitForFinished(60000);

    if (proc2.exitCode() == 0) {
        qInfo() << "CA cert installed via osascript admin prompt";
        return true;
    }

    QString err2 = QString::fromUtf8(proc2.readAllStandardError());
    qWarning() << "osascript install failed:" << err2;

    // Method 3: Fallback to Login keychain (no admin needed, but only current user)
    QProcess proc3;
    proc3.start("security", {
        "add-trusted-cert",
        "-d",
        "-r", "trustRoot",
        "-k", QDir::homePath() + "/Library/Keychains/login.keychain-db",
        certPath
    });
    proc3.waitForFinished(30000);

    if (proc3.exitCode() == 0) {
        qInfo() << "CA cert installed to Login keychain (user-only)";
        return true;
    }

    m_lastError = QString("All installation methods failed.\n"
                          "System keychain: %1\nosascript: %2\n"
                          "Please install manually: security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain-db \"%3\"")
                  .arg(err1, err2, certPath);
    qWarning() << m_lastError;
    return false;
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
