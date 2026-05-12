#pragma once

#include <QDebug>

#ifdef Q_OS_WIN
#include <winsock2.h>
#include <ws2tcpip.h>

// Map Unix socket functions to Winsock
inline int compat_close(int fd) { return closesocket(fd); }
inline int compat_read(int fd, void *buf, int len) { return recv(fd, (char*)buf, len, 0); }
inline int compat_write(int fd, const void *buf, int len) { return send(fd, (const char*)buf, len, 0); }

// Windows doesn't have pipe() - use socketpair emulation
inline int compat_pipe(int fds[2]) {
    struct sockaddr_in addr;
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) return -1;

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    if (bind(listener, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        closesocket(listener);
        return -1;
    }
    if (listen(listener, 1) < 0) {
        closesocket(listener);
        return -1;
    }

    int len = sizeof(addr);
    getsockname(listener, (struct sockaddr*)&addr, &len);

    fds[0] = socket(AF_INET, SOCK_STREAM, 0);
    if (fds[0] < 0) {
        closesocket(listener);
        return -1;
    }

    if (connect(fds[0], (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        closesocket(fds[0]);
        closesocket(listener);
        return -1;
    }

    fds[1] = accept(listener, nullptr, nullptr);
    if (fds[1] < 0) {
        closesocket(fds[0]);
        closesocket(listener);
        return -1;
    }

    closesocket(listener);
    return 0;
}

#define CLOSE(fd) compat_close(fd)
#define READ(fd, buf, len) compat_read(fd, buf, len)
#define WRITE(fd, buf, len) compat_write(fd, buf, len)
#define PIPE(fds) compat_pipe(fds)
#define ssize_t int

// Windows doesn't have dup() for sockets. Use WSADuplicateSocket to create
// an independent handle that survives when the original QTcpSocket is closed.
inline int compat_dup(int fd) {
    WSAPROTOCOL_INFOA proto;
    if (WSADuplicateSocketA((SOCKET)fd, GetCurrentProcessId(), &proto) != 0) {
        int err = WSAGetLastError();
        qDebug() << "DUP: WSADuplicateSocket failed, fd=" << fd << "err=" << err;
        return -1;
    }
    SOCKET s = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, &proto, 0, 0);
    if (s == INVALID_SOCKET) {
        int err = WSAGetLastError();
        qDebug() << "DUP: WSASocket failed, err=" << err;
        return -1;
    }
    qDebug() << "DUP: fd" << fd << "-> new fd" << (int)s;
    return (int)s;
}
#define DUP(fd) compat_dup(fd)

#else
// Unix - use standard functions
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#define CLOSE(fd) ::close(fd)
#define READ(fd, buf, len) ::read(fd, buf, len)
#define WRITE(fd, buf, len) ::write(fd, buf, len)
#define PIPE(fds) ::pipe(fds)
#define DUP(fd) ::dup(fd)
#endif

// Socket initialization helper for Windows
class WinsockInit {
public:
    WinsockInit() {
#ifdef Q_OS_WIN
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
    }
    ~WinsockInit() {
#ifdef Q_OS_WIN
        WSACleanup();
#endif
    }
};
