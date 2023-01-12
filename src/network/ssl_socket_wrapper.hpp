/*!
 * Copyright (c) 2016 Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */
#ifndef LIGHTGBM_NETWORK_SOCKET_WRAPPER_HPP_
#define LIGHTGBM_NETWORK_SOCKET_WRAPPER_HPP_
#ifdef USE_SSL_SOCKET

#include <LightGBM/utils/log.h>

#include <string>
#include <cerrno>
#include <cstdlib>
#include <unordered_set>

#if defined(_WIN32)

#ifdef _MSC_VER
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#else

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


#include <ifaddrs.h>

#endif  // defined(_WIN32)

#ifdef _MSC_VER
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "IPHLPAPI.lib")
#endif

namespace LightGBM {

#ifndef _WIN32

typedef int SOCKET;
const int INVALID_SOCKET = -1;
#define SOCKET_ERROR -1

#endif

#ifdef _WIN32
// existence of inet_pton is checked in CMakeLists.txt and configure.win, then stored in WIN_HAS_INET_PTON
#ifndef WIN_HAS_INET_PTON
inline int inet_pton(int af, const char *src, void *dst) {
  struct sockaddr_storage ss;
  int size = sizeof(ss);
  char src_copy[INET6_ADDRSTRLEN + 1];

  ZeroMemory(&ss, sizeof(ss));
  /* stupid non-const API */
  strncpy(src_copy, src, INET6_ADDRSTRLEN + 1);
  src_copy[INET6_ADDRSTRLEN] = 0;

  if (WSAStringToAddress(src_copy, af, NULL, (struct sockaddr *)&ss, &size) == 0) {
    switch (af) {
    case AF_INET:
      *(struct in_addr *)dst = ((struct sockaddr_in *)&ss)->sin_addr;
      return 1;
    case AF_INET6:
      *(struct in6_addr *)dst = ((struct sockaddr_in6 *)&ss)->sin6_addr;
      return 1;
    }
  }
  return 0;
}
#endif
#endif

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

namespace SocketConfig {
const int kSocketBufferSize = 100 * 1000;
const int kMaxReceiveSize = 100 * 1000;
const int kNoDelay = 1;
}

class SslTcpSocket {
 public:
  SSL* ssl;
  
  SSL_CTX* create_context(){
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        Log::Info("Unable to create SSL context");
    }
    return ctx;
  }
  
  SslTcpSocket() {
    Log::Info("Creating default ssl tcp socket...");
    sockfd_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd_ == INVALID_SOCKET) {
      Log::Fatal("Socket construction error");
      return;
    }
    SSL_CTX* ctx = create_context();
    ssl = SSL_new (ctx);
    SSL_set_fd(ssl, sockfd_);
    if (!ssl) {
        Log::Fatal("Error creating SSL.");
    }
    ConfigSocket();
  }

  explicit SslTcpSocket(SOCKET socket) {
    Log::Info("accept a socket and create a new ssl tcp one from it...");
    sockfd_ = socket;
    if (sockfd_ == INVALID_SOCKET) {
      Log::Fatal("Passed socket error");
      return;
    }
    SSL_CTX* ctx = create_context();
    ssl = SSL_new (ctx);
    SSL_set_fd(ssl, sockfd_);
    if (!ssl) {
        Log::Fatal("Error creating SSL.");
    }
    Log::Info("calling SSL_accept...");
    int err = SSL_accept(ssl);
    if (err < 0){
       Log::Fatal("SSL accept failure.");
    }
    ConfigSocket();
  }

  SslTcpSocket(const SslTcpSocket &object) {
    Log::Info("create a new ssl tcp socket from object...");
    sockfd_ = object.sockfd_;
    if (sockfd_ == INVALID_SOCKET) {
      Log::Fatal("Passed socket error");
      return;
    }
    SSL_CTX* ctx = create_context();
    ssl = SSL_new (ctx);
    SSL_set_fd(ssl, sockfd_);
    if (!ssl) {
        Log::Fatal("Error creating SSL.");
    }
    Log::Info("calling SSL_accept...");
    int err = SSL_accept(ssl);
    if (err < 0){
       Log::Fatal("SSL accept failure.");
    }
    ConfigSocket();
  }

  ~SslTcpSocket() {
  }
  inline void SetTimeout(int timeout) {
    setsockopt(sockfd_, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));
  }
  inline void ConfigSocket() {
    if (sockfd_ == INVALID_SOCKET) {
      return;
    }

    if (setsockopt(sockfd_, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&SocketConfig::kSocketBufferSize), sizeof(SocketConfig::kSocketBufferSize)) != 0) {
      Log::Warning("Set SO_RCVBUF failed, please increase your net.core.rmem_max to 100k at least");
    }

    if (setsockopt(sockfd_, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char*>(&SocketConfig::kSocketBufferSize), sizeof(SocketConfig::kSocketBufferSize)) != 0) {
      Log::Warning("Set SO_SNDBUF failed, please increase your net.core.wmem_max to 100k at least");
    }
    if (setsockopt(sockfd_, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&SocketConfig::kNoDelay), sizeof(SocketConfig::kNoDelay)) != 0) {
      Log::Warning("Set TCP_NODELAY failed");
    }
  }

  inline static void Startup() {
#if defined(_WIN32)
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) == -1) {
      Log::Fatal("Socket error: WSAStartup error");
    }
    if (LOBYTE(wsa_data.wVersion) != 2 || HIBYTE(wsa_data.wVersion) != 2) {
      WSACleanup();
      Log::Fatal("Socket error: Winsock.dll version error");
    }
#else
#endif
  }
  inline static void Finalize() {
#if defined(_WIN32)
    WSACleanup();
#endif
  }

  inline static int GetLastError() {
#if defined(_WIN32)
    return WSAGetLastError();
#else
    return errno;
#endif
  }



#if defined(_WIN32)
  inline static std::unordered_set<std::string> GetLocalIpList() {
    std::unordered_set<std::string> ip_list;
    char buffer[512];
    // get hostName
    if (gethostname(buffer, sizeof(buffer)) == SOCKET_ERROR) {
      Log::Fatal("Error code %d, when getting local host name", WSAGetLastError());
    }
    // push local ip
    PIP_ADAPTER_INFO pAdapterInfo;
    PIP_ADAPTER_INFO pAdapter = NULL;
    DWORD dwRetVal = 0;
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    pAdapterInfo = reinterpret_cast<IP_ADAPTER_INFO *>(MALLOC(sizeof(IP_ADAPTER_INFO)));
    if (pAdapterInfo == NULL) {
      Log::Fatal("GetAdaptersinfo error: allocating memory");
    }
    // Make an initial call to GetAdaptersInfo to get
    // the necessary size into the ulOutBufLen variable
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
      FREE(pAdapterInfo);
      pAdapterInfo = reinterpret_cast<IP_ADAPTER_INFO *>(MALLOC(ulOutBufLen));
      if (pAdapterInfo == NULL) {
        Log::Fatal("GetAdaptersinfo error: allocating memory");
      }
    }
    if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
      pAdapter = pAdapterInfo;
      while (pAdapter) {
        ip_list.insert(pAdapter->IpAddressList.IpAddress.String);
        pAdapter = pAdapter->Next;
      }
    } else {
      Log::Fatal("GetAdaptersinfo error: code %d", dwRetVal);
    }
    if (pAdapterInfo)
      FREE(pAdapterInfo);
    return ip_list;
  }
#else
  inline static std::unordered_set<std::string> GetLocalIpList() {
    std::unordered_set<std::string> ip_list;
    struct ifaddrs * ifAddrStruct = NULL;
    struct ifaddrs * ifa = NULL;
    void * tmpAddrPtr = NULL;

    getifaddrs(&ifAddrStruct);

    for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
      if (!ifa->ifa_addr) {
        continue;
      }
      if (ifa->ifa_addr->sa_family == AF_INET) {
        // NOLINTNEXTLINE
        tmpAddrPtr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
        char addressBuffer[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
        ip_list.insert(std::string(addressBuffer));
      }
    }
    if (ifAddrStruct != NULL) freeifaddrs(ifAddrStruct);
    return ip_list;
  }
#endif
  inline static sockaddr_in GetAddress(const char* url, int port) {
    sockaddr_in addr = sockaddr_in();
    std::memset(&addr, 0, sizeof(sockaddr_in));
    inet_pton(AF_INET, url, &addr.sin_addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<u_short>(port));
    return addr;
  }

  inline bool Bind(int port) {
    sockaddr_in local_addr = GetAddress("0.0.0.0", port);
    if (bind(sockfd_, reinterpret_cast<const sockaddr*>(&local_addr), sizeof(sockaddr_in)) == 0) {
      return true;
    }
    return false;
  }

  inline bool Connect(const char *url, int port) {
    sockaddr_in server_addr = GetAddress(url, port);
    if (connect(sockfd_, reinterpret_cast<const sockaddr*>(&server_addr), sizeof(sockaddr_in)) == 0) {
      int err = SSL_connect(ssl);
      if (err <= 0) {
        Log::Fatal("Error creating SSL connection.  err=%x", err);
        return false;
      }
      Log::Info("SSL connection using %s", SSL_get_cipher (ssl));
      return true;
    }
    return false;
  }

  inline void Listen(int backlog = 128) {
    listen(sockfd_, backlog);
  }

  inline SslTcpSocket Accept() {
    SOCKET newfd = accept(sockfd_, NULL, NULL);
    if (newfd < 0){
      printf ("Unable to accept");
    }
    if (newfd == INVALID_SOCKET) {
      int err_code = GetLastError();
#if defined(_WIN32)
      Log::Fatal("Socket accept error (code: %d)", err_code);
#else
      Log::Fatal("Socket accept error, %s (code: %d)", std::strerror(err_code), err_code);
#endif
    }
    return SslTcpSocket(newfd);
  }

  inline int Send(const char *buf_, int len, int flag = 0) {
    int cur_cnt = SSL_write(ssl, buf_, len);
    if (cur_cnt < 0) {
        int err = SSL_get_error(ssl, cur_cnt);
        switch (err) {
        case SSL_ERROR_ZERO_RETURN:printf("SSL_ERROR_ZERO_RETURN");
	case SSL_ERROR_SYSCALL:printf("SSL_ERROR_SYSCALL");
        case SSL_ERROR_SSL:printf("SSL_ERROR_SSL");
        default:
            Log::Fatal("Socket send error (code: %d)", err);
        }
    }
    return cur_cnt;
  }

  inline int Recv(char *buf_, int len, int flags = 0) {
    int batch = len/100;
    int read_cnt = 0, cur_cnt = 0;
    do {
        cur_cnt = SSL_read(ssl, buf_ + read_cnt, batch);
        read_cnt += cur_cnt;
    } while (cur_cnt > 0);
    if (cur_cnt < 0) {
        int err = SSL_get_error(ssl, cur_cnt);
        if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL)
            Log::Fatal("Socket recv error (code: %d)", err);
    }
    return cur_cnt;
  }

  inline bool IsClosed() {
    return sockfd_ == INVALID_SOCKET;
  }

  inline void Close() {
    if (!IsClosed()) {
#if defined(_WIN32)
      closesocket(sockfd_);
#else
      close(sockfd_);
#endif
      sockfd_ = INVALID_SOCKET;
    }
  }

 private:
  SOCKET sockfd_;
};

}  // namespace LightGBM
#endif  // USE_SSL_SOCKET
#endif   // LightGBM_NETWORK_SOCKET_WRAPPER_HPP_


