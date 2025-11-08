/*#include<iostream>
#include<WinSock2.h>
#include<fstream>
#pragma comment(lib,"ws2_32.lib")
#include<easyx.h>
#include "Thread_Pool.h"
using namespace std;


std::mutex image_mutex;

// 处理客户端连接的函数
void handleClient(SOCKET client_socket) {
	cout << "New client connected, handling in thread..." << endl;

	while (1) {
		char buffer[4096];
		long long fsize;
		int ret = recv(client_socket, (char*)&fsize, sizeof(fsize), 0);
		if (ret <= 0) break;

		// 使用互斥锁保护文件操作，避免多个线程同时写入同一文件
		std::lock_guard<std::mutex> lock(image_mutex);
		FILE* fp = fopen("s.jpg", "wb");

		while (fsize > 0) {
			ret = recv(client_socket, buffer, fsize > 4096 ? 4096 : fsize, 0);
			if (ret <= 0) {
				if (nullptr != fp)
					fclose(fp);
				goto end;
			}
			fsize -= ret;
			if (nullptr != fp)
				fwrite(buffer, 1, ret, fp);
		}
		if (nullptr != fp)
			fclose(fp);

		// 加载并显示图片
		IMAGE img;
		loadimage(&img, TEXT("s.jpg"), 1280, 720);
		putimage(0, 0, &img);
	}
end:
	closesocket(client_socket);
	cout << "Client disconnected" << endl;
}

int main() {
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	
	initgraph(1280, 720);

	ThreadPool threadPool(4);

	SOCKET listen_socket= socket(AF_INET, SOCK_STREAM, 0);
	if (INVALID_SOCKET == listen_socket) {
		cout << "create listen socket failed !!! errocode:" << GetLastError() << endl;
		return -1;
	}

	struct sockaddr_in local = { 0 };
	local.sin_family = AF_INET;
	local.sin_port = htons(8080);
	local.sin_addr.s_addr = inet_addr("0.0.0.0");

	if (-1 == ::bind(listen_socket, (struct sockaddr*)&local, sizeof(local))) {
		cout << "bind socket failed !!! errocode:" << GetLastError() << endl;
		return -1;
	}

	if (-1 == ::listen(listen_socket, 10)) {
		cout << "start listen socket failed !!! errocode:" << GetLastError() << endl;
		return -1;
	}

	cout << "Server started, waiting for connections..." << endl;


	while (1) {
		SOCKET client_socket = accept(listen_socket, NULL, NULL);
		if (INVALID_SOCKET == client_socket) continue;

		cout << "New client accepted, adding to thread pool..." << endl;

		// 将客户端处理任务加入线程池队列
		threadPool.enqueue(handleClient, client_socket);
	
	}

	closesocket(listen_socket);
	WSACleanup();


	return 0;
}*/

#include<iostream>
#include<WinSock2.h>
#include<fstream>
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
#include<easyx.h>
#include "Thread_Pool.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
using namespace std;

#ifdef _WIN32
#include <openssl/applink.c>
#endif

std::mutex image_mutex;



// SSL全局初始化
bool init_ssl_library() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    return true;
}

// 创建SSL上下文
SSL_CTX* create_ssl_context(bool is_server) {
    const SSL_METHOD* method;
    SSL_CTX* ctx;

    if (is_server) {
        method = TLS_server_method();
    }
    else {
        method = TLS_client_method();
    }

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    return ctx;
}

// 配置服务器SSL上下文
bool configure_ssl_context(SSL_CTX* ctx) {
    // 加载服务器证书
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return false;
    }

    // 加载服务器私钥
    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return false;
    }

    // 验证私钥和证书是否匹配
    if (!SSL_CTX_check_private_key(ctx)) {
        cerr << "Private key does not match the certificate public key" << endl;
        return false;
    }

    return true;
}

// SSL读取函数 - 替换原来的recv
int ssl_read(SSL* ssl, void* buf, int num) {
    int ret = SSL_read(ssl, buf, num);
    if (ret < 0) {
        int ssl_error = SSL_get_error(ssl, ret);
        if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE) {
            return -1;
        }
        return 0; // 需要重试
    }
    return ret;
}

// SSL写入函数 - 替换原来的send
int ssl_write(SSL* ssl, const void* buf, int num) {
    int ret = SSL_write(ssl, buf, num);
    if (ret < 0) {
        int ssl_error = SSL_get_error(ssl, ret);
        if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE) {
            return -1;
        }
        return 0; // 需要重试
    }
    return ret;
}

// 修改后的客户端处理函数
void handleClient(SOCKET client_socket, SSL_CTX* ssl_ctx) {
    cout << "New client connected, handling in thread..." << endl;

    // 为这个连接创建SSL对象
    SSL* ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, client_socket);

    // 进行SSL握手
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        closesocket(client_socket);
        return;
    }

    cout << "SSL handshake completed" << endl;

    while (1) {
        char buffer[4096];
        long long fsize;

        // 使用SSL读取代替recv
        int ret = ssl_read(ssl, (char*)&fsize, sizeof(fsize));
        if (ret <= 0) break;

        std::lock_guard<std::mutex> lock(image_mutex);
        FILE* fp = fopen("s.jpg", "wb");

        while (fsize > 0) {
            int to_read = fsize > 4096 ? 4096 : static_cast<int>(fsize);
            ret = ssl_read(ssl, buffer, to_read);
            if (ret <= 0) {
                if (nullptr != fp)
                    fclose(fp);
                goto end;
            }
            fsize -= ret;
            if (nullptr != fp)
                fwrite(buffer, 1, ret, fp);
        }
        if (nullptr != fp)
            fclose(fp);

        // 加载并显示图片
        IMAGE img;
        loadimage(&img, TEXT("s.jpg"), 1280, 720);
        putimage(0, 0, &img);
    }
end:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(client_socket);
    cout << "Client disconnected" << endl;
}

int main() {

    // 初始化SSL库
    if (!init_ssl_library()) {
        cerr << "SSL library initialization failed" << endl;
        return -1;
    }

    // 创建SSL上下文
    SSL_CTX* ssl_ctx = create_ssl_context(true);
    if (!ssl_ctx) {
        cerr << "SSL context creation failed" << endl;
        return -1;
    }

    // 配置SSL上下文
    if (!configure_ssl_context(ssl_ctx)) {
        cerr << "SSL context configuration failed" << endl;
        SSL_CTX_free(ssl_ctx);
        return -1;
    }

    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    initgraph(1280, 720);

    ThreadPool threadPool(4);

    SOCKET listen_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (INVALID_SOCKET == listen_socket) {
        cout << "create listen socket failed !!! errocode:" << GetLastError() << endl;
        SSL_CTX_free(ssl_ctx);
        return -1;
    }

    struct sockaddr_in local = { 0 };
    local.sin_family = AF_INET;
    local.sin_port = htons(8080);
    local.sin_addr.s_addr = inet_addr("0.0.0.0");

    if (-1 == ::bind(listen_socket, (struct sockaddr*)&local, sizeof(local))) {
        cout << "bind socket failed !!! errocode:" << GetLastError() << endl;
        SSL_CTX_free(ssl_ctx);
        return -1;
    }

    if (-1 == ::listen(listen_socket, 10)) {
        cout << "start listen socket failed !!! errocode:" << GetLastError() << endl;
        SSL_CTX_free(ssl_ctx);
        return -1;
    }

    cout << "SSL Server started, waiting for connections..." << endl;

    while (1) {
        SOCKET client_socket = accept(listen_socket, NULL, NULL);
        if (INVALID_SOCKET == client_socket) continue;

        cout << "New client accepted, adding to thread pool..." << endl;

        // 传递SSL上下文到处理函数
        threadPool.enqueue(handleClient, client_socket, ssl_ctx);
    }

    closesocket(listen_socket);
    SSL_CTX_free(ssl_ctx);
    WSACleanup();

    return 0;
}