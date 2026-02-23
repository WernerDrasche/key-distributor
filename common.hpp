#include <cstdio>
#include <exception>
#include <iostream>
#include <cassert>
#include <mutex>
#include <stdexcept>
#include <vector>
#include <string>

#include <sqlite3.h>
#include <cryptlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

static socklen_t addrsize = sizeof(sockaddr_in);
static constexpr size_t username_maxlen = 32;

inline std::ostream &operator<<(std::ostream &out, const sockaddr_in &addr) {
    return out << inet_ntoa(addr.sin_addr);
}

struct sys_error : std::exception {
    const char *fn;
    const char *error;
    int old_errno;

    sys_error(const char *fn) : fn(fn), old_errno(errno), error(strerror(errno)) {}

    const char *what() const noexcept override { return error; }

    friend std::ostream &operator<<(std::ostream &out, const sys_error &self) {
        return out << self.fn << ": " << self.error;
    }
};

struct sql_error : std::exception {
    const char *fn;
    const char *error;

    sql_error(const char *fn, sqlite3 *db) : fn(fn), error(sqlite3_errmsg(db)) {}
    sql_error(const char *fn, const char *error) : fn(fn), error(error) {}
    
    const char *what() const noexcept override { return error; }

    friend std::ostream &operator<<(std::ostream &out, const sql_error &self) {
        return out << self.fn << ": " << self.error;
    }
};

struct crypt_error : std::exception {
    const char *fn;
    char scratchbuf[64] = {0};

    crypt_error(const char *fn, int status) : fn(fn) {
        switch (status) {
            case CRYPT_ERROR_PARAM7...CRYPT_ERROR_PARAM1:
                snprintf(scratchbuf, sizeof(scratchbuf), "error in parameter %i", status * -1);
                break;
            case CRYPT_ERROR_NOTINITED:
                snprintf(scratchbuf, sizeof(scratchbuf), "data not initialized");
                break;
            case CRYPT_ERROR_COMPLETE:
                snprintf(scratchbuf, sizeof(scratchbuf), "operation complete, can't continue");
                break;
            case CRYPT_ERROR_READ:
                snprintf(scratchbuf, sizeof(scratchbuf), "cannot read item from object");
                break;
            case CRYPT_ERROR_PERMISSION:
                snprintf(scratchbuf, sizeof(scratchbuf), "permission error");
                break;
            case CRYPT_ERROR_BADDATA:
                snprintf(scratchbuf, sizeof(scratchbuf), "bad data");
                break;
            default:
                snprintf(scratchbuf, sizeof(scratchbuf), "status code %i", status);
                break;
        }
    }

    const char *what() const noexcept override {
        return scratchbuf;
    }

    friend std::ostream &operator<<(std::ostream &out, const crypt_error &self) {
        return out << self.fn << ": " << self.scratchbuf;
    }
};

struct server {
    int fd;

    server(in_port_t port) {
        fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (fd < 0) throw sys_error("socket");
        int opt = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int));
        sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_port = htons(port),
            .sin_addr{INADDR_ANY},
        };
        if (bind(fd, (sockaddr *)&addr, addrsize) < 0) throw sys_error("bind");
        if (listen(fd, 4) < 0) throw sys_error("listen");
    }

    ~server() { close(fd); }

    operator int() { return fd; }
};

struct user {
    //IMPORTANT: don't change field order
    std::string name;
    std::string password;

    user() = default;
    user(const char *name, const char *password) 
        : name(name)
        , password(password) {}
};

struct connection {
    static constexpr size_t netbuf_size = 4096;

    int fd = -1;
    sockaddr_in addr;
    CRYPT_SESSION session;
    char *netbuf;

    connection() = default;

    connection(connection &&other)
        : fd(other.fd)
        , addr(other.addr)
        , session(other.session)
        , netbuf(other.netbuf)
    {
        other.invalidate();
    }

    connection &operator=(connection &&other) {
        assert(!alive());
        fd = other.fd;
        addr = other.addr;
        session = other.session;
        netbuf = other.netbuf;
        other.invalidate();
        return *this;
    }
    
    virtual std::vector<user> get_users() { throw std::logic_error("unreachable"); }

    void init_tls(CRYPT_SESSION_TYPE type) {
        int status;
        status = cryptCreateSession(&session, CRYPT_UNUSED, type);
        if (cryptStatusError(status)) throw crypt_error("createSession", status);
        std::vector users = get_users();
        for (const user &user : users) {
            cryptSetAttributeString(session, CRYPT_SESSINFO_USERNAME, user.name.c_str(), user.name.size());
            cryptSetAttributeString(session, CRYPT_SESSINFO_PASSWORD, user.password.c_str(), user.password.size());
        }
        cryptSetAttribute(session, CRYPT_SESSINFO_NETWORKSOCKET, fd);
        cryptSetAttribute(session, CRYPT_SESSINFO_ACTIVE, true);
        std::cout << "TLS ready" << std::endl;
    }

    std::string username() {
        char username[username_maxlen];
        int len;
        int status = cryptGetAttributeString(session, CRYPT_SESSINFO_USERNAME, username, &len);
        if (cryptStatusError(status)) throw crypt_error("getAttributeUsername", status);
        return username;
    }

    void sendall(int length) {
        assert(length <= netbuf_size);
        sendall(netbuf, length);
    }

    void sendall(const void *buffer, int length) {
        int written = 0;
        int bytesCopied;
        while (written < length) {
            int status = cryptPushData(session, (char *)buffer + written, length - written, &bytesCopied);
            if (cryptStatusError(status)) throw crypt_error("pushData", status);
            written += bytesCopied;
            status = cryptFlushData(session);
            if (cryptStatusError(status)) throw crypt_error("flushData", status);
        }
    }

    int recv(int length = netbuf_size) {
        return recv(netbuf, length);
    }

    int recv(void *buffer, int length) {
        int bytesCopied;
        int status = cryptPopData(session, buffer, length, &bytesCopied);
        if (cryptStatusError(status))
            throw crypt_error("popData", status);
        assert(bytesCopied > 0);
        return bytesCopied;
    }

    ~connection() { 
        if (!alive()) return;
        cryptDestroySession(session);
        close(fd); 
        delete[] netbuf;
    }

    bool alive() { return fd != -1; }
    void invalidate() { fd = -1; }

    operator int() { return fd; }
};

template <typename T>
struct init_library {};

struct cryptlib {};

template <>
struct init_library<cryptlib> {
    init_library() {
        int status = cryptInit();
        if (cryptStatusError(status)) throw crypt_error("init", status);
    }

    ~init_library() {
        cryptEnd();
    }
};

inline int invoke_with_error_handling(void (*fn)()) {
    try {
        fn();
    } catch (const crypt_error &e) {
        std::cout << e << std::endl;
        return EXIT_FAILURE;
    } catch (const sql_error &e) {
        std::cout << e << std::endl;
        return EXIT_FAILURE;
    } catch (const sys_error &e) {
        if (e.old_errno != EINTR) {
            std::cout << e << std::endl;
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}
