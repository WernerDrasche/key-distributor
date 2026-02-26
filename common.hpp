#include <exception>
#include <iostream>
#include <cassert>

#include <cryptlib.h>

static constexpr size_t username_maxlen = 32;

struct crypt_error : std::exception {
    int status;
    const char *fn;
    char scratchbuf[64] = {0};

    crypt_error(const char *fn, int status) : status(status), fn(fn) {
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

    int fd;
    CRYPT_SESSION session;
    char *netbuf = nullptr;

    connection() = default;

    connection(connection &&other)
        : fd(other.fd)
        , session(other.session)
        , netbuf(other.netbuf)
    {
        other.invalidate();
    }

    connection &operator=(connection &&other) {
        assert(!alive());
        fd = other.fd;
        session = other.session;
        netbuf = other.netbuf;
        other.invalidate();
        return *this;
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

    int recv() {
        int len = recv(netbuf, netbuf_size - 1);
        netbuf[len] = 0;
        return len;
    }

    int recv(int length) {
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
        delete[] netbuf;
    }

    bool alive() { return netbuf; }
    void invalidate() { netbuf = nullptr; }

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
