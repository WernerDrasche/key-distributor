#include "common.hpp"
#include <unordered_map>
#include <thread>
#include <condition_variable>
#include <vector>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <sqlite3.h>
#include <string.h>

inline std::ostream &operator<<(std::ostream &out, const sockaddr_in &addr) {
    return out << inet_ntoa(addr.sin_addr);
}

struct sys_error : std::exception {
    const char *fn;
    const char *error;
    int old_errno;

    sys_error(const char *fn) : fn(fn), error(strerror(errno)), old_errno(errno) {}

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

struct server {
    int fd;

    server(in_port_t port);
    ~server() { close(fd); }
    operator int() { return fd; }
};

struct database {
    sqlite3 *db;

    database(const char *filename) {
        if (sqlite3_open(filename, &db)) throw sql_error("sqlOpen", db);
    }

    ~database() {
        sqlite3_close(db);
    }

    static int user_row(void *arg, int ncols, char **colvals, char **colnames);
    std::vector<user> get_users();
    std::unordered_map<std::string, std::string> get_permissions(std::string_view username);
};

struct thread_dispatcher {
    static constexpr unsigned num_threads = 4;

    std::vector<std::thread> threads;
    connection conn;
    std::mutex mtx;
    std::condition_variable read;
    std::condition_variable write;

    thread_dispatcher();
    connection get_connection();
    void set_connection(connection &&conn);
    void join();
};
