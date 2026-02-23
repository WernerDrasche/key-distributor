#include "common.hpp"
#include <cstdlib>
#include <string>
#include <thread>
#include <condition_variable>
#include <unordered_map>

#include <signal.h>

bool running = true;

struct database {
    sqlite3 *db;

    database(const char *filename) {
        if (sqlite3_open(filename, &db)) throw sql_error("sqlOpen", db);
    }

    ~database() {
        sqlite3_close(db);
    }

    static int user_row(void *arg, int ncols, char **colvals, char **colnames) {
        if (ncols != 3) return 1;
        auto *set = static_cast<std::vector<user> *>(arg);
        int id = std::stoi(colvals[0]);
        set->emplace_back(colvals[1], colvals[2]);
        return 0;
    }

    std::vector<user> get_users() {
        static const char query[] = "select * from users;";
        std::vector<user> users;
        char *errmsg;
        int status = sqlite3_exec(db, query, user_row, &users, &errmsg);
        if (status != SQLITE_OK) throw sql_error("sqlExec", errmsg);
        return users;
    }

    std::unordered_map<std::string, std::string> get_permissions(std::string_view username) {
        static const char query[] = 
            "select s.name, k.filepath"
            " from users u"
            " join permissions p on u.id = p.user_id"
            " join keys k on k.id = p.key_id"
            " join servers s on s.id = k.server_id"
            " where u.name = ?;";
        sqlite3_stmt *stmt;
        int status = sqlite3_prepare_v2(db, query, sizeof(query), &stmt, NULL);
        if (status != SQLITE_OK) throw sql_error("sqlPreparePerm", db);
        status = sqlite3_bind_text(stmt, 1, username.cbegin(), username.size(), SQLITE_STATIC);
        if (status != SQLITE_OK) throw sql_error("sqlBindPerm", db);
        std::unordered_map<std::string, std::string> perms;
        while ((status = sqlite3_step(stmt)) == SQLITE_ROW) {
            auto server = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
            auto key_filepath = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
            if (!perms.try_emplace(server, key_filepath).second) {
                //TODO: lock output
                std::cerr << "WARN: " << username << " has multiple keys for " << server << '\n';
            }
        }
        if (status != SQLITE_DONE) throw sql_error("sqlStepPerm", db);
        sqlite3_finalize(stmt);
        return perms;
    }
} db("config.db");

struct connection_s : connection {
    connection_s(server &server) {
        fd = accept(server, (sockaddr *)&addr, &addrsize);
        if (fd < 0) throw sys_error("accept");
        std::cout << "connection from " << addr << std::endl;
        netbuf = new char[netbuf_size];
        init_tls(CRYPT_SESSION_TLS_SERVER);
    }

    std::vector<user> get_users() override {
        return db.get_users();
    }
};

struct thread_dispatcher;

void handle();

struct thread_dispatcher {
    static constexpr unsigned num_threads = 4;

    std::vector<std::thread> threads;
    connection conn;
    std::mutex mtx;
    std::condition_variable read;
    std::condition_variable write;

    thread_dispatcher() {
        threads.reserve(num_threads);
        for (unsigned i = 0; i < num_threads; ++i) {
            threads.emplace_back(handle);
        }
    }

    connection get_connection() {
        std::unique_lock lock(mtx);
        if (!conn.alive()) {
            read.wait(lock);
        }
        write.notify_one();
        return std::move(conn);
    }

    void set_connection(connection &&conn) {
        std::unique_lock lock(mtx);
        if (this->conn.alive()) {
            write.wait(lock);
        }
        this->conn = std::move(conn);
        assert(this->conn.alive());
        read.notify_one();
    }

    void join() {
        read.notify_all();
        for (auto &thread : threads) {
            thread.join();
        }
    }
} dispatcher;

void worker_thread() {
    connection conn = dispatcher.get_connection();
    if (!running) return;
    dispatcher.write.notify_one();
    std::this_thread::sleep_for(std::chrono::seconds(2));
    std::string username = conn.username();
    auto perms = db.get_permissions(username);
    char *buf = conn.netbuf;
    buf++[0] = perms.size();
    int len = 1;
    std::vector<std::string_view> keys;
    keys.reserve(perms.size());
    for (const auto &perm : perms) {
        keys.emplace_back(perm.second);
        int single_len = snprintf(buf, conn.netbuf_size - len, "%s", perm.first.c_str()) + 1;
        buf += single_len;
        len += single_len;
    }
    if (len >= conn.netbuf_size) throw "netbuf full";
    conn.sendall(len);
    if (perms.empty()) return;
    conn.recv(1);
    int sel = conn.netbuf[0] - 1;
    std::string_view key = keys.at(sel);
    std::cout << key << std::endl;
}

void handle() {
    while (running) {
        invoke_with_error_handling(worker_thread);
    }
}

void signal_handler(int) {
    running = false;
}

void install_signal_handler() {
    struct sigaction action = {};
    action.sa_handler = signal_handler;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, nullptr) < 0) throw sys_error("sigaction");
}

void main_thread() {
    install_signal_handler();
    init_library<cryptlib> lib;
    server serv(12345);
    while (running) {
        dispatcher.set_connection(connection_s(serv));
    }
}

int main() {
    int status = invoke_with_error_handling(main_thread);
    std::cout << "shutting down" << std::endl;
    running = false;
    dispatcher.join();
    return status;
}
