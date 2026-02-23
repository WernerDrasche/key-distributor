#include "common.hpp"
#include <cstdlib>
#include <thread>
#include <condition_variable>
#include <unordered_set>

#include <signal.h>

bool running = true;

struct permission {
    std::string server;
    std::string key_filepath;

    permission(const char *server, const char *key_filepath)
        : server(server)
        , key_filepath(key_filepath) {}
};

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
        auto *set = (std::vector<user> *)(arg);
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

    std::vector<permission> get_permissions(std::string_view username) {
        static const char query[] = 
            "select s.name, k.filepath"
            " from users u"
            " join permissions p on u.id = p.user_id"
            " join servers s on s.id = p.key_id"
            " join keys k on k.id = p.key_id"
            " where u.name = ?;";
        sqlite3_stmt *stmt;
        int status = sqlite3_prepare_v2(db, query, sizeof(query), &stmt, NULL);
        if (status != SQLITE_OK) throw sql_error("sqlPreparePerm", db);
        status = sqlite3_bind_text(stmt, 1, username.cbegin(), username.size(), SQLITE_STATIC);
        if (status != SQLITE_OK) throw sql_error("sqlBindPerm", db);
        while ((status = sqlite3_step(stmt)) == SQLITE_ROW) {

        }
        if (status != SQLITE_DONE) throw sql_error("sqlStepPerm", db);
        return {};
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
    int len = sprintf(conn.netbuf, "Hello %s from server!", username.c_str());
    db.get_permissions(username);
    conn.sendall(len);
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
