#include "common.hpp"

struct connection_c : connection {
    connection_c(const char *ip, in_port_t port) {
        fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (fd < 0) throw sys_error("socket");
        inet_aton(ip, &addr.sin_addr);
        addr.sin_port = htons(port);
        addr.sin_family = AF_INET;
        if (connect(fd, (sockaddr *)&addr, addrsize) < 0) throw sys_error("connect");
        netbuf = new char[netbuf_size];
        init_tls(CRYPT_SESSION_TLS);
    }

    std::vector<user> get_users() override {
        return {{"simon", "1234"}};
        user user;
        std::cout << "username: ";
        std::cin >> user.name;
        std::cout << "password: ";
        std::cin >> user.password;
        return {user};
    }
};

unsigned choice(unsigned n) {
    int choice;
    do {
        std::cout << "Select [1-" << n << "]: ";
        std::cin >> choice;
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    } while (choice < 1 || choice > n);
    return choice;
}

void handle(connection &conn) {
    conn.recv();
    char *buf = conn.netbuf;
    int n = buf++[0]; //this is a char
    if (n == 0) throw "no permission";
    for (int i = 1; i <= n; ++i) {
        std::cout << i << ") " << buf << '\n';
        buf += strlen(buf) + 1;
    }
    if (n > 1) {
        n = choice(n);
    }
    conn.netbuf[0] = n;
    conn.sendall(1);
}

void main_thread() {
    init_library<cryptlib> lib;
    connection_c conn("0.0.0.0", 12345);
    handle(conn);
}

int main() {
    return invoke_with_error_handling(main_thread);
}
