#include "common.hpp"
#include "base64.hpp"
#include "der.hpp"
#include <string_view>
#include <fstream>

#include <cryptlib.h>

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

struct connection_ssh : connection {
    connection_ssh(std::string_view server, const rsa_private_key &key) {
        CRYPT_PKCINFO_RSA rsa_key;
        CRYPT_CONTEXT rsa_ctx;

        int status = cryptCreateContext(&rsa_ctx, CRYPT_UNUSED, CRYPT_ALGO_RSA);
        if (cryptStatusError(status)) throw crypt_error("createContext", status);
        cryptSetAttributeString(rsa_ctx, CRYPT_CTXINFO_LABEL, "RSA", 3);

        cryptInitComponents(&rsa_key, CRYPT_KEYTYPE_PRIVATE);
        cryptSetComponent((&rsa_key)->n, key.modulus.val.get(), key.modulus.size << 3);
        cryptSetComponent((&rsa_key)->e, key.exp_pub.val.get(), key.exp_pub.size << 3);
        cryptSetComponent((&rsa_key)->d, key.exp_priv.val.get(), key.exp_priv.size << 3);

        status = cryptSetAttributeString(rsa_ctx, CRYPT_CTXINFO_KEY_COMPONENTS, &rsa_key, sizeof(rsa_key));
        if (cryptStatusError(status)) throw crypt_error("setKeyComponents", status);
        cryptDestroyComponents(&rsa_key);
        int crypt_key;
        status = cryptGetAttribute(rsa_ctx, CRYPT_CTXINFO_KEY, &crypt_key);
        if (cryptStatusError(status)) throw crypt_error("getKey", status);

        status = cryptCreateSession(&session, CRYPT_UNUSED, CRYPT_SESSION_SSH);
        if (cryptStatusError(status)) throw crypt_error("createSessionSSH", status);
        status = cryptSetAttributeString(session, CRYPT_SESSINFO_SERVER_NAME, server.begin(), server.size());
        if (cryptStatusError(status)) throw crypt_error("setServerSSH", status);
        cryptSetAttribute(session, CRYPT_SESSINFO_PRIVATEKEY, crypt_key);
        if (cryptStatusError(status)) throw crypt_error("setKey", status);
        status = cryptSetAttribute(session, CRYPT_SESSINFO_ACTIVE, true);
        if (cryptStatusError(status)) throw crypt_error("setActiveSSH", status);
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

std::pair<std::string, std::string> get_server_key(connection conn) {
    conn.recv();
    char *buf = conn.netbuf;
    int n = buf++[0]; //this is a char
    if (n == 0) throw "no permission";
    std::vector<std::string_view> servers;
    servers.reserve(n);
    for (int i = 1; i <= n; ++i) {
        servers.emplace_back(buf);
        std::cout << i << ") " << buf << '\n';
        buf += strlen(buf) + 1;
    }
    if (n > 1) {
        n = choice(n);
    }
    std::string server(servers[n - 1]);
    conn.netbuf[0] = n;
    conn.sendall(1);
    conn.recv();
    std::string key = conn.netbuf;
    if (key.empty()) throw "bad key";
    return {server, key};
}

std::string_view strip_pem_header(std::string_view key) {
    auto tmp = key.find("-----BEGIN");
    auto start = key.find('\n', tmp) + tmp;
    auto end = key.find("-----END", start);
    return key.substr(start, end - start);
}

void main_thread() {
    init_library<cryptlib> lib;
    auto [server, key] = get_server_key(connection_c("0.0.0.0", 12345));
    std::cout << server << '\n';
    std::string der = base64_decode(strip_pem_header(key), true);
    rsa_private_key priv = rsa_private_key::decode(der);

    std::cout << "modulus:\n" << priv.modulus << "\n\n";
    std::cout << "private:\n" << priv.exp_priv << "\n\n";
    std::cout << "public:\n" << priv.exp_pub << "\n\n";

    connection_ssh conn(server, priv);
    conn.recv();
}

void test_der() {
    std::ifstream f("test.der", std::ios_base::binary);
    static char buf[8192];
    size_t len = f.read(buf, sizeof(buf)).gcount();
    std::span der(buf, len);
    try {
        rsa_private_key key = rsa_private_key::decode(der);
        assert(key.modulus.size == 257);
        assert(key.exp_priv.size == 256);
        assert(key.exp_pub.size == 3);
    } catch (const char *e) {
        std::cout << e;
    }
}

int main() {
    return invoke_with_error_handling(main_thread);
}
