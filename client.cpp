#include "common.hpp"
#include "base64.hpp"
#include "der.hpp"
#include <limits>
#include <vector>
#include <fstream>
#include <unordered_map>

#include <cryptlib.h>

std::unordered_map<std::string, std::string> config;
const char *default_hostname = "wernerdrasche.de";

user get_user() {
    user user;
    if (config.find("username") != config.end()) {
        user.name = config["username"];
    } else {
        std::cout << "username: ";
        std::cin >> user.name;
        std::cin.ignore(1);
    }
    if (config.find("password") != config.end()) {
        user.password = config["password"];
    } else {
        std::cout << "password: ";
        std::cin >> user.password;
        std::cin.ignore(1);
    }
    return user;
}

struct connection_c : connection {
    connection_c(std::string_view server, uint16_t port) {
        netbuf = new char[netbuf_size];
        int status;
        status = cryptCreateSession(&session, CRYPT_UNUSED, CRYPT_SESSION_TLS);
        if (cryptStatusError(status)) throw crypt_error("createSession", status);
        user user = get_user();
        cryptSetAttributeString(session, CRYPT_SESSINFO_USERNAME, user.name.c_str(), user.name.size());
        cryptSetAttributeString(session, CRYPT_SESSINFO_PASSWORD, user.password.c_str(), user.password.size());
        cryptSetAttributeString(session, CRYPT_SESSINFO_SERVER_NAME, server.data(), server.size());
        cryptSetAttribute(session, CRYPT_SESSINFO_SERVER_PORT, port);
        status = cryptSetAttribute(session, CRYPT_SESSINFO_ACTIVE, true);
        if (cryptStatusError(status)) throw crypt_error("activateTLS", status);
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

        cryptSetComponent(rsa_key.n, key.mod.val.get(), key.mod.bitsize());
        cryptSetComponent(rsa_key.e, key.pub.val.get(), key.pub.bitsize());
        cryptSetComponent(rsa_key.d, key.priv.val.get(), key.priv.bitsize());
        cryptSetComponent(rsa_key.p, key.p1.val.get(), key.p1.bitsize());
        cryptSetComponent(rsa_key.q, key.p2.val.get(), key.p2.bitsize());
        cryptSetComponent(rsa_key.e1, key.exp1.val.get(), key.exp1.bitsize());
        cryptSetComponent(rsa_key.e2, key.exp2.val.get(), key.exp2.bitsize());
        cryptSetComponent(rsa_key.u, key.coeff.val.get(), key.coeff.bitsize());

        status = cryptSetAttributeString(rsa_ctx, CRYPT_CTXINFO_KEY_COMPONENTS, &rsa_key, sizeof(rsa_key));
        if (cryptStatusError(status)) throw crypt_error("setKeyComponents", status);
        cryptDestroyComponents(&rsa_key);

        status = cryptCreateSession(&session, CRYPT_UNUSED, CRYPT_SESSION_SSH);
        if (cryptStatusError(status)) throw crypt_error("createSessionSSH", status);
        status = cryptSetAttributeString(session, CRYPT_SESSINFO_SERVER_NAME, server.begin(), server.size());
        if (cryptStatusError(status)) throw crypt_error("setServerSSH", status);
        cryptSetAttribute(session, CRYPT_SESSINFO_PRIVATEKEY, rsa_ctx);
        if (cryptStatusError(status)) throw crypt_error("setKey", status);
        status = cryptSetAttribute(session, CRYPT_SESSINFO_ACTIVE, true);
        if (cryptStatusError(status)) {
            char *errmsg = new char[1024];
            int len;
            int _ = cryptGetAttributeString(session, CRYPT_ATTRIBUTE_ERRORMESSAGE, errmsg, &len);
            fputs(errmsg, stderr);
            puts("");
            delete[] errmsg;
            throw crypt_error("setActiveSSH", status);
        }
        netbuf = new char[netbuf_size];
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
    try {
        conn.recv();
    } catch (const crypt_error &e) {
        if (e.status == CRYPT_ERROR_NOTINITED) throw "invalid login credentials";
        throw;
    }
    char *buf = conn.netbuf;
    int n = buf++[0]; //this is a char
    if (n == 0) throw "no permission";
    std::vector<std::string_view> servers;
    servers.reserve(n);
    for (int i = 1; i <= n; ++i) {
        servers.emplace_back(buf);
        buf += strlen(buf) + 1;
    }
    if (n > 1) {
        int i = 1;
        for (auto server : servers) {
            std::cout << i++ << ") " << server << '\n';
        }
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
    auto tmp = key.find("-----BEGIN RSA");
    auto start = key.find('\n', tmp) + tmp;
    auto end = key.find("-----END RSA", start);
    return key.substr(start, end - start);
}

void handle_ssh(connection &conn) {
    size_t len = 0;
    while (true) {
        bool end_of_text = false; // we want input (3)
        do {
            int n = conn.recv();
            std::cout << conn.netbuf + len;
            len = 0;
            end_of_text = conn.netbuf[n - 1] == 3;
        } while (!end_of_text);
        len = std::cin.getline(conn.netbuf, conn.netbuf_size - 1).gcount() - 1;
        conn.netbuf[len++] = 10;
        conn.netbuf[len] = 0;
        conn.sendall(len++);
    }
}

void main_thread() {
    init_library<cryptlib> lib;
    std::string hostname;
    if (config.find("hostname") != config.end()) {
        hostname = config["hostname"].c_str();
    } else {
        std::cout << "hostname: ";
        std::cin >> hostname;
        std::cin.ignore(1);
    }
    auto [server, key] = get_server_key(connection_c(hostname.c_str(), 5555));
    std::string der = base64_decode(strip_pem_header(key), true);
    rsa_private_key priv = der_decode(der);
    /*
    std::cout << "modulus: " << priv.mod.bitsize() << '\n' << priv.mod << "\n\n";
    std::cout << "private: " << priv.priv.bitsize() << '\n' << priv.priv << "\n\n";
    std::cout << "public: " << priv.pub.bitsize() << '\n' << priv.pub << "\n\n";
    */
    connection_ssh conn(server, priv);
    try {
        handle_ssh(conn);
    } catch (const crypt_error &e) {
        if (e.status != CRYPT_ERROR_COMPLETE) throw;
    }
}

/*
void test_der() {
    std::ifstream f("test.der", std::ios_base::binary);
    static char buf[8192];
    size_t len = f.read(buf, sizeof(buf)).gcount();
    std::span der(buf, len);
    try {
        rsa_private_key key = rsa_private_key::decode(der);
        assert(key.mod.size == 257);
        assert(key.priv.size == 256);
        assert(key.pub.size == 3);
    } catch (const char *e) {
        std::cout << e;
    }
}
*/

void init_config() {
    const char *filename = "config.txt";
    std::fstream file(filename);
    if (!file.is_open()) {
        std::ofstream file(filename, std::ios_base::out | std::ios_base::trunc);
        file << "*WARN: whitespace is not ignored*\nhostname="
             << default_hostname
             << "\nusername=\npassword=\n";
        config["hostname"] = default_hostname;
        return;
    }
    bool invalid = false;
    char line[128];
    if (file.peek() == '*') {
        file.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }
    while (file.getline(line, sizeof(line))) {
        std::string_view s = line;
        size_t eq = s.find('=');
        if (eq == s.size()) {
            invalid = true;
            break;
        }
        std::string key(s.substr(0, eq));
        std::string val(s.substr(eq + 1));
        if (!key.size()) {
            invalid = true;
            break;
        }
        if (!val.size()) continue;
        config[std::move(key)] = std::move(val);
    }
    if (invalid) {
        std::cerr << "WARN: config file invalid (must be 'key=value')" << std::endl;
    }
}

int main() {
    init_config();
    int status = EXIT_FAILURE;
    try {
        main_thread();
        status = EXIT_SUCCESS;
    } catch (const crypt_error &e) {
        std::cerr << e << std::endl;
    } catch (const char *e) {
        std::cerr << e << std::endl;
    }
    if (status == EXIT_FAILURE) {
        std::cout << "press enter to close" << std::endl;
        std::cin.get();
    } 
    return status;
}
