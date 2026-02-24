#include <inttypes.h>
#include <cstddef>
#include <span>
#include <memory>
#include <cassert>
#include <string.h>

struct bigint {
    size_t size = 0;
    std::unique_ptr<char[]> val;

    friend std::ostream &operator<<(std::ostream &out, const bigint &self) {
        auto flags = out.flags();
        out << std::hex;
        for (size_t i = 0; i < self.size; ++i) {
            out << ((int)self.val[i] & 0xff);
        }
        out.flags(flags);
        return out;
    }
};

enum der_tag {
    sequence = 0x30,
    integer = 0x02,
};

struct rsa_private_key {
    //IMPORTANT: don't change field order
    bigint modulus;
    bigint exp_pub;
    bigint exp_priv;

    static std::pair<size_t, size_t> length(std::span<char> der) {
        size_t len = 0;
        size_t consumed = 1;
        uint8_t lenlen = der[0];
        if (!(lenlen & 0x80)) return { consumed, lenlen };
        lenlen &= 0x7f;
        if (lenlen > sizeof(len)) throw "DER sequence too large";
        for (uint8_t i = 1; i <= lenlen; ++i) {
            uint8_t b = der[i];
            len <<= 8;
            len |= b;
            ++consumed;
        }
        return {consumed, len};
    }

    static std::pair<size_t, size_t> consume(std::span<char> &der, der_tag tag) {
        std::pair<size_t, size_t> res;
        if (der[0] != tag) throw "bad DER encoding";
        res = length(der.subspan(1));
        ++res.first;
        der = der.subspan(res.first);
        return res;
    }

    static bigint read_int(std::span<char> &der) {
        auto [cons, len] = consume(der, integer);
        char *val = new char[len];
        memcpy(val, der.data(), len);
        der = der.subspan(len);
        return {
            .size = len,
            .val = std::unique_ptr<char[]>(val),
        };
    }

    static rsa_private_key decode(std::span<char> der) {
        auto [_, len] = consume(der, sequence);
        assert(der.size() == len);
        bigint version = read_int(der);
        assert(version.size == 1);
        assert(version.val[0] == 0);
        return {
            .modulus = read_int(der),
            .exp_pub = read_int(der),
            .exp_priv = read_int(der),
        };
    }
};

