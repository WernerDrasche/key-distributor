#include "der.hpp"

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
    size_t real_len = len;
    int i;
    for (i = 0; i < len && !der[i]; ++i);
    if (i == len) --i;
    real_len -= i;
    char *val = new char[real_len];
    memcpy(val, der.data() + i, real_len);
    der = der.subspan(len);
    return {
        .size = real_len,
        .val = std::unique_ptr<char[]>(val),
    };
}

rsa_private_key der_decode(std::span<char> der) {
    auto [_, len] = consume(der, sequence);
    assert(der.size() == len);
    bigint version = read_int(der);
    assert(version.size == 1);
    assert(version.val[0] == 0);
    return {
        .mod = read_int(der),
        .pub = read_int(der),
        .priv = read_int(der),
        .p1 = read_int(der),
        .p2 = read_int(der),
        .exp1 = read_int(der),
        .exp2 = read_int(der),
        .coeff = read_int(der),
    };
}
