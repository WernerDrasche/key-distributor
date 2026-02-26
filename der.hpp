#include <bit>
#include <inttypes.h>
#include <cstddef>
#include <span>
#include <memory>
#include <cassert>
#include <string.h>
#include <iomanip>

struct bigint {
    size_t size = 0;
    std::unique_ptr<char[]> val;

    size_t bitsize() const {
        uint8_t msb = val[0];
        int i = 0;
        while (!(msb & 0x80)) {
            ++i;
            msb <<= 1;
        }
        size_t res = std::max((size << 3) - i, 1UL);
        assert((res + 7) >> 3 == size);
        return res;
    }

    friend std::ostream &operator<<(std::ostream &out, const bigint &self) {
        auto flags = out.flags();
        out << std::hex << std::setfill('0');
        for (size_t i = 0; i < self.size; ++i) {
            out << std::setw(2) << ((int)self.val[i] & 0xff);
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
    bigint mod;
    bigint pub;
    bigint priv;
    bigint p1;
    bigint p2;
    bigint exp1;
    bigint exp2;
    bigint coeff;
};

rsa_private_key der_decode(std::span<char> der);
