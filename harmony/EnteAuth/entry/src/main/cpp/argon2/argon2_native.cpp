// Argon2id (RFC 9106) + Blake2b 原生实现（NAPI）。
// 由宿主机三方交叉验证（@noble/hashes + libsodium-sumo，63 项向量全绿）的
// argon2-port.js 1:1 移植；与官方 app 的 KDF 层对齐（Rust/原生 Argon2id v0x13,
// p=1, dkLen=32, libsodium 兼容参数）。ArkVM 解释执行同算法慢约两个数量级
// （自测 9MiB 需 ~7s），故 KDF 全部走本原生库，wasm/ArkTS 内不跑大参数 pwhash。

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#ifndef ARGON2_HOST_TEST
#include "napi/native_api.h"
#endif

namespace {

// ---------------- Blake2b (unkeyed, outLen 1..64) ----------------

const uint64_t B2B_IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
};

const uint8_t BSIGMA[12][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
};

inline uint64_t rotr64(uint64_t x, unsigned n) {
    return (x >> n) | (x << (64 - n));
}

class Blake2b {
public:
    explicit Blake2b(size_t outLen) : outLen_(outLen), length_(0), pos_(0) {
        for (int i = 0; i < 8; i++) {
            h_[i] = B2B_IV[i];
        }
        h_[0] ^= (static_cast<uint64_t>(outLen) | 0x01010000u);
        memset(buf_, 0, sizeof(buf_));
    }

    void update(const uint8_t *data, size_t len) {
        size_t pos = 0;
        while (pos < len) {
            if (pos_ == 128) {
                compress(reinterpret_cast<const uint64_t *>(buf_), false);
                pos_ = 0;
            }
            size_t take = 128 - pos_;
            if (take > len - pos) {
                take = len - pos;
            }
            memcpy(buf_ + pos_, data + pos, take);
            pos_ += take;
            length_ += take;
            pos += take;
        }
    }

    std::vector<uint8_t> digest() {
        memset(buf_ + pos_, 0, 128 - pos_);
        compress(reinterpret_cast<const uint64_t *>(buf_), true);
        std::vector<uint8_t> out(outLen_);
        for (size_t j = 0; j < outLen_; j++) {
            out[j] = static_cast<uint8_t>((h_[j >> 3] >> (8 * (j & 7))) & 0xff);
        }
        return out;
    }

private:
    void compress(const uint64_t *m, bool isLast) {
        uint64_t w[32];
        for (int i = 0; i < 8; i++) {
            w[i] = h_[i];
            w[8 + i] = B2B_IV[i];
        }
        w[12] = B2B_IV[4] ^ (length_ & 0xffffffffu);
        w[13] = B2B_IV[5] ^ (length_ >> 32);
        if (isLast) {
            w[14] = ~w[14];
        }
        for (int r = 0; r < 12; r++) {
            const uint8_t *s = BSIGMA[r];
            G(w, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            G(w, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            G(w, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            G(w, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            G(w, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            G(w, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            G(w, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            G(w, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for (int i = 0; i < 8; i++) {
            h_[i] ^= w[i] ^ w[8 + i];
        }
    }

    // RFC 7693：G 每次消费两个消息字 x、y
    static void G(uint64_t *w, uint32_t a, uint32_t b, uint32_t c, uint32_t d,
                  uint64_t x, uint64_t y) {
        w[a] = w[a] + w[b] + x;
        w[d] = rotr64(w[d] ^ w[a], 32);
        w[c] = w[c] + w[d];
        w[b] = rotr64(w[b] ^ w[c], 24);
        w[a] = w[a] + w[b] + y;
        w[d] = rotr64(w[d] ^ w[a], 16);
        w[c] = w[c] + w[d];
        w[b] = rotr64(w[b] ^ w[c], 63);
    }

    size_t outLen_;
    uint64_t h_[8];
    uint8_t buf_[128];
    uint64_t length_;
    size_t pos_;
};

// ---------------- Argon2id (RFC 9106) ----------------

// fBlaMka(x, y) = x + y + 2 * (low32(x) * low32(y))，64 位环绕
inline uint64_t fBlaMka(uint64_t x, uint64_t y) {
    uint64_t xy = static_cast<uint64_t>(static_cast<uint32_t>(x)) *
                  static_cast<uint64_t>(static_cast<uint32_t>(y));
    return x + y + 2 * xy;
}

inline void a2G(uint64_t *w, uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
    uint64_t A = w[a];
    uint64_t B = w[b];
    uint64_t C = w[c];
    uint64_t D = w[d];
    A = fBlaMka(A, B);
    D = rotr64(D ^ A, 32);
    C = fBlaMka(C, D);
    B = rotr64(B ^ C, 24);
    A = fBlaMka(A, B);
    D = rotr64(D ^ A, 16);
    C = fBlaMka(C, D);
    B = rotr64(B ^ C, 63);
    w[a] = A;
    w[b] = B;
    w[c] = C;
    w[d] = D;
}

inline void a2P(uint64_t *w, uint32_t i0, uint32_t i1, uint32_t i2, uint32_t i3,
                uint32_t i4, uint32_t i5, uint32_t i6, uint32_t i7, uint32_t i8,
                uint32_t i9, uint32_t i10, uint32_t i11, uint32_t i12, uint32_t i13,
                uint32_t i14, uint32_t i15) {
    a2G(w, i0, i4, i8, i12);
    a2G(w, i1, i5, i9, i13);
    a2G(w, i2, i6, i10, i14);
    a2G(w, i3, i7, i11, i15);
    a2G(w, i0, i5, i10, i15);
    a2G(w, i1, i6, i11, i12);
    a2G(w, i2, i7, i8, i13);
    a2G(w, i3, i4, i9, i14);
}

// 压缩一个 1KiB 块：tmp = X xor Y（写入 out），置换，out ^= tmp
void a2Block(uint64_t *x, size_t xPos, size_t yPos, size_t outPos, bool needXor) {
    uint64_t tmp[128];
    if (needXor) {
        for (int i = 0; i < 128; i++) {
            uint64_t r = x[xPos + i] ^ x[yPos + i];
            tmp[i] = r;
            x[outPos + i] ^= r;
        }
    } else {
        for (int i = 0; i < 128; i++) {
            uint64_t r = x[xPos + i] ^ x[yPos + i];
            tmp[i] = r;
            x[outPos + i] = r;
        }
    }
    for (int i = 0; i < 128; i += 16) {
        a2P(tmp, i, i + 1, i + 2, i + 3, i + 4, i + 5, i + 6, i + 7,
            i + 8, i + 9, i + 10, i + 11, i + 12, i + 13, i + 14, i + 15);
    }
    for (int i = 0; i < 16; i += 2) {
        a2P(tmp, i, i + 1, i + 16, i + 17, i + 32, i + 33, i + 48, i + 49,
            i + 64, i + 65, i + 80, i + 81, i + 96, i + 97, i + 112, i + 113);
    }
    for (int i = 0; i < 128; i++) {
        x[outPos + i] ^= tmp[i];
    }
}

// 变长输出哈希 H'：T = LE32(dkLen)；dkLen<=64 直出，否则 32 字节级联
std::vector<uint8_t> hp(const uint8_t *a, size_t aLen, uint32_t dkLen) {
    uint8_t t[4] = {static_cast<uint8_t>(dkLen & 0xff),
                    static_cast<uint8_t>((dkLen >> 8) & 0xff),
                    static_cast<uint8_t>((dkLen >> 16) & 0xff),
                    static_cast<uint8_t>((dkLen >> 24) & 0xff)};
    if (dkLen <= 64) {
        Blake2b b(dkLen);
        b.update(t, 4);
        b.update(a, aLen);
        return b.digest();
    }
    std::vector<uint8_t> out(dkLen);
    Blake2b b(64);
    b.update(t, 4);
    b.update(a, aLen);
    std::vector<uint8_t> v = b.digest();
    memcpy(out.data(), v.data(), 32);
    size_t pos = 32;
    for (; dkLen - pos > 64; pos += 32) {
        Blake2b b2(64);
        b2.update(v.data(), v.size());
        v = b2.digest();
        memcpy(out.data() + pos, v.data(), 32);
    }
    Blake2b bl(dkLen - pos);
    bl.update(v.data(), v.size());
    std::vector<uint8_t> last = bl.digest();
    memcpy(out.data() + pos, last.data(), dkLen - pos);
    return out;
}

void putLe32(std::vector<uint8_t> &out, size_t at, uint32_t v) {
    out[at] = static_cast<uint8_t>(v & 0xff);
    out[at + 1] = static_cast<uint8_t>((v >> 8) & 0xff);
    out[at + 2] = static_cast<uint8_t>((v >> 16) & 0xff);
    out[at + 3] = static_cast<uint8_t>((v >> 24) & 0xff);
}

void blakeLe32(Blake2b &b, uint32_t v) {
    uint8_t t[4] = {static_cast<uint8_t>(v & 0xff),
                    static_cast<uint8_t>((v >> 8) & 0xff),
                    static_cast<uint8_t>((v >> 16) & 0xff),
                    static_cast<uint8_t>((v >> 24) & 0xff)};
    b.update(t, 4);
}

uint32_t indexAlpha(uint32_t r, uint32_t s, uint32_t laneLen, uint32_t segmentLen,
                    uint32_t index, uint32_t randL, bool sameLane) {
    uint32_t area;
    if (r == 0) {
        if (s == 0) {
            area = index - 1;
        } else if (sameLane) {
            area = s * segmentLen + index - 1;
        } else {
            area = s * segmentLen - (index == 0 ? 1 : 0);
        }
    } else if (sameLane) {
        area = laneLen - segmentLen + index - 1;
    } else {
        area = laneLen - segmentLen - (index == 0 ? 1 : 0);
    }
    uint32_t startPos = (r != 0 && s != 3) ? (s + 1) * segmentLen : 0;
    uint64_t rand = static_cast<uint64_t>(randL) * randL; // randL^2（64 位）
    uint32_t randHigh = static_cast<uint32_t>(rand >> 32);
    uint64_t prod = static_cast<uint64_t>(area) * randHigh;
    uint32_t areaHigh = static_cast<uint32_t>(prod >> 32);
    uint64_t rel = area - 1 - areaHigh;
    return static_cast<uint32_t>((startPos + rel) % laneLen);
}

// memLimitBytes: libsodium 风格内存上限（字节）；opsLimit: t；p: lane 数（生产恒 1）
std::vector<uint8_t> argon2idCore(const uint8_t *pwd, size_t pwdLen,
                                  const uint8_t *salt, size_t saltLen,
                                  uint32_t opsLimit, uint64_t memLimitBytes,
                                  uint32_t p, uint32_t dkLen) {
    const uint32_t t = opsLimit;
    const uint32_t mKiB = static_cast<uint32_t>(memLimitBytes / 1024);
    if (saltLen < 8) {
        throw std::string("salt too short");
    }
    // H0 前像必须包含全部长度前缀（密码/盐/secret/AD），与 libsodium 完全一致
    Blake2b bb(64);
    blakeLe32(bb, p);
    blakeLe32(bb, dkLen);
    blakeLe32(bb, mKiB);
    blakeLe32(bb, t);
    blakeLe32(bb, 0x13);
    blakeLe32(bb, 2); // y = Argon2id
    blakeLe32(bb, static_cast<uint32_t>(pwdLen));
    bb.update(pwd, pwdLen);
    blakeLe32(bb, static_cast<uint32_t>(saltLen));
    bb.update(salt, saltLen);
    blakeLe32(bb, 0); // secret 长度 = 0
    blakeLe32(bb, 0); // AD 长度 = 0
    std::vector<uint8_t> H0 = bb.digest();
    H0.resize(72);

    const uint32_t mP = 4 * p * (mKiB / (4 * p));
    const uint32_t laneLen = mP / p;
    const uint32_t segmentLen = laneLen / 4;
    if (mP == 0 || segmentLen == 0) {
        throw std::string("bad kdf params");
    }
    std::vector<uint64_t> B(static_cast<size_t>(mP) * 128);
    for (uint32_t l = 0; l < p; l++) {
        putLe32(H0, 64, 0);
        putLe32(H0, 68, l);
        std::vector<uint8_t> w0 = hp(H0.data(), H0.size(), 1024);
        memcpy(B.data() + static_cast<size_t>(l) * laneLen * 128, w0.data(), 1024);
        putLe32(H0, 64, 1);
        putLe32(H0, 68, l);
        std::vector<uint8_t> w1 = hp(H0.data(), H0.size(), 1024);
        memcpy(B.data() + (static_cast<size_t>(l) * laneLen + 1) * 128, w1.data(), 1024);
    }

    std::vector<uint64_t> address(3 * 128);
    address[128 + 3] = mP;
    address[128 + 4] = t;
    address[128 + 5] = 2;
    for (uint32_t r = 0; r < t; r++) {
        const bool needXor = r != 0;
        address[128] = r;
        for (uint32_t s = 0; s < 4; s++) {
            address[130] = s;
            const bool dataIndependent = r == 0 && s < 2;
            for (uint32_t l = 0; l < p; l++) {
                address[129] = l;
                address[134] = 0;
                uint32_t startPos = 0;
                if (r == 0 && s == 0) {
                    startPos = 2;
                    if (dataIndependent) {
                        address[134]++;
                        a2Block(address.data(), 128, 256, 0, false);
                        a2Block(address.data(), 0, 256, 0, false);
                    }
                }
                size_t offset = static_cast<size_t>(l) * laneLen + s * segmentLen + startPos;
                for (uint32_t index = startPos; index < segmentLen; index++, offset++) {
                    uint32_t prev = (offset % laneLen != 0)
                        ? static_cast<uint32_t>(offset - 1)
                        : static_cast<uint32_t>(offset + laneLen - 1);
                    uint32_t randL = 0;
                    uint32_t randH = 0;
                    if (dataIndependent) {
                        uint32_t i128 = index % 128;
                        if (i128 == 0) {
                            address[134]++;
                            a2Block(address.data(), 128, 256, 0, false);
                            a2Block(address.data(), 0, 256, 0, false);
                        }
                        uint64_t rw = address[i128];
                        randL = static_cast<uint32_t>(rw);
                        randH = static_cast<uint32_t>(rw >> 32);
                    } else {
                        uint64_t rw = B[static_cast<size_t>(128) * prev];
                        randL = static_cast<uint32_t>(rw);
                        randH = static_cast<uint32_t>(rw >> 32);
                    }
                    uint32_t refLane = (r == 0 && s == 0) ? l : (randH % p);
                    uint32_t refPos = indexAlpha(r, s, laneLen, segmentLen, index, randL, refLane == l);
                    size_t refBlock = static_cast<size_t>(laneLen) * refLane + refPos;
                    a2Block(B.data(), static_cast<size_t>(128) * prev,
                            refBlock * 128, offset * 128, needXor);
                }
            }
        }
    }

    uint64_t bFinal[128];
    memset(bFinal, 0, sizeof(bFinal));
    for (uint32_t l = 0; l < p; l++) {
        const uint64_t *base = B.data() +
            (static_cast<size_t>(laneLen) * l + laneLen - 1) * 128;
        for (int i = 0; i < 128; i++) {
            bFinal[i] ^= base[i];
        }
    }
    return hp(reinterpret_cast<const uint8_t *>(bFinal), sizeof(bFinal), dkLen);
}

// ---------------- base64 ----------------

const char B64_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string b64Encode(const uint8_t *data, size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    size_t i = 0;
    for (; i + 3 <= len; i += 3) {
        uint32_t v = (static_cast<uint32_t>(data[i]) << 16) |
                     (static_cast<uint32_t>(data[i + 1]) << 8) |
                     static_cast<uint32_t>(data[i + 2]);
        out.push_back(B64_CHARS[(v >> 18) & 63]);
        out.push_back(B64_CHARS[(v >> 12) & 63]);
        out.push_back(B64_CHARS[(v >> 6) & 63]);
        out.push_back(B64_CHARS[v & 63]);
    }
    size_t rem = len - i;
    if (rem == 1) {
        uint32_t v = static_cast<uint32_t>(data[i]) << 16;
        out.push_back(B64_CHARS[(v >> 18) & 63]);
        out.push_back(B64_CHARS[(v >> 12) & 63]);
        out.push_back('=');
        out.push_back('=');
    } else if (rem == 2) {
        uint32_t v = (static_cast<uint32_t>(data[i]) << 16) |
                     (static_cast<uint32_t>(data[i + 1]) << 8);
        out.push_back(B64_CHARS[(v >> 18) & 63]);
        out.push_back(B64_CHARS[(v >> 12) & 63]);
        out.push_back(B64_CHARS[(v >> 6) & 63]);
        out.push_back('=');
    }
    return out;
}

int b64Val(char c) {
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    }
    if (c == '+' || c == '-') {
        return 62;
    }
    if (c == '/' || c == '_') {
        return 63;
    }
    return -1;
}

bool b64Decode(const std::string &in, std::vector<uint8_t> &out) {
    out.clear();
    if (in.size() % 4 != 0 || in.empty()) {
        return false;
    }
    out.reserve(in.size() / 4 * 3);
    for (size_t i = 0; i < in.size(); i += 4) {
        int pad = 0;
        uint32_t v = 0;
        for (int j = 0; j < 4; j++) {
            char c = in[i + j];
            if (c == '=') {
                if (i + 4 != in.size() || j < 2) {
                    return false;
                }
                pad++;
                v <<= 6;
            } else {
                if (pad > 0) {
                    return false;
                }
                int d = b64Val(c);
                if (d < 0) {
                    return false;
                }
                v = (v << 6) | static_cast<uint32_t>(d);
            }
        }
        out.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
        if (pad < 2) {
            out.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
        }
        if (pad < 1) {
            out.push_back(static_cast<uint8_t>(v & 0xff));
        }
    }
    return true;
}

std::string toHex(const uint8_t *data, size_t len) {
    static const char *hex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        out.push_back(hex[data[i] >> 4]);
        out.push_back(hex[data[i] & 0xf]);
    }
    return out;
}

// ---------------- NAPI ----------------

#ifndef ARGON2_HOST_TEST

struct KekContext {
    napi_async_work work = nullptr;
    napi_deferred deferred = nullptr;
    // 输入
    std::string password; // UTF-8
    std::vector<uint8_t> salt;
    uint32_t opsLimit = 0;
    uint64_t memLimit = 0;
    // 输出
    bool ok = false;
    std::string result; // b64(kek) 或错误信息
};

void KekExecute(napi_env env, void *data) {
    KekContext *ctx = static_cast<KekContext *>(data);
    try {
        std::vector<uint8_t> kek = argon2idCore(
            reinterpret_cast<const uint8_t *>(ctx->password.data()), ctx->password.size(),
            ctx->salt.data(), ctx->salt.size(),
            ctx->opsLimit, ctx->memLimit, 1, 32);
        ctx->result = b64Encode(kek.data(), kek.size());
        ctx->ok = true;
    } catch (const std::string &err) {
        ctx->result = err;
        ctx->ok = false;
    } catch (const std::exception &e) {
        ctx->result = e.what();
        ctx->ok = false;
    } catch (...) {
        ctx->result = "oom";
        ctx->ok = false;
    }
}

void KekComplete(napi_env env, napi_status status, void *data) {
    KekContext *ctx = static_cast<KekContext *>(data);
    napi_value result = nullptr;
    if (ctx->ok) {
        napi_create_string_utf8(env, ctx->result.c_str(), ctx->result.size(), &result);
        napi_resolve_deferred(env, ctx->deferred, result);
    } else {
        napi_value err = nullptr;
        napi_value msg = nullptr;
        napi_create_string_utf8(env, ctx->result.c_str(), ctx->result.size(), &msg);
        napi_create_error(env, nullptr, msg, &err);
        napi_reject_deferred(env, ctx->deferred, err);
    }
    napi_delete_async_work(env, ctx->work);
    delete ctx;
}

napi_value DeriveKek(napi_env env, napi_callback_info info) {
    size_t argc = 4;
    napi_value argv[4];
    if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok || argc != 4) {
        napi_throw_error(env, nullptr, "deriveKek: expected 4 arguments");
        return nullptr;
    }
    KekContext *ctx = new KekContext();
    size_t len = 0;
    // password
    if (napi_get_value_string_utf8(env, argv[0], nullptr, 0, &len) != napi_ok) {
        delete ctx;
        napi_throw_error(env, nullptr, "deriveKek: bad password");
        return nullptr;
    }
    if (len > 0) {
        ctx->password.resize(len + 1);
        size_t written = 0;
        if (napi_get_value_string_utf8(env, argv[0], &ctx->password[0], len + 1, &written) != napi_ok) {
            delete ctx;
            napi_throw_error(env, nullptr, "deriveKek: bad password");
            return nullptr;
        }
        ctx->password.resize(written);
    }
    // saltB64
    std::string saltB64;
    if (napi_get_value_string_utf8(env, argv[1], nullptr, 0, &len) != napi_ok) {
        delete ctx;
        napi_throw_error(env, nullptr, "deriveKek: bad salt");
        return nullptr;
    }
    if (len > 0) {
        saltB64.resize(len + 1);
        size_t written = 0;
        if (napi_get_value_string_utf8(env, argv[1], &saltB64[0], len + 1, &written) != napi_ok) {
            delete ctx;
            napi_throw_error(env, nullptr, "deriveKek: bad salt");
            return nullptr;
        }
        saltB64.resize(written);
    }
    if (!b64Decode(saltB64, ctx->salt) || ctx->salt.size() < 8) {
        delete ctx;
        napi_throw_error(env, nullptr, "deriveKek: bad salt base64");
        return nullptr;
    }
    // opsLimit / memLimit
    uint32_t opsLimit = 0;
    uint32_t memLimit = 0;
    if (napi_get_value_uint32(env, argv[2], &opsLimit) != napi_ok ||
        napi_get_value_uint32(env, argv[3], &memLimit) != napi_ok) {
        delete ctx;
        napi_throw_error(env, nullptr, "deriveKek: bad kdf params");
        return nullptr;
    }
    ctx->opsLimit = opsLimit;
    ctx->memLimit = memLimit;

    napi_value promise = nullptr;
    napi_create_promise(env, &ctx->deferred, &promise);
    napi_value name = nullptr;
    napi_create_string_utf8(env, "argon2DeriveKek", NAPI_AUTO_LENGTH, &name);
    napi_create_async_work(env, nullptr, name, KekExecute, KekComplete, ctx, &ctx->work);
    napi_queue_async_work(env, ctx->work);
    return promise;
}

struct SelfTestContext {
    napi_async_work work = nullptr;
    napi_deferred deferred = nullptr;
    std::string result;
};

void SelfTestExecute(napi_env env, void *data) {
    SelfTestContext *ctx = static_cast<SelfTestContext *>(data);
    try {
        const char *v1pwd = "p@ssw0rd!";
        const char *v1salt = "0123456789abcdef";
        std::vector<uint8_t> kek1 = argon2idCore(
            reinterpret_cast<const uint8_t *>(v1pwd), strlen(v1pwd),
            reinterpret_cast<const uint8_t *>(v1salt), strlen(v1salt), 1, 8388608, 1, 32);
        const std::string hex1 = toHex(kek1.data(), kek1.size());
        if (hex1 != "44f160fba4653d18bb1fedaeddc6294d008b9536b9e2b7274116bb9b1afcc0f5") {
            ctx->result = "fail:v1:" + hex1;
            return;
        }
        const char *v2pwd = "password";
        const char *v2salt = "somesalt";
        std::vector<uint8_t> kek2 = argon2idCore(
            reinterpret_cast<const uint8_t *>(v2pwd), strlen(v2pwd),
            reinterpret_cast<const uint8_t *>(v2salt), strlen(v2salt), 2, 1048576, 1, 32);
        const std::string hex2 = toHex(kek2.data(), kek2.size());
        if (hex2 != "ec57ec9c0eaf51eeea2e92ffdcaa9cdee478f1927215b515b7b8d66657f41ed9") {
            ctx->result = "fail:v2:" + hex2;
            return;
        }
        ctx->result = "ok";
    } catch (...) {
        ctx->result = "fail:exception";
    }
}

void SelfTestComplete(napi_env env, napi_status status, void *data) {
    SelfTestContext *ctx = static_cast<SelfTestContext *>(data);
    napi_value result = nullptr;
    napi_create_string_utf8(env, ctx->result.c_str(), ctx->result.size(), &result);
    napi_resolve_deferred(env, ctx->deferred, result);
    napi_delete_async_work(env, ctx->work);
    delete ctx;
}

napi_value SelfTest(napi_env env, napi_callback_info info) {
    SelfTestContext *ctx = new SelfTestContext();
    napi_value promise = nullptr;
    napi_create_promise(env, &ctx->deferred, &promise);
    napi_value name = nullptr;
    napi_create_string_utf8(env, "argon2SelfTest", NAPI_AUTO_LENGTH, &name);
    napi_create_async_work(env, nullptr, name, SelfTestExecute, SelfTestComplete, ctx, &ctx->work);
    napi_queue_async_work(env, ctx->work);
    return promise;
}

#endif // ARGON2_HOST_TEST

} // namespace

#ifndef ARGON2_HOST_TEST

EXTERN_C_START
static napi_value Init(napi_env env, napi_value exports) {
    napi_property_descriptor desc[] = {
        {"deriveKekNative", nullptr, DeriveKek, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"argon2SelfTestNative", nullptr, SelfTest, nullptr, nullptr, nullptr, napi_default, nullptr},
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    return exports;
}
EXTERN_C_END

static napi_module demoModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "entry",
    .nm_priv = nullptr,
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void RegisterEntryModule(void) {
    napi_module_register(&demoModule);
}

#endif // ARGON2_HOST_TEST
