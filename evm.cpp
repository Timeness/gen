#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <cstring>
#include <random>
#include <algorithm>
#include <fstream>
#include <queue>
#include <condition_variable>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/err.h>

typedef uint64_t kuint64_t;

#define KECCAK_ROUNDS 24

static const kuint64_t KECCAK_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

static inline void keccak256(const uint8_t *in, size_t inlen, uint8_t out[32]) {
    kuint64_t st[25];
    uint8_t temp[144];
    size_t i, rsiz, rsizw;

    rsiz = 136;
    rsizw = rsiz / 8;

    memset(st, 0, sizeof(st));

    while (inlen >= rsiz) {
        for (i = 0; i < rsizw; i++) {
            st[i] ^= ((kuint64_t *)in)[i];
        }
        in += rsiz;
        inlen -= rsiz;

        for (int round = 0; round < KECCAK_ROUNDS; round++) {
            kuint64_t C[5], D[5], B[25];

            C[0] = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20];
            C[1] = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21];
            C[2] = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22];
            C[3] = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23];
            C[4] = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24];

            D[0] = C[4] ^ ROTL64(C[1], 1);
            D[1] = C[0] ^ ROTL64(C[2], 1);
            D[2] = C[1] ^ ROTL64(C[3], 1);
            D[3] = C[2] ^ ROTL64(C[4], 1);
            D[4] = C[3] ^ ROTL64(C[0], 1);

            st[0]  ^= D[0]; st[5]  ^= D[0]; st[10] ^= D[0]; st[15] ^= D[0]; st[20] ^= D[0];
            st[1]  ^= D[1]; st[6]  ^= D[1]; st[11] ^= D[1]; st[16] ^= D[1]; st[21] ^= D[1];
            st[2]  ^= D[2]; st[7]  ^= D[2]; st[12] ^= D[2]; st[17] ^= D[2]; st[22] ^= D[2];
            st[3]  ^= D[3]; st[8]  ^= D[3]; st[13] ^= D[3]; st[18] ^= D[3]; st[23] ^= D[3];
            st[4]  ^= D[4]; st[9]  ^= D[4]; st[14] ^= D[4]; st[19] ^= D[4]; st[24] ^= D[4];

            B[0]  = st[0];           B[1]  = ROTL64(st[6], 44);  B[2]  = ROTL64(st[12], 43);
            B[3]  = ROTL64(st[18], 21); B[4]  = ROTL64(st[24], 14); B[5]  = ROTL64(st[3], 28);
            B[6]  = ROTL64(st[9], 20);  B[7]  = ROTL64(st[10], 3);  B[8]  = ROTL64(st[16], 45);
            B[9]  = ROTL64(st[22], 61); B[10] = ROTL64(st[1], 1);   B[11] = ROTL64(st[7], 6);
            B[12] = ROTL64(st[13], 25); B[13] = ROTL64(st[19], 8);  B[14] = ROTL64(st[20], 18);
            B[15] = ROTL64(st[4], 27);  B[16] = ROTL64(st[5], 36);  B[17] = ROTL64(st[11], 10);
            B[18] = ROTL64(st[17], 15); B[19] = ROTL64(st[23], 56); B[20] = ROTL64(st[2], 62);
            B[21] = ROTL64(st[8], 55);  B[22] = ROTL64(st[14], 39); B[23] = ROTL64(st[15], 41);
            B[24] = ROTL64(st[21], 2);

            st[0]  = B[0]  ^ ((~B[1])  & B[2]);   st[1]  = B[1]  ^ ((~B[2])  & B[3]);
            st[2]  = B[2]  ^ ((~B[3])  & B[4]);   st[3]  = B[3]  ^ ((~B[4])  & B[0]);
            st[4]  = B[4]  ^ ((~B[0])  & B[1]);   st[5]  = B[5]  ^ ((~B[6])  & B[7]);
            st[6]  = B[6]  ^ ((~B[7])  & B[8]);   st[7]  = B[7]  ^ ((~B[8])  & B[9]);
            st[8]  = B[8]  ^ ((~B[9])  & B[5]);   st[9]  = B[9]  ^ ((~B[5])  & B[6]);
            st[10] = B[10] ^ ((~B[11]) & B[12]);  st[11] = B[11] ^ ((~B[12]) & B[13]);
            st[12] = B[12] ^ ((~B[13]) & B[14]);  st[13] = B[13] ^ ((~B[14]) & B[10]);
            st[14] = B[14] ^ ((~B[10]) & B[11]);  st[15] = B[15] ^ ((~B[16]) & B[17]);
            st[16] = B[16] ^ ((~B[17]) & B[18]);  st[17] = B[17] ^ ((~B[18]) & B[19]);
            st[18] = B[18] ^ ((~B[19]) & B[15]);  st[19] = B[19] ^ ((~B[15]) & B[16]);
            st[20] = B[20] ^ ((~B[21]) & B[22]);  st[21] = B[21] ^ ((~B[22]) & B[23]);
            st[22] = B[22] ^ ((~B[23]) & B[24]);  st[23] = B[23] ^ ((~B[24]) & B[20]);
            st[24] = B[24] ^ ((~B[20]) & B[21]);

            st[0] ^= KECCAK_RC[round];
        }
    }

    memcpy(temp, in, inlen);
    temp[inlen++] = 0x01;
    memset(temp + inlen, 0, rsiz - inlen);
    temp[rsiz - 1] |= 0x80;

    for (i = 0; i < rsizw; i++) {
        st[i] ^= ((kuint64_t *)temp)[i];
    }

    for (int round = 0; round < KECCAK_ROUNDS; round++) {
        kuint64_t C[5], D[5], B[25];

        C[0] = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20];
        C[1] = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21];
        C[2] = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22];
        C[3] = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23];
        C[4] = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24];

        D[0] = C[4] ^ ROTL64(C[1], 1);
        D[1] = C[0] ^ ROTL64(C[2], 1);
        D[2] = C[1] ^ ROTL64(C[3], 1);
        D[3] = C[2] ^ ROTL64(C[4], 1);
        D[4] = C[3] ^ ROTL64(C[0], 1);

        st[0]  ^= D[0]; st[5]  ^= D[0]; st[10] ^= D[0]; st[15] ^= D[0]; st[20] ^= D[0];
        st[1]  ^= D[1]; st[6]  ^= D[1]; st[11] ^= D[1]; st[16] ^= D[1]; st[21] ^= D[1];
        st[2]  ^= D[2]; st[7]  ^= D[2]; st[12] ^= D[2]; st[17] ^= D[2]; st[22] ^= D[2];
        st[3]  ^= D[3]; st[8]  ^= D[3]; st[13] ^= D[3]; st[18] ^= D[3]; st[23] ^= D[3];
        st[4]  ^= D[4]; st[9]  ^= D[4]; st[14] ^= D[4]; st[19] ^= D[4]; st[24] ^= D[4];

        B[0]  = st[0];           B[1]  = ROTL64(st[6], 44);  B[2]  = ROTL64(st[12], 43);
        B[3]  = ROTL64(st[18], 21); B[4]  = ROTL64(st[24], 14); B[5]  = ROTL64(st[3], 28);
        B[6]  = ROTL64(st[9], 20);  B[7]  = ROTL64(st[10], 3);  B[8]  = ROTL64(st[16], 45);
        B[9]  = ROTL64(st[22], 61); B[10] = ROTL64(st[1], 1);   B[11] = ROTL64(st[7], 6);
        B[12] = ROTL64(st[13], 25); B[13] = ROTL64(st[19], 8);  B[14] = ROTL64(st[20], 18);
        B[15] = ROTL64(st[4], 27);  B[16] = ROTL64(st[5], 36);  B[17] = ROTL64(st[11], 10);
        B[18] = ROTL64(st[17], 15); B[19] = ROTL64(st[23], 56); B[20] = ROTL64(st[2], 62);
        B[21] = ROTL64(st[8], 55);  B[22] = ROTL64(st[14], 39); B[23] = ROTL64(st[15], 41);
        B[24] = ROTL64(st[21], 2);

        st[0]  = B[0]  ^ ((~B[1])  & B[2]);   st[1]  = B[1]  ^ ((~B[2])  & B[3]);
        st[2]  = B[2]  ^ ((~B[3])  & B[4]);   st[3]  = B[3]  ^ ((~B[4])  & B[0]);
        st[4]  = B[4]  ^ ((~B[0])  & B[1]);   st[5]  = B[5]  ^ ((~B[6])  & B[7]);
        st[6]  = B[6]  ^ ((~B[7])  & B[8]);   st[7]  = B[7]  ^ ((~B[8])  & B[9]);
        st[8]  = B[8]  ^ ((~B[9])  & B[5]);   st[9]  = B[9]  ^ ((~B[5])  & B[6]);
        st[10] = B[10] ^ ((~B[11]) & B[12]);  st[11] = B[11] ^ ((~B[12]) & B[13]);
        st[12] = B[12] ^ ((~B[13]) & B[14]);  st[13] = B[13] ^ ((~B[14]) & B[10]);
        st[14] = B[14] ^ ((~B[10]) & B[11]);  st[15] = B[15] ^ ((~B[16]) & B[17]);
        st[16] = B[16] ^ ((~B[17]) & B[18]);  st[17] = B[17] ^ ((~B[18]) & B[19]);
        st[18] = B[18] ^ ((~B[19]) & B[15]);  st[19] = B[19] ^ ((~B[15]) & B[16]);
        st[20] = B[20] ^ ((~B[21]) & B[22]);  st[21] = B[21] ^ ((~B[22]) & B[23]);
        st[22] = B[22] ^ ((~B[23]) & B[24]);  st[23] = B[23] ^ ((~B[24]) & B[20]);
        st[24] = B[24] ^ ((~B[20]) & B[21]);

        st[0] ^= KECCAK_RC[round];
    }

    memcpy(out, st, 32);
}

static const char HEX_TABLE[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

inline void bytes_to_hex(const uint8_t *bin, size_t len, char *hex) {
    for (size_t i = 0; i < len; i++) {
        hex[i*2]   = HEX_TABLE[bin[i] >> 4];
        hex[i*2+1] = HEX_TABLE[bin[i] & 0x0F];
    }
    hex[len*2] = '\0';
}

enum class MatchMode { PREFIX, ANYWHERE, SUFFIX };

struct Pattern {
    std::string raw;
    MatchMode mode;
    bool case_sensitive;
    std::string lowered;

    Pattern() : mode(MatchMode::PREFIX), case_sensitive(false) {}
    Pattern(const std::string &r, MatchMode m, bool cs) : raw(r), mode(m), case_sensitive(cs) {
        lowered = raw;
        std::transform(lowered.begin(), lowered.end(), lowered.begin(), ::tolower);
    }
};

inline bool is_hex_str(const std::string &s) {
    for (char c : s) {
        if (!isxdigit(c)) return false;
    }
    return !s.empty();
}

inline bool match_pattern(const char *addr, const Pattern &pat) {
    if (pat.raw.empty()) return true;

    size_t addr_len = 40;
    size_t pat_len = pat.raw.size();
    if (pat_len > addr_len) return false;

    if (pat.mode == MatchMode::PREFIX) {
        if (pat.case_sensitive) {
            return strncmp(addr, pat.raw.c_str(), pat_len) == 0;
        } else {
            for (size_t i = 0; i < pat_len; i++) {
                char c = addr[i];
                if (c >= 'A' && c <= 'F') c = c - 'A' + 'a';
                if (c != pat.lowered[i]) return false;
            }
            return true;
        }
    } else if (pat.mode == MatchMode::SUFFIX) {
        const char *suf = addr + (addr_len - pat_len);
        if (pat.case_sensitive) {
            return strcmp(suf, pat.raw.c_str()) == 0;
        } else {
            for (size_t i = 0; i < pat_len; i++) {
                char c = suf[i];
                if (c >= 'A' && c <= 'F') c = c - 'A' + 'a';
                if (c != pat.lowered[i]) return false;
            }
            return true;
        }
    } else {
        for (size_t i = 0; i <= addr_len - pat_len; i++) {
            bool ok = true;
            for (size_t j = 0; j < pat_len; j++) {
                char c = addr[i + j];
                if (!pat.case_sensitive && c >= 'A' && c <= 'F') c = c - 'A' + 'a';
                if (c != pat.lowered[j]) { ok = false; break; }
            }
            if (ok) return true;
        }
        return false;
    }
}

inline void pub_to_address(const uint8_t pub[65], uint8_t addr[20]) {
    uint8_t hash[32];
    keccak256(pub + 1, 64, hash);
    memcpy(addr, hash + 12, 20);
}

struct Result {
    std::string address;
    std::string private_key_hex;
};

class ResultQueue {
    std::queue<Result> q;
    std::mutex mtx;
    std::condition_variable cv;
public:
    void push(const Result &r) {
        std::lock_guard<std::mutex> lock(mtx);
        q.push(r);
        cv.notify_one();
    }
    bool try_pop(Result &r) {
        std::lock_guard<std::mutex> lock(mtx);
        if (q.empty()) return false;
        r = q.front();
        q.pop();
        return true;
    }
    size_t size() {
        std::lock_guard<std::mutex> lock(mtx);
        return q.size();
    }
};

struct Stats {
    std::atomic<uint64_t> attempts{0};
    std::atomic<uint64_t> found{0};
    std::atomic<uint64_t> last_attempts{0};
};

class VanityGenerator {
public:
    std::vector<Pattern> patterns;
    ResultQueue result_queue;
    Stats stats;
    std::atomic<bool> should_stop{false};
    int num_threads;
    int batch_size;
    bool save_results;
    std::string output_file;
    uint64_t max_attempts;
    int max_results;

    VanityGenerator(int nt, int bs, bool save, const std::string &of, uint64_t max_att = 0, int max_res = 0)
        : num_threads(nt), batch_size(bs), save_results(save), output_file(of),
          max_attempts(max_att), max_results(max_res) {}

    void add_pattern(const Pattern &p) {
        patterns.push_back(p);
    }

    void run() {
        std::vector<std::thread> threads;
        auto start = std::chrono::high_resolution_clock::now();

        std::cout << R"(
   _____ _   _____ ________________  _________  ___   ___  
  |  ___| | / / _ |_  /__  /__  / |/_/  _ _ \/ _ | / _ \ 
  | |_  | |/ / __ |/ /  / /  / /_  > _ \  __/ __ |/ // / 
  |  _| | / /_/ /___/  /_/  /_/ /_/\___/\__/_/ |_/____/  
  |_|   |_|\___/   /___/  /___/                           

)";
        std::cout << "  EVM VANITY GENERATOR v3.0 - ULTRA FAST\n";
        std::cout << "  ======================================\n";
        std::cout << "  Threads:        " << num_threads << "\n";
        std::cout << "  Batch size:     " << batch_size << "\n";
        std::cout << "  Patterns:       " << patterns.size() << "\n";
        for (size_t i = 0; i < patterns.size(); i++) {
            std::cout << "    [" << i << "] ";
            if (patterns[i].mode == MatchMode::PREFIX) std::cout << "PREFIX";
            else if (patterns[i].mode == MatchMode::SUFFIX) std::cout << "SUFFIX";
            else std::cout << "ANYWHERE";
            std::cout << " \"" << patterns[i].raw << "\" ("
                      << (patterns[i].case_sensitive ? "case-sensitive" : "case-insensitive") << ")\n";
        }
        if (max_attempts > 0)
            std::cout << "  Max attempts:   " << max_attempts << "\n";
        if (max_results > 0)
            std::cout << "  Max results:    " << max_results << "\n";
        std::cout << "  ======================================\n\n";

        for (int i = 0; i < num_threads; i++) {
            threads.emplace_back(&VanityGenerator::worker, this, i);
        }

        std::thread reporter(&VanityGenerator::progress_loop, this, start);
        std::thread saver;
        if (save_results) {
            saver = std::thread(&VanityGenerator::save_loop, this);
        }

        for (auto &t : threads) t.join();
        should_stop = true;
        reporter.join();
        if (saver.joinable()) saver.join();

        auto end = std::chrono::high_resolution_clock::now();
        double secs = std::chrono::duration<double>(end - start).count();
        uint64_t total = stats.attempts.load();

        std::cout << "\n  ======================================\n";
        std::cout << "  DONE!\n";
        std::cout << "  Total attempts: " << total << "\n";
        std::cout << "  Time:           " << std::fixed << std::setprecision(2) << secs << " sec\n";
        std::cout << "  Speed:          " << std::fixed << std::setprecision(0) << (total / secs) << " addr/sec\n";
        std::cout << "  Found:          " << stats.found.load() << "\n";
        std::cout << "  ======================================\n";

        flush_results();
    }

private:
    void worker(int tid) {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
        if (!ctx) {
            std::cerr << "Thread " << tid << ": Failed to create EVP context\n";
            return;
        }

        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            std::cerr << "Thread " << tid << ": Failed to init keygen\n";
            EVP_PKEY_CTX_free(ctx);
            return;
        }

        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string("group", (char*)"secp256k1", 0);
        params[1] = OSSL_PARAM_construct_end();

        if (EVP_PKEY_CTX_set_params(ctx, params) <= 0) {
            std::cerr << "Thread " << tid << ": Failed to set curve\n";
            EVP_PKEY_CTX_free(ctx);
            return;
        }

        uint8_t addr[20];
        char addr_hex[41];
        std::vector<Result> local_buffer;
        local_buffer.reserve(16);

        while (!should_stop.load(std::memory_order_relaxed)) {
            if (max_attempts > 0 && stats.attempts.load() >= max_attempts) {
                should_stop = true;
                break;
            }
            if (max_results > 0 && stats.found.load() >= max_results) {
                should_stop = true;
                break;
            }

            for (int b = 0; b < batch_size; b++) {
                EVP_PKEY *pkey = nullptr;
                if (EVP_PKEY_generate(ctx, &pkey) <= 0) continue;

                size_t publen = 65;
                uint8_t pub[65];
                if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, pub, 65, &publen) <= 0) {
                    EVP_PKEY_free(pkey);
                    continue;
                }

                pub_to_address(pub, addr);
                bytes_to_hex(addr, 20, addr_hex);

                bool matched = false;
                for (const auto &pat : patterns) {
                    if (match_pattern(addr_hex, pat)) {
                        matched = true;
                        break;
                    }
                }

                if (matched) {
                    BIGNUM *priv = nullptr;
                    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv) > 0) {
                        char *priv_hex_str = BN_bn2hex(priv);
                        for (char *p = priv_hex_str; *p; p++) {
                            if (*p >= 'A' && *p <= 'F') *p = *p - 'A' + 'a';
                        }

                        Result r;
                        r.address = std::string(addr_hex);
                        r.private_key_hex = std::string(priv_hex_str);
                        local_buffer.push_back(r);

                        OPENSSL_free(priv_hex_str);
                        BN_free(priv);

                        stats.found.fetch_add(1, std::memory_order_relaxed);
                    }
                }

                EVP_PKEY_free(pkey);
                stats.attempts.fetch_add(1, std::memory_order_relaxed);
            }

            if (!local_buffer.empty()) {
                for (const auto &r : local_buffer) {
                    result_queue.push(r);
                }
                local_buffer.clear();
            }
        }

        EVP_PKEY_CTX_free(ctx);
    }

    void progress_loop(std::chrono::high_resolution_clock::time_point start) {
        while (!should_stop.load(std::memory_order_relaxed)) {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            auto now = std::chrono::high_resolution_clock::now();
            double secs = std::chrono::duration<double>(now - start).count();
            uint64_t att = stats.attempts.load(std::memory_order_relaxed);
            uint64_t fnd = stats.found.load(std::memory_order_relaxed);
            uint64_t last = stats.last_attempts.load(std::memory_order_relaxed);
            double rate = (secs > 0) ? (att / secs) : 0;
            double inst_rate = (att - last) / 2.0;

            std::cout << "  [+] " << std::fixed << std::setprecision(1) << secs << "s | "
                      << "Attempts: " << att;
            if (max_attempts > 0)
                std::cout << "/" << max_attempts;
            std::cout << " | "
                      << "Speed: " << std::setprecision(0) << rate << " (inst: " << inst_rate << ") addr/s | "
                      << "Found: " << fnd;
            if (max_results > 0)
                std::cout << "/" << max_results;
            std::cout << "\n" << std::flush;

            stats.last_attempts.store(att, std::memory_order_relaxed);
        }
    }

    void save_loop() {
        std::ofstream ofs(output_file);
        ofs << "# EVM Vanity Addresses\n";
        ofs << "# ====================\n\n";
        ofs.flush();

        Result r;
        while (!should_stop.load(std::memory_order_relaxed)) {
            while (result_queue.try_pop(r)) {
                ofs << "Address:  0x" << r.address << "\n";
                ofs << "PrivKey:  0x" << r.private_key_hex << "\n\n";
                ofs.flush();
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        while (result_queue.try_pop(r)) {
            ofs << "Address:  0x" << r.address << "\n";
            ofs << "PrivKey:  0x" << r.private_key_hex << "\n\n";
        }
    }

    void flush_results() {
        if (!save_results) return;
        std::ofstream ofs(output_file, std::ios::app);
        Result r;
        while (result_queue.try_pop(r)) {
            ofs << "Address:  0x" << r.address << "\n";
            ofs << "PrivKey:  0x" << r.private_key_hex << "\n\n";
        }
    }
};

void print_usage(const char *prog) {
    std::cout << "Usage: " << prog << " [options] <pattern1> [pattern2] ...\n\n";
    std::cout << "Options:\n";
    std::cout << "  -t <n>        Number of threads (default: auto-detect)\n";
    std::cout << "  -b <n>        Batch size per thread (default: 256)\n";
    std::cout << "  -m <mode>     Match mode: prefix, suffix, anywhere (default: prefix)\n";
    std::cout << "  -c            Case-sensitive matching\n";
    std::cout << "  -o <file>     Save results to file (default: vanity_results.txt)\n";
    std::cout << "  -n <num>      Stop after finding N results\n";
    std::cout << "  -a <num>      Stop after N attempts\n";
    std::cout << "  -h            Show this help\n";
    std::cout << "\nExamples:\n";
    std::cout << "  " << prog << " dead                    # prefix: 0xdead...\n";
    std::cout << "  " << prog << " -m suffix beef           # suffix: ...beef\n";
    std::cout << "  " << prog << " -t 16 -b 512 -n 5 cafe   # 16 threads, stop at 5 matches\n";
    std::cout << "  " << prog << " -c -t 8 ABCD             # case-sensitive prefix\n";
    std::cout << "\n";
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    int threads = (int)std::thread::hardware_concurrency();
    if (threads < 1) threads = 4;
    int batch = 256;
    MatchMode mode = MatchMode::PREFIX;
    bool case_sensitive = false;
    std::string outfile = "vanity_results.txt";
    bool save = false;
    uint64_t max_attempts = 0;
    int max_results = 0;

    std::vector<std::string> patterns_raw;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-t" && i + 1 < argc) {
            threads = std::atoi(argv[++i]);
        } else if (arg == "-b" && i + 1 < argc) {
            batch = std::atoi(argv[++i]);
        } else if (arg == "-m" && i + 1 < argc) {
            std::string m = argv[++i];
            if (m == "prefix") mode = MatchMode::PREFIX;
            else if (m == "suffix") mode = MatchMode::SUFFIX;
            else if (m == "anywhere") mode = MatchMode::ANYWHERE;
        } else if (arg == "-c") {
            case_sensitive = true;
        } else if (arg == "-o" && i + 1 < argc) {
            outfile = argv[++i];
            save = true;
        } else if (arg == "-n" && i + 1 < argc) {
            max_results = std::atoi(argv[++i]);
        } else if (arg == "-a" && i + 1 < argc) {
            max_attempts = std::strtoull(argv[++i], nullptr, 10);
        } else if (arg == "-h") {
            print_usage(argv[0]);
            return 0;
        } else if (arg[0] != '-') {
            patterns_raw.push_back(arg);
        }
    }

    if (patterns_raw.empty()) {
        std::cerr << "Error: No patterns provided.\n";
        print_usage(argv[0]);
        return 1;
    }

    VanityGenerator gen(threads, batch, save, outfile, max_attempts, max_results);
    for (const auto &pr : patterns_raw) {
        if (!is_hex_str(pr)) {
            std::cerr << "Warning: \"" << pr << "\" is not valid hex, skipping.\n";
            continue;
        }
        gen.add_pattern(Pattern(pr, mode, case_sensitive));
    }

    if (gen.patterns.empty()) {
        std::cerr << "Error: No valid patterns.\n";
        return 1;
    }

    gen.run();
    return 0;
}
