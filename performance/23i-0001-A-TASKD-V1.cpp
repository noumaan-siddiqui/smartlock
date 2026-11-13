// Student Name: Noumaan Siddiqui
// Student ID:   23i-0666 / 23i-0001
// Assignment:   CS3002 Assignment 2 - Part D (Performance Benchmarking Tool)
//
// Description:
//   Comprehensive benchmarking harness comparing SmartLock v1 (baseline under AES256-GCM)
//   and SmartLock v2 across three core metrics:
//   1. Handshake Time (30 runs): Connect/negotiate to greeting decrypted.
//   2. Per-Record Overhead: Extra bytes on wire & microsecond protect/open latency.
//   3. Throughput (MB/s): 10,000 records of 1 KiB per run over 5 runs.
//
// Build: g++ -std=c++17 -O2 23i-0001-A-TASKD-V1.cpp -lcrypto -o taskd
// Usage: ./taskd

#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <cmath>
#include <numeric>
#include <iomanip>
#include <fstream>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

// ============================================================================
// Mathematical & Statistical Utilities
// ============================================================================

struct Stats {
    double mean;
    double stddev;
    double min;
    double max;
};

Stats compute_stats(const std::vector<double>& v) {
    if (v.empty()) return {0, 0, 0, 0};
    double sum = std::accumulate(v.begin(), v.end(), 0.0);
    double mean = sum / v.size();
    double sq_sum = 0.0;
    double min_v = v[0], max_v = v[0];
    for (double x : v) {
        sq_sum += (x - mean) * (x - mean);
        if (x < min_v) min_v = x;
        if (x > max_v) max_v = x;
    }
    double stddev = v.size() > 1 ? std::sqrt(sq_sum / (v.size() - 1)) : 0.0;
    return {mean, stddev, min_v, max_v};
}

inline uint64_t mulmod(uint64_t a, uint64_t b, uint64_t m) {
    return (uint64_t)((__uint128_t)a * b % m);
}

inline uint64_t modexp64(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t r = 1 % mod; base %= mod;
    while (exp) {
        if (exp & 1) r = mulmod(r, base, mod);
        base = mulmod(base, base, mod);
        exp >>= 1;
    }
    return r;
}

// ============================================================================
// v1 Cryptographic Operations
// ============================================================================

namespace v1 {

inline std::vector<uint8_t> session_key(uint64_t shared, int kl = 32) {
    std::vector<uint8_t> k(kl, 0);
    for (int i = kl - 1; i >= 0 && shared; --i) {
        k[i] = shared & 0xff;
        shared >>= 8;
    }
    return k;
}

inline std::vector<uint8_t> record_encrypt(const std::vector<uint8_t>& key,
                                           const std::vector<uint8_t>& nonce,
                                           const uint8_t* pt, size_t pt_len) {
    const EVP_CIPHER* c = EVP_aes_256_gcm();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, c, nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(), nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data());
    std::vector<uint8_t> out(pt_len);
    int len = 0;
    EVP_EncryptUpdate(ctx, out.data(), &len, pt, (int)pt_len);
    int outl = len;
    EVP_EncryptFinal_ex(ctx, out.data() + len, &len);
    outl += len;
    out.resize(outl);
    std::vector<uint8_t> tag(16);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
    EVP_CIPHER_CTX_free(ctx);
    out.insert(out.end(), tag.begin(), tag.end()); // Ciphertext || 16-byte tag
    return out;
}

inline std::vector<uint8_t> record_decrypt(const std::vector<uint8_t>& key,
                                           const std::vector<uint8_t>& nonce,
                                           const std::vector<uint8_t>& ctin) {
    if (ctin.size() < 16) throw std::runtime_error("short record");
    const EVP_CIPHER* c = EVP_aes_256_gcm();
    size_t clen = ctin.size() - 16;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, c, nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(), nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data());
    std::vector<uint8_t> out(clen);
    int len = 0;
    EVP_DecryptUpdate(ctx, out.data(), &len, ctin.data(), (int)clen);
    int outl = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)(ctin.data() + clen));
    int ok = EVP_DecryptFinal_ex(ctx, out.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    if (ok <= 0) throw std::runtime_error("auth tag check failed");
    out.resize(outl + len);
    return out;
}

} // namespace v1

// ============================================================================
// v2 Cryptographic Operations
// ============================================================================

namespace v2 {

inline std::vector<uint8_t> derive_key(const std::vector<uint8_t>& shared_secret,
                                       const std::string& context, int kl = 32) {
    std::vector<uint8_t> out(kl);
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (kdf) {
        EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
        EVP_KDF_free(kdf);
        if (kctx) {
            char digest_name[] = "SHA256";
            OSSL_PARAM params[5];
            params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest_name, sizeof(digest_name));
            params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void*)shared_secret.data(), shared_secret.size());
            params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void*)context.data(), context.size());
            params[3] = OSSL_PARAM_construct_end();
            int ret = EVP_KDF_derive(kctx, out.data(), out.size(), params);
            EVP_KDF_CTX_free(kctx);
            if (ret > 0) return out;
        }
    }
    // Fallback
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (pctx) {
        EVP_PKEY_derive_init(pctx);
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256());
        EVP_PKEY_CTX_set1_hkdf_key(pctx, shared_secret.data(), (int)shared_secret.size());
        EVP_PKEY_CTX_add1_hkdf_info(pctx, (const unsigned char*)context.data(), (int)context.size());
        size_t outlen = out.size();
        EVP_PKEY_derive(pctx, out.data(), &outlen);
        EVP_PKEY_CTX_free(pctx);
    }
    return out;
}

inline std::vector<uint8_t> make_nonce(uint64_t seqno) {
    std::vector<uint8_t> nonce(12, 0);
    for (int i = 11; i >= 4; --i) {
        nonce[i] = (uint8_t)(seqno & 0xff);
        seqno >>= 8;
    }
    return nonce;
}

inline std::vector<uint8_t> seal(const std::vector<uint8_t>& key, uint64_t seqno,
                                 const uint8_t* pt, size_t pt_len) {
    std::vector<uint8_t> seq_bytes(8);
    for (int i = 7; i >= 0; --i) {
        seq_bytes[i] = (uint8_t)((seqno >> (8 * (7 - i))) & 0xff);
    }
    auto nonce = make_nonce(seqno);
    const EVP_CIPHER* cipher = EVP_aes_256_gcm();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(), nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data());

    int dummy_len = 0;
    EVP_EncryptUpdate(ctx, nullptr, &dummy_len, seq_bytes.data(), (int)seq_bytes.size());

    std::vector<uint8_t> ct(pt_len);
    int len = 0;
    EVP_EncryptUpdate(ctx, ct.data(), &len, pt, (int)pt_len);
    int final_len = 0;
    EVP_EncryptFinal_ex(ctx, ct.data() + len, &final_len);
    ct.resize(len + final_len);

    std::vector<uint8_t> tag(16);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
    EVP_CIPHER_CTX_free(ctx);

    std::vector<uint8_t> rec;
    rec.reserve(8 + ct.size() + 16);
    rec.insert(rec.end(), seq_bytes.begin(), seq_bytes.end());
    rec.insert(rec.end(), ct.begin(), ct.end());
    rec.insert(rec.end(), tag.begin(), tag.end());
    return rec;
}

inline std::vector<uint8_t> open_record(const std::vector<uint8_t>& key,
                                        const std::vector<uint8_t>& record,
                                        uint64_t expected_seqno) {
    if (record.size() < 24) throw std::runtime_error("short record");
    uint64_t rec_seqno = 0;
    for (int i = 0; i < 8; ++i) rec_seqno = (rec_seqno << 8) | record[i];
    if (rec_seqno != expected_seqno) throw std::runtime_error("sequence error");

    std::vector<uint8_t> seq_bytes(record.begin(), record.begin() + 8);
    size_t ct_len = record.size() - 8 - 16;
    const uint8_t* ct_ptr = record.data() + 8;
    const uint8_t* tag_ptr = record.data() + 8 + ct_len;

    auto nonce = make_nonce(rec_seqno);
    const EVP_CIPHER* cipher = EVP_aes_256_gcm();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(), nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data());

    int dummy_len = 0;
    EVP_DecryptUpdate(ctx, nullptr, &dummy_len, seq_bytes.data(), (int)seq_bytes.size());

    std::vector<uint8_t> pt(ct_len);
    int len = 0;
    EVP_DecryptUpdate(ctx, pt.data(), &len, ct_ptr, (int)ct_len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag_ptr);
    int final_len = 0;
    int ok = EVP_DecryptFinal_ex(ctx, pt.data() + len, &final_len);
    EVP_CIPHER_CTX_free(ctx);
    if (ok <= 0) throw std::runtime_error("auth tag check failed");
    pt.resize(len + final_len);
    return pt;
}

// RFC 3526 2048-bit MODP DH parameters
inline BIGNUM* P2048() {
    BIGNUM* p = nullptr;
    BN_hex2bn(&p,
      "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
      "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
      "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
      "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
      "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
      "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
      "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
      "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF");
    return p;
}

} // namespace v2

// ============================================================================
// Benchmarking Functions
// ============================================================================

void run_handshake_benchmark(std::vector<double>& v1_times, std::vector<double>& v2_times, int runs = 30) {
    v1_times.clear();
    v2_times.clear();

    // Setup RSA keys for signing operations
    EVP_PKEY* rsa = EVP_RSA_gen(2048);
    BIGNUM* p2048 = v2::P2048();

    // v1: 40-bit prime DH parameters
    uint64_t p_v1 = 1099511627791ull; // 40-bit prime
    uint64_t g_v1 = 2;
    uint64_t b_v1 = 123456789ull;
    uint64_t B_v1 = modexp64(g_v1, b_v1, p_v1);

    const std::string greeting = "Paired with SmartLock. Pairing secret: FLAG{benchmark_sample_flag_1234}";

    // Benchmark v1 Handshake
    for (int r = 0; r < runs; ++r) {
        auto t0 = std::chrono::high_resolution_clock::now();

        // 1. Negotiation: String comparison & suite selection
        std::string suite = "AES256-GCM";

        // 2. Lock creates certificate signature (unverified by client)
        EVP_MD_CTX* sign_ctx = EVP_MD_CTX_new();
        EVP_DigestSignInit(sign_ctx, nullptr, EVP_sha256(), nullptr, rsa);
        std::string cert_data = "smartlock.local";
        size_t sig_len = 0;
        EVP_DigestSign(sign_ctx, nullptr, &sig_len, (const unsigned char*)cert_data.data(), cert_data.size());
        std::vector<uint8_t> sig(sig_len);
        EVP_DigestSign(sign_ctx, sig.data(), &sig_len, (const unsigned char*)cert_data.data(), cert_data.size());
        EVP_MD_CTX_free(sign_ctx);

        // 3. DH exchange on 40-bit prime
        uint64_t a_v1 = 987654321ull;
        uint64_t A_v1 = modexp64(g_v1, a_v1, p_v1);
        uint64_t s_client = modexp64(B_v1, a_v1, p_v1);
        uint64_t s_server = modexp64(A_v1, b_v1, p_v1);

        // 4. Raw key conversion
        auto k_s = v1::session_key(s_server);
        auto k_c = v1::session_key(s_client);

        // 5. Greeting encryption & decryption
        std::vector<uint8_t> nonce(12, 0xAA);
        auto ct = v1::record_encrypt(k_s, nonce, (const uint8_t*)greeting.data(), greeting.size());
        auto pt = v1::record_decrypt(k_c, nonce, ct);

        auto t1 = std::chrono::high_resolution_clock::now();
        double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        v1_times.push_back(ms);
    }

    // Benchmark v2 Handshake
    for (int r = 0; r < runs; ++r) {
        auto t0 = std::chrono::high_resolution_clock::now();

        // 1. Negotiation policy check (choose_suite)
        std::string suite = "AES256-GCM";

        // 2. Server creates certificate signature
        EVP_MD_CTX* sign_ctx = EVP_MD_CTX_new();
        EVP_DigestSignInit(sign_ctx, nullptr, EVP_sha256(), nullptr, rsa);
        std::string cert_data = "smartlock.local";
        size_t sig_len = 0;
        EVP_DigestSign(sign_ctx, nullptr, &sig_len, (const unsigned char*)cert_data.data(), cert_data.size());
        std::vector<uint8_t> sig(sig_len);
        EVP_DigestSign(sign_ctx, sig.data(), &sig_len, (const unsigned char*)cert_data.data(), cert_data.size());
        EVP_MD_CTX_free(sign_ctx);

        // Client validates pinned certificate signature
        EVP_MD_CTX* verify_ctx = EVP_MD_CTX_new();
        EVP_DigestVerifyInit(verify_ctx, nullptr, EVP_sha256(), nullptr, rsa);
        EVP_DigestVerify(verify_ctx, sig.data(), sig_len, (const unsigned char*)cert_data.data(), cert_data.size());
        EVP_MD_CTX_free(verify_ctx);

        // 3. RFC 3526 2048-bit DH Key Generation & Transcript Signing
        BN_CTX* bn_ctx = BN_CTX_new();
        BIGNUM* g = BN_new(); BN_set_word(g, 2);
        BIGNUM* b = BN_new(); BN_rand(b, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
        BIGNUM* B = BN_new(); BN_mod_exp(B, g, b, p2048, bn_ctx);

        // Sign transcript (offer|suite|B)
        std::string transcript = "AES256-GCM,AES128-GCM|AES256-GCM|B_HEX_SAMPLE";
        sign_ctx = EVP_MD_CTX_new();
        EVP_DigestSignInit(sign_ctx, nullptr, EVP_sha256(), nullptr, rsa);
        EVP_DigestSign(sign_ctx, nullptr, &sig_len, (const unsigned char*)transcript.data(), transcript.size());
        sig.resize(sig_len);
        EVP_DigestSign(sign_ctx, sig.data(), &sig_len, (const unsigned char*)transcript.data(), transcript.size());
        EVP_MD_CTX_free(sign_ctx);

        // Client verifies transcript signature
        verify_ctx = EVP_MD_CTX_new();
        EVP_DigestVerifyInit(verify_ctx, nullptr, EVP_sha256(), nullptr, rsa);
        EVP_DigestVerify(verify_ctx, sig.data(), sig_len, (const unsigned char*)transcript.data(), transcript.size());
        EVP_MD_CTX_free(verify_ctx);

        // Client DH generation
        BIGNUM* a = BN_new(); BN_rand(a, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
        BIGNUM* A = BN_new(); BN_mod_exp(A, g, a, p2048, bn_ctx);

        // Compute 2048-bit shared secret
        BIGNUM* s_bn = BN_new(); BN_mod_exp(s_bn, B, a, p2048, bn_ctx);
        std::vector<uint8_t> shared_sec(256);
        BN_bn2binpad(s_bn, shared_sec.data(), 256);

        // 4. HKDF Key Derivation for both directions
        auto k_c2s = v2::derive_key(shared_sec, "c2s");
        auto k_s2c = v2::derive_key(shared_sec, "s2c");

        // 5. Sequence-bound Greeting seal & open
        auto rec = v2::seal(k_s2c, 0, (const uint8_t*)greeting.data(), greeting.size());
        auto pt = v2::open_record(k_s2c, rec, 0);

        BN_free(A); BN_free(a); BN_free(B); BN_free(b); BN_free(g); BN_free(s_bn);
        BN_CTX_free(bn_ctx);

        auto t1 = std::chrono::high_resolution_clock::now();
        double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        v2_times.push_back(ms);
    }

    BN_free(p2048);
    EVP_PKEY_free(rsa);
}

void run_record_benchmark(double& v1_lat_us, double& v2_lat_us, size_t iterations = 50000) {
    std::vector<uint8_t> key(32, 0x55);
    std::vector<uint8_t> nonce(12, 0x11);
    std::string test_cmd = "STATE LOCKED unlocks=42"; // 23 bytes

    // v1 record latency
    auto t0 = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < iterations; ++i) {
        auto ct = v1::record_encrypt(key, nonce, (const uint8_t*)test_cmd.data(), test_cmd.size());
        auto pt = v1::record_decrypt(key, nonce, ct);
    }
    auto t1 = std::chrono::high_resolution_clock::now();
    v1_lat_us = std::chrono::duration<double, std::micro>(t1 - t0).count() / iterations;

    // v2 record latency
    t0 = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < iterations; ++i) {
        auto rec = v2::seal(key, i, (const uint8_t*)test_cmd.data(), test_cmd.size());
        auto pt = v2::open_record(key, rec, i);
    }
    t1 = std::chrono::high_resolution_clock::now();
    v2_lat_us = std::chrono::duration<double, std::micro>(t1 - t0).count() / iterations;
}

void run_throughput_benchmark(std::vector<double>& v1_mbps, std::vector<double>& v2_mbps,
                              size_t records_per_run = 10000, int runs = 5) {
    v1_mbps.clear();
    v2_mbps.clear();

    const size_t rec_size = 1024; // 1 KiB
    std::vector<uint8_t> payload(rec_size, 0x7E);
    std::vector<uint8_t> key(32, 0x33);
    std::vector<uint8_t> nonce(12, 0x44);

    double total_bytes = (double)records_per_run * rec_size;

    // v1 Throughput
    for (int r = 0; r < runs; ++r) {
        auto t0 = std::chrono::high_resolution_clock::now();
        for (size_t i = 0; i < records_per_run; ++i) {
            auto ct = v1::record_encrypt(key, nonce, payload.data(), payload.size());
            auto pt = v1::record_decrypt(key, nonce, ct);
        }
        auto t1 = std::chrono::high_resolution_clock::now();
        double s = std::chrono::duration<double>(t1 - t0).count();
        double mbps = (total_bytes / (1024.0 * 1024.0)) / s; // MB/s
        v1_mbps.push_back(mbps);
    }

    // v2 Throughput
    for (int r = 0; r < runs; ++r) {
        auto t0 = std::chrono::high_resolution_clock::now();
        for (size_t i = 0; i < records_per_run; ++i) {
            auto rec = v2::seal(key, i, payload.data(), payload.size());
            auto pt = v2::open_record(key, rec, i);
        }
        auto t1 = std::chrono::high_resolution_clock::now();
        double s = std::chrono::duration<double>(t1 - t0).count();
        double mbps = (total_bytes / (1024.0 * 1024.0)) / s; // MB/s
        v2_mbps.push_back(mbps);
    }
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "================================================================\n";
    std::cout << " CS3002 Assignment 2 - Part D Performance Benchmark Tool\n";
    std::cout << " Comparing SmartLock v1 (AES256-GCM) vs SmartLock v2\n";
    std::cout << "================================================================\n\n";

    std::cout << "[*] Running Handshake Benchmark (30 runs each)...\n";
    std::vector<double> v1_hs, v2_hs;
    run_handshake_benchmark(v1_hs, v2_hs, 30);
    Stats v1_hs_stats = compute_stats(v1_hs);
    Stats v2_hs_stats = compute_stats(v2_hs);
    std::cout << "    v1 Handshake: " << v1_hs_stats.mean << " ms (+/- " << v1_hs_stats.stddev << " ms)\n";
    std::cout << "    v2 Handshake: " << v2_hs_stats.mean << " ms (+/- " << v2_hs_stats.stddev << " ms)\n\n";

    std::cout << "[*] Running Per-Record Latency Benchmark (50,000 iterations)...\n";
    double v1_lat = 0.0, v2_lat = 0.0;
    run_record_benchmark(v1_lat, v2_lat, 50000);
    std::cout << "    v1 Latency (protect + open): " << v1_lat << " us\n";
    std::cout << "    v2 Latency (protect + open): " << v2_lat << " us\n\n";

    std::cout << "[*] Running Throughput Benchmark (1 KiB records, 10,000/run, 5 runs)...\n";
    std::vector<double> v1_tp, v2_tp;
    run_throughput_benchmark(v1_tp, v2_tp, 10000, 5);
    Stats v1_tp_stats = compute_stats(v1_tp);
    Stats v2_tp_stats = compute_stats(v2_tp);
    std::cout << "    v1 Throughput: " << v1_tp_stats.mean << " MB/s (+/- " << v1_tp_stats.stddev << " MB/s)\n";
    std::cout << "    v2 Throughput: " << v2_tp_stats.mean << " MB/s (+/- " << v2_tp_stats.stddev << " MB/s)\n\n";

    // Summary Table Display
    std::cout << "========================================================================================\n";
    std::cout << "                          PART D BENCHMARK SUMMARY TABLE                                \n";
    std::cout << "========================================================================================\n";
    std::cout << std::left << std::setw(30) << "Metric"
              << std::setw(25) << "SmartLock v1 (Baseline)"
              << std::setw(25) << "SmartLock v2 (Hardened)"
              << std::setw(15) << "Ratio (v2/v1)" << "\n";
    std::cout << "----------------------------------------------------------------------------------------\n";

    std::ostringstream s1_v1, s1_v2;
    s1_v1 << std::fixed << std::setprecision(2) << v1_hs_stats.mean << " +/- " << v1_hs_stats.stddev << " ms";
    s1_v2 << std::fixed << std::setprecision(2) << v2_hs_stats.mean << " +/- " << v2_hs_stats.stddev << " ms";
    double hs_ratio = v2_hs_stats.mean / v1_hs_stats.mean;
    std::cout << std::left << std::setw(30) << "Handshake Time (30 runs)"
              << std::setw(25) << s1_v1.str()
              << std::setw(25) << s1_v2.str()
              << std::fixed << std::setprecision(2) << hs_ratio << "x" << "\n";

    std::cout << std::left << std::setw(30) << "Wire Payload Overhead"
              << std::setw(25) << "+16 bytes (Tag)"
              << std::setw(25) << "+24 bytes (Seq+Tag)"
              << "+8 bytes" << "\n";

    std::ostringstream s2_v1, s2_v2;
    s2_v1 << std::fixed << std::setprecision(2) << v1_lat << " us";
    s2_v2 << std::fixed << std::setprecision(2) << v2_lat << " us";
    std::cout << std::left << std::setw(30) << "Record Latency (Seal+Open)"
              << std::setw(25) << s2_v1.str()
              << std::setw(25) << s2_v2.str()
              << std::fixed << std::setprecision(2) << (v2_lat / v1_lat) << "x" << "\n";

    std::ostringstream s3_v1, s3_v2;
    s3_v1 << std::fixed << std::setprecision(2) << v1_tp_stats.mean << " +/- " << v1_tp_stats.stddev << " MB/s";
    s3_v2 << std::fixed << std::setprecision(2) << v2_tp_stats.mean << " +/- " << v2_tp_stats.stddev << " MB/s";
    double tp_ratio = (v2_tp_stats.mean / v1_tp_stats.mean) * 100.0;
    std::cout << std::left << std::setw(30) << "Throughput (1 KiB records)"
              << std::setw(25) << s3_v1.str()
              << std::setw(25) << s3_v2.str()
              << std::fixed << std::setprecision(1) << tp_ratio << "% retention" << "\n";
    std::cout << "========================================================================================\n\n";

    // Export raw data to CSV
    std::ofstream csv("benchmark_results.csv");
    csv << "metric,run_index,v1_value,v2_value,unit\n";
    for (size_t i = 0; i < v1_hs.size(); ++i) {
        csv << "handshake," << (i + 1) << "," << v1_hs[i] << "," << v2_hs[i] << ",ms\n";
    }
    for (size_t i = 0; i < v1_tp.size(); ++i) {
        csv << "throughput," << (i + 1) << "," << v1_tp[i] << "," << v2_tp[i] << ",MB/s\n";
    }
    csv << "record_latency,1," << v1_lat << "," << v2_lat << ",us\n";
    csv << "wire_overhead,1,16,24,bytes\n";
    csv.close();
    std::cout << "[+] Exported raw data to 'benchmark_results.csv'.\n";

    // Export text summary
    std::ofstream sum("benchmark_summary.txt");
    sum << "CS3002 Assignment 2 - Part D Benchmark Summary\n";
    sum << "Handshake v1: " << v1_hs_stats.mean << " +/- " << v1_hs_stats.stddev << " ms\n";
    sum << "Handshake v2: " << v2_hs_stats.mean << " +/- " << v2_hs_stats.stddev << " ms\n";
    sum << "Overhead v1: 16 bytes, Latency: " << v1_lat << " us\n";
    sum << "Overhead v2: 24 bytes, Latency: " << v2_lat << " us\n";
    sum << "Throughput v1: " << v1_tp_stats.mean << " +/- " << v1_tp_stats.stddev << " MB/s\n";
    sum << "Throughput v2: " << v2_tp_stats.mean << " +/- " << v2_tp_stats.stddev << " MB/s\n";
    sum.close();
    std::cout << "[+] Exported text summary to 'benchmark_summary.txt'.\n";

    return 0;
}
