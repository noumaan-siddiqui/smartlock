// Student Name: [Your Name]
// Student ID:   [Your Roll Number, e.g., 23i-0001]
// Assignment:   CS3002 Assignment 2 - Part C (SmartLock v2 Security Module)
//
// Description:
//   Implements the core cryptographic policies and mechanisms for SmartLock v2:
//   1. Strict cipher suite policy (rejects NULL, never downgrades).
//   2. Cryptographic key derivation from DH shared secret via HKDF-SHA256 (evp_kdf).
//   3. Per-record unique 12-byte nonces derived from sequence numbers.
//   4. Sequence-bound Authenticated Encryption with Associated Data (AES-GCM AEAD).
//   5. Strict sequence verification preventing replay and reordering attacks.

#include "securelink2.hpp"
#include <stdexcept>
#include <vector>
#include <string>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

namespace sl2 {

std::vector<std::string> strong_suites() {
    return {"AES256-GCM", "AES128-GCM"};
}

std::string choose_suite(const std::vector<std::string>& hub_offer) {
    bool has_aes256 = false;
    bool has_aes128 = false;

    for (const auto& s : hub_offer) {
        if (s == "AES256-GCM") has_aes256 = true;
        if (s == "AES128-GCM") has_aes128 = true;
    }

    if (has_aes256) return "AES256-GCM";
    if (has_aes128) return "AES128-GCM";

    // Rejects NULL and any unapproved or weak cipher suites
    return "";
}

std::vector<uint8_t> derive_key(const std::vector<uint8_t>& shared_secret,
                                const std::string& suite, const std::string& context) {
    int kl = keylen(suite);
    if (kl <= 0) {
        throw std::runtime_error("invalid suite for key derivation");
    }

    std::vector<uint8_t> out(kl);

    // OpenSSL 3.0 evp_kdf HKDF API
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (kdf) {
        EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
        EVP_KDF_free(kdf);
        if (kctx) {
            char digest_name[] = "SHA256";
            OSSL_PARAM params[5];
            params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest_name, sizeof(digest_name));
            params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                                          (void*)shared_secret.data(), shared_secret.size());
            params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                                          (void*)context.data(), context.size());
            params[3] = OSSL_PARAM_construct_end();

            int ret = EVP_KDF_derive(kctx, out.data(), out.size(), params);
            EVP_KDF_CTX_free(kctx);
            if (ret > 0) return out;
        }
    }

    // OpenSSL 1.1.1 fallback using EVP_PKEY_CTX HKDF
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (pctx) {
        if (EVP_PKEY_derive_init(pctx) > 0 &&
            EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) > 0 &&
            EVP_PKEY_CTX_set1_hkdf_key(pctx, shared_secret.data(), (int)shared_secret.size()) > 0 &&
            EVP_PKEY_CTX_add1_hkdf_info(pctx, (const unsigned char*)context.data(), (int)context.size()) > 0) {
            size_t outlen = out.size();
            if (EVP_PKEY_derive(pctx, out.data(), &outlen) > 0) {
                EVP_PKEY_CTX_free(pctx);
                return out;
            }
        }
        EVP_PKEY_CTX_free(pctx);
    }

    throw std::runtime_error("hkdf key derivation failed");
}

std::vector<uint8_t> make_nonce(uint64_t seqno) {
    std::vector<uint8_t> nonce(12, 0);
    for (int i = 11; i >= 4; --i) {
        nonce[i] = (uint8_t)(seqno & 0xff);
        seqno >>= 8;
    }
    return nonce;
}

std::vector<uint8_t> seal(const std::vector<uint8_t>& key, uint64_t seqno, const std::string& plaintext) {
    const EVP_CIPHER* cipher = nullptr;
    if (key.size() == 32) cipher = EVP_aes_256_gcm();
    else if (key.size() == 16) cipher = EVP_aes_128_gcm();
    else throw std::runtime_error("invalid key length for seal");

    std::vector<uint8_t> seq_bytes(8);
    for (int i = 7; i >= 0; --i) {
        seq_bytes[i] = (uint8_t)((seqno >> (8 * (7 - i))) & 0xff);
    }

    auto nonce = make_nonce(seqno);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("failed to allocate cipher context");

    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("encrypt init failed");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(), nullptr) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("failed to set ivlen");
    }

    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("failed to set key and nonce");
    }

    // Bind sequence number as Additional Authenticated Data (AAD)
    int dummy_len = 0;
    if (EVP_EncryptUpdate(ctx, nullptr, &dummy_len, seq_bytes.data(), (int)seq_bytes.size()) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("failed to set aad");
    }

    std::vector<uint8_t> ct(plaintext.size());
    int len = 0;
    if (EVP_EncryptUpdate(ctx, ct.data(), &len, (const unsigned char*)plaintext.data(), (int)plaintext.size()) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("encrypt update failed");
    }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, ct.data() + len, &final_len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("encrypt final failed");
    }
    ct.resize(len + final_len);

    std::vector<uint8_t> tag(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("failed to get auth tag");
    }
    EVP_CIPHER_CTX_free(ctx);

    // Framing: [8-byte seqno] || [ciphertext] || [16-byte tag]
    std::vector<uint8_t> record;
    record.reserve(8 + ct.size() + 16);
    record.insert(record.end(), seq_bytes.begin(), seq_bytes.end());
    record.insert(record.end(), ct.begin(), ct.end());
    record.insert(record.end(), tag.begin(), tag.end());

    return record;
}

std::string open_record(const std::vector<uint8_t>& key, const std::vector<uint8_t>& record,
                        uint64_t expected_seqno) {
    if (record.size() < 8 + 16) {
        throw std::runtime_error("short record");
    }

    uint64_t rec_seqno = 0;
    for (int i = 0; i < 8; ++i) {
        rec_seqno = (rec_seqno << 8) | record[i];
    }

    if (rec_seqno != expected_seqno) {
        throw std::runtime_error("sequence number mismatch: expected " +
                                 std::to_string(expected_seqno) +
                                 ", got " + std::to_string(rec_seqno));
    }

    const EVP_CIPHER* cipher = nullptr;
    if (key.size() == 32) cipher = EVP_aes_256_gcm();
    else if (key.size() == 16) cipher = EVP_aes_128_gcm();
    else throw std::runtime_error("invalid key length for open_record");

    std::vector<uint8_t> seq_bytes(record.begin(), record.begin() + 8);
    size_t ct_len = record.size() - 8 - 16;
    const uint8_t* ct_ptr = record.data() + 8;
    const uint8_t* tag_ptr = record.data() + 8 + ct_len;

    auto nonce = make_nonce(rec_seqno);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("failed to allocate cipher context");

    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("decrypt init failed");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(), nullptr) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("failed to set ivlen");
    }

    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("failed to set key and nonce");
    }

    int dummy_len = 0;
    if (EVP_DecryptUpdate(ctx, nullptr, &dummy_len, seq_bytes.data(), (int)seq_bytes.size()) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("failed to set aad");
    }

    std::vector<uint8_t> pt(ct_len);
    int len = 0;
    if (EVP_DecryptUpdate(ctx, pt.data(), &len, ct_ptr, (int)ct_len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("decrypt update failed");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag_ptr) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("failed to set tag");
    }

    int final_len = 0;
    int ok = EVP_DecryptFinal_ex(ctx, pt.data() + len, &final_len);
    EVP_CIPHER_CTX_free(ctx);

    if (ok <= 0) {
        throw std::runtime_error("auth tag check failed");
    }

    pt.resize(len + final_len);
    return std::string(pt.begin(), pt.end());
}

}  // namespace sl2
