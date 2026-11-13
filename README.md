# SmartLock: Cryptographic Protocol Security Engagement

This repository contains the cryptographic security audit, exploit suite, and hardened re-implementation for the **SmartLock** Internet-of-Things (IoT) ecosystem.

* **Course:** CS3002 - Information Security
* **Assignment:** Assignment 2: Break It, Then Build It
* **Language & Toolchain:** C++17, OpenSSL (`libcrypto`), GNU Make, Python 3

---

## Repository Structure

```text
.
├── exploits/                            # Part A: Five-Stage Exploit Suite
│   ├── 23i-0001-A-TASKA1-V1.cpp         # Stage 1: Cipher suite downgrade to NULL
│   ├── 23i-0001-A-TASKA2-V1.cpp         # Stage 2: MITM proxy & impersonation
│   ├── 23i-0001-A-TASKA3-V1.cpp         # Stage 3: Discrete log BSGS on 40-bit prime
│   ├── 23i-0001-A-TASKA4-V1.cpp         # Stage 4: AES-GCM nonce reuse (two-time pad)
│   ├── 23i-0001-A-TASKA5-V1.cpp         # Stage 5: Session & command replay attack
│   └── crack_pin.py                     # Offline MD5 PIN cracker (?d?d?d mask)
├── smartlock/                           # Shipped v1 Implementation (Vulnerable)
│   ├── lock_server.cpp                  # Server daemon
│   ├── hub_client.cpp                   # Client controller
│   ├── slink.hpp                        # v1 wire framing and record crypto
│   ├── pki.hpp                          # RSA helpers
│   ├── instance_generator.cpp           # Deterministic instance builder
│   └── secrets.hpp                      # Instance derivation
├── v2_skeleton/                         # Hardened v2 Implementation
│   ├── securelink2.cpp                  # Security core (Part C)
│   ├── securelink2.hpp                  # Security interface contracts
│   ├── test_securelink2.cpp             # Automated self-check test suite
│   ├── lock_server2.cpp                 # Hardened lock server daemon
│   ├── hub_client2.cpp                  # Hardened controller client
│   ├── dh2048.hpp                       # RFC 3526 2048-bit MODP DH group
│   ├── slink.hpp                        # Framing utilities
│   ├── pki.hpp                          # RSA signature & verification helpers
│   └── Makefile                         # Build system for v2
├── securelink2.cpp                      # Part C top-level deliverable
├── answers_template.txt                 # Part A recovered secrets template
└── BUILD.md                             # Toolchain and compilation guide
```

---

## Part A: Exploit Demonstrations

Each Part A exploit attacks one stage of the v1 protocol:

1. **TASKA1 (Negotiation Downgrade):** Acts as an on-path proxy rewriting `suites` in `HELLO` to `NULL`. The lock defaults to unencrypted communication, exposing the pairing secret flag and commands in cleartext.
2. **TASKA2 (MITM Relay & Impersonation):** Exploits unvalidated RSA certificates and unauthenticated DH parameters. Negotiates two independent DH session keys ($K_{lock}$ and $K_{hub}$), intercepting and decrypting all traffic in flight while harvesting the PIN hash.
3. **TASKA3 (Keying Recovery via BSGS):** Solves $g^b \equiv B \pmod p$ on the 40-bit prime in $<100$ ms using the Baby-Step Giant-Step algorithm ($O(\sqrt{p})$). Derives the session key and decrypts the greeting record to recover the flag.
4. **TASKA4 (Nonce Reuse Plaintext Extraction):** Exploits reuse of `static_nonce` across records. XORing two records ($C_1 \oplus C_2$) cancels the AES-GCM keystream. Using the known greeting prefix (`"Paired with SmartLock. Pairing secret: "`), recovers the STATUS response without the key.
5. **TASKA5 (Replay Attack):** Replays a captured handshake and `UNLOCK` command against a new TCP session. Due to static DH exponents and missing sequence numbers, the lock verifies the tag, executes `UNLOCK`, and increments its counter.

### Compiling Part A Exploits:
```bash
cd exploits
g++ -std=c++17 -O2 23i-0001-A-TASKA1-V1.cpp -lcrypto -o taska1
g++ -std=c++17 -O2 23i-0001-A-TASKA2-V1.cpp -lcrypto -o taska2
g++ -std=c++17 -O2 23i-0001-A-TASKA3-V1.cpp -lcrypto -o taska3
g++ -std=c++17 -O2 23i-0001-A-TASKA4-V1.cpp -lcrypto -o taska4
g++ -std=c++17 -O2 23i-0001-A-TASKA5-V1.cpp -lcrypto -o taska5
```

---

## Part B: Design SmartLock v2

* **Threat Model:** Dolev-Yao on-path attacker capable of sniffing, modifying, dropping, and replaying packets. Attacker does not possess the lock's RSA private key or pairing PIN.
* **Stage 1 (Negotiation):** Rejection of `NULL`. Server cryptographically signs the negotiation transcript (`offer|suite|B`) with its RSA private key; hub verifies with pinned public key.
* **Stage 2 (Authentication):** Client-side RSA certificate pinning. PIN protected on wire via PAKE/encrypted tunnel and at rest via memory-hard salted KDF (e.g. Argon2id / PBKDF2).
* **Stage 3 (Keying):** RFC 3526 2048-bit MODP Diffie-Hellman group with ephemeral exponents (PFS). Session keys derived using HKDF-SHA256 (`evp_kdf`) with directional separation (`"c2s"` and `"s2c"`).
* **Stage 4 (Message Protection):** AES-GCM AEAD with an explicit monotonic nonce derivation rule (`make_nonce(seqno)`), ensuring zero IV reuse.
* **Stage 5 (Anti-Replay):** Monotonic 64-bit sequence numbers embedded in records and bound as Additional Authenticated Data (AAD) in AES-GCM. Out-of-order or duplicate records are immediately rejected.

---

## Part C: Implementation & Verification

### Building and Running v2:
```bash
cd v2_skeleton
make clean && make
./lock_server2 ../smartlock/instance.txt
./hub_client2 ../smartlock/instance.txt 127.0.0.1
```

### Running the Part C.1 Self-Checks:
```bash
cd v2_skeleton
g++ -std=c++17 -O2 test_securelink2.cpp securelink2.cpp -lcrypto -o test_securelink2
./test_securelink2
```
All 6 automated checks pass (Downgrade protection, HKDF derivation, unique nonces, AEAD seal/open, replay rejection, and source cleanliness scan).
