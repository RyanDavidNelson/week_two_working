# eCTF Timeline and Task List

Each week produces a self-contained module for formal verification.

---

## Week 1: Security Primitives Module ✓

### `firmware/inc/security.h`
- [x] Define `secure_compare(a, b, len) → bool` (constant-time, no early exit)
- [x] Define `check_pin(input) → bool` (5s delay on failure, glitch-resistant)
- [x] Define `validate_permission(group_id, perm_type) → bool`
- [x] Define `validate_slot(slot) → bool` (0 ≤ slot < 8)
- [x] Define `validate_name(name, len) → bool` (printable ASCII)
- [x] Define `validate_perm_count(count) → bool` (0 ≤ count ≤ 8)
- [x] Define `secure_zero(ptr, len)` (volatile, not optimized away)
- [x] Define `security_halt()` (infinite loop on security violation)
- [x] Define TRNG functions: `trng_init()`, `trng_read_word()`, `trng_read_byte()`
- [x] Define timing functions: `delay_cycles()`, `delay_ms()`, `random_delay()`

### `firmware/src/security.c`
- [x] Implement `secure_compare()` — XOR accumulator, volatile result
- [x] Implement `check_pin()` — double-check with random delay, halt on mismatch
- [x] Implement `validate_permission()` — iterate `global_permissions[0..perm_count-1]`
- [x] Implement `validate_slot()` — bounds check
- [x] Implement `validate_name()` — character range check, null termination
- [x] Implement `validate_perm_count()` — bounds check
- [x] Implement `secure_zero()` — volatile pointer write loop
- [x] Implement `security_halt()` — infinite nop loop
- [x] Implement TRNG functions using hardware TRNG
- [x] Implement timing functions using assembly delay

### `firmware/src/commands.c` 
- [ ] Add `validate_slot()` call at entry of `read()`, `write()`, `receive()`
- [ ] Add `validate_perm_count()` in preparation for protocol work
- [ ] Add `validate_name()` call in `write()`
- [ ] Add `contents_len <= MAX_CONTENTS_SIZE` check in `write()`

### `firmware/src/filesystem.c`
- [ ] Replace `strcpy` with `strncpy` + forced null termination
- [ ] Add length validation before all `memcpy` calls

---

## Week 2: Cryptographic Module ✓

### `ectf26_design/src/gen_secrets.py`
- [x] Generate `GCM_KEY[32]` using `secrets.token_bytes(32)`
- [x] Generate `AUTH_KEY[32]` using `secrets.token_bytes(32)`
- [x] Store deployment group IDs
- [x] Output as hex-encoded JSON

### `firmware/secrets_to_c_header.py`
- [x] Parse keys from secrets file
- [x] Define canonical permission serialization (little-endian, packed)
- [x] Compute `PERMISSION_MAC = HMAC-SHA256(AUTH_KEY, perm_count || permissions)`
- [x] Output `secrets.h` with GCM_KEY (aligned for KEYSTORE) and AUTH_KEY (byte array)

### `firmware/inc/crypto.h`
- [x] Define `crypto_init()` — load GCM_KEY into KEYSTORE
- [x] Define `aes_gcm_encrypt(nonce, aad, aad_len, plaintext, pt_len, ciphertext, tag) → int`
- [x] Define `aes_gcm_decrypt(nonce, aad, aad_len, ciphertext, ct_len, tag, plaintext) → int`
- [x] Define `hmac_sha256(key, data, len, output) → int` — wolfcrypt wrapper
- [x] Define `generate_nonce(nonce) → int` — 12 bytes from TRNG
- [x] Define constants: `GCM_KEY_SIZE 32`, `NONCE_SIZE 12`, `TAG_SIZE 16`, `HMAC_SIZE 32`
- [x] Define KEYSTORE slot: `KEYSTORE_SLOT_GCM 0`

### `firmware/src/crypto.c`
- [x] Implement `crypto_init()` — load GCM_KEY into KEYSTORE slot 0
- [x] Implement `aes_gcm_encrypt()` using hardware AESADV + KEYSTORE
- [x] Implement `aes_gcm_decrypt()` using hardware AESADV (tag verify in hardware)
- [x] Implement `hmac_sha256()` using wolfcrypt `wc_Hmac*` functions
- [x] Implement `generate_nonce()` — 12 bytes from trng_read_byte()
- [x] Add double-computation for GCM operations (glitch protection)
- [x] Add random delays around crypto operations

### Key Architecture
- [x] GCM_KEY in KEYSTORE slot 0 (hardware protected, write-only)
- [x] AUTH_KEY in flash/RAM (required for wolfcrypt HMAC)
- [x] No software access to GCM_KEY after init


---

## Week 3: Secure Storage Module

### `firmware/inc/filesystem.h`
- [ ] Update `file_t` structure:
  - [ ] `slot`, `uuid[16]`, `group_id`, `name[32]`, `contents_len`
  - [ ] `nonce[12]`, `tag[16]`, `ciphertext[MAX_CONTENTS_SIZE]`
- [ ] Define `secure_write_file(slot, group_id, name, contents, len, uuid) → int`
- [ ] Define `secure_read_file(slot, dest) → int`
- [ ] Define AAD construction helpers

### `firmware/src/filesystem.c`
- [ ] Implement `build_storage_aad()` — slot || uuid || group_id || name
- [ ] Implement `secure_write_file()`:
  - [ ] Validate all inputs
  - [ ] Generate 12-byte nonce via TRNG
  - [ ] Construct AAD
  - [ ] GCM encrypt (plaintext → ciphertext + tag)
  - [ ] Write metadata + nonce + ciphertext + tag to flash
- [ ] Implement `secure_read_file()`:
  - [ ] Validate slot bounds and in-use
  - [ ] Load file data
  - [ ] Reconstruct AAD
  - [ ] GCM decrypt (verify tag in hardware)
  - [ ] Return plaintext on success, error on tag failure
  - [ ] `secure_zero()` plaintext buffer on error

### `firmware/src/commands.c` (storage integration)
- [ ] Update `write()` to call `secure_write_file()`
- [ ] Update `read()` to call `secure_read_file()`
- [ ] Add permission check BEFORE calling `secure_read_file()`
- [ ] Add TOCTOU defense: verify group_id matches after load
- [ ] `secure_zero()` plaintext after sending response


---

## Week 4: Protocol Module

### `firmware/inc/commands.h`
- [ ] Define protocol message structures:
  - [ ] `receive_request_t`: slot, receiver_challenge[12]
  - [ ] `challenge_response_t`: sender_challenge[12], sender_auth[32]
  - [ ] `permission_proof_t`: receiver_auth[32], perm_count, permissions[], permission_mac[32]
  - [ ] `file_data_t`: nonce[12], ciphertext[], tag[16]
- [ ] Define HMAC domain separator constants

### HMAC Helper Functions
- [ ] `compute_sender_auth(receiver_challenge, output)` — HMAC(AUTH_KEY, challenge || "sender")
- [ ] `compute_receiver_auth(sender_challenge, output)` — HMAC(AUTH_KEY, challenge || "receiver")
- [ ] `verify_permission_mac(perm_count, permissions, received_mac) → bool`

### `firmware/src/commands.c` — RECEIVE Protocol

**Requester side** (`receive()`):
- [ ] Generate `receiver_challenge` (12 bytes, TRNG)
- [ ] Send `slot || receiver_challenge`
- [ ] Receive `sender_challenge || sender_auth`
- [ ] Verify `sender_auth = HMAC(AUTH_KEY, receiver_challenge || "sender")`
- [ ] Compute `receiver_auth = HMAC(AUTH_KEY, sender_challenge || "receiver")`
- [ ] Send `receiver_auth || perm_count || permissions || PERMISSION_MAC`
- [ ] Receive `nonce || ciphertext || tag`
- [ ] Construct transfer_AAD = receiver_challenge || sender_challenge || slot || uuid || group_id
- [ ] GCM decrypt with transfer_AAD (verifies integrity + authenticity)
- [ ] Verify local RECEIVE permission for group_id
- [ ] Re-encrypt for local storage with new nonce and storage_AAD
- [ ] Store to flash

**Responder side** (`listen()` RECEIVE_MSG):
- [ ] Receive `requested_slot || receiver_challenge`
- [ ] Validate slot, load file metadata
- [ ] Generate `sender_challenge` (TRNG)
- [ ] Compute `sender_auth = HMAC(AUTH_KEY, receiver_challenge || "sender")`
- [ ] Send `sender_challenge || sender_auth`
- [ ] Receive `receiver_auth || perm_count || permissions || permission_mac` (2000ms timeout)
- [ ] Validate `perm_count <= MAX_PERMS`
- [ ] Verify `permission_mac = HMAC(AUTH_KEY, perm_count || permissions)`
- [ ] Verify `receiver_auth = HMAC(AUTH_KEY, sender_challenge || "receiver")`
- [ ] Check RECEIVE permission exists for file's group_id in received permissions
- [ ] Load and decrypt stored file (verify storage integrity)
- [ ] Generate `transfer_nonce` (TRNG)
- [ ] Construct transfer_AAD
- [ ] GCM encrypt for transfer
- [ ] Send `transfer_nonce || transfer_ciphertext || transfer_tag`

### `firmware/src/commands.c` — INTERROGATE Protocol

**Requester side** (`interrogate()`):
- [ ] Generate challenge (12 bytes, TRNG)
- [ ] Compute `auth = HMAC(AUTH_KEY, challenge || "interrogate_req")`
- [ ] Send `challenge || auth || perm_count || permissions || PERMISSION_MAC`
- [ ] Receive `response_auth || filtered_list`
- [ ] Verify `response_auth = HMAC(AUTH_KEY, challenge || filtered_list || "interrogate_resp")`

**Responder side** (`listen()` INTERROGATE_MSG):
- [ ] Receive and verify `permission_mac`
- [ ] Verify `auth = HMAC(AUTH_KEY, challenge || "interrogate_req")`
- [ ] Filter file list by requester's RECEIVE permissions
- [ ] Compute `response_auth = HMAC(AUTH_KEY, challenge || filtered_list || "interrogate_resp")`
- [ ] Send `response_auth || filtered_list`

### `firmware/src/host_messaging.c`
- [ ] Add 2000ms timeout to `uart_readbyte()`
- [ ] Add 5000ms total protocol timeout
- [ ] Consistent error timing on all paths

### Hardening
- [ ] Delete `boot_flag()`, obfuscated arrays, `crypto_example()`
- [ ] Remove all error logging and unnecessary I/O commands
- [ ] Review for Vulnerabilities (strcpy, md5, etc.)
- [ ] Ensure all error paths have consistent timing
- [ ] Test attacks on the secure design if time permits
- [ ] Final `secure_zero()` audit
