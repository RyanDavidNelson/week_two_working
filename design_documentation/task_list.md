# eCTF Timeline and Task List

Each week produces a self-contained module for formal verification.

---

## Week 1: Security Primitives Module

### `firmware/inc/security.h`
- [ ] Define `secure_compare(a, b, len) → bool` (constant-time, no early exit)
- [ ] Define `check_pin(input) → bool` (5s delay on failure, glitch-resistant)
- [ ] Define `validate_permission(group_id, perm_type) → bool`
- [ ] Define `validate_slot(slot) → bool` (0 ≤ slot < 8)
- [ ] Define `validate_name(name, len) → bool` (printable ASCII)
- [ ] Define `validate_perm_count(count) → bool` (0 ≤ count ≤ 8)
- [ ] Define `explicit_bzero(ptr, len)` (volatile, not optimized away)

### `firmware/src/security.c`
- [ ] Implement `secure_compare()` — XOR accumulator, volatile result
- [ ] Implement `check_pin()` — double-check with random delay, halt on mismatch
- [ ] Implement `validate_permission()` — iterate `global_permissions[0..perm_count-1]`
- [ ] Implement `validate_slot()` — bounds check
- [ ] Implement `validate_name()` — character range check, null termination
- [ ] Implement `validate_perm_count()` — bounds check
- [ ] Implement `explicit_bzero()` — volatile pointer write loop

### `firmware/src/commands.c` 
- [ ] Add `validate_slot()` call at entry of `read()`, `write()`, `receive()`
- [ ] Add `validate_perm_count()` in preparation for protocol work
- [ ] Add `validate_name()` call in `write()`
- [ ] Add `contents_len <= MAX_CONTENTS_SIZE` check in `write()`

### `firmware/src/filesystem.c`
- [ ] Replace `strcpy` with `strncpy` + forced null termination
- [ ] Add length validation before all `memcpy` calls

### Formal Verification Deliverables
- [ ] Prove `secure_compare()` is constant-time 
- [ ] Prove correctness??

---

## Week 2: Cryptographic Module

### `ectf26_design/src/gen_secrets.py`
- [ ] Generate `AES_KEY[32]` using `secrets.token_bytes(32)`
- [ ] Generate `HMAC_KEY[32]` using `secrets.token_bytes(32)`
- [ ] Generate `AUTH_KEY[32]` using `secrets.token_bytes(32)`
- [ ] Store deployment group IDs
- [ ] Output as hex-encoded JSON

### `firmware/secrets_to_c_header.py`
- [ ] Parse keys from secrets file
- [ ] Define canonical permission serialization (little-endian, packed)
- [ ] Compute `PERMISSION_MAC = HMAC-SHA256(AUTH_KEY, perm_count || permissions)`
- [ ] Output `secrets.h` with all keys and `PERMISSION_MAC`

### `firmware/inc/simple_crypto.h`
- [ ] Define `aes_gcm_encrypt(key, iv, plaintext, len, ciphertext) → int` 
- [ ] Define `aes_gcm_decrypt(key, iv, ciphertext, len, plaintext) → int` 
- [ ] Define `hmac_sha256(key, data, len, output) → int` 
- [ ] Define `trng_read(buffer, len) → int` 
- [ ] Define `pkcs7_pad(data, len, block_size) → padded_len` 
- [ ] Define `pkcs7_unpad(data, len) → unpadded_len` 
- [ ] Define constants: `AES_KEY_SIZE 32`, `IV_SIZE 16`, `HMAC_SIZE 32`, `BLOCK_SIZE 16`

### `firmware/src/simple_crypto.c`
- [ ] Implement `aes_gcm_encrypt()` using wolfSSL or hardware AESADV
- [ ] Implement `aes_gcm_decrypt()` using wolfSSL or hardware AESADV
- [ ] Implement `hmac_sha256()` using wolfSSL
- [ ] Implement `trng_read()` wrapping hardware TRNG
- [ ] Implement `pkcs7_pad()` — add 1-16 padding bytes
- [ ] Implement `pkcs7_unpad()` — validate and remove padding
- [ ] Add `explicit_bzero()` for intermediate buffers


---

## Week 3: Secure Storage Module

### `firmware/inc/filesystem.h`
- [ ] Extend `file_t` with `slot`, `iv[16]`, `hmac[32]` fields
- [ ] Define `secure_write_file(slot, group_id, name, contents, len, uuid) → int` 
- [ ] Define `secure_read_file(slot, dest) → int` 
- [ ] Define `compute_file_hmac(file, output) → int` 
- [ ] Define `verify_file_hmac(file) → bool` 

### `firmware/src/filesystem.c`
- [ ] Implement `compute_file_hmac()` — HMAC(HMAC_KEY, slot || uuid || iv || group_id || name || len || ciphertext)
- [ ] Implement `verify_file_hmac()` — recompute and `secure_compare()`
- [ ] Implement `secure_write_file()`:
  - [ ] Validate all inputs
  - [ ] Generate IV via `trng_read()`
  - [ ] Pad and encrypt contents
  - [ ] Compute HMAC
  - [ ] Write to flash, update FAT with UUID
- [ ] Implement `secure_read_file()`:
  - [ ] Validate slot bounds and in-use
  - [ ] Load file from flash
  - [ ] Verify stored slot matches requested slot
  - [ ] Verify HMAC (return error if failed, treat as empty)
  - [ ] Decrypt and unpad contents
  - [ ] `explicit_bzero()` ciphertext buffer

### `firmware/src/commands.c` (storage integration)
- [ ] Update `write()` to call `secure_write_file()`
- [ ] Update `read()` to call `secure_read_file()`
- [ ] Add permission check BEFORE calling `secure_read_file()`
- [ ] Add TOCTOU defense: verify group_id matches after load
- [ ] `explicit_bzero()` plaintext after sending response


---

## Week 4: Protocol Module


### `firmware/inc/commands.h`
- [ ] Update `receive_request_t`: `slot`, `receiver_challenge[16]`
- [ ] Define `receive_auth_t`: `perm_count`, `permissions[]`, `permission_mac[32]`, `response[32]`
- [ ] Update `receive_response_t`: `sender_auth[32]`, `uuid[16]`, `group_id`, `iv[16]`, `ciphertext[]`, `file_hmac[32]`, `transfer_mac[32]`
- [ ] Define `interrogate_request_t`: `perm_count`, `permissions[]`, `permission_mac[32]`
- [ ] Define `interrogate_response_t`: `file_list`, `list_mac[32]`

### `firmware/src/commands.c` — RECEIVE Protocol
- [ ] **Receiver side** (`receive()`):
  - [ ] Generate `receiver_challenge` via TRNG
  - [ ] Send `requested_slot || receiver_challenge`
  - [ ] Receive `sender_challenge`
  - [ ] Compute `response = HMAC(AUTH_KEY, sender_challenge || slot || permissions)`
  - [ ] Send `perm_count || permissions || PERMISSION_MAC || response`
  - [ ] Receive `sender_auth || uuid || group_id || iv || ciphertext || file_hmac || transfer_mac`
  - [ ] Verify `sender_auth = HMAC(AUTH_KEY, receiver_challenge)` (mutual auth)
  - [ ] Verify RECEIVE permission for `group_id`
  - [ ] Verify `transfer_mac = HMAC(HMAC_KEY, slot || uuid || group_id || iv || challenge || ciphertext || file_hmac)`
  - [ ] Verify `file_hmac`
  - [ ] Re-encrypt with new IV, compute new HMAC, store

- [ ] **Sender side** (`listen()` RECEIVE_MSG):
  - [ ] Receive `requested_slot || receiver_challenge`
  - [ ] Validate slot bounds and in-use
  - [ ] Generate `sender_challenge` via TRNG
  - [ ] Send `sender_challenge`
  - [ ] Receive `perm_count || permissions || permission_mac || response`
  - [ ] Validate `perm_count <= MAX_PERMS`
  - [ ] Verify `permission_mac = HMAC(AUTH_KEY, perm_count || permissions)`
  - [ ] Verify `response = HMAC(AUTH_KEY, sender_challenge || slot || permissions)`
  - [ ] Check RECEIVE permission exists for file's group_id
  - [ ] Compute `sender_auth = HMAC(AUTH_KEY, receiver_challenge)`
  - [ ] Load file, compute `transfer_mac`
  - [ ] Send complete response

### `firmware/src/commands.c` — INTERROGATE Protocol
- [ ] **Requester side** (`interrogate()`):
  - [ ] Send `perm_count || permissions || PERMISSION_MAC`
  - [ ] Receive challenge
  - [ ] Send `response = HMAC(AUTH_KEY, challenge || permissions)`
  - [ ] Receive `filtered_list || list_mac`
  - [ ] Verify `list_mac`

- [ ] **Responder side** (`listen()` INTERROGATE_MSG):
  - [ ] Receive and verify `permission_mac`
  - [ ] Generate and send challenge
  - [ ] Receive and verify response
  - [ ] Filter file list by requester's RECEIVE permissions
  - [ ] Send `filtered_list || HMAC(AUTH_KEY, challenge || list)`

### `firmware/src/host_messaging.c`
- [ ] Add 2000ms timeout to `uart_readbyte()`
- [ ] Add 5000ms total protocol timeout
- [ ] Consistent error timing on all paths

### Hardening
- [ ] Delete `boot_flag()`, obfuscated arrays, `crypto_example()`
- [ ] Replace all specific errors with generic "Operation failed"
- [ ] Review for Vulnerabilities, I've seen strcpy and md5 hash, etc
- [ ] Ensure all error paths have consistent timing
- [ ] Test attacks on the secure design if time permits
- [ ] Final `explicit_bzero()` audit

---

