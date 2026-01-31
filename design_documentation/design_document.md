# eCTF Security Design

## Threat Model

**Attacker capabilities:**
- Technician HSM: full physical access, UART0, UART1, known PIN
- Engineer HSM: full physical access, UART0, UART1, but PIN unknown
- Photolithography HSM: no physical access, limited UART0 access, full UART1 access, PIN unknown

**Attacker goals:**
- Read Design: read file without correct PIN
- Read Update: read file without READ permission
- Steal Design: receive file without RECEIVE permission
- Backdoored Design: inject malicious file from rogue device
- Compromise Machine: upload corrupted file to Photolithography

---

## Security Requirements

**SR1: HSM-to-HSM transfers**
- Both devices must prove membership in same deployment (mutual authentication)
- Sender must verify receiver has RECEIVE permission for file's group
- Receiver must verify sender is legitimate deployment member
- Fresh challenge required per transfer (replay protection)

**SR2: PIN protection**
- All local operations (LIST, READ, WRITE, RECEIVE, INTERROGATE) require correct 6-byte PIN
- LISTEN does not require PIN
- Failed attempts: 5-second delay
- PIN comparison must be constant-time

**SR3: Permission enforcement**
- READ permission required to read file contents
- WRITE permission required to write file to group
- RECEIVE permission required to receive file from neighbor
- Permissions set at build time, immutable at runtime

**SR4: Data integrity**
- Files must be authenticated
- File transfers must be authenticated 

**SR5: Data confidentiality**
- Files encrypted at rest
- Files encrypted in transit

---

## Cryptographic Architecture

**Keys (generated per deployment, stored in hardware KEYSTORE):**

| Key | Size | Slot | Purpose |
|-----|------|------|---------|
| AES_KEY | 256-bit | 0 | File encryption (AES-256-CBC) |
| HMAC_KEY | 256-bit | 1 | File/transfer integrity (HMAC-SHA256) |
| AUTH_KEY | 256-bit | 2 | Device authentication, permission binding |

**Per-HSM secrets (computed at build time):**

| Secret | Derivation | Purpose |
|--------|------------|---------|
| PERMISSION_MAC | HMAC(AUTH_KEY, perm_count \|\| serialized_permissions) | Prove permissions are authentic |

**PIN Storage:**
PIN stored in firmware flash (secrets.h). KEYSTORE is write-only; cannot store PIN there.

**Algorithms:**
- Encryption: AES-256-CBC (hardware AESADV)
- Integrity: HMAC-SHA256
- Authentication: HMAC-SHA256 challenge-response
- IV/Nonce: Hardware TRNG
- Padding: PKCS#7

---

## Protocol: File Transfer (RECEIVE_MSG)

**Requester (Receiver):**
```
1. Verify local RECEIVE permission exists for at least one group
2. Generate 16-byte receiver_challenge (TRNG)
3. Send RECEIVE_REQUEST: requested_slot || receiver_challenge
4. Receive sender_challenge from sender
5. Compute response = HMAC(AUTH_KEY, sender_challenge || requested_slot || permissions)
6. Send perm_count || permissions || permission_mac || response
7. Receive sender_auth || uuid || file_group_id || iv || ciphertext || file_hmac || transfer_mac
8. Verify sender_auth = HMAC(AUTH_KEY, receiver_challenge)
9. Verify local RECEIVE permission for file_group_id
10. Verify transfer_mac = HMAC(HMAC_KEY, requested_slot || uuid || file_group_id || iv || sender_challenge || ciphertext || file_hmac)
11. Verify file_hmac matches HMAC(HMAC_KEY, requested_slot || uuid || iv || file_group_id || name || len || ciphertext)
12. Generate new_iv (TRNG)
13. Decrypt ciphertext with original iv, re-encrypt with new_iv
14. Compute new_hmac = HMAC(HMAC_KEY, write_slot || uuid || new_iv || file_group_id || name || len || new_ciphertext)
15. Write to flash with uuid (preserve original UUID in FAT)
```

**Sender:**
```
1. Receive RECEIVE_REQUEST: requested_slot || receiver_challenge
2. Validate requested_slot < MAX_FILE_COUNT and slot in use
3. Read file metadata, extract file_group_id and uuid
4. Generate 16-byte sender_challenge (TRNG)
5. Send sender_challenge
6. Receive perm_count || permissions || permission_mac || response (2000ms timeout)
7. Validate perm_count <= MAX_PERMS
8. Verify permission_mac = HMAC(AUTH_KEY, perm_count || permissions)
9. Verify response = HMAC(AUTH_KEY, sender_challenge || requested_slot || permissions)
10. Iterate permissions[0..perm_count-1], check RECEIVE exists for file_group_id
11. Compute sender_auth = HMAC(AUTH_KEY, receiver_challenge)
12. Load encrypted file (iv, ciphertext, file_hmac) from flash
13. Compute transfer_mac = HMAC(HMAC_KEY, requested_slot || uuid || file_group_id || iv || sender_challenge || ciphertext || file_hmac)
14. Send sender_auth || uuid || file_group_id || iv || ciphertext || file_hmac || transfer_mac
```

---

## Protocol: File List (INTERROGATE_MSG)

**Requester:**
```
1. Send INTERROGATE_MSG: perm_count || permissions || permission_mac
2. Receive challenge from sender
3. Send response = HMAC(AUTH_KEY, challenge || permissions)
4. Receive filtered_file_list || list_mac
5. Verify list_mac = HMAC(AUTH_KEY, challenge || filtered_file_list)
```

**Sender:**
```
1. Receive INTERROGATE_MSG: perm_count || permissions || permission_mac
2. Validate perm_count <= MAX_PERMS
3. Verify permission_mac = HMAC(AUTH_KEY, perm_count || permissions)
4. Generate 16-byte challenge (TRNG)
5. Send challenge
6. Receive response (2000ms timeout)
7. Verify response = HMAC(AUTH_KEY, challenge || permissions)
8. Filter file_list: include only files where permissions[0..perm_count-1] has RECEIVE for file's group_id
9. Send filtered_file_list || HMAC(AUTH_KEY, challenge || filtered_file_list)
```

---

## File Storage

**file_t structure (extended for encryption):**
```c
#pragma pack(push, 1)
typedef struct {
    uint32_t in_use;
    slot_t slot;
    uint8_t uuid[16];
    group_id_t group_id;
    char name[MAX_NAME_SIZE];
    uint16_t contents_len;
    uint8_t iv[16];
    uint8_t hmac[32];
    uint8_t contents[MAX_CONTENTS_SIZE];
} file_t;
#pragma pack(pop)
```

**FAT structure (functionally defined, at 0x3a000):**
```c
typedef struct {
    char uuid[UUID_SIZE];
    uint16_t length;
    uint16_t padding;
    unsigned int flash_addr;
} filesystem_entry_t;
```

**Write operation:**
```
1. Validate contents_len <= MAX_CONTENTS_SIZE
2. Validate name: only printable ASCII (0x20-0x7E), null-terminated
3. Generate 16-byte IV (TRNG)
4. Encrypt: ciphertext = AES-256-CBC(AES_KEY, IV, PKCS7_pad(plaintext))
5. Compute: hmac = HMAC(HMAC_KEY, slot || uuid || iv || group_id || name || len || ciphertext)
6. Store to flash, update FAT with uuid
```

**Read operation:**
```
1. Verify slot < MAX_FILE_COUNT
2. Verify slot in use
3. Load file metadata (group_id) from flash
4. Verify READ permission for file's group_id
5. Load full file from flash
6. Verify loaded file's group_id matches permission-checked group_id (TOCTOU defense)
7. Verify stored slot matches requested slot
8. Verify hmac = HMAC(HMAC_KEY, slot || uuid || iv || group_id || name || len || ciphertext)
9. Decrypt and remove PKCS#7 padding
10. Return plaintext (name + contents only)
```

**Integrity failure handling:** If HMAC verification fails on any file operation, treat slot as empty. 
---

## Interface Segregation

| Interface | Allowed Messages |
|-----------|------------------|
| UART0 (Control) | LIST, READ, WRITE, RECEIVE, INTERROGATE (initiator), LISTEN |
| UART1 (Transfer) | RECEIVE, INTERROGATE (responder only) |

Messages on wrong interface rejected immediately.

---

## Local Operations (UART0)

**LIST:** Requires valid PIN. Returns slot, group_id, name for each file.

**READ:** Verify PIN → Verify READ permission for file's group_id → Load file → Re-verify group_id → Decrypt → Return name + plaintext contents.

**WRITE:** Verify PIN → Verify WRITE permission for command's group_id → Validate name (printable ASCII) → Generate uuid (from host), encrypt, compute HMAC, store.

**LISTEN:** No PIN required. Waits for INTERROGATE_MSG or RECEIVE_MSG on UART1, processes as sender/responder.

---

## Input Validation

- Packet length must match expected structure exactly
- slot < MAX_FILE_COUNT (8)
- contents_len <= MAX_CONTENTS_SIZE (8192)
- perm_count <= MAX_PERMS (8); validate before iterating permissions array
- name: printable ASCII only (0x20-0x7E), null-terminated, strnlen < MAX_NAME_SIZE
- Boolean permission fields must be 0 or 1
- Safe integer arithmetic: validate before computation
- 2000ms timeout on all UART reads; 5000ms total protocol timeout

---

## Side Channel Prevention

**PIN Verification with Glitch Resistance:**
```c
bool check_pin(uint8_t *input) {
    volatile uint8_t result1 = 0, result2 = 0;
    
    for (int i = 0; i < PIN_LENGTH; i++) //XOR Accumulator for Constant-Time
        result1 |= input[i] ^ stored_pin[i];
    
    volatile uint8_t delay = TRNG_read_byte() & 0x7F;
    while (delay--) { __asm("nop"); }
    
    for (int i = 0; i < PIN_LENGTH; i++)
        result2 |= input[i] ^ stored_pin[i];
    
    if (result1 != result2) while(1);  // Glitch detected—Loss
    
    if (result1 != 0) {
        busy_wait_5_seconds();
        return false;
    }
    return true;
}
```

**Error Timing Consistency:**
```c
// Collect all verification results to prevent timing leaks
bool ok = true;
ok &= secure_compare(computed_mac, received_mac, 32);
ok &= secure_compare(computed_auth, received_auth, 32);
ok &= (file_group_id == expected_group_id);
if (!ok) return GENERIC_ERROR;
```

---

## Attack Mitigations

| Attack | Mitigation |
|--------|------------|
| Brute force PIN | 5s delay per attempt |
| Timing attacks | Constant-time comparisons; consistent error timing |
| Flash dump keys | Hardware KEYSTORE (write-only) |
| Forge permissions | Permission MAC verification; perm_count validation |
| Rogue device injection | Mutual authentication (both parties prove AUTH_KEY) |
| Slot swapping | requested_slot bound in transfer_mac |
| File tampering | HMAC verification (includes slot, uuid, IV) |
| TOCTOU | Re-verify group_id after load |
| Replay transfer | Fresh challenge bound in transfer_mac |
| Replay interrogate | Challenge bound in list_mac |
| UART injection | Interface segregation |
| Malformed packets | Exact length + bounds validation |
| Permission array overflow | Validate perm_count <= MAX_PERMS before iteration |
| Buffer overflow | Bounds checking, strncpy, validate before compute |
| Voltage glitching | Double-check + random delays |
| Memory disclosure | explicit_bzero() after use |
| Group confusion | Inner/outer group_id must match; permission filtering |
| Name injection | Printable ASCII validation |
| Partial write corruption | HMAC failure = treat slot as empty |

---

## Error Handling

- Return generic error code (no details that aid attackers)
- Never reveal which check failed
- All error paths execute in consistent time
- Disable debug output in production
- 2000ms read timeout; 5000ms protocol timeout prevents hangs

---

## Build-Time Security

**gen_secrets.py:** Generate keys using `secrets.token_bytes(32)`.

**secrets_to_c_header.py:**
- Compute PERMISSION_MAC = HMAC(AUTH_KEY, perm_count || serialized_permissions)
- Serialize: little-endian, packed, canonical order

**Deployment isolation:** Each deployment has unique keys. Cross-deployment authentication impossible without key extraction.

---