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
- Files must be authenticated (GCM tag)
- File transfers must be authenticated (GCM tag + challenge binding)

**SR5: Data confidentiality**
- Files encrypted at rest (AES-256-GCM)
- Files encrypted in transit (AES-256-GCM)

---

## Cryptographic Architecture

**Keys:**

| Key | Size | Storage | Purpose |
|-----|------|---------|---------|
| GCM_KEY | 256-bit | Flash (secrets.h, 4-byte aligned) | File encryption + integrity (AES-256-GCM) |
| AUTH_KEY | 256-bit | Flash (secrets.h) | Challenge-response authentication, permission binding |

**Key storage rationale:**
- GCM_KEY in flash (4-byte aligned): Loaded into AESADV key registers per operation via `DL_AESADV_setKeyAligned()`. Hardware KEYSTORE incompatible with secure bootloader.
- AUTH_KEY in flash: wolfcrypt HMAC requires key accessible in memory

**Per-HSM secrets (computed at build time):**

| Secret | Derivation | Purpose |
|--------|------------|---------|
| PERMISSION_MAC | HMAC(AUTH_KEY, perm_count \|\| serialized_permissions \|\| "permission") | Prove permissions are authentic |

**PIN Storage:**
PIN stored in firmware flash (secrets.h).

**Algorithms:**
- Encryption + Integrity: AES-256-GCM (hardware AESADV, single pass)
- Authentication: HMAC-SHA256 (wolfcrypt library)
- Nonce: 12-byte from hardware TRNG (96-bit, sufficient for eCTF scale)
- No padding required (GCM is stream mode)

**Why GCM over CBC + HMAC:**
1. Single-pass authenticated encryption (faster, simpler)
2. Hardware tag verification (constant-time, no software timing leak)
3. AAD binds metadata without encryption overhead
4. No padding oracle vulnerabilities

---

## Error Handling

All crypto operations return only `0` (success) or `-1` (failure). No error differentiation is exposed — parameter errors, tag failures, and hardware errors all return the same generic code. All command handlers respond with `"Operation failed"` on any error path. This prevents attackers from distinguishing failure modes to refine their attacks.

---

## File Storage

**Storage layout:**

```
FAT entry (at 0x3A000):
| uuid[16] | length[2] | padding[2] | flash_addr[4] |

File metadata (firmware managed):
| slot[1] | group_id[2] | name[32] | uuid[16] |

Encrypted file data (at flash_addr):
| nonce[12] | ciphertext[contents_len] | tag[16] |
```

**GCM parameters for file storage:**
- Key: GCM_KEY from flash (loaded into AESADV registers per operation)
- Nonce: 12 bytes from TRNG (stored with file)
- AAD: slot || uuid || group_id || name (authenticated, not encrypted)
- Plaintext: file contents only
- Tag: 128-bit (full length, no truncation)

**Write operation:**
```
1. Validate inputs (slot, group_id, name, contents_len)
2. Verify WRITE permission for group_id
3. Generate 12-byte nonce via TRNG
4. Construct AAD = slot || uuid || group_id || name
5. (ciphertext, tag) = AES-256-GCM-Encrypt(GCM_KEY, nonce, AAD, contents)
6. Store metadata + nonce || ciphertext || tag to flash
7. Update FAT with uuid, length, address
```

**Read operation:**
```
1. Verify slot < MAX_FILE_COUNT and slot in use
2. Load metadata, extract group_id
3. Verify READ permission for group_id
4. Load encrypted data (nonce, ciphertext, tag)
5. Reconstruct AAD = slot || uuid || group_id || name
6. plaintext = AES-256-GCM-Decrypt(GCM_KEY, nonce, AAD, ciphertext, tag)
7. If tag verification fails → return generic error
8. Verify loaded group_id matches permission-checked group_id (TOCTOU defense)
9. Return name + plaintext contents
10. secure_zero() all sensitive buffers
```

**Integrity failure handling:** 
If GCM tag verification fails, treat slot as empty/corrupted. Do not reveal which check failed.

---

## Protocol: File Transfer (RECEIVE_MSG)

**Message flow:**
```
    Receiver                              Sender
       |                                    |
       |-- RECEIVE_REQUEST ---------------->|
       |   slot || receiver_challenge       |
       |                                    |
       |<------------ CHALLENGE_RESPONSE ---|
       |              sender_challenge ||   |
       |              sender_auth           |
       |                                    |
       |-- PERMISSION_PROOF --------------->|
       |   receiver_auth || perm_count ||   |
       |   permissions || permission_mac    |
       |                                    |
       |<------------------- FILE_DATA -----|
       |   nonce || ciphertext || tag       |
       |   (AAD includes both challenges)   |
       |                                    |
```

**Receiver (Requester):**
```
1. Verify local RECEIVE permission exists for at least one group
2. Generate 12-byte receiver_challenge (TRNG)
3. Send RECEIVE_REQUEST: requested_slot || receiver_challenge

4. Receive CHALLENGE_RESPONSE: sender_challenge || sender_auth
5. Verify sender_auth = HMAC(AUTH_KEY, receiver_challenge || "sender")

6. Compute receiver_auth = HMAC(AUTH_KEY, sender_challenge || "receiver")
7. Send PERMISSION_PROOF: receiver_auth || perm_count || permissions || permission_mac

8. Receive FILE_DATA: nonce || ciphertext || tag
9. Construct AAD = receiver_challenge || sender_challenge || requested_slot || uuid || group_id
10. plaintext = AES-256-GCM-Decrypt(GCM_KEY, nonce, AAD, ciphertext, tag)
11. If tag fails → abort (sender not authentic or data tampered)
12. Verify local RECEIVE permission for group_id
13. Generate new_nonce for local storage
14. Construct storage_AAD = write_slot || uuid || group_id || name
15. Re-encrypt: (new_ciphertext, new_tag) = AES-256-GCM-Encrypt(GCM_KEY, new_nonce, storage_AAD, plaintext)
16. Store to flash with original UUID
```

**Sender (Responder via LISTEN):**
```
1. Receive RECEIVE_REQUEST: requested_slot || receiver_challenge
2. Validate requested_slot < MAX_FILE_COUNT and slot in use
3. Load file metadata (uuid, group_id, name)

4. Generate 12-byte sender_challenge (TRNG)
5. Compute sender_auth = HMAC(AUTH_KEY, receiver_challenge || "sender")
6. Send CHALLENGE_RESPONSE: sender_challenge || sender_auth

7. Receive PERMISSION_PROOF: receiver_auth || perm_count || permissions || permission_mac (2000ms timeout)
8. Validate perm_count <= MAX_PERMS
9. Verify permission_mac = HMAC(AUTH_KEY, perm_count || serialized_permissions || "permission")
10. Verify receiver_auth = HMAC(AUTH_KEY, sender_challenge || "receiver")
11. Iterate permissions[0..perm_count-1], verify RECEIVE exists for file's group_id
12. If any check fails → abort with generic error

13. Load encrypted file from flash (stored_nonce, ciphertext, stored_tag)
14. Decrypt locally to get plaintext (verify stored file integrity)
15. Generate transfer_nonce (TRNG)
16. Construct transfer_AAD = receiver_challenge || sender_challenge || requested_slot || uuid || group_id
17. (transfer_ciphertext, transfer_tag) = AES-256-GCM-Encrypt(GCM_KEY, transfer_nonce, transfer_AAD, plaintext)
18. Send FILE_DATA: transfer_nonce || transfer_ciphertext || transfer_tag
```

**Security properties:**
- Mutual authentication: Both parties prove knowledge of AUTH_KEY via HMAC
- Replay protection: Fresh challenges included in GCM AAD
- Permission verification: Sender checks receiver's RECEIVE permission before sending
- Integrity: GCM tag covers challenges + metadata + contents
- Confidentiality: Contents encrypted with GCM_KEY
- Slot binding: requested_slot in AAD prevents misdirection

---

## Protocol: File List (INTERROGATE_MSG)

**Requester:**
```
1. Generate 12-byte challenge (TRNG)
2. Compute auth = HMAC(AUTH_KEY, challenge || "interrogate_req")
3. Send INTERROGATE_REQUEST: challenge || auth || perm_count || permissions || permission_mac
4. Receive INTERROGATE_RESPONSE: response_auth || filtered_list
5. Verify response_auth = HMAC(AUTH_KEY, challenge || filtered_list || "interrogate_resp")
6. Return filtered_list to host
```

**Responder:**
```
1. Receive INTERROGATE_REQUEST: challenge || auth || perm_count || permissions || permission_mac
2. Validate perm_count <= MAX_PERMS
3. Verify permission_mac = HMAC(AUTH_KEY, perm_count || serialized_permissions || "permission")
4. Verify auth = HMAC(AUTH_KEY, challenge || "interrogate_req")
5. Filter file_list: include only files where requester has RECEIVE for file's group_id
6. Compute response_auth = HMAC(AUTH_KEY, challenge || filtered_list || "interrogate_resp")
7. Send INTERROGATE_RESPONSE: response_auth || filtered_list
```

---

## Data Structures

**file_t structure:**
```c
#pragma pack(push, 1)
typedef struct {
    uint32_t in_use;           // Slot occupancy flag
    uint8_t  slot;             // Slot index (for AAD reconstruction)
    uint8_t  uuid[16];         // Unique file identifier
    uint16_t group_id;         // Permission group
    char     name[32];         // Null-terminated filename
    uint16_t contents_len;     // Plaintext length (no padding needed)
    uint8_t  nonce[12];        // GCM nonce
    uint8_t  tag[16];          // GCM authentication tag
    uint8_t  ciphertext[MAX_CONTENTS_SIZE];  // Encrypted contents
} file_t;
#pragma pack(pop)
```

**Permission structure:**
```c
typedef struct {
    uint16_t group_id;
    uint8_t  read;    // 0 or 1
    uint8_t  write;   // 0 or 1
    uint8_t  receive; // 0 or 1
} permission_t;
```

---

## Interface Segregation

| Interface | Allowed Messages |
|-----------|------------------|
| UART0 (Management) | LIST, READ, WRITE, RECEIVE, INTERROGATE (initiator), LISTEN |
| UART1 (Transfer) | RECEIVE, INTERROGATE (responder only) |

Messages on wrong interface rejected immediately with generic error.

---

## Input Validation

- Packet length must match expected structure exactly
- slot < MAX_FILE_COUNT (8)
- contents_len <= MAX_CONTENTS_SIZE (8192)
- perm_count <= MAX_PERMS (8); validate before iterating permissions array
- name: printable ASCII only (0x20-0x7E), null-terminated, strnlen < MAX_NAME_SIZE
- Boolean permission fields must be 0 or 1
- Nonce must be exactly 12 bytes
- Safe integer arithmetic: validate before computation
- 2000ms timeout on all UART reads; 5000ms total protocol timeout

---

## Side Channel Mitigations

**PIN Verification (software, glitch-resistant):**
```c
bool check_pin(uint8_t *input) {
    volatile uint8_t result1 = 0, result2 = 0;
    
    // First pass: constant-time XOR accumulator
    for (int i = 0; i < PIN_LENGTH; i++)
        result1 |= input[i] ^ stored_pin[i];
    
    // Random delay to desynchronize glitch attempts
    random_delay();
    
    // Second pass: detect single-glitch bypass
    for (int i = 0; i < PIN_LENGTH; i++)
        result2 |= input[i] ^ stored_pin[i];
    
    // Glitch detection: results must match
    if (result1 != result2) {
        while(1);  // Halt on detected glitch
    }
    
    if (result1 != 0) {
        busy_wait_5_seconds();
        return false;
    }
    return true;
}
```
---

## Attack Mitigations

| Attack | Mitigation |
|--------|------------|
| Brute force PIN | 5s delay per failed attempt; constant-time comparison |
| Timing attacks | Hardware GCM + secure_compare tag verify; single generic error code on all failures |
| Key extraction (GCM) | GCM_KEY in flash; loaded into AESADV registers only during operations |
| Key extraction (AUTH) | AUTH_KEY in flash; minimize time in RAM during HMAC |
| Permission forgery | PERMISSION_MAC verification; perm_count bounds check |
| Rogue device injection | Mutual authentication via HMAC challenge-response |
| Replay attacks | Fresh challenges bound into GCM AAD each transfer |
| Slot swapping | requested_slot included in transfer AAD |
| File tampering | GCM tag covers metadata (via AAD) + contents |
| TOCTOU | Re-verify group_id after load, before return |
| Nonce reuse | 12-byte TRNG nonce per operation |
| Group ID manipulation | group_id in AAD; tag fails if modified |
| Glitch attacks | Random delays around crypto ops; PIN and HMAC-verify double-check with halt on mismatch |
| Buffer overflow | Strict length validation; safe memcpy wrappers |
| Error oracle | Single generic error code and message on all failure paths |

---

## AAD Structure Reference

**File Storage AAD (51 bytes):**
```
Offset  Size  Field
0       1     slot
1       16    uuid
17      2     group_id (little-endian)
19      32    name (null-padded)
```

**Transfer AAD (43 bytes):**
```
Offset  Size  Field
0       12    receiver_challenge
12      12    sender_challenge
24      1     requested_slot
25      16    uuid
41      2     group_id (little-endian)
```

---

## HMAC Domain Separation

All HMAC operations use a mandatory domain separator appended to the data before computation. There is one unified `hmac_sha256(key, data, len, domain, output)` function — no domain-less variant exists. This prevents cross-protocol attacks by construction.

| Context | HMAC Input |
|---------|------------|
| Sender auth | `receiver_challenge \|\| "sender"` |
| Receiver auth | `sender_challenge \|\| "receiver"` |
| Interrogate request | `challenge \|\| "interrogate_req"` |
| Interrogate response | `challenge \|\| file_list \|\| "interrogate_resp"` |
| Permission MAC | `perm_count \|\| serialized_permissions \|\| "permission"` |

Domain separator constants defined in `crypto.h`:
- `HMAC_DOMAIN_SENDER` = `"sender"`
- `HMAC_DOMAIN_RECEIVER` = `"receiver"`
- `HMAC_DOMAIN_INTERROGATE_REQ` = `"interrogate_req"`
- `HMAC_DOMAIN_INTERROGATE_RSP` = `"interrogate_resp"`
- `HMAC_DOMAIN_PERMISSION` = `"permission"`
