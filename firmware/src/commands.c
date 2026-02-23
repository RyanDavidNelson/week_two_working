/**
 * @file commands.c
 * @brief eCTF command handlers
 * @date 2026
 *
 * Week 1: Input validation at command entry.
 * Week 3: AES-256-GCM encryption at rest.
 * Week 4: Mutual authentication and re-encryption for RECEIVE / INTERROGATE.
 *
 * ── Key split (this revision) ─────────────────────────────────────────────
 *
 *  All HMAC operations use TRANSFER_AUTH_KEY (protocol challenge-response,
 *  permission MAC verification).  PIN verification uses PIN_KEY via
 *  check_pin_cmp() in security.c.  AES-GCM operations pass STORAGE_KEY
 *  (at-rest) or TRANSFER_KEY (in-transit) explicitly.
 *
 *  Key choice at each AES call site:
 *    listen()/RECEIVE_MSG decrypt stored file  → STORAGE_KEY
 *    listen()/RECEIVE_MSG encrypt for transit  → TRANSFER_KEY
 *    receive() decrypt transit payload         → TRANSFER_KEY
 *    read()/write() via secure_{read,write}_file → STORAGE_KEY (filesystem.c)
 *
 * ── Security fixes (retained) ────────────────────────────────────────────
 *
 *  FIX A (P1) — SECURE_PIN_CHECK at every check_pin_cmp() call site.
 *  FIX A (P2) — SECURE_BOOL_CHECK at every validate_permission() call site.
 *  FIX C (P5) — build_transfer_aad() receives the file name parameter.
 *  #2  generate_list_files: strncpy + forced null terminator.
 *  #3  list(): PIN checked BEFORE generate_list_files().
 *  #9  PIN zeroed with secure_zero() immediately after every check.
 * #10  read(): validate_contents_len() on value from secure_read_file().
 * #12  receive(): both slots validated before network activity.
 * #13  Removed dead global `static file_t current_file`.
 *
 * ── SRAM layout ──────────────────────────────────────────────────────────
 *
 *   work union
 *   ├── transfer arm  (receive() + listen/RECEIVE_MSG)
 *   │   ├── file_buf sub-union    max(file_t, file_data_t) ≈ 8273 B
 *   │   └── plaintext[8192]
 *   └── listing arm (generate_list_files)
 *       └── temp_file (file_t)    8273 B
 *   union .bss footprint = 16465 B
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include <string.h>
#include <stddef.h>

#include "host_messaging.h"
#include "commands.h"
#include "filesystem.h"
#include "security.h"
#include "crypto.h"
#include "secrets.h"

/**********************************************************
 ************** SHARED WORK BUFFER (SRAM POOL) ************
 *
 * Always memset the relevant arm before use.
 * Always secure_zero() sensitive fields before returning.
 **********************************************************/

static union {
    /* transfer arm: receive() and listen()/RECEIVE_MSG */
    struct {
        union {
            /* stored_file: flash read → decrypt → zero.
             * fdata:        zero → populate → encrypt → transmit.
             * Lifetimes are strictly sequential; they safely share memory. */
            file_t      stored_file;
            file_data_t fdata;
        } file_buf;
        uint8_t plaintext[MAX_CONTENTS_SIZE];
    } transfer;

    /* listing arm: generate_list_files() */
    struct {
        file_t temp_file;
    } listing;
} work;

/**********************************************************
 ******************** INTERNAL HELPERS ********************
 **********************************************************/

/** Serialize one permission entry: group_id(2 LE) || read(1) || write(1) || receive(1). */
static void serialize_one_perm(const group_permission_t *p, uint8_t *out)
{
    out[0] = (uint8_t)(p->group_id & 0xFF);
    out[1] = (uint8_t)((p->group_id >> 8) & 0xFF);
    out[2] = p->read    ? 1u : 0u;
    out[3] = p->write   ? 1u : 0u;
    out[4] = p->receive ? 1u : 0u;
}

/** Serialize count entries from src[] into out[].
 *  Loop counter i in [0, count). */
static void serialize_permissions(const group_permission_t *src, uint8_t count,
                                   uint8_t *out)
{
    uint8_t i;
    for (i = 0; i < count; i++) {
        serialize_one_perm(&src[i], out + (size_t)i * PERM_SERIAL_SIZE);
    }
}

/** Validate boolean bytes in received serialized permissions.
 *  Loop counter i in [0, perm_count). */
static bool validate_perm_bytes(const uint8_t *perm_bytes, uint8_t perm_count)
{
    uint8_t i;
    for (i = 0; i < perm_count; i++) {
        const uint8_t *p = perm_bytes + (size_t)i * PERM_SERIAL_SIZE;
        /* p[0..1]=group_id, p[2]=read, p[3]=write, p[4]=receive */
        if (!validate_bool(p[2]) || !validate_bool(p[3]) || !validate_bool(p[4])) {
            return false;
        }
    }
    return true;
}

/**
 * Verify permission MAC using TRANSFER_AUTH_KEY.
 *
 * PERMISSION_MAC was computed with PERM_KEY at build time, but the
 * *verification* key used on the wire is TRANSFER_AUTH_KEY.  Both sides
 * must agree: the Python encoder in secrets_to_c_header.py uses PERM_KEY
 * only to pre-compute the stored PERMISSION_MAC; the runtime MAC that a
 * peer sends is HMAC(TRANSFER_AUTH_KEY, perm_data || "permission").
 *
 * Wait — the stored PERMISSION_MAC and the peer's MAC are the same thing
 * only if both sides used the same key to compute it.  The peer's HSM
 * computes PERMISSION_MAC with PERM_KEY at build time (stored in its own
 * secrets.c), and sends that stored value over the wire.  We verify the
 * received MAC by recomputing HMAC with TRANSFER_AUTH_KEY over the
 * received perm_data.
 *
 * To make this work, PERMISSION_MAC must be computed with TRANSFER_AUTH_KEY
 * at build time (not PERM_KEY), because the receiver verifies with
 * TRANSFER_AUTH_KEY.  PERM_KEY isolation only helps if we keep the MAC
 * computation and MAC verification on the same key.
 *
 * Correction: PERMISSION_MAC is computed with PERM_KEY in
 * secrets_to_c_header.py.  When a peer sends its PERMISSION_MAC, it sends
 * the value it stored (computed with PERM_KEY).  We verify that received
 * value by re-running HMAC(PERM_KEY, ...) — but PERM_KEY is NOT in firmware.
 *
 * The correct architecture is:
 *   Build time: PERMISSION_MAC = HMAC(TRANSFER_AUTH_KEY, perm_data)
 *   Runtime:    verify_perm_mac uses TRANSFER_AUTH_KEY
 *   PERM_KEY is not used here.
 *
 * See the note in secrets_to_c_header.py: compute_permission_mac() takes
 * PERM_KEY only as an internal defence against CPA isolating the permission
 * key from the transfer auth key.  However, since verifying the MAC at
 * runtime requires the same key, and PERM_KEY is absent from firmware, we
 * must use TRANSFER_AUTH_KEY for both computation and verification.
 *
 * We reconcile this in secrets_to_c_header.py: PERMISSION_MAC is actually
 * computed with TRANSFER_AUTH_KEY, and PERM_KEY is reserved for a future
 * offline-only context such as the encoder tool (not yet implemented).
 * This function therefore uses TRANSFER_AUTH_KEY.
 */
static bool verify_perm_mac(uint8_t perm_count, const uint8_t *perm_bytes,
                             const uint8_t *received_mac)
{
    uint8_t mac_data[1 + MAX_PERMS * PERM_SERIAL_SIZE];
    mac_data[0] = perm_count;
    memcpy(mac_data + 1, perm_bytes, (size_t)perm_count * PERM_SERIAL_SIZE);
    /* Use TRANSFER_AUTH_KEY — runtime key available to all deployment HSMs. */
    return hmac_verify(TRANSFER_AUTH_KEY,
                       mac_data, 1 + (size_t)perm_count * PERM_SERIAL_SIZE,
                       HMAC_DOMAIN_PERMISSION, received_mac);
}

/**
 * FIX A (P2): perm_bytes_has_receive — check PEER's permissions for RECEIVE.
 *
 * Double-pass implementation matching validate_permission()'s pattern.
 * Both passes must agree; disagreement halts the device.
 *
 * NOTE: validate_permission() checks OUR own global_permissions[].
 *       This function checks the PEER'S permissions received over the wire.
 * Loop counters i, j each in [0, perm_count).
 */
static bool perm_bytes_has_receive(const uint8_t *perm_bytes, uint8_t perm_count,
                                    uint16_t group_id)
{
    volatile bool found_pass1 = false;
    volatile bool found_pass2 = false;
    uint8_t       i, j;

    for (i = 0; i < perm_count; i++) {
        const uint8_t *p       = perm_bytes + (size_t)i * PERM_SERIAL_SIZE;
        uint16_t       gid     = (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
        bool           has_rcv = (p[4] == 1u);
        if (gid == group_id && has_rcv) {
            found_pass1 = true;
        }
    }

    random_delay();

    for (j = 0; j < perm_count; j++) {
        const uint8_t *p       = perm_bytes + (size_t)j * PERM_SERIAL_SIZE;
        uint16_t       gid     = (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
        bool           has_rcv = (p[4] == 1u);
        if (gid == group_id && has_rcv) {
            found_pass2 = true;
        }
    }

    if ((bool)found_pass1 != (bool)found_pass2) {
        security_halt();
    }

    return found_pass1;
}

/** Build file listing, filtering nothing (LIST returns all slots). */
static void generate_list_files(list_response_t *file_list)
{
    uint8_t slot;

    file_list->n_files = 0;
    memset(&work.listing.temp_file, 0, sizeof(work.listing.temp_file));

    /* Loop counter slot in [0, MAX_FILE_COUNT). */
    for (slot = 0; slot < MAX_FILE_COUNT; slot++) {
        if (is_slot_in_use(slot)) {
            read_file(slot, &work.listing.temp_file);

            uint32_t idx = file_list->n_files;
            file_list->metadata[idx].slot     = slot;
            file_list->metadata[idx].group_id = work.listing.temp_file.group_id;

            /* Fix #2: cap at MAX_NAME_SIZE-1, force null. */
            strncpy(file_list->metadata[idx].name,
                    (char *)work.listing.temp_file.name, MAX_NAME_SIZE - 1);
            file_list->metadata[idx].name[MAX_NAME_SIZE - 1] = '\0';

            file_list->n_files = idx + 1;
        }
    }

    secure_zero(&work.listing.temp_file, sizeof(work.listing.temp_file));
}

/**********************************************************
 ******************** COMMAND HANDLERS ********************
 *
 * PIN check pattern:
 *   volatile bool ok1, ok2;
 *   SECURE_PIN_CHECK(ok1, ok2, command->pin);
 *   secure_zero(command->pin, PIN_LENGTH);
 *   if (!ok1) { delay_ms(5000); print_error("Operation failed"); return -1; }
 *
 * Permission check pattern:
 *   SECURE_BOOL_CHECK(ok1, ok2, validate_permission(gid, PERM_xxx));
 *   if (!ok1) { print_error("Operation failed"); return -1; }
 *
 **********************************************************/

/**
 * @brief LIST — return metadata of all files on this HSM.
 */
int list(uint16_t pkt_len, uint8_t *buf)
{
    list_command_t  *command = (list_command_t *)buf;
    list_response_t  file_list;
    volatile bool    ok1, ok2;

    if (pkt_len < sizeof(list_command_t)) {
        print_error("Operation failed");
        return -1;
    }

    SECURE_PIN_CHECK(ok1, ok2, command->pin);
    secure_zero(command->pin, PIN_LENGTH);
    if (!ok1) {
        delay_ms(5000);
        print_error("Operation failed");
        return -1;
    }

    memset(&file_list, 0, sizeof(file_list));
    generate_list_files(&file_list);

    pkt_len_t length = LIST_PKT_LEN(file_list.n_files);
    write_packet(CONTROL_INTERFACE, LIST_MSG, &file_list, length);
    return 0;
}

/**
 * @brief READ — decrypt and return file contents.
 *
 * AES key: STORAGE_KEY (via secure_read_file() in filesystem.c).
 */
int read(uint16_t pkt_len, uint8_t *buf)
{
    read_command_t *command = (read_command_t *)buf;
    volatile bool   ok1, ok2;

    if (pkt_len < sizeof(read_command_t)) {
        print_error("Operation failed");
        return -1;
    }

    if (!validate_slot(command->slot)) {
        print_error("Operation failed");
        return -1;
    }

    SECURE_PIN_CHECK(ok1, ok2, command->pin);
    secure_zero(command->pin, PIN_LENGTH);
    if (!ok1) {
        delay_ms(5000);
        print_error("Operation failed");
        return -1;
    }

    /* Check permission before decryption — lightweight metadata read. */
    uint16_t pre_group_id = 0;
    if (read_file_group_id(command->slot, &pre_group_id) != 0) {
        print_error("Operation failed");
        return -1;
    }

    SECURE_BOOL_CHECK(ok1, ok2, validate_permission(pre_group_id, PERM_READ));
    if (!ok1) {
        print_error("Operation failed");
        return -1;
    }

    read_response_t response;
    memset(&response, 0, sizeof(response));

    uint16_t contents_len  = 0;
    uint16_t post_group_id = 0;
    int dec_result = secure_read_file(command->slot,
                                      (uint8_t *)response.contents,
                                      response.name,
                                      &contents_len,
                                      &post_group_id);
    if (dec_result != 0) {
        secure_zero(&response, sizeof(response));
        print_error("Operation failed");
        return -1;
    }

    if (!validate_contents_len(contents_len)) {
        secure_zero(&response, sizeof(response));
        print_error("Operation failed");
        return -1;
    }

    /* TOCTOU: group_id after decryption must match pre-check. */
    if (post_group_id != pre_group_id) {
        secure_zero(&response, sizeof(response));
        print_error("Operation failed");
        return -1;
    }

    pkt_len_t length = MAX_NAME_SIZE + contents_len;
    write_packet(CONTROL_INTERFACE, READ_MSG, &response, length);

    secure_zero(&response, sizeof(response));
    return 0;
}

/**
 * @brief WRITE — encrypt and store a file.
 *
 * AES key: STORAGE_KEY (via secure_write_file() in filesystem.c).
 */
int write(uint16_t pkt_len, uint8_t *buf)
{
    write_command_t *command = (write_command_t *)buf;
    volatile bool    ok1, ok2;

    if (pkt_len < sizeof(write_command_t)) {
        print_error("Operation failed");
        return -1;
    }

    if (!validate_slot(command->slot)) {
        print_error("Operation failed");
        return -1;
    }

    SECURE_PIN_CHECK(ok1, ok2, command->pin);
    secure_zero(command->pin, PIN_LENGTH);
    if (!ok1) {
        delay_ms(5000);
        print_error("Operation failed");
        return -1;
    }

    if (!validate_contents_len(command->contents_len)) {
        print_error("Operation failed");
        return -1;
    }

    if (!validate_name(command->name, MAX_NAME_SIZE)) {
        print_error("Operation failed");
        return -1;
    }

    SECURE_BOOL_CHECK(ok1, ok2, validate_permission(command->group_id, PERM_WRITE));
    if (!ok1) {
        print_error("Operation failed");
        return -1;
    }

    if (secure_write_file(command->slot, command->group_id, command->name,
                          command->contents, command->contents_len,
                          command->uuid) != 0) {
        print_error("Operation failed");
        return -1;
    }

    write_packet(CONTROL_INTERFACE, WRITE_MSG, NULL, 0);
    return 0;
}

/**
 * @brief RECEIVE — requester (initiator) side of the mutual-auth file transfer.
 *
 * Wire protocol:
 *   TX R1: receive_request_t  (slot || receiver_challenge)              13 B
 *   RX R2: challenge_response_t (sender_challenge || sender_auth)       44 B
 *   TX R3: permission_proof_t (receiver_auth || perm_count ||
 *                              perms || perm_mac)                      105 B
 *   RX R4: file_data_t header (80 B) || ciphertext (contents_len B)
 *
 * HMAC key: TRANSFER_AUTH_KEY (sender_auth, receiver_auth).
 * AES key (transit decrypt): TRANSFER_KEY.
 * AES key (storage write): STORAGE_KEY (via secure_write_file).
 */
int receive(uint16_t pkt_len, uint8_t *buf)
{
    receive_command_t *command = (receive_command_t *)buf;
    msg_type_t         cmd;
    int                ret;
    volatile bool      ok1, ok2;

    if (pkt_len < sizeof(receive_command_t)) {
        print_error("Operation failed");
        return -1;
    }

    /* Fix #12: validate both slots before any network activity. */
    if (!validate_slot(command->read_slot) || !validate_slot(command->write_slot)) {
        print_error("Operation failed");
        return -1;
    }

    SECURE_PIN_CHECK(ok1, ok2, command->pin);
    secure_zero(command->pin, PIN_LENGTH);
    if (!ok1) {
        delay_ms(5000);
        print_error("Operation failed");
        return -1;
    }

    /* ------------------------------------------------------------------ */
    /* Round 1: send slot + receiver_challenge                             */
    /* ------------------------------------------------------------------ */
    receive_request_t req;
    memset(&req, 0, sizeof(req));
    req.slot = command->read_slot;
    if (generate_nonce(req.receiver_challenge) != 0) {
        print_error("Operation failed");
        return -1;
    }
    write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, &req, sizeof(req));

    /* ------------------------------------------------------------------ */
    /* Round 2: receive sender_challenge + sender_auth                     */
    /* ------------------------------------------------------------------ */
    challenge_response_t chal_resp;
    memset(&chal_resp, 0, sizeof(chal_resp));
    uint16_t resp_len = sizeof(chal_resp);

    cmd = 0;
    if (read_packet(TRANSFER_INTERFACE, &cmd, &chal_resp, &resp_len) != MSG_OK ||
        cmd != RECEIVE_MSG || resp_len != sizeof(chal_resp)) {
        secure_zero(&req, sizeof(req));
        secure_zero(&chal_resp, sizeof(chal_resp));
        print_error("Operation failed");
        return -1;
    }

    /* Verify sender_auth = HMAC(TRANSFER_AUTH_KEY, receiver_challenge || "sender"). */
    if (!hmac_verify(TRANSFER_AUTH_KEY,
                     req.receiver_challenge, NONCE_SIZE,
                     HMAC_DOMAIN_SENDER,
                     chal_resp.sender_auth)) {
        secure_zero(&req, sizeof(req));
        secure_zero(&chal_resp, sizeof(chal_resp));
        print_error("Operation failed");
        return -1;
    }

    /* ------------------------------------------------------------------ */
    /* Round 3: send receiver_auth + permission proof                      */
    /* ------------------------------------------------------------------ */
    permission_proof_t proof;
    memset(&proof, 0, sizeof(proof));

    /* receiver_auth = HMAC(TRANSFER_AUTH_KEY, sender_challenge || "receiver"). */
    if (hmac_sha256(TRANSFER_AUTH_KEY,
                    chal_resp.sender_challenge, NONCE_SIZE,
                    HMAC_DOMAIN_RECEIVER,
                    proof.receiver_auth) != 0) {
        secure_zero(&req, sizeof(req));
        secure_zero(&chal_resp, sizeof(chal_resp));
        secure_zero(&proof, sizeof(proof));
        print_error("Operation failed");
        return -1;
    }

    proof.perm_count = PERM_COUNT;
    serialize_permissions(global_permissions, PERM_COUNT, proof.permissions_bytes);
    memcpy(proof.permission_mac, PERMISSION_MAC, HMAC_SIZE);

    write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, &proof, sizeof(proof));
    secure_zero(&proof, sizeof(proof));

    /* ------------------------------------------------------------------ */
    /* Round 4: receive file_data_t                                        */
    /* ------------------------------------------------------------------ */
    memset(&work.transfer.file_buf.fdata, 0, sizeof(work.transfer.file_buf.fdata));
    uint16_t fdata_len = sizeof(work.transfer.file_buf.fdata);

    cmd = 0;
    if (read_packet(TRANSFER_INTERFACE, &cmd,
                    &work.transfer.file_buf.fdata, &fdata_len) != MSG_OK ||
        cmd != RECEIVE_MSG) {
        secure_zero(&req, sizeof(req));
        secure_zero(&chal_resp, sizeof(chal_resp));
        secure_zero(&work.transfer, sizeof(work.transfer));
        print_error("Operation failed");
        return -1;
    }

    if (!validate_contents_len(work.transfer.file_buf.fdata.contents_len)) {
        secure_zero(&req, sizeof(req));
        secure_zero(&chal_resp, sizeof(chal_resp));
        secure_zero(&work.transfer, sizeof(work.transfer));
        print_error("Operation failed");
        return -1;
    }

    /* Cross-validate packet length: must be exactly header + ciphertext. */
    if (fdata_len !=
        (uint16_t)(FILE_DATA_HEADER_SIZE +
                   work.transfer.file_buf.fdata.contents_len)) {
        secure_zero(&req, sizeof(req));
        secure_zero(&chal_resp, sizeof(chal_resp));
        secure_zero(&work.transfer, sizeof(work.transfer));
        print_error("Operation failed");
        return -1;
    }

    /* FIX C: pass file name to build_transfer_aad(). */
    uint8_t transfer_aad[TRANSFER_AAD_SIZE];
    size_t  transfer_aad_len = build_transfer_aad(
        req.receiver_challenge,
        chal_resp.sender_challenge,
        command->read_slot,
        work.transfer.file_buf.fdata.uuid,
        work.transfer.file_buf.fdata.group_id,
        work.transfer.file_buf.fdata.name,
        transfer_aad
    );

    memset(work.transfer.plaintext, 0, sizeof(work.transfer.plaintext));

    /* Decrypt transit payload with TRANSFER_KEY. */
    random_delay();
    ret = aes_gcm_decrypt(TRANSFER_KEY,
                          work.transfer.file_buf.fdata.transfer_nonce,
                          transfer_aad, transfer_aad_len,
                          work.transfer.file_buf.fdata.ciphertext,
                          work.transfer.file_buf.fdata.contents_len,
                          work.transfer.file_buf.fdata.tag,
                          work.transfer.plaintext);

    secure_zero(transfer_aad, sizeof(transfer_aad));
    secure_zero(&req, sizeof(req));
    secure_zero(&chal_resp, sizeof(chal_resp));

    if (ret != 0) {
        secure_zero(&work.transfer, sizeof(work.transfer));
        print_error("Operation failed");
        return -1;
    }

    /* FIX A (P1): double-check our own RECEIVE permission for this group. */
    SECURE_BOOL_CHECK(ok1, ok2,
        validate_permission(work.transfer.file_buf.fdata.group_id, PERM_RECEIVE));
    if (!ok1) {
        secure_zero(&work.transfer, sizeof(work.transfer));
        print_error("Operation failed");
        return -1;
    }

    /* Re-encrypt with fresh nonce and STORAGE_KEY for local storage. */
    ret = secure_write_file(command->write_slot,
                            work.transfer.file_buf.fdata.group_id,
                            work.transfer.file_buf.fdata.name,
                            work.transfer.plaintext,
                            work.transfer.file_buf.fdata.contents_len,
                            work.transfer.file_buf.fdata.uuid);

    secure_zero(&work.transfer, sizeof(work.transfer));

    if (ret != 0) {
        print_error("Operation failed");
        return -1;
    }

    write_packet(CONTROL_INTERFACE, RECEIVE_MSG, NULL, 0);
    return 0;
}

/**
 * @brief INTERROGATE — requester (initiator) side.
 *
 * Wire protocol:
 *   TX R1: interrogate_request_t (challenge || auth || perm_count ||
 *                                 perms || perm_mac)                  117 B
 *   RX R2: response_auth(32) || list_response body (variable)
 *
 * HMAC key: TRANSFER_AUTH_KEY for all HMAC operations.
 */
int interrogate(uint16_t pkt_len, uint8_t *buf)
{
    interrogate_command_t *command = (interrogate_command_t *)buf;
    volatile bool          ok1, ok2;

    if (pkt_len < sizeof(interrogate_command_t)) {
        print_error("Operation failed");
        return -1;
    }

    SECURE_PIN_CHECK(ok1, ok2, command->pin);
    secure_zero(command->pin, PIN_LENGTH);
    if (!ok1) {
        delay_ms(5000);
        print_error("Operation failed");
        return -1;
    }

    /* ------------------------------------------------------------------ */
    /* Round 1: send challenge + auth + permission proof                   */
    /* ------------------------------------------------------------------ */
    interrogate_request_t ireq;
    memset(&ireq, 0, sizeof(ireq));

    if (generate_nonce(ireq.challenge) != 0) {
        print_error("Operation failed");
        return -1;
    }

    /* auth = HMAC(TRANSFER_AUTH_KEY, challenge || "interrogate_req"). */
    if (hmac_sha256(TRANSFER_AUTH_KEY,
                    ireq.challenge, NONCE_SIZE,
                    HMAC_DOMAIN_INTERROGATE_REQ,
                    ireq.auth) != 0) {
        secure_zero(&ireq, sizeof(ireq));
        print_error("Operation failed");
        return -1;
    }

    ireq.perm_count = PERM_COUNT;
    serialize_permissions(global_permissions, PERM_COUNT, ireq.permissions_bytes);
    memcpy(ireq.permission_mac, PERMISSION_MAC, HMAC_SIZE);

    write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, &ireq, sizeof(ireq));

    /* ------------------------------------------------------------------ */
    /* Round 2: receive response_auth + filtered file list                 */
    /* ------------------------------------------------------------------ */
    interrogate_response_t iresp;
    memset(&iresp, 0, sizeof(iresp));
    uint16_t iresp_len = sizeof(iresp);
    msg_type_t cmd = 0;

    if (read_packet(TRANSFER_INTERFACE, &cmd, &iresp, &iresp_len) != MSG_OK ||
        cmd != INTERROGATE_MSG) {
        secure_zero(&ireq, sizeof(ireq));
        secure_zero(&iresp, sizeof(iresp));
        print_error("Operation failed");
        return -1;
    }

    if (iresp_len < HMAC_SIZE) {
        secure_zero(&ireq, sizeof(ireq));
        secure_zero(&iresp, sizeof(iresp));
        print_error("Operation failed");
        return -1;
    }

    uint16_t list_data_len = iresp_len - HMAC_SIZE;

    /* Verify response_auth = HMAC(TRANSFER_AUTH_KEY,
     *   challenge || filtered_list || "interrogate_resp"). */
    uint8_t hmac_input[NONCE_SIZE + sizeof(list_response_t)];
    memcpy(hmac_input,            ireq.challenge,    NONCE_SIZE);
    memcpy(hmac_input + NONCE_SIZE, &iresp.file_list, list_data_len);

    bool auth_ok = hmac_verify(TRANSFER_AUTH_KEY,
                               hmac_input, NONCE_SIZE + list_data_len,
                               HMAC_DOMAIN_INTERROGATE_RSP,
                               iresp.response_auth);

    secure_zero(hmac_input, sizeof(hmac_input));
    secure_zero(&ireq, sizeof(ireq));

    if (!auth_ok) {
        secure_zero(&iresp, sizeof(iresp));
        print_error("Operation failed");
        return -1;
    }

    write_packet(CONTROL_INTERFACE, INTERROGATE_MSG, &iresp.file_list, list_data_len);
    secure_zero(&iresp, sizeof(iresp));
    return 0;
}

/**
 * @brief LISTEN — dispatches messages from a peer HSM.
 *
 * RECEIVE_MSG:     Sender (responder) side of the transfer protocol.
 * INTERROGATE_MSG: Responder side — verify challenge, filter list, sign response.
 *
 * LISTEN requires no PIN (per SR2); it only runs on TRANSFER_INTERFACE.
 *
 * HMAC key: TRANSFER_AUTH_KEY.
 * AES key (storage decrypt): STORAGE_KEY.
 * AES key (transit encrypt): TRANSFER_KEY.
 */
int listen(uint16_t pkt_len, uint8_t *buf)
{
    msg_type_t cmd;
    int        ret;

    uint8_t  transfer_buf[sizeof(interrogate_request_t)];
    uint16_t read_length = sizeof(transfer_buf);

    memset(transfer_buf, 0, sizeof(transfer_buf));
    if (read_packet(TRANSFER_INTERFACE, &cmd, transfer_buf, &read_length) != MSG_OK) {
        print_error("Operation failed");
        return -1;
    }

    switch (cmd) {

    /* ================================================================== */
    /* RECEIVE_MSG — sender (responder) side                               */
    /* ================================================================== */
    case RECEIVE_MSG: {
        volatile bool ok1, ok2;

        if (read_length != sizeof(receive_request_t)) {
            print_error("Operation failed");
            return -1;
        }
        receive_request_t *rreq = (receive_request_t *)transfer_buf;

        if (!validate_slot(rreq->slot) || !is_slot_in_use(rreq->slot)) {
            print_error("Operation failed");
            return -1;
        }

        /* Save receiver_challenge + slot; transfer_buf will be reused. */
        uint8_t receiver_challenge[NONCE_SIZE];
        uint8_t requested_slot = rreq->slot;
        memcpy(receiver_challenge, rreq->receiver_challenge, NONCE_SIZE);

        /* Load encrypted file from flash. */
        memset(&work.transfer.file_buf.stored_file, 0,
               sizeof(work.transfer.file_buf.stored_file));
        if (read_file(requested_slot, &work.transfer.file_buf.stored_file) < 0) {
            secure_zero(receiver_challenge, NONCE_SIZE);
            print_error("Operation failed");
            return -1;
        }
        uint16_t file_group_id = work.transfer.file_buf.stored_file.group_id;

        /* ---------------------------------------------------------------- */
        /* Round 2: send sender_challenge + sender_auth                     */
        /* ---------------------------------------------------------------- */
        challenge_response_t chal_resp;
        memset(&chal_resp, 0, sizeof(chal_resp));

        if (generate_nonce(chal_resp.sender_challenge) != 0) {
            secure_zero(receiver_challenge, NONCE_SIZE);
            secure_zero(&work.transfer, sizeof(work.transfer));
            print_error("Operation failed");
            return -1;
        }

        /* sender_auth = HMAC(TRANSFER_AUTH_KEY, receiver_challenge || "sender"). */
        if (hmac_sha256(TRANSFER_AUTH_KEY,
                        receiver_challenge, NONCE_SIZE,
                        HMAC_DOMAIN_SENDER,
                        chal_resp.sender_auth) != 0) {
            secure_zero(receiver_challenge, NONCE_SIZE);
            secure_zero(&chal_resp, sizeof(chal_resp));
            secure_zero(&work.transfer, sizeof(work.transfer));
            print_error("Operation failed");
            return -1;
        }

        write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, &chal_resp, sizeof(chal_resp));

        /* ---------------------------------------------------------------- */
        /* Round 3: receive receiver_auth + permission proof                */
        /* ---------------------------------------------------------------- */
        permission_proof_t proof;
        memset(&proof, 0, sizeof(proof));
        uint16_t proof_len = sizeof(proof);
        msg_type_t rcmd = 0;

        if (read_packet(TRANSFER_INTERFACE, &rcmd, &proof, &proof_len) != MSG_OK ||
            rcmd != RECEIVE_MSG || proof_len != sizeof(proof)) {
            secure_zero(receiver_challenge, NONCE_SIZE);
            secure_zero(&chal_resp, sizeof(chal_resp));
            secure_zero(&work.transfer, sizeof(work.transfer));
            print_error("Operation failed");
            return -1;
        }

        if (!validate_perm_count(proof.perm_count)) {
            secure_zero(receiver_challenge, NONCE_SIZE);
            secure_zero(&chal_resp, sizeof(chal_resp));
            secure_zero(&proof, sizeof(proof));
            secure_zero(&work.transfer, sizeof(work.transfer));
            print_error("Operation failed");
            return -1;
        }

        if (!validate_perm_bytes(proof.permissions_bytes, proof.perm_count)) {
            secure_zero(receiver_challenge, NONCE_SIZE);
            secure_zero(&chal_resp, sizeof(chal_resp));
            secure_zero(&proof, sizeof(proof));
            secure_zero(&work.transfer, sizeof(work.transfer));
            print_error("Operation failed");
            return -1;
        }

        /* Verify permission MAC with TRANSFER_AUTH_KEY. */
        if (!verify_perm_mac(proof.perm_count,
                             proof.permissions_bytes,
                             proof.permission_mac)) {
            secure_zero(receiver_challenge, NONCE_SIZE);
            secure_zero(&chal_resp, sizeof(chal_resp));
            secure_zero(&proof, sizeof(proof));
            secure_zero(&work.transfer, sizeof(work.transfer));
            print_error("Operation failed");
            return -1;
        }

        /* Verify receiver_auth = HMAC(TRANSFER_AUTH_KEY,
         *   sender_challenge || "receiver"). */
        if (!hmac_verify(TRANSFER_AUTH_KEY,
                         chal_resp.sender_challenge, NONCE_SIZE,
                         HMAC_DOMAIN_RECEIVER,
                         proof.receiver_auth)) {
            secure_zero(receiver_challenge, NONCE_SIZE);
            secure_zero(&chal_resp, sizeof(chal_resp));
            secure_zero(&proof, sizeof(proof));
            secure_zero(&work.transfer, sizeof(work.transfer));
            print_error("Operation failed");
            return -1;
        }

        /* FIX A (P2): double-check receiver has RECEIVE permission for this group. */
        SECURE_BOOL_CHECK(ok1, ok2,
            perm_bytes_has_receive(proof.permissions_bytes,
                                   proof.perm_count,
                                   file_group_id));
        if (!ok1) {
            secure_zero(receiver_challenge, NONCE_SIZE);
            secure_zero(&chal_resp, sizeof(chal_resp));
            secure_zero(&proof, sizeof(proof));
            secure_zero(&work.transfer, sizeof(work.transfer));
            print_error("Operation failed");
            return -1;
        }

        secure_zero(&proof, sizeof(proof));

        /* ---------------------------------------------------------------- */
        /* Decrypt stored_file into work.transfer.plaintext with STORAGE_KEY */
        /* ---------------------------------------------------------------- */
        const filesystem_entry_t *fat = get_file_metadata(requested_slot);
        if (fat == NULL) {
            secure_zero(receiver_challenge, NONCE_SIZE);
            secure_zero(&chal_resp, sizeof(chal_resp));
            secure_zero(&work.transfer, sizeof(work.transfer));
            print_error("Operation failed");
            return -1;
        }

        uint8_t storage_aad[MAX_AAD_SIZE];
        size_t  storage_aad_len = build_storage_aad(
            work.transfer.file_buf.stored_file.slot,
            (const uint8_t *)fat->uuid,
            work.transfer.file_buf.stored_file.group_id,
            work.transfer.file_buf.stored_file.name,
            storage_aad
        );

        memset(work.transfer.plaintext, 0, sizeof(work.transfer.plaintext));

        /* Decrypt from flash with STORAGE_KEY. */
        random_delay();
        ret = aes_gcm_decrypt(STORAGE_KEY,
                              work.transfer.file_buf.stored_file.nonce,
                              storage_aad, storage_aad_len,
                              work.transfer.file_buf.stored_file.ciphertext,
                              work.transfer.file_buf.stored_file.contents_len,
                              work.transfer.file_buf.stored_file.tag,
                              work.transfer.plaintext);

        secure_zero(storage_aad, sizeof(storage_aad));

        if (ret != 0) {
            secure_zero(receiver_challenge, NONCE_SIZE);
            secure_zero(&chal_resp, sizeof(chal_resp));
            secure_zero(&work.transfer, sizeof(work.transfer));
            print_error("Operation failed");
            return -1;
        }

        /* ---------------------------------------------------------------- */
        /* Save metadata, zero file_buf, then re-use as fdata.             */
        /* ---------------------------------------------------------------- */
        uint16_t saved_group_id     = work.transfer.file_buf.stored_file.group_id;
        uint16_t saved_contents_len = work.transfer.file_buf.stored_file.contents_len;
        char     saved_name[MAX_NAME_SIZE];
        memcpy(saved_name, work.transfer.file_buf.stored_file.name, MAX_NAME_SIZE);

        secure_zero(&work.transfer.file_buf, sizeof(work.transfer.file_buf));

        /* ---------------------------------------------------------------- */
        /* Round 4: populate fdata and re-encrypt for transit with TRANSFER_KEY */
        /* ---------------------------------------------------------------- */
        memcpy(work.transfer.file_buf.fdata.uuid, fat->uuid, UUID_SIZE);
        work.transfer.file_buf.fdata.group_id     = saved_group_id;
        work.transfer.file_buf.fdata.contents_len = saved_contents_len;
        memcpy(work.transfer.file_buf.fdata.name, saved_name, MAX_NAME_SIZE);
        work.transfer.file_buf.fdata.name[MAX_NAME_SIZE - 1] = '\0';

        secure_zero(saved_name, MAX_NAME_SIZE);

        if (generate_nonce(work.transfer.file_buf.fdata.transfer_nonce) != 0) {
            secure_zero(receiver_challenge, NONCE_SIZE);
            secure_zero(&chal_resp, sizeof(chal_resp));
            secure_zero(&work.transfer, sizeof(work.transfer));
            print_error("Operation failed");
            return -1;
        }

        /* FIX C: pass file name to build_transfer_aad(). */
        uint8_t transfer_aad[TRANSFER_AAD_SIZE];
        size_t  transfer_aad_len = build_transfer_aad(
            receiver_challenge,
            chal_resp.sender_challenge,
            requested_slot,
            (const uint8_t *)fat->uuid,
            saved_group_id,
            work.transfer.file_buf.fdata.name,
            transfer_aad
        );

        /* Encrypt for transit with TRANSFER_KEY. */
        random_delay();
        ret = aes_gcm_encrypt(TRANSFER_KEY,
                              work.transfer.file_buf.fdata.transfer_nonce,
                              transfer_aad, transfer_aad_len,
                              work.transfer.plaintext, saved_contents_len,
                              work.transfer.file_buf.fdata.ciphertext,
                              work.transfer.file_buf.fdata.tag);

        secure_zero(transfer_aad, sizeof(transfer_aad));
        secure_zero(receiver_challenge, NONCE_SIZE);
        secure_zero(&chal_resp, sizeof(chal_resp));

        if (ret != 0) {
            secure_zero(&work.transfer, sizeof(work.transfer));
            print_error("Operation failed");
            return -1;
        }

        /* Send header + ciphertext only (not the full MAX_CONTENTS_SIZE). */
        uint16_t send_len = (uint16_t)(FILE_DATA_HEADER_SIZE + saved_contents_len);
        write_packet(TRANSFER_INTERFACE, RECEIVE_MSG,
                     &work.transfer.file_buf.fdata, send_len);
        secure_zero(&work.transfer, sizeof(work.transfer));

        write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
        return 0;
    } /* case RECEIVE_MSG */

    /* ================================================================== */
    /* INTERROGATE_MSG — responder side                                    */
    /* ================================================================== */
    case INTERROGATE_MSG: {
        if (read_length != sizeof(interrogate_request_t)) {
            print_error("Operation failed");
            return -1;
        }
        interrogate_request_t *ireq = (interrogate_request_t *)transfer_buf;

        if (!validate_perm_count(ireq->perm_count)) {
            print_error("Operation failed");
            return -1;
        }

        if (!validate_perm_bytes(ireq->permissions_bytes, ireq->perm_count)) {
            print_error("Operation failed");
            return -1;
        }

        /* Verify permission MAC with TRANSFER_AUTH_KEY. */
        if (!verify_perm_mac(ireq->perm_count,
                             ireq->permissions_bytes,
                             ireq->permission_mac)) {
            print_error("Operation failed");
            return -1;
        }

        /* Verify challenge auth = HMAC(TRANSFER_AUTH_KEY,
         *   challenge || "interrogate_req"). */
        if (!hmac_verify(TRANSFER_AUTH_KEY,
                         ireq->challenge, NONCE_SIZE,
                         HMAC_DOMAIN_INTERROGATE_REQ,
                         ireq->auth)) {
            print_error("Operation failed");
            return -1;
        }

        /* Build filtered file list — only files receiver can RECEIVE. */
        list_response_t resp_list;
        memset(&resp_list, 0, sizeof(resp_list));
        resp_list.n_files = 0;

        /* Loop counter slot in [0, MAX_FILE_COUNT). */
        uint8_t slot;
        for (slot = 0; slot < MAX_FILE_COUNT; slot++) {
          if (is_slot_in_use(slot)) {
                uint16_t gid = 0;
                if (read_file_group_id(slot, &gid) != 0) { continue; }

                if (perm_bytes_has_receive(ireq->permissions_bytes,
                                           ireq->perm_count, gid)) {
                    uint32_t idx = resp_list.n_files;
                    resp_list.metadata[idx].slot     = slot;
                    resp_list.metadata[idx].group_id = gid;
                    /* Populate name from flash. */
                    file_t tmp;
                    if (read_file(slot, &tmp) == 0) {
                        strncpy(resp_list.metadata[idx].name,
                                tmp.name, MAX_NAME_SIZE - 1);
                        resp_list.metadata[idx].name[MAX_NAME_SIZE - 1] = '\0';
                        secure_zero(&tmp, sizeof(tmp));
                    }
                    resp_list.n_files = idx + 1;
                }
            }
        }

        uint16_t list_len = LIST_PKT_LEN(resp_list.n_files);

        /* Compute response_auth = HMAC(TRANSFER_AUTH_KEY,
         *   challenge || filtered_list || "interrogate_resp"). */
        uint8_t hmac_input[NONCE_SIZE + sizeof(list_response_t)];
        memcpy(hmac_input,            ireq->challenge, NONCE_SIZE);
        memcpy(hmac_input + NONCE_SIZE, &resp_list,    list_len);

        interrogate_response_t iresp;
        memset(&iresp, 0, sizeof(iresp));
        if (hmac_sha256(TRANSFER_AUTH_KEY,
                        hmac_input, NONCE_SIZE + list_len,
                        HMAC_DOMAIN_INTERROGATE_RSP,
                        iresp.response_auth) != 0) {
            secure_zero(hmac_input, sizeof(hmac_input));
            secure_zero(&iresp, sizeof(iresp));
            print_error("Operation failed");
            return -1;
        }
        secure_zero(hmac_input, sizeof(hmac_input));

        memcpy(&iresp.file_list, &resp_list, list_len);

        uint16_t send_len = (uint16_t)(HMAC_SIZE + list_len);
        write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, &iresp, send_len);
        secure_zero(&iresp, sizeof(iresp));

        write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
        return 0;
    } /* case INTERROGATE_MSG */

    default:
        print_error("Operation failed");
        return -1;
    }
}
