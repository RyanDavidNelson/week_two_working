/**
 * @file commands.c
 * @brief eCTF command handlers
 * @date 2026
 *
 * Module 5: Full mutual-authentication transfer protocol for
 *   RECEIVE, INTERROGATE, and LISTEN.
 *
 * ── Key usage at each call site ──────────────────────────────────────────
 *   STORAGE_KEY   : at-rest encryption via secure_{read,write}_file()
 *   TRANSFER_KEY  : in-transit encryption in listen(RECEIVE) / receive()
 *   TRANSFER_AUTH_KEY : all HMAC-SHA256 operations (challenge-response,
 *                       permission MAC, interrogate auth)
 *   PIN_KEY       : PIN verification via SECURE_PIN_CHECK / check_pin_cmp()
 *
 * ── SRAM layout ──────────────────────────────────────────────────────────
 *   static union work
 *   ├── transfer arm  (receive + listen/RECEIVE_MSG)  ≈ 16469 bytes
 *   │   ├── file_buf  union(file_t=8277, receive_r4_t=8273)
 *   │   └── plaintext[8192]
 *   └── listing arm  (generate_list_files)            ≈  8277 bytes
 *       └── temp_file (file_t)
 *   .bss footprint = 16469 bytes
 *
 * ── Security properties ───────────────────────────────────────────────────
 *   PIN check:         SECURE_PIN_CHECK (double-eval, halt on mismatch)
 *   Permission check:  SECURE_BOOL_CHECK (double-eval, halt on mismatch)
 *   HMAC verification: hmac_verify() (double-compute, halt on mismatch)
 *   Peer permissions:  double-pass perm_bytes_has_receive()
 *   TOCTOU:            read_file_group_id() before decrypt; post-check in read()
 *   Plaintext zeroed:  secure_zero() in all exit paths
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include <string.h>
#include <stddef.h>
#include <stdbool.h>

#include "host_messaging.h"
#include "commands.h"
#include "filesystem.h"
#include "security.h"
#include "crypto.h"
#include "secrets.h"

/**********************************************************
 ************** SHARED WORK BUFFER (SRAM POOL) ************
 *
 * Sensitivity:
 *   file_buf.stored_file  — encrypted flash contents (not sensitive in .bss,
 *                           but must be zeroed after decrypt or on error)
 *   file_buf.fdata        — transit-encrypted data being constructed/received
 *   plaintext             — decrypted file contents; MUST be zeroed before return
 *
 * Lifetime rules:
 *   receive(): only fdata arm used (stored_file arm never touched)
 *   listen():  stored_file filled first → decrypt → zero → fdata arm filled
 *   These operations never overlap, so the sub-union is safe.
 *
 * Always call memset(arm, 0, ...) before use and
 * secure_zero(arm, ...) before every return path.
 **********************************************************/

static union {
    struct {
        union {
            file_t       stored_file;   /* flash read in listen/RECEIVE_MSG */
            receive_r4_t fdata;         /* R4 construction/reception        */
        } file_buf;
        uint8_t plaintext[MAX_CONTENTS_SIZE];
    } transfer;

    struct {
        file_t temp_file;
    } listing;
} work;

/**********************************************************
 ******************** INTERNAL HELPERS ********************
 **********************************************************/

/*
 * Serialize one group_permission_t into 5 wire bytes:
 * group_id(2 LE) || read(1) || write(1) || receive(1).
 */
static void serialize_one_perm(const group_permission_t *p, uint8_t *out)
{
    out[0] = (uint8_t)(p->group_id & 0xFF);
    out[1] = (uint8_t)((p->group_id >> 8) & 0xFF);
    out[2] = p->read    ? 1u : 0u;
    out[3] = p->write   ? 1u : 0u;
    out[4] = p->receive ? 1u : 0u;
}

/*
 * Serialize 'count' entries from src[] into out[].
 * Loop counter i in [0, count); terminates when i == count.
 */
static void serialize_permissions(const group_permission_t *src,
                                   uint8_t count, uint8_t *out)
{
    uint8_t i;
    for (i = 0; i < count; i++) {
        serialize_one_perm(&src[i], out + (size_t)i * PERM_SERIAL_SIZE);
    }
}

/*
 * Validate that all boolean fields in perm_bytes are 0 or 1.
 * perm_bytes layout per entry: group_id(2) || read(1) || write(1) || receive(1).
 * Loop counter i in [0, perm_count); terminates when i == perm_count.
 */
static bool validate_perm_bytes(const uint8_t *perm_bytes, uint8_t perm_count)
{
    uint8_t i;
    for (i = 0; i < perm_count; i++) {
        const uint8_t *p = perm_bytes + (size_t)i * PERM_SERIAL_SIZE;
        /* p[2]=read, p[3]=write, p[4]=receive — must all be 0 or 1 */
        if (!validate_bool(p[2]) || !validate_bool(p[3]) || !validate_bool(p[4])) {
            return false;
        }
    }
    return true;
}

/*
 * Verify a peer's PERMISSION_MAC.
 * MAC = HMAC(TRANSFER_AUTH_KEY, perm_count_byte || perm_bytes || "permission").
 * Returns true if the MAC is valid.
 */
static bool verify_perm_mac(uint8_t perm_count, const uint8_t *perm_bytes,
                             const uint8_t *received_mac)
{
    uint8_t mac_data[1 + MAX_PERMS * PERM_SERIAL_SIZE];
    mac_data[0] = perm_count;
    memcpy(mac_data + 1, perm_bytes, (size_t)perm_count * PERM_SERIAL_SIZE);
    return hmac_verify(TRANSFER_AUTH_KEY,
                       mac_data, 1u + (size_t)perm_count * PERM_SERIAL_SIZE,
                       HMAC_DOMAIN_PERMISSION, received_mac);
}

/*
 * Check whether a peer (whose permissions are in perm_bytes) has RECEIVE
 * permission for group_id.  Double-pass implementation: both passes must
 * agree or security_halt() is called.
 * Loop counters i, j each in [0, perm_count); terminate when equal to perm_count.
 */
static bool perm_bytes_has_receive(const uint8_t *perm_bytes, uint8_t perm_count,
                                    uint16_t group_id)
{
    volatile bool found_pass1 = false;
    volatile bool found_pass2 = false;
    uint8_t       i, j;

    for (i = 0; i < perm_count; i++) {
        const uint8_t *p   = perm_bytes + (size_t)i * PERM_SERIAL_SIZE;
        uint16_t       gid = (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
        if (gid == group_id && p[4] == 1u) {
            found_pass1 = true;
        }
    }

    random_delay();

    for (j = 0; j < perm_count; j++) {
        const uint8_t *p   = perm_bytes + (size_t)j * PERM_SERIAL_SIZE;
        uint16_t       gid = (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
        if (gid == group_id && p[4] == 1u) {
            found_pass2 = true;
        }
    }

    if ((bool)found_pass1 != (bool)found_pass2) {
        security_halt();
    }

    return found_pass1;
}

/*
 * Build list of files on this HSM (no filtering; LIST shows all).
 * Uses work.listing.temp_file to avoid stack-allocating an 8 KB file_t.
 * Loop counter slot in [0, MAX_FILE_COUNT); terminates when slot == MAX_FILE_COUNT.
 */
static void generate_list_files(list_response_t *file_list)
{
    uint8_t slot;

    file_list->n_files = 0;
    memset(&work.listing.temp_file, 0, sizeof(work.listing.temp_file));

    for (slot = 0; slot < MAX_FILE_COUNT; slot++) {
        if (!is_slot_in_use(slot)) {
            continue;
        }

        if (read_file(slot, &work.listing.temp_file) != 0) {
            continue;
        }

        uint32_t idx = file_list->n_files;
        file_list->metadata[idx].slot     = slot;
        file_list->metadata[idx].group_id = work.listing.temp_file.group_id;

        /* Bounded copy; force null terminator. */
        strncpy(file_list->metadata[idx].name,
                work.listing.temp_file.name,
                MAX_NAME_SIZE - 1);
        file_list->metadata[idx].name[MAX_NAME_SIZE - 1] = '\0';

        file_list->n_files = idx + 1;

        secure_zero(&work.listing.temp_file, sizeof(work.listing.temp_file));
    }
}


/**********************************************************
 ******************** COMMAND HANDLERS ********************
 **********************************************************/

/*
 * LIST — return metadata for all files on this HSM.
 * PIN checked BEFORE generating the list so file names are not leaked
 * to an unauthenticated caller.
 */
int list(uint16_t pkt_len, uint8_t *buf)
{
    list_command_t  *command = (list_command_t *)buf;
    list_response_t  file_list;
    volatile bool    ok1, ok2;
    uint16_t         send_len;

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

    send_len = (uint16_t)LIST_PKT_LEN(file_list.n_files);
    write_packet(CONTROL_INTERFACE, LIST_MSG, &file_list, send_len);
    return 0;
}

/*
 * READ — decrypt and return a file to the host.
 * Permission is checked before decryption; TOCTOU check after.
 * Plaintext is zeroed in all exit paths.
 */
#define READ_CMD_HEADER_SIZE ((uint16_t)sizeof(read_command_t))

int read(uint16_t pkt_len, uint8_t *buf)
{
    read_command_t  *command = (read_command_t *)buf;
    read_response_t  response;
    volatile bool    ok1, ok2;
    uint16_t         len;
    uint16_t         pre_gid, post_gid;
    int              ret;

    if (pkt_len < READ_CMD_HEADER_SIZE) {
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

    /* Read group_id from flash header BEFORE decryption (TOCTOU pre-check). */
    if (read_file_group_id(command->slot, &pre_gid) != 0) {
        print_error("Operation failed");
        return -1;
    }

    SECURE_BOOL_CHECK(ok1, ok2, validate_permission(pre_gid, PERM_READ));
    if (!ok1) {
        print_error("Operation failed");
        return -1;
    }

    memset(&response, 0, sizeof(response));

    ret = secure_read_file(command->slot,
                           (uint8_t *)response.contents,
                           response.name,
                           &len,
                           &post_gid);
    if (ret != 0) {
        secure_zero(&response, sizeof(response));
        print_error("Operation failed");
        return -1;
    }

    /* TOCTOU post-check: group_id must not have changed between reads. */
    if (post_gid != pre_gid) {
        secure_zero(&response, sizeof(response));
        print_error("Operation failed");
        return -1;
    }

    if (!validate_contents_len(len)) {
        secure_zero(&response, sizeof(response));
        print_error("Operation failed");
        return -1;
    }

    /* Send: name (32) + contents (len). */
    write_packet(CONTROL_INTERFACE, READ_MSG, &response,
                 (uint16_t)(MAX_NAME_SIZE + len));
    secure_zero(&response, sizeof(response));
    return 0;
}

/*
 * WRITE — encrypt and store a file from the host.
 * Permission checked before flash write.
 */
#define WRITE_CMD_HEADER_SIZE ((uint16_t)offsetof(write_command_t, contents))

int write(uint16_t pkt_len, uint8_t *buf)
{
    write_command_t *command = (write_command_t *)buf;
    volatile bool    ok1, ok2;

    if (pkt_len < WRITE_CMD_HEADER_SIZE) {
        print_error("Operation failed");
        return -1;
    }

    if (!validate_slot(command->slot)) {
        print_error("Operation failed");
        return -1;
    }

    if (!validate_contents_len(command->contents_len)) {
        print_error("Operation failed");
        return -1;
    }

    /* Ensure packet contains declared payload bytes. */
    if (pkt_len < (uint16_t)(WRITE_CMD_HEADER_SIZE + command->contents_len)) {
        print_error("Operation failed");
        return -1;
    }

    if (!validate_name(command->name, MAX_NAME_SIZE)) {
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

    SECURE_BOOL_CHECK(ok1, ok2, validate_permission(command->group_id, PERM_WRITE));
    if (!ok1) {
        print_error("Operation failed");
        return -1;
    }

    if (secure_write_file(command->slot,
                          command->group_id,
                          command->name,
                          command->contents,
                          command->contents_len,
                          command->uuid) != 0) {
        print_error("Operation failed");
        return -1;
    }

    write_packet(CONTROL_INTERFACE, WRITE_MSG, NULL, 0);
    return 0;
}

/*
 * RECEIVE — initiator side of the 4-round transfer protocol.
 *
 * Round 1: send receive_r1_t (slot + recv_chal) on TRANSFER_INTERFACE.
 * Round 2: receive receive_r2_t; verify sender_auth = HMAC(TAK, recv_chal || "sender").
 * Round 3: send receive_r3_t (recv_auth + own permissions + PERMISSION_MAC).
 * Round 4: receive receive_r4_t; verify GCM tag; check own RECEIVE permission;
 *           write decrypted file to write_slot.
 *
 * Plaintext and all protocol buffers are zeroed before return in all paths.
 */
int receive(uint16_t pkt_len, uint8_t *buf)
{
    receive_command_t *command = (receive_command_t *)buf;
    receive_r1_t       r1;
    receive_r2_t       r2;
    receive_r3_t       r3;
    volatile bool      ok1, ok2;
    msg_type_t         cmd;
    uint16_t           r2_len, r4_len;
    uint8_t            transfer_aad[TRANSFER_AAD_SIZE];
    size_t             transfer_aad_len;
    int                ret;

    /* ---- Entry validation ---- */
    if (pkt_len < sizeof(receive_command_t)) {
        print_error("Operation failed");
        return -1;
    }
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
    /* Round 1: send slot + receiver challenge                              */
    /* ------------------------------------------------------------------ */
    memset(&r1, 0, sizeof(r1));
    r1.slot = command->read_slot;
    if (generate_nonce(r1.recv_chal) != 0) {
        print_error("Operation failed");
        return -1;
    }
    write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, &r1, sizeof(r1));

    /* ------------------------------------------------------------------ */
    /* Round 2: receive sender challenge + verify sender authentication    */
    /* ------------------------------------------------------------------ */
    memset(&r2, 0, sizeof(r2));
    r2_len = sizeof(r2);
    cmd    = 0;
    if (read_packet(TRANSFER_INTERFACE, &cmd, &r2, &r2_len) != MSG_OK ||
        cmd    != RECEIVE_MSG ||
        r2_len != sizeof(r2)) {
        secure_zero(&r1, sizeof(r1));
        secure_zero(&r2, sizeof(r2));
        print_error("Operation failed");
        return -1;
    }

    /* sender_auth = HMAC(TAK, recv_chal || "sender") */
    if (!hmac_verify(TRANSFER_AUTH_KEY,
                     r1.recv_chal, NONCE_SIZE,
                     HMAC_DOMAIN_SENDER,
                     r2.sender_auth)) {
        secure_zero(&r1, sizeof(r1));
        secure_zero(&r2, sizeof(r2));
        print_error("Operation failed");
        return -1;
    }

    /* ------------------------------------------------------------------ */
    /* Round 3: send receiver authentication + own permission proof        */
    /* ------------------------------------------------------------------ */
    memset(&r3, 0, sizeof(r3));

    /* recv_auth = HMAC(TAK, send_chal || "receiver") */
    if (hmac_sha256(TRANSFER_AUTH_KEY,
                    r2.send_chal, NONCE_SIZE,
                    HMAC_DOMAIN_RECEIVER,
                    r3.recv_auth) != 0) {
        secure_zero(&r1, sizeof(r1));
        secure_zero(&r2, sizeof(r2));
        secure_zero(&r3, sizeof(r3));
        print_error("Operation failed");
        return -1;
    }

    r3.perm_count = PERM_COUNT;
    serialize_permissions(global_permissions, PERM_COUNT, r3.perms);
    memcpy(r3.perm_mac, PERMISSION_MAC, HMAC_SIZE);

    write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, &r3, sizeof(r3));
    secure_zero(&r3, sizeof(r3));

    /* ------------------------------------------------------------------ */
    /* Round 4: receive encrypted file; decrypt; check permission; store   */
    /* ------------------------------------------------------------------ */
    memset(&work.transfer.file_buf.fdata, 0, sizeof(work.transfer.file_buf.fdata));
    r4_len = sizeof(work.transfer.file_buf.fdata);
    cmd    = 0;

    if (read_packet(TRANSFER_INTERFACE, &cmd,
                    &work.transfer.file_buf.fdata, &r4_len) != MSG_OK ||
        cmd != RECEIVE_MSG) {
        secure_zero(&r1, sizeof(r1));
        secure_zero(&r2, sizeof(r2));
        secure_zero(&work.transfer, sizeof(work.transfer));
        print_error("Operation failed");
        return -1;
    }

    if (!validate_contents_len(work.transfer.file_buf.fdata.contents_len)) {
        secure_zero(&r1, sizeof(r1));
        secure_zero(&r2, sizeof(r2));
        secure_zero(&work.transfer, sizeof(work.transfer));
        print_error("Operation failed");
        return -1;
    }

    /* Packet length must be exactly header + declared ciphertext. */
    if (r4_len != (uint16_t)(FILE_DATA_HEADER_SIZE +
                             work.transfer.file_buf.fdata.contents_len)) {
        secure_zero(&r1, sizeof(r1));
        secure_zero(&r2, sizeof(r2));
        secure_zero(&work.transfer, sizeof(work.transfer));
        print_error("Operation failed");
        return -1;
    }

    /* Reconstruct transfer AAD: recv_chal || send_chal || slot || uuid ||
     * group_id || name.  slot comes from the R4 packet itself; if tampered
     * the GCM tag will fail, so no separate slot validation is needed. */
    transfer_aad_len = build_transfer_aad(
        r1.recv_chal,
        r2.send_chal,
        work.transfer.file_buf.fdata.slot,
        work.transfer.file_buf.fdata.uuid,
        work.transfer.file_buf.fdata.group_id,
        work.transfer.file_buf.fdata.name,
        transfer_aad
    );

    /* Decrypt transit payload with TRANSFER_KEY. */
    memset(work.transfer.plaintext, 0, MAX_CONTENTS_SIZE);
    ret = aes_gcm_decrypt(
        TRANSFER_KEY,
        work.transfer.file_buf.fdata.nonce,
        transfer_aad, transfer_aad_len,
        work.transfer.file_buf.fdata.ciphertext,
        work.transfer.file_buf.fdata.contents_len,
        work.transfer.file_buf.fdata.tag,
        work.transfer.plaintext
    );

    secure_zero(transfer_aad, sizeof(transfer_aad));
    secure_zero(&r1, sizeof(r1));
    secure_zero(&r2, sizeof(r2));

    if (ret != 0) {
        secure_zero(work.transfer.plaintext, MAX_CONTENTS_SIZE);
        secure_zero(&work.transfer, sizeof(work.transfer));
        print_error("Operation failed");
        return -1;
    }

    /* Check that WE have RECEIVE permission for this file's group. */
    SECURE_BOOL_CHECK(ok1, ok2,
        validate_permission(work.transfer.file_buf.fdata.group_id, PERM_RECEIVE));
    if (!ok1) {
        secure_zero(work.transfer.plaintext, MAX_CONTENTS_SIZE);
        secure_zero(&work.transfer, sizeof(work.transfer));
        print_error("Operation failed");
        return -1;
    }

    /* Write decrypted file to write_slot with STORAGE_KEY. */
    ret = secure_write_file(
        command->write_slot,
        work.transfer.file_buf.fdata.group_id,
        work.transfer.file_buf.fdata.name,
        work.transfer.plaintext,
        work.transfer.file_buf.fdata.contents_len,
        work.transfer.file_buf.fdata.uuid
    );

    secure_zero(work.transfer.plaintext, MAX_CONTENTS_SIZE);
    secure_zero(&work.transfer, sizeof(work.transfer));

    if (ret != 0) {
        print_error("Operation failed");
        return -1;
    }

    write_packet(CONTROL_INTERFACE, RECEIVE_MSG, NULL, 0);
    return 0;
}

/*
 * INTERROGATE — initiator side.
 *
 * Round 1: send challenge + auth + own permissions to TRANSFER_INTERFACE.
 * Round 2: receive resp_auth + filtered list; verify resp_auth; forward to host.
 *
 * All protocol buffers zeroed before return.
 */
int interrogate(uint16_t pkt_len, uint8_t *buf)
{
    interrogate_command_t *command = (interrogate_command_t *)buf;
    volatile bool          ok1, ok2;
    interrogate_r1_t       r1;
    interrogate_r2_t       r2;
    uint16_t               r2_len;
    uint16_t               list_data_len;
    msg_type_t             cmd;
    uint8_t                hmac_input[NONCE_SIZE + sizeof(list_response_t)];

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
    /* Round 1: send challenge + auth + own permission proof               */
    /* ------------------------------------------------------------------ */
    memset(&r1, 0, sizeof(r1));

    if (generate_nonce(r1.challenge) != 0) {
        print_error("Operation failed");
        return -1;
    }

    /* auth = HMAC(TAK, challenge || "interrogate_req") */
    if (hmac_sha256(TRANSFER_AUTH_KEY,
                    r1.challenge, NONCE_SIZE,
                    HMAC_DOMAIN_INTERROGATE_REQ,
                    r1.auth) != 0) {
        secure_zero(&r1, sizeof(r1));
        print_error("Operation failed");
        return -1;
    }

    r1.perm_count = PERM_COUNT;
    serialize_permissions(global_permissions, PERM_COUNT, r1.perms);
    memcpy(r1.perm_mac, PERMISSION_MAC, HMAC_SIZE);

    write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, &r1, sizeof(r1));

    /* ------------------------------------------------------------------ */
    /* Round 2: receive resp_auth + filtered file list; verify             */
    /* ------------------------------------------------------------------ */
    memset(&r2, 0, sizeof(r2));
    r2_len = sizeof(r2);
    cmd    = 0;

    if (read_packet(TRANSFER_INTERFACE, &cmd, &r2, &r2_len) != MSG_OK ||
        cmd    != INTERROGATE_MSG ||
        r2_len < HMAC_SIZE) {
        secure_zero(&r1, sizeof(r1));
        secure_zero(&r2, sizeof(r2));
        print_error("Operation failed");
        return -1;
    }

    list_data_len = r2_len - HMAC_SIZE;

    /* resp_auth = HMAC(TAK, challenge || list_bytes || "interrogate_resp") */
    memcpy(hmac_input,             r1.challenge, NONCE_SIZE);
    memcpy(hmac_input + NONCE_SIZE, &r2.list,    list_data_len);

    if (!hmac_verify(TRANSFER_AUTH_KEY,
                     hmac_input, (size_t)(NONCE_SIZE + list_data_len),
                     HMAC_DOMAIN_INTERROGATE_RSP,
                     r2.resp_auth)) {
        secure_zero(hmac_input, sizeof(hmac_input));
        secure_zero(&r1, sizeof(r1));
        secure_zero(&r2, sizeof(r2));
        print_error("Operation failed");
        return -1;
    }

    secure_zero(hmac_input, sizeof(hmac_input));
    secure_zero(&r1, sizeof(r1));

    /* Forward filtered list to host. */
    write_packet(CONTROL_INTERFACE, INTERROGATE_MSG, &r2.list, list_data_len);
    secure_zero(&r2, sizeof(r2));
    return 0;
}

/*
 * LISTEN — dispatches one incoming message from a peer HSM.
 *
 * RECEIVE_MSG:     Responder (sender) side of the 4-round transfer protocol.
 * INTERROGATE_MSG: Responder side — verify challenge, filter list, sign response.
 *
 * No PIN check; LISTEN accepts commands only on TRANSFER_INTERFACE.
 * Sends a LISTEN_MSG success ACK on CONTROL_INTERFACE when done.
 */
int listen(uint16_t pkt_len, uint8_t *buf)
{
    /* Read the first message from the transfer interface.
     * Size the buffer to hold the largest expected R1 (interrogate_r1_t). */
    uint8_t    first_buf[sizeof(interrogate_r1_t)];
    uint16_t   first_len = sizeof(first_buf);
    msg_type_t cmd       = 0;

    (void)pkt_len;
    (void)buf;

    memset(first_buf, 0, sizeof(first_buf));
    if (read_packet(TRANSFER_INTERFACE, &cmd, first_buf, &first_len) != MSG_OK) {
        print_error("Operation failed");
        return -1;
    }

    /* ================================================================== */
    /* RECEIVE_MSG — responder (sender) side                               */
    /* ================================================================== */
    if (cmd == RECEIVE_MSG) {
        volatile bool ok1, ok2;
        receive_r1_t *r1;
        receive_r2_t  r2;
        receive_r3_t  r3;
        receive_r4_t *fdata;

        /* Local copies of values needed after file_buf is repurposed. */
        uint8_t  recv_chal[NONCE_SIZE];
        uint8_t  send_chal[NONCE_SIZE];
        char     saved_name[MAX_NAME_SIZE];   /* char* for build_*_aad compatibility */
        uint16_t saved_group_id;
        uint16_t saved_contents_len;
        uint8_t  saved_uuid[UUID_SIZE];
        uint8_t  slot_req;

        uint8_t  storage_aad[STORAGE_AAD_SIZE];
        size_t   storage_aad_len;
        uint8_t  transfer_aad[TRANSFER_AAD_SIZE];
        size_t   transfer_aad_len;

        msg_type_t r3_cmd;
        uint16_t   r3_len;
        int        ret;

        /* --- Validate R1 --- */
        if (first_len != sizeof(receive_r1_t)) {
            print_error("Operation failed");
            return -1;
        }

        r1 = (receive_r1_t *)first_buf;

        if (!validate_slot(r1->slot) || !is_slot_in_use(r1->slot)) {
            print_error("Operation failed");
            return -1;
        }

        /* Save R1 values before first_buf is potentially reused. */
        slot_req = r1->slot;
        memcpy(recv_chal, r1->recv_chal, NONCE_SIZE);

        /* Load encrypted file into work.transfer.file_buf.stored_file. */
        memset(&work.transfer, 0, sizeof(work.transfer));
        if (read_file(slot_req, &work.transfer.file_buf.stored_file) != 0) {
            secure_zero(&work.transfer, sizeof(work.transfer));
            print_error("Operation failed");
            return -1;
        }

        if (work.transfer.file_buf.stored_file.in_use != FILE_IN_USE) {
            secure_zero(&work.transfer, sizeof(work.transfer));
            print_error("Operation failed");
            return -1;
        }

        if (!validate_contents_len(work.transfer.file_buf.stored_file.contents_len)) {
            secure_zero(&work.transfer, sizeof(work.transfer));
            print_error("Operation failed");
            return -1;
        }

        /* Save metadata we need after zeroing stored_file. */
        saved_group_id    = work.transfer.file_buf.stored_file.group_id;
        saved_contents_len = work.transfer.file_buf.stored_file.contents_len;
        memcpy(saved_name, work.transfer.file_buf.stored_file.name, MAX_NAME_SIZE);
        saved_name[MAX_NAME_SIZE - 1] = '\0';

        /* UUID comes from the FAT (authoritative source for transfer AAD). */
        {
            const filesystem_entry_t *fat = get_file_metadata(slot_req);
            if (fat == NULL) {
                secure_zero(&work.transfer, sizeof(work.transfer));
                print_error("Operation failed");
                return -1;
            }
            memcpy(saved_uuid, fat->uuid, UUID_SIZE);
        }

        /* ---- Round 2: generate sender challenge, send authentication ---- */
        memset(&r2, 0, sizeof(r2));
        if (generate_nonce(r2.send_chal) != 0) {
            secure_zero(&work.transfer, sizeof(work.transfer));
            print_error("Operation failed");
            return -1;
        }
        memcpy(send_chal, r2.send_chal, NONCE_SIZE);

        /* sender_auth = HMAC(TAK, recv_chal || "sender") */
        if (hmac_sha256(TRANSFER_AUTH_KEY,
                        recv_chal, NONCE_SIZE,
                        HMAC_DOMAIN_SENDER,
                        r2.sender_auth) != 0) {
            secure_zero(&r2, sizeof(r2));
            secure_zero(&work.transfer, sizeof(work.transfer));
            print_error("Operation failed");
            return -1;
        }

        write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, &r2, sizeof(r2));
        secure_zero(&r2, sizeof(r2));

        /* ---- Round 3: receive and verify receiver auth + permissions ---- */
        memset(&r3, 0, sizeof(r3));
        r3_len = sizeof(r3);
        r3_cmd = 0;

        if (read_packet(TRANSFER_INTERFACE, &r3_cmd, &r3, &r3_len) != MSG_OK ||
            r3_cmd != RECEIVE_MSG ||
            r3_len != sizeof(r3)) {
            secure_zero(recv_chal, NONCE_SIZE);
            secure_zero(send_chal, NONCE_SIZE);
            secure_zero(&r3, sizeof(r3));
            secure_zero(&work.transfer, sizeof(work.transfer));
            print_error("Operation failed");
            return -1;
        }

        if (!validate_perm_count(r3.perm_count)) {
            secure_zero(recv_chal, NONCE_SIZE);
            secure_zero(send_chal, NONCE_SIZE);
            secure_zero(&r3, sizeof(r3));
            secure_zero(&work.transfer, sizeof(work.transfer));
            print_error("Operation failed");
            return -1;
        }

        if (!validate_perm_bytes(r3.perms, r3.perm_count)) {
            secure_zero(recv_chal, NONCE_SIZE);
            secure_zero(send_chal, NONCE_SIZE);
            secure_zero(&r3, sizeof(r3));
            secure_zero(&work.transfer, sizeof(work.transfer));
            print_error("Operation failed");
            return -1;
        }

        /* Verify receiver's PERMISSION_MAC before trusting perm content. */
        if (!verify_perm_mac(r3.perm_count, r3.perms, r3.perm_mac)) {
            secure_zero(recv_chal, NONCE_SIZE);
            secure_zero(send_chal, NONCE_SIZE);
            secure_zero(&r3, sizeof(r3));
            secure_zero(&work.transfer, sizeof(work.transfer));
            print_error("Operation failed");
            return -1;
        }

        /* recv_auth = HMAC(TAK, send_chal || "receiver") */
        if (!hmac_verify(TRANSFER_AUTH_KEY,
                         send_chal, NONCE_SIZE,
                         HMAC_DOMAIN_RECEIVER,
                         r3.recv_auth)) {
            secure_zero(recv_chal, NONCE_SIZE);
            secure_zero(send_chal, NONCE_SIZE);
            secure_zero(&r3, sizeof(r3));
            secure_zero(&work.transfer, sizeof(work.transfer));
            print_error("Operation failed");
            return -1;
        }

        /* Check that the receiver has RECEIVE permission for this file's group. */
        SECURE_BOOL_CHECK(ok1, ok2,
            perm_bytes_has_receive(r3.perms, r3.perm_count, saved_group_id));
        if (!ok1) {
            secure_zero(recv_chal, NONCE_SIZE);
            secure_zero(send_chal, NONCE_SIZE);
            secure_zero(&r3, sizeof(r3));
            secure_zero(&work.transfer, sizeof(work.transfer));
            print_error("Operation failed");
            return -1;
        }

        secure_zero(&r3, sizeof(r3));

        /* ---- Decrypt stored_file → work.transfer.plaintext (STORAGE_KEY) ---- */
        storage_aad_len = build_storage_aad(
            work.transfer.file_buf.stored_file.slot,
            saved_uuid,
            saved_group_id,
            saved_name,
            storage_aad
        );

        memset(work.transfer.plaintext, 0, MAX_CONTENTS_SIZE);
        random_delay();
        ret = aes_gcm_decrypt(
            STORAGE_KEY,
            work.transfer.file_buf.stored_file.nonce,
            storage_aad, storage_aad_len,
            work.transfer.file_buf.stored_file.ciphertext,
            saved_contents_len,
            work.transfer.file_buf.stored_file.tag,
            work.transfer.plaintext
        );
        secure_zero(storage_aad, sizeof(storage_aad));

        if (ret != 0) {
            secure_zero(recv_chal, NONCE_SIZE);
            secure_zero(send_chal, NONCE_SIZE);
            secure_zero(work.transfer.plaintext, MAX_CONTENTS_SIZE);
            secure_zero(&work.transfer, sizeof(work.transfer));
            print_error("Operation failed");
            return -1;
        }

        /* stored_file no longer needed; zero it before reusing file_buf. */
        secure_zero(&work.transfer.file_buf.stored_file,
                    sizeof(work.transfer.file_buf.stored_file));

        /* ---- Populate fdata header fields ---- */
        fdata = &work.transfer.file_buf.fdata;
        memset(fdata, 0, sizeof(*fdata));

        fdata->contents_len = saved_contents_len;
        fdata->slot         = slot_req;
        fdata->group_id     = saved_group_id;
        memcpy(fdata->uuid, saved_uuid, UUID_SIZE);
        memcpy(fdata->name, saved_name, MAX_NAME_SIZE);
        fdata->name[MAX_NAME_SIZE - 1] = '\0';

        /* Fresh nonce for transit encryption. */
        if (generate_nonce(fdata->nonce) != 0) {
            secure_zero(recv_chal, NONCE_SIZE);
            secure_zero(send_chal, NONCE_SIZE);
            secure_zero(work.transfer.plaintext, MAX_CONTENTS_SIZE);
            secure_zero(&work.transfer, sizeof(work.transfer));
            print_error("Operation failed");
            return -1;
        }

        /* ---- Encrypt plaintext → fdata.ciphertext (TRANSFER_KEY) ---- */
        transfer_aad_len = build_transfer_aad(
            recv_chal,
            send_chal,
            slot_req,
            saved_uuid,
            saved_group_id,
            saved_name,
            transfer_aad
        );

        random_delay();
        ret = aes_gcm_encrypt(
            TRANSFER_KEY,
            fdata->nonce,
            transfer_aad, transfer_aad_len,
            work.transfer.plaintext, saved_contents_len,
            fdata->ciphertext,
            fdata->tag
        );

        secure_zero(transfer_aad, sizeof(transfer_aad));
        secure_zero(recv_chal, NONCE_SIZE);
        secure_zero(send_chal, NONCE_SIZE);

        if (ret != 0) {
            secure_zero(work.transfer.plaintext, MAX_CONTENTS_SIZE);
            secure_zero(&work.transfer, sizeof(work.transfer));
            print_error("Operation failed");
            return -1;
        }

        /* Send header + ciphertext only (not the padded tail). */
        write_packet(TRANSFER_INTERFACE, RECEIVE_MSG,
                     fdata,
                     (uint16_t)(FILE_DATA_HEADER_SIZE + saved_contents_len));

        secure_zero(work.transfer.plaintext, MAX_CONTENTS_SIZE);
        secure_zero(&work.transfer, sizeof(work.transfer));

        write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
        return 0;
    }

    /* ================================================================== */
    /* INTERROGATE_MSG — responder side                                    */
    /* ================================================================== */
    if (cmd == INTERROGATE_MSG) {
        interrogate_r1_t *ir1;
        interrogate_r2_t  ir2;
        list_response_t   resp_list;
        uint8_t           hmac_input[NONCE_SIZE + sizeof(list_response_t)];
        uint16_t          list_len;
        uint8_t           slot_i;   /* loop counter */

        if (first_len != sizeof(interrogate_r1_t)) {
            print_error("Operation failed");
            return -1;
        }

        ir1 = (interrogate_r1_t *)first_buf;

        if (!validate_perm_count(ir1->perm_count)) {
            print_error("Operation failed");
            return -1;
        }

        if (!validate_perm_bytes(ir1->perms, ir1->perm_count)) {
            print_error("Operation failed");
            return -1;
        }

        /* Verify permission MAC before trusting perm content. */
        if (!verify_perm_mac(ir1->perm_count, ir1->perms, ir1->perm_mac)) {
            print_error("Operation failed");
            return -1;
        }

        /* Verify challenge auth = HMAC(TAK, challenge || "interrogate_req"). */
        if (!hmac_verify(TRANSFER_AUTH_KEY,
                         ir1->challenge, NONCE_SIZE,
                         HMAC_DOMAIN_INTERROGATE_REQ,
                         ir1->auth)) {
            print_error("Operation failed");
            return -1;
        }

        /* Build filtered list: include only slots where the requester has
         * RECEIVE permission for the file's group_id.
         * Loop counter slot_i in [0, MAX_FILE_COUNT). */
        memset(&resp_list, 0, sizeof(resp_list));
        resp_list.n_files = 0;

        for (slot_i = 0; slot_i < MAX_FILE_COUNT; slot_i++) {
            uint16_t gid = 0;

            if (!is_slot_in_use(slot_i)) {
                continue;
            }
            if (read_file_group_id(slot_i, &gid) != 0) {
                continue;
            }
            if (!perm_bytes_has_receive(ir1->perms, ir1->perm_count, gid)) {
                continue;
            }

            /* Slot passes filter — add to response. */
            {
                uint32_t idx = resp_list.n_files;
                resp_list.metadata[idx].slot     = slot_i;
                resp_list.metadata[idx].group_id = gid;

                /* Read name from flash for this slot. */
                memset(&work.listing.temp_file, 0, sizeof(work.listing.temp_file));
                if (read_file(slot_i, &work.listing.temp_file) == 0) {
                    strncpy(resp_list.metadata[idx].name,
                            work.listing.temp_file.name,
                            MAX_NAME_SIZE - 1);
                    resp_list.metadata[idx].name[MAX_NAME_SIZE - 1] = '\0';
                    secure_zero(&work.listing.temp_file,
                                sizeof(work.listing.temp_file));
                }
                resp_list.n_files = idx + 1;
            }
        }

        list_len = (uint16_t)LIST_PKT_LEN(resp_list.n_files);

        /* resp_auth = HMAC(TAK, challenge || filtered_list || "interrogate_resp") */
        memset(&ir2, 0, sizeof(ir2));
        memcpy(hmac_input,              ir1->challenge, NONCE_SIZE);
        memcpy(hmac_input + NONCE_SIZE, &resp_list,     list_len);

        if (hmac_sha256(TRANSFER_AUTH_KEY,
                        hmac_input, (size_t)(NONCE_SIZE + list_len),
                        HMAC_DOMAIN_INTERROGATE_RSP,
                        ir2.resp_auth) != 0) {
            secure_zero(hmac_input, sizeof(hmac_input));
            secure_zero(&ir2, sizeof(ir2));
            print_error("Operation failed");
            return -1;
        }
        secure_zero(hmac_input, sizeof(hmac_input));

        memcpy(&ir2.list, &resp_list, list_len);

        write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG,
                     &ir2, (uint16_t)(HMAC_SIZE + list_len));
        secure_zero(&ir2, sizeof(ir2));

        write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
        return 0;
    }

    /* Unknown message type. */
    print_error("Operation failed");
    return -1;
}
