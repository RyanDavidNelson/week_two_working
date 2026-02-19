/**
 * @file commands.c
 * @brief eCTF command handlers
 * @date 2026
 *
 * Week 1: Input validation at command entry.
 * Week 3: AES-256-GCM encryption at rest via secure_read_file/secure_write_file.
 * Week 4: Mutual authentication and re-encryption for RECEIVE and INTERROGATE.
 *
 * ── SRAM layout ──────────────────────────────────────────────────────────
 * All large (~8 KB) work buffers are pooled into one global union so that
 * only the maximum single-arm footprint lands in .bss.  Commands are
 * mutually exclusive on a bare-metal single-threaded MCU.
 *
 *   work union
 *   ├── transfer arm  (receive() + listen/RECEIVE_MSG)
 *   │   ├── file_buf sub-union          max(file_t, file_data_t) ≈ 8273 B
 *   │   │   ├── stored_file  (file_t)   8273 B — flash → decrypt → zero
 *   │   │   └── fdata (file_data_t)     8272 B — zero → encrypt → transmit
 *   │   └── plaintext[MAX_CONTENTS_SIZE]            8192 B
 *   │   total transfer arm:                       ≈16465 B
 *   └── listing arm   (generate_list_files)
 *       └── temp_file (file_t)                     8273 B
 *
 *   union .bss footprint = max(16465, 8273) ≈ 16465 B
 *   (down from ≈24737 B when fdata was a separate member)
 *
 * stored_file and fdata share file_buf because their lifetimes are
 * strictly sequential: in listen/RECEIVE_MSG, stored_file fields are saved
 * to small stack locals, stored_file is zeroed (which also zeroes the fdata
 * region), then fdata is populated from those locals before encryption.
 *
 * ── Security fixes (post-review) ─────────────────────────────────────────
 *  • file_data_t tag field moved before ciphertext[] so write_packet
 *    serializes it at the correct wire offset. FILE_DATA_HEADER_SIZE = 80.
 *    receive() cross-validates fdata_len == FILE_DATA_HEADER_SIZE + contents_len.
 *  • list(): PIN checked before generate_list_files() — eliminates timing
 *    oracle on number of stored files.
 *  • All command entry points check pkt_len >= sizeof(command_struct).
 *  • listen/RECEIVE_MSG: receive_request_t and permission_proof_t lengths
 *    checked for exact match (not just minimum).
 *  • validate_permission() (glitch-resistant, from security.c) used for all
 *    permission checks against our own global_permissions[].
 *  • Received permission bool fields validated via validate_bool().
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
 * Always memset the relevant arm/sub-union before use.
 * Always secure_zero() sensitive fields before returning.
 **********************************************************/

static union {
    /* transfer arm: receive() and listen()/RECEIVE_MSG */
    struct {
        union {
            /* stored_file: populated by read_file(), zeroed after decrypt.
             * fdata:        zeroed when stored_file is cleared, then
             *               populated from saved locals and encrypted into.
             * INVARIANT: stored_file is fully zeroed before fdata is written. */
            file_t      stored_file;
            file_data_t fdata;
        } file_buf;
        uint8_t plaintext[MAX_CONTENTS_SIZE];
    } transfer;

    /* listing arm: generate_list_files() — list() + listen()/INTERROGATE_MSG */
    struct {
        file_t temp_file;
    } listing;
} work;

/**********************************************************
 ******************** INTERNAL HELPERS ********************
 **********************************************************/

/** Serialize one group_permission_t: group_id(2 LE) || read(1) || write(1) || receive(1). */
static void serialize_one_perm(const group_permission_t *p, uint8_t *out)
{
    out[0] = (uint8_t)(p->group_id & 0xFF);
    out[1] = (uint8_t)((p->group_id >> 8) & 0xFF);
    out[2] = p->read    ? 1u : 0u;
    out[3] = p->write   ? 1u : 0u;
    out[4] = p->receive ? 1u : 0u;
}

/** Serialize count entries from src[] into out[]. */
static void serialize_permissions(const group_permission_t *src, uint8_t count,
                                   uint8_t *out)
{
    uint8_t i;
    for (i = 0; i < count; i++) {
        serialize_one_perm(&src[i], out + (size_t)i * PERM_SERIAL_SIZE);
    }
}

/** Validate boolean fields in received serialized permissions.
 *  Calls validate_bool() from security.c on each read/write/receive byte. */
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

/** Verify permission MAC: HMAC(AUTH_KEY, perm_count(1) || perm_bytes, "permission").
 *  Uses the glitch-resistant hmac_verify() from crypto.c. */
static bool verify_perm_mac(uint8_t perm_count, const uint8_t *perm_bytes,
                             const uint8_t *received_mac)
{
    uint8_t mac_data[1 + MAX_PERMS * PERM_SERIAL_SIZE];
    mac_data[0] = perm_count;
    memcpy(mac_data + 1, perm_bytes, (size_t)perm_count * PERM_SERIAL_SIZE);
    return hmac_verify(AUTH_KEY,
                       mac_data, 1 + (size_t)perm_count * PERM_SERIAL_SIZE,
                       HMAC_DOMAIN_PERMISSION, received_mac);
}

/** Check whether received serialized permissions include RECEIVE for group_id.
 *  NOTE: validate_permission() from security.c checks OUR OWN global_permissions[].
 *  This function checks the PEER'S permissions from the protocol message. */
static bool perm_bytes_has_receive(const uint8_t *perm_bytes, uint8_t perm_count,
                                   uint16_t group_id)
{
    uint8_t i;
    for (i = 0; i < perm_count; i++) {
        const uint8_t *p = perm_bytes + (size_t)i * PERM_SERIAL_SIZE;
        uint16_t gid = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
        if (gid == group_id && p[4] == 1u) {
            return true;
        }
    }
    return false;
}

/** Build file list for this device into file_list.
 *  Uses work.listing.temp_file — caller must not hold the transfer arm. */
static void generate_list_files(list_response_t *file_list)
{
    uint8_t slot;

    file_list->n_files = 0;
    memset(&work.listing.temp_file, 0, sizeof(work.listing.temp_file));

    for (slot = 0; slot < MAX_FILE_COUNT; slot++) {
        if (is_slot_in_use(slot)) {
            read_file(slot, &work.listing.temp_file);

            uint32_t idx = file_list->n_files;
            file_list->metadata[idx].slot     = slot;
            file_list->metadata[idx].group_id = work.listing.temp_file.group_id;

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
 **********************************************************/

int list(uint16_t pkt_len, uint8_t *buf)
{
    list_command_t *command = (list_command_t *)buf;
    list_response_t file_list;

    if (pkt_len < sizeof(list_command_t)) {
        print_error("Operation failed");
        return -1;
    }

    /* PIN check first — prevents timing oracle on number of stored files */
    if (!check_pin(command->pin)) {
        print_error("Operation failed");
        return -1;
    }

    memset(&file_list, 0, sizeof(file_list));
    generate_list_files(&file_list);

    pkt_len_t length = LIST_PKT_LEN(file_list.n_files);
    write_packet(CONTROL_INTERFACE, LIST_MSG, &file_list, length);
    return 0;
}

int read(uint16_t pkt_len, uint8_t *buf)
{
    read_command_t *command = (read_command_t *)buf;

    if (pkt_len < sizeof(read_command_t)) {
        print_error("Operation failed");
        return -1;
    }

    if (!validate_slot(command->slot)) {
        print_error("Operation failed");
        return -1;
    }

    if (!check_pin(command->pin)) {
        print_error("Operation failed");
        return -1;
    }

    /* Permission check BEFORE decryption — lightweight metadata read */
    uint16_t pre_group_id = 0;
    if (read_file_group_id(command->slot, &pre_group_id) != 0) {
        print_error("Operation failed");
        return -1;
    }

    /* validate_permission() from security.c: double-check with random_delay */
    if (!validate_permission(pre_group_id, PERM_READ)) {
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

    /* TOCTOU defense: verify group_id after decryption matches pre-check */
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

int write(uint16_t pkt_len, uint8_t *buf)
{
    write_command_t *command = (write_command_t *)buf;

    if (pkt_len < sizeof(write_command_t)) {
        print_error("Operation failed");
        return -1;
    }

    if (!validate_slot(command->slot)) {
        print_error("Operation failed");
        return -1;
    }

    if (!check_pin(command->pin)) {
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

    /* validate_permission() from security.c — glitch-resistant */
    if (!validate_permission(command->group_id, PERM_WRITE)) {
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
 * @brief RECEIVE — requester (initiator) side.
 *
 * Uses work.transfer.file_buf.fdata (stored_file not needed here).
 *
 * Wire protocol:
 *   TX R1: receive_request_t  (slot || receiver_challenge)              13 B
 *   RX R2: challenge_response_t  (sender_challenge || sender_auth)      44 B
 *   TX R3: permission_proof_t  (receiver_auth || perm_count ||
 *                               perms || perm_mac)                     105 B
 *   RX R4: file_data_t  (header 80 B || ciphertext contents_len B)
 */
int receive(uint16_t pkt_len, uint8_t *buf)
{
    receive_command_t *command = (receive_command_t *)buf;
    msg_type_t cmd;
    int ret;

    if (pkt_len < sizeof(receive_command_t)) {
        print_error("Operation failed");
        return -1;
    }

    if (!validate_slot(command->read_slot) || !validate_slot(command->write_slot)) {
        print_error("Operation failed");
        return -1;
    }

    if (!check_pin(command->pin)) {
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

    /* Verify sender_auth = HMAC(AUTH_KEY, receiver_challenge, "sender") */
    if (!hmac_verify(AUTH_KEY,
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

    /* receiver_auth = HMAC(AUTH_KEY, sender_challenge, "receiver") */
    if (hmac_sha256(AUTH_KEY,
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
    /* Round 4: receive file_data_t into work.transfer.file_buf.fdata     */
    /* tag precedes ciphertext[] in the struct (FILE_DATA_HEADER_SIZE=80) */
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

    /* Validate contents_len range before using it in crypto */
    if (!validate_contents_len(work.transfer.file_buf.fdata.contents_len)) {
        secure_zero(&req, sizeof(req));
        secure_zero(&chal_resp, sizeof(chal_resp));
        secure_zero(&work.transfer, sizeof(work.transfer));
        print_error("Operation failed");
        return -1;
    }

    /* Cross-validate: packet length must be exactly header + ciphertext */
    if (fdata_len !=
        (uint16_t)(FILE_DATA_HEADER_SIZE +
                   work.transfer.file_buf.fdata.contents_len)) {
        secure_zero(&req, sizeof(req));
        secure_zero(&chal_resp, sizeof(chal_resp));
        secure_zero(&work.transfer, sizeof(work.transfer));
        print_error("Operation failed");
        return -1;
    }

    /* ------------------------------------------------------------------ */
    /* Decrypt transfer envelope into work.transfer.plaintext             */
    /* transfer_AAD = recv_chal||send_chal||slot||uuid||gid  (43 bytes)   */
    /* ------------------------------------------------------------------ */
    uint8_t transfer_aad[43];
    size_t  transfer_aad_len = build_transfer_aad(
        req.receiver_challenge,
        chal_resp.sender_challenge,
        command->read_slot,
        work.transfer.file_buf.fdata.uuid,
        work.transfer.file_buf.fdata.group_id,
        transfer_aad
    );

    memset(work.transfer.plaintext, 0, sizeof(work.transfer.plaintext));

    random_delay();
    /* fdata.tag is at offset (FILE_DATA_HEADER_SIZE - TAG_SIZE), immediately
     * before ciphertext[], so read_packet populated it as part of the header. */
    ret = aes_gcm_decrypt(work.transfer.file_buf.fdata.transfer_nonce,
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

    /* validate_permission() from security.c — glitch-resistant double-check */
    if (!validate_permission(work.transfer.file_buf.fdata.group_id, PERM_RECEIVE)) {
        secure_zero(&work.transfer, sizeof(work.transfer));
        print_error("Operation failed");
        return -1;
    }

    /* Re-encrypt for local storage with a fresh nonce and storage AAD */
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
 *   TX R1: interrogate_request_t  (challenge || auth || perm_count ||
 *                                  perms || perm_mac)                  117 B
 *   RX R2: response_auth(32) || list_response_t body
 */
int interrogate(uint16_t pkt_len, uint8_t *buf)
{
    interrogate_command_t *command = (interrogate_command_t *)buf;
    msg_type_t cmd;

    if (pkt_len < sizeof(interrogate_command_t)) {
        print_error("Operation failed");
        return -1;
    }

    if (!check_pin(command->pin)) {
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

    /* auth = HMAC(AUTH_KEY, challenge, "interrogate_req") */
    if (hmac_sha256(AUTH_KEY,
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
    /* Round 2: receive response_auth || list_response_t body             */
    /* ------------------------------------------------------------------ */
    interrogate_response_t iresp;
    memset(&iresp, 0, sizeof(iresp));
    uint16_t iresp_len = sizeof(iresp);

    cmd = 0;
    if (read_packet(TRANSFER_INTERFACE, &cmd, &iresp, &iresp_len) != MSG_OK ||
        cmd != INTERROGATE_MSG) {
        secure_zero(&ireq, sizeof(ireq));
        secure_zero(&iresp, sizeof(iresp));
        print_error("Operation failed");
        return -1;
    }

    /* Response must carry at least the auth MAC */
    if (iresp_len < (uint16_t)HMAC_SIZE) {
        secure_zero(&ireq, sizeof(ireq));
        secure_zero(&iresp, sizeof(iresp));
        print_error("Operation failed");
        return -1;
    }

    uint16_t list_data_len = iresp_len - (uint16_t)HMAC_SIZE;

    if (list_data_len > (uint16_t)sizeof(list_response_t)) {
        secure_zero(&ireq, sizeof(ireq));
        secure_zero(&iresp, sizeof(iresp));
        print_error("Operation failed");
        return -1;
    }

    /* Verify response_auth = HMAC(AUTH_KEY, challenge || list_data,
     *                              "interrogate_resp") */
    uint8_t hmac_input[NONCE_SIZE + sizeof(list_response_t)];
    memcpy(hmac_input, ireq.challenge, NONCE_SIZE);
    memcpy(hmac_input + NONCE_SIZE, &iresp.file_list, list_data_len);

    bool auth_ok = hmac_verify(AUTH_KEY,
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
 * @brief LISTEN — dispatches incoming messages from a peer HSM.
 *
 * RECEIVE_MSG:     Sender (responder) side of the mutual-auth transfer protocol.
 *                  Uses work.transfer arm (file_buf sub-union + plaintext).
 * INTERROGATE_MSG: Responder side — verify challenge, filter list, sign response.
 *                  Uses work.listing arm (via generate_list_files).
 */
int listen(uint16_t pkt_len, uint8_t *buf)
{
    msg_type_t cmd;
    int ret;

    /* Largest first inbound message is interrogate_request_t (117 bytes) */
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
        /* Round 1: receive_request_t must be exactly 13 bytes */
        if (read_length != sizeof(receive_request_t)) {
            print_error("Operation failed");
            return -1;
        }
        receive_request_t *rreq = (receive_request_t *)transfer_buf;

        if (!validate_slot(rreq->slot)) {
            print_error("Operation failed");
            return -1;
        }

        if (!is_slot_in_use(rreq->slot)) {
            print_error("Operation failed");
            return -1;
        }

        /* Save receiver_challenge and slot before transfer_buf is reused */
        uint8_t receiver_challenge[NONCE_SIZE];
        uint8_t requested_slot = rreq->slot;
        memcpy(receiver_challenge, rreq->receiver_challenge, NONCE_SIZE);

        /* Load file from flash into work.transfer.file_buf.stored_file */
        memset(&work.transfer.file_buf.stored_file, 0,
               sizeof(work.transfer.file_buf.stored_file));
        if (read_file(requested_slot, &work.transfer.file_buf.stored_file) != 0) {
            secure_zero(receiver_challenge, NONCE_SIZE);
            secure_zero(&work.transfer, sizeof(work.transfer));
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

        /* sender_auth = HMAC(AUTH_KEY, receiver_challenge, "sender") */
        if (hmac_sha256(AUTH_KEY,
                        receiver_challenge, NONCE_SIZE,
                        HMAC_DOMAIN_SENDER,
                        chal_resp.sender_auth) != 0) {
            secure_zero(receiver_challenge, NONCE_SIZE);
            secure_zero(&work.transfer, sizeof(work.transfer));
            secure_zero(&chal_resp, sizeof(chal_resp));
            print_error("Operation failed");
            return -1;
        }

        write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, &chal_resp, sizeof(chal_resp));

        /* ---------------------------------------------------------------- */
        /* Round 3: receive permission_proof_t (exact size enforced)        */
        /* ---------------------------------------------------------------- */
        permission_proof_t proof;
        memset(&proof, 0, sizeof(proof));
        uint16_t proof_len = sizeof(proof);

        cmd = 0;
        if (read_packet(TRANSFER_INTERFACE, &cmd, &proof, &proof_len) != MSG_OK ||
            cmd != RECEIVE_MSG || proof_len != sizeof(proof)) {
            secure_zero(receiver_challenge, NONCE_SIZE);
            secure_zero(&work.transfer, sizeof(work.transfer));
            secure_zero(&chal_resp, sizeof(chal_resp));
            secure_zero(&proof, sizeof(proof));
            print_error("Operation failed");
            return -1;
        }

        if (!validate_perm_count(proof.perm_count)) {
            secure_zero(receiver_challenge, NONCE_SIZE);
            secure_zero(&work.transfer, sizeof(work.transfer));
            secure_zero(&chal_resp, sizeof(chal_resp));
            secure_zero(&proof, sizeof(proof));
            print_error("Operation failed");
            return -1;
        }

        if (!validate_perm_bytes(proof.permissions_bytes, proof.perm_count)) {
            secure_zero(receiver_challenge, NONCE_SIZE);
            secure_zero(&work.transfer, sizeof(work.transfer));
            secure_zero(&chal_resp, sizeof(chal_resp));
            secure_zero(&proof, sizeof(proof));
            print_error("Operation failed");
            return -1;
        }

        if (!verify_perm_mac(proof.perm_count, proof.permissions_bytes,
                             proof.permission_mac)) {
            secure_zero(receiver_challenge, NONCE_SIZE);
            secure_zero(&work.transfer, sizeof(work.transfer));
            secure_zero(&chal_resp, sizeof(chal_resp));
            secure_zero(&proof, sizeof(proof));
            print_error("Operation failed");
            return -1;
        }

        /* Verify receiver_auth = HMAC(AUTH_KEY, sender_challenge, "receiver") */
        if (!hmac_verify(AUTH_KEY,
                         chal_resp.sender_challenge, NONCE_SIZE,
                         HMAC_DOMAIN_RECEIVER,
                         proof.receiver_auth)) {
            secure_zero(receiver_challenge, NONCE_SIZE);
            secure_zero(&work.transfer, sizeof(work.transfer));
            secure_zero(&chal_resp, sizeof(chal_resp));
            secure_zero(&proof, sizeof(proof));
            print_error("Operation failed");
            return -1;
        }

        if (!perm_bytes_has_receive(proof.permissions_bytes,
                                    proof.perm_count,
                                    file_group_id)) {
            secure_zero(receiver_challenge, NONCE_SIZE);
            secure_zero(&work.transfer, sizeof(work.transfer));
            secure_zero(&chal_resp, sizeof(chal_resp));
            secure_zero(&proof, sizeof(proof));
            print_error("Operation failed");
            return -1;
        }

        secure_zero(&proof, sizeof(proof));

        /* ---------------------------------------------------------------- */
        /* Decrypt stored_file into work.transfer.plaintext                */
        /* ---------------------------------------------------------------- */
        const filesystem_entry_t *fat = get_file_metadata(requested_slot);
        if (fat == NULL) {
            secure_zero(receiver_challenge, NONCE_SIZE);
            secure_zero(&work.transfer, sizeof(work.transfer));
            secure_zero(&chal_resp, sizeof(chal_resp));
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

        random_delay();
        ret = aes_gcm_decrypt(work.transfer.file_buf.stored_file.nonce,
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
        /* Transition: save stored_file fields needed for fdata, then zero  */
        /* stored_file.  Zeroing file_buf also clears the fdata region      */
        /* (they share the same union memory) giving a clean slate.         */
        /* ---------------------------------------------------------------- */
        uint16_t saved_group_id     = work.transfer.file_buf.stored_file.group_id;
        uint16_t saved_contents_len = work.transfer.file_buf.stored_file.contents_len;
        char     saved_name[MAX_NAME_SIZE];
        memcpy(saved_name, work.transfer.file_buf.stored_file.name, MAX_NAME_SIZE);
        /* fat->uuid comes from flash — no need to save separately */

        secure_zero(&work.transfer.file_buf, sizeof(work.transfer.file_buf));

        /* ---------------------------------------------------------------- */
        /* Round 4: populate fdata and re-encrypt for transfer             */
        /* fdata now occupies the same memory previously held by stored_file */
        /* ---------------------------------------------------------------- */
        memcpy(work.transfer.file_buf.fdata.uuid, fat->uuid, UUID_SIZE);
        work.transfer.file_buf.fdata.group_id     = saved_group_id;
        work.transfer.file_buf.fdata.contents_len = saved_contents_len;
        memcpy(work.transfer.file_buf.fdata.name, saved_name, MAX_NAME_SIZE);
        work.transfer.file_buf.fdata.name[MAX_NAME_SIZE - 1] = '\0';

        /* Clear the saved locals now that they're in fdata */
        secure_zero(saved_name, MAX_NAME_SIZE);

        if (generate_nonce(work.transfer.file_buf.fdata.transfer_nonce) != 0) {
            secure_zero(receiver_challenge, NONCE_SIZE);
            secure_zero(&chal_resp, sizeof(chal_resp));
            secure_zero(&work.transfer, sizeof(work.transfer));
            print_error("Operation failed");
            return -1;
        }

        uint8_t transfer_aad[43];
        size_t  transfer_aad_len = build_transfer_aad(
            receiver_challenge,
            chal_resp.sender_challenge,
            requested_slot,
            work.transfer.file_buf.fdata.uuid,
            work.transfer.file_buf.fdata.group_id,
            transfer_aad
        );

        random_delay();
        ret = aes_gcm_encrypt(work.transfer.file_buf.fdata.transfer_nonce,
                              transfer_aad, transfer_aad_len,
                              work.transfer.plaintext,
                              work.transfer.file_buf.fdata.contents_len,
                              work.transfer.file_buf.fdata.ciphertext,
                              work.transfer.file_buf.fdata.tag);

        secure_zero(transfer_aad, sizeof(transfer_aad));
        secure_zero(receiver_challenge, NONCE_SIZE);
        secure_zero(&chal_resp, sizeof(chal_resp));
        secure_zero(work.transfer.plaintext, sizeof(work.transfer.plaintext));

        if (ret != 0) {
            secure_zero(&work.transfer.file_buf.fdata,
                        sizeof(work.transfer.file_buf.fdata));
            print_error("Operation failed");
            return -1;
        }

        /* Send: header (80 B, includes tag) + ciphertext (contents_len B) */
        uint16_t send_len = (uint16_t)(FILE_DATA_HEADER_SIZE +
                             work.transfer.file_buf.fdata.contents_len);
        write_packet(TRANSFER_INTERFACE, RECEIVE_MSG,
                     &work.transfer.file_buf.fdata, send_len);
        secure_zero(&work.transfer.file_buf.fdata,
                    sizeof(work.transfer.file_buf.fdata));
        break;
    }

    /* ================================================================== */
    /* INTERROGATE_MSG — responder side                                    */
    /* ================================================================== */
    case INTERROGATE_MSG: {
        /* Round 1: interrogate_request_t must be exactly 117 bytes */
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

        if (!verify_perm_mac(ireq->perm_count, ireq->permissions_bytes,
                             ireq->permission_mac)) {
            print_error("Operation failed");
            return -1;
        }

        /* Verify auth = HMAC(AUTH_KEY, challenge, "interrogate_req") */
        if (!hmac_verify(AUTH_KEY,
                         ireq->challenge, NONCE_SIZE,
                         HMAC_DOMAIN_INTERROGATE_REQ,
                         ireq->auth)) {
            print_error("Operation failed");
            return -1;
        }

        /* Build full list via work.listing arm, then filter */
        list_response_t full_list;
        memset(&full_list, 0, sizeof(full_list));
        generate_list_files(&full_list);

        list_response_t filtered_list;
        memset(&filtered_list, 0, sizeof(filtered_list));
        filtered_list.n_files = 0;

        uint32_t fi;
        for (fi = 0; fi < full_list.n_files; fi++) {
            uint16_t gid = full_list.metadata[fi].group_id;
            if (perm_bytes_has_receive(ireq->permissions_bytes,
                                       ireq->perm_count, gid)) {
                uint32_t out_idx = filtered_list.n_files;
                filtered_list.metadata[out_idx] = full_list.metadata[fi];
                filtered_list.n_files = out_idx + 1;
            }
        }

        /* ---------------------------------------------------------------- */
        /* Round 2: sign and send response_auth || filtered_list           */
        /* ---------------------------------------------------------------- */
        uint16_t list_data_len = (uint16_t)LIST_PKT_LEN(filtered_list.n_files);

        uint8_t hmac_input[NONCE_SIZE + sizeof(list_response_t)];
        memcpy(hmac_input, ireq->challenge, NONCE_SIZE);
        memcpy(hmac_input + NONCE_SIZE, &filtered_list, list_data_len);

        uint8_t response_auth[HMAC_SIZE];
        if (hmac_sha256(AUTH_KEY,
                        hmac_input, NONCE_SIZE + list_data_len,
                        HMAC_DOMAIN_INTERROGATE_RSP,
                        response_auth) != 0) {
            secure_zero(hmac_input, sizeof(hmac_input));
            secure_zero(response_auth, HMAC_SIZE);
            print_error("Operation failed");
            return -1;
        }

        secure_zero(hmac_input, sizeof(hmac_input));

        interrogate_response_t iresp;
        memset(&iresp, 0, sizeof(iresp));
        memcpy(iresp.response_auth, response_auth, HMAC_SIZE);
        memcpy(&iresp.file_list, &filtered_list, list_data_len);
        secure_zero(response_auth, HMAC_SIZE);

        uint16_t send_len = (uint16_t)HMAC_SIZE + list_data_len;
        write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, &iresp, send_len);
        break;
    }

    default:
        print_error("Operation failed");
        return -1;
    }

    write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
    return 0;
}
