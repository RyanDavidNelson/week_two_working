/**
 * @file commands.c
 * @brief eCTF command handlers
 * @date 2026
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include <string.h>
#include <stddef.h>
#include <stdbool.h>

#include "host_messaging.h"
#include "simple_uart.h"
#include "commands.h"
#include "filesystem.h"
#include "security.h"
#include "crypto.h"
#include "secrets.h"

/*
 * Shared static work buffer — one command runs at a time on bare metal.
 *
 *   .plain[]  8192 B — plaintext staging for listen()/RECEIVE_MSG
 *   .rsp{}    8224 B — read response: name(32) + contents(8192)
 *   .rcv      8273 B — R4 wire buffer for receive() initiator
 *
 * After aes_gcm_decrypt(..., in=.rcv.ciphertext, out=.rcv.ciphertext),
 * the ciphertext field holds the decrypted plaintext.  Field name is a
 * naming artifact; after in-place decrypt it contains plaintext.
 */
static union {
    uint8_t plain[MAX_CONTENTS_SIZE];        /* 8192 B — listen() plaintext staging */
    struct {
        char    name[MAX_NAME_SIZE];         /*   32 B                      */
        uint8_t contents[MAX_CONTENTS_SIZE]; /* 8192 B                      */
    } rsp;                                   /* 8224 B — read response      */
    receive_r4_t rcv;                        /* 8273 B — receive() R4 wire buffer */
} s_work;


/**********************************************************
 ******************** INTERNAL HELPERS ********************
 **********************************************************/

/* Serialize one permission: group_id(2 LE) || read(1) || write(1) || receive(1).
 * out must have PERM_SERIAL_SIZE bytes available. */
static void serialize_one_perm(const group_permission_t *p, uint8_t *out)
{
    out[0] = (uint8_t)(p->group_id & 0xFF);
    out[1] = (uint8_t)((p->group_id >> 8) & 0xFF);
    out[2] = p->read    ? 1u : 0u;
    out[3] = p->write   ? 1u : 0u;
    out[4] = p->receive ? 1u : 0u;
}

/*
 * Serialize count entries from src[] into out[].
 */
static void serialize_permissions(const group_permission_t *src,
                                  uint8_t count, uint8_t *out)
{
    uint8_t i;
    for (i = 0U; i < count; i++) {
        serialize_one_perm(&src[i], out + (size_t)i * PERM_SERIAL_SIZE);
    }
}

/*
 * Validate boolean fields in received serialized permissions.
 * p[2]=read, p[3]=write, p[4]=receive must each be exactly 0 or 1.
 */
static bool validate_perm_bytes(const uint8_t *perms, uint8_t perm_count)
{
    uint8_t i;
    for (i = 0U; i < perm_count; i++) {
        const uint8_t *p = perms + (size_t)i * PERM_SERIAL_SIZE;
        if (!validate_bool(p[2]) || !validate_bool(p[3]) || !validate_bool(p[4])) {
            return false;
        }
    }
    return true;
}

/*
 * Check if serialized permissions grant RECEIVE for a given group_id.
 */
static bool perm_bytes_has_receive(const uint8_t *perms, uint8_t perm_count,
                                   uint16_t group_id)
{
    uint8_t i;
    for (i = 0U; i < perm_count; i++) {
        const uint8_t *p   = perms + (size_t)i * PERM_SERIAL_SIZE;
        uint16_t       gid = (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
        if (gid == group_id && p[4] == 1u) { return true; }
    }
    return false;
}

/*
 * Verify the PERMISSION_MAC attached to a received permission blob.
 * PERMISSION_MAC = HMAC(PERM_MAC_KEY, count || perms || "permission").
 * enters any runtime HMAC hardware call — it only exists as a flash constant.
 * CPA on handshake traces cannot recover it.
 */
static bool verify_perm_mac(uint8_t perm_count, const uint8_t *perms,
                             const uint8_t *mac)
{
    uint8_t input[1 + MAX_PERMS * PERM_SERIAL_SIZE];
    input[0] = perm_count;
    memcpy(input + 1, perms, (size_t)perm_count * PERM_SERIAL_SIZE);
    return hmac_verify(PERM_MAC_KEY,                               /* FIX SCA3 */
                       input, 1 + (size_t)perm_count * PERM_SERIAL_SIZE,
                       HMAC_DOMAIN_PERMISSION, mac);
}

/*
 * XOR nonce with CHALLENGE_TWEAK into tweaked[NONCE_SIZE].
 * controls the nonce bytes on the wire but cannot predict the actual HMAC
 * first-block input without knowing CHALLENGE_TWEAK (a deployment secret).
 * Both sides of an exchange apply the same tweak so authentication is
 * unaffected.
 *
 * Call apply_tweak(), pass tweaked to hmac_sha256/hmac_verify, then
 * secure_zero(tweaked, NONCE_SIZE) after the call.
 */
static void apply_tweak(const uint8_t *nonce, uint8_t *tweaked)
{
    uint8_t i;
    for (i = 0U; i < NONCE_SIZE; i++) {
        tweaked[i] = nonce[i] ^ CHALLENGE_TWEAK[i];
    }
}


/*
 * generate_list_files — read all flash slots and populate file_list.
 * NOTE: reads the full file_t once per slot — does NOT call is_slot_in_use()
 * separately because that would put a second 8277-byte file_t on the stack
 * while temp_file is still live, overflowing the stack budget.
 */
static void generate_list_files(list_response_t *file_list)
{
    file_t  temp_file;
    uint8_t slot;

    file_list->n_files = 0;

    for (slot = 0U; slot < MAX_FILE_COUNT; slot++) {
        if (read_file(slot, &temp_file) != 0) { continue; }
        if (temp_file.in_use != FILE_IN_USE) {
            secure_zero(&temp_file, sizeof(temp_file));
            continue;
        }

        uint32_t idx = file_list->n_files;
        file_list->metadata[idx].slot     = slot;
        file_list->metadata[idx].group_id = temp_file.group_id;
        strncpy(file_list->metadata[idx].name, temp_file.name, MAX_NAME_SIZE - 1);
        file_list->metadata[idx].name[MAX_NAME_SIZE - 1] = '\0';
        file_list->n_files = idx + 1;

        secure_zero(&temp_file, sizeof(temp_file));
    }
}


/**********************************************************
 ******************** COMMAND HANDLERS ********************
 **********************************************************/

/*
 * LIST — enumerate all occupied slots.
 *
 * generate_list_files() places a file_t (8277 B) on the stack.
 * list() itself is thin, so combined stack stays under 15.8 KB.
 */
int list(uint16_t pkt_len, uint8_t *buf)
{
    list_command_t *command = (list_command_t *)buf;
    list_response_t file_list;
    volatile bool   ok1, ok2;

    if (pkt_len < sizeof(list_command_t)) {
        print_error("Operation failed");
        return -1;
    }

    SECURE_PIN_CHECK(ok1, ok2, command->pin);
    secure_zero(command->pin, PIN_LENGTH);
    if (!(ok1 & ok2)) {
        delay_ms(4500);
        print_error("Operation failed");
        return -1;
    }

    memset(&file_list, 0, sizeof(file_list));
    generate_list_files(&file_list);

    pkt_len_t length = (pkt_len_t)LIST_PKT_LEN(file_list.n_files);
    write_packet(CONTROL_INTERFACE, LIST_MSG, &file_list, length);
    return 0;
}

/*
 * READ — permission checked before decrypt; TOCTOU re-check after.
 *
 * Uses s_work.rsp (static) so that this function's stack frame and
 * secure_read_file()'s stack frame (each ~8.3 KB) do NOT overlap on the stack.
 * Both frames stay well within the 15.8 KB available stack budget.
 */
int read(uint16_t pkt_len, uint8_t *buf)
{
    read_command_t *command = (read_command_t *)buf;
    volatile bool   ok1, ok2;
    uint16_t        pre_gid      = 0;
    uint16_t        post_gid     = 0;
    uint16_t        contents_len = 0;

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
    if (!(ok1 & ok2)) {
        delay_ms(4500);
        print_error("Operation failed");
        return -1;
    }

    /* TOCTOU pre-check: read only group_id header (no full file_t). */
    if (read_file_group_id(command->slot, &pre_gid) != 0) {
        print_error("Operation failed");
        return -1;
    }

    SECURE_BOOL_CHECK(ok1, ok2, validate_permission(pre_gid, PERM_READ));
    if (!(ok1 & ok2)) {
        print_error("Operation failed");
        return -1;
    }

    /* Decrypt into s_work.rsp (static) — avoids 8224 B on the stack. */
    memset(&s_work.rsp, 0, sizeof(s_work.rsp));
    if (secure_read_file(command->slot,
                         s_work.rsp.contents,
                         s_work.rsp.name,
                         &contents_len,
                         &post_gid) != 0) {
        secure_zero(&s_work.rsp, sizeof(s_work.rsp));
        print_error("Operation failed");
        return -1;
    }
    if (!validate_contents_len(contents_len)) {
        secure_zero(&s_work.rsp, sizeof(s_work.rsp));
        print_error("Operation failed");
        return -1;
    }

    /* TOCTOU post-check: group_id must not have changed between reads. */
    if (pre_gid != post_gid) {
        secure_zero(&s_work.rsp, sizeof(s_work.rsp));
        print_error("Operation failed");
        return -1;
    }

    pkt_len_t length = (pkt_len_t)(sizeof(s_work.rsp.name) + contents_len);
    write_packet(CONTROL_INTERFACE, READ_MSG, &s_work.rsp, length);
    secure_zero(&s_work.rsp, sizeof(s_work.rsp));
    return 0;
}

/*
 * Byte length of the fixed header portion of write_command_t.
 * The host sends header + contents_len bytes, not the full struct.
 */
#define WRITE_CMD_HEADER_SIZE ((uint16_t)offsetof(write_command_t, contents))

/*
 * WRITE — permission enforced; overwrites existing slot content if occupied.
 *   Structural guards (slot, contents_len, packet length) remain before
 *   the PIN because they reject malformed packets regardless of credentials.
 *   Moving validate_name() after the PIN eliminates the pre-auth oracle.
 */
int write(uint16_t pkt_len, uint8_t *buf)
{
    write_command_t *command = (write_command_t *)buf;
    volatile bool    ok1, ok2;

    /* Step 1: structural guards — reject malformed packets before any work. */
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
    if (pkt_len < (uint16_t)(WRITE_CMD_HEADER_SIZE + command->contents_len)) {
        print_error("Operation failed");
        return -1;
    }

    /* Step 2: authenticate before inspecting any business-logic fields. */
    SECURE_PIN_CHECK(ok1, ok2, command->pin);
    secure_zero(command->pin, PIN_LENGTH);
    if (!(ok1 & ok2)) {
        delay_ms(4500);
        print_error("Operation failed");
        return -1;
    }

    /* Step 3: validate name only after a valid PIN — prevents pre-auth oracle. */
    if (!validate_name(command->name, MAX_NAME_SIZE)) {
        print_error("Operation failed");
        return -1;
    }

    SECURE_BOOL_CHECK(ok1, ok2, validate_permission(command->group_id, PERM_WRITE));
    if (!(ok1 & ok2)) {
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
 * RECEIVE — initiator side of the 4-round authenticated file transfer.
 *
 * R1 → send slot + recv_chal
 * R2 ← verify sender_auth = HMAC(TAK, recv_chal XOR TWEAK || "sender")
 * R3 → send recv_auth = HMAC(TAK, send_chal XOR TWEAK || "receiver") + perms
 * R4 ← verify GCM tag; check OWN RECEIVE permission; write to write_slot
 *
 * CHALLENGE_TWEAK is applied to every nonce before the HMAC call (FIX SCA4).
 *
 * STACK FIX: receive_r4_t (8273 B) lives in s_work.rcv (static).
 * Approach: receive R4 into s_work.rcv, save the 81-byte header to small
 * stack variables, decrypt in-place, then pass s_work.rcv.ciphertext
 * (now holding plaintext) to secure_write_file.
 * receive()'s stack frame is ~350 B at the secure_write_file call site.
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
    uint8_t            tweaked_chal[NONCE_SIZE];   /* SCA4: nonce XOR tweak */
    int                ret;

    /* Saved R4 header fields (81 bytes total) — fits on stack. */
    uint8_t  saved_nonce[NONCE_SIZE];
    uint8_t  saved_tag[TAG_SIZE];
    uint16_t saved_contents_len;
    uint8_t  saved_uuid[UUID_SIZE];
    uint8_t  saved_slot;
    uint16_t saved_group_id;
    char     saved_name[MAX_NAME_SIZE];

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
    if (!(ok1 & ok2)) {
        delay_ms(4500);
        print_error("Operation failed");
        return -1;
    }

    /* ---- R1: send slot + receiver challenge ---- */
    memset(&r1, 0, sizeof(r1));
    r1.slot = command->read_slot;
    if (generate_nonce(r1.recv_chal) != 0) {
        print_error("Operation failed");
        return -1;
    }
    delay_ms(200);
    if (write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, &r1, sizeof(r1)) != MSG_OK) {
        secure_zero(&r1, sizeof(r1));
        print_error("Operation failed");
        return -1;
    }

    /* ---- R2: verify sender authentication ---- */
    memset(&r2, 0, sizeof(r2));
    r2_len = sizeof(r2);
    cmd    = 0;
    if (read_packet(TRANSFER_INTERFACE, &cmd, &r2, &r2_len) != MSG_OK ||
        cmd != RECEIVE_MSG || r2_len != sizeof(r2)) {
        secure_zero(&r1, sizeof(r1));
        secure_zero(&r2, sizeof(r2));
        print_error("Operation failed");
        return -1;
    }

    /* SCA4: verify sender_auth over tweaked recv_chal. */
    apply_tweak(r1.recv_chal, tweaked_chal);
    if (!hmac_verify(TRANSFER_AUTH_KEY, tweaked_chal, NONCE_SIZE,
                     HMAC_DOMAIN_SENDER, r2.sender_auth)) {
        secure_zero(tweaked_chal, NONCE_SIZE);
        secure_zero(&r1, sizeof(r1));
        secure_zero(&r2, sizeof(r2));
        print_error("Operation failed");
        return -1;
    }
    secure_zero(tweaked_chal, NONCE_SIZE);

    /* ---- R3: send receiver auth + own permission proof ---- */
    memset(&r3, 0, sizeof(r3));

    /* SCA4: compute recv_auth over tweaked send_chal. */
    apply_tweak(r2.send_chal, tweaked_chal);
    if (hmac_sha256(TRANSFER_AUTH_KEY, tweaked_chal, NONCE_SIZE,
                    HMAC_DOMAIN_RECEIVER, r3.recv_auth) != 0) {
        secure_zero(tweaked_chal, NONCE_SIZE);
        secure_zero(&r1, sizeof(r1));
        secure_zero(&r2, sizeof(r2));
        print_error("Operation failed");
        return -1;
    }
    secure_zero(tweaked_chal, NONCE_SIZE);

    r3.perm_count = PERM_COUNT;
    serialize_permissions(global_permissions, PERM_COUNT, r3.perms);
    memcpy(r3.perm_mac, PERMISSION_MAC, HMAC_SIZE);
    if (write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, &r3, sizeof(r3)) != MSG_OK) {
        secure_zero(&r1, sizeof(r1));
        secure_zero(&r2, sizeof(r2));
        secure_zero(&r3, sizeof(r3));
        print_error("Operation failed");
        return -1;
    }
    secure_zero(&r3, sizeof(r3));

    /* ---- R4: receive encrypted file into s_work.rcv (static, not stack) ---- */
    memset(&s_work.rcv, 0, sizeof(s_work.rcv));
    r4_len = sizeof(s_work.rcv);
    cmd    = 0;
    if (read_packet(TRANSFER_INTERFACE, &cmd, &s_work.rcv, &r4_len) != MSG_OK ||
        cmd != RECEIVE_MSG) {
        secure_zero(&r1, sizeof(r1));
        secure_zero(&r2, sizeof(r2));
        secure_zero(&s_work.rcv, sizeof(s_work.rcv));
        print_error("Operation failed");
        return -1;
    }
    if (!validate_contents_len(s_work.rcv.contents_len)) {
        secure_zero(&r1, sizeof(r1));
        secure_zero(&r2, sizeof(r2));
        secure_zero(&s_work.rcv, sizeof(s_work.rcv));
        print_error("Operation failed");
        return -1;
    }
    if (r4_len != (uint16_t)(FILE_DATA_HEADER_SIZE + s_work.rcv.contents_len)) {
        secure_zero(&r1, sizeof(r1));
        secure_zero(&r2, sizeof(r2));
        secure_zero(&s_work.rcv, sizeof(s_work.rcv));
        print_error("Operation failed");
        return -1;
    }

    /*
     * Save the 81-byte R4 header to stack variables so that s_work.rcv can
     * be used as both the ciphertext source and plaintext destination (in-place
     * decrypt).  wolfcrypt AES-GCM verifies the tag over the original ciphertext
     * before overwriting, so in == out is safe.
     */
    memcpy(saved_nonce, s_work.rcv.nonce, NONCE_SIZE);
    memcpy(saved_tag,   s_work.rcv.tag,   TAG_SIZE);
    saved_contents_len = s_work.rcv.contents_len;
    memcpy(saved_uuid,  s_work.rcv.uuid,  UUID_SIZE);
    saved_slot         = s_work.rcv.slot;
    saved_group_id     = s_work.rcv.group_id;
    memcpy(saved_name,  s_work.rcv.name,  MAX_NAME_SIZE);
    saved_name[MAX_NAME_SIZE - 1] = '\0';

    /* Build transfer AAD using challenges from r1/r2 and saved metadata. */
    transfer_aad_len = build_transfer_aad(r1.recv_chal, r2.send_chal,
                                          saved_slot, saved_uuid,
                                          saved_group_id, saved_name,
                                          transfer_aad);

    /*
     * In-place GCM decrypt: source and destination are both s_work.rcv.ciphertext.
     * After this call s_work.rcv.ciphertext holds the plaintext.
     */
    ret = aes_gcm_decrypt(TRANSFER_KEY, saved_nonce,
                          transfer_aad, transfer_aad_len,
                          s_work.rcv.ciphertext, saved_contents_len,
                          saved_tag,
                          s_work.rcv.ciphertext);   /* in-place */

    secure_zero(transfer_aad, sizeof(transfer_aad));
    secure_zero(saved_nonce,   NONCE_SIZE);
    secure_zero(saved_tag,     TAG_SIZE);
    secure_zero(&r1, sizeof(r1));
    secure_zero(&r2, sizeof(r2));

    if (ret != 0) {
        secure_zero(&s_work.rcv, sizeof(s_work.rcv));
        secure_zero(saved_uuid,  UUID_SIZE);
        secure_zero(saved_name,  MAX_NAME_SIZE);
        print_error("Operation failed");
        return -1;
    }

    /*
     * Verify OUR own RECEIVE permission for this file's group.
     * P1 note: permission check structurally follows decryption because
     * saved_group_id is authenticated inside the GCM ciphertext and cannot
     * be verified until after the tag check passes.  Plaintext is zeroed
     * on failure, and the FI1 fix below hardens the branch.
     */
    SECURE_BOOL_CHECK(ok1, ok2, validate_permission(saved_group_id, PERM_RECEIVE));
    if (!(ok1 & ok2)) {
        secure_zero(&s_work.rcv, sizeof(s_work.rcv));
        secure_zero(saved_uuid,  UUID_SIZE);
        secure_zero(saved_name,  MAX_NAME_SIZE);
        print_error("Operation failed");
        return -1;
    }

    /*
     * Write plaintext to flash.
     * receive()'s stack frame here: saved_uuid(16) + saved_name(32) +
     * saved_contents_len(2) + saved_group_id(2) + saved_slot(1) + misc ≈ 100 B.
     * secure_write_file() pushes file_t (8277 B) — total ~8400 B, well within
     * the 15.8 KB stack budget.
     */
    ret = secure_write_file(command->write_slot,
                            saved_group_id,
                            saved_name,
                            s_work.rcv.ciphertext,   /* plaintext after in-place decrypt */
                            saved_contents_len,
                            saved_uuid);

    secure_zero(&s_work.rcv, sizeof(s_work.rcv));
    secure_zero(saved_uuid,  UUID_SIZE);
    secure_zero(saved_name,  MAX_NAME_SIZE);

    if (ret != 0) {
        print_error("Operation failed");
        return -1;
    }

    write_packet(CONTROL_INTERFACE, RECEIVE_MSG, NULL, 0);
    return 0;
}

/*
 * INTERROGATE — initiator side: authenticate, send R1, receive filtered list.
 */
int interrogate(uint16_t pkt_len, uint8_t *buf)
{
    interrogate_command_t *command = (interrogate_command_t *)buf;
    interrogate_r1_t       r1;
    interrogate_r2_t       r2;
    volatile bool          ok1, ok2;
    msg_type_t             cmd;
    uint16_t               r2_len;
    uint16_t               list_data_len;
    uint8_t                hmac_input[NONCE_SIZE + sizeof(list_response_t)];
    uint8_t                tweaked_chal[NONCE_SIZE];   /* SCA4 */

    if (pkt_len < sizeof(interrogate_command_t)) {
        print_error("Operation failed");
        return -1;
    }

    SECURE_PIN_CHECK(ok1, ok2, command->pin);
    secure_zero(command->pin, PIN_LENGTH);
    if (!(ok1 & ok2)) {
        delay_ms(4500);
        print_error("Operation failed");
        return -1;
    }

    /* ---- R1: send challenge + auth + permission proof ---- */
    memset(&r1, 0, sizeof(r1));
    if (generate_nonce(r1.challenge) != 0) {
        print_error("Operation failed");
        return -1;
    }

    /* SCA4: authenticate over tweaked challenge so responder CPA sees unknown input. */
    apply_tweak(r1.challenge, tweaked_chal);
    if (hmac_sha256(TRANSFER_AUTH_KEY, tweaked_chal, NONCE_SIZE,
                    HMAC_DOMAIN_INTERROGATE_REQ, r1.auth) != 0) {
        secure_zero(tweaked_chal, NONCE_SIZE);
        secure_zero(&r1, sizeof(r1));
        print_error("Operation failed");
        return -1;
    }
    secure_zero(tweaked_chal, NONCE_SIZE);

    r1.perm_count = PERM_COUNT;
    serialize_permissions(global_permissions, PERM_COUNT, r1.perms);
    memcpy(r1.perm_mac, PERMISSION_MAC, HMAC_SIZE);
    if (write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, &r1, sizeof(r1)) != MSG_OK) {
        secure_zero(&r1, sizeof(r1));
        print_error("Operation failed");
        return -1;
    }

    /* ---- R2: receive filtered list + verify resp_auth ---- */
    memset(&r2, 0, sizeof(r2));
    r2_len = sizeof(r2);
    cmd    = 0;
    if (read_packet(TRANSFER_INTERFACE, &cmd, &r2, &r2_len) != MSG_OK ||
        cmd != INTERROGATE_MSG || r2_len < HMAC_SIZE) {
        secure_zero(&r1, sizeof(r1));
        secure_zero(&r2, sizeof(r2));
        print_error("Operation failed");
        return -1;
    }

    list_data_len = r2_len - HMAC_SIZE;

    /* SCA4: build hmac_input with tweaked challenge prefix. */
    apply_tweak(r1.challenge, tweaked_chal);
    memcpy(hmac_input,              tweaked_chal, NONCE_SIZE);
    memcpy(hmac_input + NONCE_SIZE, &r2.list,     list_data_len);
    secure_zero(tweaked_chal, NONCE_SIZE);

    if (!hmac_verify(TRANSFER_AUTH_KEY,
                     hmac_input, (size_t)(NONCE_SIZE + list_data_len),
                     HMAC_DOMAIN_INTERROGATE_RSP, r2.resp_auth)) {
        secure_zero(hmac_input, sizeof(hmac_input));
        secure_zero(&r1, sizeof(r1));
        secure_zero(&r2, sizeof(r2));
        print_error("Operation failed");
        return -1;
    }

    secure_zero(hmac_input, sizeof(hmac_input));
    secure_zero(&r1, sizeof(r1));

    /*
     * A crafted n_files value larger than what list_data_len can hold would
     * cause the host-side parser to read past the actual data.  Enforce that
     * the serialized list size implied by n_files fits within list_data_len.
     *
     * Required: sizeof(uint32_t) + n_files * sizeof(file_metadata_t) <= list_data_len
     */
    if (list_data_len < sizeof(uint32_t)) {
        secure_zero(&r2, sizeof(r2));
        print_error("Operation failed");
        return -1;
    }
    {
        uint32_t n_files     = r2.list.n_files;
        uint32_t needed_len  = (uint32_t)sizeof(uint32_t)
                               + n_files * (uint32_t)sizeof(file_metadata_t);
        if (n_files > MAX_FILE_COUNT || needed_len > (uint32_t)list_data_len) {
            secure_zero(&r2, sizeof(r2));
            print_error("Operation failed");
            return -1;
        }
    }

    write_packet(CONTROL_INTERFACE, INTERROGATE_MSG, &r2.list, list_data_len);
    secure_zero(&r2, sizeof(r2));
    return 0;
}

/*
 * LISTEN — responder side for RECEIVE_MSG and INTERROGATE_MSG.
 *
 * No PIN check; LISTEN accepts exactly one command from TRANSFER_INTERFACE.
 *
 * STALE DRAIN: drain any bytes left in the UART1 FIFO from a prior aborted
 * exchange before blocking on the peer's R1.  uart_drain_rx() is non-blocking.
 *
 * RECEIVE_MSG stack peak:
 *   union u { file_t stored; receive_r4_t fdata } = 8277 B
 *   r2(44) + r3(105) + nonces/aads/misc ≈ 600 B
 *   Total ≈ 8.9 KB.  Plaintext lives in s_work.plain (static).
 *
 * INTERROGATE_MSG stack peak:
 *   file_header_t hdr(55) + ir2(316) + resp_list(284) + hmac_input(296) ≈ 1 KB.
 *
 */
int listen(uint16_t pkt_len, uint8_t *buf)
{
    uint8_t    first_buf[sizeof(interrogate_r1_t)]; /* 117 B — largest R1 */
    uint16_t   first_len = sizeof(first_buf);
    msg_type_t cmd       = 0;

    (void)pkt_len;
    (void)buf;

    /* Ack the host immediately so the test framework can fire the peer command. */
    write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);

    (void)uart_drain_rx(TRANSFER_INTERFACE, MAX_SYNC_DISCARD);

    memset(first_buf, 0, sizeof(first_buf));
    if (read_packet(TRANSFER_INTERFACE, &cmd, first_buf, &first_len) != MSG_OK) {
        return -1;
    }

    /* ================================================================== */
    /* RECEIVE_MSG — sender (responder) side                               */
    /* ================================================================== */
    if (cmd == RECEIVE_MSG) {
        volatile bool ok1, ok2;

        /* Union: file_t and receive_r4_t share 8277 B of stack. */
        union {
            file_t       stored; /* 8277 B — used for STORAGE_KEY decrypt   */
            receive_r4_t fdata;  /* 8273 B — used for TRANSFER_KEY encrypt  */
        } u;

        receive_r1_t *r1 = (receive_r1_t *)first_buf;
        receive_r2_t  r2;
        receive_r3_t  r3;
        msg_type_t    r3_cmd;
        uint16_t      r3_len;
        uint8_t       recv_chal[NONCE_SIZE];
        uint8_t       send_chal[NONCE_SIZE];
        uint8_t       tweaked_chal[NONCE_SIZE];   /* SCA4 */
        uint8_t       storage_aad[STORAGE_AAD_SIZE];
        uint8_t       transfer_aad[TRANSFER_AAD_SIZE];
        size_t        aad_len;
        int           ret;

        /* Saved fields from R1 — needed after r1 (first_buf) is reused. */
        uint8_t  saved_uuid[UUID_SIZE];
        uint16_t saved_group_id;
        uint16_t saved_contents_len;
        char     saved_name[MAX_NAME_SIZE];
        uint8_t  slot_req;

        if (first_len != sizeof(receive_r1_t)) { return -1; }

        slot_req = r1->slot;
        if (!validate_slot(slot_req)) { return -1; }

        memcpy(recv_chal, r1->recv_chal, NONCE_SIZE);

        /* Read and decrypt stored file. */
        memset(&u.stored, 0, sizeof(u.stored));
        if (read_file(slot_req, &u.stored) != 0) {
            secure_zero(recv_chal, NONCE_SIZE);
            return -1;
        }
        if (u.stored.in_use != FILE_IN_USE) {
            secure_zero(recv_chal, NONCE_SIZE);
            secure_zero(&u.stored, sizeof(u.stored));
            return -1;
        }
        if (!validate_contents_len(u.stored.contents_len)) {
            secure_zero(recv_chal, NONCE_SIZE);
            secure_zero(&u.stored, sizeof(u.stored));
            return -1;
        }

        /* Save header fields before u.stored is overwritten by re-use. */
        saved_contents_len = u.stored.contents_len;
        saved_group_id     = u.stored.group_id;
        memcpy(saved_uuid, u.stored.uuid, UUID_SIZE);
        memcpy(saved_name, u.stored.name, MAX_NAME_SIZE);
        saved_name[MAX_NAME_SIZE - 1] = '\0';

        /* ---- R2: build sender auth + send challenge ---- */
        memset(&r2, 0, sizeof(r2));
        if (generate_nonce(r2.send_chal) != 0) {
            secure_zero(recv_chal, NONCE_SIZE);
            secure_zero(&u.stored, sizeof(u.stored));
            return -1;
        }
        memcpy(send_chal, r2.send_chal, NONCE_SIZE);

        /* SCA4: sender_auth over tweaked recv_chal. */
        apply_tweak(recv_chal, tweaked_chal);
        if (hmac_sha256(TRANSFER_AUTH_KEY, tweaked_chal, NONCE_SIZE,
                        HMAC_DOMAIN_SENDER, r2.sender_auth) != 0) {
            secure_zero(tweaked_chal, NONCE_SIZE);
            secure_zero(&u.stored, sizeof(u.stored));
            secure_zero(&r2, sizeof(r2));
            return -1;
        }
        secure_zero(tweaked_chal, NONCE_SIZE);

        /* Decrypt stored file into s_work.plain with STORAGE_KEY. */
        aad_len = build_storage_aad(slot_req, saved_uuid,
                                    saved_group_id, saved_name,
                                    storage_aad);
        memset(s_work.plain, 0, MAX_CONTENTS_SIZE);
        ret = aes_gcm_decrypt(STORAGE_KEY, u.stored.nonce,
                              storage_aad, aad_len,
                              u.stored.ciphertext, saved_contents_len,
                              u.stored.tag, s_work.plain);

        secure_zero(storage_aad, sizeof(storage_aad));
        secure_zero(&u.stored, sizeof(u.stored));

        if (ret != 0) {
            secure_zero(s_work.plain, MAX_CONTENTS_SIZE);
            secure_zero(&r2, sizeof(r2));
            return -1;
        }

        if (write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, &r2, sizeof(r2)) != MSG_OK) {
            secure_zero(s_work.plain, MAX_CONTENTS_SIZE);
            secure_zero(&r2, sizeof(r2));
            return -1;
        }
        secure_zero(&r2, sizeof(r2));

        /*
         * R2 delivered — receiver is now committed to waiting for R4.
         * Every error path from here MUST send ERROR_MSG on TRANSFER_INTERFACE
         * to prevent UART desync on the control side.
         */

        /* ---- R3: receive and verify receiver auth + permissions ---- */
        memset(&r3, 0, sizeof(r3));
        r3_len = sizeof(r3);
        r3_cmd = 0;
        if (read_packet(TRANSFER_INTERFACE, &r3_cmd, &r3, &r3_len) != MSG_OK ||
            r3_cmd != RECEIVE_MSG || r3_len != sizeof(r3)) {
            secure_zero(recv_chal, NONCE_SIZE);
            secure_zero(send_chal, NONCE_SIZE);
            secure_zero(&r3, sizeof(r3));
            secure_zero(s_work.plain, MAX_CONTENTS_SIZE);
            (void)write_packet(TRANSFER_INTERFACE, ERROR_MSG, NULL, 0);
            return -1;
        }

        /*
         * verify_perm_mac() (PERM_MAC_KEY).  An unauthenticated sender who
         * reaches verify_perm_mac() with arbitrary perms[] can mount a
         * chosen-input CPA on PERM_MAC_KEY without needing TRANSFER_AUTH_KEY.
         * After this reorder, PERM_MAC_KEY is only exercised once the sender
         * has proven knowledge of TRANSFER_AUTH_KEY.
         */

        /* SCA4: verify recv_auth over tweaked send_chal. */
        apply_tweak(send_chal, tweaked_chal);
        if (!hmac_verify(TRANSFER_AUTH_KEY, tweaked_chal, NONCE_SIZE,
                         HMAC_DOMAIN_RECEIVER, r3.recv_auth)) {
            secure_zero(tweaked_chal, NONCE_SIZE);
            secure_zero(recv_chal, NONCE_SIZE);
            secure_zero(send_chal, NONCE_SIZE);
            secure_zero(&r3, sizeof(r3));
            secure_zero(s_work.plain, MAX_CONTENTS_SIZE);
            (void)write_packet(TRANSFER_INTERFACE, ERROR_MSG, NULL, 0);
            return -1;
        }
        secure_zero(tweaked_chal, NONCE_SIZE);

        /* Validate perm format and PERMISSION_MAC — only after auth passes. */
        if (!validate_perm_count(r3.perm_count) ||
            !validate_perm_bytes(r3.perms, r3.perm_count) ||
            !verify_perm_mac(r3.perm_count, r3.perms, r3.perm_mac)) {
            secure_zero(recv_chal, NONCE_SIZE);
            secure_zero(send_chal, NONCE_SIZE);
            secure_zero(&r3, sizeof(r3));
            secure_zero(s_work.plain, MAX_CONTENTS_SIZE);
            (void)write_packet(TRANSFER_INTERFACE, ERROR_MSG, NULL, 0);
            return -1;
        }

        /*
         * Previously a single voltage glitch at the predictable window
         * immediately after R3 arrives could skip this branch entirely,
         * allowing an unauthorized receiver to obtain the file.
         */
        SECURE_BOOL_CHECK(ok1, ok2,
            perm_bytes_has_receive(r3.perms, r3.perm_count, saved_group_id));
        if (!(ok1 & ok2)) {
            secure_zero(recv_chal, NONCE_SIZE);
            secure_zero(send_chal, NONCE_SIZE);
            secure_zero(&r3, sizeof(r3));
            secure_zero(s_work.plain, MAX_CONTENTS_SIZE);
            (void)write_packet(TRANSFER_INTERFACE, ERROR_MSG, NULL, 0);
            return -1;
        }
        secure_zero(&r3, sizeof(r3));

        /* ---- R4: build and send encrypted file ---- */
        memset(&u.fdata, 0, sizeof(u.fdata));
        if (generate_nonce(u.fdata.nonce) != 0) {
            secure_zero(recv_chal, NONCE_SIZE);
            secure_zero(send_chal, NONCE_SIZE);
            secure_zero(s_work.plain, MAX_CONTENTS_SIZE);
            (void)write_packet(TRANSFER_INTERFACE, ERROR_MSG, NULL, 0);
            return -1;
        }

        u.fdata.contents_len = saved_contents_len;
        u.fdata.slot         = slot_req;
        u.fdata.group_id     = saved_group_id;
        memcpy(u.fdata.uuid, saved_uuid, UUID_SIZE);
        memcpy(u.fdata.name, saved_name, MAX_NAME_SIZE);
        u.fdata.name[MAX_NAME_SIZE - 1] = '\0';

        aad_len = build_transfer_aad(recv_chal, send_chal,
                                     slot_req, saved_uuid,
                                     saved_group_id, saved_name,
                                     transfer_aad);
        secure_zero(recv_chal, NONCE_SIZE);
        secure_zero(send_chal, NONCE_SIZE);

        ret = aes_gcm_encrypt(TRANSFER_KEY, u.fdata.nonce,
                              transfer_aad, aad_len,
                              s_work.plain, saved_contents_len,
                              u.fdata.ciphertext, u.fdata.tag);

        secure_zero(transfer_aad, sizeof(transfer_aad));
        secure_zero(s_work.plain, MAX_CONTENTS_SIZE);

        if (ret != 0) {
            secure_zero(&u.fdata, sizeof(u.fdata));
            (void)write_packet(TRANSFER_INTERFACE, ERROR_MSG, NULL, 0);
            return -1;
        }

        if (write_packet(TRANSFER_INTERFACE, RECEIVE_MSG,
                         &u.fdata,
                         (uint16_t)(FILE_DATA_HEADER_SIZE + saved_contents_len)) != MSG_OK) {
            secure_zero(&u.fdata, sizeof(u.fdata));
            return -1;
        }

        secure_zero(&u.fdata, sizeof(u.fdata));
        return 0;
    } /* end RECEIVE_MSG */

    /* ================================================================== */
    /* INTERROGATE_MSG — responder side                                    */
    /* ================================================================== */
    if (cmd == INTERROGATE_MSG) {
        interrogate_r1_t  *ir1 = (interrogate_r1_t *)first_buf;
        interrogate_r2_t   ir2;
        file_header_t      hdr;
        list_response_t    resp_list;
        uint8_t            hmac_input[NONCE_SIZE + sizeof(list_response_t)];
        uint8_t            tweaked_chal[NONCE_SIZE];   /* SCA4 */
        uint8_t            slot;
        uint16_t           send_len;

        if (first_len != sizeof(interrogate_r1_t)) { return -1; }

        /*
         * Validate requester TRANSFER_AUTH_KEY first, then PERMISSION_MAC.
         * Same ordering rationale as RECEIVE_MSG R3 fix (FIX P1).
         */

        /* SCA4: verify interrogate_req auth over tweaked challenge. */
        apply_tweak(ir1->challenge, tweaked_chal);
        if (!hmac_verify(TRANSFER_AUTH_KEY, tweaked_chal, NONCE_SIZE,
                         HMAC_DOMAIN_INTERROGATE_REQ, ir1->auth)) {
            secure_zero(tweaked_chal, NONCE_SIZE);
            return -1;
        }
        secure_zero(tweaked_chal, NONCE_SIZE);

        /* Validate perm format and PERMISSION_MAC — only after auth passes. */
        if (!validate_perm_count(ir1->perm_count) ||
            !validate_perm_bytes(ir1->perms, ir1->perm_count) ||
            !verify_perm_mac(ir1->perm_count, ir1->perms, ir1->perm_mac)) {
            return -1;
        }

        /*
         * Build filtered file list.
         * Uses file_header_t hdr (55 B) per slot, NOT file_t (8277 B).
         */
        memset(&resp_list, 0, sizeof(resp_list));
        for (slot = 0U; slot < MAX_FILE_COUNT; slot++) {
            if (read_file_header(slot, &hdr) != 0) { continue; }
            /* Include slot only if requester has RECEIVE for this group. */
            if (!perm_bytes_has_receive(ir1->perms, ir1->perm_count, hdr.group_id)) {
                continue;
            }
            uint32_t idx                     = resp_list.n_files;
            resp_list.metadata[idx].slot     = slot;
            resp_list.metadata[idx].group_id = hdr.group_id;
            memcpy(resp_list.metadata[idx].name, hdr.name, MAX_NAME_SIZE);
            resp_list.metadata[idx].name[MAX_NAME_SIZE - 1] = '\0';
            resp_list.n_files = idx + 1;
        }

        /* Build and send R2: resp_auth || list.
         * SCA4: resp_auth is over tweaked challenge prefix || list body. */
        send_len = (uint16_t)LIST_PKT_LEN(resp_list.n_files);

        apply_tweak(ir1->challenge, tweaked_chal);
        memcpy(hmac_input,              tweaked_chal, NONCE_SIZE);
        memcpy(hmac_input + NONCE_SIZE, &resp_list,   send_len);
        secure_zero(tweaked_chal, NONCE_SIZE);

        memset(&ir2, 0, sizeof(ir2));
        if (hmac_sha256(TRANSFER_AUTH_KEY,
                        hmac_input, (size_t)(NONCE_SIZE + send_len),
                        HMAC_DOMAIN_INTERROGATE_RSP, ir2.resp_auth) != 0) {
            secure_zero(hmac_input, sizeof(hmac_input));
            return -1;
        }
        secure_zero(hmac_input, sizeof(hmac_input));

        memcpy(&ir2.list, &resp_list, send_len);

        if (write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG,
                         &ir2, (uint16_t)(HMAC_SIZE + send_len)) != MSG_OK) {
            secure_zero(&ir2, sizeof(ir2));
            return -1;
        }
        secure_zero(&ir2, sizeof(ir2));
        return 0;
    } /* end INTERROGATE_MSG */

    /* Unknown opcode on TRANSFER_INTERFACE — ignore silently. */
    return -1;
}
