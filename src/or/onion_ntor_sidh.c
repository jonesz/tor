/* Copyright (c) 2012-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/* Modified to include SIDH, 2018, Ethan Jones. */

/* onion_ntor_sidh.c
 *
 * An implementation of a hybrid ntor + sidh handshake. This is effectively
 * a modified x25519 ntor handshake and an ephemeral SIDH handshake 
 * occurring simultaneously. The produced shared secrets are concatenated 
 * and then fed into a KDF.
 *
 * For a design analysis/reasoning, see qc-resistant-handshakes.txt in /.
 *
 * NOTE: We've essentially just dropped a SIDH handshake into the existing
 * ntor spec to introduce some quantum-hard bits. We've also changed
 * the KDF/hashes to a ShakeXOF construction, a la prop270. Tinkered with
 * inputs for the SECRET_INPUT, AUTH_INPUT.
 *
 * You should probably be using the SIKE scheme, which uses an existing,
 * security-proven construction by Schanck, Whyte, and Zhang.
 *
 * This code reflects much of the original onion_ntor.c codebase. */

#include "orconfig.h"

#define ONION_NTOR_SIDH_PRIVATE
#include "crypto.h"
#include "crypto_isogeny.h"
#include "onion_ntor_sidh.h"
#include "torlog.h"
#include "util.h"

/* String constants used by ntor_sidh. */
#define PROTOID "ntor-sidh-shake256-1"
#define PROTOID_LEN (sizeof(PROTOID) - 1)
#define SERVER_STR "Server"
#define SERVER_STR_LEN (sizeof(SERVER_STR) - 1)

/* Tweaks specific to this protocol. */
#define TWEAK_VERIFY (PROTOID ":verify")
#define TWEAK_VERIFY_LEN (sizeof(TWEAK_VERIFY) -1)
#define TWEAK_MAC (PROTOID ":mac")
#define TWEAK_MAC_LEN (sizeof(TWEAK_MAC) -1)
#define TWEAK_EXPAND (PROTOID ":expand")
#define TWEAK_EXPAND_LEN (sizeof(TWEAK_EXPAND) -1)

/* The published router identity keys have been removed from the secret input;
 * there's already a good amount of suitable material from handshake/ephemeral
 * key generation. XXX: But, what do I know. */
#define SECRET_INPUT_LEN (CURVE25519_OUTPUT_LEN * 2 \
    + SIDH_OUTPUT_LEN + PROTOID_LEN \
    + CURVE25519_PUBKEY_LEN * 2 + SIDH_PUBKEY_LEN * 2)
#define AUTH_INPUT_LEN (DIGEST256_LEN + DIGEST_LEN \
    + CURVE25519_PUBKEY_LEN*3 + SIDH_PUBKEY_LEN * 2 \
    + PROTOID_LEN + SERVER_STR_LEN)

/* Free a handshake state securely. */
void
ntor_sidh_handshake_state_free(ntor_sidh_handshake_state_t *state)
{
  if (!state)
    return;
  memwipe(state, 0, sizeof(*state));
  tor_free(state);
}

/** Convenience macro: copy <b>len</b> bytes from <b>inp</b> to <b>ptr</b>,
 * and advance <b>ptr</b> by the number of bytes copied. */
#define APPEND(ptr, inp, len)                   \
  STMT_BEGIN {                                  \
    memcpy(ptr, (inp), (len));                  \
    ptr += len;                                 \
  } STMT_END

/* Out with the old hmac, in with the new shake256 xof construction. */
static void
h_tweak(uint8_t *out, size_t out_len, const uint8_t *input, 
        size_t input_len, const uint8_t *tag, size_t tag_len)
{
  uint8_t *bits, *b;
  bits = tor_malloc_zero(sizeof(uint8_t) * (input_len + tag_len));
  b = bits;

  APPEND(b, input, input_len);
  APPEND(b, tag, tag_len);

  crypto_xof_t *xof = crypto_xof_new();
  crypto_xof_add_bytes(xof, bits, input_len + tag_len);
  crypto_xof_squeeze_bytes(xof, out, out_len);
  crypto_xof_free(xof);
  memwipe(bits, 0, input_len + tag_len);
  tor_free(bits);
}

/* Client-Side handshake initiation.
 * Communicates with a server whose DIGEST_LEN-byte server identity is
 * router_id. Computes two ephemeral keypairs: x25519, SIDH.
 * Sends over router_id, router.pub, x25519.pub, and SIDH.pub
 * in handshake_state_out. */
int
onion_skin_ntor_sidh_create(const uint8_t *router_id,
    const curve25519_public_key_t *router_key,
    ntor_sidh_handshake_state_t **handshake_state_out,
    uint8_t *onion_skin_out)
{

  ntor_sidh_handshake_state_t *state;
  uint8_t *op;

  state = tor_malloc_zero(sizeof(ntor_sidh_handshake_state_t));

  memcpy(state->router_id, router_id, DIGEST_LEN);
  memcpy(&state->pubkey_B, router_key, sizeof(curve25519_public_key_t));
  if (curve25519_secret_key_generate(&state->seckey_x, 0) < 0) {
    /* LCOV_EXCL_START
     * Secret key generation should be unable to fail when the key isn't
     * marked as "extra-strong" */
    tor_assert_nonfatal_unreached();
    tor_free(state);
    return -1;
    /* LCOV_EXCL_STOP */
  }

  curve25519_public_key_generate(&state->pubkey_X, &state->seckey_x);

  /* Ephemeral SIDH key generation, alice's subgroup. 
   * NOTE: there's an attack on reused keys in SIDH. */
  sidh_a_secret_key_generate(&state->sidh_seckey);
  sidh_a_public_key_generate(&state->sidh_pubkey, &state->sidh_seckey);

  op = onion_skin_out;
  APPEND(op, router_id, DIGEST_LEN);
  APPEND(op, router_key->public_key, CURVE25519_PUBKEY_LEN);
  APPEND(op, state->pubkey_X.public_key, CURVE25519_PUBKEY_LEN);
  APPEND(op, state->sidh_pubkey.public_key, SIDH_PUBKEY_LEN);
  tor_assert(op == onion_skin_out + NTOR_SIDH_ONIONSKIN_LEN);

  *handshake_state_out = state;

  return 0;
}

/* Server response to a client's handshake creation. We build both the
 * response and extract the key of a specified length into key_out.
 *
 * Get our long-term key, generate ephemeral x25519 and SIDH keypairs.
 * Compute the ephemeral x25519 handshake, the long-term handshake, and
 * the SIDH handshake. Compute secret_input hash, auth_input hash.
 * Build the reply and then generate the needed key_material into key_out. */
int
onion_skin_ntor_sidh_server_handshake(const uint8_t *onion_skin,
                                 const di_digest256_map_t *private_keys,
                                 const curve25519_keypair_t *junk_keys,
                                 const uint8_t *my_node_id,
                                 uint8_t *handshake_reply_out,
                                 uint8_t *key_out,
                                 size_t key_out_len)
{
  /* Wipe this later. */
  struct {
    uint8_t secret_input[SECRET_INPUT_LEN];
    uint8_t auth_input[AUTH_INPUT_LEN];
    uint8_t verify[DIGEST256_LEN];

    curve25519_public_key_t pubkey_X;
    curve25519_secret_key_t seckey_y;
    curve25519_public_key_t pubkey_Y;

    sidh_public_a_key_t sidh_alice_pub;
    sidh_secret_b_key_t sidh_bob_sec;
    sidh_public_b_key_t sidh_bob_pub;
  } s;

  uint8_t *si = s.secret_input, *ai = s.auth_input;
  const curve25519_keypair_t *keypair_bB;
  int bad;

  /* Decode the onion skin */
  /* XXX: Does this possible early-return business threaten our security? */
  if (tor_memneq(onion_skin, my_node_id, DIGEST_LEN))
    return -1;

  /* Note that on key-not-found, we go through with this operation anyway,
   * using "junk_keys". This will result in failed authentication, but won't
   * leak whether we recognized the key. */
  keypair_bB = dimap_search(private_keys, onion_skin + DIGEST_LEN,
                            (void*)junk_keys);
  if (!keypair_bB)
    return -1;

  /* Copy over x25519 pub, then SIDH pub from the client. */
  memcpy(s.pubkey_X.public_key, onion_skin+DIGEST_LEN+DIGEST256_LEN,
         CURVE25519_PUBKEY_LEN);
  memcpy(s.sidh_alice_pub.public_key, onion_skin+DIGEST_LEN+DIGEST256_LEN
      +CURVE25519_PUBKEY_LEN, SIDH_PUBKEY_LEN);
  
  /* Ephemeral key generation:
   * NOTE: As above, there's an attack on reused SIDH keys. */
  curve25519_secret_key_generate(&s.seckey_y, 0);
  curve25519_public_key_generate(&s.pubkey_Y, &s.seckey_y);

  sidh_b_secret_key_generate(&s.sidh_bob_sec);
  sidh_b_public_key_generate(&s.sidh_bob_pub, &s.sidh_bob_sec);

  /* Compute the handshakes, adding them to the secret_input. */
  curve25519_handshake(si, &s.seckey_y, &s.pubkey_X);
  bad = safe_mem_is_zero(si, CURVE25519_OUTPUT_LEN);
  si += CURVE25519_OUTPUT_LEN;
  curve25519_handshake(si, &keypair_bB->seckey, &s.pubkey_X);
  bad |= safe_mem_is_zero(si, CURVE25519_OUTPUT_LEN);
  si += CURVE25519_OUTPUT_LEN;
  sidh_b_handshake(&s.sidh_bob_sec, &s.sidh_alice_pub, si);
  bad |= safe_mem_is_zero(si, SIDH_OUTPUT_LEN);
  si += SIDH_OUTPUT_LEN;

  /* Onto PROTOID, 2x x25519 pubs keys, 2x sidh pubs. */
  APPEND(si, PROTOID, PROTOID_LEN);
  APPEND(si, s.pubkey_X.public_key, CURVE25519_PUBKEY_LEN);
  APPEND(si, s.pubkey_Y.public_key, CURVE25519_PUBKEY_LEN);
  APPEND(si, s.sidh_alice_pub.public_key, SIDH_PUBKEY_LEN);
  APPEND(si, s.sidh_bob_pub.public_key, SIDH_PUBKEY_LEN);
  tor_assert(si == s.secret_input + sizeof(s.secret_input));

  /* Compute verify */
  h_tweak(s.verify, DIGEST256_LEN, s.secret_input, sizeof(s.secret_input),
      (const uint8_t*)TWEAK_VERIFY, TWEAK_VERIFY_LEN);
  
  /* Compute auth_input */
  APPEND(ai, s.verify, DIGEST256_LEN);
  APPEND(ai, my_node_id, DIGEST_LEN);
  APPEND(ai, keypair_bB->pubkey.public_key, CURVE25519_PUBKEY_LEN);
  APPEND(ai, s.pubkey_X.public_key, CURVE25519_PUBKEY_LEN);
  APPEND(ai, s.pubkey_Y.public_key, CURVE25519_PUBKEY_LEN);
  APPEND(ai, s.sidh_alice_pub.public_key, SIDH_PUBKEY_LEN);
  APPEND(ai, s.sidh_bob_pub.public_key, SIDH_PUBKEY_LEN);
  APPEND(ai, PROTOID, PROTOID_LEN);
  APPEND(ai, SERVER_STR, SERVER_STR_LEN);
  tor_assert(ai == s.auth_input + sizeof(s.auth_input));

  /* Build the reply. */
  memcpy(handshake_reply_out, s.pubkey_Y.public_key, CURVE25519_PUBKEY_LEN);
  memcpy(handshake_reply_out+CURVE25519_PUBKEY_LEN, s.sidh_bob_pub.public_key, 
    SIDH_PUBKEY_LEN);
  h_tweak(handshake_reply_out+CURVE25519_PUBKEY_LEN+SIDH_PUBKEY_LEN,
          DIGEST256_LEN, s.auth_input, sizeof(s.auth_input),
          (const uint8_t*)TWEAK_MAC, TWEAK_MAC_LEN);

  /* Generate key material. */
  h_tweak(key_out, key_out_len, s.secret_input, sizeof(s.secret_input),
      (const uint8_t*)TWEAK_EXPAND, TWEAK_EXPAND_LEN);
  memwipe(&s, 0, sizeof(s));
  
  return bad ? -1 : 0;
}

/* Client-side final handshake, reading from handshake_reply.
 * Compute the same handshakes as the above (in the same order!), concat'ing
 * them into the secret input, compute verify, compute auth, and compare it
 * to the sent over auth_candidate. If they match, build the key material. */
int
onion_skin_ntor_sidh_client_handshake(
                             const ntor_sidh_handshake_state_t *handshake_state,
                             const uint8_t *handshake_reply,
                             uint8_t *key_out,
                             size_t key_out_len,
                             const char **msg_out)
{
  /* Wipe this later. */
  struct {
    uint8_t secret_input[SECRET_INPUT_LEN];
    uint8_t verify[DIGEST256_LEN];
    uint8_t auth_input[AUTH_INPUT_LEN];
    uint8_t auth[DIGEST256_LEN];

    curve25519_public_key_t pubkey_Y;
    sidh_public_b_key_t sidh_bob_pub;
  } s;

  uint8_t *ai = s.auth_input, *si = s.secret_input;
  const uint8_t *auth_candidate;
  int bad;
  
  /* Decode input. */
  memcpy(s.pubkey_Y.public_key, handshake_reply, CURVE25519_PUBKEY_LEN);
  memcpy(s.sidh_bob_pub.public_key, handshake_reply + CURVE25519_PUBKEY_LEN, SIDH_PUBKEY_LEN);
  auth_candidate = handshake_reply + CURVE25519_PUBKEY_LEN + SIDH_PUBKEY_LEN;

  /* Compute the handshakes into secret_input. */
  curve25519_handshake(si, &handshake_state->seckey_x, &s.pubkey_Y);
  bad = safe_mem_is_zero(si, CURVE25519_OUTPUT_LEN);
  si += CURVE25519_OUTPUT_LEN;
  curve25519_handshake(si, &handshake_state->seckey_x, &handshake_state->pubkey_B);
  bad |= (safe_mem_is_zero(si, CURVE25519_OUTPUT_LEN) << 1);
  si += CURVE25519_OUTPUT_LEN;
  sidh_a_handshake(&handshake_state->sidh_seckey, &s.sidh_bob_pub, si);

  /* XXX: Include the result of this as a parameter in message out. */
  bad |= (safe_mem_is_zero(si, SIDH_OUTPUT_LEN));
  si += SIDH_OUTPUT_LEN;
  
  /* On to PROTOID, 2x x25519 pubs keys, 2x sidh pubs. */
  APPEND(si, PROTOID, PROTOID_LEN);
  APPEND(si, handshake_state->pubkey_X.public_key, CURVE25519_PUBKEY_LEN);
  APPEND(si, s.pubkey_Y.public_key, CURVE25519_PUBKEY_LEN);
  APPEND(si, handshake_state->sidh_pubkey.public_key, SIDH_PUBKEY_LEN);
  APPEND(si, s.sidh_bob_pub.public_key, SIDH_PUBKEY_LEN);
  tor_assert(si == s.secret_input + sizeof(s.secret_input));

  /* Compute verify. */
  h_tweak(s.verify, DIGEST256_LEN, s.secret_input, 
      sizeof(s.secret_input), (const uint8_t*)TWEAK_VERIFY, TWEAK_VERIFY_LEN);

  /* Compute auth_input. */
  APPEND(ai, s.verify, DIGEST256_LEN);
  APPEND(ai, handshake_state->router_id, DIGEST_LEN);
  APPEND(ai, handshake_state->pubkey_B.public_key, CURVE25519_PUBKEY_LEN);
  APPEND(ai, handshake_state->pubkey_X.public_key, CURVE25519_PUBKEY_LEN);
  APPEND(ai, s.pubkey_Y.public_key, CURVE25519_PUBKEY_LEN);
  APPEND(ai, handshake_state->sidh_pubkey.public_key, SIDH_PUBKEY_LEN);
  APPEND(ai, s.sidh_bob_pub.public_key, SIDH_PUBKEY_LEN);
  APPEND(ai, PROTOID, PROTOID_LEN);
  APPEND(ai, SERVER_STR, SERVER_STR_LEN);
  tor_assert(ai == s.auth_input + sizeof(s.auth_input));

  /* Compute auth. */
  h_tweak(s.auth, DIGEST256_LEN, s.auth_input, sizeof(s.auth_input), 
      (const uint8_t*)TWEAK_MAC, TWEAK_MAC_LEN);

  bad |= (tor_memneq(s.auth, auth_candidate, DIGEST256_LEN) << 2);

  h_tweak(key_out, key_out_len, s.secret_input, sizeof(s.secret_input),
      (const uint8_t*)TWEAK_EXPAND, TWEAK_EXPAND_LEN);

  memwipe(&s, 0, sizeof(s));

  /* XXX: Include SIDH memzero failures in message out. */
  if (bad) {
    if (bad & 4) {
      if (msg_out)
        *msg_out = NULL; /* Don't report this one; we probably just had the
                          * wrong onion key.*/
      log_fn(LOG_INFO, LD_PROTOCOL,
             "Invalid result from curve25519 handshake: %d", bad);
    }
    if (bad & 3) {
      if (msg_out)
        *msg_out = "Zero output from curve25519 handshake";
      log_fn(LOG_WARN, LD_PROTOCOL,
             "Invalid result from curve25519 handshake: %d", bad);
    }
  }

  return bad ? -1 : 0;
}
