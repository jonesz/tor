/* Copyright (c) 2012-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/* Modified to include SIKE, 2018, Ethan Jones. */

/* onion_ntor_sike.c
 *
 * An implementation of a hybrid ntor + sike handshake. This is effectively
 * a modified x25519 ntor handshake and a SIKE key exchange occurring
 * simultaneously. The produced shared secrets are concatenated and then
 * fed into a KDF.
 *
 * For a design analysis/reasoning, see qc-resistant-handshakes.txt in /.
 *
 * Also, look at https://eprint.iacr.org/2015/287.pdf; We've tried to 
 * implement that specific handshake protocol with SIKE as the KEM. 
 * Additionally: https://gitweb.torproject.org/torspec.git/tree/proposals/269-hybrid-handshake.txt */

#include "orconfig.h"

#define ONION_NTOR_SIKE_PRIVATE
#include "crypto_isogeny.h"
#include "crypto.h"
#include "torlog.h"
#include "util.h"
#include "onion_ntor_sike.h"

/* String constants used by ntor_sike. */
#define PROTOID "hybrid-x25519-sike-shake128-1"
#define PROTOID_LEN (sizeof(PROTOID) - 1)

/* Tweaks specific to this protocol. */
#define T_AUTH (PROTOID ":auth")
#define T_AUTH_LEN (sizeof(T_AUTH) - 1)
#define T_KEY (PROTOID ":key")
#define T_KEY_LEN (sizeof(T_KEY) - 1)

/* Free a handshake state securely. */
void
ntor_sike_handshake_state_free(ntor_sike_handshake_state_t *state)
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

/* Out with the old hmac, in with the new shake256 xof construction. 
 * The XOF memwipes when free'd.
 * XXX: nickm was talking about concatenation of hashes:
 * H(A | X) vs H(A | H(X)), is it correct to malloc then copy into;
 * can we just call add_bytes twice because of sponge properties? */
static void
h_tweak(crypto_xof_t *xof, uint8_t *out, size_t out_len, const uint8_t *input, 
        size_t input_len, const unsigned char *tag, size_t tag_len)

{
  uint8_t *bits, *b;
  bits = tor_malloc_zero(sizeof(uint8_t) * (input_len + tag_len));
  b = bits;

  APPEND(b, input, input_len);
  APPEND(b, tag, tag_len);

  xof = crypto_xof128_new();
  crypto_xof_add_bytes(xof, bits, input_len + tag_len);
  crypto_xof_squeeze_bytes(xof, out, out_len);
  crypto_xof_free(xof);
  memwipe(bits, 0, input_len + tag_len);
  tor_free(bits);
}

/* Initial onion_skin creation.
 * The client generates two ephemeral key pairs:
 *  x, X := x25519_keygen()
 *  a, A := sike_keygen()
 * The client then sends over router_id | router_key | X | A
 */
int
onion_skin_ntor_sike_create(const uint8_t *router_id,
                       const curve25519_public_key_t *router_key,
                       ntor_sike_handshake_state_t **handshake_state_out,
                       uint8_t *onion_skin_out)
{
  ntor_sike_handshake_state_t *state;
  uint8_t *op;

  state = tor_malloc_zero(sizeof(ntor_sike_handshake_state_t));

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
  sike_keypair_generate(&state->seckey_a, &state->pubkey_A);

  op = onion_skin_out;
  APPEND(op, router_id, DIGEST_LEN);
  APPEND(op, router_key->public_key, CURVE25519_PUBKEY_LEN);
  APPEND(op, state->pubkey_X.public_key, CURVE25519_PUBKEY_LEN);
  APPEND(op, state->pubkey_A.public_key, SIKE_PUBKEY_LEN);
  tor_assert(op == onion_skin_out + NTOR_SIKE_ONIONSKIN_LEN);

  *handshake_state_out = state;

  return 0;
}

/* Inputs to be hashed as defined in the SWZ protocol. */
#define SECRET_INPUT_LEN (DIGEST256_LEN + CURVE25519_OUTPUT_LEN \
    + SIKE_OUTPUT_LEN)
#define SALT_LEN (DIGEST_LEN + CURVE25519_PUBKEY_LEN * 2 \
    + SIKE_PUBKEY_LEN)
#define TRANSCRIPT_LEN (DIGEST_LEN + CURVE25519_PUBKEY_LEN * 3 \
    + SIKE_PUBKEY_LEN + SIKE_CIPHERTEXT_LEN + PROTOID_LEN)

/* Response from the initial client handshake initiation.
 * The client generates an ephemeral keypair.
 *  y, Y := x25519_keygen()
 *
 * The server computes the three secret shares:
 *  s0 := H(x25519_handshake(X, b))
 *  s1 := x25519_handshake(X, y)
 *  s2, C := sike_enc(A)
 *
 * Computes secret as s0 | s1 | s2; SALT as ID | bB | X | A.
 * Seed is computed as H(salt, secret). Verify is H(seed, T_AUTH). 
 * Transcript computed as ID | bB | X | A | Y | C | PROTOID
 * Auth is computed as H(verify, transcript).
 *
 * Server responds with Y | C | AUTH.
 */
int
onion_skin_ntor_sike_server_handshake(const uint8_t *onion_skin,
                                 const di_digest256_map_t *private_keys,
                                 const curve25519_keypair_t *junk_keys,
                                 const uint8_t *my_node_id,
                                 uint8_t *handshake_reply_out,
                                 uint8_t *key_out,
                                 size_t key_out_len)
{

  /* Anonymous struct for EZwipe. */
  struct {
    curve25519_public_key_t pubkey_X;

    curve25519_secret_key_t seckey_y;
    curve25519_public_key_t pubkey_Y;

    sike_public_key_t pubkey_A;

    uint8_t s0[CURVE25519_OUTPUT_LEN];
    uint8_t sike_ciphertext[SIKE_CIPHERTEXT_LEN];

    uint8_t secret[SECRET_INPUT_LEN];
    uint8_t salt[SALT_LEN];
    uint8_t transcript[TRANSCRIPT_LEN];

    uint8_t seed[DIGEST256_LEN];
    uint8_t verify[DIGEST256_LEN];
    uint8_t auth[DIGEST256_LEN];
    crypto_xof_t *xof;
  } s;

  //memwipe(&s, 0, sizeof(s));
  uint8_t *se = s.secret, *sa = s.salt, *tr = s.transcript;
  const curve25519_keypair_t *keypair_bB;
  int bad;

  /* Decode the onion skin
   * XXX: Does this possible early-return business threaten our security? */
  if (tor_memneq(onion_skin, my_node_id, DIGEST_LEN))
    return -1;

  /* Note that on key-not-found, we go through with this operation anyway,
   * using "junk_keys". This will result in failed authentication, but won't
   * leak whether we recognized the key. */
  keypair_bB = dimap_search(private_keys, onion_skin + DIGEST_LEN,
      (void*)junk_keys);
  if (!keypair_bB)
    return -1;

  memcpy(s.pubkey_X.public_key, onion_skin+DIGEST_LEN+DIGEST256_LEN,
      CURVE25519_PUBKEY_LEN);
  memcpy(s.pubkey_A.public_key, onion_skin+DIGEST_LEN+DIGEST256_LEN
      +CURVE25519_PUBKEY_LEN, SIKE_PUBKEY_LEN);

  /* Generate y, Y. */
  curve25519_secret_key_generate(&s.seckey_y, 0);
  curve25519_public_key_generate(&s.pubkey_Y, &s.seckey_y);

  /* Compute the three handshakes that build the secret:
   * H(DH(b, X)) | DH(y, X) | shared secret of KEM_ENC(A).*/
  curve25519_handshake(s.s0, &keypair_bB->seckey, &s.pubkey_X);
  bad = safe_mem_is_zero(s.s0, CURVE25519_OUTPUT_LEN);
  h_tweak(s.xof, se, DIGEST256_LEN, s.s0, CURVE25519_OUTPUT_LEN, NULL, 0);
  se += DIGEST256_LEN;
  curve25519_handshake(se, &s.seckey_y, &s.pubkey_X);
  bad |= safe_mem_is_zero(se, CURVE25519_OUTPUT_LEN);
  se += CURVE25519_OUTPUT_LEN;
  sike_kem_enc(s.sike_ciphertext, se, &s.pubkey_A);
  bad |= safe_mem_is_zero(s.sike_ciphertext, SIKE_CIPHERTEXT_LEN);
  bad |= safe_mem_is_zero(se, SIKE_OUTPUT_LEN);
  se += SIKE_OUTPUT_LEN;
  tor_assert(se == s.secret + sizeof(s.secret));
  
  /* Compute the salt: SALT = ID | bB | X | A. */
  APPEND(sa, my_node_id, DIGEST_LEN);
  APPEND(sa, keypair_bB->pubkey.public_key, CURVE25519_PUBKEY_LEN);
  APPEND(sa, s.pubkey_X.public_key, CURVE25519_PUBKEY_LEN);
  APPEND(sa, s.pubkey_A.public_key, SIKE_PUBKEY_LEN);
  tor_assert(sa == s.salt + sizeof(s.salt));

  /* Compute seed: H(salt | secret_input). */
  h_tweak(s.xof, s.seed, DIGEST256_LEN, s.salt, SALT_LEN, s.secret, SECRET_INPUT_LEN);

  /* Compute verify: H(seed | T_AUTH). */
  h_tweak(s.xof, s.verify, DIGEST256_LEN, s.seed, DIGEST256_LEN, (const uint8_t*)T_AUTH, T_AUTH_LEN); 

  /* Compute transcript: TRANSCRIPT = ID | bB | X | Y | A | C | PROTOID */
  APPEND(tr, my_node_id, DIGEST_LEN);
  APPEND(tr, keypair_bB->pubkey.public_key, CURVE25519_PUBKEY_LEN);
  APPEND(tr, s.pubkey_X.public_key, CURVE25519_PUBKEY_LEN);
  APPEND(tr, s.pubkey_Y.public_key, CURVE25519_PUBKEY_LEN);
  APPEND(tr, s.pubkey_A.public_key, SIKE_PUBKEY_LEN);
  APPEND(tr, s.sike_ciphertext, SIKE_CIPHERTEXT_LEN);
  APPEND(tr, PROTOID, PROTOID_LEN);
  tor_assert(tr == s.transcript + sizeof(s.transcript));

  /* Create AUTH: H(verify | transcript). */
  h_tweak(s.xof, s.auth, DIGEST256_LEN, s.verify, DIGEST256_LEN, s.transcript, TRANSCRIPT_LEN);

  /* Expand KEY: H(seed, T_KEY). */
  h_tweak(s.xof, key_out, key_out_len, s.seed, DIGEST256_LEN, (const uint8_t*)T_KEY, T_KEY_LEN);

  /* Build handshake_reply_out: Y | C | AUTH */
  APPEND(handshake_reply_out, s.pubkey_Y.public_key, CURVE25519_PUBKEY_LEN);
  APPEND(handshake_reply_out, s.sike_ciphertext, SIKE_CIPHERTEXT_LEN);
  APPEND(handshake_reply_out, s.auth, DIGEST256_LEN);
  
  memwipe(&s, 0, sizeof(s));

  return bad ? -1 : 0;
}

/* Client response to server handshake.
 *
 * The client computes s0, s1, s2:
 *  s0 := H(x25519_handshake(x, B))
 *  s1 := x25519_handshake(x, Y)
 *  s2, C := sike_dec(ct, a)
 *
 * Computes secret as s0 | s1 | s2; SALT as ID | bB | X | A.
 * Seed is computed as H(salt, secret). Verify is H(seed, T_AUTH).
 * Transcript computed as ID | bB | X | A | Y | C | PROTOID
 * Auth is computed as H(verify, transcript).
 *
 * Compare the computed auth and the auth_candidate, then expand the
 * key if all is right.
 */
int
onion_skin_ntor_sike_client_handshake(
                             const ntor_sike_handshake_state_t *handshake_state,
                             const uint8_t *handshake_reply,
                             uint8_t *key_out,
                             size_t key_out_len,
                             const char **msg_out)
{
  /* Wipe this later. */
  struct {
    uint8_t s0[CURVE25519_OUTPUT_LEN];
    uint8_t sike_ciphertext[SIKE_CIPHERTEXT_LEN];

    uint8_t secret[SECRET_INPUT_LEN];
    uint8_t salt[SALT_LEN];
    uint8_t transcript[TRANSCRIPT_LEN];

    uint8_t seed[DIGEST256_LEN];
    uint8_t verify[DIGEST256_LEN];
    uint8_t auth[DIGEST256_LEN];
    uint8_t auth_candidate[DIGEST256_LEN];

    curve25519_public_key_t pubkey_Y;
    crypto_xof_t *xof;
  } s;

  //memwipe(&s, 0, sizeof(s));
  uint8_t *se = s.secret, *sa = s.salt, *tr = s.transcript;
  int bad;

  memcpy(s.pubkey_Y.public_key, handshake_reply, CURVE25519_PUBKEY_LEN);
  memcpy(s.sike_ciphertext, handshake_reply + CURVE25519_PUBKEY_LEN, SIKE_CIPHERTEXT_LEN);
  memcpy(s.auth_candidate, handshake_reply + CURVE25519_PUBKEY_LEN + SIKE_CIPHERTEXT_LEN, DIGEST256_LEN);

  /* Compute the three handshakes that build the secret:
   * H(DH(b, X)) | DH(y, X) | shared secret of KEM_DEC(A).*/
  curve25519_handshake(s.s0, &handshake_state->seckey_x, &handshake_state->pubkey_B);
  bad = safe_mem_is_zero(s.s0, CURVE25519_OUTPUT_LEN);
  h_tweak(s.xof, se, DIGEST256_LEN, s.s0, CURVE25519_OUTPUT_LEN, NULL, 0);
  se += DIGEST256_LEN;
  curve25519_handshake(se, &handshake_state->seckey_x, &s.pubkey_Y);
  bad |= (safe_mem_is_zero(se, CURVE25519_OUTPUT_LEN) << 1) ;
  se += CURVE25519_OUTPUT_LEN;
  sike_kem_dec(s.sike_ciphertext, se, &handshake_state->seckey_a);
  bad |= safe_mem_is_zero(se, SIKE_OUTPUT_LEN);
  se += SIKE_OUTPUT_LEN;
  tor_assert(se == s.secret + sizeof(s.secret));

  /* Compute the salt:
   * SALT = ID | bB | X | A */
  APPEND(sa, &handshake_state->router_id, DIGEST_LEN);
  APPEND(sa, &handshake_state->pubkey_B.public_key, CURVE25519_PUBKEY_LEN);
  APPEND(sa, &handshake_state->pubkey_X.public_key, CURVE25519_PUBKEY_LEN);
  APPEND(sa, &handshake_state->pubkey_A.public_key, SIKE_PUBKEY_LEN);
  tor_assert(sa == s.salt + sizeof(s.salt));

  /* Compute seed: H(salt | secret_input). */
  h_tweak(s.xof, s.seed, DIGEST256_LEN, s.salt, SALT_LEN, s.secret, SECRET_INPUT_LEN);

  /* Compute verify: H(seed | T_AUTH). */
  h_tweak(s.xof, s.verify, DIGEST256_LEN, s.seed, DIGEST256_LEN, (const uint8_t*)T_AUTH, T_AUTH_LEN);

  /* Create TRANSCRIPT: ID | bB | X | Y | A | C | PROTOID */
  APPEND(tr, &handshake_state->router_id, DIGEST_LEN);
  APPEND(tr, &handshake_state->pubkey_B.public_key, CURVE25519_PUBKEY_LEN);
  APPEND(tr, &handshake_state->pubkey_X.public_key, CURVE25519_PUBKEY_LEN);
  APPEND(tr, s.pubkey_Y.public_key, CURVE25519_PUBKEY_LEN);
  APPEND(tr, &handshake_state->pubkey_A.public_key, SIKE_PUBKEY_LEN);
  APPEND(tr, s.sike_ciphertext, SIKE_CIPHERTEXT_LEN);
  APPEND(tr, PROTOID, PROTOID_LEN);
  tor_assert(tr == s.transcript + sizeof(s.transcript));

  /* Create AUTH: H(verify | transcript). */
  h_tweak(s.xof, s.auth, DIGEST256_LEN, s.verify, DIGEST256_LEN, s.transcript, TRANSCRIPT_LEN);
  bad |= (tor_memneq(s.auth, s.auth_candidate, DIGEST256_LEN) << 2);

  /* Expand KEY: H(seed, T_KEY). */
  h_tweak(s.xof, key_out, key_out_len, s.seed, DIGEST256_LEN, (const uint8_t*)T_KEY, T_KEY_LEN);

  memwipe(&s, 0, sizeof(s));

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
