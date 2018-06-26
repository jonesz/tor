#include "hs3_util.h"
#include "ed25519_cert.h"

static tor_cert_t* hs3_cert_parse(const uint8_t *encoded, const size_t len);

/* Largely ripped out functions from hs_common, torcert to whatever
 * narrow case we need them for. Specifically, some of the existing functions
 * were calling out to the network for parameters, logging that was throwing
 * linking errors, etc. At this point I don't want to do that. ;) */

/* Ed25519 Basepoint value. Taken from section 5 of
 * https://tools.ietf.org/html/draft-josefsson-eddsa-ed25519-03 */
static const char *str_ed25519_basepoint =
  "(15112221349535400772501151409588531511"
  "454012693041857206046113283949847762202, "
  "463168356949264781694283940034751631413"
  "07993866256225615783033603165251855960)";

void
hs3_blind(ed25519_keypair_t *kp, const uint8_t *secret, size_t secret_len,
    uint64_t period_num, ed25519_keypair_t *blinded_kp_out)
{
  uint8_t param[DIGEST256_LEN];

  /* Taken from build_blinded_key_param in hs_common.c */
  size_t offset = 0;
  const char blind_str[] = "Derive temporary signing key";
  uint8_t nonce[HS_KEYBLIND_NONCE_LEN];
  crypto_digest_t *digest;

  /* Create the nonce N. The construction is as follow:
   *    N = "key-blind" || INT_8(period_num) || INT_8(period_length) */
  memcpy(nonce, HS_KEYBLIND_NONCE_PREFIX, HS_KEYBLIND_NONCE_PREFIX_LEN);
  offset += HS_KEYBLIND_NONCE_PREFIX_LEN;
  set_uint64(nonce + offset, tor_htonll(period_num));
  offset += sizeof(uint64_t);

  /* XXX: Modified: we're using the default period length here.
   * We should probably call out to the consensus or allow a passed
   * argument. */
  set_uint64(nonce + offset, tor_htonll(HS_TIME_PERIOD_LENGTH_DEFAULT));
  offset += sizeof(uint64_t);
  tor_assert(offset == HS_KEYBLIND_NONCE_LEN);

  /* Generate the parameter h and the construction is as follow:
   *    h = H(BLIND_STRING | pubkey | [secret] | ed25519-basepoint | N) */
  digest = crypto_digest256_new(DIGEST_SHA3_256);
  crypto_digest_add_bytes(digest, blind_str, sizeof(blind_str));
  crypto_digest_add_bytes(digest, (char *) kp, ED25519_PUBKEY_LEN);
  /* Optional secret. */
  if (secret) {
    crypto_digest_add_bytes(digest, (char *) secret, secret_len);
  }
  crypto_digest_add_bytes(digest, str_ed25519_basepoint,
                          strlen(str_ed25519_basepoint));
  crypto_digest_add_bytes(digest, (char *) nonce, sizeof(nonce));

  /* Extract digest and put it in the param. */
  crypto_digest_get_digest(digest, (char *) param, DIGEST256_LEN);
  crypto_digest_free(digest);

  memwipe(nonce, 0, sizeof(nonce));

  ed25519_keypair_blind(blinded_kp_out, kp, param);
  memwipe(param, 0, sizeof(param));
}

/* Calculate the current time period; makes no calls out
 * to the network. */
uint64_t 
hs3_calculate_time_period(time_t now)
{
  uint64_t time_period_num;

  uint64_t time_period_length = HS_TIME_PERIOD_LENGTH_DEFAULT;
  uint64_t minutes_since_epoch = now / 60;

  unsigned int time_period_rotation_offset = SHARED_RANDOM_N_ROUNDS *
    HS_DEFAULT_V3_AUTH_INTERVAL;
  time_period_rotation_offset /= 60;
  minutes_since_epoch -= time_period_rotation_offset;
  time_period_num = minutes_since_epoch / time_period_length;
  return time_period_num;
}

/* Parse a tor_cert_t. */
static tor_cert_t *
hs3_cert_parse(const uint8_t *encoded, const size_t len)
{
  tor_cert_t *cert = NULL;
  ed25519_cert_t *parsed = NULL;
  ssize_t got_len = ed25519_cert_parse(&parsed, encoded, len);
  if (got_len < 0 || (size_t) got_len != len) {
    fprintf(stderr, "Can't parse!\n");
    goto err;
  }

  cert = tor_malloc_zero(sizeof(tor_cert_t));
  cert->encoded = tor_memdup(encoded, len);
  cert->encoded_len = len;

  memcpy(cert->signed_key.pubkey, parsed->certified_key, 32);
  int64_t valid_until_64 = ((int64_t)parsed->exp_field) * 3000;

  cert->valid_until = (time_t) valid_until_64;
  cert->cert_type = parsed->cert_type;

  for (unsigned i = 0; i < ed25519_cert_getlen_ext(parsed); ++i) {
    ed25519_cert_extension_t *ext = ed25519_cert_get_ext(parsed, i);
    cert->signing_key_included = 1;
    memcpy(cert->signing_key.pubkey, ext->un_signing_key, 32);
  }

  goto done;

 err:
  cert = NULL;

 done:
  ed25519_cert_free(parsed);
  return cert;
}

/* Create a certificate. */
tor_cert_t*
hs3_cert_create(ed25519_keypair_t *signing_key, ed25519_public_key_t *signed_key,
    time_t lifetime, time_t now)
{
  tor_cert_t *hs3cert = NULL;

  ed25519_cert_t *cert = ed25519_cert_new();
  cert->cert_type = CERT_TYPE_SIGNING_HS_DESC;
  cert->exp_field = (uint32_t) CEIL_DIV(now + lifetime, 3600);
  cert->cert_key_type = SIGNED_KEY_TYPE_ED25519;
  memcpy(cert->certified_key, signed_key->pubkey, 32);

  /* We're always including the signed key. */
  ed25519_cert_extension_t *ext = ed25519_cert_extension_new();
  ext->ext_type = CERTEXT_SIGNED_WITH_KEY;
  memcpy(ext->un_signing_key, signing_key->pubkey.pubkey, 32);
  ed25519_cert_add_ext(cert, ext);
  ++cert->n_extensions;

  const ssize_t alloc_len = ed25519_cert_encoded_len(cert);
  tor_assert(alloc_len > 0);
  uint8_t *encoded = tor_malloc(alloc_len);
  const ssize_t real_len = ed25519_cert_encode(encoded, alloc_len, cert);
  if (real_len < 0) {
    goto err;
  }
  tor_assert(real_len == alloc_len);
  tor_assert(real_len > ED25519_SIG_LEN);
  uint8_t *sig = encoded + (real_len - ED25519_SIG_LEN);
  tor_assert(tor_mem_is_zero((char*)sig, ED25519_SIG_LEN));

  ed25519_signature_t signature;
  if (ed25519_sign(&signature, encoded, real_len-ED25519_SIG_LEN, signing_key) < 0) {
    goto err;
  }

  memcpy(sig, signature.sig, ED25519_SIG_LEN);
  hs3cert = hs3_cert_parse(encoded, real_len);
  if (!hs3cert) {
    goto err;
  }

  tor_free(encoded);
  goto done;

 err:
  hs3_cert_free(hs3cert);
  hs3cert = NULL;
 done:
  ed25519_cert_free(cert);
  tor_free(encoded);
  return hs3cert;
}

/* Free a certificate. */
void
hs3_cert_free(tor_cert_t *cert)
{
  if (!cert)
    return;
  if (cert->encoded)
    memwipe(cert->encoded, 0, cert->encoded_len);
  tor_free(cert->encoded);

  memwipe(cert, 0, sizeof(tor_cert_t));
  tor_free(cert);
}
