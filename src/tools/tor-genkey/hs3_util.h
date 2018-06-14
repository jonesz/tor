#ifndef HS3_UTIL
#define HS3_UTIL

#include "crypto_ed25519.h"

#define HS_KEYBLIND_NONCE_PREFIX "key-blind"
#define HS_KEYBLIND_NONCE_PREFIX_LEN (sizeof(HS_KEYBLIND_NONCE_PREFIX) - 1)
#define HS_KEYBLIND_NONCE_LEN \
  (HS_KEYBLIND_NONCE_PREFIX_LEN + sizeof(uint64_t) + sizeof(uint64_t))
#define HS_TIME_PERIOD_LENGTH_DEFAULT 1440 /* 1440 minutes == one day */

void hs3_blind(ed25519_keypair_t *kp, const uint8_t *secret, size_t secret_len,
    uint64_t period_num, ed25519_keypair_t *blinded_kp_out);

#define HS_DESC_CERT_LIFETIME (54 * 60 * 60)
#define SIGNED_KEY_TYPE_ED25519 0x01
#define CERT_TYPE_SIGNING_HS_DESC   0x08

typedef struct {
  ed25519_public_key_t signed_key;
  ed25519_public_key_t signing_key;
  time_t valid_until;
  uint8_t *encoded;
  size_t encoded_len;
  uint8_t cert_type;
  unsigned signing_key_included : 1;
  unsigned sig_bad : 1;
  unsigned sig_ok : 1;
  unsigned cert_expired : 1;
  unsigned cert_valid : 1;
} tor_cert_t;

tor_cert_t* hs3_cert_create(ed25519_keypair_t *signing_key, ed25519_public_key_t *signed_key,
    time_t lifetime, time_t now);
void hs3_cert_free(tor_cert_t *hs3cert);

#endif // HS3_UTIL
