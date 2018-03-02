#ifndef TOR_CRYPTO_ISOGENY_H
#define TOR_CRYPTO_ISOGENY_H

/* Wrappers around an existing isogeny based cryptosystem for use in tor. 
 * At the time of writing, we're using the library provided by Microsoft:
 * https://github.com/Microsoft/PQCrypto-SIKE */

/* Ephemeral SIDH lengths, used in ntor_sidh. */
#define SIDH_PUBKEY_LEN 378
#define SIDH_SECKEY_LEN 32
#define SIDH_OUTPUT_LEN 126

/* SIKE lengths, used in ntor_sike. */
#define SIKE_PUBKEY_LEN 378
#define SIKE_SECKEY_LEN 434
#define SIKE_CIPHERTEXT_LEN 402
#define SIKE_OUTPUT_LEN 16 

typedef struct sidh_public_a_key_t {
  unsigned char public_key[SIDH_PUBKEY_LEN];
} sidh_public_a_key_t;

typedef struct sidh_public_b_key_t {
  unsigned char public_key[SIDH_PUBKEY_LEN];
} sidh_public_b_key_t;

/* Private key within the range [0, 2^250 -1]. */
typedef struct sidh_secret_a_key_t {
  unsigned char secret_key[SIDH_SECKEY_LEN];
} sidh_secret_a_key_t;

/* Private key within the range [0, 2^Floor(Log(2,3^159)) - 1]. */
typedef struct sidh_secret_b_key_t {
  unsigned char secret_key[SIDH_SECKEY_LEN];
} sidh_secret_b_key_t;

void sidh_a_secret_key_generate(sidh_secret_a_key_t *key_out);
void sidh_b_secret_key_generate(sidh_secret_b_key_t *key_out);

void sidh_a_public_key_generate(sidh_public_a_key_t *key_out,
    const sidh_secret_a_key_t *in);

void sidh_b_public_key_generate(sidh_public_b_key_t *key_out,
    const sidh_secret_b_key_t *in);

void sidh_a_handshake(const sidh_secret_a_key_t *sec_A, const sidh_public_b_key_t *pub_B, unsigned char* shared_secret);
void sidh_b_handshake(const sidh_secret_b_key_t *sec_B, const sidh_public_a_key_t *pub_A, unsigned char* shared_secret);

typedef struct sike_secret_key_t {
  unsigned char secret_key[SIKE_SECKEY_LEN];
} sike_secret_key_t;

typedef struct sike_public_key_t {
  unsigned char public_key[SIKE_PUBKEY_LEN];
} sike_public_key_t;

int sike_keypair_generate(sike_secret_key_t *seckey, sike_public_key_t *pubkey);
int sike_kem_enc(unsigned char *ct, unsigned char *ss, const sike_public_key_t *pk);
int sike_kem_dec(const unsigned char *ct, unsigned char *ss, const sike_secret_key_t *sk);

#endif
