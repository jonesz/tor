/* Wrapper code for an isogeny based crypto implementation,
 * in this case: sidh/sike.
 *
 * The implementation chosen is Microsoft's PQCrypto-SIKE:
 * https://github.com/Microsoft/PQCrypto-SIKE
 */

#include "crypto_isogeny.h"
#include "isogeny/api_tor.h"

void
sidh_a_secret_key_generate(sidh_secret_a_key_t *key_out)
{
  random_mod_order_A(key_out->secret_key);
}

void
sidh_b_secret_key_generate(sidh_secret_b_key_t *key_out)
{
  random_mod_order_B(key_out->secret_key);
}

void sidh_a_public_key_generate(sidh_public_a_key_t *key_out,
    const sidh_secret_a_key_t *in)
{
  EphemeralKeyGeneration_A(in->secret_key, key_out->public_key);
}

void sidh_b_public_key_generate(sidh_public_b_key_t *key_out,
    const sidh_secret_b_key_t *in)
{
  EphemeralKeyGeneration_B(in->secret_key, key_out->public_key);
}

void 
sidh_a_handshake(const sidh_secret_a_key_t *sec_A, const sidh_public_b_key_t *pub_B, unsigned char* shared_secret)
{
  EphemeralSecretAgreement_A(sec_A->secret_key, pub_B->public_key, shared_secret);
}

void 
sidh_b_handshake(const sidh_secret_b_key_t *sec_B, const sidh_public_a_key_t *pub_A, unsigned char* shared_secret)
{
  EphemeralSecretAgreement_B(sec_B->secret_key, pub_A->public_key, shared_secret);
}

// Include SIKE stuff!

int sike_keypair_generate(sike_secret_key_t *seckey, sike_public_key_t *pubkey)
{
  return crypto_kem_keypair(pubkey->public_key, seckey->secret_key);
}

int sike_kem_enc(unsigned char *ct, unsigned char *ss, const sike_public_key_t *pk)
{
  return crypto_kem_enc(ct, ss, pk->public_key);
}

int sike_kem_dec(const unsigned char *ct, unsigned char *ss, const sike_secret_key_t *sk)
{
  return crypto_kem_dec(ss, ct, sk->secret_key);
}
