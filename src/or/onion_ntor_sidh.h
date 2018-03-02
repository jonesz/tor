#ifndef TOR_ONION_NTOR_SIDH_H
#define TOR_ONION_NTOR_SIDH_H

#include "torint.h"
#include "crypto_curve25519.h"
#include "crypto_isogeny.h"
#include "di_ops.h"

/* State to hold data used in initial client communication and needed 
 * once the server responds. */
typedef struct ntor_sidh_handshake_state_t ntor_sidh_handshake_state_t;

/* ntor onionskin + SIDH pub length. */
#define NTOR_SIDH_ONIONSKIN_LEN 84 + 378  // 474
/* ntor reply + SIDH pub length. */
#define NTOR_SIDH_REPLY_LEN 64 + 378

void ntor_sidh_handshake_state_free(ntor_sidh_handshake_state_t *state);

int 
onion_skin_ntor_sidh_create(const uint8_t *router_id,
                                const curve25519_public_key_t *router_key,
                                ntor_sidh_handshake_state_t **handshake_state_out,
                                uint8_t *onion_skin_out);

int 
onion_skin_ntor_sidh_server_handshake(const uint8_t *onion_skin,
                                 const di_digest256_map_t *private_keys,
                                 const curve25519_keypair_t *junk_keys,
                                 const uint8_t *my_node_id,
                                 uint8_t *handshake_reply_out,
                                 uint8_t *key_out,
                                 size_t key_out_len);
int
onion_skin_ntor_sidh_client_handshake(const ntor_sidh_handshake_state_t *handshake_state,
                             const uint8_t *handshake_reply,
                             uint8_t *key_out,
                             size_t key_out_len,
                             const char **msg_out);

#ifdef ONION_NTOR_SIDH_PRIVATE

struct ntor_sidh_handshake_state_t {

  uint8_t router_id[DIGEST_LEN];
  curve25519_public_key_t pubkey_B;

  // ephemeral keys.
  curve25519_secret_key_t seckey_x;
  curve25519_public_key_t pubkey_X;

  /* ephemeral sidh keys; We only ever need this
   * struct on the client side, so only alice keys. */
  sidh_secret_a_key_t sidh_seckey;
  sidh_public_a_key_t sidh_pubkey;
};

#endif

#endif
