/* Copyright (c) 2012-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/* Modified test_ntor_cl.c for use in testing our isogeny-based cryptosystems.
 * There's no changes to authentication keys in our schemes, the difference is 
 * just the addition of quantum-hard bits. */

#include "orconfig.h"
#include <stdio.h>
#include <stdlib.h>

#define ONION_NTOR_SIDH_PRIVATE
#define ONION_NTOR_SIKE_PRIVATE
#include "or.h"
#include "util.h"
#include "compat.h"
#include "crypto.h"
#include "crypto_curve25519.h"
#include "onion_ntor_sidh.h"
#include "onion_ntor_sike.h"

#define N_ARGS(n) STMT_BEGIN {                                  \
    if (argc < (n)) {                                           \
      fprintf(stderr, "%s needs %d arguments.\n",argv[1],n);    \
      return 1;                                                 \
    }                                                           \
  } STMT_END

#define BASE16(idx, var, n) STMT_BEGIN {                                \
    const char *s = argv[(idx)];                                        \
    if (base16_decode((char*)var, n, s, strlen(s)) < (int)n ) {              \
      fprintf(stderr, "couldn't decode argument %d (%s)\n",idx,s);      \
      return 1;                                                         \
    }                                                                   \
  } STMT_END

#define INT(idx, var) STMT_BEGIN {                                      \
    var = atoi(argv[(idx)]);                                            \
    if (var <= 0) {                                                     \
      fprintf(stderr, "bad integer argument %d (%s)\n",idx,argv[(idx)]); \
    }                                                                   \
  } STMT_END

/* XXX: These functions contain duplicated stuff, but since it's testing code
 * I guess it's fine. One could pivot between sike and sidh in the same
 * function, but... */
static int
client1_sidh(int argc, char **argv)
{
  /* client1 nodeID B -> msg state */
  curve25519_public_key_t B;
  uint8_t node_id[DIGEST_LEN];
  ntor_sidh_handshake_state_t *state = NULL;
  uint8_t msg[NTOR_SIDH_ONIONSKIN_LEN];
  char buf[2048];

  N_ARGS(4);
  BASE16(2, node_id, DIGEST_LEN);
  BASE16(3, B.public_key, CURVE25519_PUBKEY_LEN);

  if (onion_skin_ntor_sidh_create(node_id, &B, &state, msg)<0) {
    fprintf(stderr, "handshake failed");
    return 2;
  }

  base16_encode(buf, sizeof(buf), (const char*)msg, sizeof(msg));
  printf("%s\n", buf);
  base16_encode(buf, sizeof(buf), (void*)state, sizeof(*state));
  printf("%s\n", buf);

  ntor_sidh_handshake_state_free(state);
  return 0;
}

static int
server1_sidh(int argc, char **argv)
{
  uint8_t msg_in[NTOR_SIDH_ONIONSKIN_LEN];
  curve25519_keypair_t kp;
  di_digest256_map_t *keymap=NULL;
  uint8_t node_id[DIGEST_LEN];
  int keybytes;

  uint8_t msg_out[NTOR_SIDH_REPLY_LEN];
  uint8_t *keys = NULL;
  char *hexkeys = NULL;
  int result = 0;

  char buf[2048];

  /* server1: b nodeID msg N -> msg keys */
  N_ARGS(6);
  BASE16(2, kp.seckey.secret_key, CURVE25519_SECKEY_LEN);
  BASE16(3, node_id, DIGEST_LEN);
  BASE16(4, msg_in, NTOR_SIDH_ONIONSKIN_LEN);
  INT(5, keybytes);

  curve25519_public_key_generate(&kp.pubkey, &kp.seckey);
  dimap_add_entry(&keymap, kp.pubkey.public_key, &kp);

  keys = tor_malloc(keybytes);
  hexkeys = tor_malloc(keybytes*2+1);
  if (onion_skin_ntor_sidh_server_handshake(
                                msg_in, keymap, NULL, node_id, msg_out, keys,
                                (size_t)keybytes)<0) {
    fprintf(stderr, "handshake failed");
    result = 2;
    goto done;
  }

  base16_encode(buf, sizeof(buf), (const char*)msg_out, sizeof(msg_out));
  printf("%s\n", buf);
  base16_encode(hexkeys, keybytes*2+1, (const char*)keys, keybytes);
  printf("%s\n", hexkeys);

 done:
  tor_free(keys);
  tor_free(hexkeys);
  dimap_free(keymap, NULL);
  return result;
}

static int
client2_sidh(int argc, char **argv)
{
  struct ntor_sidh_handshake_state_t state;
  uint8_t msg[NTOR_SIDH_REPLY_LEN];
  int keybytes;
  uint8_t *keys;
  char *hexkeys;
  int result = 0;

  N_ARGS(5);
  BASE16(2, (&state), sizeof(state));
  BASE16(3, msg, sizeof(msg));
  INT(4, keybytes);

  keys = tor_malloc(keybytes);
  hexkeys = tor_malloc(keybytes*2+1);
  if (onion_skin_ntor_sidh_client_handshake(&state, msg, keys, keybytes, NULL)<0) {
    fprintf(stderr, "handshake failed");
    result = 2;
    goto done;
  }

  base16_encode(hexkeys, keybytes*2+1, (const char*)keys, keybytes);
  printf("%s\n", hexkeys);

 done:
  tor_free(keys);
  tor_free(hexkeys);
  return result;
}


static int
client1_sike(int argc, char **argv)
{
  /* client1 nodeID B -> msg state */
  curve25519_public_key_t B;
  uint8_t node_id[DIGEST_LEN];
  ntor_sike_handshake_state_t *state = NULL;
  uint8_t msg[NTOR_SIKE_ONIONSKIN_LEN];

  char buf[2048];

  N_ARGS(4);
  BASE16(2, node_id, DIGEST_LEN);
  BASE16(3, B.public_key, CURVE25519_PUBKEY_LEN);

  if (onion_skin_ntor_sike_create(node_id, &B, &state, msg)<0) {
    fprintf(stderr, "handshake failed");
    return 2;
  }

  base16_encode(buf, sizeof(buf), (const char*)msg, sizeof(msg));
  printf("%s\n", buf);
  base16_encode(buf, sizeof(buf), (void*)state, sizeof(*state));
  printf("%s\n", buf);

  ntor_sike_handshake_state_free(state);
  return 0;
}

static int
server1_sike(int argc, char **argv)
{
  uint8_t msg_in[NTOR_SIKE_ONIONSKIN_LEN];
  curve25519_keypair_t kp;
  di_digest256_map_t *keymap=NULL;
  uint8_t node_id[DIGEST_LEN];
  int keybytes;

  uint8_t msg_out[NTOR_SIKE_REPLY_LEN];
  uint8_t *keys = NULL;
  char *hexkeys = NULL;
  int result = 0;

  char buf[2048];

  /* server1: b nodeID msg N -> msg keys */
  N_ARGS(6);
  BASE16(2, kp.seckey.secret_key, CURVE25519_SECKEY_LEN);
  BASE16(3, node_id, DIGEST_LEN);
  BASE16(4, msg_in, NTOR_SIKE_ONIONSKIN_LEN);
  INT(5, keybytes);

  curve25519_public_key_generate(&kp.pubkey, &kp.seckey);
  dimap_add_entry(&keymap, kp.pubkey.public_key, &kp);

  keys = tor_malloc(keybytes);
  hexkeys = tor_malloc(keybytes*2+1);
  if (onion_skin_ntor_sike_server_handshake(
                                msg_in, keymap, NULL, node_id, msg_out, keys,
                                (size_t)keybytes)<0) {
    fprintf(stderr, "handshake failed");
    result = 2;
    goto done;
  }

  base16_encode(buf, sizeof(buf), (const char*)msg_out, sizeof(msg_out));
  printf("%s\n", buf);
  base16_encode(hexkeys, keybytes*2+1, (const char*)keys, keybytes);
  printf("%s\n", hexkeys);

 done:
  tor_free(keys);
  tor_free(hexkeys);
  dimap_free(keymap, NULL);
  return result;
}

static int
client2_sike(int argc, char **argv)
{
  struct ntor_sike_handshake_state_t state;
  uint8_t msg[NTOR_SIKE_REPLY_LEN];
  int keybytes;
  uint8_t *keys;
  char *hexkeys;
  int result = 0;

  N_ARGS(5);
  BASE16(2, (&state), sizeof(state));
  BASE16(3, msg, sizeof(msg));
  INT(4, keybytes);

  keys = tor_malloc(keybytes);
  hexkeys = tor_malloc(keybytes*2+1);
  if (onion_skin_ntor_sike_client_handshake(&state, msg, keys, keybytes, NULL)<0) {
    fprintf(stderr, "handshake failed");
    result = 2;
    goto done;
  }

  base16_encode(hexkeys, keybytes*2+1, (const char*)keys, keybytes);
  printf("%s\n", hexkeys);

 done:
  tor_free(keys);
  tor_free(hexkeys);
  return result;
}

/* this runs both the SIDH and SIKE with non-passed, static values. */
static int
demo(void)
{
  // Router identitiy keys.
  curve25519_secret_key_t b;
  curve25519_public_key_t B;

  // Router Keypair.
  curve25519_keypair_t kp;

  // Generate published server keys. Non-ephemeral.
  curve25519_secret_key_generate(&b, 0);
  curve25519_public_key_generate(&B, &b);

  kp.seckey = b; kp.pubkey = B;
  di_digest256_map_t *keymap=NULL;
  dimap_add_entry(&keymap, kp.pubkey.public_key, &kp);

  uint8_t *server_key_out = NULL;
  uint8_t *client_key_out = NULL;
  char *hex_server_key = NULL;
  char *hex_client_key = NULL;

  int keybytes = 256/8;

  server_key_out = tor_malloc(keybytes);
  client_key_out = tor_malloc(keybytes);
  hex_server_key = tor_malloc(keybytes*2+1);
  hex_client_key = tor_malloc(keybytes*2+1);

  // Random node_id digest.
  uint8_t node_id[DIGEST_LEN];
  crypto_rand((char*)node_id, DIGEST_LEN);
  
  ntor_sidh_handshake_state_t *state_sidh = NULL;
  ntor_sike_handshake_state_t *state_sike = NULL;
  uint8_t msg_client_create_sidh[NTOR_SIDH_ONIONSKIN_LEN];
  uint8_t msg_server_response_sidh[NTOR_SIDH_REPLY_LEN];
  uint8_t msg_client_create_sike[NTOR_SIKE_ONIONSKIN_LEN];
  uint8_t msg_server_response_sike[NTOR_SIKE_REPLY_LEN];
  int result = 0;

  if (onion_skin_ntor_sidh_create(node_id, &B, &state_sidh, msg_client_create_sidh) < 0) {
    result = 1;
    goto done;
  }

  if (onion_skin_ntor_sidh_server_handshake(msg_client_create_sidh, keymap, NULL, node_id, msg_server_response_sidh, server_key_out, (size_t)keybytes) < 0) {
    result = 2;
    goto done;
  }

  if (onion_skin_ntor_sidh_client_handshake(state_sidh, msg_server_response_sidh, client_key_out, (size_t)keybytes, NULL) < 0) {
    result = 3;
    goto done;
  }

  if (memcmp(client_key_out, server_key_out, keybytes != 0) || 
      tor_mem_is_zero((const char*)client_key_out, keybytes) != 0 || 
      tor_mem_is_zero((const char*)server_key_out, keybytes) != 0) {
    result = 4;
    goto done;
  }

  fprintf(stdout, "SIDH succesful.\n");

  if (onion_skin_ntor_sike_create(node_id, &B, &state_sike, msg_client_create_sike) < 0) {
    result = 1;
    goto done;
  }

  if (onion_skin_ntor_sike_server_handshake(msg_client_create_sike, keymap, NULL, node_id, msg_server_response_sike, server_key_out, (size_t)keybytes) < 0) {
    result = 2;
    goto done;
  }

  if (onion_skin_ntor_sike_client_handshake(state_sike, msg_server_response_sike, client_key_out, (size_t)keybytes, NULL) < 0) {
    result = 3;
    goto done;
  }

  if (memcmp(client_key_out, server_key_out, keybytes != 0) || 
      tor_mem_is_zero((const char*)client_key_out, keybytes) != 0 || 
      tor_mem_is_zero((const char*)server_key_out, keybytes) != 0) {
    result = 4;
    goto done;
  }

  fprintf(stdout, "SIKE succesful.\n");


done:
  switch(result) {
    case 0:
      break;
    case 1:
      fprintf(stdout, "Initial handshake failed.\n");
      break;
    case 2:
      fprintf(stdout, "Server handshake failed.\n");
      break;
    case 3:
      fprintf(stdout, "Client response handshake failed.\n");
      break;
    case 4:
      fprintf(stdout, "keys are useless.\n");
      base16_encode(hex_server_key, keybytes*2+1, (const char*)server_key_out, keybytes);
      base16_encode(hex_client_key, keybytes*2+1, (const char*)client_key_out, keybytes);
      printf("%s\n", hex_server_key);
      printf("%s\n", hex_client_key);
      break;
    }

  tor_free(server_key_out);
  tor_free(client_key_out);
  tor_free(hex_server_key);
  tor_free(hex_client_key);
  dimap_free(keymap, NULL);
  return result;
}

int
main(int argc, char **argv)
{
  /*
    client1: nodeID B -> msg state
    server1: b nodeID msg N -> msg keys
    client2: state msg N -> keys
  */
  if (argc < 2) {
    fprintf(stderr, "I need arguments. Read source for more info.\n");
    return 1;
  }

  curve25519_init();
  if (!strcmp(argv[1], "client1_sidh")) {
    return client1_sidh(argc, argv);
  } else if (!strcmp(argv[1], "server1_sidh")) {
    return server1_sidh(argc, argv);
  } else if (!strcmp(argv[1], "client2_sidh")) {
    return client2_sidh(argc, argv);
  } else if (!strcmp(argv[1], "client1_sike")) {
    return client1_sike(argc, argv);
  } else if (!strcmp(argv[1], "server1_sike")) {
    return server1_sike(argc, argv);
  } else if (!strcmp(argv[1], "client2_sike")) {
    return client2_sike(argc, argv);
  } else if (!strcmp(argv[1], "demo")) {
    return demo();
  } else {
    fprintf(stderr, "What's a %s?\n", argv[1]);
    return 1;
  }
}
