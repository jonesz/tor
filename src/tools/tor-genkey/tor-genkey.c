/* tor-genkey.c
 * key generation utility for a hacked together offline key hidden service. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "crypto.h"
#include "crypto_ed25519.h"
#include "crypto_format.h"
#include "torlog.h"
#include "util.h"

#include "hs3_util.h"

/* potential options; is memset to zero at runtime. */
typedef struct {
  int show_help;
  int verbosity;

  /* v3 hidden service master keypair. */
  int hs3_gen_master_keypair;
  int hs3_existing_secret;
  char *hs3_existing_secret_fname;

  /* v3 hidden service offline key. */
  int hs3_gen_offline_keys;
  uint64_t curr_time_period;
  uint64_t time_period;
  unsigned long num_keys;
} options_s;

static int
parse_options(int argc, char **argv, options_s *s)
{
  for (int i = 0; i < argc; ++i) {
    if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
      s->show_help = 1;
      return 0;
    } if (!strcmp(argv[i], "--verbose") || !strcmp(argv[i], "-v")) {
      s->verbosity = 1;
    } else if (!strcmp(argv[i], "-g")) {
      if (i+1>=argc) {
        fprintf(stderr, "No argument to -g.\n");
        return -1;
      }
      if (!strcmp(argv[i+1], "hs3master")) {
        s->hs3_gen_master_keypair = 1;
        i++;
      } else if (!strcmp(argv[i+1], "hs3offline")) {
        s->hs3_gen_offline_keys = 1;
        i++;
      } else {
        fprintf(stderr, "Unrecognized argument to -g.\n");
        return -1;
      }
    } else if (!strcmp(argv[i], "-pt")) {
      if (i+1>=argc) {
        fprintf(stderr, "No argument to -pt.\n");
        return -1;
      }
      /* XXX: What happens if you screw this up? */
      s->time_period = tor_parse_uint64(argv[i+1], 10, 0, UINT64_MAX, NULL, NULL);
      i++;
    } else if (!strcmp(argv[i], "-ct")) {
      if (i+1>=argc) {
        fprintf(stderr, "No argument to -ct.\n");
        return -1;
      }
      /* XXX: What happens if you screw this up? */
      s->curr_time_period = tor_parse_uint64(argv[i+1], 10, 0, UINT64_MAX, NULL, NULL);
      i++;
    } else if (!strcmp(argv[i], "-l")) {
      if (i+1>=argc) {
        fprintf(stderr, "No argument to -l.\n");
        return -1;
      }
      s->hs3_existing_secret = 1;
      s->hs3_existing_secret_fname = argv[i+1];
      i++;
    } else if (!strcmp(argv[i], "-n")) {
      if (i+1>= argc) {
        fprintf(stderr, "No argument to -n.\n");
        return -1;
      }
      /* XX: What happens if you screw this up? */
      s->num_keys = tor_parse_ulong(argv[i+1], 10, 0, ULONG_MAX, NULL, NULL);
      i++;
    }
  }
  return 0;
}

static int
validate_options(options_s *s)
{
  /* Can we generate offline keys? */
  if (s->hs3_gen_offline_keys) {
    if (!s->hs3_gen_master_keypair && !s->hs3_existing_secret) {
      fprintf(stderr, "Can't generate offline keys without loading a secret "
          "or generating a new master keypair.\n");
      return -1;
    }
    if (!s->time_period) {
        /* XXX: We should allow the user to specify dates, not just
         * time periods. */
      fprintf(stderr, "Can't generate offline keys without having a valid "
          "time period.\n");
      return -1;
    }
    if (!s->curr_time_period) {
        /* XXX: We could grab the current time period from consensus. */
        fprintf(stderr, "Can't generate offline keys without knowing the current "
            "time period.\n");
        return -1;
    }
    if (s->curr_time_period >= s->time_period) {
      fprintf(stderr, "Can't only generate future keys.\n");
      return -1;
    }
  }
  if (s->hs3_gen_master_keypair && s->hs3_existing_secret) {
    fprintf(stderr, "Can't generate a new master keypair and load an existing secret.\n");
    return -1;
  }
  if (s->num_keys == 0) {
    fprintf(stderr, "Can't generate less than 1 offline key.\n");
    return -1;
  }
  return 0;
}

static void
show_help(void)
{
    fprintf(stderr, "tor-genkey: [-h|--help] [-v|--verbose] -g {hs3master, hs3offline}"
        " -l {existing_secret} -pt {projected time period} -ct {current time period}"
        " -n {num_keys}\n");
}

int
main(int argc, char **argv)
{
  int ret = 1;

  /* XXX: fix this. */
  init_logging(1);

  struct {
    ed25519_keypair_t master;
    ed25519_keypair_t descriptor;
    ed25519_keypair_t blinded;
  } secrets;

  options_s s;
  /* Set default values. */
  memset(&s, 0, sizeof(s));
  /* Half a month's worth of keys. */
  s.num_keys = 15;

  time_t now;
  time(&now);

  if (argc < 2) {
    show_help();
    goto done;
  }

  if (crypto_early_init()) {
    fprintf(stderr, "Couldn't initialize crypto.\n");
    goto done;
  }

  if (parse_options(argc, argv, &s) < 0) {
    fprintf(stderr, "Couldn't parse options.\n");
    goto done;
  }

  if (s.show_help) {
    show_help();
    goto done;
  }

  if (validate_options(&s) < 0) {
    fprintf(stderr, "Couldn't validate options.\n");
    goto done;
  }

  /* keygen */
  if (s.hs3_gen_master_keypair) {
    if (ed25519_keypair_generate(&secrets.master, 1) < 0) {
      fprintf(stderr, "Couldn't generate a strong enough key.\n");
      goto done;
    }
    ed25519_seckey_write_to_file(&secrets.master.seckey,
        "hs_ed25519_secret_key",
        "type0");
    ed25519_pubkey_write_to_file(&secrets.master.pubkey,
        "hs_ed25519_public_key",
        "type0");
  } else if (s.hs3_existing_secret) {
    char *tag = NULL;
    if (ed25519_seckey_read_from_file(&secrets.master.seckey, &tag,
          s.hs3_existing_secret_fname) < 0) {
      fprintf(stderr, "Couldn't load existing secret.\n");
      tor_free(tag);
      goto done;
    }
    tor_free(tag);
    ed25519_public_key_generate(&secrets.master.pubkey, &secrets.master.seckey);
    /* We're writing the master keypair here; the service still tries to load
     * the master pubkey (even if we don't necessarily need it?). */
    ed25519_pubkey_write_to_file(&secrets.master.pubkey,
        "hs_ed25519_public_key",
        "type0");
  }

  if (s.hs3_gen_offline_keys) {
    /* XXX: should check for a zero'd secret key. */
    if (!s.hs3_gen_master_keypair && !s.hs3_existing_secret) {
      fprintf(stderr, "Can't generate offline keys, master secret is zero.\n");
      goto done;
    }

    for (unsigned int i = 0; i < s.num_keys; i++) {
      if (ed25519_keypair_generate(&secrets.descriptor, 0) < 0) {
        fprintf(stderr, "Couldn't generate a strong enough key.\n");
        goto done;
      }
      if (ed25519_keypair_generate(&secrets.blinded, 0) < 0) {
        fprintf(stderr, "Couldn't generate a strong enough key.\n");
        goto done;
      }

      /* XXX: allow for an optional secret? */
      hs3_blind(&secrets.master, NULL, 0, s.time_period + i, &secrets.blinded);
      tor_cert_t *cert = NULL;
      cert = hs3_cert_create(&secrets.blinded, &secrets.descriptor.pubkey,
          (s.time_period + i - s.curr_time_period)
          * HS_DESC_CERT_LIFETIME, now);
      if (cert == NULL) {
        fprintf(stderr, "Couldn't create a certificate.\n");
        goto done;
      }

      char *fname = NULL;
      tor_asprintf(&fname, "hs_ed25519_blinded_%" PRIu64 "_public_key", s.time_period + i);
      ed25519_pubkey_write_to_file(&secrets.blinded.pubkey, fname, "type0");
      tor_free(fname);

      tor_asprintf(&fname, "hs_ed25519_descriptor_%" PRIu64 "_public_key", s.time_period + i);
      ed25519_pubkey_write_to_file(&secrets.descriptor.pubkey, fname, "type0");
      tor_free(fname);

      tor_asprintf(&fname, "hs_ed25519_descriptor_%" PRIu64 "_secret_key", s.time_period + i);
      ed25519_seckey_write_to_file(&secrets.descriptor.seckey, fname, "type0");
      tor_free(fname);

      tor_asprintf(&fname, "hs_ed25519_descriptor_%" PRIu64 "_cert", s.time_period + i);
      crypto_write_tagged_contents_to_file(fname, "ed25519v1-cert",
          "type8", cert->encoded, cert->encoded_len);
      tor_free(fname);
      hs3_cert_free(cert);
    }
  }

  ret = 0;

done:
  memset(&s, 0, sizeof(s));
  memset(&secrets, 0, sizeof(secrets));
  return ret;
}
