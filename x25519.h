#pragma once
#include <stdint.h>

#define X25519_KEY_LEN 32

/* Generate a random private key (clamps automatically) */
void x25519_generate_private(uint8_t priv[X25519_KEY_LEN]);

/* Compute public key from private key */
void x25519_public_key(const uint8_t priv[X25519_KEY_LEN], uint8_t pub[X25519_KEY_LEN]);

/* Compute shared secret: our_private × their_public → shared */
int  x25519_shared_secret(const uint8_t our_priv[X25519_KEY_LEN],
                           const uint8_t their_pub[X25519_KEY_LEN],
                           uint8_t       shared[X25519_KEY_LEN]);
