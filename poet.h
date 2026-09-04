/*
// @author Eik List, Christian Forler
// @last-modified 2021-03-12
// This is free and unencumbered software released into the public domain.
//
// Anyone is free to copy, modify, publish, use, compile, sell, or
// distribute this software, either in source code form or as a compiled
// binary, for any purpose, commercial or non-commercial, and by any
// means.
//
// In jurisdictions that recognize copyright laws, the author or authors
// of this software dedicate any and all copyright interest in the
// software to the public domain. We make this dedication for the benefit
// of the public at large and to the detriment of our heirs and
// successors. We intend this dedication to be an overt act of
// relinquishment in perpetuity of all present and future rights to this
// software under copyright law.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// For more information, please refer to <http://unlicense.org/>
*/
#ifndef _POET_H_
#define _POET_H_

#include <stdint.h>
#include "aes.h"
#include "helper.h"

// ---------------------------------------------------------------------

#define BLOCKLEN      16
#define BLOCKLEN_BITS (BLOCKLEN*8)
#define KEYLEN        16
#define KEYLEN_BITS   KEYLEN*8
#define TAGLEN        16

#define NUM_BLOCKS_PER_PART     0
#define INTERMEDIATE_TAGLEN     0

#define SUCCESS       0
#define FAIL          1

// ---------------------------------------------------------------------

typedef byte_t block[BLOCKLEN];
typedef int boolean;

// ---------------------------------------------------------------------

typedef struct {
  AES_KEY aes_enc;   // Expanded encryption key for the AES
  AES_KEY aes_dec;   // Expanded decryption key for the AES
  AES_KEY aes_axu; // Expanded key for the AXU hash function (top and bottom)
  block k;           // Block-cipher key
  block l;           // PMAC key
  block k_axu;       // Key for the AXU hash function (top and bottom)
  block x;           // Top-chaining value
  block y;           // Bottom-chaining value
  block tau;         // Result of the header-processing step
  uint64_t mlen;     // Message length
} poet_ctx_t;

// ---------------------------------------------------------------------

void keysetup_encrypt_only(poet_ctx_t *ctx, const byte_t key[KEYLEN]);

void keysetup(poet_ctx_t *ctx, const byte_t key[KEYLEN]);


// Can be called after the keysetup
void process_header(poet_ctx_t *ctx,
                    const byte_t *header,
                    uint64_t header_len);
/*
 * Can be called after process_header
 * Encrypt a specific plaintext block mi to a the 
 *  ciphertext block ci
 */
void encrypt_block(poet_ctx_t *ctx, 
                    const block mi, 
                    block ci);

/*
 * Can be called after the header processing.
 * Encrypt the final part of the plaintext m
 * to the ciphertext c and generates
 *  tag (cryptographic checksum)
 * All other parts of the plaintext should be processed before by 
 * multiple invokations of encrypt_block().
 */
void encrypt_final(poet_ctx_t *ctx,
                   const byte_t *m,
                   uint64_t mlen,
                   byte_t *c,
                   byte_t tag[TAGLEN]);


/*
 * Can be called after the header processing.
 *  Encrypt the plaintext block in to the 
 *  ciphertext block out
 */
void decrypt_block(poet_ctx_t *ctx,
                   const block in,
                   block out);
  



 /* Can be called after the header processing.
  * Decrypts the final part of the ciphertext c
  * to the ciphertext c and verifies the 
  * tag (cryptographic checksum).
  * On successful verification, decrypt_final() returns 0.
  */
__attribute__ ((warn_unused_result))
int decrypt_final(poet_ctx_t *ctx,
                  const byte_t *c,
                  uint64_t clen,
                  const byte_t tag[TAGLEN],
                  byte_t *m);

// ---------------------------------------------------------------------

#endif //  _POET_H_
