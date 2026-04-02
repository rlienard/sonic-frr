/* LISP authentication (HMAC-SHA-256-128) for Map-Register / Map-Notify.
 * Copyright (C) 2024 FRR Project
 *
 * This file is part of FRRouting.
 *
 * FRRouting is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRRouting is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "lib/sha256.h"

#include "lispd/lisp_auth.h"

/*
 * Compute HMAC-SHA-256-128 over buf[0..buf_len) treating the 16 bytes at
 * auth_off as zeroed (as required by RFC 9301 §8.2: the authentication-data
 * field is set to all-zeros before computing the HMAC).
 *
 * The full 32-byte HMAC is computed; only the first 16 bytes (128 bits)
 * are written into *out (the "-128" truncation from HMAC-SHA-256-128).
 */
void lisp_auth_compute(const uint8_t *buf, size_t buf_len,
		       size_t auth_off,
		       const struct lisp_auth_key *key,
		       uint8_t *out)
{
	HMAC_SHA256_CTX ctx;
	uint8_t digest[32];

	/* The packet must have been built with the auth field zeroed. */
	HMAC__SHA256_Init(&ctx, key->key, key->key_len);

	/* Feed the portion before the auth field. */
	if (auth_off > 0)
		HMAC__SHA256_Update(&ctx, buf, auth_off);

	/* Feed 16 zero bytes in place of the auth field. */
	{
		uint8_t zeros[LISP_AUTH_SHA256_128_LEN];

		memset(zeros, 0, sizeof(zeros));
		HMAC__SHA256_Update(&ctx, zeros, sizeof(zeros));
	}

	/* Feed the portion after the auth field. */
	if (auth_off + LISP_AUTH_SHA256_128_LEN < buf_len)
		HMAC__SHA256_Update(&ctx,
				    buf + auth_off + LISP_AUTH_SHA256_128_LEN,
				    buf_len - auth_off - LISP_AUTH_SHA256_128_LEN);

	HMAC__SHA256_Final(digest, &ctx);

	/* Truncate to 128 bits. */
	memcpy(out, digest, LISP_AUTH_SHA256_128_LEN);
}

/*
 * Verify the authentication data embedded in buf at auth_off.
 * Returns true if it matches the HMAC computed with key.
 */
bool lisp_auth_verify(const uint8_t *buf, size_t buf_len,
		      size_t auth_off,
		      const struct lisp_auth_key *key)
{
	uint8_t expected[LISP_AUTH_SHA256_128_LEN];

	lisp_auth_compute(buf, buf_len, auth_off, key, expected);

	return (memcmp(buf + auth_off, expected, LISP_AUTH_SHA256_128_LEN) == 0);
}
