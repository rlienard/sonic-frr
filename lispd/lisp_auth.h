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

#ifndef _LISP_AUTH_H
#define _LISP_AUTH_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/*
 * RFC 9301 §8.2 / §8.4 — authentication algorithm IDs.
 * HMAC-SHA-256-128 (ID 3) is the mandatory-to-implement algorithm.
 */
#define LISP_AUTH_NONE             0
#define LISP_AUTH_HMAC_SHA1_96     1
#define LISP_AUTH_HMAC_SHA256_128  3

/* Authentication data length for HMAC-SHA-256-128 (128 bits = 16 bytes). */
#define LISP_AUTH_SHA256_128_LEN  16

/* Maximum authentication data length we allocate for. */
#define LISP_AUTH_DATA_MAX_LEN    32

/* A pre-shared key entry (one per key-id). */
struct lisp_auth_key {
	/* Key identifier (16-bit, used in Map-Register / Map-Notify). */
	uint16_t key_id;

	/* Algorithm ID (LISP_AUTH_*). */
	uint8_t algorithm_id;

	/* Raw key material. */
	uint8_t  key[64];
	uint16_t key_len;
};

/*
 * Compute HMAC-SHA-256-128 over a Map-Register or Map-Notify packet.
 *
 * The caller must:
 *  1. Build the full packet with the authentication-data field zeroed.
 *  2. Call lisp_auth_compute() to fill in the 16-byte auth-data field.
 *
 * buf       – pointer to the start of the packet
 * buf_len   – total packet length
 * auth_off  – byte offset within buf where the 16-byte auth field sits
 * key       – pointer to the auth key entry
 * out       – output buffer, must be at least LISP_AUTH_SHA256_128_LEN bytes
 */
extern void lisp_auth_compute(const uint8_t *buf, size_t buf_len,
			      size_t auth_off,
			      const struct lisp_auth_key *key,
			      uint8_t *out);

/*
 * Verify HMAC-SHA-256-128 of a received packet.
 * Returns true if the authentication data in the packet matches.
 */
extern bool lisp_auth_verify(const uint8_t *buf, size_t buf_len,
			     size_t auth_off,
			     const struct lisp_auth_key *key);

#endif /* _LISP_AUTH_H */
