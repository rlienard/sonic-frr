/* LISP control-plane packet encode / decode (RFC 9301).
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

#ifndef _LISP_PACKET_H
#define _LISP_PACKET_H

#include <stdint.h>
#include <stdbool.h>
#include "prefix.h"
#include "stream.h"
#include "lispd/lispd.h"
#include "lispd/lisp_auth.h"

/* Maximum LISP control-plane packet size (UDP payload). */
#define LISP_MAX_PACKET_SIZE  4096

/* Nonce size: 64 bits (8 octets) per RFC 9301 §6.1.2. */
#define LISP_NONCE_LEN  8

/*
 * LISP RLOC record flags (RFC 9301 §6.2).
 *
 *  L  – the RLOC is a local RLOC (locally assigned address)
 *  p  – RLOC-probe reply bit (set in Map-Reply when answering an RLOC probe)
 *  R  – RLOC reachability bit (1 = reachable)
 */
#define LISP_LOC_FLAG_L   0x04
#define LISP_LOC_FLAG_p   0x02
#define LISP_LOC_FLAG_R   0x01

/* -----------------------------------------------------------------------
 * Decoded representations of each message type.
 * These are in-memory structures used after parsing or before encoding.
 * ---------------------------------------------------------------------- */

/* A single decoded RLOC record (Locator entry). */
struct lisp_loc_record {
	uint8_t        priority;
	uint8_t        weight;
	uint8_t        mpriority;
	uint8_t        mweight;
	uint8_t        flags;   /* LISP_LOC_FLAG_* bitmask */
	struct prefix  rloc;
};

/* A single EID record (may contain multiple RLOCs). */
struct lisp_eid_record {
	uint32_t       ttl;           /* minutes; 0xffffffff = indefinite   */
	uint8_t        action;        /* LISP_ACTION_* (negative map-reply) */
	bool           authoritative; /* A bit                               */
	uint16_t       map_version;
	struct prefix  eid_prefix;
	uint8_t        loc_count;
	struct lisp_loc_record locs[32]; /* up to 32 RLOCs per record */
};

/* Decoded Map-Request (RFC 9301 §6.1). */
struct lisp_map_request {
	/* Header flags */
	bool     authoritative;   /* A bit */
	bool     map_data_present;/* M bit */
	bool     probe;           /* P bit (RLOC-probe) */
	bool     smr;             /* S bit (Solicit Map-Request) */
	bool     pitr;            /* p bit */
	bool     smr_invoked;     /* s bit */

	uint8_t  itr_rloc_count;  /* number of ITR-RLOCs (value+1 in wire) */
	uint8_t  record_count;

	uint8_t  nonce[LISP_NONCE_LEN];

	struct prefix  src_eid;
	struct prefix  itr_rlocs[32];  /* ITR-RLOC addresses */

	/* Requested EID records */
	struct {
		struct prefix eid_prefix;
	} records[8];
};

/* Decoded Map-Reply (RFC 9301 §6.2). */
struct lisp_map_reply {
	bool    probe;        /* P bit */
	bool    echo_nonce;   /* E bit (echo-nonce mechanism) */
	bool    security;     /* S bit */

	uint8_t record_count;
	uint8_t nonce[LISP_NONCE_LEN];

	struct lisp_eid_record records[8];
};

/* Decoded Map-Register (RFC 9301 §8.2). */
struct lisp_map_register {
	bool     proxy_reply;      /* P bit */
	bool     want_map_notify;  /* M bit */
	bool     id_present;       /* I bit */
	bool     use_ttl;          /* T bit */
	bool     merge_request;    /* a bit */

	uint8_t  record_count;
	uint8_t  nonce[LISP_NONCE_LEN];
	uint16_t key_id;
	uint16_t algorithm_id;
	/* 16-byte auth data follows in wire format */
	uint8_t  auth_data[LISP_AUTH_SHA256_128_LEN];

	struct lisp_eid_record records[8];

	/* xTR-ID (128 bits) and Site-ID (64 bits), present when I bit set */
	uint8_t  xtr_id[16];
	uint8_t  site_id[8];
};

/* Decoded Map-Notify (RFC 9301 §8.4). */
struct lisp_map_notify {
	uint8_t  record_count;
	uint8_t  nonce[LISP_NONCE_LEN];
	uint16_t key_id;
	uint16_t algorithm_id;
	uint8_t  auth_data[LISP_AUTH_SHA256_128_LEN];

	struct lisp_eid_record records[8];
};

/* -----------------------------------------------------------------------
 * Encode functions — write a message into a stream (to be sent via UDP).
 * Return 0 on success, -1 on error.
 * ---------------------------------------------------------------------- */

extern int lisp_encode_map_request(struct stream *s,
				   const struct lisp_map_request *req);

extern int lisp_encode_map_reply(struct stream *s,
				 const struct lisp_map_reply *rep);

extern int lisp_encode_map_register(struct stream *s,
				    struct lisp_map_register *reg,
				    const struct lisp_auth_key *key);

extern int lisp_encode_map_notify(struct stream *s,
				  struct lisp_map_notify *notify,
				  const struct lisp_auth_key *key);

/*
 * Encode a Map-Request inside an Encapsulated Control Message (ECM, type 8).
 * Used by ITRs to send Map-Requests via a Map-Resolver (RFC 9301 §6.4).
 *
 * outer_src / outer_dst are the IP addresses for the outer UDP header
 * (typically the ITR's RLOC and the Map-Resolver's address).
 */
extern int lisp_encode_ecm(struct stream *s,
			   const struct lisp_map_request *req,
			   const struct prefix *outer_src,
			   const struct prefix *outer_dst);

/* -----------------------------------------------------------------------
 * Decode functions — parse a received UDP payload.
 * Return 0 on success, -1 on parse error.
 * ---------------------------------------------------------------------- */

extern int lisp_decode_map_request(struct stream *s,
				   struct lisp_map_request *req);

extern int lisp_decode_map_reply(struct stream *s,
				 struct lisp_map_reply *rep);

extern int lisp_decode_map_register(struct stream *s,
				    struct lisp_map_register *reg);

extern int lisp_decode_map_notify(struct stream *s,
				  struct lisp_map_notify *notify);

/* Decode an ECM outer header and advance s to the inner Map-Request. */
extern int lisp_decode_ecm(struct stream *s);

#endif /* _LISP_PACKET_H */
