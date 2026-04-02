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

/*
 * Wire format references (all section numbers are from RFC 9301):
 *
 *  Map-Request  §6.1   type=1
 *  Map-Reply    §6.2   type=2
 *  Map-Register §8.2   type=3
 *  Map-Notify   §8.4   type=4
 *  ECM          §6.4   type=8
 *
 * EID-Record and Locator (RLOC) sub-format §6.1 / §6.2.
 *
 * All multi-byte fields are big-endian (network byte order).
 */

#include <zebra.h>

#include "stream.h"
#include "prefix.h"
#include "log.h"
#include "sockunion.h"

#include "lispd/lispd.h"
#include "lispd/lisp_packet.h"
#include "lispd/lisp_auth.h"
#include "lispd/lisp_errors.h"

/* =========================================================================
 * Helpers
 * ====================================================================== */

/* Write an AFI (2 bytes) followed by the address bytes for a prefix. */
static int stream_put_prefix_afi(struct stream *s, const struct prefix *p)
{
	if (p->family == AF_INET) {
		stream_putw(s, LISP_AFI_IPV4);
		stream_put(s, &p->u.prefix4, 4);
	} else if (p->family == AF_INET6) {
		stream_putw(s, LISP_AFI_IPV6);
		stream_put(s, &p->u.prefix6, 16);
	} else {
		/* AFI 0 = no address */
		stream_putw(s, 0);
	}
	return 0;
}

/* Read AFI + address into a prefix.  Returns addr bytes read, -1 on error. */
static int stream_get_prefix_afi(struct stream *s, struct prefix *p)
{
	uint16_t afi;

	if (STREAM_READABLE(s) < 2)
		return -1;

	afi = stream_getw(s);
	if (afi == LISP_AFI_IPV4) {
		if (STREAM_READABLE(s) < 4)
			return -1;
		p->family = AF_INET;
		p->prefixlen = IPV4_MAX_BITLEN;
		stream_get(&p->u.prefix4, s, 4);
		return 4;
	} else if (afi == LISP_AFI_IPV6) {
		if (STREAM_READABLE(s) < 16)
			return -1;
		p->family = AF_INET6;
		p->prefixlen = IPV6_MAX_BITLEN;
		stream_get(&p->u.prefix6, s, 16);
		return 16;
	} else if (afi == 0) {
		memset(p, 0, sizeof(*p));
		return 0;
	}
	return -1;
}

/*
 * Encode a single EID record (used in Map-Reply, Map-Register, Map-Notify).
 *
 * Wire layout (§6.2):
 *   4  bytes  Record TTL
 *   1  byte   Locator Count
 *   1  byte   EID Mask-Len
 *   2  bytes  ACT(3b)|A(1b)|reserved(4b) | Map-Version(12b)
 *   2  bytes  EID-Prefix-AFI
 *   var       EID-Prefix address
 *   for each locator:
 *     1 byte  Priority
 *     1 byte  Weight
 *     1 byte  M-Priority
 *     1 byte  M-Weight
 *     2 bytes reserved(9b)|L(1b)|p(1b)|R(1b)... actually flags in low byte
 *     2 bytes Locator-AFI
 *     var     Locator address
 */
static int stream_put_eid_record(struct stream *s,
				 const struct lisp_eid_record *rec)
{
	int i;

	stream_putl(s, rec->ttl);
	stream_putc(s, rec->loc_count);
	stream_putc(s, rec->eid_prefix.prefixlen);

	/* ACT(3 bits) | A(1 bit) | reserved(4 bits) — high byte */
	stream_putc(s, ((rec->action & 0x07) << 5)
			| (rec->authoritative ? 0x10 : 0x00));
	/* Map-Version high nibble (bits 11-8) */
	stream_putc(s, (rec->map_version >> 8) & 0x0f);

	stream_put_prefix_afi(s, &rec->eid_prefix);

	for (i = 0; i < rec->loc_count; i++) {
		const struct lisp_loc_record *loc = &rec->locs[i];

		stream_putc(s, loc->priority);
		stream_putc(s, loc->weight);
		stream_putc(s, loc->mpriority);
		stream_putc(s, loc->mweight);
		stream_putc(s, 0); /* reserved */
		stream_putc(s, loc->flags & 0x07);
		stream_put_prefix_afi(s, &loc->rloc);
	}
	return 0;
}

static int stream_get_eid_record(struct stream *s, struct lisp_eid_record *rec)
{
	uint8_t act_a, mv_low;
	int i;

	if (STREAM_READABLE(s) < 8)
		return -1;

	rec->ttl = stream_getl(s);
	rec->loc_count = stream_getc(s);
	rec->eid_prefix.prefixlen = stream_getc(s);

	act_a = stream_getc(s);
	mv_low = stream_getc(s);

	rec->action = (act_a >> 5) & 0x07;
	rec->authoritative = !!(act_a & 0x10);
	rec->map_version = ((uint16_t)(mv_low & 0x0f)) |
			   ((uint16_t)((act_a & 0x0f)) << 4);

	if (stream_get_prefix_afi(s, &rec->eid_prefix) < 0)
		return -1;

	if (rec->loc_count > 32)
		return -1;

	for (i = 0; i < rec->loc_count; i++) {
		struct lisp_loc_record *loc = &rec->locs[i];

		if (STREAM_READABLE(s) < 6)
			return -1;
		loc->priority  = stream_getc(s);
		loc->weight    = stream_getc(s);
		loc->mpriority = stream_getc(s);
		loc->mweight   = stream_getc(s);
		stream_getc(s); /* reserved */
		loc->flags = stream_getc(s) & 0x07;

		if (stream_get_prefix_afi(s, &loc->rloc) < 0)
			return -1;
	}
	return 0;
}

/* =========================================================================
 * Map-Request encode / decode  (RFC 9301 §6.1)
 *
 * Wire layout:
 *   1 byte   type(4b)|A(1b)|M(1b)|P(1b)|S(1b)
 *   1 byte   p(1b)|s(1b)|reserved(6b)
 *   1 byte   Reserved
 *   1 byte   IRC(4b)|Record Count(4b)   [IRC = ITR-RLOC-count - 1]
 *   8 bytes  Nonce
 *   2 bytes  Source-EID-AFI
 *   var      Source-EID address
 *   for each ITR-RLOC (IRC+1 entries):
 *     2 bytes  AFI
 *     var      address
 *   for each record:
 *     1 byte   Reserved
 *     3 bytes  EID-Mask-Len(8b) | EID-Prefix-AFI(16b) ... actually:
 *     1 byte   Reserved
 *     1 byte   EID Mask-Len
 *     2 bytes  EID-Prefix-AFI
 *     var      EID-Prefix address
 * ====================================================================== */

int lisp_encode_map_request(struct stream *s,
			    const struct lisp_map_request *req)
{
	uint8_t byte1, byte2, irc_rc;
	int i;

	byte1 = (LISP_MAP_REQUEST << 4)
		| (req->authoritative    ? 0x08 : 0)
		| (req->map_data_present ? 0x04 : 0)
		| (req->probe            ? 0x02 : 0)
		| (req->smr              ? 0x01 : 0);

	byte2 = (req->pitr        ? 0x80 : 0)
		| (req->smr_invoked ? 0x40 : 0);

	irc_rc = (((req->itr_rloc_count - 1) & 0x0f) << 4)
		 | (req->record_count & 0x0f);

	stream_putc(s, byte1);
	stream_putc(s, byte2);
	stream_putc(s, 0); /* reserved */
	stream_putc(s, irc_rc);

	stream_put(s, req->nonce, LISP_NONCE_LEN);

	stream_put_prefix_afi(s, &req->src_eid);

	for (i = 0; i < req->itr_rloc_count && i < 32; i++)
		stream_put_prefix_afi(s, &req->itr_rlocs[i]);

	for (i = 0; i < req->record_count && i < 8; i++) {
		stream_putc(s, 0); /* reserved */
		stream_putc(s, req->records[i].eid_prefix.prefixlen);
		stream_put_prefix_afi(s, &req->records[i].eid_prefix);
	}

	return 0;
}

int lisp_decode_map_request(struct stream *s, struct lisp_map_request *req)
{
	uint8_t byte1, byte2, rsvd, irc_rc;
	int i;

	if (STREAM_READABLE(s) < 4 + LISP_NONCE_LEN)
		return -1;

	byte1 = stream_getc(s);
	byte2 = stream_getc(s);
	rsvd  = stream_getc(s);
	(void)rsvd;
	irc_rc = stream_getc(s);

	/* type is the top 4 bits of byte1 — caller verified it is 1 */
	req->authoritative    = !!(byte1 & 0x08);
	req->map_data_present = !!(byte1 & 0x04);
	req->probe            = !!(byte1 & 0x02);
	req->smr              = !!(byte1 & 0x01);
	req->pitr             = !!(byte2 & 0x80);
	req->smr_invoked      = !!(byte2 & 0x40);

	req->itr_rloc_count = ((irc_rc >> 4) & 0x0f) + 1;
	req->record_count   = irc_rc & 0x0f;

	stream_get(req->nonce, s, LISP_NONCE_LEN);

	if (stream_get_prefix_afi(s, &req->src_eid) < 0)
		return -1;

	if (req->itr_rloc_count > 32)
		return -1;

	for (i = 0; i < req->itr_rloc_count; i++) {
		if (stream_get_prefix_afi(s, &req->itr_rlocs[i]) < 0)
			return -1;
	}

	if (req->record_count > 8)
		return -1;

	for (i = 0; i < req->record_count; i++) {
		uint8_t masklen;

		if (STREAM_READABLE(s) < 2)
			return -1;
		stream_getc(s); /* reserved */
		masklen = stream_getc(s);
		if (stream_get_prefix_afi(s, &req->records[i].eid_prefix) < 0)
			return -1;
		req->records[i].eid_prefix.prefixlen = masklen;
	}

	return 0;
}

/* =========================================================================
 * Map-Reply encode / decode  (RFC 9301 §6.2)
 *
 * Wire layout:
 *   1 byte   type(4b)|reserved(2b)|P(1b)|E(1b)
 *   1 byte   S(1b)|reserved(7b)
 *   2 bytes  reserved
 *   8 bytes  Nonce
 *   for each record:  EID record (see stream_put_eid_record)
 * ====================================================================== */

int lisp_encode_map_reply(struct stream *s, const struct lisp_map_reply *rep)
{
	int i;

	stream_putc(s, (LISP_MAP_REPLY << 4)
			| (rep->probe      ? 0x02 : 0)
			| (rep->echo_nonce ? 0x01 : 0));
	stream_putc(s, (rep->security ? 0x80 : 0));
	stream_putw(s, rep->record_count); /* upper byte reserved = 0 */

	stream_put(s, rep->nonce, LISP_NONCE_LEN);

	for (i = 0; i < rep->record_count && i < 8; i++)
		stream_put_eid_record(s, &rep->records[i]);

	return 0;
}

int lisp_decode_map_reply(struct stream *s, struct lisp_map_reply *rep)
{
	uint8_t byte1, byte2;
	uint16_t rc_word;
	int i;

	if (STREAM_READABLE(s) < 4 + LISP_NONCE_LEN)
		return -1;

	byte1   = stream_getc(s);
	byte2   = stream_getc(s);
	rc_word = stream_getw(s);

	rep->probe      = !!(byte1 & 0x02);
	rep->echo_nonce = !!(byte1 & 0x01);
	rep->security   = !!(byte2 & 0x80);
	rep->record_count = rc_word & 0xff;

	stream_get(rep->nonce, s, LISP_NONCE_LEN);

	if (rep->record_count > 8)
		return -1;

	for (i = 0; i < rep->record_count; i++) {
		if (stream_get_eid_record(s, &rep->records[i]) < 0)
			return -1;
	}

	return 0;
}

/* =========================================================================
 * Map-Register encode / decode  (RFC 9301 §8.2)
 *
 * Wire layout:
 *   1 byte   type(4b)|reserved(2b)|P(1b)|reserved(1b)
 *   1 byte   reserved(3b)|I(1b)|T(1b)|a(1b)|M(1b)|reserved(1b)
 *   1 byte   reserved
 *   1 byte   Record Count
 *   8 bytes  Nonce
 *   2 bytes  Key-ID
 *   2 bytes  Authentication Data Length
 *  16 bytes  Authentication Data  (HMAC-SHA-256-128)
 *   for each record:  EID record
 *  16 bytes  xTR-ID    (only if I bit set)
 *   8 bytes  Site-ID   (only if I bit set)
 * ====================================================================== */

int lisp_encode_map_register(struct stream *s,
			     struct lisp_map_register *reg,
			     const struct lisp_auth_key *key)
{
	size_t auth_off;
	int i;

	stream_putc(s, (LISP_MAP_REGISTER << 4)
			| (reg->proxy_reply ? 0x02 : 0));
	stream_putc(s, (reg->id_present     ? 0x10 : 0)
			| (reg->use_ttl      ? 0x08 : 0)
			| (reg->merge_request ? 0x04 : 0)
			| (reg->want_map_notify ? 0x02 : 0));
	stream_putc(s, 0); /* reserved */
	stream_putc(s, reg->record_count);

	stream_put(s, reg->nonce, LISP_NONCE_LEN);

	stream_putw(s, key ? key->key_id : 0);
	stream_putw(s, LISP_AUTH_SHA256_128_LEN);

	/* Remember offset for HMAC computation; write zeros for now. */
	auth_off = stream_get_endp(s);
	stream_put(s, reg->auth_data, LISP_AUTH_SHA256_128_LEN);

	for (i = 0; i < reg->record_count && i < 8; i++)
		stream_put_eid_record(s, &reg->records[i]);

	if (reg->id_present) {
		stream_put(s, reg->xtr_id,  sizeof(reg->xtr_id));
		stream_put(s, reg->site_id, sizeof(reg->site_id));
	}

	/* Compute and fill in HMAC. */
	if (key && key->algorithm_id != LISP_AUTH_NONE) {
		uint8_t *buf = STREAM_DATA(s);
		size_t   len = stream_get_endp(s);

		lisp_auth_compute(buf, len, auth_off, key, buf + auth_off);
	}

	return 0;
}

int lisp_decode_map_register(struct stream *s, struct lisp_map_register *reg)
{
	uint8_t byte1, byte2, rsvd;
	uint16_t auth_len;
	int i;

	if (STREAM_READABLE(s) < 4 + LISP_NONCE_LEN + 4)
		return -1;

	byte1 = stream_getc(s);
	byte2 = stream_getc(s);
	rsvd  = stream_getc(s);
	(void)rsvd;
	reg->record_count = stream_getc(s);

	reg->proxy_reply    = !!(byte1 & 0x02);
	reg->id_present     = !!(byte2 & 0x10);
	reg->use_ttl        = !!(byte2 & 0x08);
	reg->merge_request  = !!(byte2 & 0x04);
	reg->want_map_notify = !!(byte2 & 0x02);

	stream_get(reg->nonce, s, LISP_NONCE_LEN);

	reg->key_id      = stream_getw(s);
	reg->algorithm_id = LISP_AUTH_HMAC_SHA256_128; /* implied by key-id */
	auth_len         = stream_getw(s);

	if (auth_len > LISP_AUTH_SHA256_128_LEN || STREAM_READABLE(s) < auth_len)
		return -1;

	memset(reg->auth_data, 0, sizeof(reg->auth_data));
	stream_get(reg->auth_data, s, auth_len);

	if (reg->record_count > 8)
		return -1;

	for (i = 0; i < reg->record_count; i++) {
		if (stream_get_eid_record(s, &reg->records[i]) < 0)
			return -1;
	}

	if (reg->id_present) {
		if (STREAM_READABLE(s) < 24)
			return -1;
		stream_get(reg->xtr_id,  s, 16);
		stream_get(reg->site_id, s,  8);
	}

	return 0;
}

/* =========================================================================
 * Map-Notify encode / decode  (RFC 9301 §8.4)
 *
 * Wire layout:
 *   1 byte   type(4b)|reserved(4b)
 *   2 bytes  reserved
 *   1 byte   Record Count
 *   8 bytes  Nonce
 *   2 bytes  Key-ID
 *   2 bytes  Authentication Data Length
 *  16 bytes  Authentication Data
 *   for each record:  EID record
 * ====================================================================== */

int lisp_encode_map_notify(struct stream *s,
			   struct lisp_map_notify *notify,
			   const struct lisp_auth_key *key)
{
	size_t auth_off;
	int i;

	stream_putc(s, LISP_MAP_NOTIFY << 4);
	stream_putw(s, 0); /* reserved */
	stream_putc(s, notify->record_count);

	stream_put(s, notify->nonce, LISP_NONCE_LEN);

	stream_putw(s, key ? key->key_id : 0);
	stream_putw(s, LISP_AUTH_SHA256_128_LEN);

	auth_off = stream_get_endp(s);
	stream_put(s, notify->auth_data, LISP_AUTH_SHA256_128_LEN);

	for (i = 0; i < notify->record_count && i < 8; i++)
		stream_put_eid_record(s, &notify->records[i]);

	if (key && key->algorithm_id != LISP_AUTH_NONE) {
		uint8_t *buf = STREAM_DATA(s);
		size_t   len = stream_get_endp(s);

		lisp_auth_compute(buf, len, auth_off, key, buf + auth_off);
	}

	return 0;
}

int lisp_decode_map_notify(struct stream *s, struct lisp_map_notify *notify)
{
	uint16_t auth_len;
	int i;

	if (STREAM_READABLE(s) < 4 + LISP_NONCE_LEN + 4)
		return -1;

	stream_getc(s); /* type byte already identified by caller */
	stream_getw(s); /* reserved */
	notify->record_count = stream_getc(s);

	stream_get(notify->nonce, s, LISP_NONCE_LEN);

	notify->key_id       = stream_getw(s);
	notify->algorithm_id = LISP_AUTH_HMAC_SHA256_128;
	auth_len             = stream_getw(s);

	if (auth_len > LISP_AUTH_SHA256_128_LEN || STREAM_READABLE(s) < auth_len)
		return -1;

	memset(notify->auth_data, 0, sizeof(notify->auth_data));
	stream_get(notify->auth_data, s, auth_len);

	if (notify->record_count > 8)
		return -1;

	for (i = 0; i < notify->record_count; i++) {
		if (stream_get_eid_record(s, &notify->records[i]) < 0)
			return -1;
	}

	return 0;
}

/* =========================================================================
 * Encapsulated Control Message (ECM)  (RFC 9301 §6.4)
 *
 * An ITR sends a Map-Request to a Map-Resolver by encapsulating it inside
 * an ECM.  The outer header is a normal IP/UDP header (src=ITR-RLOC,
 * dst=Map-Resolver, dport=4342).  The ECM itself is:
 *
 *   1 byte   type(4b)=8 | S(1b) | reserved(3b)
 *   3 bytes  reserved
 *
 * followed immediately by a copy of the inner IP/UDP/Map-Request.  In this
 * implementation we write the inner Map-Request directly (no inner IP/UDP
 * re-encapsulation), as the ECM header + inner LISP message is what gets
 * placed in the UDP payload sent by the OS socket.
 * ====================================================================== */

int lisp_encode_ecm(struct stream *s,
		    const struct lisp_map_request *req,
		    const struct prefix *outer_src,
		    const struct prefix *outer_dst)
{
	/* ECM header */
	stream_putc(s, LISP_ENCAP_CONTROL << 4); /* S bit = 0 */
	stream_putc(s, 0);
	stream_putc(s, 0);
	stream_putc(s, 0);

	/* Inner Map-Request */
	return lisp_encode_map_request(s, req);
}

/*
 * Consume the 4-byte ECM header; leave the stream positioned at the inner
 * Map-Request first byte.  Returns -1 if this is not an ECM.
 */
int lisp_decode_ecm(struct stream *s)
{
	uint8_t type_byte;

	if (STREAM_READABLE(s) < 4)
		return -1;

	type_byte = stream_getc(s);
	if ((type_byte >> 4) != LISP_ENCAP_CONTROL)
		return -1;

	stream_getc(s); /* reserved */
	stream_getc(s); /* reserved */
	stream_getc(s); /* reserved */

	return 0;
}
