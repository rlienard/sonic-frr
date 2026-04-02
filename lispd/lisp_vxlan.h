/* LISP VxLAN-GPE data-plane encapsulation with GBP Security Group extension.
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
 * References:
 *   RFC 9301         LISP Control Plane §2.4 — VxLAN-GPE data-plane option
 *   draft-ietf-nvo3-vxlan-gpe  — VxLAN Generic Protocol Extension (GPE)
 *   draft-smith-vxlan-group-policy — VxLAN Group Based Policy (GBP)
 *
 * Wire format — VxLAN-GPE header (8 bytes), UDP dst-port 4789:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |G|R|Ver|I|P|B|O|  SGT[15:8]   |   SGT[7:0]   | Next Protocol  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          VXLAN Network Identifier (VNI)       |   Reserved    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Byte 0 flags:
 *   G   (bit 7) — GBP extension present; bytes 1–2 carry SGT.
 *                 When G=0 bytes 1–2 are reserved (must be 0).
 *   R   (bit 6) — Reserved
 *   Ver (bits 5-4) — VxLAN-GPE version, currently 0
 *   I   (bit 3) — VNI present and valid
 *   P   (bit 2) — Next Protocol field is valid
 *   B   (bit 1) — BUM (Broadcast/Unknown-unicast/Multicast) indicator
 *   O   (bit 0) — OAM packet
 *
 * SGT field (bytes 1–2, only valid when G=1):
 *   16-bit Security Group Tag transported from the source xTR so that
 *   the destination xTR can enforce Group-Based Policy (GBP) rules.
 *   SGT 0 is reserved / untagged.
 *
 * Next Protocol (byte 3, only valid when P=1):
 *   0x01  IPv4
 *   0x02  IPv6
 *   0x03  Ethernet
 *   0x04  NSH (Network Service Header)
 *   0x05  LISP (LISP data-plane message inside VxLAN-GPE)
 *
 * VNI (bytes 4–6, 24-bit big-endian, only valid when I=1):
 *   Identifies the overlay virtual network.  Maps to a VRF / L3VNI in
 *   the LISP fabric (Cisco SD-Access convention).
 */

#ifndef _LISP_VXLAN_H
#define _LISP_VXLAN_H

#include <stdint.h>
#include <stdbool.h>
#include "prefix.h"
#include "stream.h"
#include "table.h"
#include "thread.h"
#include "linklist.h"

/* -------------------------------------------------------------------------
 * Port and size constants
 * ---------------------------------------------------------------------- */

/* VxLAN / VxLAN-GPE destination UDP port (IANA assigned). */
#define LISP_VXLAN_GPE_PORT      4789

/* Maximum raw data packet size (outer IP + UDP + VxLAN-GPE + inner payload). */
#define LISP_VXLAN_MAX_PKT_SIZE  9216

/* VxLAN-GPE header is always 8 bytes. */
#define LISP_VXLAN_GPE_HDR_LEN   8

/* Maximum VNI value (24-bit field). */
#define LISP_VNI_MAX             0x00FFFFFFUL

/* SGT value 0 = untagged / no group policy. */
#define LISP_SGT_UNTAGGED        0x0000
/* SGT 0xFFFF is reserved. */
#define LISP_SGT_RESERVED        0xFFFF

/* -------------------------------------------------------------------------
 * VxLAN-GPE byte-0 flag bits
 * ---------------------------------------------------------------------- */

#define LISP_VXLAN_GPE_F_G    0x80  /* GBP: SGT present in bytes 1–2     */
#define LISP_VXLAN_GPE_F_R    0x40  /* Reserved                           */
#define LISP_VXLAN_GPE_VER_MASK 0x30 /* Version field (2 bits, shift >>4) */
#define LISP_VXLAN_GPE_F_I    0x08  /* VNI valid                          */
#define LISP_VXLAN_GPE_F_P    0x04  /* Next Protocol valid                */
#define LISP_VXLAN_GPE_F_B    0x02  /* BUM packet                         */
#define LISP_VXLAN_GPE_F_O    0x01  /* OAM packet                         */

/* Convenience: flags set for normal unicast data with VNI + Next-Proto. */
#define LISP_VXLAN_GPE_FLAGS_DATA  (LISP_VXLAN_GPE_F_I | LISP_VXLAN_GPE_F_P)
/* Same plus GBP SGT. */
#define LISP_VXLAN_GPE_FLAGS_GBP   (LISP_VXLAN_GPE_FLAGS_DATA | LISP_VXLAN_GPE_F_G)

/* -------------------------------------------------------------------------
 * Next Protocol codes (byte 3)
 * ---------------------------------------------------------------------- */

#define LISP_VXLAN_NP_IPV4    0x01
#define LISP_VXLAN_NP_IPV6    0x02
#define LISP_VXLAN_NP_ETH     0x03
#define LISP_VXLAN_NP_NSH     0x04
#define LISP_VXLAN_NP_LISP    0x05  /* LISP data-plane inside VxLAN-GPE */

/* -------------------------------------------------------------------------
 * GBP-specific flags carried in SGT bytes when G=1
 *
 * Per draft-smith-vxlan-group-policy, two control bits are multiplexed
 * into the SGT bytes:
 *   D-bit (bit 14 of the 16-bit SGT word, i.e. byte 1 bit 6):
 *     Don't Learn — source MAC/IP should not be learned by the destination.
 *   A-bit (bit 12 of the 16-bit SGT word, i.e. byte 1 bit 4):
 *     Applied — GBP policy has already been enforced at the source xTR;
 *     destination need not re-apply.
 *
 * The actual 14-bit SGT value occupies the remaining bits [13:8] of
 * byte 1 and all 8 bits of byte 2 (bits [7:0]), yielding a 14-bit tag
 * space of 0–16383.
 * ---------------------------------------------------------------------- */

#define LISP_GBP_D_BIT        0x4000  /* Don't Learn (bit 14 of SGT word) */
#define LISP_GBP_A_BIT        0x1000  /* Applied     (bit 12 of SGT word) */
#define LISP_GBP_SGT_MASK     0x3FFF  /* 14-bit SGT value mask            */

/* Maximum 14-bit SGT value. */
#define LISP_SGT_MAX          0x3FFF

/* -------------------------------------------------------------------------
 * Decoded VxLAN-GPE header (in-memory, after parsing)
 * ---------------------------------------------------------------------- */

struct lisp_vxlan_gpe_hdr {
	/* Byte 0 flags (LISP_VXLAN_GPE_F_* bitmask). */
	uint8_t  flags;

	/* VxLAN-GPE version (should be 0). */
	uint8_t  version;

	/* Next Protocol code (LISP_VXLAN_NP_*), valid when P flag is set. */
	uint8_t  next_proto;

	/* 24-bit VNI, valid when I flag is set. */
	uint32_t vni;

	/* GBP fields, valid when G flag is set. */
	bool     gbp_present;
	uint16_t sgt;       /* 14-bit Security Group Tag (LISP_GBP_SGT_MASK) */
	bool     dont_learn; /* D-bit */
	bool     applied;    /* A-bit */
};

/* -------------------------------------------------------------------------
 * SGT-to-EID mapping entry
 *
 * Associates an EID prefix with a Security Group Tag so the local xTR
 * knows which SGT to stamp on outgoing packets destined for that EID, and
 * can verify the SGT on arriving packets claiming to come from that EID.
 * ---------------------------------------------------------------------- */

struct lisp_sgt_map {
	/* EID prefix covered by this entry. */
	struct prefix  eid_prefix;

	/* Security Group Tag for this EID/group. */
	uint16_t       sgt;

	/* Route-node back-pointer (in lisp->sgt_table). */
	struct route_node *rn;
};

/* -------------------------------------------------------------------------
 * GBP policy rule
 *
 * A simple ordered list of (src_sgt, dst_sgt) → permit/deny rules.
 * Rules are evaluated in list order; the first match wins.
 * If no rule matches, the default action (lisp->gbp_default_permit) applies.
 * ---------------------------------------------------------------------- */

struct lisp_gbp_policy {
	/*
	 * Source and destination SGTs.
	 * Use LISP_SGT_UNTAGGED (0) to match any / wildcard.
	 */
	uint16_t  src_sgt;
	uint16_t  dst_sgt;

	/* true = permit, false = deny. */
	bool      permit;

	/* Human-readable description (optional). */
	char      description[64];

	/* Back-pointer to LISP instance. */
	struct lisp *lisp;
};

/* -------------------------------------------------------------------------
 * Per-VRF VxLAN-GPE state (embedded in struct lisp)
 *
 * This block is added to struct lisp in lispd.h; it is declared here for
 * easy cross-reference.
 *
 *   int           data_sock       — UDP socket on port 4789
 *   struct thread *t_data_read    — I/O thread for data_sock
 *   uint32_t      default_vni     — VNI for this VRF/instance
 *   uint16_t      local_sgt       — SGT stamped on packets *sent* by this xTR
 *   bool          gbp_enabled     — GBP enforcement active
 *   bool          gbp_default_permit — default action when no policy matches
 *   struct route_table *sgt_table — EID → SGT map (lisp_sgt_map)
 *   struct list   *gbp_policies   — ordered list of lisp_gbp_policy
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * Function prototypes
 * ---------------------------------------------------------------------- */

/* Codec ----------------------------------------------------------------- */

/*
 * Encode a VxLAN-GPE header into stream s.
 * vni:       24-bit VNI (set I-flag automatically).
 * next_proto: LISP_VXLAN_NP_* code (set P-flag automatically).
 * sgt:       14-bit SGT; pass LISP_SGT_UNTAGGED to suppress GBP (G=0).
 * dont_learn / applied: GBP control bits (ignored when sgt == 0).
 */
extern int lisp_vxlan_gpe_encode(struct stream *s,
				 uint32_t vni,
				 uint8_t  next_proto,
				 uint16_t sgt,
				 bool     dont_learn,
				 bool     applied);

/*
 * Decode the 8-byte VxLAN-GPE header from stream s into hdr.
 * Returns 0 on success, -1 on parse error.
 */
extern int lisp_vxlan_gpe_decode(struct stream *s,
				 struct lisp_vxlan_gpe_hdr *hdr);

/* Packet send / receive ------------------------------------------------- */

/*
 * Encapsulate inner_buf (inner_len bytes) in VxLAN-GPE and send it
 * to dst_rloc (IPv4) using the data socket.
 *
 * The next protocol is inferred from the first nibble of inner_buf
 * (0x4→IPv4, 0x6→IPv6).  sgt == LISP_SGT_UNTAGGED suppresses GBP.
 */
extern int lisp_vxlan_send(struct lisp *lisp,
			   const struct prefix *dst_rloc,
			   uint32_t vni,
			   uint16_t sgt,
			   const uint8_t *inner_buf,
			   size_t inner_len);

/*
 * Thread callback: read one VxLAN-GPE packet from the data socket,
 * decap, apply GBP policy, and forward the inner payload.
 */
extern int lisp_vxlan_recv_packet(struct thread *t);

/* Socket management ----------------------------------------------------- */

extern int lisp_vxlan_create_socket(struct vrf *vrf);

/* SGT map --------------------------------------------------------------- */

extern void lisp_sgt_map_add(struct lisp *lisp,
			     const struct prefix *eid,
			     uint16_t sgt);

extern uint16_t lisp_sgt_map_lookup(struct lisp *lisp,
				    const struct prefix *eid);

extern void lisp_sgt_map_delete(struct lisp *lisp,
				const struct prefix *eid);

extern void lisp_sgt_map_clean(struct lisp *lisp);

/* GBP policy ------------------------------------------------------------ */

extern void lisp_gbp_policy_add(struct lisp *lisp,
				uint16_t src_sgt, uint16_t dst_sgt,
				bool permit, const char *description);

extern void lisp_gbp_policy_delete(struct lisp *lisp,
				   uint16_t src_sgt, uint16_t dst_sgt);

/*
 * Evaluate GBP policy for a packet arriving with src_sgt destined to an
 * EID that belongs to dst_sgt.  Returns true if the packet is permitted.
 */
extern bool lisp_gbp_policy_apply(struct lisp *lisp,
				  uint16_t src_sgt, uint16_t dst_sgt);

extern void lisp_gbp_policy_clean(struct lisp *lisp);

/* CLI ------------------------------------------------------------------- */

extern void lisp_vxlan_cli_init(void);

#endif /* _LISP_VXLAN_H */
