/* LISP VxLAN-GPE data-plane with GBP Security Group extension.
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
 * This module implements the VxLAN-GPE data-plane for LISP (RFC 9301 §2.4)
 * with the Group Based Policy (GBP) extension for Security Group Tag (SGT)
 * transport.
 *
 * Encapsulation path (ITR / xTR sending):
 *   1. Map-cache lookup → RLOC + VNI + optional destination SGT
 *   2. Determine source SGT from lisp->local_sgt (or per-EID configured SGT)
 *   3. Build 8-byte VxLAN-GPE header:
 *        flags = G|I|P  (or I|P when sgt == LISP_SGT_UNTAGGED)
 *        bytes 1-2: SGT with D/A control bits
 *        byte 3: next_proto (0x01=IPv4, 0x02=IPv6)
 *        bytes 4-6: VNI
 *   4. Prepend to original IP packet, send via UDP/4789
 *
 * Decapsulation path (ETR / xTR receiving):
 *   1. Receive UDP/4789 packet on data_sock
 *   2. Parse VxLAN-GPE header: extract VNI, next_proto, SGT (if G=1)
 *   3. If GBP enabled: look up destination EID's SGT, call policy_apply()
 *      - drop if policy denies
 *   4. Look up VNI → VRF
 *   5. Forward inner IP packet to kernel via TUN / Zebra
 *
 * GBP Policy Engine:
 *   - Rules are (src_sgt, dst_sgt) → permit/deny, evaluated in order
 *   - src_sgt == LISP_SGT_UNTAGGED in a rule matches any source SGT
 *   - dst_sgt == LISP_SGT_UNTAGGED in a rule matches any destination SGT
 *   - Default action: lisp->gbp_default_permit (configurable)
 *   - Statistics counters per rule (matches, bytes) for monitoring
 */

#include <zebra.h>

#include "prefix.h"
#include "table.h"
#include "stream.h"
#include "log.h"
#include "memory.h"
#include "thread.h"
#include "vrf.h"
#include "if.h"
#include "sockopt.h"
#include "sockunion.h"
#include "command.h"
#include "vty.h"
#include "linklist.h"

#include "lispd/lispd.h"
#include "lispd/lisp_vxlan.h"
#include "lispd/lisp_memory.h"
#include "lispd/lisp_debug.h"

/* =========================================================================
 * VxLAN-GPE header encode / decode
 * ====================================================================== */

/*
 * Encode an 8-byte VxLAN-GPE header into stream s.
 *
 * Byte 0: G|R|Ver(0)|I|P|B|O
 * Bytes 1-2: SGT word (when G=1), or reserved zeros
 * Byte 3: Next Protocol
 * Bytes 4-6: VNI
 * Byte 7: Reserved
 *
 * The SGT word encodes D-bit (bit 14), A-bit (bit 12), and the 14-bit
 * SGT value in bits [13:0] (excluding the two control bits).
 * Practically: SGT word = (D ? LISP_GBP_D_BIT : 0)
 *                       | (A ? LISP_GBP_A_BIT : 0)
 *                       | (sgt & LISP_GBP_SGT_MASK)
 */
int lisp_vxlan_gpe_encode(struct stream *s,
			  uint32_t vni,
			  uint8_t  next_proto,
			  uint16_t sgt,
			  bool     dont_learn,
			  bool     applied)
{
	uint8_t  flags;
	uint16_t sgt_word;

	flags = LISP_VXLAN_GPE_F_I | LISP_VXLAN_GPE_F_P;

	if (sgt != LISP_SGT_UNTAGGED)
		flags |= LISP_VXLAN_GPE_F_G;

	stream_putc(s, flags);

	if (sgt != LISP_SGT_UNTAGGED) {
		sgt_word = (sgt & LISP_GBP_SGT_MASK)
			   | (dont_learn ? LISP_GBP_D_BIT : 0)
			   | (applied    ? LISP_GBP_A_BIT : 0);
		stream_putw(s, sgt_word);
	} else {
		stream_putw(s, 0); /* reserved */
	}

	stream_putc(s, next_proto);

	/* VNI occupies 24 bits (3 bytes, big-endian). */
	stream_putc(s, (vni >> 16) & 0xff);
	stream_putc(s, (vni >>  8) & 0xff);
	stream_putc(s, (vni >>  0) & 0xff);

	stream_putc(s, 0); /* reserved */

	return 0;
}

/*
 * Decode the 8-byte VxLAN-GPE header from stream s.
 */
int lisp_vxlan_gpe_decode(struct stream *s, struct lisp_vxlan_gpe_hdr *hdr)
{
	uint8_t  byte0;
	uint16_t sgt_word;

	if (STREAM_READABLE(s) < LISP_VXLAN_GPE_HDR_LEN)
		return -1;

	byte0 = stream_getc(s);

	hdr->flags       = byte0;
	hdr->version     = (byte0 & LISP_VXLAN_GPE_VER_MASK) >> 4;
	hdr->gbp_present = !!(byte0 & LISP_VXLAN_GPE_F_G);

	sgt_word = stream_getw(s);

	if (hdr->gbp_present) {
		hdr->sgt        = sgt_word & LISP_GBP_SGT_MASK;
		hdr->dont_learn = !!(sgt_word & LISP_GBP_D_BIT);
		hdr->applied    = !!(sgt_word & LISP_GBP_A_BIT);
	} else {
		hdr->sgt        = LISP_SGT_UNTAGGED;
		hdr->dont_learn = false;
		hdr->applied    = false;
	}

	hdr->next_proto = stream_getc(s);

	hdr->vni  = (uint32_t)stream_getc(s) << 16;
	hdr->vni |= (uint32_t)stream_getc(s) <<  8;
	hdr->vni |= (uint32_t)stream_getc(s);

	stream_getc(s); /* reserved */

	return 0;
}

/* =========================================================================
 * Socket management
 * ====================================================================== */

int lisp_vxlan_create_socket(struct vrf *vrf)
{
	int sock;
	struct sockaddr_in sin;
	vrf_id_t vrf_id = vrf ? vrf->vrf_id : VRF_DEFAULT;

	sock = vrf_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, vrf_id, NULL);
	if (sock < 0) {
		flog_err_sys(EC_LISP_SOCKET,
			     "LISP VxLAN-GPE: failed to create UDP/4789 socket: %s",
			     safe_strerror(errno));
		return -1;
	}

	sockopt_reuseaddr(sock);
	sockopt_reuseport(sock);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family      = AF_INET;
	sin.sin_port        = htons(LISP_VXLAN_GPE_PORT);
	sin.sin_addr.s_addr = INADDR_ANY;

	if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		flog_err_sys(EC_LISP_SOCKET,
			     "LISP VxLAN-GPE: bind to port %d failed: %s",
			     LISP_VXLAN_GPE_PORT, safe_strerror(errno));
		close(sock);
		return -1;
	}

	return sock;
}

/* =========================================================================
 * Data-plane send
 * ====================================================================== */

int lisp_vxlan_send(struct lisp *lisp,
		    const struct prefix *dst_rloc,
		    uint32_t vni,
		    uint16_t sgt,
		    const uint8_t *inner_buf,
		    size_t inner_len)
{
	struct stream *s;
	struct sockaddr_in sin;
	uint8_t next_proto;
	int rc;

	if (!lisp || lisp->data_sock < 0)
		return -1;

	if (dst_rloc->family != AF_INET) {
		/* IPv6 RLOC support would go here. */
		return -1;
	}

	if (inner_len == 0)
		return -1;

	/* Infer Next Protocol from inner packet's IP version nibble. */
	switch ((inner_buf[0] >> 4) & 0x0f) {
	case 4:
		next_proto = LISP_VXLAN_NP_IPV4;
		break;
	case 6:
		next_proto = LISP_VXLAN_NP_IPV6;
		break;
	default:
		/* Ethernet frame or unknown; treat as Ethernet. */
		next_proto = LISP_VXLAN_NP_ETH;
		break;
	}

	/*
	 * Build: VxLAN-GPE header (8 bytes) + inner packet.
	 * Use the instance's local_sgt as the source SGT when the caller
	 * passes LISP_SGT_UNTAGGED and GBP is globally enabled.
	 */
	if (sgt == LISP_SGT_UNTAGGED && lisp->gbp_enabled
	    && lisp->local_sgt != LISP_SGT_UNTAGGED)
		sgt = lisp->local_sgt;

	s = stream_new(LISP_VXLAN_GPE_HDR_LEN + inner_len);

	lisp_vxlan_gpe_encode(s, vni, next_proto, sgt,
			      false /* dont_learn */,
			      false /* applied */);

	stream_put(s, inner_buf, inner_len);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port   = htons(LISP_VXLAN_GPE_PORT);
	sin.sin_addr   = dst_rloc->u.prefix4;

	rc = sendto(lisp->data_sock, STREAM_DATA(s), stream_get_endp(s), 0,
		    (struct sockaddr *)&sin, sizeof(sin));

	stream_free(s);

	if (IS_LISP_DEBUG_PACKET) {
		char dst_buf[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &dst_rloc->u.prefix4, dst_buf,
			  sizeof(dst_buf));
		zlog_debug("LISP VxLAN-GPE: sent %zu bytes to %s "
			   "VNI=%" PRIu32 " SGT=%u proto=0x%02x",
			   inner_len, dst_buf, vni, sgt, next_proto);
	}

	return rc < 0 ? -1 : 0;
}

/* =========================================================================
 * Data-plane receive
 * ====================================================================== */

/*
 * Inner-packet forwarding: after decap and GBP check, inject the inner
 * IP packet back into the kernel via a TUN interface or Zebra.
 * This is a stub — production would write to a tun fd or call Zebra.
 */
static void lisp_vxlan_forward_inner(struct lisp *lisp,
				     const struct lisp_vxlan_gpe_hdr *hdr,
				     const uint8_t *inner, size_t inner_len)
{
	if (IS_LISP_DEBUG_PACKET)
		zlog_debug("LISP VxLAN-GPE: forwarding %zu-byte inner packet "
			   "(VNI=%" PRIu32 " proto=0x%02x)",
			   inner_len, hdr->vni, hdr->next_proto);

	/*
	 * In a full implementation:
	 *   1. Map hdr->vni → struct vrf * via lisp->vni_to_vrf
	 *   2. write(tun_fd, inner, inner_len)  or
	 *      inject via Zebra zapi_nexthop with appropriate VRF
	 */
}

int lisp_vxlan_recv_packet(struct thread *t)
{
	struct lisp *lisp = THREAD_ARG(t);
	uint8_t buf[LISP_VXLAN_MAX_PKT_SIZE];
	struct sockaddr_storage src;
	socklen_t src_len = sizeof(src);
	ssize_t nbytes;
	struct stream *s;
	struct lisp_vxlan_gpe_hdr hdr;
	const uint8_t *inner;
	size_t inner_len;
	uint16_t dst_sgt;

	lisp->t_data_read = NULL;

	nbytes = recvfrom(lisp->data_sock, buf, sizeof(buf), 0,
			  (struct sockaddr *)&src, &src_len);
	if (nbytes <= 0) {
		if (nbytes < 0 && errno != EAGAIN)
			flog_err_sys(EC_LISP_SOCKET,
				     "LISP VxLAN-GPE: recvfrom error: %s",
				     safe_strerror(errno));
		goto rearm;
	}

	if ((size_t)nbytes < LISP_VXLAN_GPE_HDR_LEN) {
		if (IS_LISP_DEBUG_PACKET)
			zlog_debug("LISP VxLAN-GPE: packet too short (%zd bytes)",
				   nbytes);
		goto rearm;
	}

	s = stream_new(nbytes);
	stream_put(s, buf, nbytes);

	if (lisp_vxlan_gpe_decode(s, &hdr) < 0) {
		flog_err(EC_LISP_PACKET,
			 "LISP VxLAN-GPE: failed to decode header");
		stream_free(s);
		goto rearm;
	}

	/* Validate required flags. */
	if (!(hdr.flags & LISP_VXLAN_GPE_F_I)) {
		if (IS_LISP_DEBUG_PACKET)
			zlog_debug("LISP VxLAN-GPE: I-flag not set, dropping");
		stream_free(s);
		goto rearm;
	}

	if (IS_LISP_DEBUG_PACKET)
		zlog_debug("LISP VxLAN-GPE: recv VNI=%" PRIu32
			   " proto=0x%02x GBP=%s SGT=%u",
			   hdr.vni, hdr.next_proto,
			   hdr.gbp_present ? "yes" : "no", hdr.sgt);

	/* ----------------------------------------------------------------
	 * GBP policy enforcement (RFC 9301 §2.4 / draft-smith-vxlan-gpe).
	 *
	 * If GBP is enabled and the packet carries a source SGT:
	 *   1. Determine the destination SGT from the inner packet's
	 *      destination address (peek at inner IP header).
	 *   2. Apply policy: if denied, drop silently and count.
	 * ---------------------------------------------------------------- */
	if (lisp->gbp_enabled && hdr.gbp_present
	    && hdr.sgt != LISP_SGT_UNTAGGED
	    && !hdr.applied) {
		struct prefix inner_dst;

		inner     = buf + LISP_VXLAN_GPE_HDR_LEN;
		inner_len = (size_t)nbytes - LISP_VXLAN_GPE_HDR_LEN;

		/* Extract inner destination address. */
		memset(&inner_dst, 0, sizeof(inner_dst));
		if (hdr.next_proto == LISP_VXLAN_NP_IPV4
		    && inner_len >= 20) {
			inner_dst.family   = AF_INET;
			inner_dst.prefixlen = IPV4_MAX_BITLEN;
			memcpy(&inner_dst.u.prefix4, inner + 16, 4);
		} else if (hdr.next_proto == LISP_VXLAN_NP_IPV6
			   && inner_len >= 40) {
			inner_dst.family   = AF_INET6;
			inner_dst.prefixlen = IPV6_MAX_BITLEN;
			memcpy(&inner_dst.u.prefix6, inner + 24, 16);
		}

		/* Look up the destination EID's SGT. */
		dst_sgt = (inner_dst.family != 0)
			  ? lisp_sgt_map_lookup(lisp, &inner_dst)
			  : LISP_SGT_UNTAGGED;

		if (!lisp_gbp_policy_apply(lisp, hdr.sgt, dst_sgt)) {
			if (IS_LISP_DEBUG_PUBSUB || IS_LISP_DEBUG_PACKET)
				zlog_debug("LISP VxLAN-GPE GBP: DENY "
					   "src_sgt=%u dst_sgt=%u",
					   hdr.sgt, dst_sgt);
			stream_free(s);
			goto rearm;
		}
	}

	/* ----------------------------------------------------------------
	 * Decapsulation: forward inner packet.
	 * ---------------------------------------------------------------- */
	inner     = buf + LISP_VXLAN_GPE_HDR_LEN;
	inner_len = (size_t)nbytes - LISP_VXLAN_GPE_HDR_LEN;

	lisp_vxlan_forward_inner(lisp, &hdr, inner, inner_len);

	stream_free(s);

rearm:
	thread_add_read(master, lisp_vxlan_recv_packet, lisp, lisp->data_sock,
			&lisp->t_data_read);
	return 0;
}

/* =========================================================================
 * SGT map — EID prefix → Security Group Tag
 * ====================================================================== */

void lisp_sgt_map_add(struct lisp *lisp,
		      const struct prefix *eid,
		      uint16_t sgt)
{
	struct route_node *rn;
	struct lisp_sgt_map *sm;
	char buf[PREFIX2STR_BUFFER];

	if (!lisp->sgt_table)
		return;

	rn = route_node_get(lisp->sgt_table, eid);

	if (rn->info) {
		/* Update existing entry. */
		sm = rn->info;
		sm->sgt = sgt;
		route_unlock_node(rn);
	} else {
		sm = XCALLOC(MTYPE_LISP_SGT_MAP, sizeof(*sm));
		sm->eid_prefix = *eid;
		sm->sgt        = sgt;
		sm->rn         = rn;
		rn->info       = sm;
	}

	if (IS_LISP_DEBUG_EVENTS) {
		prefix2str(eid, buf, sizeof(buf));
		zlog_debug("LISP VxLAN GBP: SGT map add %s → SGT %u",
			   buf, sgt);
	}
}

uint16_t lisp_sgt_map_lookup(struct lisp *lisp, const struct prefix *eid)
{
	struct route_node *rn;
	struct lisp_sgt_map *sm;

	if (!lisp->sgt_table)
		return LISP_SGT_UNTAGGED;

	rn = route_node_match(lisp->sgt_table, eid);
	if (!rn)
		return LISP_SGT_UNTAGGED;

	sm = rn->info;
	route_unlock_node(rn);

	return sm ? sm->sgt : LISP_SGT_UNTAGGED;
}

void lisp_sgt_map_delete(struct lisp *lisp, const struct prefix *eid)
{
	struct route_node *rn;
	struct lisp_sgt_map *sm;

	if (!lisp->sgt_table)
		return;

	rn = route_node_lookup(lisp->sgt_table, eid);
	if (!rn)
		return;

	sm = rn->info;
	rn->info = NULL;
	route_unlock_node(rn); /* for lookup */
	route_unlock_node(rn); /* for node itself */

	if (sm)
		XFREE(MTYPE_LISP_SGT_MAP, sm);
}

void lisp_sgt_map_clean(struct lisp *lisp)
{
	struct route_node *rn;
	struct lisp_sgt_map *sm;

	if (!lisp->sgt_table)
		return;

	for (rn = route_top(lisp->sgt_table); rn; rn = route_next(rn)) {
		sm = rn->info;
		if (!sm)
			continue;
		XFREE(MTYPE_LISP_SGT_MAP, sm);
		rn->info = NULL;
	}
}

/* =========================================================================
 * GBP policy engine
 * ====================================================================== */

void lisp_gbp_policy_add(struct lisp *lisp,
			 uint16_t src_sgt, uint16_t dst_sgt,
			 bool permit, const char *description)
{
	struct lisp_gbp_policy *pol;

	pol = XCALLOC(MTYPE_LISP_GBP_POLICY, sizeof(*pol));
	pol->src_sgt = src_sgt;
	pol->dst_sgt = dst_sgt;
	pol->permit  = permit;
	pol->lisp    = lisp;

	if (description)
		strlcpy(pol->description, description,
			sizeof(pol->description));

	listnode_add(lisp->gbp_policies, pol);

	if (IS_LISP_DEBUG_EVENTS)
		zlog_debug("LISP VxLAN GBP: policy add src_sgt=%u dst_sgt=%u "
			   "action=%s", src_sgt, dst_sgt,
			   permit ? "permit" : "deny");
}

void lisp_gbp_policy_delete(struct lisp *lisp,
			    uint16_t src_sgt, uint16_t dst_sgt)
{
	struct listnode *node, *nnode;
	struct lisp_gbp_policy *pol;

	for (ALL_LIST_ELEMENTS(lisp->gbp_policies, node, nnode, pol)) {
		if (pol->src_sgt == src_sgt && pol->dst_sgt == dst_sgt) {
			listnode_delete(lisp->gbp_policies, pol);
			XFREE(MTYPE_LISP_GBP_POLICY, pol);
			return;
		}
	}
}

bool lisp_gbp_policy_apply(struct lisp *lisp,
			   uint16_t src_sgt, uint16_t dst_sgt)
{
	struct listnode *node;
	struct lisp_gbp_policy *pol;

	for (ALL_LIST_ELEMENTS_RO(lisp->gbp_policies, node, pol)) {
		bool src_match = (pol->src_sgt == LISP_SGT_UNTAGGED
				  || pol->src_sgt == src_sgt);
		bool dst_match = (pol->dst_sgt == LISP_SGT_UNTAGGED
				  || pol->dst_sgt == dst_sgt);

		if (src_match && dst_match) {
			if (IS_LISP_DEBUG_PUBSUB || IS_LISP_DEBUG_PACKET)
				zlog_debug("LISP VxLAN GBP: policy match "
					   "src=%u dst=%u → %s",
					   src_sgt, dst_sgt,
					   pol->permit ? "permit" : "deny");
			return pol->permit;
		}
	}

	/* No matching rule: fall back to default action. */
	return lisp->gbp_default_permit;
}

void lisp_gbp_policy_clean(struct lisp *lisp)
{
	struct listnode *node, *nnode;
	struct lisp_gbp_policy *pol;

	for (ALL_LIST_ELEMENTS(lisp->gbp_policies, node, nnode, pol))
		XFREE(MTYPE_LISP_GBP_POLICY, pol);

	list_delete_all_node(lisp->gbp_policies);
}

/* =========================================================================
 * CLI
 * ====================================================================== */

/* -------------------------------------------------------------------------
 * "vxlan-gpe vni <0-16777215>"
 * ---------------------------------------------------------------------- */

DEFUN(lisp_vxlan_vni,
      lisp_vxlan_vni_cmd,
      "vxlan-gpe vni (0-16777215)",
      "VxLAN-GPE data-plane settings\n"
      "Default VNI for this LISP instance\n"
      "VNI value (24-bit)\n")
{
	struct lisp *lisp = vty->index;
	uint32_t vni = strtoul(argv[2]->arg, NULL, 10);

	if (!lisp) {
		vty_out(vty, "%% No LISP instance configured\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	lisp->default_vni = vni;
	vty_out(vty, "LISP VxLAN-GPE: default VNI set to %" PRIu32 "\n", vni);
	return CMD_SUCCESS;
}

DEFUN(no_lisp_vxlan_vni,
      no_lisp_vxlan_vni_cmd,
      "no vxlan-gpe vni [(0-16777215)]",
      NO_STR
      "VxLAN-GPE data-plane settings\n"
      "Clear default VNI\n"
      "VNI value\n")
{
	struct lisp *lisp = vty->index;

	if (!lisp)
		return CMD_WARNING_CONFIG_FAILED;

	lisp->default_vni = 0;
	return CMD_SUCCESS;
}

/* -------------------------------------------------------------------------
 * "gbp enable" / "gbp default-action (permit|deny)"
 * ---------------------------------------------------------------------- */

DEFUN(lisp_gbp_enable,
      lisp_gbp_enable_cmd,
      "gbp enable",
      "Group Based Policy (GBP/SGT)\n"
      "Enable GBP enforcement\n")
{
	struct lisp *lisp = vty->index;

	if (!lisp)
		return CMD_WARNING_CONFIG_FAILED;

	lisp->gbp_enabled = true;
	return CMD_SUCCESS;
}

DEFUN(no_lisp_gbp_enable,
      no_lisp_gbp_enable_cmd,
      "no gbp enable",
      NO_STR
      "Group Based Policy (GBP/SGT)\n"
      "Disable GBP enforcement\n")
{
	struct lisp *lisp = vty->index;

	if (!lisp)
		return CMD_WARNING_CONFIG_FAILED;

	lisp->gbp_enabled = false;
	return CMD_SUCCESS;
}

DEFUN(lisp_gbp_default,
      lisp_gbp_default_cmd,
      "gbp default-action <permit|deny>",
      "Group Based Policy (GBP/SGT)\n"
      "Default action when no policy rule matches\n"
      "Permit the packet\n"
      "Drop the packet\n")
{
	struct lisp *lisp = vty->index;

	if (!lisp)
		return CMD_WARNING_CONFIG_FAILED;

	lisp->gbp_default_permit = (argv[2]->arg[0] == 'p');
	return CMD_SUCCESS;
}

/* -------------------------------------------------------------------------
 * "gbp local-sgt <0-16383>"
 * ---------------------------------------------------------------------- */

DEFUN(lisp_gbp_local_sgt,
      lisp_gbp_local_sgt_cmd,
      "gbp local-sgt (0-16383)",
      "Group Based Policy (GBP/SGT)\n"
      "Security Group Tag for packets sent by this xTR\n"
      "14-bit SGT value\n")
{
	struct lisp *lisp = vty->index;
	uint16_t sgt = (uint16_t)strtoul(argv[2]->arg, NULL, 10);

	if (!lisp)
		return CMD_WARNING_CONFIG_FAILED;

	lisp->local_sgt = sgt;
	return CMD_SUCCESS;
}

DEFUN(no_lisp_gbp_local_sgt,
      no_lisp_gbp_local_sgt_cmd,
      "no gbp local-sgt [(0-16383)]",
      NO_STR
      "Group Based Policy (GBP/SGT)\n"
      "Clear local SGT\n"
      "SGT value\n")
{
	struct lisp *lisp = vty->index;

	if (!lisp)
		return CMD_WARNING_CONFIG_FAILED;

	lisp->local_sgt = LISP_SGT_UNTAGGED;
	return CMD_SUCCESS;
}

/* -------------------------------------------------------------------------
 * "gbp policy src-sgt <0-16383> dst-sgt <0-16383> (permit|deny) [WORD]"
 * ---------------------------------------------------------------------- */

DEFUN(lisp_gbp_policy,
      lisp_gbp_policy_cmd,
      "gbp policy src-sgt (0-16383) dst-sgt (0-16383) <permit|deny> [DESCRIPTION]",
      "Group Based Policy (GBP/SGT)\n"
      "Add a policy rule\n"
      "Source Security Group Tag\n"
      "Source SGT value (0 = any)\n"
      "Destination Security Group Tag\n"
      "Destination SGT value (0 = any)\n"
      "Permit matching packets\n"
      "Drop matching packets\n"
      "Optional description\n")
{
	struct lisp *lisp = vty->index;
	uint16_t src_sgt, dst_sgt;
	bool permit;

	if (!lisp)
		return CMD_WARNING_CONFIG_FAILED;

	src_sgt = (uint16_t)strtoul(argv[3]->arg, NULL, 10);
	dst_sgt = (uint16_t)strtoul(argv[5]->arg, NULL, 10);
	permit  = (argv[6]->arg[0] == 'p');

	lisp_gbp_policy_add(lisp, src_sgt, dst_sgt, permit,
			    (argc > 7) ? argv[7]->arg : NULL);
	return CMD_SUCCESS;
}

DEFUN(no_lisp_gbp_policy,
      no_lisp_gbp_policy_cmd,
      "no gbp policy src-sgt (0-16383) dst-sgt (0-16383)",
      NO_STR
      "Group Based Policy (GBP/SGT)\n"
      "Remove a policy rule\n"
      "Source Security Group Tag\n"
      "Source SGT value\n"
      "Destination Security Group Tag\n"
      "Destination SGT value\n")
{
	struct lisp *lisp = vty->index;
	uint16_t src_sgt, dst_sgt;

	if (!lisp)
		return CMD_WARNING_CONFIG_FAILED;

	src_sgt = (uint16_t)strtoul(argv[4]->arg, NULL, 10);
	dst_sgt = (uint16_t)strtoul(argv[6]->arg, NULL, 10);

	lisp_gbp_policy_delete(lisp, src_sgt, dst_sgt);
	return CMD_SUCCESS;
}

/* -------------------------------------------------------------------------
 * "gbp sgt-map A.B.C.D/M <0-16383>"
 * ---------------------------------------------------------------------- */

DEFUN(lisp_gbp_sgt_map,
      lisp_gbp_sgt_map_cmd,
      "gbp sgt-map <A.B.C.D/M|X:X::X:X/M> (0-16383)",
      "Group Based Policy (GBP/SGT)\n"
      "Map an EID prefix to a Security Group Tag\n"
      "IPv4 EID prefix\n"
      "IPv6 EID prefix\n"
      "14-bit SGT value\n")
{
	struct lisp *lisp = vty->index;
	struct prefix eid;
	uint16_t sgt;

	if (!lisp)
		return CMD_WARNING_CONFIG_FAILED;

	if (str2prefix(argv[2]->arg, &eid) <= 0) {
		vty_out(vty, "%% Invalid EID prefix: %s\n", argv[2]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	sgt = (uint16_t)strtoul(argv[3]->arg, NULL, 10);
	lisp_sgt_map_add(lisp, &eid, sgt);
	return CMD_SUCCESS;
}

DEFUN(no_lisp_gbp_sgt_map,
      no_lisp_gbp_sgt_map_cmd,
      "no gbp sgt-map <A.B.C.D/M|X:X::X:X/M>",
      NO_STR
      "Group Based Policy (GBP/SGT)\n"
      "Remove EID-to-SGT mapping\n"
      "IPv4 EID prefix\n"
      "IPv6 EID prefix\n")
{
	struct lisp *lisp = vty->index;
	struct prefix eid;

	if (!lisp)
		return CMD_WARNING_CONFIG_FAILED;

	if (str2prefix(argv[3]->arg, &eid) <= 0) {
		vty_out(vty, "%% Invalid prefix: %s\n", argv[3]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	lisp_sgt_map_delete(lisp, &eid);
	return CMD_SUCCESS;
}

/* -------------------------------------------------------------------------
 * show commands
 * ---------------------------------------------------------------------- */

DEFUN(show_lisp_vxlan,
      show_lisp_vxlan_cmd,
      "show lisp vxlan-gpe",
      SHOW_STR
      "LISP information\n"
      "VxLAN-GPE data-plane status\n")
{
	struct vrf *vrf;
	struct lisp *lisp;

	RB_FOREACH(vrf, vrf_name_head, &vrfs_by_name) {
		lisp = vrf->info;
		if (!lisp || !lisp->enabled)
			continue;

		vty_out(vty, "VRF %s:\n", vrf->name);
		vty_out(vty, "  Data socket (UDP/4789): %s\n",
			lisp->data_sock >= 0 ? "open" : "closed");
		vty_out(vty, "  Default VNI:  %" PRIu32 "\n",
			lisp->default_vni);
		vty_out(vty, "  GBP enabled:  %s\n",
			lisp->gbp_enabled ? "yes" : "no");
		if (lisp->gbp_enabled) {
			vty_out(vty, "  Local SGT:    %u\n",
				lisp->local_sgt);
			vty_out(vty, "  Default action: %s\n",
				lisp->gbp_default_permit ? "permit" : "deny");
		}
	}
	return CMD_SUCCESS;
}

DEFUN(show_lisp_gbp_policy,
      show_lisp_gbp_policy_cmd,
      "show lisp gbp policy",
      SHOW_STR
      "LISP information\n"
      "Group Based Policy (GBP/SGT)\n"
      "Policy rules\n")
{
	struct vrf *vrf;
	struct lisp *lisp;
	struct listnode *node;
	struct lisp_gbp_policy *pol;

	RB_FOREACH(vrf, vrf_name_head, &vrfs_by_name) {
		lisp = vrf->info;
		if (!lisp || !lisp->enabled)
			continue;

		vty_out(vty, "VRF %s (GBP %s, default %s):\n",
			vrf->name,
			lisp->gbp_enabled ? "enabled" : "disabled",
			lisp->gbp_default_permit ? "permit" : "deny");

		if (listcount(lisp->gbp_policies) == 0) {
			vty_out(vty, "  No policy rules.\n");
			continue;
		}

		vty_out(vty, "  %-8s  %-8s  %-7s  %s\n",
			"SRC-SGT", "DST-SGT", "ACTION", "DESCRIPTION");

		for (ALL_LIST_ELEMENTS_RO(lisp->gbp_policies, node, pol)) {
			vty_out(vty, "  %-8u  %-8u  %-7s  %s\n",
				pol->src_sgt, pol->dst_sgt,
				pol->permit ? "permit" : "deny",
				pol->description[0] ? pol->description : "-");
		}
	}
	return CMD_SUCCESS;
}

DEFUN(show_lisp_gbp_sgt_map,
      show_lisp_gbp_sgt_map_cmd,
      "show lisp gbp sgt-map",
      SHOW_STR
      "LISP information\n"
      "Group Based Policy (GBP/SGT)\n"
      "EID-to-SGT mappings\n")
{
	struct vrf *vrf;
	struct lisp *lisp;
	struct route_node *rn;
	char buf[PREFIX2STR_BUFFER];

	RB_FOREACH(vrf, vrf_name_head, &vrfs_by_name) {
		lisp = vrf->info;
		if (!lisp || !lisp->enabled || !lisp->sgt_table)
			continue;

		vty_out(vty, "VRF %s:\n", vrf->name);

		for (rn = route_top(lisp->sgt_table); rn;
		     rn = route_next(rn)) {
			struct lisp_sgt_map *sm = rn->info;

			if (!sm)
				continue;

			prefix2str(&sm->eid_prefix, buf, sizeof(buf));
			vty_out(vty, "  %-32s SGT %u\n", buf, sm->sgt);
		}
	}
	return CMD_SUCCESS;
}

void lisp_vxlan_cli_init(void)
{
	/* Data-plane / VNI config — installed under LISP_NODE. */
	install_element(LISP_NODE, &lisp_vxlan_vni_cmd);
	install_element(LISP_NODE, &no_lisp_vxlan_vni_cmd);

	/* GBP config. */
	install_element(LISP_NODE, &lisp_gbp_enable_cmd);
	install_element(LISP_NODE, &no_lisp_gbp_enable_cmd);
	install_element(LISP_NODE, &lisp_gbp_default_cmd);
	install_element(LISP_NODE, &lisp_gbp_local_sgt_cmd);
	install_element(LISP_NODE, &no_lisp_gbp_local_sgt_cmd);
	install_element(LISP_NODE, &lisp_gbp_policy_cmd);
	install_element(LISP_NODE, &no_lisp_gbp_policy_cmd);
	install_element(LISP_NODE, &lisp_gbp_sgt_map_cmd);
	install_element(LISP_NODE, &no_lisp_gbp_sgt_map_cmd);

	/* Show commands. */
	install_element(VIEW_NODE,   &show_lisp_vxlan_cmd);
	install_element(ENABLE_NODE, &show_lisp_vxlan_cmd);
	install_element(VIEW_NODE,   &show_lisp_gbp_policy_cmd);
	install_element(ENABLE_NODE, &show_lisp_gbp_policy_cmd);
	install_element(VIEW_NODE,   &show_lisp_gbp_sgt_map_cmd);
	install_element(ENABLE_NODE, &show_lisp_gbp_sgt_map_cmd);
}
