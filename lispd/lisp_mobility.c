/* LISP EID Mobility (draft-ietf-lisp-eid-mobility-17).
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
 * Implements the EID mobility procedures from draft-ietf-lisp-eid-mobility-17:
 *
 * § 4  Map-Server database + Map-Register processing
 * § 5  Solicit-Map-Request (SMR) send/receive
 * § 5.3 Away Table: ETR tracks moved-away EIDs and generates data-driven SMRs
 *
 * Section references throughout the code refer to the above draft unless
 * otherwise noted.
 */

#include <zebra.h>

#include "prefix.h"
#include "table.h"
#include "stream.h"
#include "linklist.h"
#include "log.h"
#include "memory.h"
#include "thread.h"
#include "vty.h"
#include "command.h"
#include "sockunion.h"
#include "sockopt.h"
#include "vrf.h"

#include "lispd/lispd.h"
#include "lispd/lisp_mobility.h"
#include "lispd/lisp_packet.h"
#include "lispd/lisp_memory.h"
#include "lispd/lisp_debug.h"
#include "lispd/lisp_auth.h"
#include "lispd/lisp_pubsub.h"
#include "lispd/lisp_pubsub.h"

/* Master thread — defined in lisp_main.c, declared in lispd.h. */
extern struct thread_master *master;

/* =========================================================================
 * Helpers
 * ====================================================================== */

/*
 * Compare two RLOC lists for equality.
 *
 * Two lists are considered equal if they contain the same set of RLOC
 * addresses (order-independent, only address compared — not priority /
 * weight, since the MS only cares whether the locator itself changed).
 *
 * Returns true if the sets are identical.
 */
static bool rloc_lists_equal(const struct list *a, const struct list *b)
{
	struct listnode *na, *nb;
	struct lisp_rloc *ra, *rb;
	bool found;

	if (listcount(a) != listcount(b))
		return false;

	for (ALL_LIST_ELEMENTS_RO(a, na, ra)) {
		found = false;
		for (ALL_LIST_ELEMENTS_RO(b, nb, rb)) {
			if (prefix_same(&ra->rloc_addr, &rb->rloc_addr)) {
				found = true;
				break;
			}
		}
		if (!found)
			return false;
	}
	return true;
}

/*
 * Build a list of struct lisp_rloc * from the locator records in an
 * lisp_eid_record.  Returns a newly-allocated list (caller owns it).
 */
static struct list *rloc_list_from_eid_record(const struct lisp_eid_record *rec)
{
	struct list *lst;
	int i;

	lst = list_new();
	for (i = 0; i < rec->loc_count; i++) {
		struct lisp_rloc *r =
			XCALLOC(MTYPE_LISP_RLOC, sizeof(*r));

		prefix_copy(&r->rloc_addr,  &rec->locs[i].rloc);
		r->priority  = rec->locs[i].priority;
		r->weight    = rec->locs[i].weight;
		r->mpriority = rec->locs[i].mpriority;
		r->mweight   = rec->locs[i].mweight;
		r->local     = !!(rec->locs[i].flags & LISP_LOC_FLAG_L);
		r->reachable = !!(rec->locs[i].flags & LISP_LOC_FLAG_R);

		listnode_add(lst, r);
	}
	return lst;
}

static void rloc_list_free(struct list *lst)
{
	struct listnode *node, *nnode;
	struct lisp_rloc *r;

	for (ALL_LIST_ELEMENTS(lst, node, nnode, r))
		XFREE(MTYPE_LISP_RLOC, r);
	list_delete(&lst);
}

/* =========================================================================
 * MS entry expiry timer  (§4.3: TTL from Map-Register)
 * ====================================================================== */

static int lisp_ms_entry_expire(struct thread *t)
{
	struct lisp_ms_entry *me = THREAD_ARG(t);
	struct route_node *rn = me->rn;
	char buf[PREFIX2STR_BUFFER];

	me->t_expire = NULL;

	if (IS_LISP_DEBUG_MAPCACHE) {
		prefix2str(&me->eid_prefix, buf, sizeof(buf));
		zlog_debug("LISP mobility MS: entry %s expired", buf);
	}

	/* Withdraw pub/sub subscribers before removing (TTL=0). */
	lisp_pubsub_withdraw(me->lisp, &me->eid_prefix);

	rloc_list_free(me->rloc_list);
	me->rloc_list = NULL;

	{
		struct listnode *node, *nnode;
		struct lisp_itr_track *it;

		for (ALL_LIST_ELEMENTS(me->itr_cache, node, nnode, it))
			XFREE(MTYPE_LISP_ITR_TRACK, it);
		list_delete(&me->itr_cache);
	}

	XFREE(MTYPE_LISP_MS_ENTRY, me);
	rn->info = NULL;
	route_unlock_node(rn);
	return 0;
}

/* =========================================================================
 * MS database management
 * ====================================================================== */

struct lisp_ms_entry *
lisp_mobility_ms_lookup(struct lisp *lisp, const struct prefix *eid_prefix)
{
	struct route_node *rn;

	/*
	 * Use exact-match lookup: each MS entry corresponds to the exact
	 * EID-prefix that was registered, not a covering aggregate.
	 */
	rn = route_node_lookup(lisp->ms_db, eid_prefix);
	if (!rn)
		return NULL;
	route_unlock_node(rn);
	return rn->info;
}

/*
 * Create or fully replace an MS entry for eid_prefix.
 * The new RLOC list is adopted (caller must not free it).
 */
static struct lisp_ms_entry *
ms_entry_set(struct lisp *lisp, const struct prefix *eid_prefix,
	     struct list *rloc_list,
	     const uint8_t xtr_id[16], const uint8_t site_id[8],
	     uint32_t ttl, const struct prefix *xtr_rloc)
{
	struct route_node *rn;
	struct lisp_ms_entry *me;

	rn = route_node_get(lisp->ms_db, eid_prefix);
	me = rn->info;

	if (me) {
		/* Update existing entry. */
		THREAD_TIMER_OFF(me->t_expire);
		rloc_list_free(me->rloc_list);
		route_unlock_node(rn); /* route_node_get added a ref */
	} else {
		me = XCALLOC(MTYPE_LISP_MS_ENTRY, sizeof(*me));
		me->itr_cache = list_new();
		me->rn   = rn;
		me->lisp = lisp;
		prefix_copy(&me->eid_prefix, eid_prefix);
		rn->info = me;
	}

	me->rloc_list = rloc_list;
	me->ttl       = ttl;
	if (xtr_rloc)
		prefix_copy(&me->xtr_rloc, xtr_rloc);
	memcpy(me->xtr_id,  xtr_id,  16);
	memcpy(me->site_id, site_id, 8);

	/* Arm expiry timer (TTL is in minutes). */
	if (ttl != LISP_MAP_CACHE_TTL_PERMANENT && ttl != 0) {
		thread_add_timer(master, lisp_ms_entry_expire, me,
				 (long)ttl * 60, &me->t_expire);
	}

	return me;
}

void lisp_mobility_ms_db_clean(struct lisp *lisp)
{
	struct route_node *rn;
	struct lisp_ms_entry *me;

	for (rn = route_top(lisp->ms_db); rn; rn = route_next(rn)) {
		me = rn->info;
		if (!me)
			continue;
		THREAD_TIMER_OFF(me->t_expire);
		if (me->rloc_list)
			rloc_list_free(me->rloc_list);
		{
			struct listnode *node, *nnode;
			struct lisp_itr_track *it;

			for (ALL_LIST_ELEMENTS(me->itr_cache, node, nnode, it))
				XFREE(MTYPE_LISP_ITR_TRACK, it);
			list_delete(&me->itr_cache);
		}
		XFREE(MTYPE_LISP_MS_ENTRY, me);
		rn->info = NULL;
	}
}

/* =========================================================================
 * ITR-RLOC tracking  (§4.2)
 * ====================================================================== */

void lisp_mobility_track_itr(struct lisp *lisp,
			     const struct prefix *eid_prefix,
			     const struct prefix *itr_rloc)
{
	struct lisp_ms_entry *me;
	struct listnode *node;
	struct lisp_itr_track *it;

	if (!lisp->ms_role)
		return;

	me = lisp_mobility_ms_lookup(lisp, eid_prefix);
	if (!me)
		return; /* EID not in our database yet; ignore. */

	/* Avoid duplicates. */
	for (ALL_LIST_ELEMENTS_RO(me->itr_cache, node, it)) {
		if (prefix_same(&it->addr, itr_rloc))
			return;
	}

	it = XCALLOC(MTYPE_LISP_ITR_TRACK, sizeof(*it));
	prefix_copy(&it->addr, itr_rloc);
	listnode_add(me->itr_cache, it);

	if (IS_LISP_DEBUG_EVENTS) {
		char eid_buf[PREFIX2STR_BUFFER];
		char itr_buf[PREFIX2STR_BUFFER];

		prefix2str(eid_prefix, eid_buf, sizeof(eid_buf));
		prefix2str(itr_rloc,   itr_buf, sizeof(itr_buf));
		zlog_debug("LISP mobility MS: tracking ITR %s for EID %s",
			   itr_buf, eid_buf);
	}
}

/* =========================================================================
 * SMR sender  (§5.1)
 *
 * Sends a Map-Request with the S-bit set directly (no ECM wrapper) to
 * itr_rloc on UDP port 4342.  Upon receipt the ITR will invalidate its
 * stale cache entry and send an SMR-invoked Map-Request.
 * ====================================================================== */

void lisp_mobility_send_smr(struct lisp *lisp,
			    const struct prefix *eid_prefix,
			    const struct prefix *itr_rloc)
{
	struct lisp_map_request req;
	struct stream *s;
	struct sockaddr_in dst;

	if (lisp->sock < 0)
		return;

	if (!itr_rloc || itr_rloc->family != AF_INET)
		return;

	memset(&req, 0, sizeof(req));

	req.smr           = true;       /* S-bit: this is an SMR (§5.1) */
	req.record_count  = 1;
	req.itr_rloc_count = 1;

	lisp_nonce_generate(req.nonce);

	/*
	 * Source EID is set to the moved EID so the receiving ITR knows
	 * which cache entry to invalidate.
	 */
	prefix_copy(&req.src_eid, eid_prefix);
	prefix_copy(&req.records[0].eid_prefix, eid_prefix);

	/*
	 * ITR-RLOC in the SMR is our own RLOC (or any reachable address).
	 * We use the target ITR's address as a placeholder so the receiver
	 * can echo it back if needed; in practice the source IP of the UDP
	 * packet is sufficient for the ITR to reply.
	 */
	prefix_copy(&req.itr_rlocs[0], itr_rloc);

	s = stream_new(LISP_MAX_PACKET_SIZE);
	if (lisp_encode_map_request(s, &req) < 0) {
		stream_free(s);
		return;
	}

	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_port   = htons(LISP_CONTROL_PORT);
	dst.sin_addr   = itr_rloc->u.prefix4;

	if (sendto(lisp->sock, STREAM_DATA(s), stream_get_endp(s), 0,
		   (struct sockaddr *)&dst, sizeof(dst)) < 0) {
		flog_err_sys(EC_LISP_SOCKET,
			     "LISP mobility: sendto SMR to %pI4 failed: %s",
			     &dst.sin_addr, safe_strerror(errno));
	} else if (IS_LISP_DEBUG_EVENTS) {
		char eid_buf[PREFIX2STR_BUFFER];
		char itr_buf[PREFIX2STR_BUFFER];

		prefix2str(eid_prefix, eid_buf, sizeof(eid_buf));
		prefix2str(itr_rloc,   itr_buf, sizeof(itr_buf));
		zlog_debug("LISP mobility: sent SMR for EID %s to ITR %s",
			   eid_buf, itr_buf);
	}

	stream_free(s);
}

/* =========================================================================
 * SMR receiver  (§5.2)
 *
 * Called from lisp_handle_map_request() when the incoming Map-Request has
 * the S-bit set.  We:
 *  1. Remove the stale map-cache entries for all queried EIDs.
 *  2. Send an SMR-invoked Map-Request (s-bit=1) via the Map-Resolver.
 * ====================================================================== */

void lisp_mobility_handle_smr(struct lisp *lisp,
			      struct lisp_map_request *req,
			      struct sockaddr_storage *src)
{
	int i;

	if (IS_LISP_DEBUG_EVENTS)
		zlog_debug("LISP mobility: received SMR (%u EID record(s))",
			   req->record_count);

	for (i = 0; i < req->record_count && i < 8; i++) {
		struct prefix *eid = &req->records[i].eid_prefix;
		char buf[PREFIX2STR_BUFFER];

		/* Invalidate any stale map-cache entry (§5.2 step 1). */
		lisp_map_cache_delete(lisp, eid);

		if (IS_LISP_DEBUG_MAPCACHE) {
			prefix2str(eid, buf, sizeof(buf));
			zlog_debug(
				"LISP mobility: SMR invalidated cache for %s",
				buf);
		}

		/*
		 * Send an SMR-invoked Map-Request (s-bit=1) to refresh the
		 * mapping (§5.2 step 2).  We reuse the existing
		 * lisp_send_map_request() path; the smr_invoked flag is set
		 * via the dedicated wrapper below.
		 */
		lisp_send_smr_invoked_request(lisp, eid);
	}
}

/* =========================================================================
 * Away Table  (§5.3)
 * ====================================================================== */

void lisp_mobility_away_add(struct lisp *lisp, const struct prefix *eid_prefix)
{
	struct route_node *rn;
	struct lisp_away_entry *ae;
	char buf[PREFIX2STR_BUFFER];

	rn = route_node_get(lisp->away_table, eid_prefix);
	if (rn->info) {
		/* Already tracked. */
		route_unlock_node(rn);
		return;
	}

	ae = XCALLOC(MTYPE_LISP_AWAY_ENTRY, sizeof(*ae));
	prefix_copy(&ae->eid_prefix, eid_prefix);
	ae->rn  = rn;
	rn->info = ae;

	if (IS_LISP_DEBUG_EVENTS) {
		prefix2str(eid_prefix, buf, sizeof(buf));
		zlog_debug("LISP mobility: EID %s added to away table", buf);
	}
}

bool lisp_mobility_away_lookup(struct lisp *lisp,
			       const struct prefix *eid_prefix)
{
	struct route_node *rn;

	rn = route_node_match(lisp->away_table, eid_prefix);
	if (!rn)
		return false;
	route_unlock_node(rn);
	return (rn->info != NULL);
}

void lisp_mobility_away_clean(struct lisp *lisp)
{
	struct route_node *rn;
	struct lisp_away_entry *ae;

	for (rn = route_top(lisp->away_table); rn; rn = route_next(rn)) {
		ae = rn->info;
		if (!ae)
			continue;
		XFREE(MTYPE_LISP_AWAY_ENTRY, ae);
		rn->info = NULL;
	}
}

/* =========================================================================
 * Map-Register processing  (§4 — MS role)
 * ====================================================================== */

/*
 * Send SMRs to every ITR in the away MS entry's itr_cache list.
 */
static void send_smrs_for_entry(struct lisp *lisp,
				struct lisp_ms_entry *me)
{
	struct listnode *node;
	struct lisp_itr_track *it;

	for (ALL_LIST_ELEMENTS_RO(me->itr_cache, node, it))
		lisp_mobility_send_smr(lisp, &me->eid_prefix, &it->addr);
}

/*
 * Build a Map-Notify from the updated MS entry and send it to old_xtr_rloc.
 *
 * This informs the old ETR that its EID has moved, causing the old ETR to
 * populate its Away Table (§5.3).
 */
static void notify_old_xtr(struct lisp *lisp,
			   const struct prefix *eid_prefix,
			   const struct prefix *old_xtr_rloc,
			   uint64_t nonce)
{
	if (!old_xtr_rloc || old_xtr_rloc->family == 0)
		return;
	lisp_send_map_notify(lisp, eid_prefix, old_xtr_rloc, nonce);
}

void lisp_mobility_handle_map_register(struct lisp *lisp,
				       struct stream *s,
				       struct sockaddr_storage *src)
{
	struct lisp_map_register reg;
	struct lisp_auth_key *key;
	struct prefix src_rloc;
	int i;

	if (lisp_decode_map_register(s, &reg) < 0) {
		flog_err(EC_LISP_PACKET,
			 "LISP mobility MS: failed to decode Map-Register");
		return;
	}

	/* Verify HMAC (RFC 9301 §8.2). */
	key = lisp_auth_key_get(lisp, reg.key_id);
	if (key) {
		uint8_t *buf = STREAM_DATA(s);
		size_t   len = stream_get_endp(s);
		/*
		 * The auth-data offset is fixed: 4-byte header + 8-byte nonce
		 * + 2-byte key-id + 2-byte auth-len = offset 16.
		 */
		if (!lisp_auth_verify(buf, len, 16, key)) {
			zlog_warn(
				"LISP mobility MS: Map-Register auth failed (key-id %u)",
				reg.key_id);
			return;
		}
	}

	/* Extract registering xTR's RLOC from the UDP source address. */
	memset(&src_rloc, 0, sizeof(src_rloc));
	if (src->ss_family == AF_INET) {
		src_rloc.family   = AF_INET;
		src_rloc.prefixlen = IPV4_MAX_BITLEN;
		src_rloc.u.prefix4 =
			((struct sockaddr_in *)src)->sin_addr;
	} else if (src->ss_family == AF_INET6) {
		src_rloc.family    = AF_INET6;
		src_rloc.prefixlen = IPV6_MAX_BITLEN;
		src_rloc.u.prefix6 =
			((struct sockaddr_in6 *)src)->sin6_addr;
	}

	if (IS_LISP_DEBUG_EVENTS)
		zlog_debug(
			"LISP mobility MS: Map-Register from %pFX (%u record(s))",
			&src_rloc, reg.record_count);

	for (i = 0; i < reg.record_count && i < 8; i++) {
		struct lisp_eid_record *rec  = &reg.records[i];
		struct lisp_ms_entry   *me;
		struct list            *new_rlocs;
		bool                    mobility = false;
		struct prefix           old_xtr_rloc;
		uint64_t                notify_nonce;
		char                    eid_buf[PREFIX2STR_BUFFER];

		prefix2str(&rec->eid_prefix, eid_buf, sizeof(eid_buf));
		new_rlocs = rloc_list_from_eid_record(rec);
		me        = lisp_mobility_ms_lookup(lisp, &rec->eid_prefix);

		memset(&old_xtr_rloc, 0, sizeof(old_xtr_rloc));
		/*
		 * Echo the Map-Register nonce in the Map-Notify ack
		 * (RFC 9301 §8.4).  reg.nonce is in network byte order;
		 * lisp_send_map_notify() expects host byte order and calls
		 * htobe64() internally.
		 */
		notify_nonce = 0;
		memcpy(&notify_nonce, reg.nonce, LISP_NONCE_LEN);
		notify_nonce = be64toh(notify_nonce);

		if (me) {
			/*
			 * EID already registered.  Check if the RLOC set has
			 * changed — that would indicate EID mobility (§4.1).
			 */
			if (!rloc_lists_equal(me->rloc_list, new_rlocs)) {
				mobility = true;
				prefix_copy(&old_xtr_rloc, &me->xtr_rloc);

				zlog_info(
					"LISP mobility MS: EID %s moved — old xTR %pFX → new xTR %pFX",
					eid_buf, &old_xtr_rloc, &src_rloc);
			} else {
				/* Simple re-registration (no change). */
				rloc_list_free(new_rlocs);
				/* Refresh entry */
				ms_entry_set(lisp, &rec->eid_prefix,
					     rloc_list_from_eid_record(rec),
					     reg.id_present ? reg.xtr_id
							    : me->xtr_id,
					     reg.id_present ? reg.site_id
							    : me->site_id,
					     rec->ttl, &src_rloc);

				if (IS_LISP_DEBUG_EVENTS)
					zlog_debug(
						"LISP mobility MS: re-registered %s (no RLOC change)",
						eid_buf);
				goto ack;
			}
		}

		/* Store / update mapping in ms_db. */
		ms_entry_set(lisp, &rec->eid_prefix, new_rlocs,
			     reg.id_present ? reg.xtr_id
					    : (uint8_t[16]){0},
			     reg.id_present ? reg.site_id
					    : (uint8_t[8]){0},
			     rec->ttl, &src_rloc);

		/*
		 * Also update the map-cache on the MS itself so
		 * lisp_send_map_notify() can look up the current RLOCs.
		 */
		lisp_map_cache_delete(lisp, &rec->eid_prefix);
		{
			struct lisp_rloc r;
			struct listnode *nd;
			struct lisp_rloc *lr;
			struct lisp_ms_entry *updated =
				lisp_mobility_ms_lookup(lisp,
							&rec->eid_prefix);

			if (updated) {
				for (ALL_LIST_ELEMENTS_RO(updated->rloc_list,
							  nd, lr)) {
					r = *lr;
					lisp_map_cache_add(lisp,
							   &rec->eid_prefix,
							   &r, rec->ttl,
							   rec->action);
				}
			}
		}

		if (mobility) {
			/*
			 * (a) Notify pub/sub subscribers (RFC 9437) about the
			 *     updated mapping.
			 */
			lisp_pubsub_notify_subscribers(lisp,
						       &rec->eid_prefix);

			/*
			 * (b) Send SMR to every cached ITR-RLOC so they
			 *     invalidate their stale map-cache entries (§5.1).
			 */
			{
				struct lisp_ms_entry *updated =
					lisp_mobility_ms_lookup(
						lisp, &rec->eid_prefix);
				if (updated)
					send_smrs_for_entry(lisp, updated);
			}

			/*
			 * (c) Notify the old registering xTR so it can
			 *     populate its Away Table (§5.3).
			 */
			notify_old_xtr(lisp, &rec->eid_prefix,
				       &old_xtr_rloc, notify_nonce);
		}

ack:
		/*
		 * Send Map-Notify acknowledgement to registering ETR
		 * when the M-bit (want_map_notify) is set (RFC 9301 §8.2).
		 */
		if (reg.want_map_notify) {
			lisp_send_map_notify(lisp, &rec->eid_prefix, &src_rloc,
					     notify_nonce);
			if (IS_LISP_DEBUG_EVENTS)
				zlog_debug(
					"LISP mobility MS: sent Map-Notify ack for %s to %pFX",
					eid_buf, &src_rloc);
		}
	}
}

/* =========================================================================
 * CLI — show commands
 * ====================================================================== */

DEFUN(show_lisp_ms_database,
      show_lisp_ms_database_cmd,
      "show lisp map-server database [vrf NAME]",
      SHOW_STR
      "LISP information\n"
      "Map-Server information\n"
      "Show Map-Server EID database\n"
      VRF_CMD_HELP_STR)
{
	const char *vrf_name = (argc > 4) ? argv[4]->arg : VRF_DEFAULT_NAME;
	struct lisp *lisp;
	struct route_node *rn;
	char eid_buf[PREFIX2STR_BUFFER];

	lisp = lisp_lookup_by_vrf_name(vrf_name);
	if (!lisp) {
		vty_out(vty, "%% No LISP instance for VRF %s\n", vrf_name);
		return CMD_WARNING;
	}

	if (!lisp->ms_role) {
		vty_out(vty,
			"%% Map-Server role not enabled (use 'map-server-role')\n");
		return CMD_WARNING;
	}

	vty_out(vty, "LISP Map-Server EID Database (VRF %s)\n", vrf_name);
	vty_out(vty, "%-40s %-6s  %s\n", "EID Prefix", "TTL", "RLOC(s) / xTR");
	vty_out(vty, "%-40s %-6s  %s\n",
		"----------------------------------------",
		"------",
		"--------------------------------------------------");

	for (rn = route_top(lisp->ms_db); rn; rn = route_next(rn)) {
		struct lisp_ms_entry *me = rn->info;
		struct listnode *ln;
		struct lisp_rloc *rloc;
		struct lisp_itr_track *it;

		if (!me)
			continue;

		prefix2str(&me->eid_prefix, eid_buf, sizeof(eid_buf));

		if (me->ttl == LISP_MAP_CACHE_TTL_PERMANENT)
			vty_out(vty, "%-40s %-6s  ", eid_buf, "perm");
		else
			vty_out(vty, "%-40s %-6u  ", eid_buf, me->ttl);

		for (ALL_LIST_ELEMENTS_RO(me->rloc_list, ln, rloc)) {
			char rbuf[PREFIX2STR_BUFFER];

			prefix2str(&rloc->rloc_addr, rbuf, sizeof(rbuf));
			vty_out(vty, "%s (p=%u w=%u)", rbuf,
				rloc->priority, rloc->weight);
		}
		vty_out(vty, "\n");

		/* Show registering xTR RLOC. */
		if (me->xtr_rloc.family) {
			char xbuf[PREFIX2STR_BUFFER];

			prefix2str(&me->xtr_rloc, xbuf, sizeof(xbuf));
			vty_out(vty, "  %-40s xTR: %s\n", "", xbuf);
		}

		/* Show cached ITR-RLOCs. */
		if (!list_isempty(me->itr_cache)) {
			vty_out(vty, "  %-40s ITR cache:", "");
			for (ALL_LIST_ELEMENTS_RO(me->itr_cache, ln, it)) {
				char ibuf[PREFIX2STR_BUFFER];

				prefix2str(&it->addr, ibuf, sizeof(ibuf));
				vty_out(vty, " %s", ibuf);
			}
			vty_out(vty, "\n");
		}
	}

	return CMD_SUCCESS;
}

DEFUN(show_lisp_away_table,
      show_lisp_away_table_cmd,
      "show lisp away-table [vrf NAME]",
      SHOW_STR
      "LISP information\n"
      "Show EIDs that have moved away from this ETR\n"
      VRF_CMD_HELP_STR)
{
	const char *vrf_name = (argc > 3) ? argv[3]->arg : VRF_DEFAULT_NAME;
	struct lisp *lisp;
	struct route_node *rn;
	char buf[PREFIX2STR_BUFFER];
	bool any = false;

	lisp = lisp_lookup_by_vrf_name(vrf_name);
	if (!lisp) {
		vty_out(vty, "%% No LISP instance for VRF %s\n", vrf_name);
		return CMD_WARNING;
	}

	vty_out(vty, "LISP Away Table (VRF %s) — EIDs moved away from this ETR\n",
		vrf_name);

	for (rn = route_top(lisp->away_table); rn; rn = route_next(rn)) {
		struct lisp_away_entry *ae = rn->info;

		if (!ae)
			continue;
		prefix2str(&ae->eid_prefix, buf, sizeof(buf));
		vty_out(vty, "  %s\n", buf);
		any = true;
	}

	if (!any)
		vty_out(vty, "  (empty)\n");

	return CMD_SUCCESS;
}

void lisp_mobility_cli_init(void)
{
	install_element(VIEW_NODE,   &show_lisp_ms_database_cmd);
	install_element(ENABLE_NODE, &show_lisp_ms_database_cmd);
	install_element(VIEW_NODE,   &show_lisp_away_table_cmd);
	install_element(ENABLE_NODE, &show_lisp_away_table_cmd);
}
