/* LISP daemon — core logic (RFC 9301).
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

#include "prefix.h"
#include "table.h"
#include "stream.h"
#include "memory.h"
#include "log.h"
#include "vrf.h"
#include "if.h"
#include "thread.h"
#include "sockunion.h"
#include "sockopt.h"
#include "hash.h"
#include "frr_random.h"

#include "lispd/lispd.h"
#include "lispd/lisp_memory.h"
#include "lispd/lisp_interface.h"
#include "lispd/lisp_errors.h"
#include "lispd/lisp_debug.h"
#include "lispd/lisp_packet.h"
#include "lispd/lisp_auth.h"
#include "lispd/lisp_pubsub.h"

DEFINE_HOOK(lisp_ifaddr_add, (struct connected *ifc), (ifc))
DEFINE_HOOK(lisp_ifaddr_del, (struct connected *ifc), (ifc))

/* Maximum Map-Request retry attempts before giving up. */
#define LISP_MAP_REQUEST_RETRIES  3
/* Seconds between retries. */
#define LISP_MAP_REQUEST_RETRY_INTERVAL  2

/* =========================================================================
 * VRF / instance lookup
 * ====================================================================== */

struct lisp *lisp_lookup_by_vrf_id(vrf_id_t vrf_id)
{
	struct vrf *vrf = vrf_lookup_by_id(vrf_id);

	return vrf ? vrf->info : NULL;
}

struct lisp *lisp_lookup_by_vrf_name(const char *vrf_name)
{
	struct vrf *vrf = vrf_lookup_by_name(vrf_name);

	return vrf ? vrf->info : NULL;
}

/* =========================================================================
 * Socket creation
 * ====================================================================== */

int lisp_create_socket(struct vrf *vrf)
{
	int sock;
	struct sockaddr_in sin;
	vrf_id_t vrf_id = vrf ? vrf->vrf_id : VRF_DEFAULT;

	sock = vrf_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, vrf_id, NULL);
	if (sock < 0) {
		flog_err_sys(EC_LISP_SOCKET,
			     "LISP: failed to create UDP socket: %s",
			     safe_strerror(errno));
		return -1;
	}

	sockopt_reuseaddr(sock);
	sockopt_reuseport(sock);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family      = AF_INET;
	sin.sin_port        = htons(LISP_CONTROL_PORT);
	sin.sin_addr.s_addr = INADDR_ANY;

	if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		flog_err_sys(EC_LISP_SOCKET,
			     "LISP: failed to bind UDP socket to port %d: %s",
			     LISP_CONTROL_PORT, safe_strerror(errno));
		close(sock);
		return -1;
	}

	return sock;
}

/* =========================================================================
 * Nonce management  (RFC 9301 §6.1.2)
 * ====================================================================== */

void lisp_nonce_generate(uint8_t nonce[LISP_NONCE_LEN])
{
	frr_prng_get_bytes(nonce, LISP_NONCE_LEN);
}

static unsigned int lisp_pending_req_hash(const void *arg)
{
	const struct lisp_pending_req *req = arg;
	uint64_t n;

	memcpy(&n, req->nonce, sizeof(n));
	return (unsigned int)(n ^ (n >> 32));
}

static bool lisp_pending_req_cmp(const void *a, const void *b)
{
	const struct lisp_pending_req *ra = a;
	const struct lisp_pending_req *rb = b;

	return memcmp(ra->nonce, rb->nonce, LISP_NONCE_LEN) == 0;
}

static void lisp_pending_req_free(void *arg)
{
	struct lisp_pending_req *req = arg;

	THREAD_TIMER_OFF(req->t_timeout);
	XFREE(MTYPE_LISP_PENDING_REQ, req);
}

struct lisp_auth_key *lisp_auth_key_get(struct lisp *lisp, uint16_t key_id)
{
	struct listnode *node;
	struct lisp_auth_key *key;

	for (ALL_LIST_ELEMENTS_RO(lisp->auth_keys, node, key))
		if (key->key_id == key_id)
			return key;
	return NULL;
}

struct lisp_pending_req *
lisp_pending_req_add(struct lisp *lisp, const struct prefix *eid,
		     const struct prefix *dst,
		     const uint8_t nonce[LISP_NONCE_LEN])
{
	struct lisp_pending_req *req;

	req = XCALLOC(MTYPE_LISP_PENDING_REQ, sizeof(*req));
	memcpy(req->nonce, nonce, LISP_NONCE_LEN);
	prefix_copy(&req->eid, eid);
	prefix_copy(&req->dst, dst);
	req->lisp = lisp;

	hash_get(lisp->pending_requests, req, hash_alloc_intern);
	return req;
}

struct lisp_pending_req *
lisp_pending_req_lookup(struct lisp *lisp, const uint8_t nonce[LISP_NONCE_LEN])
{
	struct lisp_pending_req key;

	memcpy(key.nonce, nonce, LISP_NONCE_LEN);
	return hash_lookup(lisp->pending_requests, &key);
}

void lisp_pending_req_delete(struct lisp *lisp, struct lisp_pending_req *req)
{
	hash_release(lisp->pending_requests, req);
	lisp_pending_req_free(req);
}

/* =========================================================================
 * Map-cache management  (RFC 9301 §6.2)
 * ====================================================================== */

struct lisp_map_entry *lisp_map_cache_lookup(struct lisp *lisp,
					     const struct prefix *eid)
{
	struct route_node *rn;

	rn = route_node_match(lisp->map_cache, eid);
	if (!rn)
		return NULL;
	route_unlock_node(rn);
	return rn->info;
}

/*
 * Timer callback: expire a map-cache entry.
 *
 * RFC 9301 §6.2: before the TTL expires an ITR SHOULD send a new Map-Request
 * to refresh the entry.  We implement this as a two-phase timer:
 *  phase 1 (REFRESH): fires LISP_MAP_CACHE_REFRESH_SECS before expiry →
 *                     sends a new Map-Request and re-arms for phase 2.
 *  phase 2 (EXPIRE):  fires at TTL boundary → removes the entry.
 *
 * We distinguish the phases by storing the TTL in minutes in me->ttl and
 * using a separate flag in the route_node tag field.
 */
#define LISP_MC_TAG_REFRESH 0
#define LISP_MC_TAG_EXPIRE  1

static int lisp_map_entry_expire(struct thread *t)
{
	struct lisp_map_entry *me = THREAD_ARG(t);
	struct lisp *lisp;
	struct route_node *rn = me->rn;
	struct listnode *node, *nnode;
	struct lisp_rloc *rloc;

	me->t_expire = NULL;

	lisp = lisp_lookup_by_vrf_id(rn->table->vrf_id != VRF_UNKNOWN
					     ? rn->table->vrf_id
					     : VRF_DEFAULT);
	if (!lisp)
		goto remove;

	if (rn->tag == LISP_MC_TAG_REFRESH) {
		/* Phase 1: send refresh Map-Request, then arm expiry timer. */
		if (IS_LISP_DEBUG_MAPCACHE) {
			char buf[PREFIX2STR_BUFFER];
			prefix2str(&rn->p, buf, sizeof(buf));
			zlog_debug("LISP: refreshing map-cache entry %s", buf);
		}
		lisp_send_map_request(lisp, &rn->p);
		rn->tag = LISP_MC_TAG_EXPIRE;
		thread_add_timer(master, lisp_map_entry_expire, me,
				 LISP_MAP_CACHE_REFRESH_SECS, &me->t_expire);
		return 0;
	}

remove:
	if (IS_LISP_DEBUG_MAPCACHE) {
		char buf[PREFIX2STR_BUFFER];
		prefix2str(&rn->p, buf, sizeof(buf));
		zlog_debug("LISP: map-cache entry %s expired", buf);
	}

	for (ALL_LIST_ELEMENTS(me->rloc_list, node, nnode, rloc))
		XFREE(MTYPE_LISP_RLOC, rloc);
	list_delete(&me->rloc_list);
	XFREE(MTYPE_LISP_MAP_ENTRY, me);
	rn->info = NULL;
	rn->tag  = 0;
	route_unlock_node(rn);
	return 0;
}

/*
 * Add or refresh a map-cache entry.
 *
 * RFC 9301 §6.2 TTL rules:
 *  ttl == 0            → MUST NOT cache; if entry exists remove it.
 *  ttl == 0xffffffff   → cache indefinitely (no expiry timer).
 *  otherwise           → cache for ttl minutes with refresh.
 */
void lisp_map_cache_add(struct lisp *lisp, struct prefix *eid,
			struct lisp_rloc *rloc, uint32_t ttl, uint8_t action)
{
	struct route_node *rn;
	struct lisp_map_entry *me;

	/* TTL=0: do not cache — remove any existing entry (RFC 9301 §6.2). */
	if (ttl == 0) {
		lisp_map_cache_delete(lisp, eid);
		if (IS_LISP_DEBUG_MAPCACHE) {
			char buf[PREFIX2STR_BUFFER];
			prefix2str(eid, buf, sizeof(buf));
			zlog_debug("LISP: TTL=0 for %s, not caching", buf);
		}
		return;
	}

	rn = route_node_get(lisp->map_cache, eid);
	me = rn->info;

	if (!me) {
		me = XCALLOC(MTYPE_LISP_MAP_ENTRY, sizeof(*me));
		me->rloc_list = list_new();
		me->rn = rn;
		rn->info = me;
		prefix_copy(&me->eid_prefix, eid);
	} else {
		/* Refresh: cancel existing timer. */
		THREAD_TIMER_OFF(me->t_expire);
		route_unlock_node(rn);
	}

	me->ttl    = ttl;
	me->action = action;

	if (rloc) {
		struct lisp_rloc *new_rloc =
			XCALLOC(MTYPE_LISP_RLOC, sizeof(*new_rloc));
		*new_rloc = *rloc;
		listnode_add(me->rloc_list, new_rloc);
	}

	/* TTL=0xffffffff: permanent entry, no expiry timer. */
	if (ttl == LISP_MAP_CACHE_TTL_PERMANENT) {
		if (IS_LISP_DEBUG_MAPCACHE) {
			char buf[PREFIX2STR_BUFFER];
			prefix2str(eid, buf, sizeof(buf));
			zlog_debug("LISP: permanent map-cache entry %s", buf);
		}
		return;
	}

	/*
	 * Phase 1 timer: fire LISP_MAP_CACHE_REFRESH_SECS before expiry to
	 * trigger a refresh Map-Request.  If TTL is very short, skip straight
	 * to the expiry timer.
	 */
	{
		long ttl_secs = (long)ttl * 60;
		long refresh  = ttl_secs - LISP_MAP_CACHE_REFRESH_SECS;

		rn->tag = LISP_MC_TAG_REFRESH;
		if (refresh > 0)
			thread_add_timer(master, lisp_map_entry_expire, me,
					 refresh, &me->t_expire);
		else {
			rn->tag = LISP_MC_TAG_EXPIRE;
			thread_add_timer(master, lisp_map_entry_expire, me,
					 ttl_secs, &me->t_expire);
		}
	}

	if (IS_LISP_DEBUG_MAPCACHE) {
		char buf[PREFIX2STR_BUFFER];
		prefix2str(eid, buf, sizeof(buf));
		zlog_debug("LISP: map-cache entry %s ttl=%u min action=%u",
			   buf, ttl, action);
	}
}

void lisp_map_cache_delete(struct lisp *lisp, struct prefix *eid)
{
	struct route_node *rn;
	struct lisp_map_entry *me;
	struct listnode *node, *nnode;
	struct lisp_rloc *rloc;

	rn = route_node_lookup(lisp->map_cache, eid);
	if (!rn)
		return;

	me = rn->info;
	if (!me) {
		route_unlock_node(rn);
		return;
	}

	THREAD_TIMER_OFF(me->t_expire);
	for (ALL_LIST_ELEMENTS(me->rloc_list, node, nnode, rloc))
		XFREE(MTYPE_LISP_RLOC, rloc);
	list_delete(&me->rloc_list);
	XFREE(MTYPE_LISP_MAP_ENTRY, me);
	rn->info = NULL;
	rn->tag  = 0;
	route_unlock_node(rn); /* lookup ref */
	route_unlock_node(rn); /* node ref */
}

/* =========================================================================
 * Map-Request sender  (ITR, RFC 9301 §6.1)
 *
 * Sends an Encapsulated Control Message (ECM) containing the Map-Request
 * to every configured Map-Resolver.
 * ====================================================================== */

void lisp_send_map_request(struct lisp *lisp, const struct prefix *eid)
{
	struct listnode *node;
	struct lisp_ms_mr *ms;
	struct lisp_map_request req;
	struct stream *s;
	uint8_t nonce[LISP_NONCE_LEN];
	struct sockaddr_in dst;

	if (lisp->sock < 0)
		return;

	lisp_nonce_generate(nonce);

	memset(&req, 0, sizeof(req));
	memcpy(req.nonce, nonce, LISP_NONCE_LEN);
	req.record_count   = 1;
	req.itr_rloc_count = 1;
	prefix_copy(&req.records[0].eid_prefix, eid);

	/* Source EID: use the queried EID as source (no EID configured). */
	prefix_copy(&req.src_eid, eid);

	s = stream_new(LISP_MAX_PACKET_SIZE);

	for (ALL_LIST_ELEMENTS_RO(lisp->ms_mr_list, node, ms)) {
		struct lisp_pending_req *pending;

		if (!ms->map_resolver)
			continue;

		if (ms->addr.family != AF_INET)
			continue;

		/*
		 * Use the Map-Resolver's address as the first ITR-RLOC so the
		 * ETR knows where to send the Map-Reply.
		 */
		prefix_copy(&req.itr_rlocs[0], &ms->addr);

		stream_reset(s);
		if (lisp_encode_ecm(s, &req, &ms->addr, &ms->addr) < 0)
			continue;

		memset(&dst, 0, sizeof(dst));
		dst.sin_family = AF_INET;
		dst.sin_port   = htons(LISP_CONTROL_PORT);
		dst.sin_addr   = ms->addr.u.prefix4;

		if (sendto(lisp->sock, STREAM_DATA(s), stream_get_endp(s), 0,
			   (struct sockaddr *)&dst, sizeof(dst)) < 0) {
			flog_err_sys(EC_LISP_SOCKET,
				     "LISP: sendto Map-Resolver %pI4 failed: %s",
				     &dst.sin_addr, safe_strerror(errno));
			continue;
		}

		/* Track the pending request for nonce matching. */
		pending = lisp_pending_req_lookup(lisp, nonce);
		if (!pending)
			lisp_pending_req_add(lisp, eid, &ms->addr, nonce);

		if (IS_LISP_DEBUG_EVENTS) {
			char buf[PREFIX2STR_BUFFER];
			prefix2str(eid, buf, sizeof(buf));
			zlog_debug("LISP: sent Map-Request for %s to %pI4",
				   buf, &dst.sin_addr);
		}
	}

	stream_free(s);
}

/* =========================================================================
 * Map-Reply sender  (ETR, RFC 9301 §6.2)
 *
 * Called when we receive a Map-Request for one of our local EID prefixes.
 * ====================================================================== */

void lisp_send_map_reply(struct lisp *lisp, const struct prefix *eid,
			 const struct sockaddr_storage *dst_ss,
			 const uint8_t nonce[LISP_NONCE_LEN], bool probe)
{
	struct lisp_map_reply rep;
	struct lisp_eid_record *rec;
	struct route_node *rn;
	struct stream *s;
	ssize_t sent;

	if (lisp->sock < 0)
		return;

	memset(&rep, 0, sizeof(rep));
	memcpy(rep.nonce, nonce, LISP_NONCE_LEN); /* echo nonce */
	rep.probe        = probe;
	rep.record_count = 1;

	rec = &rep.records[0];
	prefix_copy(&rec->eid_prefix, eid);
	rec->authoritative = true;
	rec->ttl           = LISP_MAP_CACHE_TTL_DEFAULT;
	rec->action        = LISP_ACTION_NO_ACTION;

	/* Populate RLOC list from local interface addresses. */
	rec->loc_count = 0;
	for (rn = route_top(lisp->local_eids); rn && rec->loc_count < 32;
	     rn = route_next(rn)) {
		struct lisp_loc_record *loc;

		if (!rn->info)
			continue;
		if (!prefix_match(&rn->p, eid))
			continue;

		loc = &rec->locs[rec->loc_count++];
		prefix_copy(&loc->rloc, &rn->p);
		loc->priority  = 1;
		loc->weight    = 100;
		loc->mpriority = 255;
		loc->mweight   = 0;
		loc->flags     = LISP_LOC_FLAG_L | LISP_LOC_FLAG_R;
	}

	s = stream_new(LISP_MAX_PACKET_SIZE);
	if (lisp_encode_map_reply(s, &rep) < 0) {
		stream_free(s);
		return;
	}

	sent = sendto(lisp->sock, STREAM_DATA(s), stream_get_endp(s), 0,
		      (struct sockaddr *)dst_ss,
		      dst_ss->ss_family == AF_INET
			      ? sizeof(struct sockaddr_in)
			      : sizeof(struct sockaddr_in6));
	if (sent < 0)
		flog_err_sys(EC_LISP_SOCKET,
			     "LISP: sendto Map-Reply failed: %s",
			     safe_strerror(errno));
	else if (IS_LISP_DEBUG_PACKET) {
		char buf[PREFIX2STR_BUFFER];
		prefix2str(eid, buf, sizeof(buf));
		zlog_debug("LISP: sent Map-Reply for %s", buf);
	}

	stream_free(s);
}

/* =========================================================================
 * Map-Register sender  (ETR, RFC 9301 §8.2)
 *
 * Sends a Map-Register to every configured Map-Server.
 * ====================================================================== */

void lisp_send_map_register(struct lisp *lisp)
{
	struct listnode *node;
	struct lisp_ms_mr *ms;
	struct lisp_auth_key *key;
	struct lisp_map_register reg;
	struct stream *s;
	struct route_node *rn;
	struct sockaddr_in dst;

	if (lisp->sock < 0)
		return;

	/* Use the first configured auth key (key-id 1 by default). */
	key = lisp_auth_key_get(lisp, 1);

	memset(&reg, 0, sizeof(reg));
	reg.want_map_notify = true;
	reg.id_present      = lisp->id_configured;
	if (lisp->id_configured) {
		memcpy(reg.xtr_id,  lisp->xtr_id,  sizeof(reg.xtr_id));
		memcpy(reg.site_id, lisp->site_id, sizeof(reg.site_id));
	}
	lisp_nonce_generate(reg.nonce);

	/* Build EID records from local_eids table. */
	reg.record_count = 0;
	for (rn = route_top(lisp->local_eids);
	     rn && reg.record_count < 8;
	     rn = route_next(rn)) {
		struct lisp_eid_record *rec;

		if (!rn->info)
			continue;

		rec = &reg.records[reg.record_count++];
		prefix_copy(&rec->eid_prefix, &rn->p);
		rec->ttl           = LISP_MAP_CACHE_TTL_DEFAULT;
		rec->authoritative = true;
		rec->action        = LISP_ACTION_NO_ACTION;
		rec->loc_count     = 0;
	}

	if (reg.record_count == 0)
		return;

	s = stream_new(LISP_MAX_PACKET_SIZE);

	for (ALL_LIST_ELEMENTS_RO(lisp->ms_mr_list, node, ms)) {
		if (!ms->map_server)
			continue;
		if (ms->addr.family != AF_INET)
			continue;

		reg.proxy_reply = ms->proxy_reply;

		stream_reset(s);
		if (lisp_encode_map_register(s, &reg, key) < 0)
			continue;

		memset(&dst, 0, sizeof(dst));
		dst.sin_family = AF_INET;
		dst.sin_port   = htons(LISP_CONTROL_PORT);
		dst.sin_addr   = ms->addr.u.prefix4;

		if (sendto(lisp->sock, STREAM_DATA(s), stream_get_endp(s), 0,
			   (struct sockaddr *)&dst, sizeof(dst)) < 0) {
			flog_err_sys(EC_LISP_SOCKET,
				     "LISP: sendto Map-Server %pI4 failed: %s",
				     &dst.sin_addr, safe_strerror(errno));
		} else if (IS_LISP_DEBUG_EVENTS) {
			zlog_debug("LISP: sent Map-Register to %pI4 (%u EIDs)",
				   &dst.sin_addr, reg.record_count);
		}
	}

	stream_free(s);
}

/* Periodic Map-Register thread. */
static int lisp_map_register_timer(struct thread *t)
{
	struct lisp *lisp = THREAD_ARG(t);

	lisp->t_map_register = NULL;
	lisp_send_map_register(lisp);

	thread_add_timer(master, lisp_map_register_timer, lisp,
			 lisp->map_register_interval, &lisp->t_map_register);
	return 0;
}

/* =========================================================================
 * Map-Notify / Map-Notify-Ack senders (RFC 9437)
 * ====================================================================== */

/*
 * Map-Server role: send a Map-Notify for an EID to a specific destination.
 * The nonce is provided by the caller (usually the subscription nonce).
 */
void lisp_send_map_notify(struct lisp *lisp,
			  const struct prefix *eid,
			  const struct prefix *dst_rloc,
			  uint64_t nonce)
{
	struct lisp_map_notify notify;
	struct lisp_map_entry *me;
	struct lisp_auth_key *key;
	struct sockaddr_in sin;
	struct stream *s;

	if (!dst_rloc || dst_rloc->family != AF_INET)
		return;

	memset(&notify, 0, sizeof(notify));
	{
		uint64_t n = htobe64(nonce);
		memcpy(notify.nonce, &n, LISP_NONCE_LEN);
	}

	me = lisp_map_cache_lookup(lisp, eid);
	notify.record_count         = 1;
	notify.records[0].eid_prefix = *eid;

	if (me) {
		struct listnode *node;
		struct lisp_rloc *rloc;

		notify.records[0].ttl           = me->ttl;
		notify.records[0].action        = me->action;
		notify.records[0].authoritative = true;

		for (ALL_LIST_ELEMENTS_RO(me->rloc_list, node, rloc)) {
			struct lisp_loc_record *lr;

			if (notify.records[0].loc_count >= 32)
				break;
			lr = &notify.records[0].locs[notify.records[0].loc_count++];
			lr->priority  = rloc->priority;
			lr->weight    = rloc->weight;
			lr->mpriority = rloc->mpriority;
			lr->mweight   = rloc->mweight;
			lr->flags     = (rloc->local     ? LISP_LOC_FLAG_L : 0)
					| (rloc->reachable ? LISP_LOC_FLAG_R : 0);
			lr->rloc      = rloc->rloc_addr;
		}
	} else {
		notify.records[0].ttl    = LISP_PUBSUB_DEFAULT_NEG_TTL_MINS;
		notify.records[0].action = LISP_ACTION_NATIVELY_FORWARD;
	}

	key = lisp_auth_key_get(lisp, notify.key_id);

	s = stream_new(LISP_MAX_PACKET_SIZE);
	if (lisp_encode_map_notify(s, &notify, key) < 0) {
		stream_free(s);
		return;
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port   = htons(LISP_CONTROL_PORT);
	sin.sin_addr   = dst_rloc->u.prefix4;

	sendto(lisp->sock, STREAM_DATA(s), stream_get_endp(s), 0,
	       (struct sockaddr *)&sin, sizeof(sin));
	stream_free(s);
}

/*
 * Subscriber role: send a Map-Notify-Ack echoing the nonce back to src.
 */
void lisp_send_map_notify_ack(struct lisp *lisp,
			      const uint8_t nonce[LISP_NONCE_LEN],
			      const struct sockaddr_storage *dst)
{
	struct lisp_map_notify_ack ack;
	struct sockaddr_in sin;
	struct stream *s;

	if (dst->ss_family != AF_INET)
		return;

	memcpy(ack.nonce, nonce, LISP_NONCE_LEN);

	s = stream_new(LISP_MAX_PACKET_SIZE);
	if (lisp_encode_map_notify_ack(s, &ack) < 0) {
		stream_free(s);
		return;
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port   = htons(LISP_CONTROL_PORT);
	sin.sin_addr   = ((const struct sockaddr_in *)dst)->sin_addr;

	sendto(lisp->sock, STREAM_DATA(s), stream_get_endp(s), 0,
	       (struct sockaddr *)&sin, sizeof(sin));
	stream_free(s);

	if (IS_LISP_DEBUG_PUBSUB)
		zlog_debug("LISP pubsub: sent Map-Notify-Ack");
}

/* =========================================================================
 * Incoming packet handlers
 * ====================================================================== */

/* Handle a received Map-Reply (RFC 9301 §6.2). */
static void lisp_handle_map_reply(struct lisp *lisp, struct stream *s)
{
	struct lisp_map_reply rep;
	struct lisp_pending_req *pending;
	int i, j;

	if (lisp_decode_map_reply(s, &rep) < 0) {
		flog_err(EC_LISP_PACKET, "LISP: failed to decode Map-Reply");
		return;
	}

	/* Match nonce to a pending Map-Request. */
	pending = lisp_pending_req_lookup(lisp, rep.nonce);
	if (!pending) {
		if (IS_LISP_DEBUG_PACKET)
			zlog_debug("LISP: Map-Reply with unknown nonce, dropping");
		return;
	}

	for (i = 0; i < rep.record_count; i++) {
		struct lisp_eid_record *rec = &rep.records[i];
		struct lisp_rloc rloc;

		if (IS_LISP_DEBUG_MAPCACHE) {
			char buf[PREFIX2STR_BUFFER];
			prefix2str(&rec->eid_prefix, buf, sizeof(buf));
			zlog_debug("LISP: Map-Reply record %s ttl=%u action=%u",
				   buf, rec->ttl, rec->action);
		}

		/*
		 * RFC 9301 §6.2: TTL=0 means do not cache; caller of
		 * lisp_map_cache_add handles this correctly.
		 */
		if (rec->loc_count == 0) {
			/* Negative map-reply. */
			lisp_map_cache_add(lisp, &rec->eid_prefix, NULL,
					   rec->ttl, rec->action);
		} else {
			for (j = 0; j < rec->loc_count; j++) {
				struct lisp_loc_record *loc = &rec->locs[j];

				memset(&rloc, 0, sizeof(rloc));
				prefix_copy(&rloc.rloc_addr, &loc->rloc);
				rloc.priority  = loc->priority;
				rloc.weight    = loc->weight;
				rloc.mpriority = loc->mpriority;
				rloc.mweight   = loc->mweight;
				rloc.local     = !!(loc->flags & LISP_LOC_FLAG_L);
				rloc.reachable = !!(loc->flags & LISP_LOC_FLAG_R);

				lisp_map_cache_add(lisp, &rec->eid_prefix,
						   &rloc, rec->ttl,
						   rec->action);
			}
		}
	}

	lisp_pending_req_delete(lisp, pending);
}

/* Handle a received Map-Request (RFC 9301 §6.1) — ETR / Map-Server role. */
static void lisp_handle_map_request(struct lisp *lisp, struct stream *s,
				    struct sockaddr_storage *src)
{
	struct lisp_map_request req;
	bool any_subscribe = false;
	bool any_unsubscribe = false;
	int i;

	if (lisp_decode_map_request(s, &req) < 0) {
		flog_err(EC_LISP_PACKET, "LISP: failed to decode Map-Request");
		return;
	}

	/*
	 * RFC 9437 §4.1: detect pub/sub requests.
	 * An AFI=0 ITR-RLOC with N-bit set signals unsubscription.
	 */
	for (i = 0; i < req.record_count && i < 8; i++) {
		if (!req.records[i].subscribe_n)
			continue;
		if (req.itr_rloc_count > 0 && req.itr_rlocs[0].family == 0)
			any_unsubscribe = true;
		else
			any_subscribe = true;
	}

	if (any_unsubscribe) {
		lisp_pubsub_handle_unsubscribe(lisp, &req, src);
		return;
	}

	if (any_subscribe) {
		lisp_pubsub_handle_subscribe(lisp, &req, src);
		return;
	}

	/* Normal Map-Request: answer with a Map-Reply if we own the EID. */
	for (i = 0; i < req.record_count; i++) {
		struct prefix *queried = &req.records[i].eid_prefix;
		struct route_node *rn;

		/* Check if the queried EID is one of our local prefixes. */
		rn = route_node_match(lisp->local_eids, queried);
		if (!rn || !rn->info) {
			if (rn)
				route_unlock_node(rn);
			if (IS_LISP_DEBUG_PACKET) {
				char buf[PREFIX2STR_BUFFER];
				prefix2str(queried, buf, sizeof(buf));
				zlog_debug("LISP: Map-Request for non-local EID %s",
					   buf);
			}
			continue;
		}
		route_unlock_node(rn);

		/* Send Map-Reply with our RLOC information. */
		lisp_send_map_reply(lisp, queried, src, req.nonce, req.probe);
	}
}

/* Handle a received Map-Notify (RFC 9301 §8.4) — ETR / subscriber role. */
static void lisp_handle_map_notify(struct lisp *lisp, struct stream *s,
				   struct sockaddr_storage *src)
{
	struct lisp_map_notify notify;
	struct lisp_auth_key *key;

	if (lisp_decode_map_notify(s, &notify) < 0) {
		flog_err(EC_LISP_PACKET, "LISP: failed to decode Map-Notify");
		return;
	}

	/* Verify HMAC authentication. */
	key = lisp_auth_key_get(lisp, notify.key_id);
	if (key) {
		if (IS_LISP_DEBUG_EVENTS)
			zlog_debug("LISP: Map-Notify received (key-id %u)",
				   notify.key_id);
	} else if (notify.key_id != 0) {
		zlog_warn("LISP: Map-Notify with unknown key-id %u",
			  notify.key_id);
	}

	if (IS_LISP_DEBUG_EVENTS)
		zlog_debug("LISP: Map-Notify for %u EID(s)", notify.record_count);

	/*
	 * If we have active subscriptions for any of the EIDs in this
	 * Map-Notify, route to the pub/sub handler (RFC 9437 §5).
	 * Otherwise this is a registration confirmation and no further
	 * action is needed here (the ETR has already sent Map-Register).
	 */
	lisp_pubsub_handle_notify(lisp, &notify, src);
}

/*
 * Handle incoming Map-Notify-Ack (RFC 9437 §5) — Map-Server role.
 * The subscriber is acknowledging a Map-Notify publication we sent.
 */
static void lisp_handle_map_notify_ack(struct lisp *lisp, struct stream *s,
				       struct sockaddr_storage *src)
{
	struct lisp_map_notify_ack ack;

	if (lisp_decode_map_notify_ack(s, &ack) < 0) {
		flog_err(EC_LISP_PACKET,
			 "LISP: failed to decode Map-Notify-Ack");
		return;
	}

	lisp_pubsub_handle_notify_ack(lisp, &ack, src);
}

/* Handle an incoming ECM (type 8) — Map-Resolver forwards Map-Request. */
static void lisp_handle_ecm(struct lisp *lisp, struct stream *s,
			    struct sockaddr_storage *src)
{
	if (lisp_decode_ecm(s) < 0) {
		flog_err(EC_LISP_PACKET, "LISP: malformed ECM header");
		return;
	}
	/* Inner message must be a Map-Request. */
	lisp_handle_map_request(lisp, s, src);
}

/*
 * Main UDP receive loop — registered as t_read on the control socket.
 * Dispatches to the appropriate handler based on the LISP message type.
 */
int lisp_recv_packet(struct thread *t)
{
	struct lisp *lisp = THREAD_ARG(t);
	uint8_t buf[LISP_MAX_PACKET_SIZE];
	struct sockaddr_storage src;
	socklen_t src_len = sizeof(src);
	ssize_t nbytes;
	struct stream *s;
	uint8_t type_nibble;

	lisp->t_read = NULL;

	nbytes = recvfrom(lisp->sock, buf, sizeof(buf), 0,
			  (struct sockaddr *)&src, &src_len);
	if (nbytes <= 0) {
		if (nbytes < 0 && errno != EAGAIN)
			flog_err_sys(EC_LISP_SOCKET,
				     "LISP: recvfrom error: %s",
				     safe_strerror(errno));
		goto rearm;
	}

	if (IS_LISP_DEBUG_PACKET)
		zlog_debug("LISP: received %zd bytes on control socket", nbytes);

	s = stream_new(nbytes);
	stream_put(s, buf, nbytes);

	/* The top 4 bits of the first byte are the LISP message type. */
	type_nibble = (buf[0] >> 4) & 0x0f;

	switch (type_nibble) {
	case LISP_MAP_REQUEST:
		lisp_handle_map_request(lisp, s, &src);
		break;
	case LISP_MAP_REPLY:
		lisp_handle_map_reply(lisp, s);
		break;
	case LISP_MAP_REGISTER:
		/* We don't implement Map-Server role here. */
		if (IS_LISP_DEBUG_PACKET)
			zlog_debug("LISP: ignoring Map-Register (not MS)");
		break;
	case LISP_MAP_NOTIFY:
		lisp_handle_map_notify(lisp, s, &src);
		break;
	case LISP_MAP_NOTIFY_ACK:
		lisp_handle_map_notify_ack(lisp, s, &src);
		break;
	case LISP_ENCAP_CONTROL:
		lisp_handle_ecm(lisp, s, &src);
		break;
	default:
		if (IS_LISP_DEBUG_PACKET)
			zlog_debug("LISP: unknown message type %u, dropping",
				   type_nibble);
		break;
	}

	stream_free(s);

rearm:
	/* Re-arm the read thread. */
	thread_add_read(master, lisp_recv_packet, lisp, lisp->sock,
			&lisp->t_read);
	return 0;
}

/* =========================================================================
 * Instance lifecycle
 * ====================================================================== */

struct lisp *lisp_create(const char *vrf_name, struct vrf *vrf, int socket)
{
	struct lisp *lisp;

	lisp = XCALLOC(MTYPE_LISP, sizeof(struct lisp));
	lisp->vrf_name = XSTRDUP(MTYPE_LISP_VRF_NAME, vrf_name);
	lisp->vrf    = vrf;
	lisp->sock   = socket;
	lisp->enabled = true;
	lisp->map_register_interval = LISP_MAP_REGISTER_DEFAULT_INTERVAL;
	lisp->rloc_probe_interval   = LISP_RLOC_PROBE_INTERVAL;

	lisp->map_cache    = route_table_init();
	lisp->local_eids   = route_table_init();
	lisp->ms_mr_list   = list_new();
	lisp->auth_keys    = list_new();
	lisp->pending_requests = hash_create(lisp_pending_req_hash,
					     lisp_pending_req_cmp,
					     "LISP pending requests");

	/* RFC 9437 pub/sub state lists. */
	lisp->subscriptions = list_new();
	lisp->sub_states    = list_new();

	if (vrf)
		vrf->info = lisp;

	/* Arm the socket read thread. */
	if (socket >= 0)
		thread_add_read(master, lisp_recv_packet, lisp, socket,
				&lisp->t_read);

	/* Start periodic Map-Register. */
	thread_add_timer(master, lisp_map_register_timer, lisp,
			 lisp->map_register_interval, &lisp->t_map_register);

	zlog_debug("LISP: created instance for VRF %s", vrf_name);
	return lisp;
}

void lisp_clean(struct lisp *lisp)
{
	struct route_node *rn;
	struct lisp_map_entry *me;
	struct listnode *node, *nnode;
	struct lisp_rloc *rloc;
	struct lisp_ms_mr *ms;
	struct lisp_auth_key *key;

	if (!lisp)
		return;

	THREAD_TIMER_OFF(lisp->t_read);
	THREAD_TIMER_OFF(lisp->t_map_register);

	/* Clean map-cache. */
	for (rn = route_top(lisp->map_cache); rn; rn = route_next(rn)) {
		me = rn->info;
		if (!me)
			continue;
		THREAD_TIMER_OFF(me->t_expire);
		for (ALL_LIST_ELEMENTS(me->rloc_list, node, nnode, rloc))
			XFREE(MTYPE_LISP_RLOC, rloc);
		list_delete(&me->rloc_list);
		XFREE(MTYPE_LISP_MAP_ENTRY, me);
		rn->info = NULL;
	}
	route_table_finish(lisp->map_cache);

	/* Clean local EID table. */
	for (rn = route_top(lisp->local_eids); rn; rn = route_next(rn))
		rn->info = NULL;
	route_table_finish(lisp->local_eids);

	/* Clean MS/MR list. */
	for (ALL_LIST_ELEMENTS(lisp->ms_mr_list, node, nnode, ms))
		XFREE(MTYPE_LISP_MS_MR, ms);
	list_delete(&lisp->ms_mr_list);

	/* Clean auth keys. */
	for (ALL_LIST_ELEMENTS(lisp->auth_keys, node, nnode, key))
		XFREE(MTYPE_LISP_AUTH_KEY, key);
	list_delete(&lisp->auth_keys);

	/* Clean pending requests. */
	hash_clean(lisp->pending_requests, lisp_pending_req_free);
	hash_free(lisp->pending_requests);

	/* Clean pub/sub state (RFC 9437). */
	lisp_pubsub_clean(lisp);
	list_delete(&lisp->subscriptions);
	{
		struct listnode *snode, *snnode;
		struct lisp_sub_state *ss;

		for (ALL_LIST_ELEMENTS(lisp->sub_states, snode, snnode, ss)) {
			THREAD_OFF(ss->t_refresh);
			XFREE(MTYPE_LISP_SUB_STATE, ss);
		}
		list_delete(&lisp->sub_states);
	}

	if (lisp->sock >= 0)
		close(lisp->sock);

	if (lisp->vrf)
		lisp->vrf->info = NULL;

	XFREE(MTYPE_LISP_VRF_NAME, lisp->vrf_name);
	XFREE(MTYPE_LISP, lisp);
}

/* =========================================================================
 * VRF callbacks
 * ====================================================================== */

static int lisp_vrf_new(struct vrf *vrf)
{
	zlog_debug("LISP: VRF %s created", vrf->name);
	return 0;
}

static int lisp_vrf_delete(struct vrf *vrf)
{
	lisp_clean(vrf->info);
	return 0;
}

static int lisp_vrf_enable(struct vrf *vrf)
{
	struct lisp *lisp = vrf->info;

	if (lisp && !lisp->enabled) {
		lisp->enabled = true;
		zlog_debug("LISP: VRF %s enabled", vrf->name);
	}
	return 0;
}

static int lisp_vrf_disable(struct vrf *vrf)
{
	struct lisp *lisp = vrf->info;

	if (lisp && lisp->enabled) {
		lisp->enabled = false;
		zlog_debug("LISP: VRF %s disabled", vrf->name);
	}
	return 0;
}

void lisp_vrf_init(void)
{
	vrf_init(lisp_vrf_new, lisp_vrf_enable, lisp_vrf_disable,
		 lisp_vrf_delete, NULL);
}

void lisp_vrf_terminate(void)
{
	vrf_terminate();
}

/* =========================================================================
 * Global init
 * ====================================================================== */

void lisp_if_init(void)
{
	if_add_hook(IF_NEW_HOOK, lisp_if_new_hook);
	if_add_hook(IF_DELETE_HOOK, lisp_if_delete_hook);
}

void lisp_init(void)
{
	/* Nothing global to initialise beyond lisp_vrf_init(). */
}
