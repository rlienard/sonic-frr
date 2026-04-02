/* LISP Publish/Subscribe (RFC 9437 / draft-ietf-lisp-pubsub-15).
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
 * Overview of pub/sub state machines (RFC 9437):
 *
 * MAP-SERVER SIDE
 * ---------------
 * Subscription is keyed by (EID-prefix, xTR-ID).
 *
 * 1. On Map-Request with N-bit set and ITR-RLOC(s):
 *    lisp_pubsub_handle_subscribe() → upsert struct lisp_subscription,
 *    reset TTL timer, send confirming Map-Notify.
 *
 * 2. On Map-Register / mapping update:
 *    lisp_pubsub_notify_subscribers() → for each matching subscription,
 *    build Map-Notify, increment last_notify_nonce, send, arm ACK timer.
 *
 * 3. On Map-Notify-Ack from subscriber:
 *    lisp_pubsub_handle_notify_ack() → cancel ACK timer, clear retry count.
 *
 * 4. On ACK timeout: retry up to LISP_PUBSUB_MAX_RETRIES, then try next
 *    ITR-RLOC; if all RLOCs exhausted, remove subscription.
 *
 * 5. On subscription TTL expiry (t_expire): remove state, send Map-Notify TTL=0.
 *
 * 6. On EID-prefix withdrawal:
 *    lisp_pubsub_withdraw() → send Map-Notify TTL=0, remove all subs.
 *
 * SUBSCRIBER (xTR/ITR) SIDE
 * -------------------------
 * State is one struct lisp_sub_state per EID-prefix.
 *
 * 1. lisp_pubsub_subscribe():
 *    Send Map-Request with N-bit, I-bit, xTR-ID, Site-ID.
 *    Arm t_refresh to re-subscribe before TTL expiry.
 *
 * 2. lisp_pubsub_handle_notify():
 *    Incoming Map-Notify as a publication.
 *    Replay-protect via nonce > last_notify_nonce.
 *    Update map-cache, send Map-Notify-Ack.
 *
 * 3. lisp_pubsub_unsubscribe():
 *    Send Map-Request with AFI=0 ITR-RLOC (N-bit, I-bit still set).
 *    Cancel t_refresh, remove sub_state.
 */

#include <zebra.h>

#include "prefix.h"
#include "stream.h"
#include "linklist.h"
#include "log.h"
#include "memory.h"
#include "thread.h"
#include "vty.h"
#include "command.h"
#include "sockunion.h"

#include "lispd/lispd.h"
#include "lispd/lisp_pubsub.h"
#include "lispd/lisp_packet.h"
#include "lispd/lisp_memory.h"
#include "lispd/lisp_debug.h"
#include "lispd/lisp_auth.h"

/* =========================================================================
 * Internal forward declarations
 * ====================================================================== */

static int lisp_pubsub_ack_timeout(struct thread *t);
static int lisp_pubsub_sub_expire(struct thread *t);
static int lisp_pubsub_refresh(struct thread *t);
static void lisp_sub_send_notify(struct lisp *lisp,
				 struct lisp_subscription *sub);

/* =========================================================================
 * Helpers
 * ====================================================================== */

/*
 * Find a subscription by (EID-prefix, xTR-ID).
 * Returns NULL if not found.
 */
static struct lisp_subscription *
lisp_sub_lookup(struct lisp *lisp, const struct prefix *eid,
		const uint8_t xtr_id[16])
{
	struct listnode *node;
	struct lisp_subscription *sub;

	for (ALL_LIST_ELEMENTS_RO(lisp->subscriptions, node, sub)) {
		if (prefix_same(&sub->eid_prefix, eid)
		    && memcmp(sub->xtr_id, xtr_id, 16) == 0)
			return sub;
	}
	return NULL;
}

/*
 * Find a sub_state by EID-prefix (subscriber side).
 */
static struct lisp_sub_state *
lisp_sub_state_lookup(struct lisp *lisp, const struct prefix *eid)
{
	struct listnode *node;
	struct lisp_sub_state *ss;

	for (ALL_LIST_ELEMENTS_RO(lisp->sub_states, node, ss)) {
		if (prefix_same(&ss->eid_prefix, eid))
			return ss;
	}
	return NULL;
}

/*
 * Free a subscription and all its resources.
 * Does NOT remove from lisp->subscriptions — caller must do that.
 */
static void lisp_subscription_free(struct lisp_subscription *sub)
{
	struct listnode *node, *nnode;
	struct lisp_sub_rloc *sr;

	THREAD_OFF(sub->t_ack_timeout);
	THREAD_OFF(sub->t_expire);

	for (ALL_LIST_ELEMENTS(sub->rloc_list, node, nnode, sr))
		XFREE(MTYPE_LISP_SUB_RLOC, sr);

	list_delete(&sub->rloc_list);
	XFREE(MTYPE_LISP_SUBSCRIPTION, sub);
}

/*
 * Remove a subscription from lisp->subscriptions and free it.
 */
static void lisp_subscription_delete(struct lisp *lisp,
				     struct lisp_subscription *sub)
{
	listnode_delete(lisp->subscriptions, sub);
	lisp_subscription_free(sub);
}

/* =========================================================================
 * Map-Server side — subscribe / notify
 * ====================================================================== */

void lisp_pubsub_handle_subscribe(struct lisp *lisp,
				  struct lisp_map_request *req,
				  struct sockaddr_storage *src)
{
	int i, j;
	char buf[PREFIX2STR_BUFFER];

	for (i = 0; i < req->record_count && i < 8; i++) {
		struct lisp_subscription *sub;
		struct listnode *node, *nnode;
		struct lisp_sub_rloc *sr;

		if (!req->records[i].subscribe_n)
			continue;

		sub = lisp_sub_lookup(lisp, &req->records[i].eid_prefix,
				      req->xtr_id);

		if (!sub) {
			sub = XCALLOC(MTYPE_LISP_SUBSCRIPTION, sizeof(*sub));
			sub->eid_prefix    = req->records[i].eid_prefix;
			memcpy(sub->xtr_id,  req->xtr_id,  16);
			memcpy(sub->site_id, req->site_id,  8);
			sub->rloc_list     = list_new();
			sub->lisp          = lisp;
			listnode_add(lisp->subscriptions, sub);

			if (IS_LISP_DEBUG_PUBSUB) {
				prefix2str(&sub->eid_prefix, buf, sizeof(buf));
				zlog_debug("LISP pubsub: new subscription for %s",
					   buf);
			}
		} else {
			/* Refresh: clear old RLOC list. */
			for (ALL_LIST_ELEMENTS(sub->rloc_list, node, nnode, sr))
				XFREE(MTYPE_LISP_SUB_RLOC, sr);
			list_delete_all_node(sub->rloc_list);
			THREAD_OFF(sub->t_expire);
		}

		/* Update nonce from the incoming Map-Request. */
		memcpy(sub->nonce, req->nonce, LISP_NONCE_LEN);
		sub->current_rloc_idx = 0;
		sub->retries          = 0;

		/* Populate RLOC list from ITR-RLOCs in the request. */
		for (j = 0; j < req->itr_rloc_count && j < 32; j++) {
			if (req->itr_rlocs[j].family == 0)
				continue; /* AFI=0 treated as unsubscribe */
			sr = XCALLOC(MTYPE_LISP_SUB_RLOC, sizeof(*sr));
			sr->addr = req->itr_rlocs[j];
			listnode_add(sub->rloc_list, sr);
		}

		/* Arm subscription expiry timer. */
		thread_add_timer(master, lisp_pubsub_sub_expire, sub,
				 LISP_PUBSUB_DEFAULT_NEG_TTL_MINS * 60,
				 &sub->t_expire);

		/*
		 * Send confirming Map-Notify (RFC 9437 §4.2).
		 * This carries the current mapping (or a negative entry) so the
		 * subscriber can prime its cache immediately.
		 */
		lisp_sub_send_notify(lisp, sub);
	}
}

void lisp_pubsub_handle_unsubscribe(struct lisp *lisp,
				    struct lisp_map_request *req,
				    struct sockaddr_storage *src)
{
	int i;
	char buf[PREFIX2STR_BUFFER];

	for (i = 0; i < req->record_count && i < 8; i++) {
		struct lisp_subscription *sub;

		if (!req->records[i].subscribe_n)
			continue;

		sub = lisp_sub_lookup(lisp, &req->records[i].eid_prefix,
				      req->xtr_id);
		if (!sub)
			continue;

		if (IS_LISP_DEBUG_PUBSUB) {
			prefix2str(&sub->eid_prefix, buf, sizeof(buf));
			zlog_debug("LISP pubsub: unsubscribe for %s", buf);
		}

		/* Send Map-Notify with TTL=0 to acknowledge unsubscription. */
		lisp_pubsub_withdraw(lisp, &sub->eid_prefix);
	}
}

/*
 * Build and send a Map-Notify to a single subscriber for eid_prefix.
 * The nonce is taken from sub->last_notify_nonce (incremented before call).
 */
static void lisp_sub_send_notify(struct lisp *lisp,
				 struct lisp_subscription *sub)
{
	struct lisp_map_entry *me;
	struct lisp_map_notify notify;
	struct lisp_auth_key *key;
	struct lisp_sub_rloc *sr;
	struct listnode *node;
	struct prefix *dst_rloc = NULL;
	struct sockaddr_in sin;
	struct stream *s;
	int idx = 0;
	char buf[PREFIX2STR_BUFFER];

	/* Increment nonce for this new notification. */
	sub->last_notify_nonce++;

	memset(&notify, 0, sizeof(notify));

	/* Fill in nonce (stored as big-endian 8 bytes). */
	{
		uint64_t n = htobe64(sub->last_notify_nonce);
		memcpy(notify.nonce, &n, LISP_NONCE_LEN);
	}

	/* Look up the current mapping. */
	me = lisp_map_cache_lookup(lisp, &sub->eid_prefix);

	notify.record_count = 1;
	notify.records[0].eid_prefix = sub->eid_prefix;

	if (me) {
		struct lisp_rloc *rloc;

		notify.records[0].ttl           = me->ttl;
		notify.records[0].action        = me->action;
		notify.records[0].authoritative = true;

		/* Copy RLOCs from the map entry. */
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
		/* Negative Map-Notify: TTL = default, action = Natively-Forward. */
		notify.records[0].ttl    = LISP_PUBSUB_DEFAULT_NEG_TTL_MINS;
		notify.records[0].action = LISP_ACTION_NATIVELY_FORWARD;
	}

	/* Pick destination RLOC (round-robin by current_rloc_idx). */
	for (ALL_LIST_ELEMENTS_RO(sub->rloc_list, node, sr)) {
		if (idx++ == sub->current_rloc_idx) {
			dst_rloc = &sr->addr;
			break;
		}
	}

	if (!dst_rloc) {
		if (IS_LISP_DEBUG_PUBSUB) {
			prefix2str(&sub->eid_prefix, buf, sizeof(buf));
			zlog_debug("LISP pubsub: no RLOC for subscriber of %s",
				   buf);
		}
		return;
	}

	if (dst_rloc->family != AF_INET) {
		/* IPv6 RLOC support would go here; skip for now. */
		return;
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

	if (IS_LISP_DEBUG_PUBSUB) {
		char dst_buf[INET_ADDRSTRLEN];
		prefix2str(&sub->eid_prefix, buf, sizeof(buf));
		inet_ntop(AF_INET, &dst_rloc->u.prefix4, dst_buf,
			  sizeof(dst_buf));
		zlog_debug("LISP pubsub: sent Map-Notify nonce=%" PRIu64
			   " for %s to %s",
			   sub->last_notify_nonce, buf, dst_buf);
	}

	/* Arm ACK timeout. */
	THREAD_OFF(sub->t_ack_timeout);
	thread_add_timer(master, lisp_pubsub_ack_timeout, sub,
			 LISP_PUBSUB_ACK_TIMEOUT_SECS, &sub->t_ack_timeout);
}

/*
 * ACK timeout handler: retry on next ITR-RLOC, or drop subscription.
 */
static int lisp_pubsub_ack_timeout(struct thread *t)
{
	struct lisp_subscription *sub = THREAD_ARG(t);
	struct lisp *lisp = sub->lisp;
	int rloc_count;
	char buf[PREFIX2STR_BUFFER];

	sub->t_ack_timeout = NULL;
	sub->retries++;

	rloc_count = listcount(sub->rloc_list);

	if (sub->retries >= LISP_PUBSUB_MAX_RETRIES) {
		/* Exhausted retries on current RLOC; try next. */
		sub->retries = 0;
		sub->current_rloc_idx = (sub->current_rloc_idx + 1) % rloc_count;

		if (sub->current_rloc_idx == 0) {
			/* Cycled through all RLOCs without an ACK. */
			if (IS_LISP_DEBUG_PUBSUB) {
				prefix2str(&sub->eid_prefix, buf, sizeof(buf));
				zlog_debug("LISP pubsub: all RLOCs exhausted "
					   "for subscriber of %s, removing",
					   buf);
			}
			lisp_subscription_delete(lisp, sub);
			return 0;
		}
	}

	/* Retransmit Map-Notify to current RLOC. */
	lisp_sub_send_notify(lisp, sub);
	return 0;
}

/*
 * Subscription TTL expiry: remove state.
 */
static int lisp_pubsub_sub_expire(struct thread *t)
{
	struct lisp_subscription *sub = THREAD_ARG(t);
	struct lisp *lisp = sub->lisp;
	char buf[PREFIX2STR_BUFFER];

	sub->t_expire = NULL;

	if (IS_LISP_DEBUG_PUBSUB) {
		prefix2str(&sub->eid_prefix, buf, sizeof(buf));
		zlog_debug("LISP pubsub: subscription expired for %s", buf);
	}

	lisp_subscription_delete(lisp, sub);
	return 0;
}

void lisp_pubsub_notify_subscribers(struct lisp *lisp,
				    const struct prefix *eid_prefix)
{
	struct listnode *node;
	struct lisp_subscription *sub;
	char buf[PREFIX2STR_BUFFER];

	if (IS_LISP_DEBUG_PUBSUB) {
		prefix2str(eid_prefix, buf, sizeof(buf));
		zlog_debug("LISP pubsub: notifying subscribers for %s", buf);
	}

	for (ALL_LIST_ELEMENTS_RO(lisp->subscriptions, node, sub)) {
		if (!prefix_same(&sub->eid_prefix, eid_prefix))
			continue;

		sub->retries          = 0;
		sub->current_rloc_idx = 0;
		lisp_sub_send_notify(lisp, sub);
	}
}

void lisp_pubsub_withdraw(struct lisp *lisp, const struct prefix *eid_prefix)
{
	struct listnode *node, *nnode;
	struct lisp_subscription *sub;
	char buf[PREFIX2STR_BUFFER];

	if (IS_LISP_DEBUG_PUBSUB) {
		prefix2str(eid_prefix, buf, sizeof(buf));
		zlog_debug("LISP pubsub: withdraw notifications for %s", buf);
	}

	for (ALL_LIST_ELEMENTS(lisp->subscriptions, node, nnode, sub)) {
		struct lisp_map_notify notify;
		struct lisp_auth_key *key;
		struct lisp_sub_rloc *sr;
		struct listnode *rnode;
		struct sockaddr_in sin;
		struct stream *s;
		int idx = 0;

		if (!prefix_same(&sub->eid_prefix, eid_prefix))
			continue;

		/* Build TTL=0 Map-Notify to signal mapping withdrawal. */
		memset(&notify, 0, sizeof(notify));
		sub->last_notify_nonce++;
		{
			uint64_t n = htobe64(sub->last_notify_nonce);
			memcpy(notify.nonce, &n, LISP_NONCE_LEN);
		}
		notify.record_count         = 1;
		notify.records[0].eid_prefix = *eid_prefix;
		notify.records[0].ttl        = 0;
		notify.records[0].action     = LISP_ACTION_NATIVELY_FORWARD;

		key = lisp_auth_key_get(lisp, notify.key_id);
		s   = stream_new(LISP_MAX_PACKET_SIZE);

		for (ALL_LIST_ELEMENTS_RO(sub->rloc_list, rnode, sr)) {
			if (sr->addr.family != AF_INET)
				continue;

			if (lisp_encode_map_notify(s, &notify, key) < 0)
				break;

			memset(&sin, 0, sizeof(sin));
			sin.sin_family = AF_INET;
			sin.sin_port   = htons(LISP_CONTROL_PORT);
			sin.sin_addr   = sr->addr.u.prefix4;

			sendto(lisp->sock, STREAM_DATA(s),
			       stream_get_endp(s), 0,
			       (struct sockaddr *)&sin, sizeof(sin));

			stream_reset(s);
			(void)idx;
		}

		stream_free(s);
		lisp_subscription_delete(lisp, sub);
	}
}

void lisp_pubsub_handle_notify_ack(struct lisp *lisp,
				   struct lisp_map_notify_ack *ack,
				   struct sockaddr_storage *src)
{
	struct listnode *node;
	struct lisp_subscription *sub;
	uint64_t nonce_val;
	char buf[PREFIX2STR_BUFFER];

	memcpy(&nonce_val, ack->nonce, LISP_NONCE_LEN);
	nonce_val = be64toh(nonce_val);

	for (ALL_LIST_ELEMENTS_RO(lisp->subscriptions, node, sub)) {
		if (sub->last_notify_nonce != nonce_val)
			continue;

		if (IS_LISP_DEBUG_PUBSUB) {
			prefix2str(&sub->eid_prefix, buf, sizeof(buf));
			zlog_debug("LISP pubsub: Map-Notify-Ack received "
				   "nonce=%" PRIu64 " for %s",
				   nonce_val, buf);
		}

		THREAD_OFF(sub->t_ack_timeout);
		sub->retries = 0;
		return;
	}

	if (IS_LISP_DEBUG_PUBSUB)
		zlog_debug("LISP pubsub: spurious Map-Notify-Ack "
			   "nonce=%" PRIu64, nonce_val);
}

void lisp_pubsub_clean(struct lisp *lisp)
{
	struct listnode *node, *nnode;
	struct lisp_subscription *sub;

	for (ALL_LIST_ELEMENTS(lisp->subscriptions, node, nnode, sub))
		lisp_subscription_free(sub);

	list_delete_all_node(lisp->subscriptions);
}

/* =========================================================================
 * Subscriber (xTR/ITR) side
 * ====================================================================== */

/*
 * Send a Map-Request with N-bit, I-bit, xTR-ID, Site-ID to subscribe.
 * Used both for initial subscription and periodic refresh.
 */
static void lisp_pubsub_send_subscribe_req(struct lisp *lisp,
					   const struct prefix *eid_prefix)
{
	struct lisp_map_request req;
	struct lisp_ms_mr *mr;
	struct listnode *node;
	struct sockaddr_in sin;
	struct stream *s;
	char buf[PREFIX2STR_BUFFER];

	memset(&req, 0, sizeof(req));
	lisp_nonce_generate(req.nonce);

	req.record_count           = 1;
	req.records[0].eid_prefix  = *eid_prefix;
	req.records[0].subscribe_n = true;    /* N-bit: subscribe */

	/*
	 * I-bit: include xTR-ID and Site-ID so the Map-Server can key the
	 * subscription on (EID-prefix, xTR-ID) per RFC 9437 §4.1.
	 */
	req.id_present = lisp->id_configured;
	if (lisp->id_configured) {
		memcpy(req.xtr_id,  lisp->xtr_id,  16);
		memcpy(req.site_id, lisp->site_id,  8);
	}

	/* Use our configured ITR-RLOCs as the source RLOC list. */
	req.itr_rloc_count = 1;
	memset(&req.itr_rlocs[0], 0, sizeof(req.itr_rlocs[0]));
	/* Placeholder: in a full implementation this would be the local RLOC. */

	s = stream_new(LISP_MAX_PACKET_SIZE);

	for (ALL_LIST_ELEMENTS_RO(lisp->ms_mr_list, node, mr)) {
		if (!mr->map_resolver)
			continue;
		if (mr->addr.family != AF_INET)
			continue;

		stream_reset(s);
		if (lisp_encode_ecm(s, &req, NULL, &mr->addr) < 0)
			continue;

		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port   = htons(LISP_CONTROL_PORT);
		sin.sin_addr   = mr->addr.u.prefix4;

		sendto(lisp->sock, STREAM_DATA(s), stream_get_endp(s), 0,
		       (struct sockaddr *)&sin, sizeof(sin));

		if (IS_LISP_DEBUG_PUBSUB) {
			char mr_buf[INET_ADDRSTRLEN];
			prefix2str(eid_prefix, buf, sizeof(buf));
			inet_ntop(AF_INET, &mr->addr.u.prefix4, mr_buf,
				  sizeof(mr_buf));
			zlog_debug("LISP pubsub: sent subscribe Map-Request "
				   "for %s to MR %s", buf, mr_buf);
		}
	}

	stream_free(s);
}

/*
 * Refresh timer: re-send the subscription before TTL expiry.
 */
static int lisp_pubsub_refresh(struct thread *t)
{
	struct lisp_sub_state *ss = THREAD_ARG(t);

	ss->t_refresh = NULL;

	if (!ss->active)
		return 0;

	lisp_pubsub_send_subscribe_req(ss->lisp, &ss->eid_prefix);

	/*
	 * Re-arm refresh.  We use half of the negative TTL as the interval
	 * to ensure the subscription is renewed well before expiry.
	 */
	thread_add_timer(master, lisp_pubsub_refresh, ss,
			 (LISP_PUBSUB_DEFAULT_NEG_TTL_MINS * 60) / 2,
			 &ss->t_refresh);
	return 0;
}

void lisp_pubsub_subscribe(struct lisp *lisp, const struct prefix *eid_prefix)
{
	struct lisp_sub_state *ss;
	char buf[PREFIX2STR_BUFFER];

	ss = lisp_sub_state_lookup(lisp, eid_prefix);
	if (!ss) {
		ss = XCALLOC(MTYPE_LISP_SUB_STATE, sizeof(*ss));
		ss->eid_prefix = *eid_prefix;
		ss->lisp       = lisp;
		listnode_add(lisp->sub_states, ss);
	}

	ss->active           = true;
	ss->last_notify_nonce = 0;

	lisp_pubsub_send_subscribe_req(lisp, eid_prefix);

	/* Arm refresh timer. */
	THREAD_OFF(ss->t_refresh);
	thread_add_timer(master, lisp_pubsub_refresh, ss,
			 (LISP_PUBSUB_DEFAULT_NEG_TTL_MINS * 60) / 2,
			 &ss->t_refresh);

	if (IS_LISP_DEBUG_PUBSUB) {
		prefix2str(eid_prefix, buf, sizeof(buf));
		zlog_debug("LISP pubsub: subscribed to %s", buf);
	}
}

void lisp_pubsub_unsubscribe(struct lisp *lisp, const struct prefix *eid_prefix)
{
	struct lisp_map_request req;
	struct lisp_ms_mr *mr;
	struct lisp_sub_state *ss;
	struct listnode *node;
	struct sockaddr_in sin;
	struct stream *s;
	char buf[PREFIX2STR_BUFFER];

	ss = lisp_sub_state_lookup(lisp, eid_prefix);
	if (ss) {
		THREAD_OFF(ss->t_refresh);
		ss->active = false;
		listnode_delete(lisp->sub_states, ss);
		XFREE(MTYPE_LISP_SUB_STATE, ss);
	}

	/* Send Map-Request with AFI=0 ITR-RLOC (signals unsubscription). */
	memset(&req, 0, sizeof(req));
	lisp_nonce_generate(req.nonce);

	req.record_count           = 1;
	req.records[0].eid_prefix  = *eid_prefix;
	req.records[0].subscribe_n = true;

	req.id_present = lisp->id_configured;
	if (lisp->id_configured) {
		memcpy(req.xtr_id,  lisp->xtr_id,  16);
		memcpy(req.site_id, lisp->site_id,  8);
	}

	/* AFI=0 ITR-RLOC: family=0 (unspecified). */
	req.itr_rloc_count = 1;
	memset(&req.itr_rlocs[0], 0, sizeof(req.itr_rlocs[0]));

	s = stream_new(LISP_MAX_PACKET_SIZE);

	for (ALL_LIST_ELEMENTS_RO(lisp->ms_mr_list, node, mr)) {
		if (!mr->map_resolver)
			continue;
		if (mr->addr.family != AF_INET)
			continue;

		stream_reset(s);
		if (lisp_encode_ecm(s, &req, NULL, &mr->addr) < 0)
			continue;

		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port   = htons(LISP_CONTROL_PORT);
		sin.sin_addr   = mr->addr.u.prefix4;

		sendto(lisp->sock, STREAM_DATA(s), stream_get_endp(s), 0,
		       (struct sockaddr *)&sin, sizeof(sin));
	}

	stream_free(s);

	if (IS_LISP_DEBUG_PUBSUB) {
		prefix2str(eid_prefix, buf, sizeof(buf));
		zlog_debug("LISP pubsub: unsubscribed from %s", buf);
	}
}

void lisp_pubsub_handle_notify(struct lisp *lisp,
			       struct lisp_map_notify *notify,
			       struct sockaddr_storage *src)
{
	struct lisp_sub_state *ss;
	uint64_t nonce_val;
	int i;
	char buf[PREFIX2STR_BUFFER];

	memcpy(&nonce_val, notify->nonce, LISP_NONCE_LEN);
	nonce_val = be64toh(nonce_val);

	for (i = 0; i < notify->record_count && i < 8; i++) {
		struct lisp_eid_record *rec = &notify->records[i];

		ss = lisp_sub_state_lookup(lisp, &rec->eid_prefix);
		if (!ss)
			continue;

		/*
		 * RFC 9437 §6 replay protection: nonce MUST be greater than
		 * the last nonce seen for this EID-prefix.
		 */
		if (nonce_val <= ss->last_notify_nonce) {
			if (IS_LISP_DEBUG_PUBSUB) {
				prefix2str(&rec->eid_prefix, buf, sizeof(buf));
				zlog_debug("LISP pubsub: dropped replay "
					   "Map-Notify nonce=%" PRIu64
					   " (last=%" PRIu64 ") for %s",
					   nonce_val, ss->last_notify_nonce,
					   buf);
			}
			continue;
		}

		ss->last_notify_nonce = nonce_val;

		if (IS_LISP_DEBUG_PUBSUB) {
			prefix2str(&rec->eid_prefix, buf, sizeof(buf));
			zlog_debug("LISP pubsub: Map-Notify publication "
				   "nonce=%" PRIu64 " for %s (TTL=%" PRIu32 ")",
				   nonce_val, buf, rec->ttl);
		}

		/* Update local map-cache from the publication. */
		if (rec->loc_count > 0) {
			struct lisp_rloc rloc;
			struct lisp_loc_record *lr = &rec->locs[0];

			memset(&rloc, 0, sizeof(rloc));
			rloc.rloc_addr  = lr->rloc;
			rloc.priority   = lr->priority;
			rloc.weight     = lr->weight;
			rloc.mpriority  = lr->mpriority;
			rloc.mweight    = lr->mweight;
			rloc.local      = !!(lr->flags & LISP_LOC_FLAG_L);
			rloc.reachable  = !!(lr->flags & LISP_LOC_FLAG_R);

			lisp_map_cache_add(lisp,
					   (struct prefix *)&rec->eid_prefix,
					   &rloc, rec->ttl, rec->action);
		} else {
			/* Negative or withdrawal (TTL=0). */
			if (rec->ttl == 0)
				lisp_map_cache_delete(lisp,
						      (struct prefix *)&rec->eid_prefix);
			else
				lisp_map_cache_add(lisp,
						   (struct prefix *)&rec->eid_prefix,
						   NULL, rec->ttl, rec->action);
		}
	}

	/* Send Map-Notify-Ack (RFC 9437 §5) back to the Map-Server. */
	lisp_send_map_notify_ack(lisp, notify->nonce, src);
}

/* =========================================================================
 * CLI — show lisp subscriptions
 * ====================================================================== */

DEFUN(show_lisp_subscriptions,
      show_lisp_subscriptions_cmd,
      "show lisp subscriptions",
      SHOW_STR
      "LISP information\n"
      "Map-Server subscription state (RFC 9437)\n")
{
	struct vrf *vrf;
	struct lisp *lisp;
	struct listnode *node, *rnode;
	struct lisp_subscription *sub;
	char eid_buf[PREFIX2STR_BUFFER];
	char xtr_buf[33]; /* 32 hex chars + NUL */
	int i;

	RB_FOREACH(vrf, vrf_name_head, &vrfs_by_name) {
		lisp = vrf->info;
		if (!lisp || !lisp->enabled)
			continue;

		vty_out(vty, "VRF %s:\n", vrf->name);

		if (listcount(lisp->subscriptions) == 0) {
			vty_out(vty, "  No subscriptions.\n");
			continue;
		}

		for (ALL_LIST_ELEMENTS_RO(lisp->subscriptions, node, sub)) {
			struct lisp_sub_rloc *sr;

			prefix2str(&sub->eid_prefix, eid_buf, sizeof(eid_buf));
			for (i = 0; i < 16; i++)
				snprintf(xtr_buf + 2 * i, 3, "%02x",
					 sub->xtr_id[i]);

			vty_out(vty, "  EID: %-24s  xTR-ID: %s\n",
				eid_buf, xtr_buf);
			vty_out(vty, "    last-notify-nonce: %" PRIu64 "\n",
				sub->last_notify_nonce);
			vty_out(vty, "    RLOCs:\n");

			for (ALL_LIST_ELEMENTS_RO(sub->rloc_list, rnode, sr)) {
				char rloc_buf[PREFIX2STR_BUFFER];
				prefix2str(&sr->addr, rloc_buf, sizeof(rloc_buf));
				vty_out(vty, "      %s\n", rloc_buf);
			}
		}
	}

	return CMD_SUCCESS;
}

DEFUN(show_lisp_sub_states,
      show_lisp_sub_states_cmd,
      "show lisp subscription-states",
      SHOW_STR
      "LISP information\n"
      "xTR subscription states (RFC 9437)\n")
{
	struct vrf *vrf;
	struct lisp *lisp;
	struct listnode *node;
	struct lisp_sub_state *ss;
	char buf[PREFIX2STR_BUFFER];

	RB_FOREACH(vrf, vrf_name_head, &vrfs_by_name) {
		lisp = vrf->info;
		if (!lisp || !lisp->enabled)
			continue;

		vty_out(vty, "VRF %s:\n", vrf->name);

		if (listcount(lisp->sub_states) == 0) {
			vty_out(vty, "  No active subscriptions.\n");
			continue;
		}

		for (ALL_LIST_ELEMENTS_RO(lisp->sub_states, node, ss)) {
			prefix2str(&ss->eid_prefix, buf, sizeof(buf));
			vty_out(vty,
				"  EID: %-24s  active: %s  last-nonce: %" PRIu64 "\n",
				buf,
				ss->active ? "yes" : "no",
				ss->last_notify_nonce);
		}
	}

	return CMD_SUCCESS;
}

void lisp_pubsub_cli_init(void)
{
	install_element(VIEW_NODE,   &show_lisp_subscriptions_cmd);
	install_element(ENABLE_NODE, &show_lisp_subscriptions_cmd);
	install_element(VIEW_NODE,   &show_lisp_sub_states_cmd);
	install_element(ENABLE_NODE, &show_lisp_sub_states_cmd);
}
