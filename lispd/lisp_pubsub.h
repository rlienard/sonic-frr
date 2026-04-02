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

#ifndef _LISP_PUBSUB_H
#define _LISP_PUBSUB_H

#include "prefix.h"
#include "thread.h"
#include "linklist.h"
#include "lispd/lispd.h"

/*
 * RFC 9437 §5 — default TTL for subscription state when the queried
 * EID-Prefix is not present in the mapping database.  The Map-Server
 * SHOULD use 15 minutes.
 */
#define LISP_PUBSUB_DEFAULT_NEG_TTL_MINS  15

/*
 * How long (seconds) a Map-Server waits for a Map-Notify-Ack before
 * retrying to a different ITR-RLOC.
 */
#define LISP_PUBSUB_ACK_TIMEOUT_SECS  4

/* Maximum Map-Notify retransmission attempts per ITR-RLOC set. */
#define LISP_PUBSUB_MAX_RETRIES  3

/* -------------------------------------------------------------------------
 * Subscriber RLOC entry
 *
 * A single xTR may have multiple ITR-RLOCs.  The Map-Server stores all of
 * them so it can try each one when a Map-Notify-Ack is not received.
 * ---------------------------------------------------------------------- */

struct lisp_sub_rloc {
	struct prefix addr;   /* ITR-RLOC address */
};

/* -------------------------------------------------------------------------
 * Subscription state (Map-Server side, RFC 9437 §4.2)
 *
 * Keyed by (EID-prefix, xTR-ID).  The Map-Server maintains one entry per
 * subscribing xTR per EID-prefix.
 * ---------------------------------------------------------------------- */

struct lisp_subscription {
	/* EID-prefix being subscribed to. */
	struct prefix eid_prefix;

	/* xTR-ID of the subscriber (128 bits). */
	uint8_t xtr_id[16];

	/* Site-ID of the subscriber (64 bits). */
	uint8_t site_id[8];

	/*
	 * Nonce from the last Map-Request with N-bit set for this
	 * (EID, xTR-ID) pair.  Used to correlate Map-Notify-Ack and to
	 * detect replay attacks (RFC 9437 §6: incoming Map-Notify nonce
	 * MUST be greater than last_nonce_seen on the subscriber side).
	 */
	uint8_t nonce[LISP_NONCE_LEN];

	/*
	 * last_notify_nonce: last nonce sent in a Map-Notify to this
	 * subscriber.  Incremented for each new notification.
	 * On the subscriber side this is the "last nonce seen" used for
	 * replay protection.
	 */
	uint64_t last_notify_nonce;

	/* List of ITR-RLOCs (struct lisp_sub_rloc *). */
	struct list *rloc_list;

	/* Index into rloc_list of the RLOC currently being tried. */
	int current_rloc_idx;

	/* Retransmission counter for pending Map-Notify. */
	int retries;

	/* Retransmission / ACK-wait thread. */
	struct thread *t_ack_timeout;

	/* Subscription expiry thread (fires when sub TTL expires). */
	struct thread *t_expire;

	/* Back-pointer to the owning LISP instance. */
	struct lisp *lisp;

	/* Linked-list node (stored in lisp->subscriptions). */
	struct listnode *node;
};

/* -------------------------------------------------------------------------
 * Subscriber side: pending subscription entry (xTR/ITR side, RFC 9437 §4.1)
 *
 * The ITR keeps track of EID-prefixes it has subscribed to so it can:
 *  - Refresh the subscription before it expires.
 *  - Apply replay protection on incoming Map-Notify publications.
 * ---------------------------------------------------------------------- */

struct lisp_sub_state {
	/* EID-prefix we subscribed for. */
	struct prefix eid_prefix;

	/*
	 * Last nonce seen in a Map-Notify received as a publication for
	 * this EID-prefix.  RFC 9437 §6: if incoming nonce <= last_nonce,
	 * drop the message (possible replay).
	 */
	uint64_t last_notify_nonce;

	/* Subscription is active. */
	bool active;

	/* Refresh thread (fires before TTL expiry to re-subscribe). */
	struct thread *t_refresh;

	/* Back-pointer. */
	struct lisp *lisp;
};

/* -------------------------------------------------------------------------
 * Prototypes — Map-Server (publisher) side
 * ---------------------------------------------------------------------- */

/*
 * Process an incoming Map-Request with N-bit set on one or more EID-records.
 * Creates or updates subscription state.  Sends Map-Notify to confirm.
 * Called from lisp_recv_packet() after decoding the Map-Request.
 */
extern void lisp_pubsub_handle_subscribe(struct lisp *lisp,
					 struct lisp_map_request *req,
					 struct sockaddr_storage *src);

/*
 * Process an incoming Map-Request with N-bit set and AFI=0 ITR-RLOC.
 * Removes subscription state and sends Map-Notify (TTL=0).
 */
extern void lisp_pubsub_handle_unsubscribe(struct lisp *lisp,
					   struct lisp_map_request *req,
					   struct sockaddr_storage *src);

/*
 * Called when a mapping is updated (e.g. new Map-Register received).
 * Notifies all subscribers for eid_prefix by sending Map-Notify messages.
 */
extern void lisp_pubsub_notify_subscribers(struct lisp *lisp,
					   const struct prefix *eid_prefix);

/*
 * Called when an EID-prefix is withdrawn or its TTL expires.
 * Sends Map-Notify with TTL=0 to all subscribers then removes state.
 */
extern void lisp_pubsub_withdraw(struct lisp *lisp,
				 const struct prefix *eid_prefix);

/*
 * Handle incoming Map-Notify-Ack from a subscriber.
 * Cancels the retransmission timer for the pending Map-Notify.
 */
extern void lisp_pubsub_handle_notify_ack(struct lisp *lisp,
					  struct lisp_map_notify_ack *ack,
					  struct sockaddr_storage *src);

/* Clean up all subscription state for a LISP instance. */
extern void lisp_pubsub_clean(struct lisp *lisp);

/* -------------------------------------------------------------------------
 * Prototypes — Subscriber (xTR/ITR) side
 * ---------------------------------------------------------------------- */

/*
 * Send a Map-Request with N-bit set to subscribe to EID-prefix updates.
 * xTR-ID and Site-ID are taken from lisp->xtr_id / lisp->site_id.
 */
extern void lisp_pubsub_subscribe(struct lisp *lisp,
				  const struct prefix *eid_prefix);

/*
 * Send a Map-Request with N-bit set and AFI=0 ITR-RLOC to unsubscribe.
 */
extern void lisp_pubsub_unsubscribe(struct lisp *lisp,
				    const struct prefix *eid_prefix);

/*
 * Handle an incoming Map-Notify received as a publication (not a
 * subscription confirmation).  Applies replay protection, updates
 * map-cache, sends Map-Notify-Ack.
 */
extern void lisp_pubsub_handle_notify(struct lisp *lisp,
				      struct lisp_map_notify *notify,
				      struct sockaddr_storage *src);

/* CLI init. */
extern void lisp_pubsub_cli_init(void);

#endif /* _LISP_PUBSUB_H */
