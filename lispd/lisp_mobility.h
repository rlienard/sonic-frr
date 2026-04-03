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
 * This file implements the EID mobility procedures defined in
 * draft-ietf-lisp-eid-mobility-17.  Three main features are provided:
 *
 * 1. Map-Server (MS) role:
 *    The MS maintains a database (ms_db) mapping EID prefixes to the
 *    currently registered RLOC set and the xTR identity that registered it.
 *    When a new Map-Register arrives for an EID that is already in the
 *    database with a *different* RLOC set, the MS detects mobility and:
 *      a) Notifies pub/sub subscribers via Map-Notify (RFC 9437).
 *      b) Sends a Solicit-Map-Request (SMR) to every ITR-RLOC it has seen
 *         query for that EID (tracked in the per-entry itr_cache list).
 *      c) Sends Map-Notify to the old registering xTR so the old ETR can
 *         populate its Away Table.
 *
 * 2. SMR sender:
 *    lisp_mobility_send_smr() builds a Map-Request with the S-bit set and
 *    sends it directly (no ECM wrapper) to a specific ITR-RLOC.  Upon
 *    receiving the SMR, the ITR invalidates the stale map-cache entry and
 *    sends a fresh SMR-invoked Map-Request.
 *
 * 3. Away Table (ETR role):
 *    When an ETR receives a Map-Notify for an EID it previously registered
 *    locally, it adds the EID to its Away Table (away_table).  Subsequently,
 *    when data traffic for that EID arrives at the old ETR, it sends an SMR
 *    to the source ITR so the ITR's cache converges to the new location.
 */

#ifndef _LISP_MOBILITY_H
#define _LISP_MOBILITY_H

#include "prefix.h"
#include "table.h"
#include "linklist.h"
#include "thread.h"
#include "stream.h"
#include "lispd/lispd.h"

/* -------------------------------------------------------------------------
 * ITR-RLOC cache entry
 *
 * Stored in lisp_ms_entry.itr_cache.  The MS records each distinct
 * ITR-RLOC that has been seen in an ECM (Map-Request forwarding) for the
 * corresponding EID-prefix.  These RLOCs are the targets for SMRs when
 * mobility is detected.
 * ---------------------------------------------------------------------- */

struct lisp_itr_track {
	/* ITR-RLOC address. */
	struct prefix addr;
};

/* -------------------------------------------------------------------------
 * Map-Server EID database entry  (draft-ietf-lisp-eid-mobility §4)
 *
 * One entry per EID-prefix registered with this Map-Server.  Keyed by
 * EID-prefix in lisp->ms_db (a route_table).
 * ---------------------------------------------------------------------- */

struct lisp_ms_entry {
	/* EID-prefix covered by this entry. */
	struct prefix   eid_prefix;

	/* Current RLOC set (list of struct lisp_rloc *). */
	struct list    *rloc_list;

	/* Identity of the registering xTR. */
	uint8_t         xtr_id[16];
	uint8_t         site_id[8];

	/* TTL from the most-recent Map-Register (minutes). */
	uint32_t        ttl;

	/*
	 * RLOC of the xTR that sent the Map-Register.
	 * Used to send Map-Notify acknowledgements and mobility notifications
	 * to the previously-registered xTR.
	 */
	struct prefix   xtr_rloc;

	/*
	 * Cache of ITR-RLOCs that have queried for this EID-prefix.
	 * Used to target SMRs when a mobility event is detected.
	 * List of struct lisp_itr_track *.
	 */
	struct list    *itr_cache;

	/* Route-node back-pointer (into lisp->ms_db). */
	struct route_node *rn;

	/* Expiry thread: fires when TTL elapses with no re-registration. */
	struct thread  *t_expire;

	/* Back-pointer to LISP instance. */
	struct lisp    *lisp;
};

/* -------------------------------------------------------------------------
 * Away Table entry  (draft-ietf-lisp-eid-mobility §5.3)
 *
 * When an ETR receives a Map-Notify for an EID it previously registered
 * locally (meaning the EID has moved to another site), it adds the EID to
 * its away_table.  Subsequent data traffic for that EID arriving at the
 * old ETR triggers an SMR to the source ITR.
 * ---------------------------------------------------------------------- */

struct lisp_away_entry {
	/* EID-prefix that has moved away. */
	struct prefix     eid_prefix;

	/* Route-node back-pointer (into lisp->away_table). */
	struct route_node *rn;
};

/* =========================================================================
 * Prototypes — Map-Server side
 * ====================================================================== */

/*
 * Process an incoming Map-Register as a Map-Server.
 * Decodes the message, verifies authentication, updates ms_db, and — if
 * the RLOC set has changed — triggers SMR and pub/sub notifications.
 * Also sends a Map-Notify acknowledgement when the M-bit is set.
 */
extern void lisp_mobility_handle_map_register(struct lisp *lisp,
					      struct stream *s,
					      struct sockaddr_storage *src);

/*
 * Record an ITR-RLOC that issued a Map-Request for eid_prefix.
 * Called from the ECM handler so the MS can target SMRs correctly.
 * Duplicates (same RLOC for same EID) are silently discarded.
 */
extern void lisp_mobility_track_itr(struct lisp *lisp,
				    const struct prefix *eid_prefix,
				    const struct prefix *itr_rloc);

/* Look up an EID-prefix in the MS database.  Returns NULL if not found. */
extern struct lisp_ms_entry *
lisp_mobility_ms_lookup(struct lisp *lisp, const struct prefix *eid_prefix);

/* Clean up all MS database entries for a LISP instance. */
extern void lisp_mobility_ms_db_clean(struct lisp *lisp);

/* =========================================================================
 * Prototypes — SMR send / receive
 * ====================================================================== */

/*
 * Send a Solicit-Map-Request (Map-Request with S-bit=1) for eid_prefix to
 * itr_rloc.  Sent directly (no ECM wrapper) on port 4342.
 * Used by: MS when mobility detected; ETR when away-traffic arrives.
 */
extern void lisp_mobility_send_smr(struct lisp *lisp,
				   const struct prefix *eid_prefix,
				   const struct prefix *itr_rloc);

/*
 * Handle a received Solicit-Map-Request (Map-Request with S-bit=1).
 * Invalidates the map-cache entries for the queried EID-prefixes and
 * sends an SMR-invoked Map-Request (s-bit=1) to obtain fresh mappings.
 */
extern void lisp_mobility_handle_smr(struct lisp *lisp,
				     struct lisp_map_request *req,
				     struct sockaddr_storage *src);

/* =========================================================================
 * Prototypes — Away Table (ETR role)
 * ====================================================================== */

/* Add eid_prefix to the away table (EID has moved away from this ETR). */
extern void lisp_mobility_away_add(struct lisp *lisp,
				   const struct prefix *eid_prefix);

/*
 * Look up eid_prefix in the away table.
 * Returns true if the EID is known to have moved away from this ETR.
 */
extern bool lisp_mobility_away_lookup(struct lisp *lisp,
				      const struct prefix *eid_prefix);

/* Clean up all away-table entries for a LISP instance. */
extern void lisp_mobility_away_clean(struct lisp *lisp);

/* =========================================================================
 * CLI init
 * ====================================================================== */

/* Register EID-mobility CLI commands (called from lisp_cli_init). */
extern void lisp_mobility_cli_init(void);

#endif /* _LISP_MOBILITY_H */
