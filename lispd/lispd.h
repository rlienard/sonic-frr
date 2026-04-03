/* LISP (Locator/ID Separation Protocol) daemon — RFC 9301.
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

#ifndef _ZEBRA_LISP_H
#define _ZEBRA_LISP_H

#include "hook.h"
#include "nexthop.h"
#include "distribute.h"
#include "hash.h"
#include "lispd/lisp_memory.h"
#include "lispd/lisp_auth.h"
/* UDP port numbers (RFC 9301). */
#define LISP_DATA_PORT        4341
#define LISP_CONTROL_PORT     4342

/* LISP VTY port. */
#define LISP_VTY_PORT         2614

/* Default configuration file name. */
#define LISPD_DEFAULT_CONFIG  "lispd.conf"

/*
 * Map-cache default TTL in minutes (RFC 9301 §6.2: TTL field is in minutes).
 * A value of 0 means "remove from cache immediately" (do not store).
 * A value of 0xffffffff means "store indefinitely".
 */
#define LISP_MAP_CACHE_TTL_DEFAULT    1440  /* 24 hours in minutes */
#define LISP_MAP_CACHE_TTL_PERMANENT  0xffffffff

/* How many seconds before TTL expiry to send a refresh Map-Request. */
#define LISP_MAP_CACHE_REFRESH_SECS   60

/* RLOC probe interval (seconds). */
#define LISP_RLOC_PROBE_INTERVAL    30

/* Default Map-Register interval (seconds, RFC 9301 §8.2). */
#define LISP_MAP_REGISTER_DEFAULT_INTERVAL  60

/* LISP message type codes (RFC 9301 §6). */
#define LISP_MAP_REQUEST     1
#define LISP_MAP_REPLY       2
#define LISP_MAP_REGISTER    3
#define LISP_MAP_NOTIFY      4
#define LISP_MAP_NOTIFY_ACK  5   /* RFC 9437 §5 */
#define LISP_ENCAP_CONTROL   8

/* LISP AFI values. */
#define LISP_AFI_IPV4        1
#define LISP_AFI_IPV6        2

/*
 * Action codes for negative Map-Reply (RFC 9301 §6.2).
 *  0 = No-Action           : no special action, use normal forwarding
 *  1 = Natively-Forward    : forward the packet natively (non-LISP)
 *  2 = Send-Map-Request    : resend a Map-Request before forwarding
 *  3 = Drop                : drop the packet silently
 */
#define LISP_ACTION_NO_ACTION        0
#define LISP_ACTION_NATIVELY_FORWARD 1
#define LISP_ACTION_SEND_MAP_REQUEST 2
#define LISP_ACTION_DROP             3

/* Nonce size in octets (RFC 9301 §6.1.2: 64-bit nonce). */
#define LISP_NONCE_LEN  8

/* -------------------------------------------------------------------------
 * Pending Map-Request (nonce tracking, RFC 9301 §6.1.2)
 *
 * The ITR keeps a table of outstanding Map-Requests indexed by nonce.
 * When a Map-Reply arrives its nonce is matched against this table to
 * identify which EID triggered the request.
 * ---------------------------------------------------------------------- */

struct lisp_pending_req {
	/* 64-bit nonce identifying this request. */
	uint8_t nonce[LISP_NONCE_LEN];

	/* EID we queried for. */
	struct prefix eid;

	/* RLOC of the Map-Resolver / ETR we sent to. */
	struct prefix dst;

	/* Retry counter (RFC 9301 does not mandate retries but allows them). */
	int retries;

	/* Retry/timeout thread. */
	struct thread *t_timeout;

	/* Back-pointer to LISP instance. */
	struct lisp *lisp;
};

/* -------------------------------------------------------------------------
 * RLOC record
 * ---------------------------------------------------------------------- */

struct lisp_rloc {
	/* RLOC address. */
	struct prefix rloc_addr;

	/* Priority (lower = preferred, RFC 9301 §6.2). */
	uint8_t priority;

	/* Weight for load balancing. */
	uint8_t weight;

	/* Multicast priority. */
	uint8_t mpriority;

	/* Multicast weight. */
	uint8_t mweight;

	/*
	 * L-bit: RLOC is a local (directly connected) address (RFC 9301 §6.2).
	 * R-bit: RLOC is reachable.
	 */
	bool local;
	bool reachable;

	/*
	 * VxLAN-GPE data-plane metadata.
	 *
	 * vni: 24-bit VxLAN Network Identifier for traffic encapsulated
	 *      toward this RLOC.  0 means "use the instance default VNI".
	 * sgt: 14-bit Security Group Tag associated with the remote endpoint
	 *      behind this RLOC (used as dst_sgt in GBP policy evaluation).
	 *      LISP_SGT_UNTAGGED (0) means no group tag.
	 */
	uint32_t vni;
	uint16_t sgt;
};

/* -------------------------------------------------------------------------
 * Map-cache entry
 * ---------------------------------------------------------------------- */

struct lisp_map_entry {
	/* EID prefix this entry covers. */
	struct prefix eid_prefix;

	/* List of RLOCs for this EID (empty for negative entries). */
	struct list *rloc_list;

	/*
	 * TTL in minutes (RFC 9301 §6.2).
	 *   0          = entry MUST NOT be cached (negative, immediate evict)
	 *   0xffffffff = store indefinitely
	 *   other      = expire after ttl minutes
	 */
	uint32_t ttl;

	/* Map-version number. */
	uint16_t map_version;

	/* Action code for negative entries (LISP_ACTION_*). */
	uint8_t action;

	/* Expiry / refresh thread. */
	struct thread *t_expire;

	/* Route node backpointer. */
	struct route_node *rn;
};

/* -------------------------------------------------------------------------
 * Map-Server / Map-Resolver configuration entry
 * ---------------------------------------------------------------------- */

struct lisp_ms_mr {
	/* Address of the Map-Server or Map-Resolver. */
	struct prefix addr;

	/* Use this entry as Map-Server. */
	bool map_server;

	/* Use this entry as Map-Resolver. */
	bool map_resolver;

	/* Request proxy Map-Reply from Map-Server (P bit in Map-Register). */
	bool proxy_reply;
};

/* -------------------------------------------------------------------------
 * Map-Notify-Ack (RFC 9437 §5)
 *
 * Sent by a subscriber in response to a Map-Notify publication to
 * acknowledge receipt.  The nonce echoes the Map-Notify nonce.
 * ---------------------------------------------------------------------- */

struct lisp_map_notify_ack {
	uint8_t nonce[LISP_NONCE_LEN];
};

/* -------------------------------------------------------------------------
 * Per-VRF LISP instance
 * ---------------------------------------------------------------------- */

struct lisp {
	/* VRF name. */
	char *vrf_name;

	/* VRF backpointer. */
	struct vrf *vrf;

	/* Instance is enabled. */
	bool enabled;

	/* UDP socket for LISP control plane. */
	int sock;

	/* EID-to-RLOC map-cache (indexed by EID prefix). */
	struct route_table *map_cache;

	/* Locally registered EID prefixes. */
	struct route_table *local_eids;

	/* Map-Server / Map-Resolver list. */
	struct list *ms_mr_list;

	/*
	 * Pending Map-Requests keyed by nonce (first 8 bytes treated as
	 * a uint64 for hashing).
	 */
	struct hash *pending_requests;

	/* Authentication keys (list of struct lisp_auth_key *). */
	struct list *auth_keys;

	/*
	 * xTR-ID (128 bits) and Site-ID (64 bits).
	 * Set when the operator configures an xTR identity (I-bit, RFC 9301 §8.2).
	 */
	uint8_t xtr_id[16];
	uint8_t site_id[8];
	bool    id_configured;

	/* Map-Register interval (seconds). */
	uint32_t map_register_interval;

	/* RLOC probe interval (seconds). */
	uint32_t rloc_probe_interval;

	/*
	 * RFC 9437 pub/sub state.
	 *
	 * subscriptions: Map-Server side — one struct lisp_subscription per
	 *                (EID-prefix, xTR-ID) pair.
	 * sub_states:    Subscriber (xTR) side — one struct lisp_sub_state per
	 *                EID-prefix we have subscribed to.
	 */
	struct list *subscriptions;
	struct list *sub_states;

	/* ---------------------------------------------------------------
	 * VxLAN-GPE data-plane state (RFC 9301 §2.4)
	 * --------------------------------------------------------------- */

	/* UDP socket on port 4789 for VxLAN-GPE encapsulated data traffic. */
	int data_sock;

	/* I/O thread for data_sock. */
	struct thread *t_data_read;

	/* Default 24-bit VNI for this instance (0 = not configured). */
	uint32_t default_vni;

	/*
	 * GBP (Group Based Policy) / SGT (Security Group Tag) state.
	 *
	 * local_sgt:         14-bit SGT stamped on packets *sent* by this xTR.
	 * gbp_enabled:       GBP enforcement active on received packets.
	 * gbp_default_permit: action when no GBP rule matches (default: true).
	 * sgt_table:         EID-prefix → SGT mapping (struct lisp_sgt_map).
	 * gbp_policies:      ordered list of struct lisp_gbp_policy rules.
	 */
	uint16_t             local_sgt;
	bool                 gbp_enabled;
	bool                 gbp_default_permit;
	struct route_table  *sgt_table;
	struct list         *gbp_policies;

	/* ---------------------------------------------------------------
	 * EID Mobility state (draft-ietf-lisp-eid-mobility-17)
	 * --------------------------------------------------------------- */

	/*
	 * ms_role: when true this instance acts as a Map-Server.
	 * Incoming Map-Register messages are processed and stored in ms_db.
	 */
	bool ms_role;

	/*
	 * ms_db: Map-Server EID database (struct lisp_ms_entry *).
	 * Keyed by EID-prefix.  Only used when ms_role is true.
	 */
	struct route_table *ms_db;

	/*
	 * away_table: Away Table (ETR role).
	 * Tracks EIDs that previously belonged to this ETR but have since
	 * moved to another site.  Data traffic arriving for these EIDs
	 * triggers SMR generation toward the source ITR.
	 */
	struct route_table *away_table;

	/* Map-Register periodic thread. */
	struct thread *t_map_register;

	/* Read thread on control socket. */
	struct thread *t_read;

	/* Redistribute configuration. */
	struct {
		bool enabled;
		struct {
			char *name;
			struct route_map *map;
		} route_map;
	} redist[ZEBRA_ROUTE_MAX];

	/* For distribute-list container. */
	struct distribute_ctx *distribute_ctx;
};

/* -------------------------------------------------------------------------
 * LISP-specific interface state
 * ---------------------------------------------------------------------- */

struct lisp_interface {
	/* Parent LISP instance. */
	struct lisp *lisp;

	/* LISP is enabled on this interface. */
	bool enabled;

	/* This interface acts as an ETR (Egress Tunnel Router). */
	bool etr;

	/* This interface acts as an ITR (Ingress Tunnel Router). */
	bool itr;
};

/* -------------------------------------------------------------------------
 * Prototypes
 * ---------------------------------------------------------------------- */

extern void lisp_init(void);
extern void lisp_clean(struct lisp *lisp);
extern void lisp_vrf_init(void);
extern void lisp_vrf_terminate(void);
extern struct lisp *lisp_lookup_by_vrf_id(vrf_id_t vrf_id);
extern struct lisp *lisp_lookup_by_vrf_name(const char *vrf_name);
extern struct lisp *lisp_create(const char *vrf_name, struct vrf *vrf,
				int socket);

/* ITR: send an SMR-invoked Map-Request (s-bit=1) for an EID */
extern void lisp_send_smr_invoked_request(struct lisp *lisp,
					  const struct prefix *eid);

/* Map-cache */
extern void lisp_map_cache_add(struct lisp *lisp, struct prefix *eid,
			       struct lisp_rloc *rloc, uint32_t ttl,
			       uint8_t action);
extern void lisp_map_cache_delete(struct lisp *lisp, struct prefix *eid);
extern struct lisp_map_entry *lisp_map_cache_lookup(struct lisp *lisp,
						    const struct prefix *eid);

/* Nonce management */
extern void lisp_nonce_generate(uint8_t nonce[LISP_NONCE_LEN]);
extern struct lisp_pending_req *
lisp_pending_req_add(struct lisp *lisp, const struct prefix *eid,
		     const struct prefix *dst, const uint8_t nonce[LISP_NONCE_LEN]);
extern struct lisp_pending_req *
lisp_pending_req_lookup(struct lisp *lisp, const uint8_t nonce[LISP_NONCE_LEN]);
extern void lisp_pending_req_delete(struct lisp *lisp,
				    struct lisp_pending_req *req);

/* Auth-key helpers */
extern struct lisp_auth_key *lisp_auth_key_get(struct lisp *lisp,
					       uint16_t key_id);

/* ITR: send a Map-Request for an EID via all configured Map-Resolvers */
extern void lisp_send_map_request(struct lisp *lisp, const struct prefix *eid);

/* ETR: send Map-Register to all configured Map-Servers */
extern void lisp_send_map_register(struct lisp *lisp);

/* ETR: send a Map-Reply to a requesting ITR */
extern void lisp_send_map_reply(struct lisp *lisp,
				const struct prefix *eid,
				const struct sockaddr_storage *dst,
				const uint8_t nonce[LISP_NONCE_LEN],
				bool probe);

/* MS: send a Map-Notify for an EID to a specific destination RLOC */
extern void lisp_send_map_notify(struct lisp *lisp,
				 const struct prefix *eid,
				 const struct prefix *dst_rloc,
				 uint64_t nonce);

/* xTR: send Map-Notify-Ack echoing the given nonce back to src */
extern void lisp_send_map_notify_ack(struct lisp *lisp,
				     const uint8_t nonce[LISP_NONCE_LEN],
				     const struct sockaddr_storage *dst);

/* Packet I/O dispatch (called from t_read thread) */
extern int lisp_recv_packet(struct thread *t);

extern int  lisp_vxlan_create_socket(struct vrf *vrf);

extern void lisp_if_init(void);
extern void lisp_zclient_init(struct thread_master *master);
extern void lisp_zclient_stop(void);

extern void lisp_cli_init(void);
extern void lisp_debug_init(void);

extern int lisp_create_socket(struct vrf *vrf);

extern struct zebra_privs_t lispd_privs;

/* Master thread structure. */
extern struct thread_master *master;

DECLARE_HOOK(lisp_ifaddr_add, (struct connected *ifc), (ifc))
DECLARE_HOOK(lisp_ifaddr_del, (struct connected *ifc), (ifc))

#endif /* _ZEBRA_LISP_H */
