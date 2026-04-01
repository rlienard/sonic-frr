/* LISP (Locator/ID Separation Protocol) daemon.
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
#include "lisp_memory.h"

/* LISP port numbers (RFC 6830). */
#define LISP_DATA_PORT        4341
#define LISP_CONTROL_PORT     4342

/* LISP VTY port. */
#define LISP_VTY_PORT         2614

/* Default configuration file name. */
#define LISPD_DEFAULT_CONFIG  "lispd.conf"

/* LISP map-cache entry timeout (seconds). */
#define LISP_MAP_CACHE_TTL_DEFAULT  60

/* LISP RLOC probe interval (seconds). */
#define LISP_RLOC_PROBE_INTERVAL    30

/* LISP message types (RFC 6830 section 6). */
#define LISP_MAP_REQUEST     1
#define LISP_MAP_REPLY       2
#define LISP_MAP_REGISTER    3
#define LISP_MAP_NOTIFY      4
#define LISP_ENCAP_CONTROL   8

/* LISP AFI values. */
#define LISP_AFI_IPV4        1
#define LISP_AFI_IPV6        2

/* LISP action codes for negative map replies. */
#define LISP_ACTION_NO_ACTION        0
#define LISP_ACTION_NATIVELY_FORWARD 1
#define LISP_ACTION_SEND_MAP_REQUEST 2
#define LISP_ACTION_DROP             3

/* LISP RLOC record structure. */
struct lisp_rloc {
	/* RLOC address. */
	struct prefix rloc_addr;

	/* Priority (lower = preferred). */
	uint8_t priority;

	/* Weight for load balancing. */
	uint8_t weight;

	/* Multicast priority. */
	uint8_t mpriority;

	/* Multicast weight. */
	uint8_t mweight;

	/* RLOC reachability flag. */
	bool reachable;
};

/* LISP map-cache entry. */
struct lisp_map_entry {
	/* EID prefix this entry covers. */
	struct prefix eid_prefix;

	/* List of RLOCs for this EID. */
	struct list *rloc_list;

	/* TTL in minutes (0 = do not cache). */
	uint32_t ttl;

	/* Map-version number. */
	uint16_t map_version;

	/* Action code (for negative entries). */
	uint8_t action;

	/* Expiry thread. */
	struct thread *t_expire;

	/* Route node backpointer. */
	struct route_node *rn;
};

/* LISP Map-Server / Map-Resolver configuration entry. */
struct lisp_ms_mr {
	/* Address of the Map-Server or Map-Resolver. */
	struct prefix addr;

	/* Use this entry as Map-Server. */
	bool map_server;

	/* Use this entry as Map-Resolver. */
	bool map_resolver;

	/* Use proxy map-reply. */
	bool proxy_reply;
};

/* Per-VRF LISP instance. */
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

	/* Map-Register interval (seconds). */
	uint32_t map_register_interval;

	/* RLOC probe interval (seconds). */
	uint32_t rloc_probe_interval;

	/* Map-Register thread. */
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

/* LISP-specific interface state. */
struct lisp_interface {
	/* Parent LISP instance. */
	struct lisp *lisp;

	/* LISP is enabled on this interface. */
	bool enabled;

	/* This interface is an ETR (Egress Tunnel Router). */
	bool etr;

	/* This interface is an ITR (Ingress Tunnel Router). */
	bool itr;
};

/* Prototypes. */
extern void lisp_init(void);
extern void lisp_clean(struct lisp *lisp);
extern void lisp_vrf_init(void);
extern void lisp_vrf_terminate(void);
extern struct lisp *lisp_lookup_by_vrf_id(vrf_id_t vrf_id);
extern struct lisp *lisp_lookup_by_vrf_name(const char *vrf_name);
extern struct lisp *lisp_create(const char *vrf_name, struct vrf *vrf,
				int socket);

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
