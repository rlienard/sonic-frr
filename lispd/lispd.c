/* LISP (Locator/ID Separation Protocol) daemon — core logic.
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

#include "lispd/lispd.h"
#include "lispd/lisp_memory.h"
#include "lispd/lisp_interface.h"
#include "lispd/lisp_errors.h"
#include "lispd/lisp_debug.h"

DEFINE_HOOK(lisp_ifaddr_add, (struct connected *ifc), (ifc))
DEFINE_HOOK(lisp_ifaddr_del, (struct connected *ifc), (ifc))

/* -------------------------------------------------------------------------
 * VRF / instance lookup
 * ---------------------------------------------------------------------- */

struct lisp *lisp_lookup_by_vrf_id(vrf_id_t vrf_id)
{
	struct vrf *vrf = vrf_lookup_by_id(vrf_id);

	if (!vrf)
		return NULL;
	return vrf->info;
}

struct lisp *lisp_lookup_by_vrf_name(const char *vrf_name)
{
	struct vrf *vrf = vrf_lookup_by_name(vrf_name);

	if (!vrf)
		return NULL;
	return vrf->info;
}

/* -------------------------------------------------------------------------
 * Socket creation
 * ---------------------------------------------------------------------- */

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
	sin.sin_family = AF_INET;
	sin.sin_port = htons(LISP_CONTROL_PORT);
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

/* -------------------------------------------------------------------------
 * Map-cache helpers
 * ---------------------------------------------------------------------- */

/* Timer callback: expire a map-cache entry. */
static int lisp_map_entry_expire(struct thread *t)
{
	struct lisp_map_entry *me = THREAD_ARG(t);
	struct lisp *lisp;
	struct route_node *rn = me->rn;

	me->t_expire = NULL;

	lisp = lisp_lookup_by_vrf_id(
		rn->table->vrf_id != VRF_UNKNOWN ? rn->table->vrf_id
						  : VRF_DEFAULT);
	if (!lisp)
		return 0;

	if (IS_LISP_DEBUG_MAPCACHE) {
		char buf[PREFIX2STR_BUFFER];

		prefix2str(&rn->p, buf, sizeof(buf));
		zlog_debug("LISP: map-cache entry %s expired", buf);
	}

	listnode_delete(me->rloc_list, me->rloc_list->head->data);
	list_delete(&me->rloc_list);
	XFREE(MTYPE_LISP_MAP_ENTRY, me);
	rn->info = NULL;
	route_unlock_node(rn);

	return 0;
}

/* Add or refresh a map-cache entry. */
void lisp_map_cache_add(struct lisp *lisp, struct prefix *eid,
			struct lisp_rloc *rloc, uint32_t ttl)
{
	struct route_node *rn;
	struct lisp_map_entry *me;

	rn = route_node_get(lisp->map_cache, eid);
	me = rn->info;

	if (!me) {
		me = XCALLOC(MTYPE_LISP_MAP_ENTRY, sizeof(*me));
		me->rloc_list = list_new();
		me->rn = rn;
		rn->info = me;
		prefix_copy(&me->eid_prefix, eid);
	} else {
		/* Refresh: cancel existing expiry timer. */
		THREAD_TIMER_OFF(me->t_expire);
		route_unlock_node(rn);
	}

	me->ttl = ttl;

	if (rloc) {
		struct lisp_rloc *new_rloc =
			XCALLOC(MTYPE_LISP_RLOC, sizeof(*new_rloc));
		*new_rloc = *rloc;
		listnode_add(me->rloc_list, new_rloc);
	}

	if (ttl > 0)
		thread_add_timer(master, lisp_map_entry_expire, me,
				 ttl * 60, &me->t_expire);

	if (IS_LISP_DEBUG_MAPCACHE) {
		char buf[PREFIX2STR_BUFFER];

		prefix2str(eid, buf, sizeof(buf));
		zlog_debug("LISP: map-cache entry added/refreshed: %s ttl=%u",
			   buf, ttl);
	}
}

/* -------------------------------------------------------------------------
 * Instance lifecycle
 * ---------------------------------------------------------------------- */

struct lisp *lisp_create(const char *vrf_name, struct vrf *vrf, int socket)
{
	struct lisp *lisp;

	lisp = XCALLOC(MTYPE_LISP, sizeof(struct lisp));
	lisp->vrf_name = XSTRDUP(MTYPE_LISP_VRF_NAME, vrf_name);
	lisp->vrf = vrf;
	lisp->sock = socket;
	lisp->enabled = true;
	lisp->map_register_interval = 60;
	lisp->rloc_probe_interval = LISP_RLOC_PROBE_INTERVAL;

	lisp->map_cache = route_table_init();
	lisp->local_eids = route_table_init();
	lisp->ms_mr_list = list_new();

	if (vrf)
		vrf->info = lisp;

	zlog_debug("LISP: created instance for VRF %s", vrf_name);
	return lisp;
}

void lisp_clean(struct lisp *lisp)
{
	struct route_node *rn;
	struct lisp_map_entry *me;
	struct listnode *node, *nnode;
	struct lisp_ms_mr *ms;

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

	if (lisp->sock >= 0)
		close(lisp->sock);

	if (lisp->vrf)
		lisp->vrf->info = NULL;

	XFREE(MTYPE_LISP_VRF_NAME, lisp->vrf_name);
	XFREE(MTYPE_LISP, lisp);
}

/* -------------------------------------------------------------------------
 * VRF callbacks
 * ---------------------------------------------------------------------- */

static int lisp_vrf_new(struct vrf *vrf)
{
	zlog_debug("LISP: VRF %s created", vrf->name);
	return 0;
}

static int lisp_vrf_delete(struct vrf *vrf)
{
	struct lisp *lisp = vrf->info;

	if (lisp)
		lisp_clean(lisp);
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

/* -------------------------------------------------------------------------
 * Global init
 * ---------------------------------------------------------------------- */

void lisp_if_init(void)
{
	if_add_hook(IF_NEW_HOOK, lisp_if_new_hook);
	if_add_hook(IF_DELETE_HOOK, lisp_if_delete_hook);
}

void lisp_init(void)
{
	/* Nothing global to initialise beyond what lisp_vrf_init() does. */
}
