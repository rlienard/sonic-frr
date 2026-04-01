/* LISP <-> Zebra integration.
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
#include "zclient.h"
#include "log.h"
#include "vrf.h"
#include "nexthop.h"
#include "if.h"

#include "lispd/lispd.h"
#include "lispd/lisp_interface.h"
#include "lispd/lisp_memory.h"

/* Zebra client handle. */
static struct zclient *zclient = NULL;

/* -------------------------------------------------------------------------
 * Zebra interface callbacks
 * ---------------------------------------------------------------------- */

static int lisp_interface_add(int command, struct zclient *zclient,
			      zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;

	ifp = zebra_interface_add_read(zclient->ibuf, vrf_id);
	if (!ifp)
		return 0;

	lisp_if_new_hook(ifp);
	return 0;
}

static int lisp_interface_delete(int command, struct zclient *zclient,
				 zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;

	ifp = zebra_interface_state_read(zclient->ibuf, vrf_id);
	if (!ifp)
		return 0;

	lisp_if_delete_hook(ifp);
	return 0;
}

static int lisp_interface_up(int command, struct zclient *zclient,
			     zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;

	ifp = zebra_interface_state_read(zclient->ibuf, vrf_id);
	if (!ifp)
		return 0;

	lisp_if_up(ifp);
	return 0;
}

static int lisp_interface_down(int command, struct zclient *zclient,
			       zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;

	ifp = zebra_interface_state_read(zclient->ibuf, vrf_id);
	if (!ifp)
		return 0;

	lisp_if_down(ifp);
	return 0;
}

static int lisp_interface_address_add(int command, struct zclient *zclient,
				      zebra_size_t length, vrf_id_t vrf_id)
{
	struct connected *ifc;

	ifc = zebra_interface_address_read(command, zclient->ibuf, vrf_id);
	if (!ifc)
		return 0;

	lisp_if_add_addr(ifc);
	return 0;
}

static int lisp_interface_address_delete(int command, struct zclient *zclient,
					 zebra_size_t length, vrf_id_t vrf_id)
{
	struct connected *ifc;

	ifc = zebra_interface_address_read(command, zclient->ibuf, vrf_id);
	if (!ifc)
		return 0;

	lisp_if_del_addr(ifc);
	connected_free(ifc);
	return 0;
}

/* -------------------------------------------------------------------------
 * Route install / withdraw helpers
 * ---------------------------------------------------------------------- */

/* Install a resolved LISP EID route into the kernel via Zebra. */
void lisp_zebra_route_add(struct lisp *lisp, struct prefix *eid,
			  struct nexthop *nh)
{
	struct zapi_route api;
	struct zapi_nexthop *api_nh;

	memset(&api, 0, sizeof(api));
	api.vrf_id = lisp->vrf ? lisp->vrf->vrf_id : VRF_DEFAULT;
	api.type = ZEBRA_ROUTE_LISP;
	api.safi = SAFI_UNICAST;
	memcpy(&api.prefix, eid, sizeof(*eid));

	SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
	api.nexthop_num = 1;
	api_nh = &api.nexthops[0];
	memset(api_nh, 0, sizeof(*api_nh));
	api_nh->vrf_id = api.vrf_id;

	if (nh->type == NEXTHOP_TYPE_IPV4
	    || nh->type == NEXTHOP_TYPE_IPV4_IFINDEX) {
		api_nh->type = NEXTHOP_TYPE_IPV4;
		api_nh->gate.ipv4 = nh->gate.ipv4;
	} else if (nh->type == NEXTHOP_TYPE_IPV6
		   || nh->type == NEXTHOP_TYPE_IPV6_IFINDEX) {
		api_nh->type = NEXTHOP_TYPE_IPV6;
		api_nh->gate.ipv6 = nh->gate.ipv6;
	} else {
		return;
	}

	zclient_route_send(ZEBRA_ROUTE_ADD, zclient, &api);
}

/* Withdraw a previously installed LISP EID route from Zebra. */
void lisp_zebra_route_delete(struct lisp *lisp, struct prefix *eid)
{
	struct zapi_route api;

	memset(&api, 0, sizeof(api));
	api.vrf_id = lisp->vrf ? lisp->vrf->vrf_id : VRF_DEFAULT;
	api.type = ZEBRA_ROUTE_LISP;
	api.safi = SAFI_UNICAST;
	memcpy(&api.prefix, eid, sizeof(*eid));

	zclient_route_send(ZEBRA_ROUTE_DELETE, zclient, &api);
}

/* -------------------------------------------------------------------------
 * Zclient lifecycle
 * ---------------------------------------------------------------------- */

static void lisp_zebra_connected(struct zclient *z)
{
	zclient_send_requests(z, VRF_DEFAULT);
}

void lisp_zclient_stop(void)
{
	zclient_stop(zclient);
}

void lisp_zclient_init(struct thread_master *master)
{
	zclient = zclient_new(master, &zclient_options_default);
	zclient_init(zclient, ZEBRA_ROUTE_LISP, 0, &lispd_privs);

	zclient->zebra_connected = lisp_zebra_connected;
	zclient->interface_add = lisp_interface_add;
	zclient->interface_delete = lisp_interface_delete;
	zclient->interface_up = lisp_interface_up;
	zclient->interface_down = lisp_interface_down;
	zclient->interface_address_add = lisp_interface_address_add;
	zclient->interface_address_delete = lisp_interface_address_delete;
}
