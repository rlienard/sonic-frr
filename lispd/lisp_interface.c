/* LISP interface handling.
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

#include "memory.h"
#include "if.h"
#include "log.h"
#include "prefix.h"
#include "connected.h"
#include "vrf.h"

#include "lispd/lispd.h"
#include "lispd/lisp_interface.h"
#include "lispd/lisp_memory.h"

/* Retrieve (or allocate) the LISP interface info block for an interface. */
struct lisp_interface *lisp_if_get(struct interface *ifp)
{
	struct lisp_interface *li;

	if (ifp->info)
		return ifp->info;

	li = XCALLOC(MTYPE_LISP_INTERFACE, sizeof(struct lisp_interface));
	ifp->info = li;
	return li;
}

/* Called when a new interface is created. */
int lisp_if_new_hook(struct interface *ifp)
{
	lisp_if_get(ifp);
	return 0;
}

/* Called when an interface is deleted. */
int lisp_if_delete_hook(struct interface *ifp)
{
	if (ifp->info) {
		XFREE(MTYPE_LISP_INTERFACE, ifp->info);
		ifp->info = NULL;
	}
	return 0;
}

/* Interface comes up. */
int lisp_if_up(struct interface *ifp)
{
	zlog_debug("LISP: interface %s up", ifp->name);
	return 0;
}

/* Interface goes down. */
int lisp_if_down(struct interface *ifp)
{
	zlog_debug("LISP: interface %s down", ifp->name);
	return 0;
}

/* Address added to interface. */
int lisp_if_add_addr(struct connected *ifc)
{
	hook_call(lisp_ifaddr_add, ifc);
	return 0;
}

/* Address removed from interface. */
int lisp_if_del_addr(struct connected *ifc)
{
	hook_call(lisp_ifaddr_del, ifc);
	return 0;
}
