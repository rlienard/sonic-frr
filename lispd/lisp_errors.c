/* LISP-specific error messages.
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

#include "lib/ferr.h"
#include "lisp_errors.h"

static struct log_ref ferr_lisp_err[] = {
	{
		.code = EC_LISP_PACKET,
		.title = "LISP Packet Error",
		.description = "LISP detected a packet encode/decode issue",
		.suggestion = "Gather log files from both sides and open an Issue",
	},
	{
		.code = EC_LISP_MAP_CACHE,
		.title = "LISP Map-Cache Error",
		.description = "LISP encountered an error updating the map-cache",
		.suggestion = "Check EID/RLOC configuration and map-server reachability",
	},
	{
		.code = EC_LISP_SOCKET,
		.title = "LISP Socket Error",
		.description = "LISP failed to create or bind the control-plane socket",
		.suggestion = "Verify that UDP port 4342 is not in use by another process",
	},
	{
		.code = END_FERR,
	},
};

void lisp_error_init(void)
{
	log_ref_add(ferr_lisp_err);
}
