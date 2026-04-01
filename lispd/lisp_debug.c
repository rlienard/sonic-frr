/* LISP debug commands.
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

#include "command.h"
#include "log.h"

#include "lispd/lisp_debug.h"

unsigned long lisp_debug_flags = 0;

DEFUN(debug_lisp_events,
      debug_lisp_events_cmd,
      "debug lisp events",
      DEBUG_STR
      "LISP information\n"
      "LISP events\n")
{
	lisp_debug_flags |= LISP_DEBUG_EVENTS;
	return CMD_SUCCESS;
}

DEFUN(no_debug_lisp_events,
      no_debug_lisp_events_cmd,
      "no debug lisp events",
      NO_STR
      DEBUG_STR
      "LISP information\n"
      "LISP events\n")
{
	lisp_debug_flags &= ~LISP_DEBUG_EVENTS;
	return CMD_SUCCESS;
}

DEFUN(debug_lisp_packet,
      debug_lisp_packet_cmd,
      "debug lisp packet",
      DEBUG_STR
      "LISP information\n"
      "LISP packets\n")
{
	lisp_debug_flags |= LISP_DEBUG_PACKET;
	return CMD_SUCCESS;
}

DEFUN(no_debug_lisp_packet,
      no_debug_lisp_packet_cmd,
      "no debug lisp packet",
      NO_STR
      DEBUG_STR
      "LISP information\n"
      "LISP packets\n")
{
	lisp_debug_flags &= ~LISP_DEBUG_PACKET;
	return CMD_SUCCESS;
}

DEFUN(debug_lisp_zebra,
      debug_lisp_zebra_cmd,
      "debug lisp zebra",
      DEBUG_STR
      "LISP information\n"
      "LISP Zebra messages\n")
{
	lisp_debug_flags |= LISP_DEBUG_ZEBRA;
	return CMD_SUCCESS;
}

DEFUN(no_debug_lisp_zebra,
      no_debug_lisp_zebra_cmd,
      "no debug lisp zebra",
      NO_STR
      DEBUG_STR
      "LISP information\n"
      "LISP Zebra messages\n")
{
	lisp_debug_flags &= ~LISP_DEBUG_ZEBRA;
	return CMD_SUCCESS;
}

DEFUN(debug_lisp_mapcache,
      debug_lisp_mapcache_cmd,
      "debug lisp map-cache",
      DEBUG_STR
      "LISP information\n"
      "LISP map-cache operations\n")
{
	lisp_debug_flags |= LISP_DEBUG_MAPCACHE;
	return CMD_SUCCESS;
}

DEFUN(no_debug_lisp_mapcache,
      no_debug_lisp_mapcache_cmd,
      "no debug lisp map-cache",
      NO_STR
      DEBUG_STR
      "LISP information\n"
      "LISP map-cache operations\n")
{
	lisp_debug_flags &= ~LISP_DEBUG_MAPCACHE;
	return CMD_SUCCESS;
}

void lisp_debug_init(void)
{
	install_element(ENABLE_NODE, &debug_lisp_events_cmd);
	install_element(ENABLE_NODE, &no_debug_lisp_events_cmd);
	install_element(ENABLE_NODE, &debug_lisp_packet_cmd);
	install_element(ENABLE_NODE, &no_debug_lisp_packet_cmd);
	install_element(ENABLE_NODE, &debug_lisp_zebra_cmd);
	install_element(ENABLE_NODE, &no_debug_lisp_zebra_cmd);
	install_element(ENABLE_NODE, &debug_lisp_mapcache_cmd);
	install_element(ENABLE_NODE, &no_debug_lisp_mapcache_cmd);

	install_element(CONFIG_NODE, &debug_lisp_events_cmd);
	install_element(CONFIG_NODE, &no_debug_lisp_events_cmd);
	install_element(CONFIG_NODE, &debug_lisp_packet_cmd);
	install_element(CONFIG_NODE, &no_debug_lisp_packet_cmd);
	install_element(CONFIG_NODE, &debug_lisp_zebra_cmd);
	install_element(CONFIG_NODE, &no_debug_lisp_zebra_cmd);
	install_element(CONFIG_NODE, &debug_lisp_mapcache_cmd);
	install_element(CONFIG_NODE, &no_debug_lisp_mapcache_cmd);
}
