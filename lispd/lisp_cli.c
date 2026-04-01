/* LISP VTY interface.
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
#include "prefix.h"
#include "table.h"
#include "vty.h"
#include "log.h"
#include "memory.h"
#include "vrf.h"

#include "lispd/lispd.h"
#include "lispd/lisp_cli.h"
#include "lispd/lisp_memory.h"

/* -------------------------------------------------------------------------
 * LISP router-mode node
 * ---------------------------------------------------------------------- */

static struct cmd_node lisp_node = {
	.name = "lisp",
	.node = LISP_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-lisp)# ",
};

DEFUN(router_lisp,
      router_lisp_cmd,
      "router lisp [vrf NAME]",
      ROUTER_STR
      "LISP routing protocol\n"
      VRF_CMD_HELP_STR)
{
	const char *vrf_name = (argc > 2) ? argv[2]->arg : VRF_DEFAULT_NAME;
	struct lisp *lisp;

	lisp = lisp_lookup_by_vrf_name(vrf_name);
	if (!lisp) {
		struct vrf *vrf = vrf_lookup_by_name(vrf_name);
		int sock = lisp_create_socket(vrf);

		lisp = lisp_create(vrf_name, vrf, sock);
		if (!lisp) {
			vty_out(vty, "%% Failed to create LISP instance\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	VTY_PUSH_CONTEXT(LISP_NODE, lisp);
	return CMD_SUCCESS;
}

DEFUN(no_router_lisp,
      no_router_lisp_cmd,
      "no router lisp [vrf NAME]",
      NO_STR
      ROUTER_STR
      "LISP routing protocol\n"
      VRF_CMD_HELP_STR)
{
	const char *vrf_name = (argc > 3) ? argv[3]->arg : VRF_DEFAULT_NAME;
	struct lisp *lisp;

	lisp = lisp_lookup_by_vrf_name(vrf_name);
	if (!lisp) {
		vty_out(vty, "%% LISP instance not found\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	lisp_clean(lisp);
	return CMD_SUCCESS;
}

/* -------------------------------------------------------------------------
 * Map-server / Map-resolver configuration
 * ---------------------------------------------------------------------- */

DEFUN(lisp_map_server,
      lisp_map_server_cmd,
      "map-server A.B.C.D",
      "Configure a Map-Server\n"
      "IPv4 address of the Map-Server\n")
{
	VTY_DECLVAR_CONTEXT(lisp, lisp);
	struct lisp_ms_mr *ms;
	struct prefix p;

	if (str2prefix(argv[1]->arg, &p) <= 0) {
		vty_out(vty, "%% Invalid address: %s\n", argv[1]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	ms = XCALLOC(MTYPE_LISP_MS_MR, sizeof(*ms));
	ms->addr = p;
	ms->map_server = true;
	listnode_add(lisp->ms_mr_list, ms);

	return CMD_SUCCESS;
}

DEFUN(lisp_map_resolver,
      lisp_map_resolver_cmd,
      "map-resolver A.B.C.D",
      "Configure a Map-Resolver\n"
      "IPv4 address of the Map-Resolver\n")
{
	VTY_DECLVAR_CONTEXT(lisp, lisp);
	struct lisp_ms_mr *ms;
	struct prefix p;

	if (str2prefix(argv[1]->arg, &p) <= 0) {
		vty_out(vty, "%% Invalid address: %s\n", argv[1]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	ms = XCALLOC(MTYPE_LISP_MS_MR, sizeof(*ms));
	ms->addr = p;
	ms->map_resolver = true;
	listnode_add(lisp->ms_mr_list, ms);

	return CMD_SUCCESS;
}

/* -------------------------------------------------------------------------
 * EID prefix registration
 * ---------------------------------------------------------------------- */

DEFUN(lisp_eid_prefix,
      lisp_eid_prefix_cmd,
      "eid-prefix A.B.C.D/M",
      "Register a local EID prefix\n"
      "EID prefix to register\n")
{
	VTY_DECLVAR_CONTEXT(lisp, lisp);
	struct prefix p;
	struct route_node *rn;

	if (str2prefix(argv[1]->arg, &p) <= 0) {
		vty_out(vty, "%% Invalid prefix: %s\n", argv[1]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	rn = route_node_get(lisp->local_eids, &p);
	if (rn->info) {
		route_unlock_node(rn);
		vty_out(vty, "%% EID prefix already registered\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	/* Mark as registered — info pointer used as boolean sentinel. */
	rn->info = (void *)1;

	return CMD_SUCCESS;
}

DEFUN(no_lisp_eid_prefix,
      no_lisp_eid_prefix_cmd,
      "no eid-prefix A.B.C.D/M",
      NO_STR
      "Remove a local EID prefix\n"
      "EID prefix to remove\n")
{
	VTY_DECLVAR_CONTEXT(lisp, lisp);
	struct prefix p;
	struct route_node *rn;

	if (str2prefix(argv[2]->arg, &p) <= 0) {
		vty_out(vty, "%% Invalid prefix: %s\n", argv[2]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	rn = route_node_lookup(lisp->local_eids, &p);
	if (!rn || !rn->info) {
		vty_out(vty, "%% EID prefix not found\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	rn->info = NULL;
	route_unlock_node(rn);
	route_unlock_node(rn);
	return CMD_SUCCESS;
}

/* -------------------------------------------------------------------------
 * show commands
 * ---------------------------------------------------------------------- */

DEFUN(show_lisp_map_cache,
      show_lisp_map_cache_cmd,
      "show lisp map-cache [vrf NAME]",
      SHOW_STR
      "LISP information\n"
      "Show LISP map-cache entries\n"
      VRF_CMD_HELP_STR)
{
	const char *vrf_name = (argc > 3) ? argv[3]->arg : VRF_DEFAULT_NAME;
	struct lisp *lisp;
	struct route_node *rn;
	char prefix_buf[PREFIX2STR_BUFFER];

	lisp = lisp_lookup_by_vrf_name(vrf_name);
	if (!lisp) {
		vty_out(vty, "%% No LISP instance for VRF %s\n", vrf_name);
		return CMD_WARNING;
	}

	vty_out(vty, "LISP Map-Cache (VRF %s)\n", vrf_name);
	vty_out(vty, "%-40s  %s\n", "EID Prefix", "RLOC(s)");
	vty_out(vty, "%-40s  %s\n",
		"----------------------------------------",
		"-------------------------------------------");

	for (rn = route_top(lisp->map_cache); rn; rn = route_next(rn)) {
		struct lisp_map_entry *me = rn->info;
		struct listnode *ln;
		struct lisp_rloc *rloc;

		if (!me)
			continue;

		prefix2str(&rn->p, prefix_buf, sizeof(prefix_buf));
		vty_out(vty, "%-40s", prefix_buf);

		for (ALL_LIST_ELEMENTS_RO(me->rloc_list, ln, rloc)) {
			char rloc_buf[PREFIX2STR_BUFFER];

			prefix2str(&rloc->rloc_addr, rloc_buf,
				   sizeof(rloc_buf));
			vty_out(vty, "  %s (p=%u w=%u)", rloc_buf,
				rloc->priority, rloc->weight);
		}
		vty_out(vty, "\n");
	}

	return CMD_SUCCESS;
}

DEFUN(show_lisp_eid_table,
      show_lisp_eid_table_cmd,
      "show lisp eid-table [vrf NAME]",
      SHOW_STR
      "LISP information\n"
      "Show locally registered EID prefixes\n"
      VRF_CMD_HELP_STR)
{
	const char *vrf_name = (argc > 3) ? argv[3]->arg : VRF_DEFAULT_NAME;
	struct lisp *lisp;
	struct route_node *rn;
	char prefix_buf[PREFIX2STR_BUFFER];

	lisp = lisp_lookup_by_vrf_name(vrf_name);
	if (!lisp) {
		vty_out(vty, "%% No LISP instance for VRF %s\n", vrf_name);
		return CMD_WARNING;
	}

	vty_out(vty, "LISP Local EID Table (VRF %s)\n", vrf_name);
	for (rn = route_top(lisp->local_eids); rn; rn = route_next(rn)) {
		if (!rn->info)
			continue;
		prefix2str(&rn->p, prefix_buf, sizeof(prefix_buf));
		vty_out(vty, "  %s\n", prefix_buf);
	}

	return CMD_SUCCESS;
}

/* -------------------------------------------------------------------------
 * Init
 * ---------------------------------------------------------------------- */

void lisp_cli_init(void)
{
	install_node(&lisp_node);
	install_default(LISP_NODE);

	install_element(CONFIG_NODE, &router_lisp_cmd);
	install_element(CONFIG_NODE, &no_router_lisp_cmd);

	install_element(LISP_NODE, &lisp_map_server_cmd);
	install_element(LISP_NODE, &lisp_map_resolver_cmd);
	install_element(LISP_NODE, &lisp_eid_prefix_cmd);
	install_element(LISP_NODE, &no_lisp_eid_prefix_cmd);

	install_element(VIEW_NODE, &show_lisp_map_cache_cmd);
	install_element(VIEW_NODE, &show_lisp_eid_table_cmd);
	install_element(ENABLE_NODE, &show_lisp_map_cache_cmd);
	install_element(ENABLE_NODE, &show_lisp_eid_table_cmd);
}
