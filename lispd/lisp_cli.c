/* LISP VTY interface (RFC 9301).
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
#include "lispd/lisp_auth.h"
#include "lispd/lisp_mobility.h"

/* -------------------------------------------------------------------------
 * LISP router-mode node
 * ---------------------------------------------------------------------- */

static struct cmd_node lisp_node = {
	.name        = "lisp",
	.node        = LISP_NODE,
	.parent_node = CONFIG_NODE,
	.prompt      = "%s(config-lisp)# ",
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
      NO_STR ROUTER_STR
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
      "map-server A.B.C.D [proxy-reply]",
      "Configure a Map-Server\n"
      "IPv4 address of the Map-Server\n"
      "Request proxy Map-Reply from this Map-Server (P-bit in Map-Register)\n")
{
	VTY_DECLVAR_CONTEXT(lisp, lisp);
	struct lisp_ms_mr *ms;
	struct prefix p;

	if (str2prefix(argv[1]->arg, &p) <= 0) {
		vty_out(vty, "%% Invalid address: %s\n", argv[1]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	ms = XCALLOC(MTYPE_LISP_MS_MR, sizeof(*ms));
	ms->addr        = p;
	ms->map_server  = true;
	ms->proxy_reply = (argc > 2);
	listnode_add(lisp->ms_mr_list, ms);

	return CMD_SUCCESS;
}

DEFUN(no_lisp_map_server,
      no_lisp_map_server_cmd,
      "no map-server A.B.C.D",
      NO_STR
      "Remove a Map-Server\n"
      "IPv4 address of the Map-Server\n")
{
	VTY_DECLVAR_CONTEXT(lisp, lisp);
	struct prefix p;
	struct listnode *node, *nnode;
	struct lisp_ms_mr *ms;

	if (str2prefix(argv[2]->arg, &p) <= 0) {
		vty_out(vty, "%% Invalid address: %s\n", argv[2]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	for (ALL_LIST_ELEMENTS(lisp->ms_mr_list, node, nnode, ms)) {
		if (prefix_same(&ms->addr, &p) && ms->map_server) {
			listnode_delete(lisp->ms_mr_list, ms);
			XFREE(MTYPE_LISP_MS_MR, ms);
			return CMD_SUCCESS;
		}
	}

	vty_out(vty, "%% Map-Server %s not found\n", argv[2]->arg);
	return CMD_WARNING_CONFIG_FAILED;
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
	ms->addr         = p;
	ms->map_resolver = true;
	listnode_add(lisp->ms_mr_list, ms);

	return CMD_SUCCESS;
}

DEFUN(no_lisp_map_resolver,
      no_lisp_map_resolver_cmd,
      "no map-resolver A.B.C.D",
      NO_STR
      "Remove a Map-Resolver\n"
      "IPv4 address of the Map-Resolver\n")
{
	VTY_DECLVAR_CONTEXT(lisp, lisp);
	struct prefix p;
	struct listnode *node, *nnode;
	struct lisp_ms_mr *ms;

	if (str2prefix(argv[2]->arg, &p) <= 0) {
		vty_out(vty, "%% Invalid address: %s\n", argv[2]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	for (ALL_LIST_ELEMENTS(lisp->ms_mr_list, node, nnode, ms)) {
		if (prefix_same(&ms->addr, &p) && ms->map_resolver) {
			listnode_delete(lisp->ms_mr_list, ms);
			XFREE(MTYPE_LISP_MS_MR, ms);
			return CMD_SUCCESS;
		}
	}

	vty_out(vty, "%% Map-Resolver %s not found\n", argv[2]->arg);
	return CMD_WARNING_CONFIG_FAILED;
}

/* -------------------------------------------------------------------------
 * Authentication key  (RFC 9301 §8.2)
 *
 * auth-key <key-id> <key-string>
 *
 * Configures a pre-shared key used to authenticate Map-Register and
 * Map-Notify messages with HMAC-SHA-256-128.
 * ---------------------------------------------------------------------- */

DEFUN(lisp_auth_key,
      lisp_auth_key_cmd,
      "auth-key (1-65535) WORD",
      "Configure a pre-shared authentication key (RFC 9301 §8.2)\n"
      "Key ID\n"
      "Key string (plain text, max 64 characters)\n")
{
	VTY_DECLVAR_CONTEXT(lisp, lisp);
	struct lisp_auth_key *key;
	uint16_t key_id = atoi(argv[1]->arg);
	const char *key_str = argv[2]->arg;
	size_t key_len = strlen(key_str);

	if (key_len == 0 || key_len > 64) {
		vty_out(vty, "%% Key string must be 1-64 characters\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Replace existing key with same ID if present. */
	key = lisp_auth_key_get(lisp, key_id);
	if (!key) {
		key = XCALLOC(MTYPE_LISP_AUTH_KEY, sizeof(*key));
		listnode_add(lisp->auth_keys, key);
	}

	key->key_id      = key_id;
	key->algorithm_id = LISP_AUTH_HMAC_SHA256_128;
	key->key_len     = (uint16_t)key_len;
	memcpy(key->key, key_str, key_len);

	return CMD_SUCCESS;
}

DEFUN(no_lisp_auth_key,
      no_lisp_auth_key_cmd,
      "no auth-key (1-65535)",
      NO_STR
      "Remove an authentication key\n"
      "Key ID\n")
{
	VTY_DECLVAR_CONTEXT(lisp, lisp);
	uint16_t key_id = atoi(argv[2]->arg);
	struct lisp_auth_key *key;

	key = lisp_auth_key_get(lisp, key_id);
	if (!key) {
		vty_out(vty, "%% Key ID %u not found\n", key_id);
		return CMD_WARNING_CONFIG_FAILED;
	}

	listnode_delete(lisp->auth_keys, key);
	XFREE(MTYPE_LISP_AUTH_KEY, key);
	return CMD_SUCCESS;
}

/* -------------------------------------------------------------------------
 * xTR-ID / Site-ID  (RFC 9301 §8.2 I-bit)
 * ---------------------------------------------------------------------- */

DEFUN(lisp_xtr_id,
      lisp_xtr_id_cmd,
      "xtr-id WORD site-id WORD",
      "Configure xTR identity (sets I-bit in Map-Register, RFC 9301 §8.2)\n"
      "128-bit xTR-ID as hex string (32 hex chars)\n"
      "Configure Site ID\n"
      "64-bit Site-ID as hex string (16 hex chars)\n")
{
	VTY_DECLVAR_CONTEXT(lisp, lisp);
	const char *xtr_str  = argv[1]->arg;
	const char *site_str = argv[3]->arg;
	int i;

	if (strlen(xtr_str) != 32) {
		vty_out(vty, "%% xTR-ID must be 32 hex characters (128 bits)\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (strlen(site_str) != 16) {
		vty_out(vty, "%% Site-ID must be 16 hex characters (64 bits)\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	for (i = 0; i < 16; i++) {
		unsigned int byte;
		if (sscanf(xtr_str + i * 2, "%02x", &byte) != 1) {
			vty_out(vty, "%% Invalid hex in xTR-ID\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		lisp->xtr_id[i] = (uint8_t)byte;
	}

	for (i = 0; i < 8; i++) {
		unsigned int byte;
		if (sscanf(site_str + i * 2, "%02x", &byte) != 1) {
			vty_out(vty, "%% Invalid hex in Site-ID\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		lisp->site_id[i] = (uint8_t)byte;
	}

	lisp->id_configured = true;
	return CMD_SUCCESS;
}

DEFUN(no_lisp_xtr_id,
      no_lisp_xtr_id_cmd,
      "no xtr-id",
      NO_STR
      "Remove xTR identity configuration\n")
{
	VTY_DECLVAR_CONTEXT(lisp, lisp);

	memset(lisp->xtr_id,  0, sizeof(lisp->xtr_id));
	memset(lisp->site_id, 0, sizeof(lisp->site_id));
	lisp->id_configured = false;
	return CMD_SUCCESS;
}

/* -------------------------------------------------------------------------
 * Map-Register interval
 * ---------------------------------------------------------------------- */

DEFUN(lisp_map_register_interval,
      lisp_map_register_interval_cmd,
      "map-register-interval (1-65535)",
      "Set Map-Register send interval\n"
      "Interval in seconds (default 60)\n")
{
	VTY_DECLVAR_CONTEXT(lisp, lisp);
	uint32_t interval = atoi(argv[1]->arg);

	lisp->map_register_interval = interval;

	/* Restart the periodic timer with the new interval. */
	THREAD_TIMER_OFF(lisp->t_map_register);
	thread_add_timer(master, NULL /* lisp_map_register_timer not visible here */,
			 lisp, interval, &lisp->t_map_register);
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
	rn->info = (void *)1; /* boolean sentinel */

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
	route_unlock_node(rn); /* lookup */
	route_unlock_node(rn); /* node  */
	return CMD_SUCCESS;
}

/* -------------------------------------------------------------------------
 * Show commands
 * ---------------------------------------------------------------------- */

DEFUN(show_lisp_map_cache,
      show_lisp_map_cache_cmd,
      "show lisp map-cache [vrf NAME]",
      SHOW_STR "LISP information\n"
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
	vty_out(vty, "%-40s %-6s %-6s  %s\n",
		"EID Prefix", "TTL", "Action", "RLOC(s)");
	vty_out(vty, "%-40s %-6s %-6s  %s\n",
		"----------------------------------------",
		"------", "------",
		"-------------------------------------------");

	for (rn = route_top(lisp->map_cache); rn; rn = route_next(rn)) {
		struct lisp_map_entry *me = rn->info;
		struct listnode *ln;
		struct lisp_rloc *rloc;

		if (!me)
			continue;

		prefix2str(&rn->p, prefix_buf, sizeof(prefix_buf));

		if (me->ttl == LISP_MAP_CACHE_TTL_PERMANENT)
			vty_out(vty, "%-40s %-6s %-6u ", prefix_buf,
				"perm", me->action);
		else
			vty_out(vty, "%-40s %-6u %-6u ", prefix_buf,
				me->ttl, me->action);

		if (list_isempty(me->rloc_list)) {
			vty_out(vty, " (negative)\n");
			continue;
		}

		for (ALL_LIST_ELEMENTS_RO(me->rloc_list, ln, rloc)) {
			char rloc_buf[PREFIX2STR_BUFFER];
			prefix2str(&rloc->rloc_addr, rloc_buf, sizeof(rloc_buf));
			vty_out(vty, " %s (p=%u w=%u%s%s)",
				rloc_buf, rloc->priority, rloc->weight,
				rloc->local     ? " L" : "",
				rloc->reachable ? " R" : "");
		}
		vty_out(vty, "\n");
	}

	return CMD_SUCCESS;
}

DEFUN(show_lisp_eid_table,
      show_lisp_eid_table_cmd,
      "show lisp eid-table [vrf NAME]",
      SHOW_STR "LISP information\n"
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

DEFUN(show_lisp_auth_keys,
      show_lisp_auth_keys_cmd,
      "show lisp auth-keys [vrf NAME]",
      SHOW_STR "LISP information\n"
      "Show configured authentication keys\n"
      VRF_CMD_HELP_STR)
{
	const char *vrf_name = (argc > 3) ? argv[3]->arg : VRF_DEFAULT_NAME;
	struct lisp *lisp;
	struct listnode *node;
	struct lisp_auth_key *key;

	lisp = lisp_lookup_by_vrf_name(vrf_name);
	if (!lisp) {
		vty_out(vty, "%% No LISP instance for VRF %s\n", vrf_name);
		return CMD_WARNING;
	}

	vty_out(vty, "LISP Authentication Keys (VRF %s)\n", vrf_name);
	vty_out(vty, "  %-8s  %s\n", "Key-ID", "Algorithm");
	for (ALL_LIST_ELEMENTS_RO(lisp->auth_keys, node, key))
		vty_out(vty, "  %-8u  HMAC-SHA-256-128\n", key->key_id);

	return CMD_SUCCESS;
}

DEFUN(show_lisp_pending,
      show_lisp_pending_cmd,
      "show lisp pending-requests [vrf NAME]",
      SHOW_STR "LISP information\n"
      "Show pending Map-Requests (awaiting Map-Reply)\n"
      VRF_CMD_HELP_STR)
{
	const char *vrf_name = (argc > 3) ? argv[3]->arg : VRF_DEFAULT_NAME;
	struct lisp *lisp;

	lisp = lisp_lookup_by_vrf_name(vrf_name);
	if (!lisp) {
		vty_out(vty, "%% No LISP instance for VRF %s\n", vrf_name);
		return CMD_WARNING;
	}

	vty_out(vty, "LISP Pending Map-Requests (VRF %s): %u\n",
		vrf_name, lisp->pending_requests->count);
	return CMD_SUCCESS;
}

/* -------------------------------------------------------------------------
 * Map-Server role  (draft-ietf-lisp-eid-mobility-17)
 *
 * map-server-role
 *   Enables the Map-Server role on this LISP instance.  Once enabled,
 *   incoming Map-Register messages are processed: the EID-to-RLOC database
 *   (ms_db) is updated, EID mobility is detected, SMRs are sent to cached
 *   ITR-RLOCs, and pub/sub subscribers are notified.
 * ---------------------------------------------------------------------- */

DEFUN(lisp_map_server_role,
      lisp_map_server_role_cmd,
      "map-server-role",
      "Enable Map-Server role (draft-ietf-lisp-eid-mobility-17)\n")
{
	VTY_DECLVAR_CONTEXT(lisp, lisp);

	lisp->ms_role = true;
	vty_out(vty, "%% Map-Server role enabled\n");
	return CMD_SUCCESS;
}

DEFUN(no_lisp_map_server_role,
      no_lisp_map_server_role_cmd,
      "no map-server-role",
      NO_STR
      "Disable Map-Server role\n")
{
	VTY_DECLVAR_CONTEXT(lisp, lisp);

	lisp->ms_role = false;
	/* Clear the database when the role is disabled. */
	lisp_mobility_ms_db_clean(lisp);
	vty_out(vty, "%% Map-Server role disabled\n");
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
	install_element(LISP_NODE, &no_lisp_map_server_cmd);
	install_element(LISP_NODE, &lisp_map_resolver_cmd);
	install_element(LISP_NODE, &no_lisp_map_resolver_cmd);
	install_element(LISP_NODE, &lisp_auth_key_cmd);
	install_element(LISP_NODE, &no_lisp_auth_key_cmd);
	install_element(LISP_NODE, &lisp_xtr_id_cmd);
	install_element(LISP_NODE, &no_lisp_xtr_id_cmd);
	install_element(LISP_NODE, &lisp_map_register_interval_cmd);
	install_element(LISP_NODE, &lisp_eid_prefix_cmd);
	install_element(LISP_NODE, &no_lisp_eid_prefix_cmd);

	/* EID mobility — Map-Server role toggle */
	install_element(LISP_NODE, &lisp_map_server_role_cmd);
	install_element(LISP_NODE, &no_lisp_map_server_role_cmd);

	install_element(VIEW_NODE,   &show_lisp_map_cache_cmd);
	install_element(VIEW_NODE,   &show_lisp_eid_table_cmd);
	install_element(VIEW_NODE,   &show_lisp_auth_keys_cmd);
	install_element(VIEW_NODE,   &show_lisp_pending_cmd);
	install_element(ENABLE_NODE, &show_lisp_map_cache_cmd);
	install_element(ENABLE_NODE, &show_lisp_eid_table_cmd);
	install_element(ENABLE_NODE, &show_lisp_auth_keys_cmd);
	install_element(ENABLE_NODE, &show_lisp_pending_cmd);

	/* EID mobility show commands (registered via lisp_mobility.c) */
	lisp_mobility_cli_init();
}
