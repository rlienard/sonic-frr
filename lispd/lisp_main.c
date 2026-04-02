/* LISPd main routine.
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

#include <lib/version.h>
#include "getopt.h"
#include "thread.h"
#include "command.h"
#include "memory.h"
#include "memory_vty.h"
#include "prefix.h"
#include "filter.h"
#include "log.h"
#include "privs.h"
#include "sigevent.h"
#include "zclient.h"
#include "vrf.h"
#include "libfrr.h"

#include "lispd/lispd.h"
#include "lispd/lisp_errors.h"
#include "lispd/lisp_debug.h"
#include "lispd/lisp_cli.h"
#include "lispd/lisp_pubsub.h"

/* lispd privileges. */
zebra_capabilities_t _caps_p[] = {ZCAP_NET_RAW, ZCAP_BIND, ZCAP_SYS_ADMIN};

struct zebra_privs_t lispd_privs = {
#if defined(FRR_USER)
	.user = FRR_USER,
#endif
#if defined FRR_GROUP
	.group = FRR_GROUP,
#endif
#ifdef VTY_GROUP
	.vty_group = VTY_GROUP,
#endif
	.caps_p = _caps_p,
	.cap_num_p = array_size(_caps_p),
	.cap_num_i = 0,
};

/* Master thread. */
struct thread_master *master;

static struct frr_daemon_info lispd_di;

/* SIGHUP: reload configuration. */
static void sighup(void)
{
	zlog_info("SIGHUP received");
	vty_read_config(NULL, lispd_di.config_file, config_default);
}

/* SIGINT / SIGTERM: clean shutdown. */
static void sigint(void)
{
	zlog_notice("Terminating on signal");
	lisp_vrf_terminate();
	lisp_zclient_stop();
	frr_fini();
	exit(0);
}

/* SIGUSR1: rotate logs. */
static void sigusr1(void)
{
	zlog_rotate();
}

static struct quagga_signal_t lispd_signals[] = {
	{
		.signal = SIGHUP,
		.handler = &sighup,
	},
	{
		.signal = SIGUSR1,
		.handler = &sigusr1,
	},
	{
		.signal = SIGINT,
		.handler = &sigint,
	},
	{
		.signal = SIGTERM,
		.handler = &sigint,
	},
};

FRR_DAEMON_INFO(lispd, LISP, .vty_port = LISP_VTY_PORT,

		.proghelp = "Implementation of the LISP routing protocol.",

		.signals = lispd_signals,
		.n_signals = array_size(lispd_signals),

		.privs = &lispd_privs, )

/* Main routine of lispd. */
int main(int argc, char **argv)
{
	frr_preinit(&lispd_di, argc, argv);
	frr_opt_add("", NULL, "");

	/* Parse command-line options. */
	while (1) {
		int opt = frr_getopt(argc, argv, NULL);

		if (opt == EOF)
			break;

		switch (opt) {
		case 0:
			break;
		default:
			frr_help_exit(1);
			break;
		}
	}

	/* Prepare master thread. */
	master = frr_init();

	/* Library initialisation. */
	lisp_error_init();
	lisp_vrf_init();

	/* LISP daemon initialisation. */
	lisp_init();
	lisp_if_init();
	lisp_cli_init();
	lisp_debug_init();
	lisp_pubsub_cli_init();
	lisp_zclient_init(master);

	frr_config_fork();
	frr_run(master);

	/* Not reached. */
	return 0;
}
