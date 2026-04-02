/* lispd memory type definitions.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "lisp_memory.h"

DEFINE_MGROUP(LISPD, "lispd")
DEFINE_MTYPE(LISPD, LISP,            "LISP instance")
DEFINE_MTYPE(LISPD, LISP_VRF_NAME,   "LISP VRF name")
DEFINE_MTYPE(LISPD, LISP_MAP_ENTRY,  "LISP map-cache entry")
DEFINE_MTYPE(LISPD, LISP_RLOC,       "LISP RLOC")
DEFINE_MTYPE(LISPD, LISP_INTERFACE,  "LISP interface")
DEFINE_MTYPE(LISPD, LISP_MS_MR,      "LISP Map-Server/Map-Resolver")
DEFINE_MTYPE(LISPD, LISP_AUTH_KEY,    "LISP authentication key")
DEFINE_MTYPE(LISPD, LISP_PENDING_REQ, "LISP pending Map-Request")
DEFINE_MTYPE(LISPD, LISP_SUBSCRIPTION,"LISP pub/sub subscription")
DEFINE_MTYPE(LISPD, LISP_SUB_RLOC,   "LISP subscriber RLOC")
DEFINE_MTYPE(LISPD, LISP_SUB_STATE,  "LISP subscriber state")
