/* lispd memory type declarations.
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

#ifndef _LISP_MEMORY_H
#define _LISP_MEMORY_H

#include "memory.h"

DECLARE_MGROUP(LISPD)
DECLARE_MTYPE(LISP)
DECLARE_MTYPE(LISP_VRF_NAME)
DECLARE_MTYPE(LISP_MAP_ENTRY)
DECLARE_MTYPE(LISP_RLOC)
DECLARE_MTYPE(LISP_INTERFACE)
DECLARE_MTYPE(LISP_MS_MR)
DECLARE_MTYPE(LISP_AUTH_KEY)
DECLARE_MTYPE(LISP_PENDING_REQ)
DECLARE_MTYPE(LISP_SUBSCRIPTION)
DECLARE_MTYPE(LISP_SUB_RLOC)
DECLARE_MTYPE(LISP_SUB_STATE)
DECLARE_MTYPE(LISP_SGT_MAP)
DECLARE_MTYPE(LISP_GBP_POLICY)
DECLARE_MTYPE(LISP_MS_ENTRY)
DECLARE_MTYPE(LISP_ITR_TRACK)
DECLARE_MTYPE(LISP_AWAY_ENTRY)

#endif /* _LISP_MEMORY_H */
