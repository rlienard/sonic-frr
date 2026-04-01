/* LISP debug flags.
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

#ifndef _LISP_DEBUG_H
#define _LISP_DEBUG_H

#include "log.h"

/* LISP debug flags. */
extern unsigned long lisp_debug_flags;

#define LISP_DEBUG_EVENTS   0x01
#define LISP_DEBUG_PACKET   0x02
#define LISP_DEBUG_ZEBRA    0x04
#define LISP_DEBUG_MAPCACHE 0x08

#define IS_LISP_DEBUG_EVENTS   (lisp_debug_flags & LISP_DEBUG_EVENTS)
#define IS_LISP_DEBUG_PACKET   (lisp_debug_flags & LISP_DEBUG_PACKET)
#define IS_LISP_DEBUG_ZEBRA    (lisp_debug_flags & LISP_DEBUG_ZEBRA)
#define IS_LISP_DEBUG_MAPCACHE (lisp_debug_flags & LISP_DEBUG_MAPCACHE)

extern void lisp_debug_init(void);

#endif /* _LISP_DEBUG_H */
