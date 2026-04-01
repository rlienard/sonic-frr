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

#ifndef _LISP_INTERFACE_H
#define _LISP_INTERFACE_H

#include "if.h"
#include "lispd.h"

extern int lisp_if_new_hook(struct interface *ifp);
extern int lisp_if_delete_hook(struct interface *ifp);
extern int lisp_if_up(struct interface *ifp);
extern int lisp_if_down(struct interface *ifp);
extern int lisp_if_add_addr(struct connected *ifc);
extern int lisp_if_del_addr(struct connected *ifc);
extern struct lisp_interface *lisp_if_get(struct interface *ifp);

#endif /* _LISP_INTERFACE_H */
