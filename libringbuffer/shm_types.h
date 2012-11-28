#ifndef _LIBRINGBUFFER_SHM_TYPES_H
#define _LIBRINGBUFFER_SHM_TYPES_H

/*
 * libringbuffer/shm_types.h
 *
 * Copyright (C) 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; only
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <stdint.h>
#include "shm_internal.h"

struct channel;

struct shm_object {
	size_t index;	      /* within the object table */
	int shm_fd;	      /* shm fd */
	char *shm_path;       /* shm path */
	int wait_fd[2];	      /* fd for wait/wakeup */
	char *wait_pipe_path; /* named pipe path for wait/wakeup */
	char *memory_map;
	int is_shadow;
	size_t memory_map_size;
	uint64_t allocated_len;
};

struct shm_object_table {
	size_t size;
	size_t allocated_len;
	struct shm_object objects[];
};

struct lttng_ust_shm_handle {
	struct shm_object_table *table;
	DECLARE_SHMP(struct channel, chan);
	/*
	 * In the consumer, chan points to a shadow copy, validated upon
	 * reception. The chan object is overridden in the consumer to
	 * point to this shadow copy.
	 */
	struct channel *shadow_chan;
};

#endif /* _LIBRINGBUFFER_SHM_TYPES_H */
