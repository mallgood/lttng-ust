/*
 * libringbuffer/shm.c
 *
 * Copyright (C) 2005-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include "shm.h"
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>	/* For mode constants */
#include <fcntl.h>	/* For O_* constants */
#include <assert.h>
#include <stdio.h>
#include <signal.h>
#include <dirent.h>
#include <lttng/align.h>
#include <helper.h>
#include <limits.h>
#include <helper.h>
/* FIXME: Include UUID the proper way, e.g. config.h... */
#include <uuid/uuid.h>

/*
 * Ensure we have the required amount of space available by writing 0
 * into the entire buffer. Not doing so can trigger SIGBUS when going
 * beyond the available shm space.
 */
static
int zero_file(int fd, size_t len)
{
	ssize_t retlen;
	size_t written = 0;
	char *zeropage;
	long pagelen;
	int ret;

	pagelen = sysconf(_SC_PAGESIZE);
	if (pagelen < 0)
		return (int) pagelen;
	zeropage = calloc(pagelen, 1);
	if (!zeropage)
		return -ENOMEM;

	while (len > written) {
		do {
			retlen = write(fd, zeropage,
				min_t(size_t, pagelen, len - written));
		} while (retlen == -1UL && errno == EINTR);
		if (retlen < 0) {
			ret = (int) retlen;
			goto error;
		}
		written += retlen;
	}
	ret = 0;
error:
	free(zeropage);
	return ret;
}

struct shm_object_table *shm_object_table_create(size_t max_nb_obj)
{
	struct shm_object_table *table;

	table = zmalloc(sizeof(struct shm_object_table) +
			max_nb_obj * sizeof(table->objects[0]));
	table->size = max_nb_obj;
	return table;
}

/*
 * Generate a unique name with the desired prefix.
 * Pattern is as follow: prefix-pid-uuid.
 * Caller is responsible of freeing the resulting string.
 */
static
char *gen_unique_name(const char *prefix)
{
	int written;
	pid_t pid;
	uuid_t uuid;
	char uuid_str[37];
	char tmp_name[NAME_MAX];
	char *name;

	if (!prefix)
		return NULL;

	pid = getpid();

	uuid_generate(uuid);
	uuid_unparse(uuid, uuid_str);

	written = snprintf(tmp_name, NAME_MAX,
			   "%s-%d-%s", prefix, pid, uuid_str);

	if (written < 0 || written >= NAME_MAX)
		return NULL;

	name = zmalloc(written + 1);

	if (!name)
		return NULL;

	return strncpy(name, tmp_name, written);
}

struct shm_object *shm_object_table_append(struct shm_object_table *table,
					   size_t memory_map_size)
{
	int shmfd, ret, sigblocked = 0;
	struct shm_object *obj;
	char *memory_map;

	const char *base_shm      = "/dev/shm/";
	const char *base_path     = "/tmp/lttng-fds/";
	const char *waitfd_prefix = "ust-wait";
	const char *shm_prefix    = "ust-shm";

	char *wait_pipe_path, *wait_pipe_file;
	char *shm_path, *shm_symlink_path, *shm_file;

	char tmp_name[NAME_MAX] = "ust-shm-tmp-XXXXXX";

	sigset_t all_sigs, orig_sigs;

	if (table->allocated_len >= table->size)
		return NULL;
	obj = &table->objects[table->allocated_len];

	wait_pipe_file = gen_unique_name(waitfd_prefix);

	if (!wait_pipe_file) {
		goto error_gen_unique_wait;
	}

	wait_pipe_path = zmalloc(strlen(base_path)
				 + strlen(wait_pipe_file) + 1);

	if (!wait_pipe_path) {
		free(wait_pipe_file);
		goto error_wait_alloc;
	}

	strncat(wait_pipe_path, base_path, strlen(base_path));
	strncat(wait_pipe_path, wait_pipe_file, strlen(wait_pipe_file));

	free(wait_pipe_file);

	/* wait_fd: create named pipe */
	ret = mkfifo(wait_pipe_path, 0777);
	if (ret < 0) {
		PERROR("mkfifo");
		goto error_mkfifo;
	}

	obj->wait_fd[0] = -1;
	obj->wait_fd[1] = -1;
	obj->wait_pipe_path = wait_pipe_path;

	/* shm_fd: create shm */

	/*
	 * Theoretically, we could leak a shm if the application crashes
	 * between open and unlink. Disable signals on this thread for
	 * increased safety against this scenario.
	 */
	sigfillset(&all_sigs);
	ret = pthread_sigmask(SIG_BLOCK, &all_sigs, &orig_sigs);
	if (ret == -1) {
		PERROR("pthread_sigmask");
		goto error_pthread_sigmask;
	}
	sigblocked = 1;

	/*
	 * We specifically do _not_ use the / at the beginning of the
	 * pathname so that some OS implementations can keep it local to
	 * the process (POSIX leaves this implementation-defined).
	 */
	do {
		/*
		 * Using mktemp filename with O_CREAT | O_EXCL open
		 * flags.
		 */
		mktemp(tmp_name);
		if (tmp_name[0] == '\0') {
			PERROR("mktemp");
			goto error_shm_open;
		}
		shmfd = shm_open(tmp_name,
				 O_CREAT | O_EXCL | O_RDWR, 0700);
	} while (shmfd < 0 && (errno == EEXIST || errno == EACCES));
	if (shmfd < 0) {
		PERROR("shm_open");
		goto error_shm_open;
	}

	sigblocked = 0;
	ret = pthread_sigmask(SIG_SETMASK, &orig_sigs, NULL);
	if (ret == -1) {
		PERROR("pthread_sigmask");
		goto error_sigmask_release;
	}

	/* Create unique symlink to shm */
	shm_path = zmalloc(strlen(base_shm) + strlen(tmp_name) + 1);

	if (!shm_path) {
		goto error_shm_alloc;
	}

	strncat(shm_path, base_shm, strlen(base_shm));
	strncat(shm_path, tmp_name, strlen(tmp_name));

	shm_file = gen_unique_name(shm_prefix);

	if (!shm_file) {
		free(shm_path);
		goto error_gen_unique_shm;
	}

	shm_symlink_path = zmalloc(strlen(base_path) + strlen(shm_file) + 1);

	if (!shm_symlink_path) {
		free(shm_path);
		free(shm_file);
		goto error_symlink_alloc;
	}

	strncat(shm_symlink_path, base_path, strlen(base_path));
	strncat(shm_symlink_path, shm_file, strlen(shm_file));

	free(shm_file);

	ret = symlink(shm_path, shm_symlink_path);
	if (ret < 0) {
		PERROR("symlink");
		free(shm_path);
		free(shm_symlink_path);
		goto error_symlink_shm;
	}

	free(shm_path);

	ret = zero_file(shmfd, memory_map_size);
	if (ret) {
		PERROR("zero_file");
		goto error_zero_file;
	}
	ret = ftruncate(shmfd, memory_map_size);
	if (ret) {
		PERROR("ftruncate");
		goto error_ftruncate;
	}
	obj->shm_fd = shmfd;
	obj->shm_path = shm_symlink_path;

	/* memory_map: mmap */
	memory_map = mmap(NULL, memory_map_size, PROT_READ | PROT_WRITE,
			  MAP_SHARED, shmfd, 0);
	if (memory_map == MAP_FAILED) {
		PERROR("mmap");
		goto error_mmap;
	}
	obj->memory_map = memory_map;
	obj->memory_map_size = memory_map_size;
	obj->allocated_len = 0;
	obj->index = table->allocated_len++;

	return obj;

error_mmap:
error_ftruncate:
error_zero_file:
	free(shm_symlink_path);
error_symlink_shm:
error_symlink_alloc:
error_gen_unique_shm:
error_shm_alloc:
error_sigmask_release:
	ret = close(shmfd);
	if (ret) {
		PERROR("close");
		assert(0);
	}
error_shm_open:
	if (sigblocked) {
		ret = pthread_sigmask(SIG_SETMASK, &orig_sigs, NULL);
		if (ret == -1) {
			PERROR("pthread_sigmask");
		}
	}
error_pthread_sigmask:
error_mkfifo:
	free(wait_pipe_path);
error_wait_alloc:
error_gen_unique_wait:
	return NULL;
}

struct shm_object *shm_object_table_append_shadow(struct shm_object_table *table,
			int shm_fd, int wait_fd, size_t memory_map_size)
{
	struct shm_object *obj;
	char *memory_map;

	if (table->allocated_len >= table->size)
		return NULL;
	obj = &table->objects[table->allocated_len];

	/* wait_fd: set read end of the pipe. */
	obj->wait_fd[0] = wait_fd;
	obj->wait_fd[1] = -1;	/* write end is unset. */
	obj->shm_fd = shm_fd;

	/* memory_map: mmap */
	memory_map = mmap(NULL, memory_map_size, PROT_READ | PROT_WRITE,
			  MAP_SHARED, shm_fd, 0);
	if (memory_map == MAP_FAILED) {
		PERROR("mmap");
		goto error_mmap;
	}
	obj->memory_map = memory_map;
	obj->memory_map_size = memory_map_size;
	obj->allocated_len = memory_map_size;
	obj->index = table->allocated_len++;

	return obj;

error_mmap:
	return NULL;
}

static
void shmp_object_destroy(struct shm_object *obj)
{
	int ret, i;

	if (!obj->is_shadow) {
		ret = munmap(obj->memory_map, obj->memory_map_size);
		if (ret) {
			PERROR("umnmap");
			assert(0);
		}
	}
	if (obj->shm_fd >= 0) {
		ret = close(obj->shm_fd);
		if (ret) {
			PERROR("close");
			assert(0);
		}
	}

	if (obj->shm_path) {
		unlink(obj->shm_path);
		free(obj->shm_path);
	}

	for (i = 0; i < 2; i++) {
		if (obj->wait_fd[i] < 0)
			continue;
		ret = close(obj->wait_fd[i]);
		if (ret) {
			PERROR("close");
			assert(0);
		}
	}

	if (obj->wait_pipe_path) {
		unlink(obj->wait_pipe_path);
		free(obj->wait_pipe_path);
	}
}

void shm_object_table_destroy(struct shm_object_table *table)
{
	int i;

	for (i = 0; i < table->allocated_len; i++)
		shmp_object_destroy(&table->objects[i]);
	free(table);
}

/*
 * zalloc_shm - allocate memory within a shm object.
 *
 * Shared memory is already zeroed by shmget.
 * *NOT* multithread-safe (should be protected by mutex).
 * Returns a -1, -1 tuple on error.
 */
struct shm_ref zalloc_shm(struct shm_object *obj, size_t len)
{
	struct shm_ref ref;
	struct shm_ref shm_ref_error = { -1, -1 };

	if (obj->memory_map_size - obj->allocated_len < len)
		return shm_ref_error;
	ref.index = obj->index;
	ref.offset =  obj->allocated_len;
	obj->allocated_len += len;
	return ref;
}

void align_shm(struct shm_object *obj, size_t align)
{
	size_t offset_len = offset_align(obj->allocated_len, align);
	obj->allocated_len += offset_len;
}
