/*
 * Copyright (c) 2015 Dima Krasner
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <stdbool.h>
#include <limits.h>
#include <elf.h>
#include <sys/mman.h>

#define FUSE_USE_VERSION (26)
#include <fuse.h>
#include <ed25519.h>

/* the command-line usage message */
#define USAGE "Usage: %s DIR\n"

/* the global file system state */
struct ef_ctx {
	char path[PATH_MAX]; /* the mount point path */
	int fd; /* a file descriptor of the mount point - we need it for *at()
	         * system calls */
	unsigned char pub_key[32]; /* the public key */
};

static struct ef_ctx *get_ctx(struct fuse_context **ctx)
{
	struct fuse_context *tmp;

	if (NULL == ctx) {
		tmp = fuse_get_context();
		if (NULL != tmp)
			return (struct ef_ctx *) tmp->private_data;
	}
	else {
		*ctx = fuse_get_context();
		if (NULL != *ctx)
			return (struct ef_ctx *) (*ctx)->private_data;
	}

	return NULL;
}

static void *ef_init(struct fuse_conn_info *conn)
{
	openlog(PROG, 0, LOG_DAEMON);

	return (void *) get_ctx(NULL);
}

static void ef_destroy(void *private_data)
{
	closelog();
}

static int ef_access(const char *name, int mask)
{
	const struct ef_ctx *ef_ctx;
	const char *rname;

	ef_ctx = get_ctx(NULL);
	if (NULL == ef_ctx)
		return -ENOMEM;

	if (0 == strcmp("/", name))
		rname = ".";
	else
		rname = &name[1];
	if (-1 == faccessat(ef_ctx->fd, rname, mask, 0))
		return -errno;

	return 0;
}

static int stat_internal(const char *name,
                         struct stat *stbuf,
                         const bool follow)
{
	const struct ef_ctx *ef_ctx;
	int flags;

	ef_ctx = get_ctx(NULL);
	if (NULL == ef_ctx)
		return -ENOMEM;

	if (true == follow)
		flags = AT_EMPTY_PATH;
	else
		flags = AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH;
	if (-1 == fstatat(ef_ctx->fd, &name[1], stbuf, flags))
		return -errno;

	return 0;
}

static int ef_stat(const char *name, struct stat *stbuf)
{
	return stat_internal(name, stbuf, false);
}

/* returns the "name" of a process - similar to get_task_comm() */
static const char *get_name(const pid_t pid, char *buf, const size_t len)
{
	char path[PATH_MAX];
	const char *pos = NULL;
	char *term;
	ssize_t res;
	int out;
	int fd;

	out = snprintf(path, sizeof(path), "/proc/%ld/stat", (long) pid);
	if ((0 >= out) || (sizeof(path) <= out))
		goto end;

	fd = open(path, O_RDONLY);
	if (-1 == fd)
		goto end;

	res = read(fd, (void *) buf, len - 1);
	if (0 >= res)
		goto close_stat;
	buf[res] = '\0';

	/* locate and separate the process name - it's enclosed in parentheses */
	pos = strchr(buf, '(');
	if (NULL == pos)
		goto close_stat;
	++pos;

	term = strchr(pos, ')');
	if (NULL == term) {
		pos = NULL;
		goto close_stat;
	}
	term[0] = '\0';

close_stat:
	(void) close(fd);

end:
	return pos;
}

static int open_internal(const char *name, const int flags, const mode_t mode)
{
	struct ef_ctx *ef_ctx;
	int fd;

	ef_ctx = get_ctx(NULL);
	if (NULL == ef_ctx)
		return -ENOMEM;

	fd = openat(ef_ctx->fd, &name[1], flags, mode);
	if (-1 == fd)
		return -errno;

	return fd;
}

static int ef_create(const char *name,
                     mode_t mode,
                     struct fuse_file_info *fi)
{
	struct fuse_context *ctx;
	const struct ef_ctx *ef_ctx;
	int fd;
	int tmp;

	ef_ctx = get_ctx(&ctx);
	if (NULL == ef_ctx)
		return -ENOMEM;

	/* creat() does not have a *at() equivalent, so we have to use the
	 * combination openat(), O_CREAT and fchownat() */
	fd = open_internal(name, O_CREAT | fi->flags, mode);
	if (0 > fd)
		return fd;

	if (-1 == fchownat(ef_ctx->fd,
	                   &name[1],
	                   ctx->uid,
	                   ctx->gid,
	                   AT_SYMLINK_NOFOLLOW)) {
		tmp = errno;
		(void) close(fd);
		return -tmp;
	}

	fi->fh = (uint64_t) fd;

	return 0;
}

static int ef_truncate(const char *name, off_t size)
{
	int fd;
	int ret;

	fd = open_internal(name, O_WRONLY, 0);
	if (0 > fd)
		return fd;

	if (-1 == ftruncate(fd, size))
		ret = -errno;
	else
		ret = 0;

	(void) close(fd);

	return ret;
}

static int verify_elf(const char *name, const int fd, const int flags)
{
	struct stat stbuf;
	void *data;
	const struct ef_ctx *ef_ctx;
	int ret = -ENOMEM;

	if (0 != (O_WRONLY & flags)) {
		ret = 0;
		goto end;
	}

	ef_ctx = get_ctx(NULL);
	if (NULL == ef_ctx)
		goto end;

	ret = stat_internal(name, &stbuf, true);
	if (0 != ret)
		goto end;

	if (SELFMAG >= stbuf.st_size) {
		ret = 0;
		goto end;
	}

	data = mmap(NULL, (size_t) stbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (MAP_FAILED == data) {
		ret = -errno;
		goto end;
	}

	/* if the file is not an ELF binary, leave it alone */
	if (0 != memcmp(ELFMAG, data, SELFMAG)) {
		ret = 0;
		goto unmap;
	}

	/* make sure the binary is big enough to contain a signature */
	if ((SELFMAG + 64) >= stbuf.st_size) {
		ret = -EPERM;
		goto unmap;
	}

	if (1 == ed25519_verify(((const unsigned char *) data) + stbuf.st_size - 64,
	                        (const unsigned char *) data,
	                        (size_t) stbuf.st_size - 64,
	                        ef_ctx->pub_key))
		ret = 0;
	else
		ret = -EPERM;

unmap:
	(void) munmap(data, (size_t) stbuf.st_size);

end:
	return ret;
}

static int ef_open(const char *name, struct fuse_file_info *fi)
{
	char buf[NAME_MAX];
	const char *comm;
	struct fuse_context *ctx;
	const struct ef_ctx *ef_ctx;
	int fd;
	int ret;

	fd = open_internal(name, 3 & fi->flags, 0);
	if (0 > fd)
		return fd;

	ret = verify_elf(name, fd, fi->flags);
	if (0 == ret) {
		fi->fh = (uint64_t) fd;
		return 0;
	}

	if (-EPERM == ret) {
		ef_ctx = get_ctx(&ctx);
		if (NULL == ef_ctx) {
			ret = -ENOMEM;
			goto close_fd;
		}

		comm = get_name(ctx->pid, buf, sizeof(buf));
		if (NULL == comm) {
			syslog(LOG_ALERT,
			       "denied open of %s%s from %ld\n",
			       ef_ctx->path,
			       name,
			       (long) ctx->pid);
		}
		else {
			syslog(LOG_ALERT,
			       "denied open of %s%s from %ld (%s)\n",
			       ef_ctx->path,
			       name,
			       (long) ctx->pid,
			       comm);
		}
	}

close_fd:
	(void) close(fd);

	return ret;
}

static int ef_close(const char *name, struct fuse_file_info *fi)
{
	int fd = (int) fi->fh;

	if (-1 == fd)
		return -EBADF;

	if (-1 == close(fd))
		return -errno;

	fi->fh = (uint64_t) -1;

	return 0;
}

static int ef_unlink(const char *path)
{
	const struct ef_ctx *ef_ctx;

	ef_ctx = get_ctx(NULL);
	if (NULL == ef_ctx)
		return -ENOMEM;

	if (-1 == unlinkat(ef_ctx->fd, &path[1], 0))
		return -errno;

	return 0;
}

static int ef_read(const char *path,
                   char *buf,
                   size_t size,
                   off_t off,
                   struct fuse_file_info *fi)
{
	ssize_t ret;
	int fd = (int) fi->fh;

	if (-1 == fd)
		return -EBADF;

	ret = pread(fd, buf, size, off);
	if (-1 == ret)
		return -errno;

	return (int) ret;
}

static int ef_write(const char *path,
                    const char *buf,
                    size_t size,
                    off_t off,
                    struct fuse_file_info *fi)
{
	ssize_t ret;
	int fd = (int) fi->fh;

	if (-1 == fd)
		return -EBADF;

	ret = pwrite(fd, buf, size, off);
	if (-1 == ret)
		return -errno;

	return (int) ret;
}

static int ef_mkdir(const char *path, mode_t mode)
{
	const struct ef_ctx *ef_ctx;

	ef_ctx = get_ctx(NULL);
	if (NULL == ef_ctx)
		return -ENOMEM;

	if (-1 == mkdirat(ef_ctx->fd, &path[1], mode))
		return -errno;

	return 0;
}

static int ef_opendir(const char *name, struct fuse_file_info *fi)
{
	const struct ef_ctx *ef_ctx;
	DIR *fh;
	const char *rname;
	int fd;
	int ret = -ENOMEM;

	ef_ctx = get_ctx(NULL);
	if (NULL == ef_ctx)
		goto end;

	if (0 == strcmp("/", name))
		rname = ".";
	else
		rname = &name[1];
	fd = openat(ef_ctx->fd, rname, O_DIRECTORY | (3 & fi->flags), 0);
	if (-1 == fd) {
		ret = -errno;
		goto end;
	}

	fh = fdopendir(fd);
	if (NULL == fh) {
		ret = -errno;
		(void) close(fd);
		goto end;
	}

	fi->fh = (uint64_t) (uintptr_t) fh;
	ret = 0;

end:
	return ret;
}

static int ef_readdir(const char *path,
                      void *buf,
                      fuse_fill_dir_t filler,
                      off_t offset,
                      struct fuse_file_info *fi)
{
	struct stat stbuf;
	struct dirent ent;
	struct dirent *entp;
	DIR *fh = (DIR *) (void *) (uintptr_t) fi->fh;

	if (NULL == fh)
		return -EBADF;

	if (0 != readdir_r(fh, &ent, &entp))
		return -errno;
	if (NULL == entp)
		return 0;

	if (-1 == fstatat(dirfd(fh),
	                  entp->d_name,
	                  &stbuf,
	                  AT_SYMLINK_NOFOLLOW))
		return -errno;

	if (1 == filler(buf, entp->d_name, &stbuf, 1 + offset))
		return -ENOMEM;

	return 0;
}

static int ef_closedir(const char *name, struct fuse_file_info *fi)
{
	DIR *fh = (DIR *) (void *) (uintptr_t) fi->fh;

	if (NULL == fh)
		return -EBADF;

	if (-1 == closedir(fh))
		return -errno;

	fi->fh = (uint64_t) (uintptr_t) NULL;

	return 0;
}

static int ef_rmdir(const char *path)
{
	const struct ef_ctx *ef_ctx;

	ef_ctx = get_ctx(NULL);
	if (NULL == ef_ctx)
		return -ENOMEM;

	if (-1 == unlinkat(ef_ctx->fd, &path[1], AT_REMOVEDIR))
		return -errno;

	return 0;
}

static int ef_symlink(const char *oldpath, const char *newpath)
{
	const struct ef_ctx *ef_ctx;

	ef_ctx = get_ctx(NULL);
	if (NULL == ef_ctx)
		return -ENOMEM;

	if (-1 == symlinkat(oldpath, ef_ctx->fd, &newpath[1]))
		return -errno;

	return 0;
}

static int ef_readlink(const char *path, char *buf, size_t len)
{
	const struct ef_ctx *ef_ctx;

	ef_ctx = get_ctx(NULL);
	if (NULL == ef_ctx)
		return -ENOMEM;

	len = readlinkat(ef_ctx->fd, &path[1], buf, len - 1);
	if (-1 == len)
		return -errno;
	buf[len] = '\0';

	return 0;
}

static int ef_chmod(const char *path, mode_t mode)
{
	const struct ef_ctx *ef_ctx;

	ef_ctx = get_ctx(NULL);
	if (NULL == ef_ctx)
		return -ENOMEM;

	if (-1 == fchmodat(ef_ctx->fd, &path[1], mode, AT_SYMLINK_NOFOLLOW))
		return -errno;

	return 0;
}

static int ef_chown(const char *path, uid_t uid, gid_t gid)
{
	const struct ef_ctx *ef_ctx;

	ef_ctx = get_ctx(NULL);
	if (NULL == ef_ctx)
		return -ENOMEM;

	if (-1 == fchownat(ef_ctx->fd,
	                   &path[1],
	                   uid,
	                   gid,
	                   AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW))
		return -errno;

	return 0;
}

static int ef_utimens(const char *path, const struct timespec tv[2])
{
	const struct ef_ctx *ef_ctx;

	ef_ctx = get_ctx(NULL);
	if (NULL == ef_ctx)
		return -ENOMEM;

	if (-1 == utimensat(ef_ctx->fd,
	                   &path[1],
	                   tv,
	                   AT_SYMLINK_NOFOLLOW))
		return -errno;

	return 0;
}

static struct fuse_operations ef_oper = {
	.init		= ef_init,
	.destroy	= ef_destroy,

	.access		= ef_access,
	.getattr	= ef_stat,

	.chmod		= ef_chmod,
	.chown		= ef_chown,
	.utimens	= ef_utimens,

	.create		= ef_create,
	.truncate	= ef_truncate,
	.open		= ef_open,
	.release	= ef_close,
	.unlink		= ef_unlink,

	.read		= ef_read,
	.write		= ef_write,

	.symlink	= ef_symlink,
	.readlink	= ef_readlink,

	.mkdir		= ef_mkdir,
	.opendir	= ef_opendir,
	.readdir	= ef_readdir,
	.releasedir	= ef_closedir,
	.rmdir		= ef_rmdir
};

int main(int argc, char *argv[])
{
	char *fuse_argv[] = {argv[0], "-ononempty", argv[1], NULL};
	struct ef_ctx ctx;
	struct stat stbuf;
	int key_fd;
	int ret = EXIT_FAILURE;

	if (1 == argc) {
		(void) fprintf(stderr, USAGE, argv[0]);
		goto end;
	}

	/* get the canonicalized path of the mount point, for prettier logging */
	if (NULL == realpath(argv[1], ctx.path))
		goto end;

	ctx.fd = open(argv[1], O_DIRECTORY | O_RDONLY);
	if (-1 == ctx.fd)
		goto end;

	key_fd = open(PUB_KEY_PATH, O_RDONLY);
	if (-1 == key_fd)
		goto close_dir;

	if (-1 == fstat(key_fd, &stbuf))
		goto close_key;
	if (sizeof(ctx.pub_key) != stbuf.st_size)
		goto close_key;

	if (sizeof(ctx.pub_key) != read(key_fd,
	                                (void *) ctx.pub_key,
	                                sizeof(ctx.pub_key)))
		goto close_key;

	ret = fuse_main((sizeof(fuse_argv) / sizeof(fuse_argv[0])) - 1,
	                fuse_argv,
	                &ef_oper,
	                (void *) &ctx);

close_key:
	(void) close(key_fd);

close_dir:
	(void) close(ctx.fd);

end:
	return ret;
}
