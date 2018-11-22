/*-
 * Copyright (c) 2016 Poul-Henning Kamp
 * All rights reserved.
 *
 * Author: Poul-Henning Kamp <phk@phk.freebsd.dk>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

#include "vdef.h"

#include "vas.h"
#include "vsb.h"
#include "miniobj.h"

#include <sys/param.h>
#include <sys/mman.h>

#include "aardwarc.h"

#define PADDING_HEADER "z"

struct wsilo {
	unsigned		magic;
#define WSILO_MAGIC		0x4a454db2

	uint32_t		silo_no;
	uint32_t		idx;
	struct aardwarc		*aa;

	struct vsb		*silo_fn;

	struct vsb		*hold_fn;
	int			hold_fd;

	off_t			hold_len;

	struct header		*hd;
	off_t			hd_start;
	ssize_t			hd_len;

	char			*buf_ptr;
	ssize_t			buf_len;

	char			*warcinfo_id;
};

/*---------------------------------------------------------------------*/

/* Make the necessary directories to create this pathname -------------*/

static int
silo_mkparentdir(const char *path)
{
	char *p, *q;
	struct stat st;
	int i;

	p = strdup(path);
	AN(p);
	q = strrchr(p, '/');
	if (q == p)
		return (0);
	if (q != NULL)
		*q = '\0';
	i = stat(p, &st);
	if (i < 0 && errno == ENOENT) {
		i = silo_mkparentdir(p);
		if (i < 0)
			return (i);
		i = mkdir(p, 0755);
		if (i < 0)
			return (i);
		i = stat(p, &st);
	}
	if (i == 0 && !S_ISDIR(st.st_mode)) {
		errno = ENOTDIR;
		return (-1);
	}
	return (0);
}

/* Create a new (held) silo -------------------------------------------*/

struct wsilo *
Wsilo_New(struct aardwarc *aa)
{
	int j;
	uint32_t silono, high;
	int fd;
	struct vsb *vsb = NULL, *vsb2 = NULL;
	struct stat st;
	struct wsilo *sl;

	CHECK_OBJ_NOTNULL(aa, AARDWARC_MAGIC);
	ALLOC_OBJ(sl, WSILO_MAGIC);
	if (sl == NULL)
		return (NULL);
	sl->hold_fd = -1;

	AardWARC_ReadCache(aa);
	high = aa->cache_first_non_silo;
	for (silono = high; ; silono++) {
		vsb = Silo_Filename(aa, silono, 0);
		AN(vsb);

		if (!stat(VSB_data(vsb), &st)) {
			VSB_delete(vsb);
			if (silono == high + 1)
				high = silono;
			continue;
		}

		vsb2 = Silo_Filename(aa, silono, 1);
		AN(vsb2);

		j = silo_mkparentdir(VSB_data(vsb));
		if (j)
			fprintf(stderr, "MKDIR %d %d %s\n",
			    j, errno, strerror(errno));

		if (!stat(VSB_data(vsb2), &st)) {
			/* XXX: Check age, if > 1 week remove */
			VSB_delete(vsb);
			VSB_delete(vsb2);
			continue;
		}

		fd = open(VSB_data(vsb2), O_RDWR | O_CREAT | O_EXCL, 0640);

		if (fd < 0 && errno == EEXIST) {
			/* Somebody else holds it */
			VSB_delete(vsb);
			VSB_delete(vsb2);
			continue;
		}

		if (fd < 0) {
			/* XXX */
			fprintf(stderr,
			    "Unexpected error opening silo hold\n\t%s\n\t%s\n",
			    VSB_data(vsb2), strerror(errno));
			exit(2);
		}
		break;
	}

	AN(vsb);
	sl->silo_fn = vsb;
	AN(vsb2);
	sl->hold_fn = vsb2;

	sl->hold_fd = fd;
	sl->silo_no = silono;

	sl->buf_len = 1024*1024;
	sl->buf_ptr = malloc(sl->buf_len);
	AN(sl->buf_ptr);

	// fprintf(stderr, "DEBUG: Wsilo_New(%u)\n", silono);

	sl->aa = aa;

	sl->warcinfo_id = Warcinfo_New(sl->aa, sl, sl->silo_no);

	return (sl);
}

static void
wsilo_delete(struct wsilo *sl)
{

	/* We don't own ->hd, so don't free that */
	AZ(unlink(VSB_data(sl->hold_fn)));
	VSB_delete(sl->hold_fn);
	AZ(close(sl->hold_fd));
	VSB_delete(sl->silo_fn);
	REPLACE(sl->warcinfo_id, NULL);
	REPLACE(sl->buf_ptr, NULL);
	FREE_OBJ(sl);
}

/* Reserve space for first objects WARC header ------------------------*/

void
Wsilo_Header(struct wsilo *sl, struct header *hd, int pad)
{
	struct vsb *v2;
	ssize_t obuf_len, len2;
	void *obuf_ptr;
	const char *s;

	CHECK_OBJ_NOTNULL(sl, WSILO_MAGIC);
	AN(hd);
	assert(pad >= 0);

	if (pad > 0)
		pad += Header_Len(PADDING_HEADER, "_");

	sl->hd = hd;

	AZ(sl->hd_start);
	sl->hd_start = sl->hold_len;

	s = Header_Get(sl->hd, "WARC-Type");
	if (s != NULL && !strcmp(s, "metadata"))
		sl->idx |= IDX_F_METADATA;
	if (s != NULL && !strcmp(s, "resource"))
		sl->idx |= IDX_F_RESOURCE;
	v2 = Header_Serialize(sl->hd, 0);
	len2 = VSB_len(v2);
	assert(len2 > 0);

	sl->hd_len = len2 + pad;

	Wsilo_GetSpace(sl, &obuf_ptr, &obuf_len);
	assert(sl->hd_len < obuf_len);
	memcpy(obuf_ptr, VSB_data(v2), len2);
	AZ(Wsilo_Store(sl, len2));

	Wsilo_GetSpace(sl, &obuf_ptr, &obuf_len);
	assert(pad < obuf_len);
	memset(obuf_ptr, '_', pad);
	AZ(Wsilo_Store(sl, pad));

	VSB_delete(v2);
}

/* Buffered Write functions -------------------------------------------*/

void
Wsilo_GetSpace(const struct wsilo *sl, void **ptr, ssize_t *len)
{
	CHECK_OBJ_NOTNULL(sl, WSILO_MAGIC);
	AN(ptr);
	AN(len);

	*ptr = sl->buf_ptr;
	if (sl->aa->silo_maxsize - sl->hold_len > sl->buf_len)
		*len = sl->buf_len;
	else
		*len = sl->aa->silo_maxsize - sl->hold_len;
}

int
Wsilo_Store(struct wsilo *sl, ssize_t len)
{
	ssize_t s;

	CHECK_OBJ_NOTNULL(sl, WSILO_MAGIC);

	assert(len > 0);
	assert(len <= sl->buf_len);

	s = write(sl->hold_fd, sl->buf_ptr, len);
	assert(s == len);
	sl->hold_len += len;
	return (0);
}

/* Done writing -------------------------------------------------------*/

void
Wsilo_Finish(struct wsilo *sl)
{
	CHECK_OBJ_NOTNULL(sl, WSILO_MAGIC);

	AN(sl->buf_ptr);
	REPLACE(sl->buf_ptr, NULL);
	sl->buf_len = 0;
}

/* Committing silos ---------------------------------------------------*/

static int
silo_attempt_append(const struct wsilo *sl, uint32_t silono,
    const struct vsb *v2, const char *id)
{
	struct stat st;
	struct aardwarc *aa;
	struct vsb *fn, *fnh = NULL;
	off_t need;
	int fdh = -1, fds = -1;
	char *p;
	struct iovec iov[2];
	ssize_t s;
	size_t wlen;
	int ps = getpagesize();
	int retval = 0;
	off_t ax;
	off_t bx;

	aa = sl->aa;

	need = VSB_len(v2);
	need += sl->hold_len - (sl->hd_start + sl->hd_len);

	fn = Silo_Filename(aa, silono, 0);
	AN(fn);

	do {
		if (stat(VSB_data(fn), &st))
			break;
		if (!S_ISREG(st.st_mode))
			break;
		if (silono == aa->cache_first_non_silo) {
			aa->cache_first_non_silo++;
			AardWARC_WriteCache(aa);
		}
		if (!(st.st_mode & S_IWUSR)) {
			/*
			 * Permanently stored silos should be writeprotected.
			 * Assume this happen bottom up order, and stop
			 * once we hit the first of them.
			 */
			retval = -1;
			break;
		}

		/*
		 * The follwing weird heuristic autotunes how full we try
		 * to load the silos, vs. how many silos we have to examine
		 * duing a store operation.
		 *
		 * XXX: A scaling factor, roughly the smallest object size
		 * XXX: in the kilobytes may be necessary.
		 */

		ax = aa->silo_maxsize - st.st_size;
		bx = aa->cache_first_non_silo - aa->cache_first_space_silo;

		if (silono == aa->cache_first_space_silo && ax < bx) {
			aa->cache_first_space_silo++;
			AardWARC_WriteCache(aa);
		}

		if (st.st_size + need > aa->silo_maxsize)
			break;

		fnh = Silo_Filename(aa, silono, 1);
		AN(fnh);

		fdh = open(VSB_data(fnh), O_WRONLY | O_CREAT | O_EXCL, 0640);
		if (fdh < 0)
			break;

		fds = open(VSB_data(fn), O_WRONLY | O_APPEND);
		if (fds < 0)
			break;

		if (fstat(fds, &st))
			break;
		if (!S_ISREG(st.st_mode))
			break;
		if (!(st.st_mode & S_IWUSR))
			break;
		if (st.st_size + need > aa->silo_maxsize)
			break;

		p = mmap(
		    NULL,
		    roundup(sl->hold_len, ps),
		    PROT_READ,
		    MAP_PRIVATE | MAP_NOCORE ,
		    sl->hold_fd,
		    0);

		if (p == MAP_FAILED)
			break;

		iov[0].iov_base = VSB_data(v2);
		iov[0].iov_len = VSB_len(v2);
		iov[1].iov_base = p + sl->hd_start + sl->hd_len;
		iov[1].iov_len = sl->hold_len - (sl->hd_start + sl->hd_len);

		wlen = iov[0].iov_len + iov[1].iov_len;
		s = writev(fds, iov, 2);
		assert(s >= 0);
		assert((size_t)s == wlen);
		AZ(munmap(p, roundup(sl->hold_len, ps)));
		// fprintf(stderr, "DEBUG: Wsilo_Append(%u) %ju\n", silono, need);

		need = lseek(fds, 0, SEEK_CUR);
		assert(need > s);
		IDX_Insert(aa, id, sl->idx, silono, need - s, NULL);

		retval = 1;

	} while (0);

	if (fdh >= 0) {
		AN(fnh);
		AZ(close(fdh));
		AZ(unlink(VSB_data(fnh)));
	}
	if (fnh != NULL)
		VSB_delete(fnh);
	if (fds >= 0)
		AZ(close(fds));
	VSB_delete(fn);
	return (retval);
}

/* Commit a silo ------------------------------------------------------*/

void
Wsilo_Commit(struct wsilo **slp, int segd, const char *id, const char *rid)
{
	struct wsilo *sl;
	struct vsb *vsb;
	ssize_t s;
	int i, done = 0;
	uint32_t sn;
	struct aardwarc *aa;
	const char *t;

	AN(slp);
	AN(id);
	sl = *slp;
	*slp = NULL;
	CHECK_OBJ_NOTNULL(sl, WSILO_MAGIC);
	AN(sl->hd);
	AZ(sl->buf_ptr);
	aa = sl->aa;

	if (!segd && sl->silo_no > 0) {
		AZ(rid);
		/*
		 * The silo does not hold a segmented object.
		 * Attempt to append the object to a previous silo.
		 */
		vsb = Header_Serialize(sl->hd, 9);
		for (sn = aa->cache_first_space_silo; sn < sl->silo_no;sn++) {
			i = silo_attempt_append(sl, sn, vsb, id);
			if (i == 1) {
				/* Success */
				done = 1;
				break;
			} else if (i == -1)
				/* Impossible */
				break;
		}
		VSB_delete(vsb);
	}

	if (!done) {
		/*
		 * Segmented, or simply too big to be appended
		 * Pad & write the header, rename the hold to silo.
		 */
		vsb = Header_Serialize(sl->hd, 0);
		i = sl->hd_len - VSB_len(vsb);

		if (i > 0) {
			/* Add padding header */
			assert(i >= 5);
			char *p = malloc(i);
			AN(p);
			memset(p, '_', i - 1);
			p[i - 1] = '\0';
			Header_Set(sl->hd, PADDING_HEADER, "%s", p + 4);
			REPLACE(p, NULL);

			VSB_delete(vsb);
			vsb = Header_Serialize(sl->hd, 0);
		}
		assert(VSB_len(vsb) == sl->hd_len);

		s = pwrite(sl->hold_fd, VSB_data(vsb),
		    sl->hd_len, sl->hd_start);
		assert(s == sl->hd_len);

		VSB_delete(vsb);

		IDX_Insert(aa, sl->warcinfo_id, IDX_F_WARCINFO,
		    sl->silo_no, 0, NULL);
		if (segd) {
			sl->idx |= IDX_F_SEGMENTED;
			t = Header_Get(sl->hd, "WARC-Segment-Number");
			AN(t);
			if (!strcmp(t, "1"))
				sl->idx |= IDX_F_FIRSTSEG;
			if (rid == NULL)
				sl->idx |= IDX_F_LASTSEG;
		}
		IDX_Insert(aa, id, sl->idx, sl->silo_no, sl->hd_start, rid);

		/*
		 * We don't use rename(2) because it wouldn't fail if the
		 * destination silo already exists.
		 */
		AZ(link(VSB_data(sl->hold_fn), VSB_data(sl->silo_fn)));
		if (sl->silo_no == aa->cache_first_non_silo) {
			aa->cache_first_non_silo++;
			AardWARC_WriteCache(aa);
		}

	}

	wsilo_delete(sl);
}

void
Wsilo_Abandon(struct wsilo **slp)
{
	struct wsilo *sl;

	AN(slp);
	sl = *slp;
	*slp = NULL;
	CHECK_OBJ_NOTNULL(sl, WSILO_MAGIC);
	wsilo_delete(sl);
}
