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

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ZLIB_CONST
#include <zlib.h>

#include "vdef.h"

#include "vas.h"
#include "vsb.h"
#include "miniobj.h"

#include "aardwarc.h"

struct rsilo {
	unsigned		magic;
#define RSILO_MAGIC		0x61dd094a

	uint32_t		silo_no;
	struct aardwarc		*aa;

	char			*silo_fn;
	int			silo_fd;

};

/*---------------------------------------------------------------------*/

/* Open a silo for reading --------------------------------------------*/

static struct rsilo *
rsilo_open_fn(const char *fn, struct aardwarc *aa, uint32_t silono)
{
	struct rsilo *rs;
	int fd;

	AN(fn);

	fd = open(fn, O_RDONLY);
	if (fd < 0)
		return (NULL);

	ALLOC_OBJ(rs, RSILO_MAGIC);
	if (rs == NULL) {
		AZ(close(fd));
		return (NULL);
	}
	rs->silo_no = silono;
	rs->aa = aa;

	rs->silo_fd = fd;
	REPLACE(rs->silo_fn, fn);

	return (rs);
}

struct rsilo *
Rsilo_Open(struct aardwarc *aa, const char *fn, uint32_t nsilo)
{
	struct vsb *vsb = NULL;
	struct rsilo *rs;

	CHECK_OBJ_NOTNULL(aa, AARDWARC_MAGIC);

	if (fn == NULL) {
		vsb = Silo_Filename(aa, nsilo, 0);
		AN(vsb);
		rs = rsilo_open_fn(VSB_data(vsb), aa, nsilo);
		VSB_delete(vsb);
	} else {
		rs = rsilo_open_fn(fn, aa, 0xffffffff);
	}
	return (rs);
}

/* Close silo ---------------------------------------------------------*/

void
Rsilo_Close(struct rsilo **p)
{

	struct rsilo *rs;

	AN(p);
	rs = *p;
	*p = NULL;
	CHECK_OBJ_NOTNULL(rs, RSILO_MAGIC);
	REPLACE(rs->silo_fn, NULL);
	AZ(close(rs->silo_fd));
	FREE_OBJ(rs);
}

/* Seek/Tell functions ------------------------------------------------*/

off_t
Rsilo_Tell(const struct rsilo *rs)
{
	off_t o;

	CHECK_OBJ_NOTNULL(rs, RSILO_MAGIC);
	o = lseek(rs->silo_fd, 0, SEEK_CUR);
	assert(o >= 0);
	return (o);
}

void
Rsilo_Seek(const struct rsilo *rs, uint64_t o)
{
	off_t o2;

	CHECK_OBJ_NOTNULL(rs, RSILO_MAGIC);
	o2 = lseek(rs->silo_fd, (off_t)o, SEEK_SET);
	assert((uint64_t)o2 == o);
}

/* Read a WARC header -------------------------------------------------*/

struct header *
Rsilo_ReadHeader(const struct rsilo *rs)
{
	z_stream	zs[1];
	int		ps = getpagesize();
	char		ibuf[ps];
	char		obuf[ps + 1];
	int		i;
	uint64_t	gzl;

	CHECK_OBJ_NOTNULL(rs, RSILO_MAGIC);

	i = read(rs->silo_fd, ibuf, ps);
	assert(i >= 0);
	if (i == 0)
		return (NULL);

	memset(zs, 0, sizeof zs);
	zs->next_in = (void*)ibuf;
	zs->avail_in = i;
	zs->next_out = (void*)obuf;
	zs->avail_out = sizeof obuf - 1;
	i = inflateInit2(zs, 15 + 32);
	assert(i == Z_OK);

	i = inflate(zs, 0);
	xxxassert(i == Z_STREAM_END);	// One page is enough for everybody...

	obuf[ps - zs->avail_out] = '\0';

	gzl = Gzip_ReadAa(zs->next_in, zs->avail_in);

	if (zs->avail_in > 0)
		(void)lseek(rs->silo_fd, -(off_t)zs->avail_in, SEEK_CUR);

	i = inflateEnd(zs);
	assert(i == Z_OK);

	return (Header_Parse(rs->aa, obuf, (off_t)gzl));
}

/* Read a WARC body ---------------------------------------------------*/

int
Rsilo_ReadGZChunk(const struct rsilo *rs, off_t len,
    byte_iter_f *func, void *priv)
{
	int		ps = getpagesize();
	ssize_t		sz;
	char		ibuf[ps * 100];
	int		j;
	off_t		ll = 0;

	CHECK_OBJ_NOTNULL(rs, RSILO_MAGIC);
	AN(func);

	/* XXX: Substitute a gzip header without the Aa extra field? */

	do {
		sz = sizeof ibuf;
		if (sz > len)
			sz = len;
		sz = read(rs->silo_fd, ibuf, sz);
		if (sz <= 0)
			return(0);
		ll += sz;
		j = func(priv, ibuf, sz);
		if (j)
			return(0);
		len -= sz;
	} while (len > 0);
	return (ll);
}

/* Read a WARC body ---------------------------------------------------*/

uintmax_t
Rsilo_ReadChunk(const struct rsilo *rs, byte_iter_f *func, void *priv)
{
	z_stream	zs[1];
	int		ps = getpagesize();
	char		ibuf[ps * 100];
	char		obuf[ps * 100];
	int		i, j;

	CHECK_OBJ_NOTNULL(rs, RSILO_MAGIC);
	AN(func);
	(void)priv;

	memset(zs, 0, sizeof zs);
	i = inflateInit2(zs, 15 + 32);
	assert(i == Z_OK);

	do {
		if (zs->avail_in == 0) {
			i = read(rs->silo_fd, ibuf, ps);
			assert(i > 0);
			zs->next_in = (void*)ibuf;
			zs->avail_in = i;
		}

		zs->next_out = (void*)obuf;
		zs->avail_out = sizeof obuf;

		i = inflate(zs, 0);
		assert(i >= Z_OK);
		if (zs->avail_out < sizeof obuf)
			j = func(priv, obuf, sizeof obuf - zs->avail_out);
		else
			j = 0;
	} while (i >= Z_OK && i != Z_STREAM_END && j == 0);

	if (zs->avail_in > 0)
		(void)lseek(rs->silo_fd, -(off_t)zs->avail_in, SEEK_CUR);

	i = inflateEnd(zs);
	assert(i == Z_OK);
	if (j != 0)
		return(0);
	return(zs->total_in);
}

/* Read a CRNLCRNL separator ------------------------------------------*/

static int v_matchproto_(byte_iter_f)
rsilo_iter_crnlcrnl(void *priv, const void *ptr, ssize_t len)
{
	/* XXX: Should guard against multiple (and partial?) calls */
	(void)priv;
	assert(len == 4);
	assert(!memcmp(ptr, "\r\n\r\n", 4));
	return (0);
}

void
Rsilo_SkipCRNL(const struct rsilo *rs)
{
	(void)Rsilo_ReadChunk(rs, rsilo_iter_crnlcrnl, NULL);
}
