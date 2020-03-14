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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/endian.h>

#define ZLIB_CONST
#include <zlib.h>

#include "vdef.h"
#include "miniobj.h"

#include "vsb.h"
#include "vas.h"

#include "aardwarc.h"


/**********************************************************************
 * This is the gzip header we expect to find
 */

static const uint8_t gzip_head[] = {
	0x1f,			// ID1
	0x8b,			// ID2
	0x08,			// CM
	0x04,			// FLAGS
	0x00, 0x00, 0x00, 0x00,	// MTIME
	0x02,			// XFL (can be 2 or 4, see code)
	0x03,			// OS
	0x0c, 0x00,		// XLEN
	0x41, 0x61,		// SI1, SI2
	0x08, 0x00,		// LEN
};

static int
Gzip_GoodAa(const void *p, size_t l)
{
	uint8_t buf[sizeof gzip_head];

	assert(l >= sizeof buf);
	memcpy(buf, p, sizeof buf);
	if (buf[8] != 0x02 && buf[8] != 0x04)
		return (0);
	buf[8] = 0x02;
	if (memcmp(buf, gzip_head, sizeof gzip_head))
		return (0);
	return (1);
}

/**********************************************************************
 * Placeholder FEXTRA field for writing gzip files
 */

static uint8_t gzh_extra[] = {
	'A', 'a',
	8, 0,
	0, 0, 0, 0, 0, 0, 0, 0
};

static struct gz_header_s gzh = {
	.os =		3,	// UNIX
	.extra =	gzh_extra,
	.extra_len =	sizeof gzh_extra,
};

void
Gzip_AddAa(z_stream *gz)
{

	AZ(deflateSetHeader(gz, &gzh));
}

/**********************************************************************
 * Update the length in an Aa field
 */

void
Gzip_WriteAa(int fd, int64_t len)
{
	ssize_t i;
	uint8_t buf[sizeof gzip_head];

	assert(len > 0);

	/* Write the gzip'ed length to the 'Aa' extra header */
	i = read(fd, buf, sizeof gzip_head);
	assert(i == sizeof gzip_head);
	assert(Gzip_GoodAa(buf, i));
	le64enc(buf, (uint64_t)len);
	i = write(fd, buf, 8);
	assert(i == 8);
}

/**********************************************************************
 * Read the length from an Aa field
 */

int64_t
Gzip_ReadAa(const void *p, size_t l)
{
	int64_t len;

	assert(Gzip_GoodAa(p, l));
	xxxassert(l >= sizeof sizeof gzip_head + 8);
	len = (int64_t)le64dec((const uint8_t*)p + sizeof gzip_head);
	assert(len > 0);
	return (len);
}

/**********************************************************************/

const uint8_t Gzip_crnlcrnl[24] = {
	0x1f, 0x8b, 0x08, 0x00, 0x20, 0x01, 0x19, 0x66,
	0x02, 0x03, 0xe3, 0xe5, 0xe2, 0xe5, 0x02, 0x00,
	0x44, 0x15, 0xc2, 0x8b, 0x04, 0x00, 0x00, 0x00
};

/**********************************************************************/

void
Gzip_Vsb(struct vsb **vsbp, int level)
{
	struct vsb *input;
	struct vsb *output;
	char buf[1024];
	int i;
	z_stream zs[1];
	char *p;

	AN(vsbp);
	input = *vsbp;;
	*vsbp = NULL;
	AN(input);

	memset(zs, 0, sizeof zs);
	i = deflateInit2(zs,
	     level,
	     Z_DEFLATED,
	     16 + 15,
	     9,
	     Z_DEFAULT_STRATEGY);
	assert(i == Z_OK);
	Gzip_AddAa(zs);

	zs->avail_in = VSB_len(input);
	zs->next_in = (const void*) VSB_data(input);

	output = VSB_new_auto();
	AN(output);
	do {
		zs->avail_out = sizeof buf;
		zs->next_out = (void*)buf;
		i = deflate(zs, Z_FINISH);
		VSB_bcat(output, buf, sizeof buf - zs->avail_out);
	} while (i != Z_STREAM_END);
	AZ(VSB_finish(output));
	assert(deflateEnd(zs) == Z_OK);
	VSB_delete(input);
	p = VSB_data(output);
	assert(Gzip_GoodAa(p, VSB_len(output)));
	le64enc(p + sizeof gzip_head, VSB_len(output));
	*vsbp = output;
}

/**********************************************************************
 * Code to stitch multiple WARC segments, individually gzip'ed into
 * a single gzip object, because browser-people are morons who cannot
 * read.
 */

struct gzip_stitch {
	unsigned		magic;
#define GZIP_STITCH_MAGIC	0x62672ece
	byte_iter_f		*func;
	void			*priv;
	const char		*state;
	ssize_t			gzlen;
	int			retval;
	uint32_t		crc;
	uint32_t		l_crc;
	uint8_t			tailbuf[13];
};

static const char GZSTATE_OUTSIDE[] = "OUTSIDE GZIP";
static const char GZSTATE_INSIDE[] = "INSIDE GZIP";
static const char GZSTATE_TAIL[] = "TAIL GZIP";

static const uint8_t gzip_stitch_head[] = {
	0x1f,			// ID1
	0x8b,			// ID2
	0x08,			// CM
	0x00,			// FLAGS
	0x00, 0x00, 0x00, 0x00,	// MTIME
	0x04,			// XFL
	0x03,			// OS
};

struct gzip_stitch *
gzip_stitch_new(byte_iter_f *func, void *priv)
{
	struct gzip_stitch *gs;

	AN(func);

	ALLOC_OBJ(gs, GZIP_STITCH_MAGIC);
	AN(gs);
	gs->func = func;
	gs->priv = priv;
	gs->state = GZSTATE_OUTSIDE;
	gs->crc = crc32(0L, NULL, 0);

	gs->retval = gs->func(gs->priv,
	    gzip_stitch_head, sizeof gzip_stitch_head);

	return(gs);
}

int
gzip_stitch_feed(void *priv, const void *ptr, ssize_t len)
{
	struct gzip_stitch *gs;
	ssize_t skip;
	const uint8_t *p = ptr;
	uint32_t crc, bytes;
	AN(p);

	CAST_OBJ_NOTNULL(gs, priv, GZIP_STITCH_MAGIC);
	if (gs->retval)
		return (gs->retval);

	while (len > 0) {
		if (gs->state == GZSTATE_OUTSIDE) {
			/* Pick up gzlen from Aa extension and skip hdr */
			xxxassert(len >= 24);
			assert(p[0] == 0x1f);
			assert(p[1] == 0x8b);
			assert(p[2] == 0x08);
			assert(p[3] == 0x04);
			assert(p[12] == 0x41);
			assert(p[13] == 0x61);
			assert(p[14] == 0x08);
			assert(p[15] == 0x00);
			gs->gzlen = le64dec(p + 16);
			gs->state = GZSTATE_INSIDE;
			p += 24;
			len -= 24;
			gs->gzlen -= 24;
			continue;
		}
		if (gs->state == GZSTATE_INSIDE) {
			/* Pass on all the boring stuff in the middle */
			assert(len <= gs->gzlen);
			skip = len;
			if (skip > gs->gzlen - 13)
				skip = gs->gzlen - 13;
			gs->retval = gs->func(gs->priv, p, skip);
			if (gs->retval)
				return (gs->retval);
			p += skip;
			len -= skip;
			gs->gzlen -= skip;
			if (gs->gzlen == 13)
				gs->state = GZSTATE_TAIL;
			continue;
		}
		if (gs->state == GZSTATE_TAIL) {
			/* Strip from last stop-bit and accumulate CRC */
			memcpy(gs->tailbuf + 13 - gs->gzlen, p, len);
			p += len;
			gs->gzlen -= len;
			len -= len;
			if (gs->gzlen)
				continue;
			p = gs->tailbuf;
			if (p[3] == 0x03 && p[4] == 0x00) {
				gs->retval = gs->func(gs->priv, p, 3);
				if (gs->retval)
					return (gs->retval);
			} else if (p[0] == 0x01 &&
			     p[1] == 0x00 && p[2] == 0x00 &&
			     p[3] == 0xff && p[4] == 0xff) {
			} else {
				WRONG("Z_FINISH stop bit not found");
			}
			crc = le32dec(p + 5);
			bytes = le32dec(p + 9);
			gs->l_crc += bytes;
			gs->crc = crc32_combine(gs->crc, crc, bytes);
			gs->state = GZSTATE_OUTSIDE;
			len -= 13;
		}
	}
	return (gs->retval);
}

int
gzip_stitch_fini(struct gzip_stitch *gs)
{
	int retval;

	CHECK_OBJ_NOTNULL(gs, GZIP_STITCH_MAGIC);

	if (!gs->retval) {
		/* Emit a new stop-bit and a new CRC+LEN trailer */
		gs->tailbuf[0] = 0x01;
		gs->tailbuf[1] = 0x00;
		gs->tailbuf[2] = 0x00;
		gs->tailbuf[3] = 0xff;
		gs->tailbuf[4] = 0xff;
		le32enc(gs->tailbuf + 5, gs->crc);
		le32enc(gs->tailbuf + 9, gs->l_crc);
		gs->retval = gs->func(gs->priv, gs->tailbuf, 13);
	}
	retval = gs->retval;
	FREE_OBJ(gs);
	return (retval);
}
