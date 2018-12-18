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

#include <string.h>
#include <unistd.h>
#include <sys/endian.h>

#define ZLIB_CONST
#include <zlib.h>

#include "vdef.h"

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
Gzip_WriteAa(int fd, uint64_t len)
{
	ssize_t i;
	uint8_t buf[sizeof gzip_head];

	/* Write the gzip'ed length to the 'Aa' extra header */
	i = read(fd, buf, sizeof gzip_head);
	assert(i == sizeof gzip_head);
	assert(Gzip_GoodAa(buf, i));
	le64enc(buf, len);
	i = write(fd, buf, 8);
	assert(i == 8);
}

/**********************************************************************
 * Read the length from an Aa field
 */

uint64_t
Gzip_ReadAa(const void *p, size_t l)
{

	assert(Gzip_GoodAa(p, l));
	xxxassert(l >= sizeof sizeof gzip_head + 8);
	return (le64dec((const uint8_t*)p + sizeof gzip_head));
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
