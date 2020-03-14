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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sha256.h>
#include <unistd.h>

#define ZLIB_CONST
#include <zlib.h>

#include "vdef.h"

#include "vas.h"
#include "vsb.h"
#include "miniobj.h"

#include "aardwarc.h"

struct rebuild {
	unsigned			magic;
#define REBUILD_MAGIC			0xf972c416
	struct aardwarc			*aa;
	int				fdo;

	char				hdrbuf[BUFSIZ];
	unsigned char			fixbuf[BUFSIZ];
	size_t				hdrlen;
	struct vsb			*vsb;
	int				state;
	intmax_t			rlen;
	off_t				body_start;
	z_stream			zs[1];
	unsigned char			obuf[128 * 1024];
	struct SHA256Context		sha256[1];
	struct header			*h;
	intmax_t			clen;
};

static void
rebuild_process(struct rebuild *rb, const unsigned char *ptr, ssize_t len)
{
	ssize_t oz, wz;
	char *p;
	const char *q;
	off_t ll;
	int i;

	CHECK_OBJ_NOTNULL(rb, REBUILD_MAGIC);

	while (len > 0) {
		if (rb->state == 0) {
			AZ(rb->hdrlen);
			rb->state = 1;
		}

		if (rb->state == 1) {
			assert(rb->hdrlen + len + 1 < sizeof rb->hdrbuf);
			memcpy(rb->hdrbuf + rb->hdrlen, ptr, len);
			rb->hdrlen += len;
			len = 0;
			rb->hdrbuf[rb->hdrlen] = '\0';
			p = strstr(rb->hdrbuf, "\r\n\r\n");
			if (p == NULL)
				return;
			p += 4;
			xxxassert(p == rb->hdrbuf + rb->hdrlen);
			AZ(rb->h);
			rb->h = Header_Parse(rb->aa, rb->hdrbuf);
			AN(rb->h);
			rb->clen = Header_Get_Number(rb->h, "Content-Length");

			Header_Delete(rb->h, "Content-Length-GZIP");
			Header_Delete(rb->h, "z");

			q = Header_Get(rb->h, "WARC-record-digest");
			if (q != NULL) {
				rb->state = 3;
				rb->rlen = 0;
				SHA256_Init(rb->sha256);
				continue;
			}

			VSB_destroy(&rb->vsb);
			rb->vsb = Header_Serialize(rb->h, 0);
			wz = write(rb->fdo,
			    VSB_data(rb->vsb), VSB_len(rb->vsb));
			assert(wz == VSB_len(rb->vsb));
			Header_Destroy(&rb->h);
			rb->hdrlen = 0;
			rb->body_start = lseek(rb->fdo, 0, SEEK_CUR);

			memset(rb->zs, 0, sizeof rb->zs);
			i = deflateInit2(rb->zs,
			    AA_COMPRESSION,
			    Z_DEFLATED,
			    16 + 15,
			    9,
			    Z_DEFAULT_STRATEGY);
			assert(i == Z_OK);
			Gzip_AddAa(rb->zs);

			rb->state = 10;
			rb->rlen = rb->clen;
			continue;
		}

		if (rb->state == 3) {
			VSB_destroy(&rb->vsb);
			rb->vsb = Header_Serialize(rb->h, -1);
			AZ(VSB_finish(rb->vsb));
			printf("FIXUP from\n%s\n", VSB_data(rb->vsb));

			Header_Delete(rb->h, "WARC-record-digest");
			oz = rb->clen - rb->rlen;
			if (len < oz)
				oz = len;
			SHA256_Update(rb->sha256, ptr, oz);
			memcpy(rb->fixbuf + rb->rlen, ptr, oz);
			ptr += oz;
			len -= oz;
			rb->rlen += oz;
			if (rb->rlen < rb->clen)
				continue;
			p = SHA256_End(rb->sha256, NULL);
			Header_Set(rb->h, "WARC-Block-digest",
			    "sha256:%s", p);
			Header_Set_Id(rb->h, p);
			free(p);

			VSB_destroy(&rb->vsb);
			rb->vsb = Header_Serialize(rb->h, -1);
			AZ(VSB_finish(rb->vsb));
			printf("FIXUP to\n%s\n", VSB_data(rb->vsb));

			VSB_destroy(&rb->vsb);
			rb->vsb = Header_Serialize(rb->h, 0);
			wz = write(rb->fdo,
			    VSB_data(rb->vsb), VSB_len(rb->vsb));
			assert(wz == VSB_len(rb->vsb));
			Header_Destroy(&rb->h);
			rb->hdrlen = 0;

			rb->body_start = lseek(rb->fdo, 0, SEEK_CUR);
			memset(rb->zs, 0, sizeof rb->zs);
			i = deflateInit2(rb->zs,
			    AA_COMPRESSION,
			    Z_DEFLATED,
			    16 + 15,
			    9,
			    Z_DEFAULT_STRATEGY);
			assert(i == Z_OK);
			Gzip_AddAa(rb->zs);
			rb->zs->avail_in = rb->clen;
			rb->zs->next_in = rb->fixbuf;
			rb->rlen = 0;
			rb->state = 11;
			continue;
		}
		if (rb->state == 10) {
			oz = rb->rlen;
			if (len < oz)
				oz = len;
			rb->zs->avail_in = oz;
			rb->zs->next_in = ptr;
			len -= oz;
			ptr += oz;
			rb->rlen -= oz;
			rb->state = 11;
			// NB: No continue here, have to do 11 before return
		}
		if (rb->state == 11) {
			rb->zs->avail_out = sizeof rb->obuf;
			rb->zs->next_out = rb->obuf;
			i = deflate(rb->zs, rb->rlen > 0 ? 0 : Z_SYNC_FLUSH);
			assert(i == Z_OK);
			if (rb->rlen == 0) {
				i = deflate(rb->zs, Z_FINISH);
				assert(i == Z_STREAM_END);
			}
			oz = sizeof rb->obuf - rb->zs->avail_out;
			if (oz) {
				wz = write(rb->fdo, rb->obuf, oz);
				assert(wz == oz);
			}
			if (rb->rlen) {
				rb->state = 10;
				continue;
			}
			assert(deflateEnd(rb->zs) == Z_OK);
			ll = lseek(rb->fdo, 0, SEEK_CUR);
			(void)lseek(rb->fdo, rb->body_start, SEEK_SET);
			Gzip_WriteAa(rb->fdo, ll - rb->body_start);
			(void)lseek(rb->fdo, ll, SEEK_SET);
			wz = write(rb->fdo,
			    Gzip_crnlcrnl, sizeof Gzip_crnlcrnl);
			assert(wz == sizeof Gzip_crnlcrnl);
			rb->state = 20;
			rb->rlen = 4;
			continue;
		}
		if (rb->state == 20) {
			oz = rb->rlen;
			if (len < oz)
				oz = len;
			len -= oz;
			ptr += oz;
			rb->rlen -= oz;
			if (!rb->rlen)
				rb->state = 0;
			continue;
		}
	}
}


static int v_matchproto_(byte_iter_f)
rebuild_silo_iter(void *priv, const void *fn, ssize_t silono)
{
	struct rebuild	*rb;
	z_stream	zs[1];
	int		ps = getpagesize();
	unsigned char	ibuf[ps * 16];
	unsigned char	obuf[ps * 16];
	FILE		*fi;
	size_t		rz;
	ssize_t		oz;
	int		i;

	CAST_OBJ_NOTNULL(rb, priv, REBUILD_MAGIC);
	fprintf(stderr, "SILO NO %zd FN %s\n", silono, (const char *)fn);
	VSB_clear(rb->vsb);
	VSB_cat(rb->vsb, fn);
	VSB_cat(rb->vsb, "_");
	AZ(VSB_finish(rb->vsb));
	rb->fdo = open(VSB_data(rb->vsb), O_RDWR | O_CREAT | O_TRUNC, 0600);
	assert(rb->fdo >= 0);

	fi = fopen(fn, "rb");
	XXXAN(fi);

	memset(zs, 0, sizeof zs);
	zs->next_in = (void*)ibuf;
	i = inflateInit2(zs, 15 + 32);
	assert(i == Z_OK);

	do {
		zs->next_out = (void*)obuf;
		zs->avail_out = sizeof obuf;
		if (!zs->avail_in) {
			rz = fread(ibuf, 1, sizeof ibuf, fi);
			if (!rz)
				break;
			zs->next_in = ibuf;
			zs->avail_in = rz;
		}
		i = inflate(zs, 0);
		oz = sizeof obuf - zs->avail_out;
		obuf[oz] = '\0';
		rebuild_process(rb, obuf, oz);
		if (i == Z_STREAM_END) {
			assert(inflateEnd(zs) == Z_OK);
			i = inflateInit2(zs, 15 + 32);
			assert(i == Z_OK);
		}
	} while (i == Z_OK);

	AZ(close(rb->fdo));

	return(0);
}

static void
usage_rebuild(const char *a0, const char *a00, const char *err)
{
	usage(a0, err);
	fprintf(stderr, "Usage for this operation:\n");
	fprintf(stderr, "\t%s [global options] %s [options] [silo]...\n",
	    a0, a00);
}

int v_matchproto_(main_f)
main_rebuild(const char *a0, struct aardwarc *aa, int argc, char **argv)
{
	int ch, retval = 0;
	const char *a00 = *argv;
	struct rebuild *rb;

	CHECK_OBJ_NOTNULL(aa, AARDWARC_MAGIC);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	while ((ch = getopt(argc, argv, "h")) != -1) {
		switch (ch) {
		case 'h':
			usage_rebuild(a0, a00, NULL);
			exit(1);
		default:
			usage_rebuild(a0, a00, "Unknown option error.");
			exit(1);
		}
	}
	argc -= optind;
	argv += optind;

	ALLOC_OBJ(rb, REBUILD_MAGIC);
	AN(rb);
	rb->vsb = VSB_new_auto();
	AN(rb->vsb);
	rb->aa = aa;

	if (argc == 0)
		retval |= Silo_Iter(aa, rebuild_silo_iter, rb);
	while (argc-- > 0)
		retval |= rebuild_silo_iter(rb, *argv++, -1);

	VSB_destroy(&rb->vsb);
	FREE_OBJ(rb);
	return (retval);
}
