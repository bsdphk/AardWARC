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
#include <stdio.h>
#include <string.h>
#include <sha256.h>

#define ZLIB_CONST
#include <zlib.h>

#include "vdef.h"

#include "vas.h"
#include "vsb.h"
#include "miniobj.h"

#include "aardwarc.h"

/*
 * A segment of an object
 */

struct segment {
	unsigned		magic;
#define SEGMENT_MAGIC		0x28a64188
	VTAILQ_ENTRY(segment)	list;

	int			segno;
	struct header		*hdr;
	struct wsilo		*silo;
	off_t			size;
};

struct segjob {
	unsigned		magic;
#define SEGJOB_MAGIC		0x61a52fde

	struct aardwarc		*aa;
	const struct header	*hdr;
	const char		*ident;

	int			nseg;
	VTAILQ_HEAD(,segment)	segments;
	struct segment		*cur_seg;
	struct SHA256Context	sha256_payload[1];
	struct SHA256Context	sha256_segment[1];

	off_t			size;
	size_t			obuflen;
	z_stream		gz[1];
	int			gz_flag;
};

static void
segjob_destroy(struct segjob *sj)
{
	struct segment *sg;

	CHECK_OBJ_NOTNULL(sj, SEGJOB_MAGIC);
	while (!VTAILQ_EMPTY(&sj->segments)) {
		sg = VTAILQ_FIRST(&sj->segments);
		VTAILQ_REMOVE(&sj->segments, sg, list);
		if (sg->silo != NULL)
			Wsilo_Abandon(&sg->silo);
		Header_Destroy(&sg->hdr);
		FREE_OBJ(sg);
	}
	FREE_OBJ(sj);
}

static void
segjob_newseg(struct segjob *sj)
{
	struct segment *sg;
	char *digest;
	int pad = 0;
	intmax_t im;

	CHECK_OBJ_NOTNULL(sj, SEGJOB_MAGIC);
	AZ(sj->cur_seg);

	ALLOC_OBJ(sg, SEGMENT_MAGIC);
	AN(sg);

	sg->segno = ++sj->nseg;

	digest = SHA256_Data("", 0, NULL);
	AN(digest);

	sg->hdr = Header_Clone(sj->hdr);

	/*
	 * No matter how hard we try, there is no way to predict the headers
	 * precisely so we must reserve a padding space for the stuff we will
	 * only find out later as the size increases.
	 */

	Header_Set(sg->hdr, "WARC-Block-Digest", "sha256:%s", digest);

	/*
	 * We reserve two extra digits to allow up to 99% compression.
	 * This also covers the case where data is already gzip'ed and
	 * the C-L-G is longer than the C-L
	 */
	im = sj->aa->silo_maxsize;
	Header_Set(sg->hdr, "Content-Length", "00%jd", im);

	if (sg->segno == 1) {
		pad += Header_Len("WARC-Segment-Number", "1");
		pad += Header_Len("WARC-Payload-Digest", "sha256:%s", digest);
	} else {
		Header_Set(sg->hdr, "WARC-Segment-Number", "%d", sg->segno);
		Header_Set(sg->hdr, "WARC-Type", "continuation");
		Header_Set_Ref(sg->hdr, "WARC-Segment-Origin-ID", digest);

		/* In case this becomes the last segment */
		im = sj->size + sj->aa->silo_maxsize;
		pad += Header_Len("WARC-Segment-Total-Length", "%00jd", im);
	}

	REPLACE(digest, NULL);

	sg->silo = Wsilo_New(sj->aa);
	AN(sg->silo);
	Wsilo_Header(sg->silo, sg->hdr, pad);

	VTAILQ_INSERT_TAIL(&sj->segments, sg, list);

	SHA256_Init(sj->sha256_segment);
	Gzip_InitDeflate(sj->gz);
	sj->gz_flag = 0;
	Gzip_AddAa(sj->gz);
	sj->cur_seg = sg;
}

static void
segjob_finishseg(struct segjob *sj)
{
	char *dig;
	struct segment *sg;

	CHECK_OBJ_NOTNULL(sj, SEGJOB_MAGIC);

	sg = sj->cur_seg;
	sj->cur_seg = NULL;
	CHECK_OBJ_NOTNULL(sg, SEGMENT_MAGIC);

	assert(deflateEnd(sj->gz) == Z_OK);
	dig = SHA256_End(sj->sha256_segment, NULL);
	AN(dig);
	Header_Set(sg->hdr, "WARC-Block-Digest", "sha256:%s", dig);
	Header_Set(sg->hdr, "Content-Length", "%jd", (intmax_t)sg->size);
	Ident_Set(sj->aa, sg->hdr, dig, sg->segno == 1 ? sj->ident : NULL);
	Wsilo_Finish(sg->silo);
	REPLACE(dig, NULL);
}

struct segjob *
SegJob_New(struct aardwarc *aa, const struct header *hdr, const char *ident)
{
	struct segjob *sj;

	CHECK_OBJ_NOTNULL(aa, AARDWARC_MAGIC);
	AN(hdr);
	AN(Header_Get(hdr, "Content-Type"));
	AN(Header_Get(hdr, "WARC-Type"));
	AN(Header_Get(hdr, "WARC-Date"));
	AZ(Header_Get(hdr, "WARC-Segment-Number"));
	AZ(Header_Get(hdr, "WARC-Payload-Digest"));
	AZ(Header_Get(hdr, "WARC-Segment-Origin-ID"));
	AZ(Header_Get(hdr, "WARC-Segment-Total-Length"));
	assert(ident == NULL || IDX_Valid_Id(aa, ident, NULL) == NULL);

	ALLOC_OBJ(sj, SEGJOB_MAGIC);
	AN(sj);

	VTAILQ_INIT(&sj->segments);
	SHA256_Init(sj->sha256_payload);
	sj->aa = aa;
	sj->hdr = hdr;
	sj->ident = ident;

	return (sj);
}

static void
segjob_setup_outbuf(struct segjob *sj, const struct segment *sg)
{
	void *obuf_ptr;

	Wsilo_GetSpace(sg->silo, &obuf_ptr, &sj->obuflen);
	assert(sj->obuflen > 0);
	sj->obuflen -= sizeof Gzip_crnlcrnl;
	sj->gz->avail_out = sj->obuflen;
	sj->gz->next_out = obuf_ptr;
}

static void
segjob_deflate(struct segjob *sj, const struct segment *sg)
{
	int i;
	ssize_t len;

	i = deflate(sj->gz, sj->gz_flag);
	len = sj->obuflen - sj->gz->avail_out;
	assert(i == Z_OK || (sj->gz_flag == Z_FINISH && i == Z_STREAM_END));

	len = sj->obuflen - sj->gz->avail_out;
	if (len > 0)
		AZ(Wsilo_Store(sg->silo, len));
}

void
SegJob_Feed(struct segjob *sj, const void *iptr, ssize_t ilen)
{
	struct segment *sg;
	const char *ip = iptr;
	ssize_t len;
	void *ptr;

	CHECK_OBJ_NOTNULL(sj, SEGJOB_MAGIC);

	do {
		/* Get current segment --------------------------------*/

		if (sj->cur_seg == NULL)
			segjob_newseg(sj);

		sg = sj->cur_seg;
		CHECK_OBJ_NOTNULL(sg, SEGMENT_MAGIC);

		segjob_setup_outbuf(sj, sg);

		/* Steer gzip to fill silo almost exactly -------------*/

		if (sj->obuflen < 52 || ilen == 0) {
			/* 40 is found by experiment, 52 for safety */

			AZ(sj->gz->avail_in);

			/* Flush to byte-boundary, so we can do CRC-tricks */
			sj->gz_flag = Z_SYNC_FLUSH;
			segjob_deflate(sj, sg);

			sj->gz_flag = Z_FINISH;
			segjob_setup_outbuf(sj, sg);
			segjob_deflate(sj, sg);

			Wsilo_GetSpace(sg->silo, &ptr, &sj->obuflen);
			assert(sj->obuflen > (ssize_t)sizeof Gzip_crnlcrnl);
			memcpy(ptr, Gzip_crnlcrnl, sizeof Gzip_crnlcrnl);
			AZ(Wsilo_Store(sg->silo, sizeof Gzip_crnlcrnl));

			segjob_finishseg(sj);
			continue;
		}

		if (sj->gz->avail_in == 0) {
			/*
			 * At most we pass in half as much data as we have
			 * output space for, measured in bytes so we avoid
			 * Zeno's Paradox about Achilles and the Tortoise.
			 */
			len = sj->gz->avail_out >> 1;
			if (len > ilen)
				len = ilen;
			assert(len > 0);

			sj->gz->avail_in = len;
			sj->gz->next_in = (void*)(uintptr_t)ip;

			sj->size += len;
			sg->size += len;
			SHA256_Update(sj->sha256_segment, ip, len);
			SHA256_Update(sj->sha256_payload, ip, len);

			ilen -= len;
			ip += len;
		}

		if (sj->gz->avail_out < 128 * 1024) {
			/*
			 * From here on we flush all gzip output in order
			 * to not get surprised by a big lump later on.
			 * Experiments indicate that the required limit
			 * may be as low as 75K.
			 * We play it safe with 128K at the cost of 0.02%
			 * less efficient compression.
			 */
			sj->gz_flag = Z_PARTIAL_FLUSH;
		}

		segjob_deflate(sj, sg);

	} while (sj->gz->avail_in > 0 || ilen > 0);
}

char *
SegJob_Commit(struct segjob *sj)
{
	char *id;
	struct segment *sg, *sgn;
	const char *fid, *rid;
	struct getjob *gj;
	struct vsb *vsb;

	CHECK_OBJ_NOTNULL(sj, SEGJOB_MAGIC);
	SegJob_Feed(sj, "", 0);
	AN(sj->size);

	sg = VTAILQ_FIRST(&sj->segments);
	AN(sg);

	if (sj->nseg > 1) {
		/* Update ID of first segment */
		id = SHA256_End(sj->sha256_payload, NULL);
		AN(id);
		Header_Set(sg->hdr, "WARC-Payload-Digest", "sha256:%s", id);
		Ident_Set(sj->aa, sg->hdr, id, sj->ident);
		REPLACE(id, NULL);
	}

	fid = Header_Get_Id(sg->hdr);
	id = Digest2Ident(sj->aa, fid);

	vsb = VSB_new_auto();
	AN(vsb);
	gj = GetJob_New(sj->aa, fid, vsb);
	if (gj != NULL) {
		GetJob_Delete(&gj);
		fprintf(stderr, "ID %s already in archive\n", fid);
		segjob_destroy(sj);
		return (id);
	}

	if (sj->nseg == 1) {
		Wsilo_Commit(&sg->silo, 0, fid, NULL);
		segjob_destroy(sj);
		return (id);
	}

	VTAILQ_FOREACH(sg, &sj->segments, list) {
		if (sg->segno == 1)
			Header_Set(sg->hdr, "WARC-Segment-Number", "1");
		else
			Header_Set_Ref(sg->hdr, "WARC-Segment-Origin-ID", fid);

		sgn = VTAILQ_NEXT(sg, list);
		if (sgn == NULL) {
			Header_Set(sg->hdr, "WARC-Segment-Total-Length",
			    "%jd", (intmax_t)sj->size);
			rid = NULL;
		} else {
			rid = Header_Get_Id(sgn->hdr);
		}

		Wsilo_Commit(&sg->silo, 1, Header_Get_Id(sg->hdr), rid);
	}
	return (id);
}
