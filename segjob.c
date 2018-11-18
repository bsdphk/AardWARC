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

#include "vdef.h"

#include <stdlib.h>
#include <string.h>
#include <sha256.h>

#define ZLIB_CONST
#include <zlib.h>

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
	off_t			gzsize;
};

struct segjob {
	unsigned		magic;
#define SEGJOB_MAGIC		0x61a52fde

	struct aardwarc		*aa;
	struct header		*hdr;

	int			nseg;
	VTAILQ_HEAD(,segment)	segments;
	struct segment		*cur_seg;
	struct SHA256Context	sha256_payload[1];
	struct SHA256Context	sha256_segment[1];

	off_t			size;
	off_t			gzsize;
	z_stream		gz[1];
	int			gz_flag;
};

struct segjob *
SegJob_New(struct aardwarc *aa, struct header *hdr)
{
	struct segjob *sj;

	CHECK_OBJ_NOTNULL(aa, AARDWARC_MAGIC);
	AN(hdr);

	ALLOC_OBJ(sj, SEGJOB_MAGIC);
	AN(sj);

	VTAILQ_INIT(&sj->segments);
	SHA256_Init(sj->sha256_payload);
	sj->aa = aa;
	sj->hdr = hdr;

	return (sj);
}

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
		Header_Delete(&sg->hdr);
		FREE_OBJ(sg);
	}
	FREE_OBJ(sj);
}

static void
segjob_add(struct segjob *sj)
{
	struct segment *sg;
	char *dummy_digest;
	int i;

	CHECK_OBJ_NOTNULL(sj, SEGJOB_MAGIC);

	ALLOC_OBJ(sg, SEGMENT_MAGIC);
	AN(sg);

	sg->segno = ++sj->nseg;

	dummy_digest = SHA256_Data("", 0, NULL);
	AN(dummy_digest);

	if (sg->segno == 1) {
		sg->hdr = Header_Clone(sj->hdr);
	} else {
		sg->hdr = Header_Clone(sj->hdr);
		Header_Set(sg->hdr, "WARC-Type", "continuation");
		Header_Set_Ref(sg->hdr, "WARC-Segment-Origin-ID", dummy_digest);
		Header_Set(sg->hdr, "WARC-Segment-Number", "%d", sg->segno);
	}

	Header_Set(sg->hdr, "WARC-Block-Digest", "sha256:%s", dummy_digest);
	Header_Set(sg->hdr, "Content-Length-GZIP", "XXXXXXXXXXXXXXX");

	REPLACE(dummy_digest, NULL);

	sg->silo = Wsilo_New(sj->aa);
	AN(sg->silo);

	/*
	 * No matter how hard we try, there is no way to predict the headers
	 * precisely so we must reserve a padding space for the stuff we will
	 * only know at the end of segment/object.
	 */

	/* Make space for a minimal padding header */
	i = strlen("z: _\r\n");

	/* If we segment, first segment will get a number */
	if (sj->nseg == 1) {
		i += strlen("WARC-Segment-Number: 1\r\n");
		i += strlen("WARC-Payload-Digest: sha256:2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881\r\n");
	}

	/* All segments get a content length header */
	i += strlen("Content-Length: XXXXXXXXXXXXXXX\r\n");

	/* All segments get a gzip'ed content length header */

	/* In case this is last segment */
	if (sj->nseg > 1) {
		i += strlen(
		    "WARC-Segment-Total-Length: XXXXXXXXXXXXXXX\r\n");
		i += strlen(
		    "WARC-Segment-Total-Length-GZIP: XXXXXXXXXXXXXXX\r\n");
	}

	Wsilo_Header(sg->silo, sg->hdr, i);

	VTAILQ_INSERT_TAIL(&sj->segments, sg, list);

	SHA256_Init(sj->sha256_segment);

	memset(sj->gz, 0, sizeof sj->gz);
	i = deflateInit2(sj->gz,
		Z_BEST_COMPRESSION,
		Z_DEFLATED,
		16 + 15,
		9,
		Z_DEFAULT_STRATEGY);
	assert(i == Z_OK);
	sj->gz_flag = 0;

	sj->cur_seg = sg;
}

static void
segjob_finish(struct segjob *sj)
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
	Header_Set(sg->hdr, "Content-Length-GZIP", "%ju", sj->gz->total_out);
	Header_Set_Id(sg->hdr, dig);
	Wsilo_Finish(sg->silo);
	REPLACE(dig, NULL);
}

#include <stdio.h>

char *
SegJob_Commit(struct segjob *sj)
{
	char *dig, *id;
	struct segment *sg, *sgn;
	const char *rid, *typ, *ref;
	struct getjob *gj;
	struct vsb *vsb;
	struct SHA256Context sha256[1];

	CHECK_OBJ_NOTNULL(sj, SEGJOB_MAGIC);
	SegJob_Feed(sj, "", 0);
	AN(sj->size);
	dig = SHA256_End(sj->sha256_payload, NULL);
	AN(dig);

	sg = VTAILQ_FIRST(&sj->segments);
	AN(sg);
	if (sj->nseg > 1)
		Header_Set(sg->hdr, "WARC-Payload-Digest", "sha256:%s", dig);

	typ = Header_Get(sg->hdr, "WARC-Type");
	AN(typ);
	if (!strcmp(typ, "resource")) {
		/* We use the payload digest as ID */
	} else if (!strcmp(typ, "metadata")) {
		/* ID=SHA256(reference_id + "\n" + SHA256(body) + "\n") */
		SHA256_Init(sha256);
		ref = Header_Get(sg->hdr, "WARC-Refers-To");
		AN(ref);
		SHA256_Update(sha256, ref, strlen(ref));
		SHA256_Update(sha256, "\n", 1);
		SHA256_Update(sha256, dig, strlen(dig));
		SHA256_Update(sha256, "\n", 1);
		REPLACE(dig, NULL);
		dig = SHA256_End(sha256, NULL);
		AN(dig);
	} else {
		WRONG("Unknown WARC-Type");
	}

	dig[sj->aa->id_size] = '\0';

	Header_Set_Id(sg->hdr, dig);

	vsb = VSB_new_auto();
	AN(vsb);
	VSB_printf(vsb, "%s%s", sj->aa->prefix, dig);
	AZ(VSB_finish(vsb));
	id = strdup(VSB_data(vsb));
	AN(id);

	VSB_clear(vsb);
	gj = GetJob_New(sj->aa, dig, vsb);
	if (gj != NULL) {
		GetJob_Delete(&gj);
		fprintf(stderr, "ID %s already in archive\n", dig);
		REPLACE(dig, NULL);
		segjob_destroy(sj);
		return (id);
	}


	if (sj->nseg == 1) {
		Header_Set(sg->hdr, "Content-Length",
		    "%jd", (intmax_t)sg->size);

		Wsilo_Commit(&sg->silo, 0, Header_Get_Id(sg->hdr), NULL);
		REPLACE(dig, NULL);
		segjob_destroy(sj);
		return (id);
	}

	VTAILQ_FOREACH(sg, &sj->segments, list) {
		if (sg->segno == 1)
			Header_Set(sg->hdr, "WARC-Segment-Number", "1");

		if (sg->segno > 1)
			Header_Set_Ref(sg->hdr, "WARC-Segment-Origin-ID", dig);

		sgn = VTAILQ_NEXT(sg, list);
		if (sgn == NULL) {
			Header_Set(sg->hdr, "WARC-Segment-Total-Length",
			    "%jd", (intmax_t)sj->size);
			Header_Set(sg->hdr, "WARC-Segment-Total-Length-GZIP",
			    "%jd", (intmax_t)sj->gzsize);
			rid = NULL;
		} else {
			rid = Header_Get_Id(sgn->hdr);
		}

		Header_Set(sg->hdr, "Content-Length", "%jd",
		    (intmax_t)sg->size);

		Wsilo_Commit(&sg->silo, 1, Header_Get_Id(sg->hdr), rid);
	}
	REPLACE(dig, NULL);
	return (id);
}

void
SegJob_Feed(struct segjob *sj, const void *iptr, ssize_t ilen)
{
	int i;
	struct segment *sg;
	const char *ip = iptr;
	ssize_t obuf_len, len;
	void *obuf_ptr;

	CHECK_OBJ_NOTNULL(sj, SEGJOB_MAGIC);

	do {
		/* Get current segment --------------------------------*/

		if (sj->cur_seg == NULL)
			segjob_add(sj);

		sg = sj->cur_seg;
		CHECK_OBJ_NOTNULL(sg, SEGMENT_MAGIC);

		/* Get output space -----------------------------------*/

		Wsilo_GetSpace(sg->silo, &obuf_ptr, &obuf_len);
		assert(obuf_len > 0);
		sj->gz->avail_out = obuf_len;
		sj->gz->next_out = obuf_ptr;

		/* Steer gzip to fill silo almost exactly -------------*/

		if (obuf_len < 52 || ilen == 0) {
			/*
			 * Just enough space for alignment and tail
			 * 40 byte is found by trial and error
			 */
			if (sj->gz_flag != Z_FINISH) {
				AZ(sj->gz->avail_in);
				sj->gz_flag = Z_FINISH;
			}
		} else if (sj->gz_flag == 0 && sj->gz->avail_out < 128 * 1024) {
			/*
			 * From here on we flush all gzip output in order
			 * to not get surprised by a big lump later on.
			 * Experiments indicate that the required limit
			 * may be as low as 75K.
			 * We play it safe with 128K at the cost of 0.02%
			 * less efficient compression.
			 */
			sj->gz_flag = Z_PARTIAL_FLUSH;
		} else if (sj->gz->avail_in == 0) {
			/*
			 * At most we pass in half as much data as we have
			 * output space for, measured in bytes so we avoid
			 * Zeno's Paradox about Achilles and the Tortoise.
			 */
			len = sj->gz->avail_out >> 1;
			if (len < 1024)
				len -= 12;	// space for CRNLCRNL
			if (len > ilen)
				len = ilen;

			sj->gz->avail_in = len;
			sj->gz->next_in = (void*)(uintptr_t)ip;
			ilen -= len;
			ip += len;

			if (len > 0) {
				sj->size += len;
				sg->size += len;
				SHA256_Update(sj->sha256_segment,
				    sj->gz->next_in, len);
				SHA256_Update(sj->sha256_payload,
				    sj->gz->next_in, len);
			}
		}

		i = deflate(sj->gz, sj->gz_flag);
		assert(i == Z_OK ||
		    (sj->gz_flag == Z_FINISH && i == Z_STREAM_END));

		len = obuf_len - sj->gz->avail_out;
		if (len > 0) {
			sj->gzsize += len;
			sg->gzsize += len;
			AZ(Wsilo_Store(sg->silo, len));
		}

		/* Finish segment if complete -------------------------*/

		if (i == Z_STREAM_END) {
			assert(obuf_len > (ssize_t)sizeof Gzip_crnlcrnl);
			memcpy(obuf_ptr, Gzip_crnlcrnl, sizeof Gzip_crnlcrnl);
			AZ(Wsilo_Store(sg->silo, sizeof Gzip_crnlcrnl));
			segjob_finish(sj);
		}

	} while (sj->gz->avail_in > 0 || ilen > 0);
}
