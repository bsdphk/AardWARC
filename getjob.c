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
#include <stdlib.h>
#include <unistd.h>

#include "vdef.h"
#include "vas.h"
#include "vsb.h"
#include "miniobj.h"

#include "aardwarc.h"

struct getjobseg {
	unsigned		magic;
#define GETJOBSEG_MAGIC		0xedd545dd

	VTAILQ_ENTRY(getjobseg)	list;

	struct rsilo		*rs;
	struct header		*hdr;
	uint32_t		idx_flag;
	char			*idx_cont;

	unsigned		segno;
};

VTAILQ_HEAD(getjobseg_head, getjobseg);

struct getjob {
	unsigned		magic;
#define GETJOB_MAGIC		0xd0848010
	const char		*id;
	struct vsb		*vsb;
	struct aardwarc		*aa;
	const char		*err;

	struct getjobseg_head	segs;
	int			nsegs;
};

static int v_matchproto_(idx_iter_f)
getjob_iter(void *priv, const char *key,
    uint32_t flag, uint32_t silo, int64_t offset, const char *cont)
{
	struct getjob *gj;
	const char *p;
	struct getjobseg *gjs;
	struct rsilo *rs;
	struct header *hdr;
	unsigned segno = 1;
	intmax_t im;

	CAST_OBJ_NOTNULL(gj, priv, GETJOB_MAGIC);
	(void)key;

	rs = Rsilo_Open(gj->aa, NULL, silo, offset);
	AN(rs);
	hdr = Rsilo_ReadHeader(rs);
	AN(hdr);

	p = Header_Get_Id(hdr);
	if ((flag & IDX_F_WARCINFO) && !strcasecmp(p, gj->id)) {
		gj->err = "ID is warcinfo segment";
		Header_Destroy(&hdr);
		Rsilo_Close(&rs);
		return (-1);
	}
	gjs = VTAILQ_LAST(&gj->segs, getjobseg_head);
	if (gjs == NULL) {
		if (strcasecmp(p, gj->id)) {
			Header_Destroy(&hdr);
			Rsilo_Close(&rs);
			return (0);
		}
		if ((flag & IDX_F_SEGMENTED) && !(flag & IDX_F_FIRSTSEG)) {
			gj->err = "ID is continuation segment";
			Header_Destroy(&hdr);
			Rsilo_Close(&rs);
			return (-1);
		}
	} else {
		p = Header_Get(hdr, "WARC-Segment-Origin-ID");
		AN(p);
		assert(p[0] == '<');
		p++;
		assert(!memcmp(p, gj->aa->prefix, strlen(gj->aa->prefix)));
		p += strlen(gj->aa->prefix);
		assert(p[gj->aa->id_size] == '>');
		assert(p[gj->aa->id_size + 1L] == '\0');
		if (strncasecmp(p, gj->id, gj->aa->id_size)) {
			/*
			 * The next field in the index can be ambiguous
			 * but we just ignore the other ones.
			 */
			Header_Destroy(&hdr);
			Rsilo_Close(&rs);
			return (0);
		}
		im = Header_Get_Number(hdr, "WARC-Segment-Number");
		assert(im >= 0);
		segno = im;
		if (segno != gjs->segno + 1) {
			gj->err =
			    "Index Inconsistency: "
			    "Continuation out of order.";
			Header_Destroy(&hdr);
			Rsilo_Close(&rs);
			return (-1);
		}
	}

	ALLOC_OBJ(gjs, GETJOBSEG_MAGIC);
	AN(gjs);

	gjs->rs = rs;
	gjs->hdr = hdr;
	gjs->idx_flag = flag;
	gjs->idx_cont = strdup(cont);
	gjs->segno = segno;
	AN(gjs->idx_cont);
	VTAILQ_INSERT_TAIL(&gj->segs, gjs, list);
	gj->nsegs++;
	return(1);
}

void
GetJob_Delete(struct getjob **pp)
{
	struct getjob *gj;
	struct getjobseg *gjs;

	AN(pp);
	CAST_OBJ_NOTNULL(gj, *pp, GETJOB_MAGIC);
	*pp = NULL;

	while (1) {
		gjs = VTAILQ_FIRST(&gj->segs);
		if (gjs == NULL)
			break;
		VTAILQ_REMOVE(&gj->segs, gjs, list);
		if (gjs->hdr)
			Header_Destroy(&gjs->hdr);
		if (gjs->rs)
			Rsilo_Close(&gjs->rs);
		REPLACE(gjs->idx_cont, NULL);
		FREE_OBJ(gjs);
	}
	FREE_OBJ(gj);
}

struct getjob *
GetJob_New(struct aardwarc *aa, const char *id, struct vsb *vsb)
{
	int i;
	struct getjob *gj;
	struct getjobseg *gjs;
	const char *nid, *e;

	e = IDX_Valid_Id(aa, id, &nid);
	if (e != NULL) {
		VSB_printf(vsb, "%s", e);
		return (NULL);
	}

	ALLOC_OBJ(gj, GETJOB_MAGIC);
	AN(gj);
	VTAILQ_INIT(&gj->segs);
	gj->aa = aa;
	gj->id = nid;
	gj->vsb = vsb;
	gj->err = "ID not found";

	while (1) {
		i = IDX_Iter(aa, nid, getjob_iter, gj);
		if (i <= 0) {
			AN (gj->err);
			VSB_printf(vsb, "%s", gj->err);
			GetJob_Delete(&gj);
			return (NULL);
		}
		gjs = VTAILQ_LAST(&gj->segs, getjobseg_head);
		CHECK_OBJ_NOTNULL(gjs, GETJOBSEG_MAGIC);

		AZ(gjs->idx_flag & IDX_F_WARCINFO);

		if (!(gjs->idx_flag & IDX_F_SEGMENTED)) {
			AZ(gjs->idx_flag & IDX_F_FIRSTSEG);
			AZ(gjs->idx_flag & IDX_F_LASTSEG);
			AZ(strcmp(gjs->idx_cont, "00000000"));
			assert(VTAILQ_FIRST(&gj->segs) == gjs);
			break;
		}
		if (gjs->idx_flag & IDX_F_LASTSEG)
			break;
		nid = gjs->idx_cont;
	}
	return (gj);
}

const struct header *
GetJob_Header(const struct getjob *gj, int first)
{
	struct getjobseg *gjs;

	CHECK_OBJ_NOTNULL(gj, GETJOB_MAGIC);
	if (first)
		gjs = VTAILQ_FIRST(&gj->segs);
	else
		gjs = VTAILQ_LAST(&gj->segs, getjobseg_head);
	CHECK_OBJ_NOTNULL(gjs, GETJOBSEG_MAGIC);
	return (gjs->hdr);
}

void
GetJob_Iter(const struct getjob *gj, byte_iter_f *func, void *priv, int gzip)
{
	struct getjobseg *gjs;
	struct gzip_stitch *gs;

	CHECK_OBJ_NOTNULL(gj, GETJOB_MAGIC);
	AN(func);
	if (!gzip) {
		VTAILQ_FOREACH(gjs, &gj->segs, list)
			if (Rsilo_ReadChunk(gjs->rs, func, priv) == 0)
				break;
	} else if (gj->nsegs == 1) {
		gjs = VTAILQ_FIRST(&gj->segs);
		(void)Rsilo_ReadGZChunk(gjs->rs, func, priv);
	} else {
		gs = gzip_stitch_new(func, priv);
		VTAILQ_FOREACH(gjs, &gj->segs, list)
			if (Rsilo_ReadGZChunk(gjs->rs, gzip_stitch_feed, gs) == 0)
				break;
		(void)gzip_stitch_fini(gs);
	}
}

off_t
GetJob_TotalLength(const struct getjob *gj, int gzip)
{
	struct getjobseg *gjs;
	off_t sum = 0;
	intmax_t im;

	CHECK_OBJ_NOTNULL(gj, GETJOB_MAGIC);

	// XXX: ... also available in headers in last segment.
	VTAILQ_FOREACH(gjs, &gj->segs, list) {
		if (gzip)
			im = Rsilo_BodyLen(gjs->rs);
		else
			im = Header_Get_Number(gjs->hdr, "Content-Length");
		assert(im > 0);
		sum += im;
	}
	return (sum);
}

int
GetJob_IsSegmented(const struct getjob *gj)
{
	struct getjobseg *gjs;

	CHECK_OBJ_NOTNULL(gj, GETJOB_MAGIC);

	gjs = VTAILQ_FIRST(&gj->segs);
	if (VTAILQ_NEXT(gjs, list) == NULL)
		return (0);
	return (1);
}

struct vsb *
GetJob_Headers(const struct getjob *gj)
{
	struct getjobseg *gjs, *gjl;
	struct header *hdr;
	struct vsb *vsb;
	const char *p;

	CHECK_OBJ_NOTNULL(gj, GETJOB_MAGIC);

	gjs = VTAILQ_FIRST(&gj->segs);
	AN(gjs);
	gjl = VTAILQ_LAST(&gj->segs, getjobseg_head);
	AN(gjl);

	if (gjs == gjl) {
		vsb = Header_Serialize(gjs->hdr, -1);
	} else {
		// Move headers around to make segmentation less painful

		hdr = Header_Clone(gjs->hdr);
		AN(hdr);

		p = Header_Get(gjl->hdr, "WARC-Segment-Total-Length");
		AN(p);
		Header_Set(hdr, "Content-Length", "%s", p);

		p = Header_Get(gjs->hdr, "WARC-Payload-Digest");
		AN(p);
		Header_Set(hdr, "WARC-Block-Digest", "%s", p);

		vsb = Header_Serialize(hdr, -1);
		Header_Destroy(&hdr);
	}
	return (vsb);
}
