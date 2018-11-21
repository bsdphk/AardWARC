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
 * TODO:
 *	Check filename in warcinfo
 *	Check if silo has correct filename based on silono (reindex2)
 *	Don't explode on corrupt silos. (reindex2)
 *	Handle duplicates (reindex2)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "vdef.h"

#include "vas.h"
#include "miniobj.h"

#include "aardwarc.h"

struct seg {
	unsigned		magic;
#define SEG_MAGIC		0x0753a4c0
	char			*id;
	uint32_t		flg;
	char			*parent;
	ssize_t			silono;
	off_t			off, segno;
	VTAILQ_ENTRY(seg)	list;
	int			used;
	int			done;
};

static VTAILQ_HEAD(seghead,seg)	segs = VTAILQ_HEAD_INITIALIZER(segs);
static unsigned			nsegs = 0;

static void
dump(const struct aardwarc *aa, const char *pfx, struct seg *seg)
{
	printf("%s%p %.*s %d%d %zd %s %jd %jd\n",
	    pfx, seg, (int)aa->id_size, seg->parent, seg->used, seg->done,
	    seg->silono, seg->id, seg->off, seg->segno);
}

static void
dump_left(const struct aardwarc *aa)
{
	struct seg *seg;

	printf("NSEGS %u\n", nsegs);
	VTAILQ_FOREACH(seg, &segs, list)
		dump(aa, "", seg);
}

static void
drop_seg(struct seg *seg)
{

	VTAILQ_REMOVE(&segs, seg, list);
	AN(seg->done);
	REPLACE(seg->id, NULL);
	REPLACE(seg->parent, NULL);
	FREE_OBJ(seg);
	nsegs--;
}

static void
emit_seg(const struct aardwarc *aa, struct seg *seg, struct seg *seg2)
{

	CHECK_OBJ_NOTNULL(aa, AARDWARC_MAGIC);
	CHECK_OBJ_NOTNULL(seg, SEG_MAGIC);
	CHECK_OBJ_NOTNULL(seg2, SEG_MAGIC);
	IDX_Insert(aa, seg->id, seg->flg, seg->silono, seg->off, seg2->id);
	AZ(seg->done);
	AZ(seg2->used);
	seg->done++;
	seg2->used++;
	if (seg->used && seg->done)
		drop_seg(seg);
	if (seg2->used && seg2->done)
		drop_seg(seg2);
}

static void
try_seg(const struct aardwarc *aa, struct seg *seg)
{
	struct seg *seg2;

	seg2 = VTAILQ_NEXT(seg, list);
	if (seg2 != NULL && !seg2->done && seg2->segno + 1 == seg->segno &&
	    !strncmp(seg2->parent, seg->parent, aa->id_size))
		emit_seg(aa, seg2, seg);
}

static int __match_proto__(idx_iter_f)
reindex_iter(void *priv, const char *key,
    uint32_t flag, uint32_t silo, uint64_t offset, const char *cont)
{
	struct seg *seg, *seg2;

	(void)silo;
	(void)offset;
	if (!(flag & IDX_F_SEGMENTED))
		return(0);
	VTAILQ_FOREACH_SAFE(seg, &segs, list, seg2) {
		if (!strncmp(key, seg->id, 16)) {
			IDX_Insert(priv, seg->id, seg->flg, seg->silono,
			    seg->off, cont);
			seg->done++;
			drop_seg(seg);
		}
	}
	return (0);
}

static void
got_seg(const struct aardwarc *aa, const struct header *hdr,
   uint32_t flg, off_t off, off_t segno, ssize_t silono)
{
	const char *id;
	const char *parent;
	const char *tl;
	struct seg *seg, *seg2;

	CHECK_OBJ_NOTNULL(aa, AARDWARC_MAGIC);
	AN(hdr);
	id = Header_Get_Id(hdr);
	flg |= IDX_F_SEGMENTED;
	if (segno > 1) {
		parent = Header_Get(hdr, "WARC-Segment-Origin-ID");
		AN(parent);
		parent = strrchr(parent, '/');
		AN(parent);
		parent++;
	} else {
		flg |= IDX_F_FIRSTSEG;
		parent = id;
	}
	tl = Header_Get(hdr, "WARC-Segment-Total-Length");
	if (tl != NULL)
		flg |= IDX_F_LASTSEG;

	ALLOC_OBJ(seg, SEG_MAGIC);
	AN(seg);
	nsegs++;
	REPLACE(seg->id, id);
	REPLACE(seg->parent, parent);
	seg->flg = flg;
	seg->off = off;
	seg->segno = segno;
	seg->silono = silono;

	if (segno == 1)
		seg->used = 1;
	if (tl != NULL) {
		IDX_Insert(aa, seg->id, seg->flg, seg->silono, seg->off, NULL);
		seg->done = 1;
	}

	VTAILQ_FOREACH(seg2, &segs, list) {
		if (strncmp(seg2->parent, seg->parent, aa->id_size) < 0)
			continue;
		if (strncmp(seg2->parent, seg->parent, aa->id_size) > 0)
			break;
		if (seg2->segno < seg->segno)
			break;
	}
	if (seg2 != NULL)
		VTAILQ_INSERT_BEFORE(seg2, seg, list);
	else
		VTAILQ_INSERT_TAIL(&segs, seg, list);

	seg2 = VTAILQ_PREV(seg, seghead, list);
	try_seg(aa, seg);
	if (seg2 != NULL)
		try_seg(aa, seg2);
}

static int __match_proto__(byte_iter_f)
silo_iter(void *priv, const void *fn, ssize_t silono)
{
	struct aardwarc *aa;
	struct rsilo *rs;
	struct header *hdr;
	off_t off, o2, gzlen, segno;
	intmax_t im;
	uint32_t flg;
	const char *p, *wt;

	CAST_OBJ_NOTNULL(aa, priv, AARDWARC_MAGIC);

	rs = Rsilo_Open(aa, fn, silono);
	if (rs == NULL)
		return (-1);

	if (silono < 0) {
		p = strrchr(fn, '/');
		AN(p);
		p++;
		silono = (ssize_t)strtoul(p, NULL, 10);
	}

	while (1) {
		off = Rsilo_Tell(rs);
		hdr = Rsilo_ReadHeader(rs);
		o2 = Rsilo_Tell(rs);
		if (hdr == NULL)
			break;

		im = Header_Get_Number(hdr, "Content-Length-GZIP");
		assert(im > 0);
		gzlen = (off_t)im;
		assert(im == (intmax_t)gzlen);

		flg = 0;
		wt = Header_Get(hdr, "WARC-Type");
		AN(wt);
		if (!strcmp(wt, "warcinfo"))
			flg = IDX_F_WARCINFO;
		else if (!strcmp(wt, "metadata"))
			flg = IDX_F_METADATA;
		else if (!strcmp(wt, "resource"))
			flg = IDX_F_RESOURCE;

		im = Header_Get_Number(hdr, "WARC-Segment-Number");
		if (im < 0) {
			segno = 0;
			IDX_Insert(aa, Header_Get_Id(hdr), flg, silono, off, NULL);
		} else {
			segno = (off_t)im;
			got_seg(aa, hdr, flg, off, segno, silono);
		}

		Header_Delete(&hdr);
		Rsilo_Seek(rs, o2 + gzlen + 24L);
	}
	Rsilo_Close(&rs);
	IDX_Resort(aa);
	return (0);
}

static void
usage_reindex(const char *a0, const char *a00, const char *err)
{
	usage(a0, err);
	fprintf(stderr, "Usage for this operation:\n");
	fprintf(stderr, "\t%s [global options] %s [options] [silo]...\n",
	    a0, a00);
	//fprintf(stderr, "Options:\n");
	//fprintf(stderr, "\t-m mime_type\n");
	//fprintf(stderr, "\t-t {metadata|resource}\n");
}

int __match_proto__(main_f)
main_reindex(const char *a0, struct aardwarc *aa, int argc, char **argv)
{
	int ch, retval = 0;
	const char *a00 = *argv;

	CHECK_OBJ_NOTNULL(aa, AARDWARC_MAGIC);

	while ((ch = getopt(argc, argv, "h")) != -1) {
		switch (ch) {
		case 'h':
			usage_reindex(a0, a00, NULL);
			exit(1);
		default:
			usage_reindex(a0, a00, "Unknown option error.");
			exit(1);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc == 0)
		retval |= Silo_Iter(aa, silo_iter, aa);
	while (argc-- > 0)
		retval |= silo_iter(aa, *argv++, -1);
	if (nsegs > 0) {
		printf("Rematch (%u)\n", nsegs);
		(void)IDX_Iter(aa, NULL, reindex_iter, aa);
	}
	if (nsegs > 0) {
		printf("Leftovers\n");
		dump_left(aa);
	}
	return (retval);
}
