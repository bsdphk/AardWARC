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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "vdef.h"

#include "vas.h"
#include "vsb.h"
#include "miniobj.h"
#include "sha256.h"
#include "vqueue.h"

#include "aardwarc.h"

struct audit {
	unsigned		magic;
#define AUDIT_MAGIC		0xce2bb3e2
	off_t			o1;
	off_t			o2;
	ssize_t			sz;
	ssize_t			gzsz;
	struct header		*hdr;
	struct SHA256Context	sha256[1];

	/* Only used for segmented records */
	const char		*silo_fn;
	int			silo_no;
	int			segment;
	VTAILQ_ENTRY(audit)	list;
};

static VTAILQ_HEAD(,audit) segment_list =
    VTAILQ_HEAD_INITIALIZER(segment_list);

static void
audit_check_header(struct vsb *err, const struct audit *ap,
    const char *hdn, const char *expect)
{
	const char *is;

	is = Header_Get(ap->hdr, hdn);
	if (is == NULL) {
		VSB_printf(err, "ERROR: %s missing\n", hdn);
	} else if (strcmp(expect, is)) {
		VSB_printf(err, "ERROR: %s difference\n", hdn);
		VSB_printf(err, "\tis:\t\t%s\n", is);
		VSB_printf(err, "\tshould be:\t%s\n", expect);
	}
}

static void
audit_check_digest_header(struct vsb *err, const struct audit *ap,
    const char *hdn, const char *expect)
{
	const char *is;

	is = Header_Get(ap->hdr, hdn);
	if (is == NULL) {
		VSB_printf(err, "ERROR: %s missing\n", hdn);
	} else if (memcmp(is, "sha256:", 7)) {
		VSB_printf(err, "ERROR: %s is not sha256\n", hdn);
	} else if (strcmp(is + 7, expect)) {
		VSB_printf(err, "ERROR: %s difference\n", hdn);
		VSB_printf(err, "\tis:\t\t%s\n", is);
		VSB_printf(err, "\tshould be:\t%s\n", expect);
	}
}

static int v_matchproto_(byte_iter_f)
audit_iter(void *priv, const void *ptr, ssize_t len)
{
	struct audit *ap;

	CAST_OBJ_NOTNULL(ap, priv, AUDIT_MAGIC);
	SHA256_Update(ap->sha256, ptr, len);
	ap->sz += len;
	return (0);
}

static void
audit_report(FILE *fo, struct audit *ap)
{
	struct vsb *vsb;
	const char *p;

	if (fo == NULL)
		fo = stdout;
	CHECK_OBJ_NOTNULL(ap, AUDIT_MAGIC);

	vsb = Header_Serialize(ap->hdr, -1);
	AZ(VSB_finish(vsb));
	fprintf(fo, "\n\t[%jd...%jd]\n", ap->o1, ap->o2);
	fprintf(fo, "\n\t| ");
	for (p = VSB_data(vsb); *p != '\0'; p++) {
		if (*p == '\n')
			fprintf(fo, "\n\t| ");
		else if (*p != '\r')
			(void)fputc(*p, fo);
	}
	fprintf(fo, "\n\n");
	VSB_destroy(&vsb);
}

static void
audit_add_one_segment(struct aardwarc *aa, struct audit *ap0, struct audit *ap)
{
	struct rsilo *rs;
	off_t o2;

	ap0->gzsz += ap->o2 - ap->o1;

	rs = Rsilo_Open(aa, ap->silo_fn, ap->silo_no);
	AN(rs);
	Rsilo_Seek(rs, ap->o1);
	(void)Rsilo_ReadChunk(rs, audit_iter, ap0);
	o2 = Rsilo_Tell(rs);
	assert(o2 == ap->o2);
	Rsilo_Close(&rs);
}

static void
audit_final_pending(struct aardwarc *aa, struct vsb *err, struct audit *ap0,
    struct audit *apn)
{
	char buf[64];
	char dig[SHA256_DIGEST_STRING_LENGTH];
	char id[SHA256_DIGEST_STRING_LENGTH];

	(void)aa;

	bprintf(buf, "%jd", ap0->gzsz);
	audit_check_header(err, apn, "WARC-Segment-Total-Length-GZIP", buf);

	bprintf(buf, "%jd", ap0->sz);
	audit_check_header(err, apn, "WARC-Segment-Total-Length", buf);

	(void)SHA256_End(ap0->sha256, dig);
	audit_check_digest_header(err, ap0, "WARC-Payload-Digest", dig);

	Ident_Create(aa, ap0->hdr, dig, id);
	if (strcmp(id, Header_Get_Id(ap0->hdr))) {
		VSB_printf(err, "ERROR: %s difference\n", "WARC-Record-ID");
		VSB_printf(err, "\tis:\t\t%s\n", Header_Get_Id(ap0->hdr));
		VSB_printf(err, "\tshould be:\t%s\n", id);
	}
}

static int
audit_one_pending(struct aardwarc *aa, struct vsb *err)
{
	struct audit *ap0, *ap1, *ap, *apn, *aps;
	const char *origin, *oid, *p;

	CHECK_OBJ_NOTNULL(aa, AARDWARC_MAGIC);
	VTAILQ_FOREACH(ap0, &segment_list, list) {
		CHECK_OBJ_NOTNULL(ap0, AUDIT_MAGIC);
		if (ap0->segment == 1)
			break;
	}
	if (ap0 == NULL)
		return (0);
	VTAILQ_REMOVE(&segment_list, ap0, list);
	printf("Auditing this segmented object: %s\n", Header_Get_Id(ap0->hdr));
	SHA256_Init(ap0->sha256);
	ap0->sz = 0;
	ap0->gzsz = 0;
	audit_add_one_segment(aa, ap0, ap0);

	oid = Header_Get_Id(ap0->hdr);
	ap = ap0;
	do {
		ap1 = ap;
		VTAILQ_FOREACH_SAFE(apn, &segment_list, list, aps) {
			CHECK_OBJ_NOTNULL(apn, AUDIT_MAGIC);
			if (apn->segment != ap->segment + 1)
				continue;
			origin = Header_Get(apn->hdr, "WARC-Segment-Origin-ID");
			if (origin == NULL)
				continue;
			if (*origin++ != '<')
				continue;
			if (memcmp(aa->prefix, origin, strlen(aa->prefix)))
				continue;
			origin += strlen(aa->prefix);
			if (strncmp(origin, oid, strlen(oid)))
				continue;
			origin += strlen(oid);
			if (*origin++ != '>')
				continue;
			audit_add_one_segment(aa, ap0, apn);
			VTAILQ_REMOVE(&segment_list, apn, list);
			p = Header_Get(apn->hdr, "WARC-Segment-Total-Length");
			if (p != NULL) {
				VSB_clear(err);
				audit_final_pending(aa, err, ap0, apn);
				AZ(VSB_finish(err));
				if (VSB_len(err)) {
					printf("%s", VSB_data(err));
					audit_report(NULL, ap);
					return (-1);
				} else {
					return (1);
				}
			}
			ap = apn;
		}
	} while (ap == ap1);

	printf("ERROR: Failed to find segment %d\n", ap->segment + 1);
	return (0);
}

static int
audit_one(struct aardwarc *aa, struct vsb *err, struct audit *ap)
{
	char *oldid, *p;
	char newid[SHA256_DIGEST_STRING_LENGTH];
	char dig[SHA256_DIGEST_STRING_LENGTH];
	char buf[64];
	const char *is;
	int retval = 0;

	CHECK_OBJ_NOTNULL(ap, AUDIT_MAGIC);

	(void)SHA256_End(ap->sha256, dig);
	audit_check_digest_header(err, ap, "WARC-Block-Digest", dig);

	bprintf(buf, "%jd", (intmax_t)ap->sz);
	audit_check_header(err, ap, "Content-Length", buf);

	bprintf(buf, "%jd", (intmax_t)(ap->o2 - ap->o1));
	audit_check_header(err, ap, "Content-Length-GZIP", buf);

	is = Header_Get(ap->hdr, "WARC-Segment-Number");
	if (is != NULL) {
		retval = 1;
		VTAILQ_INSERT_TAIL(&segment_list, ap, list);
		p = NULL;
		ap->segment = strtoul(is, &p, 0);
		if (p == is || (p != NULL && *p != '\0'))
			VSB_printf(err, "ERROR: Bad WARC-Segment-Number\n");
	}

	if (is == NULL || strcmp(is, "1")) {
		oldid = strdup(Header_Get_Id(ap->hdr));
		AN(oldid);

		Ident_Create(aa, ap->hdr, dig, newid);

		if (strcmp(oldid, newid)) {
			VSB_printf(err, "ERROR: WARC-Record-ID difference\n");
			VSB_printf(err, "\tis:\t\t%s\n", oldid);
			VSB_printf(err, "\tshould be:\t%s\n", newid);
		}
		free(oldid);
	}

	return (retval);
}

static int
audit_silo(struct aardwarc *aa, const char *fn, int nsilo)
{
	struct rsilo *rs;
	struct audit *ap;
	struct vsb *vsberr;
	int ngood = 0;
	int tgood = 0;
	int tbad = 0;
	int r;

	CHECK_OBJ_NOTNULL(aa, AARDWARC_MAGIC);

	rs = Rsilo_Open(aa, fn, nsilo);
	if (rs == NULL)
		return (-1);
	printf("Audit silo %s #%d\n", fn, nsilo);

	vsberr = VSB_new_auto();
	AN(vsberr);

	while (1) {
		ALLOC_OBJ(ap, AUDIT_MAGIC);
		AN(ap);
		ap->silo_fn = fn;
		ap->silo_no = nsilo;
		ap->hdr = Rsilo_ReadHeader(rs);
		if (ap->hdr == NULL) {
			FREE_OBJ(ap);
			break;
		}

		ap->o1 = Rsilo_Tell(rs);

		SHA256_Init(ap->sha256);
		(void)Rsilo_ReadChunk(rs, audit_iter, ap);
		ap->o2 = Rsilo_Tell(rs);

		Rsilo_SkipCRNL(rs);

		VSB_clear(vsberr);
		r = audit_one(aa, vsberr, ap);
		if (VSB_len(vsberr)) {
			tbad++;
			AZ(VSB_finish(vsberr));
			if (ngood)
				printf("(%d good entries)\n", ngood);
			printf("%s", VSB_data(vsberr));
			audit_report(NULL, ap);
			ngood = 0;
		} else {
			ngood++;
			tgood++;
		}
		if (!r) {
			Header_Destroy(&ap->hdr);
			FREE_OBJ(ap);
		}
	}

	if (tbad && ngood)
		printf("(%d good entries)\n", ngood);
	VSB_destroy(&vsberr);
	Rsilo_Close(&rs);
	printf("%d good %d bad entries in this silo\n", tgood, tbad);
	return (0);
}

static
void
usage_audit(const char *a0, const char *a00, const char *err)
{
	usage(a0, err);
	fprintf(stderr, "Usage for this operation:\n");
	fprintf(stderr, "\t%s [global options] %s [options] [silo]...\n",
	    a0, a00);
	//fprintf(stderr, "Options:\n");
	//fprintf(stderr, "\t-m mime_type\n");
	//fprintf(stderr, "\t-t {metadata|resource}\n");
}

int v_matchproto_(main_f)
main_audit(const char *a0, struct aardwarc *aa, int argc, char **argv)
{
	int ch, i;
	const char *a00 = *argv;
	struct audit *ap;
	struct vsb *err;

	CHECK_OBJ_NOTNULL(aa, AARDWARC_MAGIC);

	while ((ch = getopt(argc, argv, "h")) != -1) {
		switch (ch) {
		case 'h':
			usage_audit(a0, a00, NULL);
			exit(1);
		default:
			usage_audit(a0, a00, "Unknown option error.");
			exit(1);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc == 0) {
		i = 0;
		while (!audit_silo(aa, NULL, i++))
			continue;
	} else {
		while (argc-- > 0)
			if (audit_silo(aa, *argv++, -1))
				break;
	}

	err = VSB_new_auto();
	AN(err);
	while (audit_one_pending(aa, err))
		continue;
	VTAILQ_FOREACH(ap, &segment_list, list) {
		printf("Left on pending %d %jd %jd %d\n",
		    ap->silo_no, ap->o1, ap->o2, ap->segment);
	}
	VSB_destroy(&err);

	return (0);
}
