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
#ifndef SHA256_DIGEST_LENGTH
#  define SHA256_DIGEST_LENGTH            32
#endif
#ifndef SHA256_DIGEST_STRING_LENGTH
#  define SHA256_DIGEST_STRING_LENGTH     (SHA256_DIGEST_LENGTH * 2 + 1)
#endif

#include "aardwarc.h"

struct audit {
	unsigned		magic;
#define AUDIT_MAGIC		0xce2bb3e2
	off_t			o1;
	off_t			o2;
	ssize_t			sz;
	struct header		*hdr;
	struct SHA256Context	sha256[1];
};


static int v_matchproto_(byte_iter_f)
audit_iter(void *priv, const void *ptr, ssize_t len)
{
	struct audit *ap;

	CAST_OBJ_NOTNULL(ap, priv, AUDIT_MAGIC);
	SHA256_Update(ap->sha256, ptr, len);
	ap->sz += len;
	return (0);
}

static int
audit_one(struct aardwarc *aa, struct vsb *err, struct audit *ap)
{
	char *oldid, *newid;
	char buf[SHA256_DIGEST_STRING_LENGTH];
	const char *is;

	CHECK_OBJ_NOTNULL(ap, AUDIT_MAGIC);
	(void)SHA256_End(ap->sha256, buf);


	is = Header_Get(ap->hdr, "WARC-Block-Digest");
	if (is == NULL) {
		VSB_printf(err, "ERROR: WARC-Block-Digest missing\n");
	} else if (memcmp(is, "sha256:", 7)) {
		VSB_printf(err, "ERROR: WARC-Block-Digest is not sha256\n");
	} else if (strcmp(is + 7, buf)) {
		VSB_printf(err, "ERROR: WARC-Block-Digest difference\n");
		VSB_printf(err, "\tis:\t\t%s\n", is);
		VSB_printf(err, "\tshould be:\t%s\n", buf);
	}

	oldid = strdup(Header_Get_Id(ap->hdr));
	AN(oldid);

	Ident_Create(aa, ap->hdr, buf);
	newid = strdup(Header_Get_Id(ap->hdr));
	AN(newid);
	Header_Set_Id(ap->hdr, oldid);

	if (strcmp(oldid, newid)) {
		VSB_printf(err, "ERROR: WARC-Record-ID difference\n");
		VSB_printf(err, "\tis:\t\t%s\n", oldid);
		VSB_printf(err, "\tshould be:\t%s\n", newid);
	}
	free(oldid);
	free(newid);

	bprintf(buf, "%jd", (intmax_t)ap->sz);
	is = Header_Get(ap->hdr, "Content-Length");
	if (is == NULL) {
		VSB_printf(err, "ERROR: Content-Length missing\n");
	} else if (strcmp(buf, is)) {
		VSB_printf(err, "ERROR: Content-Length difference\n");
		VSB_printf(err, "\tis:\t\t%s\n", is);
		VSB_printf(err, "\tshould be:\t%s\n", buf);
	}

	bprintf(buf, "%jd", (intmax_t)(ap->o2 - ap->o1));
	is = Header_Get(ap->hdr, "Content-Length-GZIP");
	if (is == NULL) {
		VSB_printf(err, "ERROR: Content-Length-GZIP missing\n");
	} else if (strcmp(buf, is)) {
		VSB_printf(err, "ERROR: Content-Length-GZIP difference\n");
		VSB_printf(err, "\tis:\t\t%s\n", is);
		VSB_printf(err, "\tshould be:\t%s\n", buf);
	}
	return (VSB_len(err) > 0);
}

static int
audit_silo(struct aardwarc *aa, const char *fn, int nsilo)
{
	struct rsilo *rs;
	struct audit *ap;
	struct vsb *vsb, *vsberr;
	const char *p;
	int ngood = 0;
	int tgood = 0;
	int tbad = 0;

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
		if (audit_one(aa, vsberr, ap)) {
			tbad++;
			AZ(VSB_finish(vsberr));
			if (ngood)
				printf("(%d good entries)\n", ngood);
			printf("%s", VSB_data(vsberr));
			vsb = Header_Serialize(ap->hdr, -1);
			AZ(VSB_finish(vsb));
			printf("\n\t[%jd...%jd]\n", ap->o1, ap->o2);
			printf("\n\t| ");
			for (p = VSB_data(vsb); *p != '\0'; p++) {
				if (*p == '\n')
					printf("\n\t| ");
				else if (*p != '\r')
					(void)putchar(*p);
			}
			printf("\n\n");
			VSB_destroy(&vsb);
			ngood = 0;
		} else {
			ngood++;
			tgood++;
		}
		Header_Destroy(&ap->hdr);
		FREE_OBJ(ap);
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

	return (0);
}
