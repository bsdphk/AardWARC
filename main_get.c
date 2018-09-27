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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sha256.h>

#include "vas.h"
#include "vsb.h"
#include "miniobj.h"

#include "aardwarc.h"

static
void
usage_get(const char *a0, const char *a00, const char *err)
{
	usage(a0, err);
	fprintf(stderr, "Usage for this operation:\n");
	fprintf(stderr, "\t%s [global options] %s [options] [silo]...\n",
	    a0, a00);
}

struct get {
	unsigned		magic;
#define GET_MAGIC		0xc6629054

	uintmax_t		len;
	struct SHA256Context	sha256[1];
	FILE			*dst;
	int			zip;
};

static int __match_proto__(byte_iter_f)
get_iter(void *priv, const void *ptr, ssize_t len)
{
	struct get *gp;

	CAST_OBJ_NOTNULL(gp, priv, GET_MAGIC);
	assert(len == (ssize_t)fwrite(ptr, 1, len, gp->dst));
	if (!gp->zip)
		SHA256_Update(gp->sha256, ptr, len);
	gp->len += len;
	return (0);
}

int __match_proto__(main_f)
main_get(const char *a0, struct aardwarc *aa, int argc, char **argv)
{
	int ch;
	const char *a00 = *argv;
	struct vsb *vsb;
	struct getjob *gj;
	struct get *gp;
	const struct header *hdr;
	char *dig;
	const char *p;
	char buf[32];
	int quiet = 0;
	const char *of = NULL;
	int zip = 0;

	CHECK_OBJ_NOTNULL(aa, AARDWARC_MAGIC);

	while ((ch = getopt(argc, argv, "ho:q:z")) != -1) {
		switch (ch) {
		case 'h':
			usage_get(a0, a00, NULL);
			exit(1);
		case 'o':
			of = optarg;
			break;
		case 'q':
			quiet = !quiet;
			break;
		case 'z':
			zip = !zip;
			break;
		default:
			usage_get(a0, a00, "Unknown option error.");
			exit(1);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1) {
		usage_get(a0, a00, "Too many IDs.");
		exit (1);
	}
	AN(*argv);

	ALLOC_OBJ(gp, GET_MAGIC);
	AN(gp);
	gp->zip = zip;
	SHA256_Init(gp->sha256);

	if (of != NULL)
		gp->dst = fopen(of, "w");
	else
		gp->dst = stdout;

	vsb = VSB_new_auto();
	AN(vsb);

	gj = GetJob_New(aa, *argv, vsb);
	if (gj == NULL) {
		AZ(VSB_finish(vsb));
		fprintf(stderr, "%s\n", VSB_data(vsb));
		exit (1);
	}
	VSB_delete(vsb);
	hdr = GetJob_Header(gj, 1);
	AN(hdr);
	if (!quiet) {
		vsb = Header_Serialize(hdr, -1);
		AZ(VSB_finish(vsb));
		if (of == NULL)
			fprintf(stderr, "%s", VSB_data(vsb));
		else
			fprintf(stdout, "%s", VSB_data(vsb));
	}

	GetJob_Iter(gj, get_iter, gp, zip);

	dig = SHA256_End(gp->sha256, NULL);
	AN(dig);

	if (!zip) {
		p = Header_Get(hdr, "WARC-Payload-Digest");
		if (p == NULL)
			p = Header_Get(hdr, "WARC-Block-Digest");
		AN(p);
		assert(!memcmp(p, "sha256:", 7));
		p += 7;
		assert(!strncmp(p, dig, aa->id_size));

		hdr = GetJob_Header(gj, 0);
		p = Header_Get(hdr, "WARC-Segment-Total-Length");
		if (p == NULL)
			p = Header_Get(hdr, "Content-Length");
		AN(p);
		bprintf(buf, "%ju", (uintmax_t)gp->len);
		assert(!strcmp(p, buf));
	}

	FREE_OBJ(gp);
	GetJob_Delete(&gj);
	return (0);
}
