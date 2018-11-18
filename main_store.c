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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "vas.h"
#include "vsb.h"
#include "miniobj.h"

#include "aardwarc.h"

static const char * const WT_RESOURCE = "resource";
static const char * const WT_METADATA = "metadata";

static int
mime_print(void *priv, const char *name, const char *arg)
{
	(void)priv;
	(void)arg;
	fprintf(stderr, "\t%s\n", name);
	return (0);
}

static int
mime_type(struct aardwarc *aa, const char *wt, const char *mt)
{
	int i;
	const char *p, *g;

	if (wt == WT_RESOURCE)
		g = "resource.mime-types";
	else
		g = "metadata.mime-types";

	i = Config_Find(aa->cfg, g, mt, &p);
	if (i) {
		fprintf(stderr, "Illegal mime-type for %s, pick one of:\n", wt);
		(void)Config_Iter(aa->cfg, g, NULL, mime_print);
	} else
		aa->mime_validator = p;
	return (i);
}

static
void
usage_store(const char *a0, const char *a00, const char *err)
{
	usage(a0, err);
	fprintf(stderr, "Usage for this operation:\n");
	fprintf(stderr, "\t%s [global options] %s [options] {filename|-}\n",
	    a0, a00);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "\t-m mime_type\n");
	fprintf(stderr, "\t-t {metadata|resource}\n");
	fprintf(stderr, "\t-r WARC-Refers-To: reference\n");
}

int __match_proto__(main_f)
main_store(const char *a0, struct aardwarc *aa, int argc, char **argv)
{
	int ch;
	int fd = -1;
	const char *wt = WT_RESOURCE;
	const char *mt = "application/octet-stream";
	struct header *hdr;
	struct getjob *gj;
	struct segjob *sj;
	char *id;
	const char *a00 = *argv;
	char *ibuf_ptr;
	const char *ref = NULL;
	ssize_t ibuf_len, rlen;
	struct vsb *vsb;
	const char *e;

	CHECK_OBJ_NOTNULL(aa, AARDWARC_MAGIC);

	while ((ch = getopt(argc, argv, "hm:t:r:")) != -1) {
		switch (ch) {
		case 'h':
			usage_store(a0, a00, NULL);
			exit(1);
		case 'm':
			mt = optarg;
			break;
		case 't':
			if (!strcasecmp(optarg, "resource"))
				wt = WT_RESOURCE;
			else if (!strcasecmp(optarg, "metadata"))
				wt = WT_METADATA;
			else {
				usage_store(a0, a00, "Illegal -t argument.");
				exit(1);
			}
			break;
		case 'r':
			e = IDX_Valid_Id(aa, optarg, NULL);
			if (e != NULL) {
				usage_store(a0, a00, e);
				exit(1);
			}
			if (strlen(optarg) == aa->id_size) {
				vsb = VSB_new_auto();
				AN(vsb);
				VSB_printf(vsb, "%s%s", aa->prefix, optarg);
				AZ(VSB_finish(vsb));
				AZ(IDX_Valid_Id(aa, VSB_data(vsb), NULL));
				ref = strdup(VSB_data(vsb));
				AN(ref);
				VSB_delete(vsb);
				vsb = NULL;
			} else
				ref = optarg;
			break;
		default:
			usage_store(a0, a00, "Unknown option error.");
			exit(1);
		}
	}
	argc -= optind;
	argv += optind;

	if (wt == WT_METADATA && ref == NULL) {
		fprintf(stderr, "Must specify -r ID for metadata\n");
		exit(1);
	} else if (wt != WT_METADATA && ref != NULL) {
		fprintf(stderr, "Can only specify -r ID for metadata\n");
		exit(1);
	}

	/* Figure out the input file ----------------------------------*/

	if (argc == 0) {
		fd = 0;
	} else if (argc != 1) {
		usage_store(a0, a00, "Too many input files");
		exit(1);
	} else if (!strcmp(*argv, "-")) {
		fd = 0;
	} else {
		fd = open(*argv, O_RDONLY);
		if (fd < 0) {
			fprintf(stderr,
			    "Cannot open %s: %s\n", *argv, strerror(errno));
			exit(1);
		}
	}

	ibuf_len = 128 * 1024;
	ibuf_ptr = malloc(ibuf_len);
	AN(ibuf_ptr);

	rlen = read(fd, ibuf_ptr, ibuf_len);
	if (rlen < 0) {
		fprintf(stderr, "Input file read error: %s\n", strerror(errno));
		exit(1);
	}
	if (rlen == 0) {
		fprintf(stderr, "Input file empty\n");
		exit(1);
	}

	/* Create headers ---------------------------------------------*/

	hdr = Header_New(aa);
	AN(hdr);

	/* Check the mime type ----------------------------------------*/

	if (mime_type(aa, wt, mt))
		exit(1);

	/* Fill in header ---------------------------------------------*/

	Header_Set_Date(hdr);
	Header_Set(hdr, "Content-Type", "%s", mt);
	Header_Set(hdr, "WARC-Type", "%s", wt);

	if (ref != NULL) {
		assert(wt == WT_METADATA);
		vsb = VSB_new_auto();
		AN(vsb);
		gj = GetJob_New(aa, ref, vsb);
		if (gj == NULL) {
			fprintf(stderr, "Referenced (-r) ID does not exist\n");
			exit(1);
		}
		GetJob_Delete(&gj);
		Header_Set(hdr, "WARC-Refers-To", "<%s>", ref);
	}

	sj = SegJob_New(aa, hdr);
	AN(sj);

	SegJob_Feed(sj, ibuf_ptr, rlen);
	do {
		rlen = read(fd, ibuf_ptr, ibuf_len);
		if (rlen > 0)
			SegJob_Feed(sj, ibuf_ptr, rlen);
	} while (rlen > 0);

	id = SegJob_Commit(sj);
	printf("%s\n", id);

	REPLACE(ibuf_ptr, NULL);

	return (0);
}
