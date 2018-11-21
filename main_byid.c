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
#include "miniobj.h"

#include "aardwarc.h"

static
void
usage_byid(const char *a0, const char *a00, const char *err)
{
	usage(a0, err);
	fprintf(stderr, "Usage for this operation:\n");
	fprintf(stderr, "\t%s [global options] %s [options] [silo]...\n",
	    a0, a00);
}

static int __match_proto__(idx_iter_f)
byid_iter(void *priv, const char *key,
    uint32_t flag, uint32_t silo, uint64_t offset, const char *cont)
{
	struct rsilo *rs;
	struct header *hdr;
	const char *p;

	(void)priv;
	(void)key;
	(void)flag;
	(void)cont;
	// printf("%s 0x%08x %8u %12ju %s\n", key, flag, silo, offset, cont);
	rs = Rsilo_Open(priv, NULL, silo);
	AN(rs);
	Rsilo_Seek(rs, offset);
	hdr = Rsilo_ReadHeader(rs);
	AN(hdr);
	p = Header_Get_Id(hdr);
	printf("id %s", p);
	p = Header_Get(hdr, "WARC-Type");
	printf(" wt %s", p);
	printf("\n");
	Header_Delete(&hdr);
	Rsilo_Close(&rs);
	return(0);
}

int __match_proto__(main_f)
main_byid(const char *a0, struct aardwarc *aa, int argc, char **argv)
{
	int ch;
	const char *a00 = *argv;
	const char *nid;

	CHECK_OBJ_NOTNULL(aa, AARDWARC_MAGIC);

	while ((ch = getopt(argc, argv, "h")) != -1) {
		switch (ch) {
		case 'h':
			usage_byid(a0, a00, NULL);
			exit(1);
		default:
			usage_byid(a0, a00, "Unknown option error.");
			exit(1);
		}
	}
	argc -= optind;
	argv += optind;

	for (;argc > 0; argc--, argv++) {
		nid = *argv;
		if (!strncasecmp(nid, aa->prefix, strlen(aa->prefix)))
			nid += strlen(aa->prefix);
		if (strspn(nid, "0123456789abcdefABCDEF") != strlen(nid)) {
			fprintf(stderr, "Invalid ID-fragment\n");
			exit(1);
		}
		(void)IDX_Iter(aa, nid, byid_iter, aa);
	}
	return (0);
}
