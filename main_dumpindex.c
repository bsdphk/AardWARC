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
usage_dumpindex(const char *a0, const char *a00, const char *err)
{
	usage(a0, err);
	fprintf(stderr, "Usage for this operation:\n");
	fprintf(stderr, "\t%s [global options] %s [options] [id-part]...\n",
	    a0, a00);
	fprintf(stderr, "\t\t -t {metadata|resource|warcinfo}\n");
}

static int v_matchproto_(idx_iter_f)
dumpindex_iter(void *priv, const char *key,
    uint32_t flag, uint32_t silo, int64_t offset, const char *cont)
{
	uint32_t *u;

	u = priv;
	if (*u != 0 && flag != *u)
		return (0);
	printf("%s 0x%08x %8u %12jd %s\n", key, flag, silo, offset, cont);
	return(0);
}

int v_matchproto_(main_f)
main_dumpindex(const char *a0, struct aardwarc *aa, int argc, char **argv)
{
	int ch;
	const char *a00 = *argv;
	uint32_t u = 0;

	CHECK_OBJ_NOTNULL(aa, AARDWARC_MAGIC);

	while ((ch = getopt(argc, argv, "ht:")) != -1) {
		switch (ch) {
		case 'h':
			usage_dumpindex(a0, a00, NULL);
			exit(1);
		case 't':
			if (!strcmp(optarg, "metadata"))
				u = IDX_F_METADATA;
			else if (!strcmp(optarg, "resource"))
				u = IDX_F_RESOURCE;
			else if (!strcmp(optarg, "warcinfo"))
				u = IDX_F_WARCINFO;
			else {
				usage_dumpindex(a0, a00,
				    "Wrong type for -t.");
				exit (1);
			}
			break;
		default:
			usage_dumpindex(a0, a00, "Unknown option error.");
			exit(1);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc == 0)
		(void)IDX_Iter(aa, NULL, dumpindex_iter, &u);
	else
		for (;argc > 0; argc--, argv++)
			(void)IDX_Iter(aa, *argv, dumpindex_iter, &u);
	return (0);
}
