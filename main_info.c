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
usage_info(const char *a0, const char *a00, const char *err)
{
	usage(a0, err);
	fprintf(stderr, "Usage for this operation:\n");
	fprintf(stderr, "\t%s [global options] %s [options] [silo]...\n",
	    a0, a00);
}

int __match_proto__(main_f)
main_info(const char *a0, struct aardwarc *aa, int argc, char **argv)
{
	int ch;
	const char *a00 = *argv;

	CHECK_OBJ_NOTNULL(aa, AARDWARC_MAGIC);

	while ((ch = getopt(argc, argv, "h")) != -1) {
		switch (ch) {
		case 'h':
			usage_info(a0, a00, NULL);
			exit(1);
		default:
			usage_info(a0, a00, "Unknown option error.");
			exit(1);
		}
	}
	if (argc > optind) {
		usage_info(a0, a00, "No arguments allowed.");
		exit(1);
	}
	if (aa->json) {
		printf("[ \"AardWARC\", \"info\", \"1\", {\n");
		printf("    \"id_size\": %u\n", aa->id_size);
		printf("} ]\n");
	} else {
		printf("id_size: %u\n", aa->id_size);
	}
	return (0);
}
