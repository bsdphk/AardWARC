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

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sha256.h>
#include <unistd.h>

#include "vdef.h"
#include "vas.h"
#include "miniobj.h"
#include "aardwarc.h"

static void
usage_mksilo(const char *a0, const char *a00, const char *err)
{
	usage(a0, err);
	fprintf(stderr, "Usage for this operation:\n");
	fprintf(stderr, "\t%s [global options] %s [options] silo#\n",
	    a0, a00);
}

int v_matchproto_(main_f)
main_mksilo(const char *a0, struct aardwarc *aa, int argc, char **argv)
{
	int ch, retval = 0;
	const char *a00 = *argv;
	unsigned u;
	struct wsilo *ws;

	CHECK_OBJ_NOTNULL(aa, AARDWARC_MAGIC);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	while ((ch = getopt(argc, argv, "h")) != -1) {
		switch (ch) {
		case 'h':
			usage_mksilo(a0, a00, NULL);
			exit(1);
		default:
			usage_mksilo(a0, a00, "Unknown option error.");
			exit(1);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc == 0) {
		usage_mksilo(a0, a00, "No silo#.");
		exit(1);
	}
	u = strtoul(argv[0], NULL, 0);
	ws = Wsilo_New(aa, u);
	if (ws == NULL) {
		usage_mksilo(a0, a00, "Could not.");
		exit(1);
	}
	Wsilo_Install(&ws);

	return (retval);
}
