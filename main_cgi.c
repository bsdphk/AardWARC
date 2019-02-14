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
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "vdef.h"

#include "vas.h"
#include "vsb.h"
#include "miniobj.h"

#include "aardwarc.h"

static
void
usage_cgi(const char *a0, const char *a00, const char *err)
{
	usage(a0, err);
	fprintf(stderr, "Usage for this operation:\n");
	fprintf(stderr, "\t%s [global options] %s [options]\n",
	    a0, a00);
}

static int v_matchproto_(byte_iter_f)
get_iter(void *priv, const void *ptr, ssize_t len)
{

	(void)priv;
	assert(len == (ssize_t)fwrite(ptr, 1, len, stdout));
	return (0);
}

int v_matchproto_(main_f)
main_cgi(const char *a0, struct aardwarc *aa, int argc, char **argv)
{
	int ch;
	const char *a00 = *argv;
	struct vsb *vsb;
	struct getjob *gj;
	const struct header *hdr;
	const char *p;
	const char *id;
	const char *ct;
	int gzip = 0;
	off_t o;

	CHECK_OBJ_NOTNULL(aa, AARDWARC_MAGIC);

	while ((ch = getopt(argc, argv, "h")) != -1) {
		switch (ch) {
		case 'h':
			usage_cgi(a0, a00, NULL);
			exit(1);
		default:
			usage_cgi(a0, a00, "Unknown option error.");
			exit(1);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 0) {
		usage_cgi(a0, a00, "Too many arguments.");
		exit (1);
	}
	AZ(*argv);

	p = getenv("GATEWAY_INTERFACE");
	if (p == NULL || strcmp(p, "CGI/1.1")) {
		usage_cgi(a0, a00, "No (good) $GATEWAY_INTERFACE");
		exit(1);
	}
	p = getenv("REQUEST_METHOD");
	if (p == NULL || strcmp(p, "GET")) {
		usage_cgi(a0, a00, "No (good) $REQUEST_METHOD");
		exit(1);
	}

	id = getenv("PATH_INFO");
	if (id == NULL) {
		usage_cgi(a0, a00, "No $PATH_INFO");
		exit (1);
	}

	p = getenv("HTTP_ACCEPT_ENCODING");
	if (p != NULL && strstr(p, "gzip"))
		gzip = 1;

	if (*id == '/')
		id++;

	vsb = VSB_new_auto();
	AN(vsb);

	gj = GetJob_New(aa, id, vsb);
	if (gj == NULL) {
		AZ(VSB_finish(vsb));
		printf("Content-Type: text/html\n");
		printf("Status: 501 Error\n");
		printf("\n");
		printf("<html>");
		printf("<pre>");
		printf("%s\n", VSB_data(vsb));
		printf("</pre>");
		printf("</html>");
		exit (0);
	}
	VSB_delete(vsb);

	/*
	 * We cannot do the gzip trick for segmented objects (exactly
	 * the ones that need it most) because firefox and curl do not
	 * properly handle concatenated gzip files.
	 * XXX: we could stich them, doing the CRC editing dance...
	 */
	if (GetJob_IsSegmented(gj))
		gzip = 0;

	hdr = GetJob_Header(gj, 1);
	AN(hdr);

	ct = Header_Get(hdr, "Content-Type");
	if (ct == NULL)
		ct = "application/binary";
	printf("Content-Type: %s\n", ct);

	if (gzip)
		printf("Content-Encoding: gzip\n");

	o = GetJob_TotalLength(gj, gzip);
	printf("Content-Length: %zd\n", o);
	printf("Status: 200\n");
	printf("\n");

	GetJob_Iter(gj, get_iter, NULL, gzip);

	GetJob_Delete(&gj);
	return (0);
}
