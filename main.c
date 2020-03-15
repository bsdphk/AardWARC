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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "vdef.h"

#include "vas.h"
#include "vsb.h"

#include "aardwarc.h"

/*---------------------------------------------------------------------*/

static const struct mains {
	const char	*name;
	main_f		*func;
	int		json;
	const char	*line1;
} mains[] = {
#define MAIN(l,j,d) { #l, main_##l, j, d}
	MAIN(audit,		0, "Audit silos"),
	MAIN(byid,		0, "List entries by ID"),
	MAIN(cgi,		0, "CGI service"),
	MAIN(dumpindex,		0, "Dump index"),
	MAIN(filter,		0, "Filter list of IDs"),
	MAIN(get,		0, "Get record"),
	MAIN(housekeeping,	0, "Do housekeeping"),
	MAIN(info,		1, "Information about the archive"),
	MAIN(mksilo,		0, "Build a new silo"),
	MAIN(rebuild,		0, "Rebuild silos"),
	MAIN(reindex,		0, "Rebuild index"),
	MAIN(stevedore,		0, "Act as server"),
	MAIN(store,		0, "Store data"),
	MAIN(stow,		0, "Stow data to remote server"),
	MAIN(_testbytes,	0, "Bytes for tests"),
	{ NULL,	NULL, 0, NULL}
};

void
usage(const char *a0, const char *err)
{
	const struct mains *mp;

	if (err != NULL)
		fprintf(stderr, "%s\n", err);
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\t%s [global options] operation [arguments]\n", a0);
	fprintf(stderr, "Global options:\n");
	fprintf(stderr, "\t-c config_file\n");
	fprintf(stderr, "Operations:\n");
	for(mp = mains; mp->name != NULL; mp++)
		if (mp->name[0] != '.')
			fprintf(stderr, "\t%-12s %s\n", mp->name, mp->line1);
}

int
call_main(const char *a0, struct aardwarc *aa, int argc, char **argv)
{
	const struct mains *mp;
	for(mp = mains; mp->name != NULL; mp++)
		if (!strcmp(mp->name, argv[0]))
			break;
	if (mp->name == NULL) {
		usage(a0, "Unknown operation");
		return (1);
	}
	if (aa->json && !mp->json) {
		usage(a0, "This subcommand does not do JSON.");
		return (2);
	}
	return (mp->func(a0, aa, argc, argv));
}

int
main(int argc, char **argv)
{
	int ch, json = 0;
	const char *cf = NULL;
	struct vsb *vsb1, *vsb2, *vsb3;
	struct aardwarc *aa = NULL;
	const char *a0;
	char *home;
	char buf[BUFSIZ];

	/* Parse global option flags ----------------------------------*/

	a0 = *argv;
	while ((ch = getopt(argc, argv, "c:hj")) != -1) {
		switch(ch) {
		case 'h':
			usage(a0, NULL);
			exit(1);
			break;
		case 'j':
			json = 1;
			break;
		case 'c':
			cf = optarg;
			break;
		default:
			usage(a0, "Unknown global option error");
			exit(1);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	optreset = 1;
	optind = 1;

	if (argc == 0) {
		usage(a0, "Need command argument");
		exit (1);
	}

	/* Open and parse our configuration ---------------------------*/

	vsb1 = VSB_new_auto();
	AN(vsb1);
	vsb2 = VSB_new_auto();
	AN(vsb2);
	vsb3 = VSB_new_auto();
	AN(vsb3);
	buf[0] = '\0';

	if (cf != NULL) {
		aa = AardWARC_New(cf, vsb1);
		if (aa == NULL) {
			AZ(VSB_finish(vsb1));
			fprintf(stderr, "%s", VSB_data(vsb1));
			exit(2);
		}
	} else {
		home = getenv("HOME");
		if (home != NULL) {
			bprintf(buf, "%s/.aardwarc.conf", home);
			aa = AardWARC_New(buf, vsb1);
			AZ(VSB_finish(vsb1));
		}
		if (aa == NULL) {
			aa = AardWARC_New("/etc/aardwarc.conf", vsb2);
			AZ(VSB_finish(vsb2));
		}
		if (aa == NULL) {
			aa = AardWARC_New("/usr/local/etc/aardwarc.conf", vsb3);
			AZ(VSB_finish(vsb3));
		}
		if (aa == NULL) {
			fprintf(stderr, "No config file found, tried:\n");
			if (buf[0] != '\0')
				fprintf(stderr, "    %s\n\t%s\n",
				    buf, VSB_data(vsb1));
			fprintf(stderr, "    /etc/aardwarc.conf\n\t%s\n",
			    VSB_data(vsb2));
			fprintf(stderr,
			    "    /usr/local/etc/aardwarc.conf\n\t%s\n",
			    VSB_data(vsb3));
			exit(1);
		}
	}
	aa->json = json;

	VSB_delete(vsb1);
	VSB_delete(vsb2);
	VSB_delete(vsb3);

	return (call_main(a0, aa, argc, argv));
}
