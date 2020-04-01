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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/endian.h>

#include "vdef.h"

#include "miniobj.h"
#include "vsb.h"
#include "vas.h"

#include "aardwarc.h"

struct aardwarc *
AardWARC_New(const char *config_file, struct vsb *err)
{
	int e;
	struct aardwarc *aa;
	const char *p, *p2;
	uintmax_t um;

	ALLOC_OBJ(aa, AARDWARC_MAGIC);
	if (aa == NULL)
		return (aa);

	do {
		aa->cfg = Config_Read(config_file);
		if (aa->cfg == NULL) {
			VSB_printf(err, "Cannot open %s: %s\n",
			    config_file, strerror(errno));
			break;
		}

		if (Config_Get(aa->cfg, "WARC-Record-ID", &aa->prefix, &p)) {
			VSB_printf(err,
			    "'WARC-Record-ID' not found in config.\n");
			break;
		}
		if (aa->prefix[strlen(aa->prefix) - 1] != '/') {
			VSB_printf(err,
			    "'WARC-Record-ID' must end in '/'\n");
			break;
		}
		if (p != NULL) {
			aa->id_size = strtoul(p, NULL, 0);
			if (aa->id_size < 64 || aa->id_size > 256) {
				VSB_printf(err,
				    "Illegal 'WARC-Record-ID' length %s.\n",
				    "\tMust be [64...256] bits");
				break;
			}
			if (aa->id_size & 3) {
				VSB_printf(err,
				    "Illegal 'WARC-Record-ID' length %s.\n",
				    "\tMust be divisible by 4 bits");
				break;
			}
			aa->id_size >>= 2;
		} else
			aa->id_size = 32;
		assert(aa->id_size >= 16 && aa->id_size <= 64);

		if (Config_Get(aa->cfg, "silo.directory", &p, NULL)) {
			VSB_printf(err,
			    "'silo.directory' not found in config.\n");
			break;
		}
		aa->silo_dirname = p;
		if (aa->silo_dirname[strlen(aa->silo_dirname) - 1] != '/') {
			VSB_printf(err,
			    "'silo.directory' must end in '/'\n");
			break;
		}

		if (Config_Get(aa->cfg, "silo.max_size", &p, NULL))
			p = "3.5G";

		p2 = VNUM_2bytes(p, &um, 0);
		if (p2 != NULL) {
			VSB_printf(err,
			    "'silo.max_size' size \"%s\":\t%s\n", p, p2);
			break;
		}
		aa->silo_maxsize = (off_t)um;
		assert(um == (uintmax_t)aa->silo_maxsize);

		if (Config_Get(aa->cfg, "silo.basename", &p, NULL))
			p = "%08u.warc.gz";

		if (fmtcheck(p, "%u") != p) {
			VSB_printf(err,
			    "'silo.basename' wrong format. %s\n",
			    "Must have a single %u compatible printf-pattern");
			break;
		}
		aa->silo_basename = p;
		if (strchr(p, '/') != NULL) {
			VSB_printf(err,
			    "'silo.basename' Cannot contain '/'\n");
			break;
		}

		if (Config_Get(aa->cfg, "index.sort_size", &p, NULL))
			p = "10M";
		p2 = VNUM_2bytes(p, &um, 0);
		if (p2 != NULL) {
			VSB_printf(err,
			    "'index.sort_size' size \"%s\":\t%s\n", p, p2);
			break;
		}
		aa->index_sort_size = (off_t)um;
		aa->index_sort_size &= ~0x1f;
		if (aa->index_sort_size < 4096) {
			VSB_printf(err,
			    "'index.sort_size' is too small (>= 4k)\n");
			break;
		}

		aa->cache_first_non_silo = 0;
		aa->cache_first_space_silo = 0;

		return (aa);

	} while (0);
	e = errno;
	/* XXX: free aa->cfg */
	FREE_OBJ(aa);
	errno = e;
	return (NULL);
}

void
AardWARC_ReadCache(struct aardwarc *aa)
{
	struct vsb *vsb;
	uint8_t buf[4 * 2];
	int i;
	int fd;

	vsb = VSB_new_auto();
	AN(vsb);
	VSB_printf(vsb, "%s/_.cache", aa->silo_dirname);
	AZ(VSB_finish(vsb));
	fd = open(VSB_data(vsb), O_RDONLY);
	if (fd >= 0) {
		i = read(fd, buf, sizeof buf);
		if (i == sizeof buf) {
			aa->cache_first_non_silo = be32dec(buf);
			aa->cache_first_space_silo = be32dec(buf + 4);
		}
		AZ(close(fd));
	}
	VSB_delete(vsb);
}

void
AardWARC_WriteCache(const struct aardwarc *aa)
{
	struct vsb *vsb;
	uint8_t buf[4 * 2];
	int fd;

	vsb = VSB_new_auto();
	AN(vsb);
	VSB_printf(vsb, "%s/_.cache", aa->silo_dirname);
	AZ(VSB_finish(vsb));
	be32enc(buf, aa->cache_first_non_silo);
	be32enc(buf + 4, aa->cache_first_space_silo);
	fd = open(VSB_data(vsb), O_WRONLY|O_CREAT, 0644);
	if (fd >= 0) {
		(void)write(fd, buf, sizeof buf);
		AZ(close(fd));
	}
	VSB_delete(vsb);
}
