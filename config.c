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

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "vdef.h"
#include "miniobj.h"
#include "vas.h"

#include "aardwarc.h"

struct entry {
	unsigned		magic;
#define ENTRY_MAGIC		0x4101dadc
	VTAILQ_ENTRY(entry)	list;
	const char		*name;
	const char		*arg;
};

struct section {
	unsigned		magic;
#define SECTION_MAGIC		0x18a00a8c
	unsigned		nentry;
	VTAILQ_ENTRY(section)	list;
	const char		*name;
	VTAILQ_HEAD(,entry)	entries;
};

struct config {
	unsigned		magic;
#define CONFIG_MAGIC		0x31b7d969
	unsigned		nsection;
	VTAILQ_HEAD(,section)	sections;
	u_char			*space;
};

static void
config_destroy(struct config *cfg)
{

	REPLACE(cfg->space, NULL);
	FREE_OBJ(cfg);
}

static const char *
config_parse(struct config *cfg)
{
	char *p, *q, *r, *e;
	struct section *sc = NULL;
	struct entry *ent = NULL;

	CHECK_OBJ_NOTNULL(cfg, CONFIG_MAGIC);

	for (p = (char*)cfg->space; *p != '\0'; p = e) {
		e = strchr(p, '\n');
		if (e != NULL)
			*e++ = '\0';
		else
			e = strchr(p, '\0');
		q = strchr(p, '#');
		if (q != NULL)
			*q = '\0';
		r = NULL;
		for (q = p; *q != '\0'; q++)
			if (!isspace(*q))
				r = q;
		if (r == NULL)
			continue;
		r[1] = '\0';
		if (!isspace(*p)) {
			r = strchr(p, ':');
			if (r == NULL || r[1] != '\0')
				return ("Section colon trouble");
			*r = '\0';
			VTAILQ_FOREACH(sc, &cfg->sections, list)
				if (!strcmp(sc->name, p))
					return ("Duplicate sections");
			ALLOC_OBJ(sc, SECTION_MAGIC);
			AN(sc);
			VTAILQ_INIT(&sc->entries);
			VTAILQ_INSERT_TAIL(&cfg->sections, sc, list);
			cfg->nsection++;
			sc->name = p;
		} else {
			if (sc == NULL)
				return ("No section yet");
			for (q = p; isspace(*q); q++)
				continue;
			ALLOC_OBJ(ent, ENTRY_MAGIC);
			AN(ent);
			VTAILQ_INSERT_TAIL(&sc->entries, ent, list);
			sc->nentry++;
			ent->name = q;
			for (; *q != '\0' && !isspace(*q) ; q++)
				continue;
			if (isspace(*q)) {
				*q++ = '\0';
				while (isspace(*q))
					q++;
				ent->arg = q;
			}
		}
	}
	return (NULL);
}

#if 0
static void
config_dump(const struct config *cfg)
{
	struct section *sc;
	struct entry *ent;

	CHECK_OBJ_NOTNULL(cfg, CONFIG_MAGIC);
	VTAILQ_FOREACH(sc, &cfg->sections, list) {
		printf("%s:\n", sc->name);
		VTAILQ_FOREACH(ent, &sc->entries, list) {
			if (ent->arg != NULL)
				printf("\t%s\t%s\n", ent->name, ent->arg);
			else
				printf("\t%s\n", ent->name);
		}
	}
}
#endif

struct config *
Config_Read(const char *fn)
{
	struct config *cfg;
	int fd;
	struct stat st;
	ssize_t ssz;
	u_char *p;
	const char *e;

	fd = open(fn, O_RDONLY);
	if (fd < 0)
		return (NULL);
	AZ(fstat(fd, &st));
	if ((st.st_mode & S_IFMT) != S_IFREG) {
		AZ(close(fd));
		errno = EINVAL;
		return (NULL);
	}
	ALLOC_OBJ(cfg, CONFIG_MAGIC);
	AN(cfg);
	VTAILQ_INIT(&cfg->sections);
	cfg->space = malloc(st.st_size + 1);
	AN(cfg->space);
	ssz = read(fd, cfg->space, st.st_size);
	AZ(close(fd));
	if (ssz != st.st_size) {
		config_destroy(cfg);
		errno = EIO;
		return (NULL);
	}

	/* Check file is not obviously bogus UTF-8 */
	for (p = cfg->space; p < cfg->space + st.st_size; p++) {
		if (*p == 0x00 || *p == 0xc0 || *p == 0xc1 || *p > 0xf4) {
			config_destroy(cfg);
			errno = EBADF;
			return (NULL);
		}
	}
	cfg->space[st.st_size] = '\0';
	e = config_parse(cfg);
	if (e != NULL)
		fprintf(stderr, "Config = %s\n", e);

	return (cfg);
}

int
Config_Get(const struct config *cfg, const char *section, const char **np,
    const char **ap)
{
	struct section *sc;
	struct entry *ent;

	CHECK_OBJ_NOTNULL(cfg, CONFIG_MAGIC);
	VTAILQ_FOREACH(sc, &cfg->sections, list)
		if (!strcasecmp(sc->name, section))
			break;
	if (sc == NULL)
		return (errno = ENOENT);
	if (sc->nentry != 1)
		return (errno = E2BIG);
	ent = VTAILQ_FIRST(&sc->entries);
	AZ(VTAILQ_NEXT(ent, list));
	if (np != NULL && ap == NULL && ent->arg != NULL)
		return (errno = E2BIG);
	if (np != NULL)
		*np = ent->name;
	if (ap != NULL)
		*ap = ent->arg;
	return (0);
}

int
Config_Find(const struct config *cfg, const char *section, const char *name,
    const char **ap)
{
	struct section *sc;
	struct entry *ent;

	CHECK_OBJ_NOTNULL(cfg, CONFIG_MAGIC);
	VTAILQ_FOREACH(sc, &cfg->sections, list)
		if (!strcasecmp(sc->name, section))
			break;
	if (sc == NULL)
		return (ENOENT);
	VTAILQ_FOREACH(ent, &sc->entries, list) {
		if (strcmp(ent->name, "*") && strcasecmp(name, ent->name))
			continue;
		if (ap != NULL)
			*ap = ent->arg;
		return (0);
	}
	return (ENOENT);
}

int
Config_Iter(const struct config *cfg, const char *section, void *priv,
    config_f func)
{
	struct section *sc;
	struct entry *ent;
	int i;

	CHECK_OBJ_NOTNULL(cfg, CONFIG_MAGIC);
	VTAILQ_FOREACH(sc, &cfg->sections, list)
		if (!strcasecmp(sc->name, section))
			break;
	if (sc == NULL)
		return (errno = ENOENT);
	if (sc->nentry == 0)
		return (errno = ENOENT);
	VTAILQ_FOREACH(ent, &sc->entries, list) {
		i = func(priv, ent->name, ent->arg);
		if (i)
			return (i);
	}
	return (0);
}
