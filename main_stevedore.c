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

#include <poll.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/endian.h>
#include <sys/wait.h>

#include "vas.h"
#include "vlu.h"
#include "miniobj.h"

#include "aardwarc.h"

struct job;

typedef int job_func(struct job *);

struct job {
	unsigned		magic;
#define JOB_MAGIC		0x231a1d7e
	pid_t			pid;
	int			fd_to;
	int			fd_fm;
	uintptr_t		ev;
	struct vlu		*vlu;
	job_func		*func_end;
	unsigned		filter_skip;
};

static struct job *filter_job;
static struct job *store_job;
static struct job *meta_job;

struct filter {
	unsigned		magic;
#define FILTER_MAGIC		0x792f10e0
	char			id[64 + 2];
	VTAILQ_ENTRY(filter)	list;
};

static VTAILQ_HEAD(, filter)	filter_queue =
    VTAILQ_HEAD_INITIALIZER(filter_queue);

static uintptr_t stdin_ev;
static const char *g_a0;
static struct aardwarc *g_aa;

static void start_filter(void);

/**********************************************************************/

static void __match_proto__(proto_ev_func_f)
job_ev(int fd, void *priv, int revents)
{
	int i;
	struct job *jp;

	(void)revents;
	CAST_OBJ_NOTNULL(jp, priv, JOB_MAGIC);

	i = VLU_Fd(fd, jp->vlu);
	if (i != 0) {
		proto_del_ev(&jp->ev);
		(void)jp->func_end(jp);
	}
}

#define MAX_ARG 20
static struct job *
job_start(vlu_f *line, job_func *eof, ...)
{
	char *av[MAX_ARG];
	int ac = 0;
	va_list ap;
	const char *p;
	int fdi[2];
	int fdo[2];
	struct job *jp;

	AZ(pipe(fdi));
	AZ(pipe(fdo));
	ALLOC_OBJ(jp, JOB_MAGIC);
	AN(jp);
	jp->pid = fork();
	if (!jp->pid) {
		va_start(ap, eof);
		do {
			p = va_arg(ap, const char *);
			if (p != NULL) {
				av[ac] = strdup(p);
				AN(av[ac]);
				ac++;
				assert(ac < MAX_ARG);
			}
		} while (p != NULL);
		va_end(ap);

		AZ(close(fdi[1]));
		assert(0 == dup2(fdi[0], 0));
		AZ(close(fdo[0]));
		assert(1 == dup2(fdo[1], 1));
		exit(call_main(g_a0, g_aa, ac, av));
	}
	assert(jp->pid > 0);
	AZ(close(fdi[0]));
	AZ(close(fdo[1]));
	jp->fd_to = fdi[1];
	jp->fd_fm = fdo[0];
	jp->vlu = VLU_New(jp, line, 256);
	AN(jp->vlu);
	jp->func_end = eof;
	jp->ev = proto_add_ev(jp->fd_fm, POLLIN, job_ev, jp);
	return (jp);
}

static void
job_end(struct job *jp)
{
	pid_t p;
	int st;

	CHECK_OBJ_NOTNULL(jp, JOB_MAGIC);

	p = wait4(jp->pid, &st, WEXITED, NULL);
	assert(p == jp->pid);
	if (st != 0)
		fprintf(stderr, "Exit status 0x%x\n", st);
	AZ(st);
	assert(jp->fd_to == -1);
	VLU_Destroy(jp->vlu);
	FREE_OBJ(jp);
}

/**********************************************************************/

static int
filter_line(void *priv, const char *line)
{
	struct job *jp;
	int i;

	CAST_OBJ_NOTNULL(jp, priv, JOB_MAGIC);
	jp->filter_skip = 0;
	i = strlen(line);
	assert(i >= 16 && i <= 64);
	AZ(proto_out(1, PROTO_FILTER, line, g_aa->id_size));
	return (0);
}

static int
filter_end(struct job *jp)
{
	uint8_t buf[4];

	CHECK_OBJ_NOTNULL(jp, JOB_MAGIC);
	filter_job = NULL;

	if (jp->filter_skip) {
		be32enc(buf, jp->filter_skip);
		AZ(proto_out(1, PROTO_FILTER, buf, sizeof buf));
	}
	job_end(jp);
	if (!VTAILQ_EMPTY(&filter_queue))
		start_filter();
	return (0);
}

static void
start_filter(void)
{
	struct filter *f;
	ssize_t i;
	unsigned n;

	while (1) {
		f = VTAILQ_FIRST(&filter_queue);
		if (f == NULL)
			return;
		if (f->id[0])
			break;
		VTAILQ_REMOVE(&filter_queue, f, list);
		FREE_OBJ(f);
		AZ(proto_out(1, PROTO_FILTER, NULL, 0));
	}
	AZ(filter_job);
	filter_job = job_start(filter_line, filter_end, "filter", "-", NULL);

	n = 0;
	AZ(VTAILQ_EMPTY(&filter_queue));
	while (!VTAILQ_EMPTY(&filter_queue)) {
		f = VTAILQ_FIRST(&filter_queue);
		if (!f->id[0])
			break;
		VTAILQ_REMOVE(&filter_queue, f, list);
		i = write(filter_job->fd_to, f->id, strlen(f->id));
		assert(i == (ssize_t)strlen(f->id));
		FREE_OBJ(f);
		if (++n == 40960)
			break;
	}
	AN(n);
	filter_job->filter_skip = n;
	AZ(close(filter_job->fd_to));
	filter_job->fd_to = -1;
}

/**********************************************************************/

static int
store_line(void *priv, const char *line)
{
	struct job *jp;

	CAST_OBJ_NOTNULL(jp, priv, JOB_MAGIC);
	AZ(proto_out(1, PROTO_DATA, line, strlen(line)));
	proto_ctl_ev(stdin_ev, 1);
	return (0);
}

static int
store_end(struct job *jp)
{
	CHECK_OBJ_NOTNULL(jp, JOB_MAGIC);

	job_end(jp);
	return (0);
}

static void
start_store(void)
{

	AZ(store_job);
	store_job = job_start(store_line, store_end, "store", "-", NULL);
}

/**********************************************************************/

static int
meta_line(void *priv, const char *line)
{
	struct job *jp;

	CAST_OBJ_NOTNULL(jp, priv, JOB_MAGIC);
	AZ(proto_out(1, PROTO_META, line, strlen(line)));
	proto_ctl_ev(stdin_ev, 1);
	return (0);
}

static int
meta_end(struct job *jp)
{
	CHECK_OBJ_NOTNULL(jp, JOB_MAGIC);

	job_end(jp);
	return (0);
}

static void
start_meta(char *ref)
{

	AZ(meta_job);
	if (strlen(ref) > g_aa->id_size)
		ref[g_aa->id_size] = '\0';
	meta_job = job_start(meta_line, meta_end,
	    "store",
	    "-t", "metadata",
	    "-m", STOW_META,
	    "-r", ref,
	    "-", NULL);
}

/**********************************************************************/

static void __match_proto__(proto_ev_func_f)
input(int fd, void *priv, int revents)
{
	uint8_t buf[8192];
	unsigned cmd, size, j;
	struct filter *fp;
	int i, i2;

	(void)priv;
	(void)revents;
	i = proto_in(fd, &cmd, &size);
	if (i == 0) {
		proto_del_ev(&stdin_ev);
		return;
	}
	if (i != 1)
		exit(42);
	switch (cmd) {
	case PROTO_MSG:
		WRONG("We don't take messages");
		break;
	case PROTO_FILTER:
		ALLOC_OBJ(fp, FILTER_MAGIC);
		AN(fp);
		VTAILQ_INSERT_TAIL(&filter_queue, fp, list);
		if (size != 0) {
			assert(size >= g_aa->id_size && size <= 64);
			j = 0;
			while (size > j) {
				i = read(0, fp->id + j, size - j);
				if (i == 0) {
					proto_del_ev(&stdin_ev);
					FREE_OBJ(fp);
					return;
				}
				j += i;
			}
			fp->id[size] = '\n';
			fp->id[size + 1L] = '\0';
		}
		if (filter_job == NULL)
			start_filter();
		break;
	case PROTO_DATA:
		if (size == 0) {
			AN(store_job);
			AZ(close(store_job->fd_to));
			store_job->fd_to = -1;
			store_job = NULL;
			/*
			 * We must preserve order, prevet new objects from
			 * being created until this one is stowed.
			 */
			proto_ctl_ev(stdin_ev, 0);
		} else {
			if (store_job == NULL)
				start_store();
			AN(store_job);
			while (size > 0) {
				if (size < sizeof buf)
					i = read(0, buf, size);
				else
					i = read(0, buf, sizeof buf);
				if (i <= 0) {
					proto_del_ev(&stdin_ev);
					exit(3);
				}
				size -= i;
				i2 = write(store_job->fd_to, buf, i);
				assert(i2 == i);
			}
		}
		break;
	case PROTO_META:
		if (meta_job == NULL) {
			j = 0;
			assert (size + 1UL < sizeof buf);
			while (size > j) {
				i = read(0, buf + j, size - j);
				if (i == 0) {
					proto_del_ev(&stdin_ev);
					return;
				}
				j += i;
			}
			buf[size] = '\0';
			start_meta((char*)buf);
			AN(meta_job);
		} else if (size > 0) {
			AN(meta_job);
			while (size > 0) {
				if (size < sizeof buf)
					i = read(0, buf, size);
				else
					i = read(0, buf, sizeof buf);
				if (i <= 0) {
					proto_del_ev(&stdin_ev);
					exit(3);
				}
				size -= i;
				i2 = write(meta_job->fd_to, buf, i);
				assert(i2 == i);
			}
		} else {
			AN(meta_job);
			AZ(close(meta_job->fd_to));
			meta_job->fd_to = -1;
			meta_job = NULL;
		}
		break;
	default:
		proto_send_msg(1, "RX? cmd=0x%x size0x%02x", cmd, size);

		while (size > 0) {
			if (size < sizeof buf)
				i = read(0, buf, size);
			else
				i = read(0, buf, sizeof buf);
			if (i == 0)
				return;
			size -= i;
		}
		break;
	}
}

/**********************************************************************/

static void
usage_stevedore(const char *a0, const char *a00, const char *err)
{
	usage(a0, err);
	fprintf(stderr, "Usage for this operation:\n");
	fprintf(stderr, "\t%s [global options] %s\n", a0, a00);
}

int __match_proto__(main_f)
main_stevedore(const char *a0, struct aardwarc *aa,
    int argc, char **argv)
{
	const char *a00 = *argv;
	int ch, i;
	const char *p;

	setbuf(stderr, NULL);

	CHECK_OBJ_NOTNULL(aa, AARDWARC_MAGIC);
	g_a0 = a0;
	g_aa = aa;

	while ((ch = getopt(argc, argv, "h")) != -1) {
		switch (ch) {
		case 'h':
			usage_stevedore(a0, a00, NULL);
			exit(1);
		default:
			usage_stevedore(a0, a00, "Unknown option error.");
			exit(1);
		}
	}
	if (argc > optind) {
		usage_stevedore(a0, a00, "No arguments allowed.");
		exit(1);
	}

	proto_send_msg(1, "Hi there, from the stevedore");

	i = Config_Find(aa->cfg, "metadata.mime-types", STOW_META, &p);
	if (i) {
		proto_send_msg(1,
		    "Stevedore config doesn't allow %s mime-type", STOW_META);
		exit(0);
	}

	stdin_ev = proto_add_ev(0, POLLIN, input, NULL);
	proto_dispatch_evs();
	return(0);
}
