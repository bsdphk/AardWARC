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

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sha256.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <vis.h>
#include <sys/endian.h>
#include <sys/wait.h>

#include "vas.h"
#include "vsb.h"
#include "miniobj.h"

#include "aardwarc.h"

struct dir {
	unsigned		magic;
#define DIR_MAGIC		0x788342a5
	char			*dirname;
	VTAILQ_ENTRY(dir)	list;
	struct dir		*parent;
};

static VTAILQ_HEAD(,dir)	dir_list = VTAILQ_HEAD_INITIALIZER(dir_list);

struct subj {
	unsigned		magic;
#define SUBJ_MAGIC		0x312859a4
	char			*filename;
	char			*digest;
	struct dir		*directory;
	VTAILQ_ENTRY(subj)	list;
};

static VTAILQ_HEAD(,subj)	subj_list = VTAILQ_HEAD_INITIALIZER(subj_list);
static VTAILQ_HEAD(,subj)	wait_list = VTAILQ_HEAD_INITIALIZER(wait_list);
static VTAILQ_HEAD(,subj)	get_list = VTAILQ_HEAD_INITIALIZER(get_list);
static VTAILQ_HEAD(,subj)	ack_list = VTAILQ_HEAD_INITIALIZER(ack_list);

static pid_t ssh_pid;
static uintptr_t stevedore_0_ev;
static uintptr_t stevedore_1_ev;
static uintptr_t stevedore_2_ev;

#define VARTBL \
	MX(directory) \
	MX(remote) \
	MX(cmd) \
	MX(exclude)

struct stow_job {
	unsigned		magic;
#define STOW_JOB_MAGIC		0xc7fcee95
	VTAILQ_ENTRY(stow_job)	list;
#define MX(n) const char	*c_##n;
	VARTBL
#undef MX
	const char		*job;
	int			target_dir;
	size_t			id_size;

	pid_t			mtree_pid;
	FILE *			mtree_tmp;
	char			mtree_buf[8192];
	uintptr_t		mtree_ev;
	SHA256_CTX		mtree_sha;

	struct subj		*meta;

	FILE *			missing;
	FILE *			changed;
};

static VTAILQ_HEAD(,stow_job)	job_list = VTAILQ_HEAD_INITIALIZER(job_list);

/**********************************************************************/

static char mtree_path[4096];
static int mtree_type_dir;
static struct dir *pwd;
static int send_fd = -1;

static void
mtree_interpret(char *line)
{
	char *word, *w0;
	char *p, *digest;
	int dir = mtree_type_dir;
	struct dir *dp = NULL;
	struct subj *cp;

	while (isspace(*line))
		line++;
	word = strsep(&line, " \t");
	if (*word == '\0')
		return;
	if (!strcmp(word, "/set")) {
		while ((word = strsep(&line, " \t")) != NULL) {
			if (!strcmp(word, "type=dir"))
				mtree_type_dir = 1;
			else if (!strcmp(word, "type=file"))
				mtree_type_dir = 0;
		}
	} else if (!strcmp(word, "..")) {
		p = strrchr(mtree_path, '/');
		if (p == NULL)
			p = mtree_path;
		*p = '\0';
		AN(pwd);
		pwd = pwd->parent;
	} else {
		w0 = word;
		digest = NULL;
		while ((word = strsep(&line, " \t")) != NULL) {
			if (!strcmp(word, "type=dir"))
				dir = 1;
			else if (!strcmp(word, "type=file"))
				dir = 0;
			else if (!strncmp(word, "type=", 5))
				return;
			else if (!strncmp(word, "sha256digest=", 13)) {
				/* SHA256 of zero bytes */
				if (!strcmp(word + 13,
				    "e3b0c44298fc1c149afbf4c8996fb924"
				    "27ae41e4649b934ca495991b7852b855"))
					return;
				digest = word + 13;
			}
		}
		if (!dir) {
			// printf("F %s %s %s\n", digest, pwd->dirname, w0);
			AN(pwd);
			AN(digest);
			ALLOC_OBJ(cp, SUBJ_MAGIC);
			AN(cp);
			cp->directory = pwd;
			cp->filename = strdup(w0);
			AN(cp->filename);
			cp->digest = strdup(digest);
			AN(cp->digest);
			VTAILQ_INSERT_TAIL(&subj_list, cp, list);
			proto_ctl_ev(stevedore_0_ev, 1);
		} else {
			strcat(mtree_path, "/");
			strcat(mtree_path, w0);
			// printf("D %s\n", mtree_path + 1);
			ALLOC_OBJ(dp, DIR_MAGIC);
			AN(dp);
			dp->dirname = strdup(mtree_path + 1);
			AN(dp->dirname);
			dp->parent = pwd;
			pwd = dp;
			VTAILQ_INSERT_TAIL(&dir_list, dp, list);
		}
	}
}

static void
mtree_process(struct stow_job *sj)
{
	char *p, *b;

	b = sj->mtree_buf;
	while (1) {
		p = strchr(b, '\n');
		if (p == NULL)
			break;
		if (p == b)
			b++;
		else if (p[-1] == '\\') {
			p[-1] = ' ';
			p[0] = ' ';
		} else {
			p[0] = '\0';
			mtree_interpret(b);
			b = p + 1;
		}
	}
	memmove(sj->mtree_buf, b, strlen(b) + 1);
}

static void __match_proto__(proto_ev_func_f)
mtree_in(int fd, void *priv, int revents)
{
	char *p;
	ssize_t i;
	size_t j;
	pid_t pid;
	int st;
	struct subj *cp;
	struct stow_job *sj;

	CAST_OBJ_NOTNULL(sj, priv, STOW_JOB_MAGIC);
	(void)revents;

	p = strchr(sj->mtree_buf, '\0');
	AN(p);
	i = read(fd, p, (sj->mtree_buf + sizeof sj->mtree_buf - 1) - p);
	assert(i >= 0);
	if (i > 0) {
		SHA256_Update(&sj->mtree_sha, p, i);
		j = fwrite(p, 1, i, sj->mtree_tmp);
		assert(j == (size_t)i);
		p[i] = '\0';
		mtree_process(sj);
		return;
	}
	pid = wait4(sj->mtree_pid, &st, WEXITED, NULL);
	assert(pid == sj->mtree_pid);
	AZ(st);
	printf("MTREE END\n");
	proto_del_ev(&sj->mtree_ev);

	ALLOC_OBJ(cp, SUBJ_MAGIC);
	AN(cp);
	cp->digest = SHA256_End(&sj->mtree_sha, NULL);
	AN(cp->digest);
	VTAILQ_INSERT_TAIL(&subj_list, cp, list);

	ALLOC_OBJ(cp, SUBJ_MAGIC);
	AN(cp);
	cp->digest = strdup("");
	AN(cp->digest);
	VTAILQ_INSERT_TAIL(&subj_list, cp, list);

	proto_ctl_ev(stevedore_0_ev, 1);
}

static void
start_mtree(struct stow_job *sj)
{
	pid_t pid;
	int fd;
	int fdo[2];

	AZ(pipe(fdo));
	pid = fork();
	if (!pid) {
		fd = open("/dev/null", O_RDONLY);
		assert(fd > 0);
		assert(dup2(fd, 0) == 0);
		AZ(close(fdo[0]));
		assert(dup2(fdo[1], 1) == 1);
		closefrom(3);
		AZ(execlp("mtree",
		    "mtree",
		    "-n",
		    "-c",
		    "-Ksha256digest",
		    "-j",
		    "-p",
		    sj->c_directory,
		    sj->c_exclude == NULL ? NULL : "-X",
		    sj->c_exclude == NULL ? NULL : sj->c_exclude,
		    NULL));
		exit(2);
	}
	assert(pid > 0);
	sj->mtree_pid = pid;
	AZ(close(fdo[1]));
	sj->mtree_tmp = tmpfile();
	AN(sj->mtree_tmp);
	SHA256_Init(&sj->mtree_sha);
	sj->mtree_ev = proto_add_ev(fdo[0], POLLIN, mtree_in, sj);
}

/**********************************************************************/

static void __match_proto__(proto_ev_func_f)
diag(int fd, void *priv, int revents)
{
	char buf[1024];
	ssize_t i;

	(void)priv;
	(void)revents;
	i = read(fd, buf, sizeof buf - 1);
	if (i > 0) {
		buf[i] = '\0';
		fprintf(stderr, "DIAG: <%s>\n", buf);
	} else {
		proto_del_ev(&stevedore_2_ev);
	}
	return;
}

/**********************************************************************/

static void
metadata(struct stow_job *sj, struct subj *cp)
{
	sj->meta = cp;
	proto_ctl_ev(stevedore_0_ev, 1);
}

static void
metafile(const struct stow_job *sj, int fd, struct vsb *vsb, FILE *f)
{
	char buf[BUFSIZ];
	size_t sz;

	AZ(fseeko(sj->changed, 0, SEEK_SET));
	AZ(VSB_finish(vsb));
	AZ(proto_out(fd, PROTO_META, VSB_data(vsb), VSB_len(vsb)));
	VSB_clear(vsb);
	(void)fgetc(f);
	(void)fgetc(f);
	do {
		sz = fread(buf, 1, sizeof buf, f);
		if (sz > 0)
			AZ(proto_out(fd, PROTO_META, buf, sz));
	} while (sz > 0);
}

static void
send_metadata(struct stow_job *sj, int fd)
{
	struct vsb *vsb;
	time_t t;

	AZ(proto_out(fd, PROTO_META,
	    sj->meta->digest, strlen(sj->meta->digest)));

	vsb = VSB_new_auto();
	AN(vsb);

	VSB_printf(vsb, "[\n    \"STOW3.0\",\n    {\n");

	fflush(sj->changed);
	if (ftello(sj->changed) > 0) {
		VSB_printf(vsb, "\t\"changed\": {\n");
		metafile(sj, fd, vsb, sj->changed);
		VSB_printf(vsb, "\n\t},\n");
	}
	AZ(fclose(sj->changed));

	fflush(sj->missing);
	if (ftello(sj->missing) > 0) {
		VSB_printf(vsb, "\t\"missing\": {\n");
		metafile(sj, fd, vsb, sj->missing);
		VSB_printf(vsb, "\n\t},\n");
	}
	AZ(fclose(sj->missing));

	VSB_printf(vsb, "\t\"mtree\": \"sha256:%s\",\n", sj->meta->digest);
	VSB_printf(vsb, "\t\"target\": \"%s\",\n", sj->job);
	(void)time(&t);
	VSB_printf(vsb, "\t\"time\": %jd\n", (intmax_t)t);
	VSB_printf(vsb, "    }\n]\n");

	AZ(VSB_finish(vsb));
	AZ(proto_out(fd, PROTO_META, VSB_data(vsb), VSB_len(vsb)));
	AZ(proto_out(fd, PROTO_META, NULL, 0));
	sj->meta = NULL;
}

/**********************************************************************/

static void
subj_flush(struct stow_job *sj, struct subj *cp)
{
	CHECK_OBJ_NOTNULL(cp, SUBJ_MAGIC);
	VTAILQ_REMOVE(&wait_list, cp, list);
	if (cp->directory == NULL && *cp->digest != '\0') {
		metadata(sj, cp);
		return;
	}
	if (cp->digest != NULL) {
		free(cp->filename);
		free(cp->digest);
	}
	FREE_OBJ(cp);
}

static void
filter_resp(struct stow_job *sj, uint8_t *p, size_t len)
{
	uint32_t u;
	struct subj *cp;

	if (len == 0) {
		while (1) {
			cp = VTAILQ_FIRST(&wait_list);
			if (cp == NULL)
				break;
			subj_flush(sj, cp);
		}
	} else if (len == 4) {
		u = be32dec(p);
		while (u > 0) {
			cp = VTAILQ_FIRST(&wait_list);
			CHECK_OBJ_NOTNULL(cp, SUBJ_MAGIC);
			subj_flush(sj, cp);
			u--;
		}
	} else if (len >= 16 && len <= 64) {
		if (sj->id_size != len)
			printf("IDSIZE %zu (%zu)\n", len, sj->id_size);
		sj->id_size = len;
		p[len] = '\0';
		while (1) {
			cp = VTAILQ_FIRST(&wait_list);
			CHECK_OBJ_NOTNULL(cp, SUBJ_MAGIC);
			if (!memcmp(cp->digest, p, len)) {
				if (cp->directory == NULL)
					printf("get\t${MTREE}\n");
				else
					printf("get\t%s/%s\n",
					    cp->directory->dirname,
					    cp->filename);
				VTAILQ_REMOVE(&wait_list, cp, list);
				VTAILQ_INSERT_TAIL(&get_list, cp, list);
				break;
			}
			subj_flush(sj, cp);
		}
	} else {
		WRONG("Wrong 1-cmd");
	}
	AN(stevedore_0_ev);
	proto_ctl_ev(stevedore_0_ev, 1);
}

static void
data_resp(struct stow_job *sj, char *p, size_t len)
{
	struct subj *cp;
	char *pp;

	(void)p;
	(void)len;
	cp = VTAILQ_FIRST(&ack_list);
	CHECK_OBJ_NOTNULL(cp, SUBJ_MAGIC);
	pp = strrchr(p, '/');
	AN(pp);
	pp++;
	if (cp->directory == NULL && *cp->digest != '\0') {
		if (strncmp(cp->digest, pp, strlen(pp))) {
			// XXX: debug
			fprintf(stderr, "HERE %s %d\n\t%s\n\t%s\n",
				__func__, __LINE__, cp->digest, pp);
		}
		AZ(strncmp(cp->digest, pp, strlen(pp)));
		metadata(sj, cp);
		return;
	}
	if (strncmp(cp->digest, pp, strlen(pp))) {
		printf("CHANGED\t %s/%s\n",
		    cp->directory->dirname, cp->filename);
		fprintf(sj->changed, ",\n");
		fprintf(sj->changed, "\t    \"sha256:%s\": \"id:%s\"",
		    cp->digest, pp);
	}
	VTAILQ_REMOVE(&ack_list, cp, list);
	free(cp->digest);
	free(cp->filename);
	FREE_OBJ(cp);
}

static void __match_proto__(proto_ev_func_f)
stevedore_in(int fd, void *priv, int revents)
{
	uint8_t u[1024];
	unsigned cmd;
	ssize_t i;
	size_t j;
	unsigned sz;
	struct stow_job *sj;

	CAST_OBJ_NOTNULL(sj, priv, STOW_JOB_MAGIC);
	(void)revents;

	i = proto_in(fd, &cmd, &sz);
	if (i == 0) {
		fprintf(stderr, "EOF STEVEDORE\n");
		proto_del_ev(&stevedore_1_ev);
		return;
	}
	assert(i == 1);
	assert (sz < sizeof u);
	j = 0;
	while (sz > 0) {
		i = read(fd, u + j, sz);
		assert(i > 0);
		sz -= i;
		j += i;
	}
	u[j] = '\0';

	switch (cmd) {
	case PROTO_MSG:
		printf("MSG: <%s>\n", u);
		break;
	case PROTO_FILTER:
		filter_resp(sj, u, j);
		break;
	case PROTO_DATA:
		data_resp(sj, (char*)u, j);
		break;
	case PROTO_META:
		fprintf(stderr, "STOWED as %s\n", (char*)u);
		proto_del_ev(&stevedore_0_ev);
		break;
	default:
		fprintf(stderr, "RX? %u(%zu)\n", cmd, j);
		exit(2);
	}
}

static void __match_proto__(proto_ev_func_f)
stevedore_out(int fd, void *priv, int revents)
{
	struct subj *cp;
	ssize_t i;
	size_t j;
	char buf[128*1024];
	struct stow_job *sj;

	CAST_OBJ_NOTNULL(sj, priv, STOW_JOB_MAGIC);
	(void)revents;
	for (i = 0; i < 10; i++) {
		cp = VTAILQ_FIRST(&subj_list);
		if (cp == NULL)
			break;
		VTAILQ_REMOVE(&subj_list, cp, list);
		VTAILQ_INSERT_TAIL(&wait_list, cp, list);
		j = strlen(cp->digest);
		if (j > sj->id_size)
			j = sj->id_size;
		AZ(proto_out(fd, PROTO_FILTER, cp->digest, j));
	}
	if (send_fd > 0) {
		i = read(send_fd, buf, sizeof buf);
		assert(i >= 0);
		AZ(proto_out(fd, PROTO_DATA, buf, i));
		if (i > 0)
			return;
		assert(send_fd > 2);
		AZ(close(send_fd));
		send_fd = -1;
	}
	if (!VTAILQ_EMPTY(&subj_list))
		return;

	cp = VTAILQ_FIRST(&get_list);
	if (cp != NULL) {
		AN(cp);
		VTAILQ_REMOVE(&get_list, cp, list);
		VTAILQ_INSERT_TAIL(&ack_list, cp, list);
		if (cp->directory == NULL) {
			fflush(sj->mtree_tmp);
			send_fd = fileno(sj->mtree_tmp);
			(void)lseek(send_fd, 0, SEEK_SET);
			printf("SEND\t${MTREE}\n");
			return;
		}
		assert(strnunvis(buf, sizeof buf, cp->directory->dirname) > 0);
		strcat(buf, "/");
		assert(strnunvis(strchr(buf, '\0'),
		    sizeof buf, cp->filename) > 0);
		printf("SEND\t%s\n", buf);
		send_fd = openat(sj->target_dir, buf, O_RDONLY);
		if (send_fd < 0) {
			fprintf(stderr, "Cannot open: %s/%s: %s\n",
			    cp->directory->dirname, cp->filename,
			    strerror(errno));
			fprintf(sj->missing, ",\n");
			fprintf(sj->missing, "\t    \"sha256:%s\": \"%s\"",
			    cp->digest, strerror(errno));
			VTAILQ_REMOVE(&get_list, cp, list);
			/* XXX handle cp */
			exit(2);
		}
	}
	if (sj->meta != NULL) {
		send_metadata(sj, fd);
		AN(stevedore_0_ev);
		proto_ctl_ev(stevedore_0_ev, 0);
		return;
	}
}

static void
start_stevedore(struct stow_job *sj)
{
	pid_t pid;
	int fdi[2];
	int fdo[2];
	int fde[2];

	AZ(pipe(fdi));
	AZ(pipe(fdo));
	AZ(pipe(fde));
	pid = fork();
	if (!pid) {
		AZ(close(fdi[1]));
		assert(dup2(fdi[0], 0) == 0);
		AZ(close(fdo[0]));
		assert(dup2(fdo[1], 1) == 1);
		AZ(close(fde[0]));
		assert(dup2(fde[1], 2) == 2);
		closefrom(3);
		if (sj->c_remote != NULL)
			AZ(execlp("ssh", "ssh", "-C",
			    sj->c_remote, sj->c_cmd, NULL));
		else
			AZ(execlp("/bin/sh", "/bin/sh", "-c", sj->c_cmd, NULL));
		exit(2);
	}
	assert(pid > 0);
	ssh_pid = pid;
	AZ(close(fdi[0]));
	AZ(close(fdo[1]));
	AZ(close(fde[1]));
	stevedore_0_ev = proto_add_ev(fdi[1], POLLOUT, stevedore_out, sj);
	proto_ctl_ev(stevedore_0_ev, 0);
	stevedore_1_ev = proto_add_ev(fdo[0], POLLIN, stevedore_in, sj);
	stevedore_2_ev = proto_add_ev(fde[0], POLLIN, diag, NULL);
}

/**********************************************************************/

static void
usage_stow(const char *a0, const char *a00, const char *err)
{
	usage(a0, err);
	fprintf(stderr, "Usage for this operation:\n");
	fprintf(stderr, "\t%s [global options] %s\n", a0, a00);
}

static int __match_proto__(config_f)
arg_iter(void *priv, const char *name, const char *arg)
{
	struct stow_job *sj;

	CAST_OBJ_NOTNULL(sj, priv, STOW_JOB_MAGIC);
#define MX(n) if (!strcmp(#n, name)) { sj->c_##n = arg; return (0); }
	VARTBL;
#undef MX
	fprintf(stderr, "Job %s has unknown config '%s'\n", sj->job, name);
	return (EINVAL);
}


int __match_proto__(main_f)
main_stow(const char *a0, struct aardwarc *aa, int argc, char **argv)
{
	const char *a00 = *argv;
	int ch;
	int st;
	pid_t pid;
	char buf[BUFSIZ];
	struct stow_job *sj;

	CHECK_OBJ_NOTNULL(aa, AARDWARC_MAGIC);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	while ((ch = getopt(argc, argv, "c:d:hr:")) != -1) {
		switch(ch) {
		case 'h':
			usage_stow(a0, a00, NULL);
			exit(1);
		default:
			usage_stow(a0, a00, "Unknown option error.");
			exit(1);
		}
	}
	argc -= optind;
	argv += optind;
	if (argc == 0) {
		usage_stow(a0, a00, "Must specify stow target(s).");
		exit(1);
	}
	for (; argc > 0; argc--,argv++) {
		ALLOC_OBJ(sj, STOW_JOB_MAGIC);
		AN(sj);
		sj->job = *argv;
		sj->id_size = 64;
		sj->missing = tmpfile();
		AN(sj->missing);
		sj->changed = tmpfile();
		AN(sj->changed);
		bprintf(buf, "stow.%s", *argv);
		ch = Config_Iter(aa->cfg, buf, sj, arg_iter);
		if (ch == ENOENT) {
			fprintf(stderr,
			    "Cannot find %s in config file\n", buf);
			exit(1);
		}
		if (ch == EINVAL)
			exit(1);
		if (ch != 0) {
			fprintf(stderr,
			    "Job %s had config error %d\n", *argv, errno);
			exit(1);
		}
		if (sj->c_directory == NULL) {
			fprintf(stderr,
			    "Job %s have no directory config\n", *argv);
			exit(1);
		}
		sj->target_dir = open(sj->c_directory, O_RDONLY);
		if (sj->target_dir < 0) {
			fprintf(stderr,
			    "Cannot open target directory for job %s:\n"
			    "  %s: %s\n",
			    *argv, sj->c_directory, strerror(errno));
			exit(1);
		}

		VTAILQ_INSERT_TAIL(&job_list, sj, list);
	}

	VTAILQ_FOREACH(sj, &job_list, list) {
		CHECK_OBJ_NOTNULL(sj, STOW_JOB_MAGIC);
		fprintf(stderr, "Starting job %s\n", sj->job);

		start_stevedore(sj);
		start_mtree(sj);

		proto_dispatch_evs();

		pid = wait4(ssh_pid, &st, WEXITED, NULL);
		assert(pid == ssh_pid);
		if (st != 0)
			printf("SSH status 0x%x\n", st);
		AZ(st);

		fprintf(stderr, "Done job %s\n", sj->job);
	}
	return (0);
}
