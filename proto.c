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
 * The stow/stevedore protocol is really simple:
 *
 *	+--+--+--+--+--+--+--+--+
 *	|Size |Reserved|Command |
 *	+--+--+--+--+--+--+--+--+
 *
 *	Size:
 *		0	zero bytes
 *		1	32 bytes
 *		2	be8 length
 *		3	be32 length
 *
 *	Cmd:
 *		0	Debug message
 *		1	sha256 for filtering
 *		2	send file
 *		3	metadata
 *
 */

#include "vdef.h"

#include <poll.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/endian.h>
#include <sys/uio.h>

#include "vas.h"
#include "vsb.h"
#include "miniobj.h"

#include "aardwarc.h"

struct ev {
	unsigned		magic;
#define EV_MAGIC		0xff6b684d
	int			fd;
	int			idx;
	int			enable;
	short			events;
	proto_ev_func_f		*func;
	void			*priv;
	VTAILQ_ENTRY(ev)	list;
};

static VTAILQ_HEAD(,ev)		evs = VTAILQ_HEAD_INITIALIZER(evs);
static int			nevs;

uintptr_t
proto_add_ev(int fd, short events, proto_ev_func_f *func, void *priv)
{
	struct ev *ev;

	ALLOC_OBJ(ev, EV_MAGIC);
	AN(ev);
	ev->fd = fd;
	ev->events = events;
	ev->func = func;
	ev->priv = priv;
	ev->enable = 1;
	ev->idx = -1;
	VTAILQ_INSERT_TAIL(&evs, ev, list);
	nevs++;
	return (uintptr_t)ev;
}

void
proto_del_ev(uintptr_t *id)
{
	struct ev *ev;

	VTAILQ_FOREACH(ev, &evs, list) {
		if (*id == (uintptr_t)ev)
			break;
	}
	CHECK_OBJ_NOTNULL(ev, EV_MAGIC);
	VTAILQ_REMOVE(&evs, ev, list);
	AZ(close(ev->fd));
	FREE_OBJ(ev);
	*id = 0;
}

void
proto_ctl_ev(uintptr_t id, int enable)
{
	struct ev *ev;

	VTAILQ_FOREACH(ev, &evs, list) {
		if (id == (uintptr_t)ev)
			break;
	}
	CHECK_OBJ_NOTNULL(ev, EV_MAGIC);
	ev->enable = enable;
}

void
proto_dispatch_evs(void)
{
	struct pollfd *fds = NULL;
	int nfds = 0, idx, i;
	struct ev *ev, *ev2;

	while (!VTAILQ_EMPTY(&evs)) {
		if (nfds < nevs) {
			fds = realloc(fds, sizeof *fds * nevs);
			nfds = nevs;
		}
		AN(fds);
		memset(fds, 0, sizeof *fds * nfds);
		idx = 0;
		VTAILQ_FOREACH(ev, &evs, list) {
			if (!ev->enable) {
				ev->idx = -1;
				continue;
			}
			fds[idx].fd = ev->fd;
			fds[idx].events = ev->events;
			ev->idx = idx++;
		}
		AN(idx);
		i = poll(fds, idx, -1);
		assert (i > 0);
		VTAILQ_FOREACH_SAFE(ev, &evs, list, ev2) {
			if (ev->idx < 0 || !fds[ev->idx].revents)
				continue;
			ev->func(ev->fd, ev->priv, fds[ev->idx].revents);
		}
	}
	free(fds);
}

int
proto_in(int fd, unsigned *cmd, unsigned *len)
{
	uint8_t u[129];
	ssize_t i;

	assert (fd >= 0);
	AN(cmd);
	AN(len);

	i = read(fd, u, 1);
	if (i == 0)
		return (0);
	if (i != 1)
		return (-1);
	*cmd = u[0] & 7;
	switch(u[0] >> 6) {
	case 0:
		*len = 0;
		break;
	case 1:
		*len = 32;
		break;
	case 2:
		i = read(fd, u + 1, 1);
		if (i != 1)
			return (-1);
		*len = u[1];
		break;
	case 3:
		i = read(fd, u + 1, 4);
		if (i != 4)
			return (-1);
		*len = be32dec(u + 1);
		break;
	default:
		WRONG("Cannot happen");
	}
	return (1);
}

int
proto_out(int fd, unsigned cmd, const void *ptr, size_t len)
{
	uint8_t u[5];
	struct iovec iov[2];
	ssize_t sz;

	assert(fd >= 0);
	AZ(cmd & ~7);
	if (len > 0)
		AN(ptr);

	iov[0].iov_base = u;
	iov[0].iov_len = 1;
	iov[1].iov_base = (void*)(uintptr_t)ptr;
	iov[1].iov_len = len;

	u[0] = (uint8_t)cmd;
	if (len == 0) {
	} else if (len == 32) {
		u[0] |= 1 << 6;
	} else if (len < 256) {
		u[0] |= 2 << 6;
		u[1] = (uint8_t)len;
		iov[0].iov_len += 1;
	} else {
		u[0] |= 3 << 6;
		be32enc(u + 1, len);
		iov[0].iov_len += 4;
	}
	sz = writev(fd, iov, len == 0 ? 1 : 2);
	if (sz < 0)
		return (-1);
	if ((size_t)sz != iov[0].iov_len + iov[1].iov_len)
		return (-1);
	return (0);
}

void
proto_send_msg(int fd, const char *fmt, ...)
{
	va_list ap;
	struct vsb *vsb;

	vsb = VSB_new_auto();
	AN(vsb);
	va_start(ap, fmt);
	VSB_vprintf(vsb, fmt, ap);
	va_end(ap);
	AZ(VSB_finish(vsb));
	AZ(proto_out(fd, 0, VSB_data(vsb), VSB_len(vsb)));
}


