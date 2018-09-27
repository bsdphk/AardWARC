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

#include "vqueue.h"

struct vsb;
struct getjob;
struct config;
struct rsilo;
struct wsilo;
struct header;
struct segjob;

/*
 * An instance of an aardwarc store
 */

struct aardwarc {
	unsigned		magic;
#define AARDWARC_MAGIC		0x50136925

	/* Arguments */
	int			json;

	/* From Configuration */
	struct config		*cfg;
	const char		*prefix;
	const char		*silo_dirname;
	const char		*silo_basename;
	off_t			silo_maxsize;
	const char		*mime_validator;
	unsigned		id_size;

	size_t			index_sort_size;

	uint32_t		cache_first_non_silo;
	uint32_t		cache_first_space_silo;
};

/* A general iterator for walking over bytes */
typedef int byte_iter_f(void *priv, const void *ptr, ssize_t len);

/* aardwarc.c */
struct aardwarc *AardWARC_New(const char *config_file, struct vsb *err);
void AardWARC_ReadCache(struct aardwarc *aa);
void AardWARC_WriteCache(const struct aardwarc *aa);

/* config.c */

struct config *Config_Read(const char *fn);
int Config_Get(const struct config *, const char *section, const char **np,
    const char **ap);

typedef int config_f(void *priv, const char *name, const char *arg);

int Config_Iter(const struct config *, const char *section, void *priv,
    config_f func);
int Config_Find(const struct config *, const char *section, const char *name,
    const char **ap);

/* getjob.c */

struct getjob *GetJob_New(struct aardwarc *, const char *id, struct vsb *);
void GetJob_Delete(struct getjob **);
const struct header *GetJob_Header(const struct getjob *, int first);
void GetJob_Iter(const struct getjob *, byte_iter_f *func, void *priv,
    int gzip);
off_t GetJob_TotalLength(const struct getjob *, int gzip);
int GetJob_IsSegmented(const struct getjob *);
struct vsb *GetJob_Headers(const struct getjob *);

/* gzip.c */

void Gzip_Vsb(struct vsb **, int level);
extern const uint8_t Gzip_crnlcrnl[24];

/* header.c */

struct header *Header_New(const struct aardwarc *);
void Header_Delete(struct header **hdp);
struct header *Header_Clone(const struct header *hd);
void Header_Set(struct header *, const char *name, const char *val, ...)
    __v_printflike(3, 4);
struct vsb *Header_Serialize(const struct header *, int level);
const char *Header_Get_Id(const struct header *);
intmax_t Header_Get_Number(const struct header *, const char *);
void Header_Set_Id(struct header *, const char *);
void Header_Set_Date(struct header *);
void Header_Set_Ref(struct header *, const char *name, const char *ref);
struct header *Header_Parse(const struct aardwarc *, char *);
const char *Header_Get(const struct header *, const char *name);

/* index.c */

void IDX_Insert(const struct aardwarc *aa, const char *key, uint32_t flags,
    uint32_t silo, uint64_t offset, const char *cont);

typedef int idx_iter_f(void *priv, const char *key,
    uint32_t flag, uint32_t silo, uint64_t offset, const char *cont);

int IDX_Iter(const struct aardwarc *aa, const char *key_part,
    idx_iter_f *func, void *priv);

void IDX_Resort(const struct aardwarc *aa);

const char *IDX_Valid_Id(const struct aardwarc *,
    const char *id, const char **nid);

/* bottom nibble: type */
/* 0 -> continuation */
#define IDX_F_WARCINFO		(1 << 1)
#define IDX_F_RESOURCE		(1 << 2)
#define IDX_F_METADATA		(1 << 3)

/* next nibble: segmentation */
#define IDX_F_SEGMENTED		(1 << 4)
#define IDX_F_FIRSTSEG		(1 << 5)
#define IDX_F_LASTSEG		(1 << 6)

/* proto.c */

int proto_in(int fd, unsigned *cmd, unsigned *len);
int proto_out(int fd, unsigned cmd, const void *ptr, size_t len);
void proto_send_msg(int fd, const char *fmt, ...) __v_printflike(2,3);

typedef void proto_ev_func_f(int fd, void *priv, int revents);
uintptr_t proto_add_ev(int fd, short events, proto_ev_func_f *func, void *priv);
void proto_del_ev(uintptr_t *id);
void proto_ctl_ev(uintptr_t id, int enable);
void proto_dispatch_evs(void);

#define PROTO_MSG	0
#define PROTO_FILTER	1
#define PROTO_DATA	2
#define PROTO_META	3

#define STOW_META	"application/json"

/* segment.c */

struct segjob *SegJob_New(struct aardwarc *, struct header *);
void SegJob_Feed(struct segjob *, const void *ptr, ssize_t len);
char *SegJob_Commit(struct segjob *);

/* silo.c */
struct vsb *Silo_Filename(const struct aardwarc *, unsigned number, int hold);
int Silo_Iter(const struct aardwarc *, byte_iter_f *func, void *priv);

/* silo_read.c */
struct rsilo *Rsilo_Open(struct aardwarc *, const char *fn, uint32_t nsilo);
void Rsilo_Close(struct rsilo **);
struct header *Rsilo_ReadHeader(const struct rsilo *);
uintmax_t Rsilo_ReadChunk(const struct rsilo *, byte_iter_f *func, void *priv);
int Rsilo_ReadGZChunk(const struct rsilo *, off_t len, byte_iter_f *func,
    void *priv);
void Rsilo_Seek(const struct rsilo *, uint64_t o);
off_t Rsilo_Tell(const struct rsilo *);
void Rsilo_SkipCRNL(const struct rsilo *rs);

/* silo_write.c */
struct wsilo *Wsilo_New(struct aardwarc *);
void Wsilo_GetSpace(const struct wsilo *, void **ptr, ssize_t *len);
int Wsilo_Store(struct wsilo *, ssize_t len);
void Wsilo_Finish(struct wsilo *);
void Wsilo_Header(struct wsilo *, struct header *, int pad);
void Wsilo_Commit(struct wsilo **, int segd, const char *id, const char *rid);
void Wsilo_Abandon(struct wsilo **);

/* vnum.c */
const char *VNUM_2bytes(const char *p, uintmax_t *r, uintmax_t rel);

/* warcinfo.c */
char *Warcinfo_New(const struct aardwarc *, struct wsilo *, uint32_t silono);

/* main*c */

void usage(const char *a0, const char *err);
int call_main(const char *a0, struct aardwarc *aa, int argc, char **argv);
typedef int main_f(const char *a0, struct aardwarc *,
    int argc, char **argv);
extern main_f main_audit;
extern main_f main_byid;
extern main_f main_cgi;
extern main_f main_dumpindex;
extern main_f main_filter;
extern main_f main_get;
extern main_f main_housekeeping;
extern main_f main_info;
extern main_f main_reindex;
extern main_f main_stevedore;
extern main_f main_store;
extern main_f main_stow;
extern main_f main__testbytes;
