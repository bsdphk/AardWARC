#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2018, Poul-Henning Kamp <phk@FreeBSD.org>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

'''
AardWARC encrypted backup utility
=================================

Depending what you put in your AardWARC silos, you may want to encrypt
(off-site) backups.  This python script does that, in a very specific
way, focused on survivability of the collection.

Overview
--------

Every time this script is run, a number of silos will be read from
`SILODIR`, encrypted, hashed, hmac'ed and written to the `STAGING`
directory.

For each silo three files are produced:

    The encrypted silo:

	########.warc.gz.bin

    The SHA256 hash of the encrypted silo:
    (This can be used for offline integrity checks at remote sites)

	########.warc.gz.bin.sha256

    The HMAC of the encrypted silo:
    (This can be used to verify integrity of files retrieved from remote sites)

	########.warc.gz.bin.hmac
    
The files from the `STAGING` directory can be copied across the net
with rsync(1) in either push or pull mode - or with any other program
or protocol for that matter.

The `STAGING` directory is renamed into place, so rsync(1) will never
see any partially produced files.

Cryptography
------------

Encryption is done with Colin-Approved™ AES256-CTR:

	https://www.daemonology.net/blog/2009-06-24-encrypt-then-mac.html

Furthermore, the CTR mode have the important property that bit-errors
in the encrypted silo do not cascade to the rest if the silo, which
means that recovery from a damaged encrypted backup copy will contain
the damage to the directly hit WARC records.

The function `get_secrets` is responsible for returning the 256 bit
encryption key and the 128 bit IV, feel free to customize.  The default
is to read them directly from a file named `secrets.txt`, which
should contain (only!) two strings of 64 respectively 32 random
hexdigits, separated by whitespace.

One way to produce a `secret.txt` is:

	dd if=/dev/random count=1 | sha256 >  secrets.txt
	dd if=/dev/random count=1 | md5    >> secrets.txt

Scheduling
----------

A maximum of `QUOTA` bytes is scheduled for backup every time the
script is run.  This limits both the amount of disk space needed
for the `STAGING` directory (twice `QUOTA` !), and the amount of
data a remote backup site could have to download every day.

The silos to be staged are selected in order of bytes added since
last staged with time since last staged as backup criteria.

This means that silos will be offered for backup periodically, so
that remote sites starting from scratch will eventually catch up.

The information about when a silo was last encrypted and what size
it had then is cached in the file `silodates.txt`

Security Considerations
-----------------------

Obviously:  Protect the keys.

The suggested setup is:

    Silos are created with mode 0640, and their group can be used to
    grant read-only access to them.

    Make sure to set the directory group owner appropriately.

    user=stevedore, uid=700, gid=700, member of silo-read group.

	Also member of a group to get read access to the silos (if necessary).

	Runs this script, encrypted files end up with 700:700 in `STAGING`

        `secret.txt` is stored in ~stevedore, mode 400

        This script should be run from the stevedore users crontab

    user=backup, uid=701, gid=701, member of group 700

	Used for running rsync.

        Can read encrypted copies in `STAGING` but not the 'raw' silos.

'''

import os
import math
import time
import shutil

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend


STAGING = os.environ.get("AA_STAGING")
if not STAGING:
    STAGING = "/tmp/BackupStaging"       # Where to stage the encrypted files

SILODIR = os.environ.get("AA_SILODIR")
if not SILODIR:
    SILODIR = "/bitstore/BitStore"       # Where the *.warc.gz files live

QUOTA = os.environ.get("AA_QUOTA")
if not QUOTA:
    QUOTA = 10 << 30                     # Max daily download quota in bytes
else:
    QUOTA = int(QUOTA)

SILODATES = "silodates.txt"

SILOS = {}


def get_secrets(_sfn, _dfn):
    ''' Retrieve the secrets for one particular file '''
    pkey, skey = open("secrets.txt").read().split()
    assert len(pkey) == 64
    assert len(skey) == 32
    return bytearray.fromhex(pkey), bytearray.fromhex(skey)

def Encrypt_File(sfn, dfn):
    '''
    Encryption and Decryption is the same operation, but the IV
    is derived from the source filename, which must therefore be
    the same for both operations.
    '''

    assert sfn != dfn

    pkey, skey = get_secrets(sfn, dfn)

    h = hmac.HMAC(
        skey,
        hashes.SHA256(),
        backend=default_backend()
    )
    x = sfn.replace(".bin", "")
    x = os.path.basename(x)
    h.update(x.encode("UTF-8"))
    iv = h.finalize()

    encryption = Cipher(
        algorithms.AES(pkey),
        modes.CTR(iv[:16]),
        backend=default_backend()
    ).encryptor()

    authentication = hmac.HMAC(
        skey,
        hashes.SHA256(),
        backend=default_backend()
    )

    integrity = hashes.Hash(
        hashes.SHA256(),
        backend=default_backend()
    )

    fi = open(sfn, "rb")
    fo = open(dfn, "wb")
    while True:
        a = fi.read(65536)
        if not a:
            break
        b = encryption.update(a)
        authentication.update(b)
        integrity.update(b)
        fo.write(b)

    b = encryption.finalize()
    assert len(b) == 0	# CTR mode
			    # otherwise:
			    # authentication.update(b)
			    # integrity.update(b)
			    # fo.write(b)

    open(dfn + ".hmac", "w").write(authentication.finalize().hex() + "\n")
    open(dfn + ".sha256", "w").write(
        "SHA256 (%s) = " % os.path.basename(dfn) +
        integrity.finalize().hex() + "\n"
    )


class Silo():
    ''' An AardWARC silo '''
    def __init__(self, fn):
        SILOS[fn] = self
        self.fn = fn
        self.now_sz = 0
        self.last_sz = 0
        self.last_tm = 0

    def __repr__(self):
        return "<Silo %s>" % self.fn

    def __lt__(self, other):
        return self.sortkey() > other.sortkey()

    def sortkey(self):
        return [
            math.fabs(self.now_sz - self.last_sz),
            time.time() - self.last_tm
        ]

    def set_last_size(self, sz):
        self.last_sz = sz

    def set_last_time(self, tm):
        self.last_tm = tm

    def probe(self, fpn):
        st = os.stat(fpn)
        self.now_sz = st.st_size
        self.fpn = fpn

def silo(f):
    s = SILOS.get(f)
    if not s:
        s = Silo(f)
    return s

def main(sdir):

    try:
        for i in open(SILODATES):
            j = i.split()
            s = silo(j[0])
            s.set_last_time(float(j[1]))
            s.set_last_size(int(j[2]))
    except FileNotFoundError:
        pass

    for path, _b, files in os.walk(SILODIR):
        for f in files:
            if f[-8:] == ".warc.gz":
                silo(f).probe(os.path.join(path, f))

    q = 0
    for s in sorted(list(SILOS.values())):
        if q + s.now_sz > QUOTA:
            break
        q += s.now_sz
        print("DO", "%14d" % q, s.fpn, s.sortkey())
        if True:
            Encrypt_File(
                s.fpn,
                os.path.join(sdir, s.fn + ".bin")
            )
        s.last_tm = time.time()
        s.last_sz = s.now_sz

    fo = open(SILODATES + ".new", "w")
    for _n, s in sorted(SILOS.items()):
        fo.write("%s %.3f %d\n" % (s.fn, s.last_tm, s.last_sz))
    fo.close()

    os.rename(SILODATES + ".new", SILODATES)

if __name__ == "__main__":

    snew = STAGING + ".new"
    sold = STAGING + ".old"

    os.umask(0o22)

    shutil.rmtree(snew, ignore_errors=True)
    shutil.rmtree(sold, ignore_errors=True)

    os.mkdir(snew, mode=0o755)

    main(snew)

    try:
        os.rename(STAGING, sold)
    except FileNotFoundError:
        pass

    os.rename(snew, STAGING)

    shutil.rmtree(sold, ignore_errors=True)
