#!/bin/sh
#
# Basic store/get test

set -e

. test.rc

new_aardwarc

for i in ../*
do
	if [ ! -f $i ] ; then
		continue
	fi
	echo "#### $0 $i"

	# Store the file
	cp $i _1
	${AXEC} store -t resource -m application/octet-stream _1 > _2

	# Store the metadata
	ls -l $i > _1m
	sha256 $i >> _1m
	${AXEC} store -t metadata -m text/plain -r `cat _2` _1m > _2m

	# Get them both back again
	${AXEC} get -o _3 `cat _2` > _4
	${AXEC} get -o _3m `cat _2m` > _4m
	${AXEC} get -n -o _3mn `cat _2m` > _4mn

	# Get back also in gzip'ed format
	${AXEC} get -z -o _5 `cat _2` > _6
	${AXEC} get -z -o _5m `cat _2m` > _6m

	# Check payload is identical
	cmp _1 _3
	cmp _1m _3m

	# Check gzip'ed payload is identical
	zcat _5 | cmp - _1
	zcat _5m | cmp - _1m

	# Check headers are the same
	diff _4 _6
	diff _4m _6m
	diff _4mn _6m

	# Check ID headers
	fgrep -q "WARC-Record-ID: <`cat _2`>" _4
	fgrep -q "WARC-Record-ID: <`cat _2m`>" _4m
	fgrep -q "WARC-Refers-To: <`cat _2`>" _4m

	# Check other headers
	fgrep -q "WARC-Type: resource" _4
	fgrep -q "Content-Type: application/octet-stream" _4
	fgrep -q "WARC-Type: metadata" _4m
	fgrep -q "Content-Type: text/plain" _4m
	fgrep -q "WARC-Type: resource" _6
	fgrep -q "Content-Type: application/octet-stream" _6
	fgrep -q "WARC-Type: metadata" _6m
	fgrep -q "Content-Type: text/plain" _6m

	# Check Content-Length headers
	l3=`stat -f '%z' _3`
	fgrep -q "Content-Length: $l3" _4
	l3m=`stat -f '%z' _3m`
	fgrep -q "Content-Length: $l3m" _4m

	# Check Digest headers
	s3=`sha256 < _3`
	fgrep -q "WARC-Block-Digest: sha256:$s3" _4
	s3m=`sha256 < _3m`
	fgrep -q "WARC-Block-Digest: sha256:$s3m" _4m
	s5=`zcat _5 | sha256`
	fgrep -q "WARC-Block-Digest: sha256:$s5" _6
	s5m=`zcat _5m | sha256`
	fgrep -q "WARC-Block-Digest: sha256:$s5m" _6m
done

echo "## $0 DONE"
rm -f _[1-6]*
