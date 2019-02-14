#!/bin/sh
#
# Coverage tests

set -e

. test.rc

unset GATEWAY_INTERFACE
unset REQUEST_METHOD
unset PATH_INFO
unset HTTP_ACCEPT_ENCODING

fail 1 'Too many arguments' \
	${AXEC} cgi foo

fail 1 'No (good) $GATEWAY_INTERFACE' \
	${AXEC} cgi

export GATEWAY_INTERFACE=CGI/1.0
fail 1 'No (good) $GATEWAY_INTERFACE' \
	${AXEC} cgi

export GATEWAY_INTERFACE=CGI/1.1
fail 1 'No (good) $REQUEST_METHOD' \
	${AXEC} cgi

export REQUEST_METHOD="PUT"
fail 1 'No (good) $REQUEST_METHOD' \
	${AXEC} cgi

export REQUEST_METHOD="GET"
fail 1 'No $PATH_INFO' \
	${AXEC} cgi

export PATH_INFO="/000000"
fail 0 'ID is invalid (too short)' \
	${AXEC} cgi

i=`sha256 < ../README.md | cut -c1-32`
export PATH_INFO=$i
fail 0 'Museum-quality bit-archive storage management' \
	${AXEC} cgi
export HTTP_ACCEPT_ENCODING=gzip
fail 0 'Content-Encoding: gzip' \
	${AXEC} cgi
