#!/bin/sh

set -e

for i in test??.sh
do
	sh $i
done
