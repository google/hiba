#!/bin/bash
# Copyright 2021 The HIBA Authors
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

dest="${DEST:-$(mktemp -d)}"
log="${LOG:-/tmp/hiba-regression-test.log}"
cleanup="${CLEANUP:-1}"

date > "$log"

output() {
	tee -a "$log" >&2
}

RUN() {
	CMD=$1
	shift 1

	echo "= Running $CMD $VERBOSE $@" >>$log
	$CMD $VERBOSE "$@" 2>>$log | tee -a "$log"
	exit_code=${PIPESTATUS[0]}
	echo "= Exit code $exit_code" >>$log
	return $exit_code
}

EXPECT_EXISTS() {
	EXPECTED="$1"
	if [ ! -e "$EXPECTED" ]; then
		echo "Error" | output
		echo "Missing expected file $EXPECTED" | output
		exit 1
	fi
}

EXPECT_NOT_EXISTS() {
	EXPECTED="$1"
	if [ -e "$EXPECTED" ]; then
		echo "Error" | output
		echo "Existing unexpected file $EXPECTED" | output
		exit 1
	fi
}

EXPECT_EQ() {
	EXPECTED="$1"
	GOT="$2"
	if [ "$GOT" != "$EXPECTED" ]; then
		echo "Error" | output
		echo "Expected: $EXPECTED" | output
		echo "Got:      $GOT" | output
		exit 1
	fi
}

START_TEST() {
	NAME="$1"
	echo -en "== Testing $NAME\t" | output
	echo >> "$log"
}

SUCCESS() {
	echo "Success"
	echo "== Success" >> "$log"
}

CLEANUP() {
	if [ "$cleanup" = "1" ]; then
		echo "== Cleaning up artifacts in $dest"
		rm -rf "$dest"
	fi
	echo "== Logs stored in $log"
}

trap CLEANUP INT QUIT TERM EXIT
