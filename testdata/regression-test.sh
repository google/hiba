#!/bin/bash
# Copyright 2021 The HIBA Authors
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

cd $(dirname $0)

source test-utils.sh

#
# Tests
#

START_TEST "hiba-ca.sh: create root identity"
RUN ../hiba-ca.sh -d "$dest" -c -- -N secret >> "$log"
EXPECT_EXISTS "$dest/ca"
EXPECT_EXISTS "$dest/ca.pub"
EXPECT_EXISTS "$dest/policy/grants"
EXPECT_EXISTS "$dest/policy/identities"
EXPECT_EXISTS "$dest/krl"
SUCCESS
#####

START_TEST "hiba-ca.sh: create host identities"
RUN ../hiba-ca.sh -d "$dest" -c -h -I host1 -- -N secret >> "$log"
RUN ../hiba-ca.sh -d "$dest" -c -h -I host2 -- -N secret >> "$log"
RUN ../hiba-ca.sh -d "$dest" -c -h -I host3 -- -N secret >> "$log"
EXPECT_EXISTS "$dest/hosts/host1"
EXPECT_EXISTS "$dest/hosts/host1.pub"
EXPECT_EXISTS "$dest/hosts/host2"
EXPECT_EXISTS "$dest/hosts/host2.pub"
EXPECT_EXISTS "$dest/hosts/host3"
EXPECT_EXISTS "$dest/hosts/host3.pub"
SUCCESS
#####

START_TEST "hiba-ca.sh: create user identities"
RUN ../hiba-ca.sh -d "$dest" -c -u -I user1 -- -N secret >> "$log"
RUN ../hiba-ca.sh -d "$dest" -c -u -I user2 -- -N secret >> "$log"
EXPECT_EXISTS "$dest/users/user1"
EXPECT_EXISTS "$dest/users/user1.pub"
EXPECT_EXISTS "$dest/users/user2"
EXPECT_EXISTS "$dest/users/user2.pub"
SUCCESS
#####

START_TEST "hiba-gen: create identities"
RUN_T ../hiba-gen -i -f "$dest/policy/identities/owner:user1" domain hibassh.dev owner user1 purpose production
RUN_T ../hiba-gen -i -f "$dest/policy/identities/owner:user2" domain hibassh.dev owner user2 purpose testing
EXPECT_EXISTS "$dest/policy/identities/owner:user1"
EXPECT_EXISTS "$dest/policy/identities/owner:user2"
SUCCESS
#####

START_TEST "hiba-gen: display identities"
EXPECTED="identity@hibassh.dev (v1):
 [0] domain = 'hibassh.dev'
 [1] owner = 'user1'
 [2] purpose = 'production'"
GOT=$(RUN_T ../hiba-gen -d -f "$dest/policy/identities/owner:user1")
EXPECT_EQ "$EXPECTED" "$GOT"
EXPECTED="identity@hibassh.dev (v1):
 [0] domain = 'hibassh.dev'
 [1] owner = 'user2'
 [2] purpose = 'testing'"
GOT=$(RUN_T ../hiba-gen -d -f "$dest/policy/identities/owner:user2")
EXPECT_EQ "$EXPECTED" "$GOT"
SUCCESS
#####

START_TEST "hiba-gen: create grants"
RUN_T ../hiba-gen -f "$dest/policy/grants/location:eu" domain hibassh.dev location EU &>> "$log"
RUN_T ../hiba-gen -f "$dest/policy/grants/purpose:testing" domain hibassh.dev purpose testing role tester &>> "$log"
RUN_T ../hiba-gen -f "$dest/policy/grants/lockedcmd" domain hibassh.dev options 'command="uname -a"' &>> "$log"
RUN_T ../hiba-gen -f "$dest/policy/grants/badcmd" domain hibassh.dev options "command=uname -a" &>> "$log"
RUN_T ../hiba-gen -f "$dest/policy/grants/all" domain hibassh.dev &>> "$log"
RUN_T ../hiba-gen -f "$dest/policy/grants/disallowed" domain hibassh.dev &>> "$log"
RUN_T ../hiba-gen -f "$dest/policy/grants/2roles" domain hibassh.dev role user1 role user2 &>> "$log"
RUN_T ../hiba-gen -f "$dest/policy/grants/selfonly" domain hibassh.dev role @PRINCIPALS &>> "$log"
EXPECT_EXISTS "$dest/policy/grants/all"
EXPECT_EXISTS "$dest/policy/grants/location:eu"
EXPECT_EXISTS "$dest/policy/grants/purpose:testing"
EXPECT_EXISTS "$dest/policy/grants/disallowed"
EXPECT_EXISTS "$dest/policy/grants/2roles"
EXPECT_EXISTS "$dest/policy/grants/selfonly"
EXPECT_NOT_EXISTS "$dest/policy/grants/badcmd"
SUCCESS
#####

START_TEST "hiba-ca.sh: add permissions"
RUN ../hiba-ca.sh -d "$dest" -p -I user2 -H location:eu &>> "$log"
RUN ../hiba-ca.sh -d "$dest" -p -I user2 -H purpose:testing &>> "$log"
EXPECT_EXISTS "$dest/policy/principals/user2/location:eu"
EXPECT_EXISTS "$dest/policy/principals/user2/purpose:testing"
SUCCESS
#####

START_TEST "hiba-ca.sh: add permissions multiple"
RUN ../hiba-ca.sh -d "$dest" -p -I user1 -H all -H location:eu -H purpose:testing -H disallowed &>> "$log"
EXPECT_EXISTS "$dest/policy/principals/user1/all"
EXPECT_EXISTS "$dest/policy/principals/user1/location:eu"
EXPECT_EXISTS "$dest/policy/principals/user1/purpose:testing"
EXPECT_EXISTS "$dest/policy/principals/user1/disallowed"
SUCCESS
#####

START_TEST "hiba-ca.sh: del permissions"
RUN ../hiba-ca.sh -d "$dest" -p -r -I user1 -H disallowed &>> "$log"
EXPECT_EXISTS "$dest/policy/principals/user1/all"
EXPECT_EXISTS "$dest/policy/principals/user1/purpose:testing"
EXPECT_NOT_EXISTS "$dest/policy/principals/user1/disallowed"
SUCCESS
#####

START_TEST "hiba-gen: display grants"
EXPECTED="grant@hibassh.dev (v1):
 [0] domain = 'hibassh.dev'
 [1] location = 'EU'"
GOT=$(RUN_T ../hiba-gen -d -f "$dest/policy/grants/location:eu")
EXPECT_EQ "$EXPECTED" "$GOT"
EXPECTED="grant@hibassh.dev (v1):
 [0] domain = 'hibassh.dev'
 [1] purpose = 'testing'
 [2] role = 'tester'"
GOT=$(RUN_T ../hiba-gen -d -f "$dest/policy/grants/purpose:testing")
EXPECT_EQ "$EXPECTED" "$GOT"
EXPECTED="grant@hibassh.dev (v1):
 [0] domain = 'hibassh.dev'"
GOT=$(RUN_T ../hiba-gen -d -f "$dest/policy/grants/all")
EXPECT_EQ "$EXPECTED" "$GOT"
SUCCESS
#####

START_TEST "hiba-gen: grant in cmdline"
EXPECTED="grant@hibassh.dev (v1):
 [0] domain = 'hibassh.dev'
 [1] location = 'EU'"
GOT=$(RUN_T ../hiba-gen -d -f "$(cat $dest/policy/grants/location:eu)")
EXPECT_EQ "$EXPECTED" "$GOT"
SUCCESS
#####

START_TEST "hiba-gen: grant format: single raw"
EXPECTED="certificate 'test' (1 principal) contains 1 HIBA grant
 principal: 'foobar'
grant@hibassh.dev (v1):
 [0] domain = 'hibassh.dev'
 [1] id = '1'"
RUN ../generate-test-certs "$SINGLERAW" "$tmpdir/user-singleraw-cert.pub"
GOT=$(RUN_T ../hiba-gen -d -f "$tmpdir/user-singleraw-cert.pub")
EXPECT_EQ "$EXPECTED" "$GOT"
if [[ -n "$WITH_EXTENSION_COMPRESSION" ]]; then
	RUN ../generate-test-certs "$SINGLERAWZ" "$tmpdir/user-singlerawz-cert.pub"
	GOT=$(RUN_T ../hiba-gen -d -f "$tmpdir/user-singlerawz-cert.pub")
	EXPECT_EQ "$EXPECTED" "$GOT"
fi
SUCCESS
#####

START_TEST "hiba-gen: grant format: single base64"
EXPECTED="certificate 'test' (1 principal) contains 1 HIBA grant
 principal: 'foobar'
grant@hibassh.dev (v1):
 [0] domain = 'hibassh.dev'
 [1] id = '1'"
RUN ../generate-test-certs "$SINGLEB64" "$tmpdir/user-singleb64-cert.pub"
GOT=$(RUN_T ../hiba-gen -d -f "$tmpdir/user-singleb64-cert.pub")
EXPECT_EQ "$EXPECTED" "$GOT"
if [[ -n "$WITH_EXTENSION_COMPRESSION" ]]; then
	RUN ../generate-test-certs "$SINGLEB64Z" "$tmpdir/user-singleb64z-cert.pub"
	GOT=$(RUN_T ../hiba-gen -d -f "$tmpdir/user-singleb64z-cert.pub")
	EXPECT_EQ "$EXPECTED" "$GOT"
fi
SUCCESS
#####

START_TEST "hiba-gen: grant format: multi raw"
EXPECTED="certificate 'test' (1 principal) contains 2 HIBA grants
 principal: 'foobar'
grant@hibassh.dev (v1):
 [0] domain = 'hibassh.dev'
 [1] id = '1'
grant@hibassh.dev (v1):
 [0] domain = 'hibassh.dev'
 [1] id = '2'"
RUN ../generate-test-certs "$MULTIRAW" "$tmpdir/user-multiraw-cert.pub"
GOT=$(RUN_T ../hiba-gen -d -f "$tmpdir/user-multiraw-cert.pub")
EXPECT_EQ "$EXPECTED" "$GOT"
if [[ -n "$WITH_EXTENSION_COMPRESSION" ]]; then
	RUN ../generate-test-certs "$MULTIRAWZ" "$tmpdir/user-multirawz-cert.pub"
	GOT=$(RUN_T ../hiba-gen -d -f "$tmpdir/user-multirawz-cert.pub")
	EXPECT_EQ "$EXPECTED" "$GOT"
fi
SUCCESS
#####

START_TEST "hiba-gen: grant format: multi base64"
EXPECTED="certificate 'test' (1 principal) contains 2 HIBA grants
 principal: 'foobar'
grant@hibassh.dev (v1):
 [0] domain = 'hibassh.dev'
 [1] id = '1'
grant@hibassh.dev (v1):
 [0] domain = 'hibassh.dev'
 [1] id = '2'"
RUN ../generate-test-certs "$MULTIB64" "$tmpdir/user-multib64-cert.pub"
GOT=$(RUN_T ../hiba-gen -d -f "$tmpdir/user-multib64-cert.pub")
EXPECT_EQ "$EXPECTED" "$GOT"
if [[ -n "$WITH_EXTENSION_COMPRESSION" ]]; then
	RUN ../generate-test-certs "$MULTIB64Z" "$tmpdir/user-multib64z-cert.pub"
	GOT=$(RUN_T ../hiba-gen -d -f "$tmpdir/user-multib64z-cert.pub")
	EXPECT_EQ "$EXPECTED" "$GOT"
fi
SUCCESS
#####

START_TEST "hiba-ca.sh: sign host"
RUN ../hiba-ca.sh -d "$dest" -s -h -I host1 -V +30d -H owner:user1 -- -P secret &>> "$log"
RUN ../hiba-ca.sh -d "$dest" -s -h -I host2 -V +30d -H owner:user2 -- -P secret &>> "$log"
EXPECT_EXISTS "$dest/hosts/host1-cert.pub"
EXPECT_EXISTS "$dest/hosts/host2-cert.pub"
EXPECT_EQ $(cat "$dest/logs" | wc -l) 2
SUCCESS
#####

START_TEST "hiba-ca.sh: sign user not eligible"
RUN ../hiba-ca.sh -d "$dest" -s -u -I user1 -H  disallowed -- -P secret &>> "$log"
EXPECT_NOT_EXISTS "$dest/users/user1-cert.pub"
SUCCESS
#####

START_TEST "hiba-ca.sh: sign user eligible"
RUN ../hiba-ca.sh -d "$dest" -s -u -I user1 -H  all -- -P secret &>> "$log"
EXPECT_EXISTS "$dest/users/user1-cert.pub"
SUCCESS
#####

START_TEST "hiba-ca.sh: sign user multiple grants"
RUN ../hiba-ca.sh -d "$dest" -s -u -I user2 -H  location:eu -H purpose:testing -- -P secret &>> "$log"
EXPECT_EXISTS "$dest/users/user2-cert.pub"
SUCCESS
#####

START_TEST "hiba-gen: display certificates"
EXPECTED="certificate 'user1' (1 principal) contains 1 HIBA grant
 principal: 'user1'
grant@hibassh.dev (v1):
 [0] domain = 'hibassh.dev'"
GOT=$(RUN_T ../hiba-gen -d -f "$dest/users/user1-cert.pub")
EXPECT_EQ "$EXPECTED" "$GOT"
EXPECTED="certificate 'user2' (1 principal) contains 2 HIBA grants
 principal: 'user2'
grant@hibassh.dev (v1):
 [0] domain = 'hibassh.dev'
 [1] location = 'EU'
grant@hibassh.dev (v1):
 [0] domain = 'hibassh.dev'
 [1] purpose = 'testing'
 [2] role = 'tester'"
GOT=$(RUN_T ../hiba-gen -d -f "$dest/users/user2-cert.pub")
EXPECT_EQ "$EXPECTED" "$GOT"
SUCCESS
#####

START_TEST "hiba-gen: certificate in cmdline"
EXPECTED="certificate 'user1' (1 principal) contains 1 HIBA grant
 principal: 'user1'
grant@hibassh.dev (v1):
 [0] domain = 'hibassh.dev'"
GOT=$(RUN_T ../hiba-gen -d -f "$(cat $dest/users/user1-cert.pub)")
EXPECT_EQ "$EXPECTED" "$GOT"
SUCCESS
#####

START_TEST "hiba-chk: extension: allow grant"
GOT=$(RUN_T ../hiba-chk -i "$dest/policy/identities/owner:user1" -r root -p user1 "$dest/policy/grants/all")
GOTCODE=$?
EXPECT_EQ "user1" "$GOT"
EXPECT_EQ 0 "$GOTCODE"
SUCCESS
#####

START_TEST "hiba-chk: extension: deny missing field"
GOT=$(RUN_T ../hiba-chk -i "$dest/policy/identities/owner:user1" -r root -p user1 "$dest/policy/grants/location:eu")
GOTCODE=$?
EXPECT_EQ "" "$GOT"
EXPECT_EQ 40 "$GOTCODE"
SUCCESS
#####

START_TEST "hiba-chk: extension: deny mismatch field"
GOT=$(RUN_T ../hiba-chk -i "$dest/policy/identities/owner:user1" -r tester -p user1 "$dest/policy/grants/purpose:testing")
GOTCODE=$?
EXPECT_EQ "" "$GOT"
EXPECT_EQ 48 "$GOTCODE"
SUCCESS
#####

START_TEST "hiba-chk: extension: deny bad role"
GOT=$(RUN_T ../hiba-chk -i "$dest/policy/identities/owner:user2" -r root -p user1 "$dest/policy/grants/purpose:testing")
GOTCODE=$?
EXPECT_EQ "" "$GOT"
EXPECT_EQ 46 "$GOTCODE"
SUCCESS
#####

START_TEST "hiba-chk: extension: allow when multiple roles"
GOT=$(RUN_T ../hiba-chk -i "$dest/policy/identities/owner:user2" -r user1 -p user1 "$dest/policy/grants/2roles")
GOTCODE=$?
EXPECT_EQ "user1" "$GOT"
EXPECT_EQ 0 "$GOTCODE"
GOT=$(RUN_T ../hiba-chk -i "$dest/policy/identities/owner:user2" -r user2 -p user1 "$dest/policy/grants/2roles")
GOTCODE=$?
EXPECT_EQ "user1" "$GOT"
EXPECT_EQ 0 "$GOTCODE"
SUCCESS
#####

START_TEST "hiba-chk: extension: allow PRINCIPALS role"
GOT=$(RUN_T ../hiba-chk -i "$dest/policy/identities/owner:user2" -r user1 -p user1 "$dest/policy/grants/selfonly")
GOTCODE=$?
EXPECT_EQ "user1" "$GOT"
EXPECT_EQ 0 "$GOTCODE"
SUCCESS
#####

START_TEST "hiba-chk: extension: deny PRINCIPALS role"
GOT=$(RUN_T ../hiba-chk -i "$dest/policy/identities/owner:user2" -r user2 -p user1 "$dest/policy/grants/selfonly")
GOTCODE=$?
EXPECT_EQ "" "$GOT"
EXPECT_EQ 46 "$GOTCODE"
SUCCESS
#####

START_TEST "hiba-chk: extension: print options"
GOT=$(RUN_T ../hiba-chk -i "$dest/policy/identities/owner:user1" -r root -p user1 "$dest/policy/grants/lockedcmd")
GOTCODE=$?
EXPECT_EQ "command=\"uname -a\" user1" "$GOT"
EXPECT_EQ 0 "$GOTCODE"
SUCCESS
#####

START_TEST "hiba-chk: certificate: allow"
GOT=$(RUN_T ../hiba-chk -i "$dest/hosts/host1-cert.pub" -r root "$dest/users/user1-cert.pub")
GOTCODE=$?
EXPECT_EQ "user1" "$GOT"
EXPECT_EQ 0 "$GOTCODE"
SUCCESS
#####

START_TEST "hiba-chk: certificate: deny multiple identities"
RUN ../hiba-ca.sh -d "$dest" -s -h -I host3 -V +30d -H owner:user1 -H owner:user2 -- -P secret &>> "$log"
GOT=$(RUN_T ../hiba-chk -i "$dest/hosts/host3-cert.pub" -r root "$dest/users/user1-cert.pub")
GOTCODE=$?
EXPECT_EQ "" "$GOT"
EXPECT_EQ 3 "$GOTCODE"
SUCCESS
#####

START_TEST "hiba-chk: certificate: deny"
GOT=$(RUN_T ../hiba-chk -i "$dest/hosts/host1-cert.pub" -r root "$dest/users/user2-cert.pub")
GOTCODE=$?
EXPECT_EQ "" "$GOT"
EXPECT_EQ 48 "$GOTCODE"
SUCCESS
#####

START_TEST "hiba-chk: certificate: expired grant"
RUN_T ../hiba-gen -f "$dest/policy/grants/all:1s" domain hibassh.dev validity 1 &>> "$log"
RUN ../hiba-ca.sh -d "$dest" -p -I user1 -H all:1s &>> "$log"
RUN ../hiba-ca.sh -d "$dest" -s -u -I user1 -H all:1s -- -P secret &>> "$log"
sleep 2
GOT=$(RUN_T ../hiba-chk -i "$dest/hosts/host1-cert.pub" -r root "$dest/users/user1-cert.pub")
GOTCODE=$?
EXPECT_EQ "" "$GOT"
EXPECT_EQ 42 "$GOTCODE"
SUCCESS
#####

START_TEST "hiba-chk: certificate: no grant"
RUN ../hiba-ca.sh -d "$dest" -s -u -I user1 -- -P secret &>> "$log"
GOT=$(RUN_T ../hiba-chk -i "$dest/hosts/host1-cert.pub" -r root "$dest/users/user1-cert.pub")
GOTCODE=$?
EXPECT_EQ "" "$GOT"
EXPECT_EQ 47 "$GOTCODE"
SUCCESS
#####

START_TEST "hiba-grl: revoke: create file"
RUN_T ../hiba-grl -f "$dest/grl.manual" -r -s 43 1 &>> "$log"
GOTCODE=$?
EXPECT_EQ 0 "$GOTCODE"
SUCCESS
#####

START_TEST "hiba-grl: revoke: update new serial"
RUN_T ../hiba-grl -f "$dest/grl.manual" -r -s 0x1234 2 3 &>> "$log"
GOTCODE=$?
EXPECT_EQ 0 "$GOTCODE"
GRL_TIMESTAMP=$(../hiba-grl -f "$dest/grl.manual" -d | grep timestamp | awk '{print $2}')
SUCCESS
#####

START_TEST "hiba-grl: revoke: dump file"
GOT=$(RUN_T ../hiba-grl -f "$dest/grl.manual" -d)
GOTCODE=$?
EXPECTED="HIBA GRL (v1):
  comment: Generated using hiba-grl
  timestamp: $GRL_TIMESTAMP
  entries: 2
  [0x000000000000002b]: 20
  [0x0000000000001234]: C0"
EXPECT_EQ "$EXPECTED" "$GOT"
EXPECT_EQ 0 "$GOTCODE"
SUCCESS
#####

START_TEST "hiba-grl: revoke: filter by serial"
GOT=$(RUN_T ../hiba-grl -f "$dest/grl.manual" -d -s 0x1234)
GOTCODE=$?
EXPECTED="HIBA GRL (v1):
  comment: Generated using hiba-grl
  timestamp: $GRL_TIMESTAMP
  entries: 2
  [0x0000000000001234]: C0"
EXPECT_EQ "$EXPECTED" "$GOT"
EXPECT_EQ 0 "$GOTCODE"
SUCCESS
#####

START_TEST "hiba-grl: revoke: test valid"
GOT=$(RUN_T ../hiba-grl -f "$dest/grl.manual" -t -s 0x1234 0)
GOTCODE=$?
EXPECTED="[0000000000001234]: 0 Valid"
EXPECT_EQ "$EXPECTED" "$GOT"
EXPECT_EQ 0 "$GOTCODE"
SUCCESS
#####

START_TEST "hiba-grl: revoke: test revoked"
GOT=$(RUN_T ../hiba-grl -f "$dest/grl.manual" -t -s 0x1234 2)
GOTCODE=$?
EXPECTED="[0000000000001234]: 2 Revoked"
EXPECT_EQ "$EXPECTED" "$GOT"
EXPECT_EQ 255 "$GOTCODE"
SUCCESS
#####

START_TEST "hiba-grl: revoke: test multiple"
GOT=$(RUN_T ../hiba-grl -f "$dest/grl.manual" -t -s 0x1234 0 1 2 3)
GOTCODE=$?
EXPECTED="[0000000000001234]: 0 Valid
[0000000000001234]: 1 Valid
[0000000000001234]: 2 Revoked
[0000000000001234]: 3 Revoked"
EXPECT_EQ "$EXPECTED" "$GOT"
EXPECT_EQ 254 "$GOTCODE"
SUCCESS
#####

START_TEST "hiba-chk: extension: non revoked grant"
GOT=$(RUN_T ../hiba-chk -i "$dest/policy/identities/owner:user1" -g "$dest/grl.manual" -r root -p user1 "$dest/policy/grants/all")
GOTCODE=$?
EXPECT_EQ "user1" "$GOT"
EXPECT_EQ 0 "$GOTCODE"
SUCCESS
#####

START_TEST "hiba-grl: revoke: update existing serial"
RUN_T ../hiba-grl -f "$dest/grl.manual" -r -s 43 0 &>> "$log"
GOTCODE=$?
EXPECT_EQ 0 "$GOTCODE"
GRL_TIMESTAMP=$(../hiba-grl -f "$dest/grl.manual" -d | grep timestamp | awk '{print $2}')
SUCCESS
#####

START_TEST "hiba-grl: revoke: dump file"
GOT=$(RUN_T ../hiba-grl -f "$dest/grl.manual" -d)
GOTCODE=$?
EXPECTED="HIBA GRL (v1):
  comment: Generated using hiba-grl
  timestamp: $GRL_TIMESTAMP
  entries: 2
  [0x000000000000002b]: 30
  [0x0000000000001234]: C0"
EXPECT_EQ "$EXPECTED" "$GOT"
EXPECT_EQ 0 "$GOTCODE"
SUCCESS
#####

START_TEST "hiba-chk: extension: revoked grant"
GOT=$(RUN_T ../hiba-chk -i "$dest/policy/identities/owner:user1" -g "$dest/grl.manual" -r root -p user1 "$dest/policy/grants/all")
GOTCODE=$?
EXPECT_EQ "" "$GOT"
EXPECT_EQ 43 "$GOTCODE"
SUCCESS
#####

START_TEST "hiba-ca.sh: extension: revoke certificate 1"
echo "serial: 1" > "$dest/revocation-spec.1"
RUN ../hiba-ca.sh -d "$dest" -k -r -z "$dest/revocation-spec.1" &>> "$log"
GOT=$(RUN ../hiba-ca.sh -d "$dest" -l -k | grep 'serial: 1')
EXPECT_EQ "serial: 1" "$GOT"
SUCCESS
#####

START_TEST "hiba-ca.sh: extension: inspect logs"
RUN_T ../hiba-gen -f "$dest/policy/grants/toberemoved" domain hibassh.dev nomatch true &>> "$log"
RUN ../hiba-ca.sh -d "$dest" -p -I user1 -H toberemoved -- -P secret &>> "$log"
RUN ../hiba-ca.sh -d "$dest" -s -u -I user1 -H toberemoved -- -P secret &>> "$log"
GOT_SERIAL=$(tail -n 1 "$dest/logs" | cut -d, -f2)
GOT=$(RUN ../hiba-ca.sh -d "$dest" -k | grep toberemoved)
EXPECT_EQ "1" "$(echo $GOT | wc -l)"
SUCCESS
#####

START_TEST "hiba-ca.sh: extension: revoke grant from policy remove"
echo y | RUN ../hiba-ca.sh -d "$dest" -p -r -I user1 -H toberemoved -- -P secret &>> "$log"
SERIAL="$(printf '0x%.16x' $GOT_SERIAL)"
GOT=$(RUN_T ../hiba-grl -f "$dest/grl" -d -s $GOT_SERIAL | grep "$SERIAL")
EXPECT_EQ "  [$SERIAL]: 10" "$GOT"
SUCCESS
#####

START_TEST "hiba-ca.sh: extension: revoke grant explicitely"
RUN ../hiba-ca.sh -d "$dest" -p -I user1 -H toberemoved -- -P secret &>> "$log"
RUN ../hiba-ca.sh -d "$dest" -s -u -I user1 -H toberemoved -- -P secret &>> "$log"
echo y | RUN ../hiba-ca.sh -d "$dest" -k -r -H "toberemoved" &>> "$log"
GOT_SERIAL=$(tail -n 1 "$dest/logs" | cut -d, -f2)
SERIAL="$(printf '0x%.16x' $GOT_SERIAL)"
GOT=$(RUN_T ../hiba-grl -f "$dest/grl" -d -s $GOT_SERIAL | grep "$SERIAL")
EXPECT_EQ "  [$SERIAL]: 10" "$GOT"
SUCCESS
#####

START_TEST "hiba-ca.sh: extension: revoke selective grant"
RUN ../hiba-ca.sh -d "$dest" -s -u -I user1 -H all -H toberemoved -- -P secret &>> "$log"
echo y | RUN ../hiba-ca.sh -d "$dest" -k -r -H "toberemoved" &>> "$log"
GOT_SERIAL=$(tail -n 1 "$dest/logs" | cut -d, -f2)
SERIAL="$(printf '0x%.16x' $GOT_SERIAL)"
GOT=$(RUN_T ../hiba-grl -f "$dest/grl" -d -s $GOT_SERIAL | grep "$SERIAL")
EXPECT_EQ "  [$SERIAL]: 20" "$GOT"
SUCCESS
#####

