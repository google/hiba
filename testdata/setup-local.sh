#!/bin/bash
# Copyright 2021 The HIBA Authors
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd
#
# This script allows testing HIBA locally
# It sets up 2 local ssh servers with 2 different HIBA identities
# It sets up 1 user certificate with 2 HIBA grants:
# * grant1: allow SSH to testing hosts
# * grant2: only allow a forced command to prod hosts
#
# The CA signing operation is the enforcement point for access authorization
#
# Note: certificate based authentication also allows trusting back the host key
# and avoid warnings and errors about changed host key or IP addresses.

CLEANUP() {
	trap - INT QUIT TERM EXIT
	rm -rf "$dest"
	kill -15 "$OPENSSHPID1" 2> /dev/null
	kill -15 "$OPENSSHPID2" 2> /dev/null
}

dest="$(mktemp -d)"
trap CLEANUP INT QUIT TERM EXIT

if [ ! -x /usr/sbin/hiba-gen ]; then
	echo "Please build HIBA and install it in /usr/sbin/ before running setup-local.sh"
	echo "Run:"
	echo "  ./configure --prefix=/usr --with-opensshdir=\$PATH_TO_OPENSSH"
	echo "  make"
	echo "  sudo make install"
	exit 1
fi
if [ ! -x /usr/sbin/hiba-chk ]; then
	echo "Please build HIBA and install it in /usr/sbin/ before running setup-local.sh"
	echo "Run:"
	echo "  ./configure --prefix=/usr --with-opensshdir=\$PATH_TO_OPENSSH"
	echo "  make"
	echo "  sudo make install"
	exit 1
fi

# Generate a new temporary CA and test identities
hiba-ca.sh -c -d "$dest" -- -N ""  || exit 1
hiba-ca.sh -c -d "$dest" -h -I localhost1 -- -N "" || exit 1
hiba-ca.sh -c -d "$dest" -h -I localhost2 -- -N "" || exit 1
hiba-ca.sh -c -d "$dest" -u -I localuser  -- -N "" || exit 1

# Generate test HIBA grants and identities
hiba-gen -i -f "$dest/policy/identities/prod" domain host.local owner localuser purpose prod
hiba-gen -i -f "$dest/policy/identities/testing" domain host.local owner localuser purpose testing
hiba-gen -f "$dest/policy/grants/shell" domain host.local owner localuser purpose testing role "$(whoami)"
hiba-gen -f "$dest/policy/grants/locked" domain host.local owner localuser purpose prod role "$(whoami)" options "command=\"echo 'prodHost: limited access'\""

# Allow localuser to request HIBA grants
hiba-ca.sh -d "$dest" -p -I localuser -H shell -H locked

# Sign ssh certificate
hiba-ca.sh -s -d "$dest" -h -I localhost1 -n localhost -n "$(hostname)" -H prod -- -P "" || exit 1
hiba-ca.sh -s -d "$dest" -h -I localhost2 -n localhost -n "$(hostname)" -H testing -- -P "" || exit 1
hiba-ca.sh -s -d "$dest" -u -I localuser -H shell -H locked -- -P "" || exit 1

# Generate custom banner
cat > "$dest/banner" << _EOF
#####################################################
#                 setup-local.sh                    #
# Host Identity Based Authorization SSHD example.   #
#####################################################
_EOF

# Generate trusted hosts file for client
echo "@cert-authority * $(cat $dest/ca.pub)" > "$dest/known_hosts"

# Generate ssh server config
cat > "$dest/sshd_config" << _EOF
# sshd_config for local HIBA testing

# Display custom welcome message
Banner $dest/banner

# Allow pubkey/certificate based authentication
# and disallow password based authentication
PubkeyAuthentication yes
PasswordAuthentication no

# Ignore KnownHosts: we trust our CA
IgnoreUserKnownHosts yes

# Ignore authorized_keys: we use HIBA
AuthorizedKeysFile /dev/null

# Declare trusted CA
TrustedUserCAKeys $dest/ca.pub

# Configure HIBA for localhost1
Match LocalPort 2201
	AuthorizedPrincipalsCommand /usr/sbin/hiba-chk -i $dest/hosts/localhost1-cert.pub -r "%u" "%k"
	AuthorizedPrincipalsCommandUser $(whoami)

# Configure HIBA for localhost2
Match LocalPort 2202
	AuthorizedPrincipalsCommand /usr/sbin/hiba-chk -i $dest/hosts/localhost2-cert.pub -r "%u" "%k"
	AuthorizedPrincipalsCommandUser $(whoami)
_EOF

# Generate ssh client config
cat > "$dest/ssh_config" << _EOF
# ssh client config for local HIBA testing

# Tell ssh to use the certificate authentication
CertificateFile $dest/users/localuser-cert.pub
IdentityFile $dest/users/localuser

# Declare our trusted CA
GlobalKnownHostsFile $dest/known_hosts
_EOF

# Start the openssh servers
echo ""
echo "#"
/usr/sbin/sshd -f "$dest/sshd_config" -D -h "$dest/hosts/localhost1" -c "$dest/hosts/localhost1-cert.pub" -p 2201 &
OPENSSHPID1=$!
echo "# Started openssh (pid:$OPENSSHPID1) listening on localhost:2201 emulating 'prod' server"
/usr/sbin/sshd -f "$dest/sshd_config" -D -h "$dest/hosts/localhost2" -c "$dest/hosts/localhost2-cert.pub" -p 2202 &
OPENSSHPID2=$!
echo "# Started openssh (pid:$OPENSSHPID2) listening on localhost:2202 emulating 'testing' server"

# Display testing instructions
echo "# Will terminate in 5 minutes (or press ^C)."
echo "# Try connecting using:"
echo "ssh -F $dest/ssh_config -p 2201 $(whoami)@localhost	   # authorize limited access on prod host"
echo "ssh -F $dest/ssh_config -p 2202 $(whoami)@localhost	   # authorize access on test host"

# Sleep 5 minutes then cleanup
sleep 300
