#!/bin/bash
# Copyright 2021 The HIBA Authors
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd
#
# hiba-ca is a tool to manage a simple CA via command line.
# It provides common CA operations like creating and signing identities. The
# user is responsible for distributing the identities to the relevant hosts and
# users.
#
# IMPORTANT: hiba-ca.sh generates the users & hosts private keys for
# convenience only. It is not required to leave the private keys in the capath.
# Users can even generate their own key pairs, copy the public part into the
# capath, then call the sign method on it.
#
# The structure of a CA is as follows:
# * root/
#   * CA public key (to be distributed globally)
#   * CA private key (secret)
#   * logs of signed certificates
#   * krl: certificate revocation list
#   * grl: grant revocation list
#   * hosts/
#     * <hostname> public key (to be kept by CA)
#     * <hostname> private key (to be distributed to the host and removed from CA)
#     * <hostname> certificate (to be distrubuted to the host)
#   * users/
#     * <username> public key (to be kept by CA)
#     * <username> private key (to be distributed to the user and removed from CA)
#     * <username> certificate (to be distrubuted to the user)
#   * policy/
#     * identities/
#       * <identityname> HIBA identity extension to be attached to host certificates
#     * grants/
#       * <grantname> HIBA grant extension to be attached to user certificates
#     * principals/
#       * <principalname>/
#         * symlinks to a grant from grants/ that this principal is allowed to
#           request
#
# The structure of the logs is the following (comma separated):
# * timestamp
# * serial
# * principals
# * ordered list of grants

usage() {
	if [ "$1" != "" ]; then
		echo "ERROR: $1"
		echo ""
	fi

	echo "Usage:"
	echo "  Create a CA"
	echo "    $0 -c -d <root CA path> -- <ssh-keygen extra args>"
	echo "  Create an identity (user / host)"
	echo "    $0 -c -u -I name -d <root CA path> -- <ssh-keygen extra args>"
	echo "    $0 -c -h -I name -d <root CA path> -- <ssh-keygen extra args>"
	echo "  Import an identity (user / host)"
	echo "    $0 -i -u -f <path to a public key> -I name -d <root CA path>"
	echo "    $0 -i -h -f <path to a public key> -I name -d <root CA path>"
	echo "  Remove an identity (user / host)"
	echo "    $0 -r -u -I name -d <root CA path>"
	echo "    $0 -r -h -I name -d <root CA path>"
	echo "  Set policy permissions (allow / disallow a grant for a user)"
	echo "    $0 -p -H grant -I name -d <root CA path>"
	echo "    $0 -p -r -H grant -I name -d <root CA path>"
	echo "  Sign an identity"
	echo "    $0 -s -u -I name -n principal -H <hiba extensions> -V <validity> -d <root CA path> -- <ssh-keygen extra args>"
	echo "    $0 -s -h -I name -n principal -H <hiba extension>  -V <validity> -d <root CA path> -- <ssh-keygen extra args>"
	echo "  Show the CA content (no secrets are displayed): all, users, hosts, HIBA policy, revocations"
	echo "    $0 -l -d <root CA path>"
	echo "    $0 -l -u -d <root CA path>"
	echo "    $0 -l -h -d <root CA path>"
	echo "    $0 -l -p -d <root CA path>"
	echo "    $0 -l -k -d <root CA path>"
	echo "  List or clean up old signing request logs (keep the last N days):"
	echo "    $0 -k -N <ndays> -d <root CA path>"
	echo "    $0 -k -c -N <ndays> -d <root CA path>"
	echo "  Revoke certificates:"
	echo "    $0 -k -r -z <revocation spec> -d <root CA path>"
	echo "  Revoke grants:"
	echo "    $0 -k -r -H grant -d <root CA path>"
	echo ""
	echo "Note:"
	echo "* -H can be repeated to include more than one grant in user certificates"
	echo "* -n can be repeated to include more than one principal"
	echo "* -z uses the KEY REVOCATION LISTS format (see man ssh-keygen)"
	echo ""
	echo "Defaults:"
	echo "* <root CA path>: default to ~/.hiba-ca/"
	echo "* <ndays>: default to 90"
	echo "* <validity>:     default to 1h. The format is similar to"
	echo "                  ssh-keygen's \`-v validity_interval\`"
	echo "                  (see man ssh-keygen)."
	echo ""

	exit 1
}

error() {
	echo "== ERROR =="
	exit 1
}

get_next_serial() {
	if [ ! -f $dest/logs ]; then
		echo 1
		return
	fi
	serial=$(tail -n 1 $dest/logs | cut -f2 -d,)
	echo $((serial+1))
}

get_logs() {
	DAYS=$1
	FIELDS=$2

	PGM='{if ($1 >= cutoff) {print '$FIELDS'}}'
	now=$(date +%s)
	cutoff=$((now - 86400 * DAYS))
	awk -F, -v cutoff=$cutoff "$PGM" <"$dest/logs"
}

cleanup_logs() {
	DAYS=$1

	rm -f "$dest/.logs.new"

	get_logs "$DAYS" '$0' > "$dest/.logs.new"
	old=$(wc -l "$dest/logs" | cut -f1 -d" ")
	new=$(wc -l "$dest/.logs.new" | cut -f1 -d" ")
	COUNT=$((old - new))
	if [ "$COUNT" -gt 0 ]; then
		echo "== Do you want to remove $COUNT entries before $(date --date=@$cutoff)? (y|N)"
		read ans
		if [ "$ans" = "y" ]; then
			mv "$dest/.logs.new" "$dest/logs"
			echo "== Confirmed =="
		else
			rm "$dest/.logs.new"
			echo "== Aborted =="
		fi
	else
		echo "== Nothing to do"
	fi
}

revoke_grants() {
	NAME="$1"
	GRANT="$2"

	SERIALS=$(awk -F, -v NAME=$NAME -v GRANT=$GRANT '{ if(($3 ~ NAME) && ($4 ~ GRANT)) {print $2}}' <"$dest/logs")
	COUNT=$(echo $SERIALS | wc -w)
	echo "== This action will revoke grants in $COUNT certificate(s)."
	if [ "$COUNT" -gt 0 ]; then
		echo "Do you want to continue? (y|N)"
		read ans
		if [ "$ans" != "y" ]; then
			return -1
		fi
	fi
	for s in $SERIALS; do
		GRANTS_BY_SERIAL=$(awk -F, -v serial=$s '{ if ($2 == serial) { print $4 }}' <"$dest/logs")
		IDS=$(echo $GRANTS_BY_SERIAL | xargs -n 1 | grep -n $GRANT | cut -f1 -d:| awk '{print $1 -1}')
                hiba-grl -f "$dest/grl" -c "$dest $(ssh-keygen -lf $dest/ca.pub)" -r -s "$s" $IDS
	done
}

revoke_cert() {
	MODE="$1"
	SERIAL="$2"

	echo "== Revoking certification serial $SERIAL"
	ssh-keygen -k -f "$dest/krl" -s "$dest/ca.pub" $MODE -z "$(date +%s)" "$SERIAL"
}

create_key() {
	TYPE="$1"
	TARGET="$2"
	shift 2

	echo "== Generating $TYPE keys in $TARGET"
	ssh-keygen -q -f "$TARGET" "$@"
}

sign() {
	TYPE="$1"
	ID="$2"
	TARGET="$3"
	PRINCIPAL="$4"
	VALIDITY="$5"
	HIBA="$6"
	shift 6

	PRINCIPALS="${PRINCIPAL// /,}"

	if [ "$TYPE" = "host" ]; then
		EXT="identity"
		SUB="identities"
		T="-h"
	else
		EXT="grant"
		SUB="grants"
		T=""
	fi

	HIBAEXTS=()
	for ext in $HIBA; do
		if [ ! -f "$dest/policy/$SUB/$ext" ]; then
			echo "cannot find requested HIBA $EXT $ext"
			return 1
		fi
		if [ "$TYPE" = "user" -a ! -f "$dest/policy/principals/$ID/$ext" ]; then
			echo "user $ID not eligible for grant $ext"
			return 1
		fi
		HIBAEXTS+=("$(cat $dest/policy/$SUB/$ext)")
	done
	HIBAOPTS=("-O" extension:$EXT@hibassh.dev=$(IFS=,; echo "${HIBAEXTS[*]}"))

	serial=$(get_next_serial)
	echo "== Signing $TYPE key ID $ID"
	if ssh-keygen -I "$ID" -s "$dest/ca" $T -z "$serial" -n "$PRINCIPALS" -V "$VALIDITY" "${HIBAOPTS[@]}" "$@" "$TARGET.pub"; then
		echo "$(date +%s),$serial,$PRINCIPAL,$HIBA" >> $dest/logs
	fi
}

#
# Main
#
ca=
create=
dest="$HOME/.hiba-ca"
host=
hiba=
name=
file=
principal=
sign=
import=
remove=
list=
manage=
cleanup=
revoke=
policy=
policy_remove=
list_policy=
list_revocations=
user=
serial=
validity="+1h"
verbose=0
days=90

while getopts "cilprskuhvf:I:n:N:d:H:V:z:" opt; do
	case $opt in
		c) create=1;;
		i) import=1;;
		l) list=1;;
		p) policy=1;;
		r) remove=1;;
		s) sign=1;;
		k) manage=1;;
		u) user=1;;
		h) host=1;;
		f) file="$OPTARG";;
		I) name="$OPTARG";;
		z) serial="$OPTARG";;
		n) principal="$principal $OPTARG";;
		N) days="$OPTARG";;
		d) dest="$OPTARG";;
		H) hiba="$hiba $OPTARG";;
		V) validity="$OPTARG";;
		v) verbose=1;;
		?) usage "Unknown option $opt";;
	esac
done

principal=$(echo "$name $principal" | xargs)
hiba=$(echo "$hiba" | xargs)
shift $((OPTIND - 1))

# Remove (-r) is a modifier of policy and manage subcommand:
if [ "${policy}${remove}" = "11" ]; then
	remove=
	policy=
	policy_remove=1
fi
if [ "${manage}${remove}" = "11" ]; then
	remove=
	manage=
	revoke=1
fi

# Cleanup (-c) is a modifier of manage subcommand:
if [ "${manage}${create}" = "11" ]; then
	create=
	manage=
	cleanup=1
fi

# Policy (-p) and Manage (-k) are modifiers of list subcommand:
if [ "${policy}${list}" = "11" ]; then
	policy=
	list_policy=1
fi
if [ "${manage}${list}" = "11" ]; then
	manage=
	list_revocations=1
fi

# Sanity check command line
action="${create}${sign}${import}${remove}${list}${policy}${manage}${policy_remove}${cleanup}${revoke}"
if [ -z "$action" ]; then
	usage "at least one action out of [-s | -c | -i | -a | -r | -l | -k] required."
fi
if [ "$action" != "1" ]; then
	usage "only one action out of [-s | -c | -i | -a | -r | -l | -k] required."
fi
if [ -z "$user" ] && [ -z "$host" ]; then
	ca=1
fi
if [ -n "$user" ] && [ -n "$host" ] && [ -z "$list" ]; then
	usage "only one type out of [-u | -h] required."
fi

# Check create required command line parameters
if [ "$create" = 1 ]; then
	# If creating a user of host identity, a name is required.
	if [ -z "$ca" ] && [ -z "$name" ]; then
		usage "missing -I <name> for user or host identity creation."
	fi
	if [ -n "$ca" ] && [ -n "$name" ]; then
		usage "unexpected -I <name> for CA identity creation."
	fi
fi

# Check list required command line parameters
if [ "$list" = 1 ]; then
	# If none of -u -h -p -k is given, display them all
	if [ -z "${user}${host}${list_policy}${list_revocations}" ]; then
		user=1
		host=1
		list_policy=1
		list_revocations=1
	fi
fi

# Check import required command line parameters
if [ "$import" = 1 ]; then
	# Only user / host identities can be imported.
	if [ -n "$ca" ]; then
		usage "missing -u or -h parameter for identity import."
	fi
	# If importing a user of host identity, pubkey is required.
	if [ -z "$file" ]; then
		usage "missing -f <pubkey path> for importing identity."
	fi
	# If the username is missing use the pubkey filename.
	if [ -z "$name" ] ; then
		fname=$(basename $file)
		name=${file%.pub}
		echo "missing -I <name> option, assuming $name"
	fi
	# The username should not already exist
	if [ -n "$user" -a -f "$dest/users/$name.pub" ]; then
		usage "user $name already exists."
	elif [ -n "$host" -a -f "$dest/hosts/$name.pub" ]; then
		usage "host $name already exists."
	fi
fi

# Check remove required command line parameters
if [ "$remove" = 1 ]; then
	# Only user / host identities can be removed.
	if [ -n "$ca" ]; then
		usage "missing -u or -h parameter for identity removal."
	fi
	# If removing a user, the user name is required.
	if [ -z "$name" ]; then
		usage "missing -I <name> for removing identity."
	fi
	# The username should already exist
	if [ -n "$user" -a ! -f "$dest/users/$name.pub" ]; then
		usage "user $name doesn't exist."
	elif [ -n "$host" -a ! -f "$dest/hosts/$name.pub" ]; then
		usage "host $name doesn't exist."
	fi
fi

# Check policy required command line parameters
if [ "${policy}${policy_remove}" = 1 ]; then
	# policy permission need a target name
	if [ -z "$name" ] ; then
		usage "missing -I <name> for managing policy permissions."
	fi
	if [ -z "$hiba" ] ; then
		usage "missing -H <grant> for managing policy permissions."
	fi
	# the user and grant should exist
	if [ ! -f "$dest/users/$name.pub" ]; then
		usage "user $name doesn't exist."
	fi
	for grant in $hiba; do
		if [ ! -f "$dest/policy/grants/$grant" ]; then
			usage "grant $grant doesn't exist."
		fi
		# For removal the eligibility must exist
		if [ -n "$policy_remove" -a ! -f "$dest/policy/principals/$name/$grant" ]; then
			usage "user $name not eligible for grant $grant."
		fi
		# For additions, the eligibility must not exist
		if [ -n "$policy" -a -f "$dest/policy/principals/$name/$grant" ]; then
			usage "user $name s already eligible for grant $grant."
		fi
	done
fi

# Check sign required command line parameters
if [ "$sign" = 1 ]; then
	if [ -z "$user" ] && [ -z "$host" ]; then
		usage "at least one type out of [-U | -h] required."
	fi
	if [ -z "$name" ]; then
		usage "missing -I <name> for user or host signing."
	fi
	if [ -z "$principal" ]; then
		usage "missing -n <principal> for user or host signing."
	fi
	if [ -z "$validity" ]; then
		usage "missing -V <validity> for user or host signing."
	fi
fi

# Check revoke required command line parameters
if [ "$revoke" = 1 ]; then
	# the certificate serial is required.
	if [ -z "$serial" -a -z "$hiba" ]; then
		usage "missing -z <revocation spec> or -H grant for revocation."
	elif [ -n "$serial" -a -n "$hiba" ]; then
		usage "only one of -z <serial> or -H grant allowed at once for revocation."
	fi
fi

# Check log required command line parameters
if [ "$manage" = 1 ]; then
	# the cut off must by a number of days.
	if [ "$days" -eq 0 ]; then
		usage "-N must be a integer representing the number of days to display."
	fi
fi

# Check cleanup required command line parameters
if [ "$cleanup" = 1 ]; then
	# the cut off must by a number of days.
	if [ "$days" -eq 0 ]; then
		usage "-N must be a integer representing the number of days to keep."
	fi
fi

if [ "$verbose" = 1 ]; then
  set -x
fi

# Init the CA
mkdir -p "$dest/policy/principals"
mkdir -p "$dest/policy/identities"
mkdir -p "$dest/policy/grants"
mkdir -p "$dest/hosts"
mkdir -p "$dest/users"

# Run required action
if [ "$list" = 1 ]; then
	echo "== Certificate Authority location =="
	echo "$dest"
	echo ""
	if [ -n "$user" ]; then
		echo "== Users =="
		for u in $(find "$dest/users/" -name '*.pub'); do
			userpub=$(basename $u)
			user=${userpub%.pub}
			[[ "$user" = *-cert ]] && continue
			eligible=$(ls "$dest/policy/principals/$user" | xargs)
			echo "* $user: eligible for [$eligible]"
		done
		echo ""
	fi
	if [ -n "$host" ]; then
		echo "== Hosts =="
		for h in $(find $dest/hosts/ -name '*.pub'); do
			hostpub=$(basename $h)
			host=${userpub%.pub}
			[[ "$host" = *-cert ]] && continue
			echo "* $host"
		done
		echo ""
	fi
	if [ -n "$list_policy" ]; then
		echo "== HIBA identities (decode using hiba-gen -d -f <filename>) =="
		for i in $(ls $dest/policy/identities/); do
			echo "* $dest/policy/identities/$i"
		done
		echo ""
		echo "== HIBA grants (decode using hiba-gen -d -f <filename>) =="
		for i in $(ls $dest/policy/grants/); do
			echo "* $dest/policy/grants/$i"
		done
		echo ""
	fi
	if [ -n "$list_revocations" ]; then
		echo "== KRL =="
		ssh-keygen -Q -f "$dest/krl" -l | tr "#" "*" | sed '/^$/d'
		echo ""
		echo "== GRL =="
                hiba-grl -f "$dest/grl" -d -c "$dest $(ssh-keygen -lf $dest/ca.pub)"
	fi
elif [ "$create" = 1 ]; then
	if [ "$ca" = 1 ]; then
		rm  -f  "$dest/logs"
		create_key "CA" "$dest/ca" -C "$dest CA" "$@" || error
		echo "" | revoke_cert "" "-" &> /dev/null
		echo "== Done =="
	elif [ "$host" = 1 ]; then
		create_key "host" "$dest/hosts/$name" "$@" || error
		echo "== Done =="
		echo "Identity created: Private: $dest/hosts/$name"
		echo "                  Public:  $dest/hosts/$name.pub"
	elif [ "$user" = 1 ]; then
		create_key "user" "$dest/users/$name" "$@" || error
		mkdir -p "$dest/policy/principals/$name"
		echo "== Done =="
		echo "Identity created: Private: $dest/users/$name"
		echo "                  Public:  $dest/users/$name.pub"
	fi
elif [ "$import" = 1 ]; then
	if [ "$host" = 1 ]; then
		cp "$file" "$dest/hosts/$name.pub"
		echo "== Done =="
		echo "Identity imported: $dest/hosts/$name.pub"
	elif [ "$user" = 1 ]; then
		cp "$file" "$dest/users/$name.pub"
		mkdir -p "$dest/policy/principals/$name"
		echo "== Done =="
		echo "Identity imported: Public: $dest/users/$name.pub"
	fi
elif [ "$remove" = 1 ]; then
	if [ "$host" = 1 ]; then
		echo "key: $(cat $dest/hosts/$name.pub)" | revoke_cert "-u" "-"
		rm -f "$dest/hosts/$name"
		rm -f "$dest/hosts/$name.pub"
		rm -f "$dest/hosts/$name-cert.pub"
		echo "== Done =="
		echo "Identity removed: $name"
	elif [ "$user" = 1 ]; then
		echo "key: $(cat $dest/users/$name.pub)" | revoke_cert "-u" "-"
		rm -f "$dest/users/$name"
		rm -f "$dest/users/$name.pub"
		rm -f "$dest/users/$name-cert.pub"
		rm -rf "$dest/policy/principals/$name"
		echo "== Done =="
		echo "Identity removed: $name"
	fi
elif [ "$policy" = 1 ]; then
	for grant in $hiba; do
		ln -s "$dest/policy/grants/$grant" "$dest/policy/principals/$name/$grant"
	done
	echo "== Done =="
	echo "User $name is now eligible for [$hiba]"
elif [ "$policy_remove" = 1 ]; then
	for grant in $hiba; do
		revoke_grants "$name" "$grant" || error
		rm "$dest/policy/principals/$name/$grant"
	done
	echo "== Done =="
	echo "User $name is not eligible anymore for [$hiba]"
elif [ "$sign" = 1 ]; then
	if [ "$host" = 1 ]; then
		sign "host" "$name" "$dest/hosts/$name" "$principal" "$validity" "$hiba" "$@" || error
		echo "== Done =="
		echo "Certificate created: $dest/hosts/$name-cert.pub"
	elif [ "$user" = 1 ]; then
		sign "user" "$name" "$dest/users/$name" "$principal" "$validity" "$hiba" "$@" || error
		echo "== Done =="
		echo "Certificate created: $dest/users/$name-cert.pub"
	fi
elif [ "$revoke" = 1 ]; then
	if [ -n "$serial" ]; then
		revoke_cert "-u" "$serial" || error
	else
		for h in $hiba; do
			revoke_grants ".*" "$h" || error
		done
	fi
	echo "== Done =="
elif [ "$manage" = 1 ]; then
	echo "Signed certificates log for the last $days days:"
	get_logs "$days" '$1 " " $2' | while read d s; do
		echo "  [$(date --date=@$d)]: serial $s"
	done
	echo "== Done =="
elif [ "$cleanup" = 1 ]; then
	cleanup_logs "$days"
	echo "== Done =="
fi
