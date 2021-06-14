# Getting started with HIBA

## Compilation

HIBA depends on OpenSSH source code for building and relies on the autotools.

Make sure OpenSSH is compiled before running `make` in the HIBA directory, or
the compilation will fail. For instructions compiling OpenSSH, refer to the
[INSTALL](https://github.com/openssh/openssh-portable/blob/master/INSTALL) file
inside OpenSSH's sources.

To compile HIBA, run the `./autogen.sh` followed by `./configure` using
the `--with-opensshdir` pointing at the root of the OpenSSH sources, and
finally, run `make`.

```
$ ./autogen.sh 
$ ./configure --with-opensshdir=/path/to/openssh/sources/ --prefix=/usr/
$ make
```

## Installation

Running `sudo make install` will default to installing all binaries, manpages,
libraries and include files into your system using the prefix `/usr/local/`. To
have HIBA installed directly in `/usr/` instead, use the `--prefix=/usr` option
to `./configure` or run `make install prefix=/usr/` directly.

```
$ sudo make install
```

### In more details

The host managing the CA needs:

* a valid installation of openssh-client (for ssh-keygen)
* [optional] the hiba-ca.sh script for managing certificates
* [optional] libhiba for generating HIBA extensions
* [optional] hiba-gen for generating HIBA extensions

The host authenticating using HIBA needs:

* a valid installation of openssh-server (version >= 7.4)
* hiba-chk
* [optional] a GRL file
* The CA pubkey
* The host private key
* The host certificate
* The sshd_config for using HIBA (see Configuration section below)

The host issuing connection requests:

* a valid installation of openssh-client
* The CA pubkey
* The user private key
* The user certificate with a valid HIBA extension attached

## Configuration

The configuration file on the host side is `/etc/ssh/sshd_config`:

* PubkeyAuthentication: enabled
* HostKey (or the sshd `-h` command line parameter): points to the private key
  of the host SSH identity
* HostCertificate (or the sshd `-c` command line parameter): point to the
  certificate matching host SSH identity
* TrustedUserCAKeys: pointing to the CA public key
* AuthorizedPrincipalsCommandUser: pointing one of: sshd user, `%u`, or
  `nobody` (HIBA requires no special permissions).
* AuthorizedPrincipalsCommand: pointing to the hiba-chk command line

  ```
  /usr/sbin/hiba-chk -i /etc/ssh/ssh_host_dsa_key-cert.pub -g /etc/ssh/hiba.grl -r %u %k
  ```

Example:

```
$ cat /etc/ssh/sshd_config
# Enable host key and certificate
HostKey /etc/ssh/ssh_host_rsa_key
HostCertificate /etc/ssh/ssh_host_rsa_key-cert.pub

# Enable certificate based authentication
PubkeyAuthentication yes

# Declare CA
TrustedUserCAKeys /etc/ssh/ca.pub

# Enable HIBA authorization
AuthorizedPrincipalsCommand /usr/sbin/hiba-chk -i /etc/ssh/ssh_host_ssa_key-cert.pub -g /etc/ssh/hiba.grl -r %u %k
AuthorizedPrincipalsCommandUser nobody
```

The configuration on the client side is optional, but provide with better trust
of the target hosts: `/etc/ssh/ssh_config`:

* GlobalKnownHostsFile: pointing to a KnownHost file containing the CA pubkey
* StrictHostKeyChecking: enabled, now that we use certificate based
  authentication, this doesn't cause noise anymore

Example:

```
$ cat /etc/ssh/ssh_config
# Enable host key checking
StrictHostKeyChecking yes

# Declare our trusted CA
GlobalKnownHostsFile /etc/ssh/known_hosts
```

And the KnownHost file can be generate with:

```
$ echo "@cert-authority * $(cat /etc/ssh/ca.pub)" > /etc/ssh/known_hosts
```

## Testing

For testing HIBA on a local setup, the `testdata/setup-local.sh` script is
provided. This script will:

* Generate the test CA and all keys
* Generate demo HIBA extensions
* Sign the certificates with extensions
* Generate ssh client and server configs
* Start 2 local sshd servers (simulating 2 different hosts)
