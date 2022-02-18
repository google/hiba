# HIBA: Host Identity Based Authorization

Pronounce: /hiːba/

## What is HIBA

HIBA is a system built on top of regular OpenSSH certificate-based
authentication that allows to manage flexible authorization of principals on
pools of target hosts without the need to push customized authorized_users files
periodically.

The authorization is performed directly on the target host based on the user
certificate content and the local host identity only. Not accessing external
services makes it suitable for low dependency, last resort, SSH access.

For more details on how authorization is computed, see
[PROTOCOL.authorizations](https://github.com/google/hiba/blob/main/PROTOCOL.authorizations).

## Concepts

HIBA defines two concepts: host identity and grants. See
[PROTOCOL.extensions](https://github.com/google/hiba/blob/main/PROTOCOL.extensions)
for the exact specifications.

### Host identity

This is a custom extension attached to host certificates that describes the main
properties of a target host. The format is flexible and only mandates one
field, `domain`, to help isolate different pools of hosts managed using the
same CA keys.

An example of a host identity could be:

* domain: dmz.example.com
* owner: frontend-team
* location: US

### Grants

This is also a custom extension, attached to user certificates that describes
which hosts this certificate should be accepted on. The grant contains a set of
constraints that a host must match for the access to be authorized. These
constraints are compared to the host identity at connection time by the hiba-chk
helper. Due to the flexible nature of the host identity, the following
semantics apply:

* Any field present in the grant and missing for the host identity is
  considered invalid and will prevent access.
* Any field missing from the grant and present in the host identity is
  ignored for authorization purposes (equivalent to a wildcard).

### Mechanism

HIBA relies on a few properties provided by OpenSSH:

* Certificate based authentication: a HIBA grant is a custom extension attached
  to the certificate. This means the CA is responsible for verifying the scope
  of the grant before attaching it.  Similarly, the host identity is attached to
  the host certificate by the CA and must represent the target host.
* AuthorizedPrincipalsCommand: this option of the sshd_config allows invoking an
  external tool to dynamically generate the content of authorized_users. This
  option is used to invoke `hiba-chk`, which knows how to extract the HIBA
  extensions from user and host certificates and grants or denies access based
  on the comparison.

### GRL (Grant Revocation List)

HIBA allows revoking individual grants rather than the whole certificate. See
[PROTOCOL.grl](PROTOCOL.grl) for more information.

Note: revocations at the grant granularity are not yet supported. The rationale
for not prioritizing these: full SSH certificate revocation is already supported
by OpenSSH, only the finer granularity is lacking. Also, it is good practice
to rely on short lived certificates, which often expire before the revocation
list makes it to the target host.

## Prerequisites

HIBA works on top of OpenSSH certificates. It relies on:

* The AuthorizedPrincipalsCommand option that was added to OpenSSH 6.9
* The `%u` and `%k` tokens that were added to OpenSSH 7.4

For compilation, configuration and installation instructions, see
[INSTALL.md](https://github.com/google/hiba/blob/main/INSTALL.md).

## Developers

The HIBA library can be used to add support for HIBA to a certificate authority.

Note: None of this code is thread safe, and it is the responsibility of
the caller to ensure proper locking when accessing individual HIBA structures.

### Generating HIBA enabled certificates

HIBA enabled certificates are generated using the HIBA API defined in
[extensions.h](https://github.com/google/hiba/blob/main/extensions.h) and the
OpenSSH API defined in
[sshkey.h](https://github.com/openssh/openssh-portable/blob/master/sshkey.h).

* Using libhiba:
  * Import or generate the required HIBA extensions (identity or grant)
  * Serialize them into an sshbuf
* Using libssh:
  * Import or generate the SSH public key
  * Attach generated extensions
  * Sign the certificate with the CA private key
  * Serialize it

### Reading HIBA enabled certificates

HIBA extensions can be extracted from existing certificates by relying on
OpenSSH to decode/verify the certificate, extracting the HIBA extensions and
interpreting them with HIBA.

* Using libssh:
  * Import certificate
  * Verify certificate signature
  * List and extract relevant extensions
* Using libhiba:
  * Parse extensions
  * Extract extensions' content

libhiba provides convenience functions to parse and extract HIBA extensions
directly from a certificate, but it does not verify the certificate. It assumes
the certificate was validated by a prior stage.
