# Example CA Usage

Although there is more than one way to handle extensions (grants/identities) and
signing certificates, HIBA includes a `hiba-ca.sh` tool and `hiba-gen` binary.
The following serves as a simple example of a way to get started with HIBA.

Once you have completed the
[compilation instructions](https://github.com/google/hiba/blob/main/INSTALL.md#compilation)
you will have a `hiba-gen` and `hiba-ca.sh` in your hiba directory. You can now
create CA keys, grants, identities, grant eligibility, and sign host and user
certificates with these extensions. The following assumes you are in your hiba
directory. The CA structure will be in `~/.hiba-ca` by default.

1. Generate a CA keypair.
    ```
    $ ./hiba-ca.sh -c
    == Generating CA keys in ~/.hiba-ca/ca
    Enter passphrase (empty for no passphrase):
    Enter same passphrase again:
    == Done ==
    ```
1. Generate a user keypair
    ```
    $ ./hiba-ca.sh -c -u -I testuser
    == Generating user keys in ~/.hiba-ca/users/testuser
    == Done ==
    Identity created: Private: ~/.hiba-ca/users/testuser
                      Public:  ~/.hiba-ca/users/testuser.pub
    ```
    * Alternatively you can copy existing keys
        ```
        $ ./hiba-ca.sh -i -u -f ~/.ssh/id_rsa.pub -I testuser
        == Done ==
        Identity imported: Public: ~/.hiba-ca/users/testuser.pub
        ```
1. Copy the OpenSSH server host public key from the OpenSSH server to your
   machine and import it.
    ```
    $ ./hiba-ca.sh -i -h -f path_to_pubkey -I hostname
    ```
    * Alternatively you can generate a new host keypair
        ```
        $ ./hiba-ca.sh -c -h -I hostname
        == Generating host keys in ~/.hiba-ca/hosts/hostname
        Enter passphrase (empty for no passphrase):
        Enter same passphrase again:
        == Done ==
        Identity created: Private: ~/.hiba-ca/hosts/hostname
        Public:  ~/.hiba-ca/hosts/hostname.pub
        ```
1. Create an identity for prod, with a domain of example.com.
    ```
    $ ./hiba-gen -i -f ~/.hiba-ca/policy/identities/prod domain example.com
    ```
1. Create a grant called `shell` with a matching domain.
    ```
    $ ./hiba-gen -f ~/.hiba-ca/policy/grants/shell domain example.com
    ```
1. Allow testuser to request this grant (shell).
    ```
    $ ./hiba-ca.sh -p -I testuser -H shell
    == Done ==
    User testuser is now eligible for [shell]
    ```
1. Sign the OpenSSH server public key into a certificate. -I points to the
   hostname you set when importing the host public key and -V is the validity
   duration.
    ```
    $ ./hiba-ca.sh -s -h -I test -H prod -V +12w
    == Signing host key ID test
    Signed host key ~/.hiba-ca/hosts/test-cert.pub: id "test" serial 1 for test valid from 2022-12-14T16:36:00 to 2023-03-14T16:36:00
    == Done ==
    Certificate created: ~/.hiba-ca/hosts/test-cert.pub
    ```
1. Get a certificate for testuser with a grant extension (shell).
    ```
    $ ./hiba-ca.sh -s -u -I testuser -H shell
    == Signing user key ID testuser
    Signed user key ~/.hiba-ca/users/testuser-cert.pub: id "testuser" serial 2 for testuser valid from 2022-12-14T16:37:00 to 2022-12-14T17:38:39
    == Done ==
    Certificate created: ~/.hiba-ca/users/testuser-cert.pub
    ```
1. Copy the host certificate to your OpenSSH server which has been configured
   with `hiba-chk` as the `AuthorizedPrincipalsCommand`. Copy the CA public key
(~/.hiba-ca/ca.pub) to the OpenSSH server and add it to the TrustedUserCaKeys
file. See the [configuration
documentation](https://github.com/google/hiba/blob/main/INSTALL.md#configuration)
for details.
1.  Use the user certificate to log in.
    ```
    $ ssh -i ~/.hiba-ca/users/testuser testuser@device.example.com
    ```
