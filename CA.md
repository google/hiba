# Example CA Usage

Although there is more than one way to handle extensions (grants/identities) and
signing certificates, HIBA includes a `hiba-ca.sh` tool and `hiba-gen` binary.
The following serves as a simple example of a way to get started with HIBA.

Once you have completed the
[compilation instructions](https://github.com/google/hiba/blob/main/INSTALL.md#compilation)
you will have a `hiba-gen` and `hiba-ca.sh` in your hiba directory. You can now
create CA keys, grants, identities, grant eligibility, and sign host and user
certificates with these extensions. The following assumes you are in your hiba
directory.

## Key design: two separate CA signing keys

This example uses **two distinct CA keypairs**: one exclusively for signing host
certificates and one exclusively for signing user certificates. Keeping them
separate limits the blast radius of a key compromise — a leaked user CA cannot
be used to forge trusted host certificates, and vice versa.

| CA directory       | Signs                  | Public key distributed to        |
|--------------------|------------------------|----------------------------------|
| `~/.hiba-ca-host/` | Host certificates      | SSH clients (via `known_hosts`)   |
| `~/.hiba-ca-user/` | User certificates      | SSH servers (via `TrustedUserCAKeys`) |

## hiba-ca.sh flag reference

`hiba-ca.sh` accepts one **action** flag plus optional **type** and **parameter**
flags:

| Flag | Meaning |
|------|---------|
| `-c` | **Create** — generate a new CA or identity keypair |
| `-i` | **Import** — register an existing public key with this CA |
| `-s` | **Sign** — issue a certificate for a registered key |
| `-p` | **Policy** — grant a user eligibility to request a specific grant |
| `-r` | **Remove** — delete an identity from the CA |
| `-l` | **List** — display CA contents (no private keys shown) |
| `-k` | **Manage** — inspect or clean signing logs; revoke certificates/grants |
| `-u` | Type modifier: operate on a **user** identity |
| `-h` | Type modifier: operate on a **host** identity |
| `-I <name>` | Identity name (username or hostname) |
| `-H <name>` | HIBA grant name (user certs) or HIBA identity name (host certs) |
| `-V <interval>` | Certificate validity period (default `+1h`; same format as `ssh-keygen -V`) |
| `-f <path>` | Path to a public key file (used with `-i` to import) |
| `-n <principal>` | Additional SSH principal; defaults to the value of `-I` if omitted |
| `-d <path>` | CA root directory (default `~/.hiba-ca`) |

## Steps

1. **Generate the host CA keypair** — the private key that will sign every host
   certificate.
    ```
    $ ./hiba-ca.sh -c -d ~/.hiba-ca-host
    == Generating CA keys in ~/.hiba-ca-host/ca
    Enter passphrase (empty for no passphrase):
    Enter same passphrase again:
    == Done ==
    ```
    * `-c` creates a new CA keypair (`~/.hiba-ca-host/ca` private,
      `~/.hiba-ca-host/ca.pub` public).
    * `-d ~/.hiba-ca-host` sets the CA root to a dedicated directory for host
      signing. This keeps the host CA key entirely separate from the user CA key.

1. **Generate the user CA keypair** — the private key that will sign every user
   certificate.
    ```
    $ ./hiba-ca.sh -c -d ~/.hiba-ca-user
    == Generating CA keys in ~/.hiba-ca-user/ca
    Enter passphrase (empty for no passphrase):
    Enter same passphrase again:
    == Done ==
    ```
    * `-d ~/.hiba-ca-user` stores this CA in its own directory. The resulting
      `~/.hiba-ca-user/ca.pub` is the key you will add to `TrustedUserCAKeys`
      on every SSH server — it is **different** from the host CA public key.

1. **Register a user keypair** with the user CA. Generate a new keypair or
   import an existing one.
    ```
    $ ./hiba-ca.sh -c -u -I testuser -d ~/.hiba-ca-user
    == Generating user keys in ~/.hiba-ca-user/users/testuser
    == Done ==
    Identity created: Private: ~/.hiba-ca-user/users/testuser
                      Public:  ~/.hiba-ca-user/users/testuser.pub
    ```
    * `-c` generates a new ED25519 keypair for the user.
    * `-u` tells `hiba-ca.sh` this is a **user** identity (not a host).
    * `-I testuser` sets the identity name to `testuser`.
    * `-d ~/.hiba-ca-user` registers the key in the user CA directory.
    * Alternatively, import an existing public key instead of generating one:
        ```
        $ ./hiba-ca.sh -i -u -f ~/.ssh/id_rsa.pub -I testuser -d ~/.hiba-ca-user
        == Done ==
        Identity imported: Public: ~/.hiba-ca-user/users/testuser.pub
        ```
        * `-i` imports rather than generating.
        * `-f ~/.ssh/id_rsa.pub` is the path to the existing public key.

1. **Register a host keypair** with the host CA. Copy the OpenSSH server's
   existing host public key from the server to your machine and import it, or
   generate a new keypair here and distribute the private key to the host later.
    ```
    $ ./hiba-ca.sh -i -h -f path_to_host_pubkey -I testhost -d ~/.hiba-ca-host
    == Done ==
    Identity imported: ~/.hiba-ca-host/hosts/testhost.pub
    ```
    * `-i` imports an existing public key (no new private key is generated).
    * `-h` tells `hiba-ca.sh` this is a **host** identity.
    * `-f path_to_host_pubkey` is the path to the host's public key file.
    * `-I testhost` sets the name used to refer to this host within the CA.
    * `-d ~/.hiba-ca-host` registers the key in the host CA directory.
    * Alternatively, generate a fresh host keypair:
        ```
        $ ./hiba-ca.sh -c -h -I testhost -d ~/.hiba-ca-host
        == Generating host keys in ~/.hiba-ca-host/hosts/testhost
        Enter passphrase (empty for no passphrase):
        Enter same passphrase again:
        == Done ==
        Identity created: Private: ~/.hiba-ca-host/hosts/testhost
                          Public:  ~/.hiba-ca-host/hosts/testhost.pub
        ```

1. **Create a HIBA identity** for the `prod` environment and attach it to the
   host CA's policy store. When the host certificate is signed in step 7, this
   identity extension will be embedded in it.
    ```
    $ ./hiba-gen -i -f ~/.hiba-ca-host/policy/identities/prod domain example.com
    ```
    * `-i` creates an **identity** extension (used in host certificates).
    * `-f ~/.hiba-ca-host/policy/identities/prod` is the output file path.
    * `domain example.com` is the key-value pair encoded into the extension.
      The domain field is matched against the domain field in user grants.

1. **Create a HIBA grant** for shell access and attach it to the user CA's
   policy store. When the user certificate is signed in step 8, this grant
   extension will be embedded in it.
    ```
    $ ./hiba-gen -f ~/.hiba-ca-user/policy/grants/shell domain example.com
    ```
    * Without `-i`, `hiba-gen` creates a **grant** extension (used in user
      certificates).
    * `-f ~/.hiba-ca-user/policy/grants/shell` is the output file path.
    * `domain example.com` must match the `domain` field in the host's identity
      for `hiba-chk` to approve the connection.

1. **Allow testuser to request the shell grant.**
    ```
    $ ./hiba-ca.sh -p -I testuser -H shell -d ~/.hiba-ca-user
    == Done ==
    User testuser is now eligible for [shell]
    ```
    * `-p` sets a **policy** permission (grant eligibility).
    * `-I testuser` is the user whose policy is being updated.
    * `-H shell` is the grant name to allow. `-H` can be repeated to permit
      multiple grants at once.
    * `-d ~/.hiba-ca-user` operates on the user CA directory where `testuser`
      is registered.

1. **Sign the host certificate** using the **host CA** private key. This embeds
   the `prod` HIBA identity extension and establishes the certificate's validity
   window.
    ```
    $ ./hiba-ca.sh -s -h -I testhost -H prod -V +12w -d ~/.hiba-ca-host
    == Signing host key ID testhost
    Signed host key ~/.hiba-ca-host/hosts/testhost-cert.pub: id "testhost" serial 1 for testhost valid from 2022-12-14T16:36:00 to 2023-03-14T16:36:00
    == Done ==
    Certificate created: ~/.hiba-ca-host/hosts/testhost-cert.pub
    ```
    * `-s` enters **sign** mode.
    * `-h` signs a **host** certificate (causes `ssh-keygen` to use the `-h`
      flag internally, marking this as a host certificate rather than a user
      certificate).
    * `-I testhost` selects the host key registered in step 4.
    * `-H prod` embeds the `prod` HIBA identity extension. This tells
      `hiba-chk` which environment this host belongs to.
    * `-V +12w` sets a validity period of 12 weeks from now.
    * `-d ~/.hiba-ca-host` uses the **host CA** private key
      (`~/.hiba-ca-host/ca`) to sign — **not** the user CA key.

1. **Sign the user certificate** using the **user CA** private key. This embeds
   the `shell` HIBA grant extension and limits how long the certificate is valid.
    ```
    $ ./hiba-ca.sh -s -u -I testuser -H shell -d ~/.hiba-ca-user
    == Signing user key ID testuser
    Signed user key ~/.hiba-ca-user/users/testuser-cert.pub: id "testuser" serial 1 for testuser valid from 2022-12-14T16:37:00 to 2022-12-14T17:38:39
    == Done ==
    Certificate created: ~/.hiba-ca-user/users/testuser-cert.pub
    ```
    * `-s` enters sign mode.
    * `-u` signs a **user** certificate.
    * `-I testuser` selects the user key registered in step 3.
    * `-H shell` embeds the `shell` HIBA grant extension. This is what
      `hiba-chk` evaluates against the host's identity to decide whether
      to allow the connection.
    * No `-V` flag is given here; the default validity of `+1h` applies.
    * `-d ~/.hiba-ca-user` uses the **user CA** private key
      (`~/.hiba-ca-user/ca`) to sign — a **different key** from the one
      used to sign the host certificate in the previous step.

1. **Distribute the certificates and CA public keys** to the relevant machines.
   Copy the host certificate to your OpenSSH server which has been configured
   with `hiba-chk` as the `AuthorizedPrincipalsCommand`. Copy the **user CA**
   public key (`~/.hiba-ca-user/ca.pub`) to the OpenSSH server and add it to
   `TrustedUserCAKeys` — this is what the server uses to verify user
   certificates. The **host CA** public key (`~/.hiba-ca-host/ca.pub`) goes
   into the client's `known_hosts` so that SSH clients can verify the host
   certificate. See the [configuration
   documentation](https://github.com/google/hiba/blob/main/INSTALL.md#configuration)
   for details.

1. **Use the user certificate to log in.**
    ```
    $ ssh -i ~/.hiba-ca-user/users/testuser testuser@device.example.com
    ```
