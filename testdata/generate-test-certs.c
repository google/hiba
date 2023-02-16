#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

#ifdef WITH_EXTENSION_COMPRESSION
#include <zlib.h>
#endif  /* WITH_EXTENSION_COMPRESSION */

#include "authfile.h"
#include "hiba.h"
#include "sshbuf.h"
#include "sshkey.h"

int save_cert_with_extension(struct sshkey *key, struct sshkey *ca, struct sshbuf *data, char *fname) {
	struct sshbuf *b = sshbuf_new();

	sshbuf_reset(key->cert->extensions);
	sshbuf_put_cstring(key->cert->extensions, HIBA_GRANT_ID);
	sshbuf_put_string(b, sshbuf_ptr(data), sshbuf_len(data));
	sshbuf_put_stringb(key->cert->extensions, b);

	sshkey_certify(key, ca, NULL, "", "");
	sshkey_save_public(key, fname, "");

	sshbuf_free(b);

	return 0;
}

int main(int argc, char **argv) {
	int type, compressed;
	char *fname;
	char **plist;
	struct sshbuf *v;
	const struct hibaext **es;
	struct hibaext *e1 = hibaext_new();
	struct hibaext *e2 = hibaext_new();
	struct sshkey *prv;
	struct sshkey *key = sshkey_new(KEY_UNSPEC);
	struct sshkey *ca = sshkey_new(KEY_UNSPEC);

	/* check args. */
	if (argc < 3) {
		fprintf(stderr, "./generate-test-certs <type> <fname>\n");
		exit(1);
	}
	type = strtol(argv[1], NULL, 10);
	compressed = (type+1) % 2;
	fname = argv[2];

	/* Generate a user public key and prepare certificates. */
	sshkey_generate(KEY_RSA, 2048, &prv);
	sshkey_from_private(prv, &key);

	plist = malloc(sizeof(char*));
	plist[0] = strdup("foobar");

	sshkey_to_certified(key);
	key->cert->type = 1;
	key->cert->serial = 12;
	key->cert->key_id = strdup("test");
	key->cert->nprincipals = 1;
	key->cert->principals = plist;
	key->cert->valid_after = 0;
	key->cert->valid_before = 0;

	/* Generate a CA signing key. */
	sshkey_generate(KEY_RSA, 2048, &ca);

	/* Build sample the HIBA extensions. */
	hibaext_init(e1, HIBA_GRANT_EXT);
	hibaext_init(e2, HIBA_GRANT_EXT);

	hibaext_add_pair(e1, "domain", "hibassh.dev");
	hibaext_add_pair(e1, "id", "1");

	hibaext_add_pair(e2, "domain", "hibassh.dev");
	hibaext_add_pair(e2, "id", "2");

	/* Prepare buffers. */
	v = sshbuf_new();

	/* Serialize. */
	switch (type) {
	case 1:  /* single RAW */
	case 2:  /* single RAW compressed */
		hibaext_encode_raw((const struct hibaext**)&e1, 1, compressed, v);
		break;
	case 3:  /* single B64 */
	case 4:  /* single B64 compressed */
		hibaext_encode_b64((const struct hibaext**)&e1, 1, compressed, v);
		break;
	case 5:  /* multi RAW */
	case 6:  /* multi RAW compressed */
		es = malloc(2*sizeof(struct hibaext*));
		es[0] = e1;
		es[1] = e2;
		hibaext_encode_raw(es, 2, compressed, v);
		break;
	case 7:  /* multi B64 */
	case 8:  /* multi B64 compressed */
		es = malloc(2*sizeof(struct hibaext*));
		es[0] = e1;
		es[1] = e2;
		hibaext_encode_b64(es, 2, compressed, v);
		break;
	default:
		fprintf(stderr, "Unknown type %s.\n", argv[1]);
		exit(1);
	}

	save_cert_with_extension(key, ca, v, fname);

	return 0;
}
