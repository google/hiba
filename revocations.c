/*
 * Copyright 2022 The HIBA Authors
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */
#include <inttypes.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "errors.h"
#include "log.h"
#include "revocations.h"

#define HIBA_CURRENT_GRL_VERSION	0x1
#define HIBA_MIN_SUPPORTED_GRL_VERSION	0x1

// Stores a list of all the certificates with revoked grants.
// This structure is meant to be mapped directly on top of a mmapped revocation
// file on top of the serial list section (see PROTOCOL.grl).
struct serials {
	u_int64_t serial;
	u_int64_t offset;
} __attribute__((packed));

// Parsed list of revocations.
struct parsed_revocations {
	u_int64_t serial;
	u_int16_t size;
	char *map;

	struct parsed_revocations *next;
};

// In memory representation of the GRL.
// The 'parsed' field is a linked list to revocations entries. The first
// element of that list (if it exists) is the head and doesn't contain any
// revocation information.
struct hibagrl {
	u_int32_t version;
	u_int32_t min_version;
	u_int64_t timestamp;
	u_int32_t n_serials;
	u_int64_t bitmaps_size;
	char *comment;

	const struct serials *serials;
	const unsigned char *bitmaps;

	struct parsed_revocations *parsed;
};

void
hibagrl_free(struct hibagrl *grl) {
	struct parsed_revocations *r;

	if (grl == NULL)
		return;

	r = grl->parsed;
	while (r != NULL) {
		struct parsed_revocations *tbd = r;
		r = r->next;
		free(tbd->map);
		free(tbd);
	}

	free(grl->comment);
	free(grl);
}

struct hibagrl*
hibagrl_new() {
	struct hibagrl *grl = calloc(sizeof(struct hibagrl), 1);
	return grl;
}

void
hibagrl_init(struct hibagrl *grl, const char *comment) {
	if (grl == NULL)
		return;

	memset(grl, 0, sizeof(struct hibagrl));
	grl->version = HIBA_CURRENT_GRL_VERSION;
	grl->min_version = HIBA_MIN_SUPPORTED_GRL_VERSION;
	grl->comment = strdup(comment);

	// Allocate the head of the parsed linked list to show this is an
	// editable GRL.
	grl->parsed = calloc(1, sizeof(struct parsed_revocations));
}

int
hibagrl_version(const struct hibagrl *grl) {
	if (grl == NULL) {
		return HIBA_BAD_PARAMS;
	}
	return grl->version;
}

const char*
hibagrl_comment(const struct hibagrl *grl) {
	if (grl == NULL) {
		return hiba_err(-HIBA_BAD_PARAMS);
	}
	return grl->comment;
}

u_int64_t
hibagrl_timestamp(const struct hibagrl *grl) {
	if (grl == NULL) {
		return 0;
	}
	return grl->timestamp;
}

u_int64_t
hibagrl_serials_count(const struct hibagrl *grl) {
	if (grl == NULL) {
		return 0;
	}
	return grl->n_serials;
}

int
hibagrl_decode(struct hibagrl *grl, struct sshbuf *blob) {
	int ret;
	u_int32_t magic;
	u_int64_t serials_section_size;

	if (grl == NULL || blob == NULL)
		return HIBA_BAD_PARAMS;

	memset(grl, 0, sizeof(struct hibagrl));

	if ((ret = sshbuf_get_u32(blob, &magic)) < 0) {
		debug3("hibagrl_decode: sshbuf_get_u32 returned %d: %s", ret, ssh_err(ret));
		return HIBA_INTERNAL_ERROR;
	}
	if (magic != HIBA_GRL_MAGIC) {
		return HIBA_INVALID_GRL;
	}

	if ((ret = sshbuf_get_u32(blob, &grl->version)) != 0) {
		debug3("hibagrl_decode: sshbuf_get_u32 returned %d: %s", ret, ssh_err(ret));
		return HIBA_INTERNAL_ERROR;
	}
	if ((ret = sshbuf_get_u32(blob, &grl->min_version)) != 0) {
		debug3("hibagrl_decode: sshbuf_get_u32 returned %d: %s", ret, ssh_err(ret));
		return HIBA_INTERNAL_ERROR;
	}
	if ((ret = sshbuf_get_u64(blob, &grl->timestamp)) != 0) {
		debug3("hibagrl_decode: sshbuf_get_u64 returned %d: %s", ret, ssh_err(ret));
		return HIBA_INTERNAL_ERROR;
	}
	if ((ret = sshbuf_get_cstring(blob, &grl->comment, NULL)) != 0) {
		debug3("hibagrl_decode: sshbuf_get_cstring returned %d: %s", ret, ssh_err(ret));
		return HIBA_INTERNAL_ERROR;
	}

	// Get the serials section
	if ((ret = sshbuf_get_u64(blob, &serials_section_size)) != 0) {
		debug3("hibagrl_decode: sshbuf_get_u64 returned %d: %s", ret, ssh_err(ret));
		return HIBA_INTERNAL_ERROR;
	}
	grl->n_serials = serials_section_size / sizeof(struct serials);
	debug2("hibagrl_decode: serials_section_size = %" PRIu64, serials_section_size);
	grl->serials = (const struct serials *)sshbuf_ptr(blob);
	if (log_level_get() >= SYSLOG_LEVEL_DEBUG3) {
		debug3("hibagrl_decode: serial list section content @%zu", blob->off);
		sshbuf_dump_data(sshbuf_ptr(blob), serials_section_size, stderr);
	}
	if ((ret = sshbuf_consume(blob, serials_section_size)) != 0) {
		debug3("hibagrl_decode: sshbuf_consume returned %d: %s", ret, ssh_err(ret));
		return HIBA_INTERNAL_ERROR;
	}

	// Get the bitmaps section
	if ((ret = sshbuf_get_u64(blob, &grl->bitmaps_size)) != 0) {
		debug3("hibagrl_decode: sshbuf_get_u64 returned %d: %s", ret, ssh_err(ret));
		return HIBA_INTERNAL_ERROR;
	}
	debug2("hibagrl_decode: bitmaps_section_size = %" PRIu64, grl->bitmaps_size);
	grl->bitmaps = sshbuf_ptr(blob);
	if (log_level_get() >= SYSLOG_LEVEL_DEBUG3) {
		debug3("hibagrl_decode: bitmap section content @%zu", blob->off);
		sshbuf_dump_data(sshbuf_ptr(blob), grl->bitmaps_size, stderr);
	}
	if ((ret = sshbuf_consume(blob, grl->bitmaps_size)) != 0) {
		debug3("hibagrl_decode: sshbuf_consume returned %d: %s", ret, ssh_err(ret));
		return HIBA_INTERNAL_ERROR;
	}

	if ((ret = sshbuf_get_u32(blob, &magic)) < 0) {
		debug3("hibagrl_decode: sshbuf_get_u32 returned %d: %s", ret, ssh_err(ret));
		return HIBA_INTERNAL_ERROR;
	}
	if (magic != HIBA_GRL_MAGIC) {
		return HIBA_INVALID_GRL;
	}

	// The parsed_revocations field is left NULL on purpose and will only be
	// actually parsed from serials/bitmaps sections when needed using
	// hibagrl_map().
	debug2("hibagrl_decode: grl->n_serials = %" PRIu32, grl->n_serials);

	return HIBA_OK;
}

int
hibagrl_map(struct hibagrl *grl) {
	u_int64_t i = 0;
	struct parsed_revocations *r;

	if (grl == NULL)
		return HIBA_BAD_PARAMS;
	if (grl->parsed != NULL)
		return HIBA_BAD_PARAMS;

	// The first parsed_revocation doesn't count, it is only used as the
	// head of the linked list.
	grl->parsed = calloc(1, sizeof(struct parsed_revocations));
	r = grl->parsed;

	debug("hibagrl_map: mapping %" PRIu32 " serials", grl->n_serials);
	for (i = 0; i < grl->n_serials; ++i) {
		u_int64_t offset;
		u_int64_t next_offset = grl->bitmaps_size;

		r->next = calloc(1, sizeof(struct parsed_revocations));
		r = r->next;
		r->serial = PEEK_U64(&grl->serials[i].serial);
		offset = PEEK_U64(&grl->serials[i].offset);

		if (i+1 < grl->n_serials) {
			next_offset = PEEK_U64(&grl->serials[i+1].offset);
		}
		r->size = next_offset - offset;
		r->map = calloc(1, r->size);
		memcpy(r->map, grl->bitmaps + offset, r->size);
	}

	// Nullify mmapped sections since we now have an editable GRL.
	grl->serials = NULL;
	grl->bitmaps = NULL;
	grl->bitmaps_size = 0;

	return 0;
}

int
hibagrl_encode(const struct hibagrl *grl, struct sshbuf *blob) {
	int ret;
	struct parsed_revocations *r;
	u_int64_t serials_section_size;
	u_int64_t i = 0;
	u_int64_t offset = 0;

	if (grl == NULL || blob == NULL || grl->parsed == NULL)
		return HIBA_BAD_PARAMS;

	// Write the header.
	if ((ret = sshbuf_put_u32(blob, HIBA_GRL_MAGIC)) < 0) {
		debug3("hibagrl_encode: sshbuf_put_u32 returned %d: %s", ret, ssh_err(ret));
		return HIBA_INTERNAL_ERROR;
	}
	if ((ret = sshbuf_put_u32(blob, grl->version)) < 0) {
		debug3("hibagrl_encode: sshbuf_put_u32 returned %d: %s", ret, ssh_err(ret));
		return HIBA_INTERNAL_ERROR;
	}
	if ((ret = sshbuf_put_u32(blob, grl->min_version)) < 0) {
		debug3("hibagrl_encode: sshbuf_put_u32 returned %d: %s", ret, ssh_err(ret));
		return HIBA_INTERNAL_ERROR;
	}
	if ((ret = sshbuf_put_u64(blob, time(NULL))) < 0) {
		debug3("hibagrl_encode: sshbuf_put_u64 returned %d: %s", ret, ssh_err(ret));
		return HIBA_INTERNAL_ERROR;
	}
	if ((ret = sshbuf_put_cstring(blob, grl->comment)) < 0) {
		debug3("hibagrl_encode: sshbuf_put_cstring returned %d: %s", ret, ssh_err(ret));
		return HIBA_INTERNAL_ERROR;
	}
	serials_section_size = grl->n_serials * sizeof(struct serials);
	debug2("hibagrl_encode: grl->n_serials = %" PRIu32, grl->n_serials);
	debug2("hibagrl_decode: serials_section_size = %" PRIu64, serials_section_size);
	if ((ret = sshbuf_put_u64(blob, serials_section_size)) < 0) {
		debug3("hibagrl_encode: sshbuf_put_u64 returned %d: %s", ret, ssh_err(ret));
		return HIBA_INTERNAL_ERROR;
	}

	// Now we build the serial list.
	debug3("hibagrl_encode: serial list section @%zu", sshbuf_len(blob));
	if ((ret = sshbuf_allocate(blob, serials_section_size)) < 0) {
		debug3("hibagrl_encode: sshbuf_allocate(%" PRIu64 ") returned %d: %s",
		       serials_section_size, ret, ssh_err(ret));
		return HIBA_INTERNAL_ERROR;
	}

	// Calculate and reserve room for the bitmap size.
	r = grl->parsed;
	while (r->next != NULL) {
		r = r->next;

		// Add the serial to the 1st section.
		if ((ret = sshbuf_put_u64(blob, r->serial)) < 0) {
			debug3("hibagrl_encode: sshbuf_put_u64 returned %d: %s", ret, ssh_err(ret));
			return HIBA_INTERNAL_ERROR;
		}
		if ((ret = sshbuf_put_u64(blob, offset)) < 0) {
			debug3("hibagrl_encode: sshbuf_put_u64 returned %d: %s", ret, ssh_err(ret));
			return HIBA_INTERNAL_ERROR;
		}

		offset += r->size;
	}

	if ((ret = sshbuf_put_u64(blob, offset)) < 0) {
		debug3("hibagrl_encode: sshbuf_put_u64 returned %d: %s", ret, ssh_err(ret));
		return HIBA_INTERNAL_ERROR;
	}
	if ((ret = sshbuf_allocate(blob, offset)) < 0) {
		debug3("hibagrl_encode: sshbuf_allocate(%" PRIu64 ") returned %d: %s",
		       offset, ret, ssh_err(ret));
		return HIBA_INTERNAL_ERROR;
	}

	debug3("hibagrl_encode: bitmap section @%zu", sshbuf_len(blob));

	r = grl->parsed;
	while (r->next != NULL) {
		int m;
		r = r->next;

		for (m = 0; m < r->size; ++m) {
			if ((ret = sshbuf_put_u8(blob, r->map[m])) < 0) {
				debug3("hibagrl_encode: sshbuf_put_u8 returned %d: %s", ret, ssh_err(ret));
				return HIBA_INTERNAL_ERROR;
			}
		}
		offset += r->size + sizeof(r->size);

		++i;
	}

	debug2("hibagrl_encode: patch bitmap section size = %" PRIu64, offset);

	// Write trailer magic.
	if ((ret = sshbuf_put_u32(blob, HIBA_GRL_MAGIC)) < 0) {
		debug3("hibagrl_encode: sshbuf_put_u32 returned %d: %s", ret, ssh_err(ret));
		return HIBA_INTERNAL_ERROR;
	}

	return HIBA_OK;
}

// The block of a grant index represents the char that contains the bit
// representing the grant.
// This corresponds to the floor of the position of the bit divided by 8 (size
// of a char).
static inline u_int32_t
block_for_idx(u_int32_t idx) {
	return idx >> 3;
}

// The offset of a grant index represents the position of the bit representing
// the grant inside the block.
// This corresponds to remainder of the position of the bit divided by 8 (size
// of a char).
static inline u_int32_t
offset_for_idx(u_int32_t idx) {
	return idx & 0x7;
}

// We want to update the offset in the right block.
static inline void
revoke_idx(struct parsed_revocations *r, u_int32_t idx) {
	u_int32_t block = block_for_idx(idx);
	u_int32_t offset = offset_for_idx(idx);
	debug("REVOKE_ID(%d): map[%d] |= %02x", idx, block, offset);
	r->map[block] |= 1 << offset;
}

// A grant ID is marked as revoked if both conditions hold true:
// - the map size is larger or equal to the grant idx.
// - the grant ID corresponding bit is set.
static inline int
is_revoked_idx(const unsigned char *bitmap, u_int32_t size, u_int32_t idx) {
	u_int32_t block = block_for_idx(idx);
	u_int32_t offset = offset_for_idx(idx);
	return (block <= size) && ((1 << offset) & bitmap[block]);
}

int
hibagrl_revoke_grant(struct hibagrl *grl, u_int64_t serial, u_int32_t lo, u_int32_t hi) {
	u_int32_t i;
	int required_size = 0;
	struct parsed_revocations *r;

	if (grl == NULL)
		return HIBA_BAD_PARAMS;
	if (grl->parsed == NULL)
		return HIBA_BAD_PARAMS;

	// Look for where to add the revocation.
	r = grl->parsed;
	while (r->next) {
		if (r->next->serial >= serial)
			break;
		r = r->next;
	}

	// Maybe add a new serial to the ordered list.
	if ((r->next == NULL) || (r->next->serial > serial)) {
		struct parsed_revocations *next = r->next;
		debug2("hibagrl_revoke_grant: adding a new entry for serial 0x%" PRIx64 " after 0x%" PRIx64 , serial, r->serial);
		r->next = calloc(1, sizeof(struct parsed_revocations));
		r = r->next;
		r->next = next;
		r->serial = serial;

		++grl->n_serials;
	} else {
		r = r->next;
		debug2("hibagrl_revoke_grant: reusing existing entry for serial 0x%" PRIx64, serial);
	}

	required_size = block_for_idx(hi) + 1;

	// Allocate or update the bitmap
	if (r->size < required_size) {
		char *prev_map = r->map;
		debug2("hibagrl_revoke_grant: resizing map to %d", required_size);
		r->map = calloc(required_size, 1);
		memcpy(r->map, prev_map, r->size);
		r->size = required_size;
		free(prev_map);
	}
	// Add our grants.
	for (i = lo; i <= hi; ++i) {
		revoke_idx(r, i);
	}

	return 0;
}

int
hibagrl_check(const struct hibagrl *grl, u_int64_t serial, u_int32_t grant_idx) {
	u_int64_t offset;
	u_int64_t size;
	u_int64_t min = 0;
	u_int64_t max;
	u_int64_t cur;

	if (grl == NULL)
		return HIBA_BAD_PARAMS;
	if (grl->serials == NULL || grl->bitmaps == NULL)
		return HIBA_BAD_PARAMS;

	// Early return if the GRL contains no serials.
	if (grl->n_serials == 0)
		return HIBA_OK;

	max = grl->n_serials - 1;
	cur = (max - min) / 2;

	// First we search through serials.
	while (1) {
		u_int64_t min_serial = PEEK_U64(&grl->serials[min].serial);
		u_int64_t max_serial = PEEK_U64(&grl->serials[max].serial);
		u_int64_t cur_serial;

		if ((min_serial > serial) ||
		    (max_serial < serial)) {
			debug2("hibagrl_check: outside of GRL range [0x%" PRIx64 " - 0x%" PRIx64 "]: 0x%" PRIx64,
			       min_serial, max_serial, serial);
			return HIBA_OK;
		}

		cur_serial = PEEK_U64(&grl->serials[cur].serial);
		debug3("hibagrl_check: current serial 0x%" PRIx64 " @%" PRIx64, cur_serial, cur);

		if (cur_serial == serial) {
			// We only break the loop when we found a matching
			// serial which index we store in cur.
			break;
		} else if (cur_serial > serial) {
			max = cur;
			cur = min + ((max - min) / 2);
		} else if (cur_serial < serial) {
			min = cur;
			cur = min + ((max - min) / 2) + 1;
		}

		// There is nothing left between min and max. We can return OK.
		if (max == min) {
			debug2("hibagrl_check: not present in GRL: 0x%" PRIx64, serial);
			return HIBA_OK;
		}
	}

	debug2("hibagrl_check: found in GRL: 0x%" PRIx64, serial);

	// If the offset points outside of the bitmap, our GRL is invalid.
	// Fail closed.
	offset = PEEK_U64(&grl->serials[cur].offset);
	if (offset > grl->bitmaps_size)
		return HIBA_BAD_PARAMS;

	if (cur >= grl->n_serials - 1)
		size = grl->bitmaps_size - offset;
	else
		size = PEEK_U64(&grl->serials[cur+1].offset) - offset;

	if (is_revoked_idx(grl->bitmaps + offset, size, grant_idx))
		return HIBA_CHECK_REVOKED;
	return HIBA_OK;
}

static void
dump_map(const struct parsed_revocations *r, FILE *f) {
	int i;
	for (i = 0; i < r->size; ++i) {
		fprintf(f, "%02X", (r->map[i] & 0xF) << 4 | r->map[i] >> 4);
	}
	fprintf(f, "\n");
}

int
hibagrl_dump_content(const struct hibagrl *grl, u_int64_t *serial, FILE *f) {
	struct parsed_revocations *r;

	if (grl == NULL)
		return HIBA_BAD_PARAMS;
	if (grl->parsed == NULL)
		return HIBA_BAD_PARAMS;

	r = grl->parsed;
	while (r->next != NULL) {
		r = r->next;
		if (serial == NULL || r->serial == *serial) {
			fprintf(f, "  [0x%.16" PRIx64 "]: ", r->serial);
			dump_map(r, f);

			// When filtering on serial, we can early exit as each
			// serial appears at most once.
			if (serial)
				break;
		}
	}
	fprintf(f, "\n");

	return HIBA_OK;
}
