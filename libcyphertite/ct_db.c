/*
 * Copyright (c) 2010-2012 Conformal Systems LLC <info@conformal.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <clog.h>
#include <exude.h>
#include <sqlite3.h>

#include "ct_types.h"
#include "ct_db.h"

static int		 ctdb_open(struct ctdb_state *);
static void		ctdb_cleanup(struct ctdb_state *);
static int		ctdb_create(struct ctdb_state *);
static int		ctdb_check_db_mode(struct ctdb_state *);

#define CT_DB_VERSION	1
#define OPS_PER_TRANSACTION	(100)
struct ctdb_state {
	sqlite3			*ctdb_db;
	char			*ctdb_dbfile;
	sqlite3_stmt		*ctdb_stmt_lookup;
	sqlite3_stmt		*ctdb_stmt_insert;
	sqlite3_stmt		*ctdb_stmt_update;
	int			 ctdb_crypt;
	int			 ctdb_genid;
	int			 ctdb_in_transaction;
	int			 ctdb_trans_commit_rem;
	int			 ctdb_in_cull;
};

static int
ctdb_begin_transaction(struct ctdb_state *state)
{
	int			 rc;
	char			*errmsg = NULL;

	CNDBG(CT_LOG_DB, "beginning transaction");
	if ((rc = sqlite3_exec(state->ctdb_db, "BEGIN TRANSACTION", NULL,
	     0, &errmsg)) != 0) {
		CNDBG(CT_LOG_DB, "can't begin transaction: %s",
		    errmsg);
		return (rc);
	}
	state->ctdb_in_transaction = 1;
	return (0);

}

static void
ctdb_end_transaction(struct ctdb_state *state)
{
	char			*errmsg = NULL;

	CNDBG(CT_LOG_DB, "commiting transaction");
	if (sqlite3_exec(state->ctdb_db, "COMMIT", NULL,
	    0, &errmsg) != 0) {
		/* this isn't a failure case because ctdb is a cache */
		CNDBG(CT_LOG_DB, "can't commit %s", errmsg);
		/* sqlite tells us to rollback just in case */
		(void)sqlite3_exec(state->ctdb_db, "ROLLBACK", NULL, 0,
		    &errmsg);
	}
	state->ctdb_in_transaction = 0;
}

struct ctdb_state *
ctdb_setup(const char *path, int crypt_enabled)
{
	struct ctdb_state	*state;
	if (path == NULL)
		return (NULL);
	state = e_calloc(1, sizeof(*state));

	state->ctdb_genid = -1;
	state->ctdb_crypt = crypt_enabled;
	state->ctdb_dbfile = e_strdup(path);
	if (ctdb_open(state) != 0) {
		e_free(&state->ctdb_dbfile);
		e_free(&state);
	}
	return (state);
}

void
ctdb_shutdown(struct ctdb_state *state)
{
	if (state == NULL)
		return;

	ctdb_cleanup(state);
	if (state->ctdb_dbfile)
		e_free(&state->ctdb_dbfile);
	e_free(&state);
}

int
ctdb_create(struct ctdb_state *state)
{
	int			rc;
	char			*errmsg = NULL;
	char			sql[4096];

	if (state->ctdb_genid == -1)
		state->ctdb_genid = 0;
	rc = sqlite3_open_v2(state->ctdb_dbfile, &state->ctdb_db,
	    SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
	if (rc)
		return (rc);

	if (state->ctdb_crypt)
		snprintf(sql, sizeof sql,
		    "CREATE TABLE digests (sha BLOB(%d)"
		    " PRIMARY KEY UNIQUE,"
		    " csha BLOB(%d), iv BLOB(%d), genid INTEGER);",
		    SHA_DIGEST_LENGTH, SHA_DIGEST_LENGTH,
		    CT_IV_LEN);
	else
		snprintf(sql, sizeof sql,
		    "CREATE TABLE digests (sha BLOB(%d)"
		    " PRIMARY KEY UNIQUE, genid INTEGER);",
		    SHA_DIGEST_LENGTH);

	CNDBG(CT_LOG_DB, "sql: %s", sql);
	rc = sqlite3_exec(state->ctdb_db, sql, NULL, 0, &errmsg);
	if (rc) {
		CNDBG(CT_LOG_DB, "create failed: %s", errmsg);
		state->ctdb_db = NULL;
		return (rc);
	}
	snprintf(sql, sizeof sql,
	    "CREATE TABLE mode (crypto TEXT, version INTEGER);");
	rc = sqlite3_exec(state->ctdb_db, sql, NULL, 0, &errmsg);
	if (rc) {
		CNDBG(CT_LOG_DB, "mode table creation failed");
		sqlite3_close(state->ctdb_db);
		state->ctdb_db = NULL;
		return (rc);
	}
	snprintf(sql, sizeof sql,
	    "INSERT INTO mode (crypto, version) VALUES ('%c', %d);",
		state->ctdb_crypt ? 'Y': 'N', CT_DB_VERSION);
	rc = sqlite3_exec(state->ctdb_db, sql, NULL, 0, &errmsg);
	if (rc) {
		CNDBG(CT_LOG_DB, "mode table init failed");
		sqlite3_close(state->ctdb_db);
		state->ctdb_db = NULL;
		return (rc);
	}

	snprintf(sql, sizeof sql,
	    "CREATE TABLE genid (value INTEGER);");
	rc = sqlite3_exec(state->ctdb_db, sql, NULL, 0, &errmsg);
	if (rc) {
		CNDBG(CT_LOG_DB, "gendi table creation failed");
		sqlite3_close(state->ctdb_db);
		state->ctdb_db = NULL;
		return (rc);
	}
	snprintf(sql, sizeof sql,
	    "insert into genid (value) VALUES (%d);", state->ctdb_genid);
	rc = sqlite3_exec(state->ctdb_db, sql, NULL, 0, &errmsg);
	if (rc) {
		CNDBG(CT_LOG_DB, "mode table init failed");
		sqlite3_close(state->ctdb_db);
		state->ctdb_db = NULL;
		return (rc);
	}

	return (SQLITE_OK);
}

int
ctdb_upgrade_db(struct ctdb_state *state, int oldversion)
{
	int		 newversion;
	char		 sql[1024];
	char		*errmsg;

	CNDBG(CT_LOG_DB, "oldversion: %d", oldversion);
	if (sqlite3_exec(state->ctdb_db, "BEGIN TRANSACTION", NULL, 0,
	    &errmsg)) {
		CNDBG(CT_LOG_DB, "can't begin %s", errmsg);
	}

	switch (oldversion) {
	case -1:
		if (sqlite3_exec(state->ctdb_db,
		    "ALTER TABLE digests ADD COLUMN genid INTEGER", NULL, 0, &errmsg)) {
			goto abort;
		}

		if (sqlite3_exec(state->ctdb_db,
		    "UPDATE digests SET genid = (SELECT value FROM genid)",
		    NULL, 0, &errmsg)) {
			goto abort;
		}
		/* FALLTHROUGH */
	case CT_DB_VERSION:
		newversion = CT_DB_VERSION;
		break;
	default:
		goto abort;
	}

	if (oldversion == newversion) {
		if (sqlite3_exec(state->ctdb_db, "ROLLBACK", NULL, 0,
		    &errmsg)) {
			CNDBG(CT_LOG_DB, "can't rollback %s", errmsg);
			return (1);
		}
		return (0);
	}
	CNDBG(CT_LOG_DB, "updated ct db from version %d to %d", oldversion,
	    newversion);
	snprintf(sql, sizeof(sql), "UPDATE mode SET version = %d;",
	    CT_DB_VERSION);
	if (sqlite3_exec(state->ctdb_db, sql, NULL, 0, &errmsg)) {
		CNDBG(CT_LOG_DB, "sqlupdatedb failed set version: %s:", errmsg);
		goto abort;
	}

	if (sqlite3_exec(state->ctdb_db, "COMMIT", NULL, 0, &errmsg)) {
		CNDBG(CT_LOG_DB, "sqlupdatedb commit failed: %s:", errmsg);
		return (1);
	}
	return (0);


abort:
	if (sqlite3_exec(state->ctdb_db, "ROLLBACK", NULL, 0, &errmsg))
		CNDBG(CT_LOG_DB, "can't rollback %s", errmsg);

	return (1);
}

int
ctdb_check_db_mode(struct ctdb_state *state)
{
	sqlite3_stmt		*stmt;
	char			*p, wanted;
	int			rc, rv = 0, curgenid, ver = -1;

	CNDBG(CT_LOG_DB, "ctdb mode %d\n", state->ctdb_crypt);
	if (sqlite3_prepare_v2(state->ctdb_db,
	    "SELECT crypto, version FROM mode", -1, &stmt, NULL)) {
		CNDBG(CT_LOG_DB, "can't prepare mode query statement");
		goto fail;
	}
	rc = sqlite3_step(stmt);
	if (rc == SQLITE_DONE) {
		CNDBG(CT_LOG_DB, "ctdb mode not found");
		goto fail;
	} else if (rc != SQLITE_ROW) {
		CNDBG(CT_LOG_DB, "could not step(%d) %d %d %s",
		    __LINE__, rc,
		    sqlite3_extended_errcode(state->ctdb_db),
		    sqlite3_errmsg(state->ctdb_db));
		goto fail;
	}
	p = (char *)sqlite3_column_text(stmt, 0);
	if (p) {
		wanted =  state->ctdb_crypt ? 'Y' : 'N';
		if (sqlite3_column_bytes(stmt, 0) != 1) {
			CNDBG(CT_LOG_DB, "ctdb invalid length of column 1");
			goto fail;
		}
		CNDBG(CT_LOG_DB, "ctdb crypto mode %c %c", p[0], wanted);
		if (p[0] != wanted) {
			CNDBG(CT_LOG_DB, "ctdb crypto mode differs %c %c",
			    p[0], wanted);
			goto fail;
		}
	}

	/* early version of localdb didn't fill in version correctly */
	if (sqlite3_column_type(stmt, 1) == SQLITE_NULL ||
	    (ver = sqlite3_column_int(stmt, 1)) < CT_DB_VERSION) {
		if (ctdb_upgrade_db(state, ver)) {
			CNDBG(CT_LOG_DB,"failed to upgrade db!");
			goto fail;
		}
	}
	if (sqlite3_finalize(stmt)) {
		CNDBG(CT_LOG_DB, "can't finalise statement");
		goto fail;
	}

	if (sqlite3_prepare_v2(state->ctdb_db, "SELECT value FROM genid",
	    -1, &stmt, NULL)) {
		CNDBG(CT_LOG_DB, "old format db detected, reseting db");
		goto fail;
	}
	rc = sqlite3_step(stmt);
	if (rc == SQLITE_DONE) {
		CNDBG(CT_LOG_DB, "ctdb genid not found");
		goto fail;
	} else if (rc != SQLITE_ROW) {
		CNDBG(CT_LOG_DB, "could not step(%d) %d %d %s", __LINE__,
		    rc, sqlite3_extended_errcode(state->ctdb_db),
		    sqlite3_errmsg(state->ctdb_db));
		goto fail;
	}
	curgenid = sqlite3_column_int(stmt, 0);
	sqlite3_finalize(stmt);
	stmt = NULL;

	if (state->ctdb_genid == -1 || state->ctdb_genid == curgenid) {
		state->ctdb_genid = curgenid;
	} else if (state->ctdb_genid > curgenid) {
		if (sqlite3_prepare(state->ctdb_db,
		    "UPDATE genid SET value = ?", -1, &stmt, NULL)) {
			CNDBG(CT_LOG_DB, "can't prepare update genid stmt");
			goto fail;
		}
		if (sqlite3_bind_int(stmt, 1, state->ctdb_genid) != 0) {
			CNDBG(CT_LOG_DB, "can't bind update genid stmt");
			goto fail;
		}
		if (sqlite3_step(stmt) != SQLITE_DONE) {
			CNDBG(CT_LOG_DB, "didn't get done on updating genid");
			goto fail;
		}
		CNDBG(CT_LOG_DB, "updated genid from %d to %d",
		    curgenid, state->ctdb_genid);
	} else {
		CNDBG(CT_LOG_DB, "ctdb genid is %d, wanted %d", curgenid,
		    state->ctdb_genid);
		goto fail;
	}

	CNDBG(CT_LOG_DB, "Mode check successful");
	rv = 1;
fail:
	/* not much we can do if this fails */
	if (stmt != NULL && sqlite3_finalize(stmt))
		CNDBG(CT_LOG_DB, "can't finalize verification lookup");
	return rv;
}

void
ctdb_set_genid(struct ctdb_state *state, int genid)
{
	sqlite3_stmt		*stmt;

	if (state == NULL || state->ctdb_db == NULL)
		return;
	if (genid == state->ctdb_genid)
		return;

	CNDBG(CT_LOG_DB, "update genid from %d to %d", state->ctdb_genid,
	    genid);

	/* -1 means turn off database! */
	if (genid == -1) {
		ctdb_cleanup(state);
		state->ctdb_genid = genid;
	}
	/*
	 * If no crypt then we can't save any operations so best to just clear
	 * the db out.
	 */
	if (state->ctdb_crypt == 0) {
		ctdb_cleanup(state);
		unlink(state->ctdb_dbfile);
		state->ctdb_genid = genid;
		(void)ctdb_open(state); /* this should not fail */
	}

	state->ctdb_genid = genid;
	if (sqlite3_prepare(state->ctdb_db,
	    "UPDATE genid SET value = ?", -1, &stmt, NULL)) {
		CNDBG(CT_LOG_DB, "can't prepare update genid stmt");
		goto fail;
	}
	if (sqlite3_bind_int(stmt, 1, state->ctdb_genid) != 0) {
		CNDBG(CT_LOG_DB, "can't bind update genid stmt");
		goto fail;
	}
	if (sqlite3_step(stmt) != SQLITE_DONE) {
		CNDBG(CT_LOG_DB, "didn't get done on updating genid");
		goto fail;
	}

fail:
	/* not much we can do if we fail, probably means oom */
	return;

}

int
ctdb_open(struct ctdb_state *state)
{
	int			rc;
	int			retry = 1;
	char			*psql;

do_retry:
	rc = sqlite3_open_v2(state->ctdb_dbfile, &state->ctdb_db,
	    SQLITE_OPEN_READWRITE, NULL);
	if (rc == SQLITE_CANTOPEN) {
		CNDBG(CT_LOG_DB, "db file doesn't exist, creating it");
		rc = ctdb_create(state);
		if (rc != SQLITE_OK)
			return 1;
	}
	if (ctdb_check_db_mode(state) == 0) {
		if (retry) {
			retry = 0;
			/* db is in incorrect mode, delete it and try again */
			CNDBG(CT_LOG_DB, "db file wrong mode, removing it");
			sqlite3_close(state->ctdb_db);
			unlink(state->ctdb_dbfile);
			goto do_retry;
		} else {
			/* db recreated in incorrect mode!?! */
			ctdb_cleanup(state);
			return (1);
		}

	}

	/* prepare query here based on crypt mode */
	if (state->ctdb_crypt) {
		psql = "SELECT csha, iv, genid FROM digests WHERE sha=?";
	} else {
		psql = "SELECT sha, genid FROM digests WHERE sha=?";
	}

	if (sqlite3_prepare(state->ctdb_db, psql,
	    -1, &state->ctdb_stmt_lookup, NULL)) {
		CNDBG(CT_LOG_DB, "can't prepare select statement");
		ctdb_cleanup(state);
		return 1;
	}
	CNDBG(CT_LOG_DB, "ctdb_stmt_lookup %p", state->ctdb_stmt_lookup);
	if (state->ctdb_crypt) {
		psql = "INSERT INTO digests(sha, csha, iv, genid) "
		    "values(?, ?, ?, ?)";
	} else {
		psql = "INSERT INTO digests(sha, genid) values(?, ?)";
	}
	if (sqlite3_prepare_v2(state->ctdb_db, psql,
	    -1, &state->ctdb_stmt_insert, NULL)) {
		CNDBG(CT_LOG_DB, "can not prepare insert statement %s", psql);
		ctdb_cleanup(state);
		return 1;
	}
	CNDBG(CT_LOG_DB, "ctdb_stmt_insert %p", state->ctdb_stmt_insert);

	psql = "UPDATE digests SET genid = ? where sha = ?";
	if (sqlite3_prepare_v2(state->ctdb_db, psql,
	    -1, &state->ctdb_stmt_update, NULL)) {
		CNDBG(CT_LOG_DB, "can not prepare update statement %s", psql);
		ctdb_cleanup(state);
		return 1;
	}
	CNDBG(CT_LOG_DB, "ctdb_stmt_update %p", state->ctdb_stmt_update);

	return 0;
}

void
ctdb_cleanup(struct ctdb_state *state)
{
	CNDBG(CT_LOG_DB, "cleaning up ctdb");
	if (state->ctdb_in_transaction) {
		CNDBG(CT_LOG_DB, "finalising transactions");
		ctdb_end_transaction(state);
	}
	if (state->ctdb_stmt_lookup != NULL) {
		CNDBG(CT_LOG_DB, "finalising stmt_lookup");
		if (sqlite3_finalize(state->ctdb_stmt_lookup))
			CNDBG(CT_LOG_DB, "can't finalize lookup");
	}
	if (state->ctdb_stmt_insert != NULL) {
		CNDBG(CT_LOG_DB, "finalising stmt_insert");
		if (sqlite3_finalize(state->ctdb_stmt_insert))
			CNDBG(CT_LOG_DB, "can't finalize insert");
	}
	if (state->ctdb_stmt_update != NULL) {
		CNDBG(CT_LOG_DB, "finalising stmt_update");
		if (sqlite3_finalize(state->ctdb_stmt_update))
			CNDBG(CT_LOG_DB, "can't finalize update");
	}

	if (state->ctdb_db != NULL) {
		CNDBG(CT_LOG_DB, "closing db");
		sqlite3_close(state->ctdb_db);
		state->ctdb_db = NULL;
	}
}

int
ctdb_get_genid(struct ctdb_state *state)
{
	if (state == NULL || state->ctdb_db == NULL)
		return (-1);
	return (state->ctdb_genid);
}

enum ctdb_lookup
ctdb_lookup_sha(struct ctdb_state *state, uint8_t *sha_k, uint8_t *sha_v,
     uint8_t *iv, int32_t *old_genid)
{
	char			 shat[SHA_DIGEST_STRING_LENGTH];
	int			 rv, rc;
	int32_t			 genid;
	uint8_t			*p;
	sqlite3_stmt		*stmt;

	rv = CTDB_SHA_NEXISTS;
	*old_genid = -1;

	if (state == NULL || state->ctdb_db == NULL)
		return rv;

	stmt = state->ctdb_stmt_lookup;

	if (state->ctdb_in_transaction == 0) {
		if (ctdb_begin_transaction(state) != 0)
			return (rv);
		state->ctdb_trans_commit_rem = OPS_PER_TRANSACTION;
	}

	if (clog_mask_is_set(CT_LOG_DB)) {
		ct_sha1_encode(sha_k, shat);
		CNDBG(CT_LOG_DB, "looking for bin %s", shat);
	}
	if (sqlite3_bind_blob(stmt, 1, sha_k, SHA_DIGEST_LENGTH,
	    SQLITE_STATIC)) {
		CNDBG(CT_LOG_DB, "could not sha");
		return (CTDB_SHA_NEXISTS);
	}

	rc = sqlite3_step(stmt);
	if (rc == SQLITE_DONE) {
		CNDBG(CT_LOG_DB, "not found");
		sqlite3_reset(stmt);
		return CTDB_SHA_NEXISTS;
	} else if (rc != SQLITE_ROW) {
		CNDBG(CT_LOG_DB, "could not step(%d) %d %d %s",
		    __LINE__, rc,
		    sqlite3_extended_errcode(state->ctdb_db),
		    sqlite3_errmsg(state->ctdb_db));
		sqlite3_reset(stmt);
		return CTDB_SHA_NEXISTS;
	}

	CNDBG(CT_LOG_DB, "found");

	p = (uint8_t *)sqlite3_column_blob(stmt, 0);
	if (p) {
		if (sqlite3_column_bytes(stmt, 0) !=
		    SHA_DIGEST_LENGTH) {
			CNDBG(CT_LOG_DB, "invalid blob size");
			sqlite3_reset(stmt);
			return rv;
		}

		if (clog_mask_is_set(CT_LOG_DB)) {
			ct_sha1_encode(p, shat);
			CNDBG(CT_LOG_DB, "found bin %s", shat);
		}

		rv = CTDB_SHA_EXISTS;
		bcopy (p, sha_v, SHA_DIGEST_LENGTH);
	} else {
		CNDBG(CT_LOG_DB, "no bin found");
	}
	if (state->ctdb_crypt) {
		p = (uint8_t *)sqlite3_column_blob(stmt, 1);
		if (p) {
			if (sqlite3_column_bytes(stmt, 1) != CT_IV_LEN) {
				CNDBG(CT_LOG_DB, "invalid blob size");
				sqlite3_reset(stmt);
				rv = CTDB_SHA_NEXISTS;
				return rv;
			}
			if (clog_mask_is_set(CT_LOG_DB)) {
				ct_sha1_encode(p, shat);
				CNDBG(CT_LOG_DB, "found iv (prefix) %s", shat);
			}

			bcopy (p, iv, CT_IV_LEN);
		} else {
			CNDBG(CT_LOG_DB, "no iv found");
			rv = CTDB_SHA_NEXISTS;
		}

		genid = sqlite3_column_int(stmt, 2);
	} else {
		genid = sqlite3_column_int(stmt, 1);
	}
	sqlite3_reset(stmt);

	if (genid < state->ctdb_genid) {
		ct_sha1_encode(sha_k, shat);
		rv = CTDB_SHA_MAYBE_EXISTS;
		*old_genid = genid;
	} else if (genid > state->ctdb_genid) {
		/* XXX Abort? */
		CWARNX("WARNING: sha with higher genid than database!");
	}


	state->ctdb_trans_commit_rem--;
	if (state->ctdb_trans_commit_rem <= 0) {
		ctdb_end_transaction(state);
	}

	return rv;
}

int
ctdb_insert_sha(struct ctdb_state *state, uint8_t *sha_k, uint8_t *sha_v,
    uint8_t *iv, int32_t genid)
{
	char			shatk[SHA_DIGEST_STRING_LENGTH];
	char			shatv[SHA_DIGEST_STRING_LENGTH];
	int			rv, rc;
	sqlite3_stmt		*stmt;

	rv = 0;

	if (state == NULL || state->ctdb_db == NULL)
		return rv;

	stmt = state->ctdb_stmt_insert;

	if (state->ctdb_in_transaction == 0) {
		if (ctdb_begin_transaction(state) != 0)
			return (rv);
		state->ctdb_trans_commit_rem = OPS_PER_TRANSACTION;
	}

	if (clog_mask_is_set(CT_LOG_DB)) {
		ct_sha1_encode(sha_k, shatk);
		if (sha_v == NULL)
			shatv[0] = '\0';
		else
			ct_sha1_encode(sha_v, shatv);
		CNDBG(CT_LOG_DB, "inserting for bin %s, %s", shatk, shatv);
	}
	if (sqlite3_bind_blob(stmt, 1, sha_k, SHA_DIGEST_LENGTH,
	    SQLITE_STATIC)) {
		CNDBG(CT_LOG_DB, "could not bind sha_k");
		return rv;
	}
	if (state->ctdb_crypt) {
		if (sha_v == NULL || iv == NULL)
			CABORTX("crypt mode, but no sha_v/iv");
		if (sqlite3_bind_blob(stmt, 2, sha_v,
		    SHA_DIGEST_LENGTH, SQLITE_STATIC)) {
			CNDBG(CT_LOG_DB, "could not bind sha_v");
			sqlite3_reset(stmt);
			return rv;
		}

		if (sqlite3_bind_blob(stmt, 3, iv,
		    CT_IV_LEN, SQLITE_STATIC)) {
			CNDBG(CT_LOG_DB, "could not bind iv ");
			sqlite3_reset(stmt);
			return rv;
		}
		if (sqlite3_bind_int(stmt, 4, genid) != 0) {
			CNDBG(CT_LOG_DB, "could not bind genid");
			sqlite3_reset(stmt);
			return rv;
		}
	} else {
		if (sqlite3_bind_int(stmt, 2, genid) != 0) {
			CNDBG(CT_LOG_DB, "could not bind genid");
			sqlite3_reset(stmt);
			return rv;
		}

	}

	rc = sqlite3_step(stmt);
	if (rc == SQLITE_DONE) {
		CNDBG(CT_LOG_DB, "insert completed");
		rv = 1;
	} else if (rc != SQLITE_CONSTRAINT) {
		CNDBG(CT_LOG_DB, "insert failed %d %d [%s]", rc,
		    sqlite3_extended_errcode(state->ctdb_db),
		    sqlite3_errmsg(state->ctdb_db));
	} else  {
		CNDBG(CT_LOG_DB, "sha already exists");
	}

	sqlite3_reset(stmt);

	/* inserts are more 'costly' than reads */
	state->ctdb_trans_commit_rem -= 4;
	if (state->ctdb_trans_commit_rem <= 0)
		ctdb_end_transaction(state);

	return rv;
}

int
ctdb_update_sha(struct ctdb_state *state, uint8_t *sha, int32_t genid)
{
	sqlite3_stmt		*stmt;
	char			 shat[SHA_DIGEST_STRING_LENGTH];
	int			 rv = 0;

	rv = 0;

	if (state == NULL || state->ctdb_db == NULL)
		return rv;

	stmt = state->ctdb_stmt_update;
	ct_sha1_encode(sha, shat);

	if (state->ctdb_in_transaction == 0) {
		if (ctdb_begin_transaction(state) != 0)
			return (rv);
		state->ctdb_trans_commit_rem = OPS_PER_TRANSACTION;
	}

	if (clog_mask_is_set(CT_LOG_DB)) {
		ct_sha1_encode(sha, shat);
		CNDBG(CT_LOG_DB, "updating %s to genid %d ", shat, genid);
	}
	if (sqlite3_bind_int(stmt, 1, genid)) {
		CNDBG(CT_LOG_DB, "could not bind genid");
		return rv;
	}
	if (sqlite3_bind_blob(stmt, 2, sha, SHA_DIGEST_LENGTH,
	    SQLITE_STATIC)) {
		CNDBG(CT_LOG_DB, "could not bind sha");
		return rv;
	}

	if (sqlite3_step(stmt) == SQLITE_DONE) {
		CNDBG(CT_LOG_DB, "update completed");
		rv = 1;
	} else {
		CNDBG(CT_LOG_DB, "update failed %d [%s]",
		    sqlite3_extended_errcode(state->ctdb_db),
		    sqlite3_errmsg(state->ctdb_db));
	}

	sqlite3_reset(stmt);

	/* inserts are more 'costly' than reads */
	state->ctdb_trans_commit_rem -= 4;
	if (state->ctdb_trans_commit_rem <= 0)
		ctdb_end_transaction(state);

	return rv;
}

void
ctdb_cull_start(struct ctdb_state *state)
{
	char		*errmsg;
	if (state == NULL || state->ctdb_db == NULL)
		return;

	CNDBG(CT_LOG_DB, "beginning cull");
	/* Remove any shas marked -1, they are stale from a cull */
	if (sqlite3_exec(state->ctdb_db,
	    "UPDATE digests set genid = 0 WHERE genid = -1;", NULL, 0,
	    &errmsg) != 0) {
		CNDBG(CT_LOG_DB, "Can't remove stale shas: %s", errmsg);
		/* XXX delete db */
		return;
	}

	if (sqlite3_exec(state->ctdb_db,
	    "BEGIN TRANSACTION;", NULL, 0, &errmsg) != 0) {
		CNDBG(CT_LOG_DB, "Can't begin transaction: %s", errmsg);
		/* XXX delete db */
		return;
	}

	/*
	 * Start a write transaction to lock the database for the duration of
	 * the cull
	 */
	state->ctdb_in_cull = 1;
}

void
ctdb_cull_mark(struct ctdb_state *state, uint8_t *sha)
{

	if (state == NULL || state->ctdb_db == NULL) {
		CNDBG(CT_LOG_DB, "no state");
		return;
	}
	if (state->ctdb_in_cull == 0) {
		CNDBG(CT_LOG_DB, "not in cull");
		return;
	}

	CNDBG(CT_LOG_DB, "marking sha");
	if (sqlite3_bind_int(state->ctdb_stmt_update, 1, -1)) {
		CNDBG(CT_LOG_DB, "could not bind genid");
		goto out;
	}

	if (sqlite3_bind_blob(state->ctdb_stmt_update, 2, sha,
	    SHA_DIGEST_LENGTH, SQLITE_STATIC)) {
		CNDBG(CT_LOG_DB, "could not bind sha");
		goto out;
	}

	if (sqlite3_step(state->ctdb_stmt_update) != SQLITE_DONE) {
		CNDBG(CT_LOG_DB, "could not step to mark sha");
	}
out:
	sqlite3_reset(state->ctdb_stmt_update);
}

void
ctdb_cull_end(struct ctdb_state *state, int32_t genid)
{
	char		*errmsg, sql[1024];

	if (state == NULL || state->ctdb_db == NULL ||
	    state->ctdb_in_cull == 0)
		return;
	state->ctdb_in_cull = 0; /* either way we are done now */
	CNDBG(CT_LOG_DB, "ending cull new genid %d", genid);

	snprintf(sql, sizeof(sql), "DELETE FROM digests WHERE genid != -1; "
	    "UPDATE digests SET genid = %d; UPDATE genid SET value = %d;"
	    "COMMIT", genid, genid);
	if (sqlite3_exec(state->ctdb_db, sql, NULL, 0, &errmsg)) {
		CNDBG(CT_LOG_DB, "update genid failed: %s:", errmsg);
		goto failure;
	}

	return;
failure:

	if (sqlite3_exec(state->ctdb_db, "ROLLBACK", NULL, 0,
	    &errmsg))
		CNDBG(CT_LOG_DB, "Failed to rollback after cull: %s", errmsg);
	/* maybe delete db in that case. */
}
