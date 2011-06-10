/* $cyphertite$ */
/*
 * Copyright (c) 2011, 2010 Conformal Systems LLC <info@conformal.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <clog.h>
#include <sqlite3.h>
#include "ct.h"

#include "ct_db.h"

int		ctdb_verbose = 1;
int		ctdb_crypt = 0;

int		ctdb_in_transaction;
int		ctdb_trans_commit_rem;
#define OPS_PER_TRANSACTION	(100)

sqlite3_stmt		*ctdb_stmt_lookup;
sqlite3_stmt		*ctdb_stmt_insert;

sqlite3			*ctdb_db;

void
ctdb_setup(const char *path, int crypt_enabled)
{
	if (path == NULL) {
		if (ctdb_db != NULL) {
			ctdb_cleanup(ctdb_db);
			ctdb_db = NULL;
		}
	}

	ctdb_db = ctdb_open(path, crypt_enabled);
}

void
ctdb_shutdown(void)
{
	if (ctdb_db != NULL)
		ctdb_cleanup(ctdb_db);
	ctdb_db = NULL;
}

int
ctdb_exists(struct ct_trans *trans)
{
	int			rv;
	if (ctdb_db == NULL)
		return 0;

	rv =  ctdb_lookup_sha(ctdb_db, trans->tr_sha, trans->tr_csha,
	    trans->tr_iv);
	return rv;
}

int
ctdb_insert(struct ct_trans *trans)
{
	if (ctdb_db == NULL)
		return 0;

	if (ct_encrypt_enabled)
		return ctdb_insert_sha(ctdb_db, trans->tr_sha, trans->tr_csha,
		    trans->tr_iv);
	else
		return ctdb_insert_sha(ctdb_db, trans->tr_sha, NULL, NULL);
}

int
ctdb_create(const char *filename, sqlite3 **db, int crypto)
{
	int			rc;
	char			*errmsg = NULL;
	char			sql[4096];

	if (db == NULL)
		CFATALX("no db");

	rc = sqlite3_open_v2(filename, db,
	    SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
	if (rc)
		return (rc);

	if (crypto)
		snprintf(sql, sizeof sql,
		    "CREATE TABLE digests (sha BLOB(%d)"
		    " PRIMARY KEY UNIQUE,"
		    " csha BLOB(%d), iv BLOB(%d));",
		    SHA_DIGEST_LENGTH, SHA_DIGEST_LENGTH,
		    CT_IV_LEN);
	else 
		snprintf(sql, sizeof sql,
		    "CREATE TABLE digests (sha BLOB(%d)"
		    " PRIMARY KEY UNIQUE);",
		    SHA_DIGEST_LENGTH);

	if (ctdb_verbose)
		CDBG("sql: %s", sql);
	rc = sqlite3_exec(*db, sql, NULL, 0, &errmsg);
	if (rc) {
		CWARNX("create failed: %s", errmsg);
		*db = NULL;
		return (rc);
	}
	snprintf(sql, sizeof sql,
	    "CREATE TABLE mode (crypto TEXT);");
	rc = sqlite3_exec(*db, sql, NULL, 0, &errmsg);
	if (rc) {
		CWARNX("mode table creation failed");
		sqlite3_close(*db);
		*db = NULL;
		return (rc);
	}
	snprintf(sql, sizeof sql,
	    "insert into mode (crypto) VALUES ('%c');",
		crypto ? 'Y': 'N');
	rc = sqlite3_exec(*db, sql, NULL, 0, &errmsg);
	if (rc) {
		CWARNX("mode table init failed");
		sqlite3_close(*db);
		*db = NULL;
		return (rc);
	}

	return (SQLITE_OK);
}

int
ctdb_query_db_mode(sqlite3 *db, int crypto)
{
	sqlite3_stmt		*stmt;
	char			*p, wanted;
	int			rc, rv = 0;

	CDBG("ctdb mode %d\n", crypto);
	if (sqlite3_prepare_v2(db, "select crypto from mode",
	    -1, &stmt, NULL))
		CFATALX("can't prepare mode query statement");
	rc = sqlite3_step(stmt);
	if (rc == SQLITE_DONE) {
		CDBG("ctdb mode not found");
		goto fail;
	} else if (rc != SQLITE_ROW)
		CFATALX("could not step %d %d %s",
		    rc,
		    sqlite3_extended_errcode(db),
		    sqlite3_errmsg(db));

	p = (char *)sqlite3_column_text(stmt, 0);
	if (p) {
		wanted =  crypto ? 'Y' : 'N';
		if (sqlite3_column_bytes(stmt, 0) != 1) {
			CDBG("ctdb invalid length of column 1");
			goto fail;
		}
		CDBG("ctdb crypto mode %c %c", p[0], wanted);
		if (p[0] != wanted) {
			CDBG("ctdb crypto mode differs %c %c", p[0], wanted);
			goto fail;
		}
	}

	rv = 1;
fail:
	if (sqlite3_finalize(stmt))
		CFATALX("can't finalize verification lookup");
	return rv;
}

sqlite3 *
ctdb_open(const char *dbfile, int crypto)
{
	sqlite3			*db;
	int			rc;
	int			retry = 1;
	char			*psql;

	/* if no database file is specified, do not open the database */
	if (dbfile == NULL)
		return NULL;
do_retry:
	rc = sqlite3_open_v2(dbfile, &db, SQLITE_OPEN_READWRITE, NULL);
	if (rc == SQLITE_CANTOPEN) {
		CWARNX("db file doesn't exist, creating it");
		rc = ctdb_create(dbfile, &db, crypto);
		if (rc != SQLITE_OK)
			return NULL;
	}
	if (ctdb_query_db_mode(db, crypto) == 0) {
		if (retry) {
			retry = 0;
			/* db is in incorrect mode, delete it and try again */
			CWARNX("db file wrong mode, removing it");
			unlink(dbfile);
			goto do_retry;
		} else {
			/* db recreated in incorrect mode!?! */
			ctdb_cleanup(db);
			db = NULL;
		}

	}

	ctdb_crypt = crypto;

	/* prepare query here based on crypt mode */
	if (crypto) {
		psql = "select csha, iv from digests where sha=?";
	} else {
		psql = "select sha from digests where sha=?";
	}

	if (sqlite3_prepare(db, psql,
	    -1, &ctdb_stmt_lookup, NULL))
		CFATALX("can't prepare select statement");
	CDBG("ctdb_stmt_lookup %p", ctdb_stmt_lookup);

	return db;
}

void
ctdb_cleanup(sqlite3 *db)
{
	char			*errmsg;

	CDBG("cleaning up ctdb");
	if (ctdb_in_transaction) {
		ctdb_in_transaction = 0;
		if (sqlite3_exec(db, "commit", NULL, 0, &errmsg))
			CFATALX("can't commit %s", errmsg);
	}
	if (ctdb_stmt_lookup != NULL) {
		if (sqlite3_finalize(ctdb_stmt_lookup))
			CFATALX("can't finalize lookup");
		ctdb_stmt_lookup = NULL;
	}
	if (ctdb_stmt_insert != NULL) {
		if (sqlite3_finalize(ctdb_stmt_insert))
			CFATALX("can't finalize insert");
		ctdb_stmt_insert = NULL;
	}

	sqlite3_close(db);
}

int
ctdb_lookup_sha(sqlite3 *db, uint8_t *sha_k, uint8_t *sha_v, uint8_t *iv)
{
	char			shat[SHA_DIGEST_STRING_LENGTH];
	int			rv, rc;
	uint8_t			*p;
	char			*errmsg;
	sqlite3_stmt		*stmt;

	rv = 0;

	if (db == NULL)
		return rv;

	if (ctdb_stmt_lookup == NULL) {
		CFATAL("ctdb incorrectly intialized\n");
	} else
		stmt = ctdb_stmt_lookup;

	if (ctdb_in_transaction == 0) {
		rc = sqlite3_exec(db, "begin transaction", NULL, 0, &errmsg);
		if (rc)
			CFATALX("can't begin %s", errmsg);
		ctdb_in_transaction = 1;
		ctdb_trans_commit_rem = OPS_PER_TRANSACTION;
	}

	if (ctdb_verbose) {
		ct_sha1_encode(sha_k, shat);
		CDBG("looking for bin %s", shat);
	}
	if (sqlite3_bind_blob(stmt, 1, sha_k, SHA_DIGEST_LENGTH,
	    SQLITE_STATIC))
		CFATALX("could not bind");

	rc = sqlite3_step(stmt);
	if (rc == SQLITE_DONE) {
		if (ctdb_verbose)
			CDBG("not found");
		sqlite3_reset(stmt);
		return rv;
	} else if (rc != SQLITE_ROW)
		CFATALX("could not step %d %d %s",
		    rc,
		    sqlite3_extended_errcode(db),
		    sqlite3_errmsg(db));

	if (ctdb_verbose)
		CDBG("found");

	p = (uint8_t *)sqlite3_column_blob(stmt, 0);
	if (p) {
		if (sqlite3_column_bytes(stmt, 0) !=
		    SHA_DIGEST_LENGTH)
			CFATALX("invalid blob size");
		if (ctdb_verbose) {
			ct_sha1_encode(p, shat);
			CDBG("found bin %s", shat);
		}

		rv = 1;
		bcopy (p, sha_v, SHA_DIGEST_LENGTH);
	} else if (ctdb_verbose) {
		CDBG("no bin found");
	}
	if (ctdb_crypt) {
		p = (uint8_t *)sqlite3_column_blob(stmt, 1);
		if (p) {
			if (sqlite3_column_bytes(stmt, 1) !=
			    E_IV_LEN)
				CFATALX("invalid blob size");
			if (ctdb_verbose) {
				ct_sha1_encode(p, shat);
				CDBG("found iv (prefix) %s", shat);
			}

			bcopy (p, iv, E_IV_LEN);
		} else if (ctdb_verbose) {
			CDBG("no iv found");
			rv = 0;
		}
	}
	sqlite3_reset(stmt);

	ctdb_trans_commit_rem--;
	if (ctdb_trans_commit_rem <= 0) {
		rc = sqlite3_exec(db, "commit", NULL, 0, &errmsg);
		if (rc)
			CFATALX("can't commit %s", errmsg);
		ctdb_in_transaction = 0;
	}

	return rv;
}

int
ctdb_insert_sha(sqlite3 *db, uint8_t *sha_k, uint8_t *sha_v, uint8_t *iv)
{
	char			shatk[SHA_DIGEST_STRING_LENGTH];
	char			shatv[SHA_DIGEST_STRING_LENGTH];
	int			rv, rc;
	char			*errmsg;
	sqlite3_stmt		*stmt;

	rv = 0;

	if (db == NULL)
		return rv;

	if (ctdb_stmt_insert == NULL) {
		if (ctdb_crypt) {
			if (sqlite3_prepare_v2(db,
			    "insert into digests(sha, csha, iv)"
			    " values(?, ?, ?)",
			    -1, &stmt, NULL))
				CFATALX("can't prepare insert statement");
		} else {
			if (sqlite3_prepare_v2(db,
			    "insert into digests(sha) values(?)",
			    -1, &stmt, NULL))
				CFATALX("can't prepare insert statement");
		}
		ctdb_stmt_insert = stmt;
	} else
		stmt = ctdb_stmt_insert;

	if (ctdb_in_transaction == 0) {
		CDBG("NEW transaction");
		rc = sqlite3_exec(db, "begin transaction", NULL, 0, &errmsg);
		if (rc)
			CFATALX("can't begin %s", errmsg);
		ctdb_in_transaction = 1;
		ctdb_trans_commit_rem = OPS_PER_TRANSACTION;
	}

	if (ctdb_verbose) {
		ct_sha1_encode(sha_k, shatk);
		if (sha_v == NULL)
			shatv[0] = '\0';
		else
			ct_sha1_encode(sha_v, shatv);
		CDBG("inserting for bin %s, %s", shatk, shatv);
	}
	if (sqlite3_bind_blob(stmt, 1, sha_k, SHA_DIGEST_LENGTH,
	    SQLITE_STATIC))
		CFATALX("could not bind sha_k");
	if (ctdb_crypt) {
		if (sha_v == NULL || iv == NULL) {
			CFATALX("crypt mode, but no sha_v/iv");
		}
		if (sqlite3_bind_blob(stmt, 2, sha_v,
		    SHA_DIGEST_LENGTH, SQLITE_STATIC))
			CFATALX("could not bind sha_v");
		if (sqlite3_bind_blob(stmt, 3, iv,
		    E_IV_LEN, SQLITE_STATIC))
			CFATALX("could not bind iv ");
	}

	rc = sqlite3_step(stmt);
	if (rc == SQLITE_DONE) {
		if (ctdb_verbose)
			CDBG("insert completed");
		sqlite3_reset(stmt);
		rv = 1;
		return rv;
	} else if (rc != SQLITE_CONSTRAINT)
		CWARNX("insert failed %d %d [%s]", rc,
		    sqlite3_extended_errcode(db),
		    sqlite3_errmsg(db));
	else if (ctdb_verbose)
		CDBG("sha already exists");

	sqlite3_reset(stmt);

	ctdb_trans_commit_rem -= 4; /* inserts are 'costly' than reads */
	if (ctdb_trans_commit_rem <= 0) {
		rc = sqlite3_exec(db, "commit", NULL, 0, &errmsg);
		if (rc)
			CFATALX("can't commit %s", errmsg);
		ctdb_in_transaction = 0;
	}

	return rv;
}
