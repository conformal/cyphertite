/*
 * Copyright (c) 2011 Conformal Systems LLC <info@conformal.com>
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

#ifdef NEED_LIBCLENS
#include <clens.h>
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <pwd.h>
#include <readpassphrase.h>

#ifndef NO_UTIL_H
#include <util.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>

#include <clog.h>

#include "ctutil.h"



extern char		*__progname;

int			ct_settings_add(struct ct_settings *, char *, char *);
uint8_t			ct_getbyteval(char);
void			ct_expand_tilde(char **, char *, char *);

int
ct_get_password(char *password, size_t passwordlen, char *prompt, int verify)
{
	int			rv = 1;
	char			pw[_PASSWORD_LEN + 1];

	if (readpassphrase(prompt ? prompt : "New password: ", password,
	    passwordlen, RPP_REQUIRE_TTY) == NULL) {
		CWARNX("invalid password");
		goto done;
	}
	if (verify) {
		if (readpassphrase("Retype password: ", pw, sizeof pw,
		    RPP_REQUIRE_TTY) == NULL) {
			CWARNX("invalid password");
			goto done;
		}
		if (strcmp(password, pw)) {
			CWARNX("passwords do not match");
			goto done;
		}
	}
	if (strlen(password) == 0) {
		CWARNX("password must not be empty");
		goto done;
	}

	rv = 0;
done:
	bzero(pw, sizeof pw);
	return (rv);
}

uint8_t
ct_getbyteval(char c)
{
	if (c == '\0')
		return (0xff);
	else if (c >= '0' && c <= '9')
		return (c - '0');
	else if (toupper(c) >= 'A' && toupper(c) <= 'F')
		return (toupper(c) - 'A' + 10);
	else
		return (0xff);
}

int
ct_text2sha(char *shat, uint8_t *sha)
{
	int			i, x;
	uint8_t			v1, v2;

	for (i = 0, x = 0; i < SHA_DIGEST_LENGTH * 2; i += 2, x++) {
		v1 = ct_getbyteval(shat[i]);
		if (v1 == 0xff)
			return (1);
		v2 = ct_getbyteval(shat[i + 1]);
		if (v2 == 0xff)
			return (1);
		sha[x] = (v1 << 4) | v2;
	}
	if (shat[i] != '\0')
		return (1);

	return (0);
}


/* opcode to error string tables; see ctutil.h/ct_header_strerror(); */
char *c_hdr_login_reply_ex_errstrs[] = {
	"Invalid login credentials. Please check your username,"
	    "password and certificates.",
	"Account Disabled - Please log in to your cyphertite.com account or "
	    "contact support@cyphertite.com",
};

char *c_hdr_write_reply_ex_errstrs[] = {
	"Account has run out of space - Please log in to your cyphertite.com "
	    "account or contact support@cyphertite.com",
};

char *
ct_header_strerror(struct ct_header *h)
{
	char	*errstr;

	if (h == NULL)
		CFATALX("invalid pointer");

	errstr = "unknown error";

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif
	/* at some future point, having 2d map table might be better. */
	switch (h->c_opcode) {
	case C_HDR_O_LOGIN_REPLY:
		if (h->c_ex_status > nitems(*c_hdr_login_reply_ex_errstrs))
			break;
		errstr = c_hdr_login_reply_ex_errstrs[h->c_ex_status];
		break;
	case C_HDR_O_WRITE_REPLY:
		if (h->c_ex_status > nitems(*c_hdr_write_reply_ex_errstrs))
			break;
		errstr = c_hdr_write_reply_ex_errstrs[h->c_ex_status];
		break;
	default:
		break;
	}
#undef nitems

	return (errstr);
}



void
ct_wire_header(struct ct_header *h)
{
	if (h == NULL)
		CFATALX("invalid pointer");

	h->c_tag = htonl(h->c_tag);
	h->c_flags = htons(h->c_flags);
	h->c_size = htonl(h->c_size);
}

void
ct_unwire_header(struct ct_header *h)
{
	if (h == NULL)
		CFATALX("invalid pointer");

	h->c_tag = ntohl(h->c_tag);
	h->c_flags = ntohs(h->c_flags);
	h->c_size = ntohl(h->c_size);
}

void
ct_unwire_nop(struct ct_nop *n)
{
	if (n == NULL)
		CFATALX("invalid pointer");

	n->cn_id = ntohl(n->cn_id);
}

void
ct_wire_nop_reply(struct ct_nop_reply *n)
{
	if (n == NULL)
		CFATALX("invalid pointer");

	n->cnr_id = htonl(n->cnr_id);
}

int
ct_settings_add(struct ct_settings *settings, char *var, char *val)
{
	int			rv = 1, *p;
	double			*f;
	char			**s;
	struct ct_settings	*cs;

	if (settings == NULL)
		CFATALX("invalid parameters");

	for (cs = settings; cs->cs_name != NULL; cs++) {
		if (strcmp(var, cs->cs_name))
			continue;

		if (cs->cs_s) {
			if (cs->cs_s->csp_set(cs, val))
				CFATALX("invalid value for %s: %s", var, val);
			rv = 0;
			break;
		} else
			switch (cs->cs_type) {
			case CT_S_INT:
				p = cs->cs_ival;
				*p = atoi(val);
				rv = 0;
				break;
			case CT_S_DIR:
			case CT_S_STR:
				s = cs->cs_sval;
				if (s == NULL)
					CFATALX("invalid sval for %s",
					    cs->cs_name);
				if (*s)
					free(*s);
				if (cs->cs_type == CT_S_DIR)
					ct_expand_tilde(s, cs->cs_name, val);
				else
					*s = strdup(val);

				if (s == NULL)
					CFATAL("no memory for %s", cs->cs_name);
				rv = 0;
				break;
			case CT_S_FLOAT:
				f = cs->cs_fval;
				*f = atof(val);
				rv = 0;
				break;
			case CT_S_SIZE:
				if (scan_scaled(val, cs->cs_szval) != 0)
					CFATAL("can't parse size for %s",
					    cs->cs_name);
				rv = 0;
				break;
			case CT_S_INVALID:
			default:
				CFATALX("invalid type for %s", var);
			}
		break;
	}

	return (rv);
}

#define	WS	"\n= \t"
int
ct_config_parse(struct ct_settings *settings, const char *filename)
{
	FILE			*config;
	char			*line, *cp, *var, *val;
	int			i;
	size_t			len, lineno = 0;

	CNDBG(CTUTIL_LOG_CONFIG, "filename %s\n", filename);

	if (filename == NULL)
		CFATALX("invalid config file name");

	if ((config = fopen(filename, "r")) == NULL)
		return 1;

	for (;;) {
		if ((line = fparseln(config, &len, &lineno, NULL, 0)) == NULL)
			if (feof(config) || ferror(config))
				break;

		cp = line;
		cp += (long)strspn(cp, WS);
		if (cp[0] == '\0') {
			/* empty line */
			free(line);
			continue;
		}

		if ((var = strsep(&cp, WS)) == NULL || cp == NULL)
			CFATALX("invalid config file entry: %s", line);

		cp += (long)strspn(cp, WS);

		if ((val = strsep(&cp, "\0")) == NULL)
			break;

		/* strip trailing spaces */
		i = strlen(val) - 1;
		while (i >= 0 && isspace(val[i]))
			i--;
		val[++i] = '\0';

		CNDBG(CTUTIL_LOG_CONFIG, "config_parse: %s=%s\n",var ,val);
		if (ct_settings_add(settings, var, val))
			CFATALX("invalid conf file entry: %s=%s", var, val);

		free(line);
	}
	CNDBG(CTUTIL_LOG_CONFIG, "loaded config from %s", filename);

	fclose(config);

	return 0;
}

void
ct_dump_block(uint8_t *p, size_t sz)
{
	char			*fp, *buf;
	int			bsz, i, j;

	bsz = 16 * 4 + 3 + 2;
	fp = buf = malloc(bsz);
	char *sep = "";
	CDBG("dumping %p %lu", p, (long unsigned) sz);
	for (i = 0; i < sz; i += 16) {
		sep = "";
		for (j = 0; j < 16; j++) {
			if (i + j < sz) {
				fp += snprintf(fp, bsz - (fp-buf), "%s%02x",
				    sep, p[i+j]);
			} else {
				fp += snprintf(fp, bsz - (fp-buf), "%s  ", sep);
			}
			sep = " ";
		}
		*fp++ = ' ';
		*fp++ = ' ';
		for (j = 0; j < 16; j++) {
			if (i + j < sz)
				fp += snprintf(fp, bsz - (fp-buf), "%c",
				    isgraph(p[i+j]) ? p[i+j] : ' ');
		}
		CDBG("%s", buf);
		fp = buf;
	}
	free(buf);
}

void
ct_polltype_setup(const char *type)
{
	if (type == NULL)
		return;

	setenv("EVENT_NOKQUEUE", "1", 1);
	setenv("EVENT_NOPOLL", "1", 1);
	setenv("EVENT_NOSELECT", "1", 1);

	if (strcmp(type, "kqueue") == 0)
		unsetenv("EVENT_NOKQUEUE");
	else if (strcmp(type, "poll") == 0)
		unsetenv("EVENT_NOPOLL");
	else if (strcmp(type, "select") == 0)
		unsetenv("EVENT_NOSELECT");
	else
		CFATALX("unknown poll type %s", type);

	CNDBG(CTUTIL_LOG_CONFIG, "polltype: %s\n", type);
}

/* cli parsing */
struct ct_cli_cmd *
ct_cli_cmd_find(struct ct_cli_cmd *cl, char *cmd)
{
	struct ct_cli_cmd	*found = NULL, *c;

	if (cl == NULL || cmd == NULL)
		return (NULL);

	for (c = cl; c->cc_cmd != NULL; c++) {
		CNDBG(CTUTIL_LOG_CONFIG, "searching for [%p] in [%p]",
		    c->cc_cmd, cmd);
		CNDBG(CTUTIL_LOG_CONFIG, "searching for [%s] in [%s]",
		    c->cc_cmd, cmd);
		if (!strncmp(c->cc_cmd, cmd, strlen(cmd))) {
			if (found)
				return (NULL); /* ambiguous */
			found = c;
		}
	}

	return (found);
}

__dead void
ct_cli_usage(struct ct_cli_cmd *cmd_list, struct ct_cli_cmd *c)
{
	struct ct_cli_cmd	*cc, *found;

	if (c == NULL) {
		fprintf(stderr, "%s ", __progname);
		for (cc = cmd_list; cc->cc_cmd != NULL; cc++)
			fprintf(stderr, "<%s> ", cc->cc_cmd);
		fprintf(stderr, "\n");
		exit(1);
	}

	for (cc = cmd_list; cc->cc_cmd != NULL; cc++) {
		found = ct_cli_cmd_find(cc->cc_subcmd, c->cc_cmd);
		if (found == c)
			break;
	}

	CFATALX("usage: %s %s%s%s %s", __progname,
	    cc->cc_cmd ? cc->cc_cmd : "",
	    cc->cc_cmd ? " " : "",
	    c->cc_cmd, c->cc_usage);
}

struct ct_cli_cmd *
ct_cli_validate(struct ct_cli_cmd *cmd_list, int *argc, char **argv[])
{
	struct ct_cli_cmd	*c, *cl;
	char			*cmd;

	cmd = **argv;
	cl = cmd_list;
	for (;;) {
		c = ct_cli_cmd_find(cl, cmd);
		if (c == NULL)
			goto bad;

		if (c->cc_paramc == CLI_CMD_UNKNOWN) {
			/* call function with all argv */
			if (*argc - 1 < 0)
				goto bad;
			break;
		} else if (c->cc_paramc == CLI_CMD_SUBCOMMAND) {
			/* dereference sub-command */
			if (*argc - 1 < 0)
				goto bad;
			cmd = *(*argv + 1);
			cl = c->cc_subcmd;
			(*argc)--;
			(*argv)++;
			continue;
		} else if (c->cc_paramc != *argc - 1) {
			/* invalid paramter count */
			goto bad;
		} else if (c->cc_paramc == *argc - 1) {
			/* correct parameter count */
			break;
		}
		goto bad;
	}

	return (c);
bad:
	if (c)
		ct_cli_usage(cmd_list, c);

	return (NULL);
}

void
ct_cli_execute(struct ct_cli_cmd *c, int *argc, char **argv[])
{
	(*argc)--;
	(*argv)++;

	c->cc_cb(c, *argc, *argv);
}
