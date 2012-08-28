/*
 * Copyright (c) 2011, 2012 Conformal Systems LLC <info@conformal.com>
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
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <inttypes.h>
#include <libgen.h>
#include <glob.h>
#include <err.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <paths.h>

#include <histedit.h>

#include <clog.h>
#include <exude.h>

#include <cyphertite.h>
#include "ct.h"
#include "ct_fb.h"

#ifndef nitems
#define nitems(_a)      (sizeof((_a)) / sizeof((_a)[0]))
#endif /* !nitems */

extern void		ct_cleanup_login_cache(void);

/* completion code */
unsigned char		 complete(EditLine *el, int cb);
unsigned char		 complete_file(EditLine *, const char *, int,
			     char , int, int, int);
void		 complete_display(char **, u_int);
int		 complete_cmd_parse(EditLine *, const char *, int,
			     char, int);
char		*complete_ambiguous(const char *, char **, size_t);

/* Cli commands */
ctfb_cmd	ctfb_cd;
ctfb_cmd	ctfb_get;
ctfb_cmd	ctfb_ls;
ctfb_cmd	ctfb_pwd;
ctfb_cmd	ctfb_lcd;
ctfb_cmd	ctfb_lpwd;
ctfb_cmd	ctfb_lmkdir;
ctfb_cmd	ctfb_lumask;
ctfb_cmd	ctfb_lls;
ctfb_cmd	ctfb_shell;
ctfb_cmd	ctfb_exit;
ctfb_cmd	ctfb_help;

extern int 			 ctfb_quit;
extern struct ct_fb_state	*ctfb_cfs;
extern struct ct_global_state	*ctfb_state;
char				*ct_fb_filename;

#define _PATH_LS "ls"
void
ctfb_lls(int argc, const char **argv)
{
	const char	**nargv;
	int		 i;

	/*
	 * marshall arguments into a new array with first arg being !PATH_LS
	 * instead of lls
	 */
	nargv = e_calloc(argc + 1, sizeof(*nargv));
	e_asprintf((char **)&nargv[0], "!%s", _PATH_LS);
	for (i = 1; i < argc; i++)
		nargv[i] = e_strdup(argv[i]);
	nargv[argc] = NULL;

	/* Shell out to ls */
	ctfb_shell(argc, nargv);

	/* cleanup */
	for (i = 0; i < argc; i++)
		e_free(&nargv[i]);
	e_free(&nargv);
}
#undef _PATH_LS

void
ctfb_shell(int argc, const char **argv)
{
	int	 status, offset = 0, noargs = 0, returnbang = 0, i, cnt;
	char	*shell, args[_POSIX_ARG_MAX];
	pid_t	 pid;

	if (argv[0][0] == '!') {
		returnbang = 1;
		argv[0]++;
	}
	if (argv[0][0] == '\0')
		offset = 1;
	if (argc - offset <= 0) {
		noargs = 1;
	} else {
		/* XXX check overflow */
		for (i = offset, cnt = 0; i < argc; i++, cnt++) {
			if (cnt == 0) {
				strlcpy(args, argv[i], sizeof(args));
			} else {
				strlcat(args, " ", sizeof(args));
				strlcat(args, argv[i], sizeof(args));
			}
		}
	}

	if (returnbang)
		argv[0]--;

	if ((shell = getenv("SHELL")) == NULL || *shell == '\0')
		shell = _PATH_BSHELL;

	if ((pid = fork()) == -1)
		CFATAL("Can't fork");

	if (pid == 0) {
		if (noargs) {
			execl(shell, shell, (char *)NULL);
		} else {
			execl(shell, shell, "-c", args, (char *)NULL);
		}
		_exit(1);
	}
	while (waitpid(pid, &status, 0) == -1)
		if (errno != EINTR)
			CFATAL("failed to wait for child");
	if (!WIFEXITED(status))
		CWARNX("Shell exited abnormally");
	else if (WEXITSTATUS(status))
		CWARNX("Shell exited with status %d", WEXITSTATUS(status));

}

/*
 * lstat a path in a ctfile.
 * XXX should have stat that follows symlinks but that is fiddly.
 */
int
ctfb_lstat(const char *path, struct stat *sb)
{
	struct ct_fb_entry		*entry;
	struct ct_fb_key		*key;
	struct ct_fb_spec		*spec;
	int				 ret = -1;

	CNDBG(CT_LOG_VERTREE, "%s %s", __func__, path);

	/* ctfb_get_version sets errno */
	if (ctfb_get_version(ctfb_cfs, path, 1, &entry, &key) != 0)
		return (-1);

	/*
	 * fields ignored for now:
	 * st_dev, st_ino, st_nlink, st_blksize, st_blocks
	 */
	sb->st_dev = 0;
	sb->st_ino = 0;
	sb->st_nlink = 1;
	sb->st_blksize = 0;
	sb->st_blocks = 0;

	sb->st_mode = key->cfb_type | key->cfb_mode; /* XXX is this correct? */
	sb->st_uid = key->cfb_uid;
	sb->st_gid = key->cfb_gid;
	sb->st_mtime = key->cfb_mtime;
	sb->st_ctime = key->cfb_mtime;
	sb->st_atime = key->cfb_atime;
	if (C_ISCHR(key->cfb_type) || C_ISBLK(key->cfb_type)) {
		spec = (struct ct_fb_spec *)key;
		sb->st_rdev = spec->cfb_rdev;
	} else {
		sb->st_rdev = 0;
	}
	ret = 0;

	return (ret);
}

/*
 * main() and assitance functions for the cyphertitefb filebrowser.
 */
struct ctfb_cmd {
	char		*name;
	ctfb_cmd	*cmd;
	/*
	 * for completion:
	 *	r: file in md
	 *	l: local fs
	 *	v: version in ctfile (includes files too)
	 * Uppercase means multiple.
	 */
	char		*args;
} cmds[] = {
	{ "cd", ctfb_cd, "r" },
	{ "exit", ctfb_exit, "" },
	{ "get", ctfb_get, "vl" },
	{ "help", ctfb_help, "" },
	{ "ls", ctfb_ls, "R" },
	{ "pwd", ctfb_pwd, "" },
	{ "lcd", ctfb_lcd, "l" },
	{ "lpwd", ctfb_lpwd, "" },
	{ "lmkdir", ctfb_lmkdir, "l" },
	{ "lumask", ctfb_lumask, "" },
	{ "lls", ctfb_lls, "L" },
	{ "quit", ctfb_exit, "" },
	{ "!", ctfb_shell, "" },
	{ "?", ctfb_help, "" },
};

struct ctfb_cmd *
ctfb_find_cmd(struct ctfb_cmd *cmdlist, size_t ncmds, const char *search)
{
	struct ctfb_cmd	*found = NULL;
	int		 i;

	for (i = 0; i < ncmds; i++) {
		if (!strncmp(cmdlist[i].name, search,
		     strlen(cmdlist[i].name))) {
			if (found)
				return (NULL); /* disallow ambiguities */
			found = &cmdlist[i];
		}
	}

	return (found);
}

char *
prompt(EditLine *unused)
{
	return ("ct_fb> ");
}

int
ctfb_main(int argc, char *argv[])
{
	struct ct_global_state	*state;
	struct ct_config	*conf;
	struct ct_fb_state	 cfs;
	struct ctfb_cmd		*cmd;
	const char		**l_argv;
	const char		*buf;
	char			*configfile = NULL, *config_file = NULL;
	char			*ctfile = NULL;
	char			*debugstring = NULL;
	EditLine		*el = NULL;
	History			*hist;
	HistEvent		 hev;
	Tokenizer		*tokenizer;
	uint64_t		 debug_mask = 0;
	uint32_t		 cflags = CLOG_F_ENABLE | CLOG_F_STDERR;
	int		 	 c, cnt, l_argc, ret;

	bzero(&cfs, sizeof(cfs));
	while ((c = getopt(argc, argv, "D:F:")) != -1) {
		switch (c) {
		case 'D':
			if (debugstring != NULL)
				CFATALX("only one -D argument is valid");
			debugstring = optarg;
			break;
		case 'F':
			configfile = optarg;
			break;
		default:
			ctfb_usage();
			/* NOTREACHED */
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc > 1) {
		CWARNX("more than one ctfile provided");
		ctfb_usage();
	} else {
		ctfile = argv[0];
	}

	if (ctfile == NULL)
		ctfb_usage();

	if (debugstring) {
		cflags |= CLOG_F_DBGENABLE | CLOG_F_FILE | CLOG_F_FUNC |
		    CLOG_F_LINE | CLOG_F_DTIME;
		exude_enable(CT_LOG_EXUDE);
#if CT_ENABLE_THREADS
		exude_enable_threads();
#endif
		debug_mask |= ct_get_debugmask(debugstring);
	}

	/* please don't delete this line AGAIN! --mp */
	if (clog_set_flags(cflags))
		errx(1, "illegal clog flags");
	clog_set_mask(debug_mask);

	/* We can allocate these now that we've decided if we need exude */
	if (configfile)
		config_file = e_strdup(configfile);

	/* load config */
	if ((ret = ct_load_config(&conf, &config_file)) != 0)
		CFATALX("%s", ct_strerror(ret));

	ct_prompt_for_login_password(conf);

	/* We may have to download files later, always set up */
	if ((ret = ct_init(&ctfb_state, conf, CT_NEED_SECRETS,
	    ct_info_sig)) != 0)
		CFATALX("failed to initialize: %s", ct_strerror(ret));
	state = ctfb_state;

	/* if we're in remote mode, try and grab the appropriate files */
	if (conf->ct_ctfile_mode == CT_MDMODE_REMOTE) {
		ctfile_find_for_operation(state, ctfile,
		    ctfile_nextop_justdl, &ct_fb_filename, 1, 0);
		ct_wakeup_file(ctfb_state->event_state);
		if ((ret = ct_run_eventloop(state)) != 0) {
			if (state->ct_errmsg[0] != '\0')
				CWARNX("%s: %s", state->ct_errmsg,
				    ct_strerror(ret));
			else	
				CWARNX("%s", ct_strerror(ret));
			return (ret);
		}
		ct_cleanup_eventloop(state);
	} else {
		ct_fb_filename = e_strdup(ctfile);
	}
	/* now have name of the file we actually want to open... */
	ct_build_tree(ct_fb_filename, &cfs.cfs_tree,
	    conf->ct_ctfile_mode == CT_MDMODE_REMOTE ?
	    conf->ct_ctfile_cachedir : NULL);
	ctfb_cfs = &cfs;
	ctfb_cfs->cfs_cwd = &ctfb_cfs->cfs_tree;
	ctfb_cfs->cfs_curpath[0] = '\0';

	if ((el = el_init(__progname, stdin, stdout, stderr)) == NULL)
		CFATALX("can't init libedit");
	hist = history_init();
	history(hist, &hev, H_SETSIZE, 100);
	el_set(el, EL_ADDFN, "ctfb-complete", "tab completion for filebrowser",
	    complete);
	el_set(el, EL_BIND, "^I", "ctfb-complete", NULL);
	el_set(el, EL_HIST, history, hist);
	el_set(el, EL_PROMPT, prompt);
	el_set(el, EL_SIGNAL, 1);
	tokenizer = tok_init(NULL);

	while (ctfb_quit == 0) {
		if ((buf = el_gets(el, &cnt)) == NULL || cnt == 0)
			break;
		/* XXX deal with positive returns lines (continuations) */
		history(hist, &hev, H_ENTER, buf);
		if (tok_line(tokenizer, el_line(el), &l_argc, &l_argv,
		    NULL, NULL) != 0 || l_argc == 0) {
			tok_reset(tokenizer);
			continue;
		}

		if ((cmd = ctfb_find_cmd(cmds, nitems(cmds), l_argv[0]))) {
			cmd->cmd(l_argc, l_argv);
		} else {
			CWARNX("command not recognized");
		}

		tok_reset(tokenizer);
	}

	e_free(&ct_fb_filename);
	tok_end(tokenizer);
	history_end(hist);
	el_end(el);
	ct_cleanup_login_cache();
	ctfb_cfs = NULL; /* XXX cleanup tree */

	ct_unload_config(config_file, conf);

	exude_cleanup();

	return (0);
}

/*
 * Code for tab completion.
 * All either original or adapted from sftp under the following license:
 *
 * Copyright (c) 2001-2004 Damien Miller <djm@openbsd.org>
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
 *
 * Additionally some ideas (but not code) from ftp(1) on OpenBSD.
 */
unsigned char
complete(EditLine *el, int cb)
{
	struct ctfb_cmd	*cmd;
	Tokenizer	*tok;
	const LineInfo	*li;
	const char	**argv;
	char		 *line = NULL;
	size_t		 argslen;
	u_int		 len;
	int		 argc, cursorc, cursoro, ret = CC_ERROR;


	tok = tok_init(NULL);

	li = el_line(el);

	len = li->cursor - li->buffer;
	line = e_malloc(len + 1);
	bcopy(li->buffer,  line, len);
	line[len] = '\0';

	/*
	 * XXX the problem with using tok_ here is that we don't get a proper
	 * return if we have a " or a ' unterminated in the line. This should
	 * be fixed so that tab completion can work correctly in these cases.
	 * Note: we can't do bad things and look at tok internal state because
	 * the struct definition is hidden from us.
	 */
	if (tok_line(tok, li, &argc, &argv, &cursorc, &cursoro) != 0)
		goto out;

	/* check cursor is at EOL or an argument boundary */
	if (argc != 0 && !(argv[cursorc] == NULL ||
	    argv[cursorc][cursoro] == '\0' || argv[cursorc][cursoro] == ' '))
		goto out;

	/* If we have no command yet, show all commands */
	if (argc == 0) {
		complete_cmd_parse(el, NULL, li->cursor == li->lastchar,
		    '\0', 1);
		ret = CC_REDISPLAY;
		goto out;
	} else if (cursorc == 0) {
		if (complete_cmd_parse(el, argv[0], li->cursor == li->lastchar,
		    '\0' /* XXX */, 1) != 0)
			ret = CC_REDISPLAY;
		goto out;
	}

	/* else look up command and what it expects. */
	if ((cmd = ctfb_find_cmd(cmds, nitems(cmds), argv[0])) == NULL)
		goto out;

	argslen = strlen(cmd->args);
	if (cursorc > argslen && argslen > 0 &&
	    isupper(cmd->args[argslen - 1]))
		cursorc = argslen;

	if (cursorc > argslen)
		goto out;

	switch(tolower(cmd->args[cursorc - 1])) {
	case 'l':
		ret = complete_file(el, argv[cursorc],
		    li->cursor == li->lastchar, '\0' /* XXX */, 1 /* XXX */,
		    0, 0);
		break;
	case 'r':
		ret = complete_file(el, argv[cursorc],
		    li->cursor == li->lastchar, '\0' /* XXX */, 1 /* XXX */,
		    1, 0);
		break;
	case 'v':
		ret = complete_file(el, argv[cursorc],
		    li->cursor == li->lastchar, '\0' /* XXX */, 1 /* XXX */,
		    1, 1);
		break;
	}
out:
	if (line)
		e_free(&line);
	tok_end(tok);
	return (ret);
}

unsigned char
complete_file(EditLine *el, const char *file, int lastarg, char quote,
    int terminated, int ctfile, int versions)
{
	glob_t g;
	char *tmp, *tmp2, ins[3];
	u_int i, hadglob, pwdlen, len, tmplen, filelen;
	const LineInfo *lf;

	/* Glob from "file" location */
	if (file == NULL)
		tmp = e_strdup("*");
	else
		e_asprintf(&tmp, "%s*", file);

	memset(&g, 0, sizeof(g));
	if (ctfile) {
		glob_ctfile(tmp, GLOB_DOOFFS|GLOB_MARK, NULL, &g, versions);
	} else {
		glob(tmp, GLOB_DOOFFS|GLOB_MARK, NULL, &g);
	}

	/* Determine length of pwd so we can trim completion display */
	for (hadglob = tmplen = pwdlen = 0; tmp[tmplen] != 0; tmplen++) {
		/* Terminate counting on first unescaped glob metacharacter */
		if (tmp[tmplen] == '*' || tmp[tmplen] == '?') {
			if (tmp[tmplen] != '*' || tmp[tmplen + 1] != '\0')
				hadglob = 1;
			break;
		}
		if (tmp[tmplen] == '\\' && tmp[tmplen + 1] != '\0')
			tmplen++;
		if (tmp[tmplen] == '/')
			pwdlen = tmplen + 1;	/* track last seen '/' */
	}
	e_free(&tmp);

	if (g.gl_matchc == 0)
		goto out;

	if (g.gl_matchc > 1)
		complete_display(g.gl_pathv, pwdlen);

	tmp = NULL;
	/* Don't try to extend globs */
	if (hadglob)
		goto out;

	if (file == NULL)
		file = "";
	tmp = complete_ambiguous(file, g.gl_pathv, g.gl_matchc);

	if (tmp == NULL)
		goto out;

	tmplen = strlen(tmp);
	filelen = strlen(file);

	if (tmplen > filelen)  {
		tmp2 = tmp + filelen;
		len = strlen(tmp2);
		/* quote argument on way out */
		for (i = 0; i < len; i++) {
			ins[0] = '\\';
			ins[1] = tmp2[i];
			ins[2] = '\0';
			switch (tmp2[i]) {
			case '\'':
			case '"':
			case '\\':
			case '\t':
			case '[':
			case ' ':
				if (quote == '\0' || tmp2[i] == quote) {
					if (el_insertstr(el, ins) == -1)
						CFATALX("el_insertstr "
						    "failed.");
					break;
				}
				/* FALLTHROUGH */
			default:
				if (el_insertstr(el, ins + 1) == -1)
					CFATALX("el_insertstr failed.");
				break;
			}
		}
	}

	lf = el_line(el);
	if (g.gl_matchc == 1) {
		i = 0;
		if (!terminated)
			ins[i++] = quote;
		if (*(lf->cursor - 1) != '/' &&
		    (lastarg || *(lf->cursor) != ' '))
			ins[i++] = ' ';
		ins[i] = '\0';
		if (i > 0 && el_insertstr(el, ins) == -1)
			CFATALX("el_insertstr failed.");
	}
	e_free(&tmp);

 out:
	globfree(&g);
	return g.gl_matchc > 0 ? CC_REDISPLAY : CC_ERROR;
}

/* Display entries in 'list' after skipping the first 'len' chars */
void
complete_display(char **list, u_int len)
{
	u_int y, m = 0, width = 80, columns = 1, colspace = 0, llen;
	struct winsize ws;
	char *tmp;

	/* Count entries for sort and find longest */
	for (y = 0; list[y]; y++)
		m = MAX(m, strlen(list[y]));

	if (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		width = ws.ws_col;

	m = m > len ? m - len : 0;
	columns = width / (m + 2);
	columns = MAX(columns, 1);
	colspace = width / columns;
	colspace = MIN(colspace, width);

	printf("\n");
	m = 1;
	for (y = 0; list[y]; y++) {
		llen = strlen(list[y]);
		tmp = llen > len ? list[y] + len : "";
		printf("%-*s", colspace, tmp);
		if (m >= columns) {
			printf("\n");
			m = 1;
		} else
			m++;
	}
	printf("\n");
}

/*
 * Given a "list" of words that begin with a common prefix of "word",
 * attempt to find an autocompletion to extends "word" by the next
 * characters common to all entries in "list".
 */
char *
complete_ambiguous(const char *word, char **list, size_t count)
{
	if (word == NULL)
		return NULL;

	if (count > 0) {
		u_int y, matchlen = strlen(list[0]);

		/* Find length of common stem */
		for (y = 1; list[y]; y++) {
			u_int x;

			for (x = 0; x < matchlen; x++)
				if (list[0][x] != list[y][x])
					break;

			matchlen = x;
		}

		if (matchlen > strlen(word)) {
			char *tmp = e_strdup(list[0]);

			tmp[matchlen] = '\0';
			return tmp;
		}
	}

	return e_strdup(word);
}

/* Autocomplete a sftp command */
int
complete_cmd_parse(EditLine *el, const char *cmd, int lastarg, char quote,
    int terminated)
{
	u_int y, count = 0, cmdlen, tmplen;
	char *tmp, **list, argterm[3];
	const LineInfo *lf;

	list = e_calloc(nitems(cmds) + 1, sizeof(char *));

	/* No command specified: display all available commands */
	if (cmd == NULL) {
		for (y = 0; y < nitems(cmds); y++)
			list[count++] = e_strdup(cmds[y].name);

		list[count] = NULL;
		complete_display(list, 0);

		for (y = 0; list[y] != NULL; y++)
			e_free(&list[y]);
		e_free(&list);
		return count;
	}

	/* Prepare subset of commands that start with "cmd" */
	cmdlen = strlen(cmd);
	for (y = 0; y < nitems(cmds); y++)  {
		if (!strncasecmp(cmd, cmds[y].name, cmdlen))
			list[count++] = e_strdup(cmds[y].name);
	}
	list[count] = NULL;

	if (count == 0) {
		e_free(&list);
		return 0;
	}

	/* Complete ambigious command */
	tmp = complete_ambiguous(cmd, list, count);
	if (count > 1)
		complete_display(list, 0);

	for (y = 0; list[y]; y++)
		e_free(&list[y]);
	e_free(&list);

	if (tmp != NULL) {
		tmplen = strlen(tmp);
		cmdlen = strlen(cmd);
		/* If cmd may be extended then do so */
		if (tmplen > cmdlen)
			if (el_insertstr(el, tmp + cmdlen) == -1)
				CFATALX("el_insertstr failed.");
		lf = el_line(el);
		/* Terminate argument cleanly */
		if (count == 1) {
			y = 0;
			if (!terminated)
				argterm[y++] = quote;
			if (lastarg || *(lf->cursor) != ' ')
				argterm[y++] = ' ';
			argterm[y] = '\0';
			if (y > 0 && el_insertstr(el, argterm) == -1)
				CFATALX("el_insertstr failed.");
		}
		e_free(&tmp);
	}

	return count;
}
