/*
 * XXX ownership, times and mode can change in each differential,
 * perhaps needa a split
 */
struct ct_fb_mdfile {
	char		cff_path[PATH_MAX];	/* MD file name */
};

TAILQ_HEAD(ct_fb_vers, ct_fb_key);
RB_HEAD(ct_fb_entries, ct_fb_entry);

struct ct_fb_entry {
	TAILQ_ENTRY(ct_fb_entry)	 cfb_link;
	RB_ENTRY(ct_fb_entry)		 cfb_entry;
	struct ct_fb_vers		 cfb_versions;
	struct ct_fb_entries		 cfb_children;
	char				*cfb_name;	/* filename */
	struct ct_fb_entry		*cfb_parent;	/* parent dir. */
};

/*
 * Version key.
 * subclasses of this have additional information.
 */
struct ct_fb_key {
	TAILQ_ENTRY(ct_fb_key)	 cfb_link;
	u_char			 cfb_type;	/* same types as in md file */
	uint32_t		 cfb_uid;	/* user id */
	uint32_t		 cfb_gid;	/* group id */
	uint32_t		 cfb_mode;	/* file mode */
	int64_t			 cfb_atime;	/* last access time */
	int64_t			 cfb_mtime;	/* last modification time */
};

struct ct_fb_file {
	struct ct_fb_key	 cfb_base;
	uint64_t		 cfb_nr_shas;	/* total shas */
	struct ct_fb_mdfile	*cfb_file;	/* file containing shas */
	off_t			 cfb_sha_offs;	/* offset into file */
	uint64_t		 cfb_file_size;
};

struct ct_fb_dir {
	struct ct_fb_key	cfb_base;
};

struct ct_fb_spec {
	struct ct_fb_key	cfb_base;
	int32_t			cfb_rdev;	/* major and minor */
};

struct ct_fb_link {
	struct ct_fb_key	 cfb_base;
	/* XXX hardlink has pointer to linkee? */
	char			*cfb_linkname;	/* where to link to */
	int			 cfb_hardlink;	/* boolean */
};

int		ctfb_main(int, char *[]);
void		ct_fb_print_entry(char *, struct ct_fb_key *, int);
