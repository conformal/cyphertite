
/* RB, probably */
struct ct_archive_file {
	RB_ENTRY(ct_archive_file)	 af_entry;
	const char			*af_name;
	int64_t				 af_mtime;
	int64_t				 af_size;
	/* for 3factor */
};

struct ct_archive_dnode {
	struct dnode					 ad_dnode;
	/* child *regular* files only */
	RB_HEAD(ct_archive_files, ct_archive_file)	 ad_children;
	int		 				 ad_seen; /* seen during real backup? */
};
RB_PROTOTYPE(ct_archive_files, ct_archive_file, af_entry, ct_archive_file_cmp);

int	ct_basis_setup(struct ct_archive_state *, const char *, char **, int,
	    const char *, int);
void	ct_archive_set_level(struct ct_archive_state *, int);
int	ct_archive_get_level(struct ct_archive_state *);
void	ct_archive_set_prev_backup_time(struct ct_archive_state *, time_t);
