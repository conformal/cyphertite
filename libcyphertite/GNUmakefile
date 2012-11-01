
-include ../config/Makefile.common

# Attempt to include platform specific makefile.
# OSNAME may be passed in.
OSNAME ?= $(shell uname -s)
OSNAME := $(shell echo $(OSNAME) | tr A-Z a-z)
-include ../config/Makefile.$(OSNAME)

# Default paths.
DESTDIR ?=
LOCALBASE ?= /usr/local
BINDIR ?= ${LOCALBASE}/bin
LIBDIR ?= ${LOCALBASE}/lib
INCDIR ?= ${LOCALBASE}/include
MANDIR ?= $(LOCALBASE)/share/man

# Use obj directory if it exists.
OBJPREFIX ?= obj/
ifeq "$(wildcard $(OBJPREFIX))" ""
	OBJPREFIX =
endif

# System utils.
AR ?= ar
CC ?= gcc
INSTALL ?= install
LN ?= ln
LNFORCE ?= -f
LNFLAGS ?= -sf
MKDIR ?= mkdir
RM ?= rm -f

# Compiler and linker flags.
CPPFLAGS += -DNEED_LIBCLENS
INCFLAGS += -I. -I../ctutil -I$(INCDIR)/clens -I$(LOCALBASE)/ssl/include
CFLAGS += $(INCFLAGS) $(WARNFLAGS) $(OPTLEVEL) $(DEBUG)

LIB.NAME = cyphertite

LIB.SRCS  = ct_aes_xts.c ct_bw_lim.c ct_config.c ct_config_paths.c ct_crypto.c
LIB.SRCS += ct_ctfile_mode.c ct_ctfile_remote.c ct_ctfile_traverse.c ct_db.c
LIB.SRCS += ct_event.c ct_files.c ct_glob.c ct_match.c ct_ops.c ct_proto.c ct_queue.c
LIB.SRCS += ct_trees.c ct_util.c ct_xdr.c ct_sapi.c ct_version_tree.c
LIB.SRCS += ct_archive.c
LIB.HEADERS = ct_crypto.h ct_ctfile.h ct_db.h ct_ext.h cyphertite.h ct_match.h
LIB.HEADERS += ct_proto.h ct_types.h ct_version_tree.h ct_sapi.h
LIB.OBJS = $(addprefix $(OBJPREFIX), $(LIB.SRCS:.c=.o))
LIB.DEPS = $(addsuffix .depend, $(LIB.OBJS))
LIB.MANPAGES = cyphertite.3 simplect.3
LIB.MLINKS+=cyphertite.3 ct_create_secrets.3
LIB.MLINKS+=cyphertite.3 ct_unlock_secrets.3
LIB.MLINKS+=cyphertite.3 ctfile_parse.3
LIB.MLINKS+=cyphertite.3 ctfile_parse_seek.3
LIB.MLINKS+=cyphertite.3 ctfile_parse_close.3
LIB.MLINKS+=cyphertite.3 ctfile_parse_tell.3
LIB.MLINKS+=cyphertite.3 ctfile_parse_finddir.3
LIB.MLINKS+=cyphertite.3 ctfile_parse_insertdir.3
LIB.MLINKS+=cyphertite.3 ctfile_write_init.3
LIB.MLINKS+=cyphertite.3 ctdb_shutdown.3
LIB.MLINKS+=cyphertite.3 ct_basis_setup.3
LIB.MLINKS+=cyphertite.3 ct_load_config.3
LIB.MLINKS+=cyphertite.3 ct_unload_config.3
LIB.MLINKS+=cyphertite.3 ct_system_config.3
LIB.MLINKS+=cyphertite.3 ct_user_config.3
LIB.MLINKS+=cyphertite.3 ct_user_config_old.3
LIB.MLINKS+=cyphertite.3 ct_write_config.3
LIB.MLINKS+=cyphertite.3 ct_default_config.3
LIB.MLINKS+=cyphertite.3 ct_download_decode_and_save_certs.3
LIB.MLINKS+=cyphertite.3 ct_setup_state.3
LIB.MLINKS+=cyphertite.3 ct_set_file_state.3
LIB.MLINKS+=cyphertite.3 ct_queue_transfer.3
LIB.MLINKS+=cyphertite.3 ct_ssl_connect.3
LIB.MLINKS+=cyphertite.3 ct_ssl_cleanup.3
LIB.MLINKS+=cyphertite.3 ct_assl_negotiate_poll.3
LIB.MLINKS+=cyphertite.3 ct_init.3
LIB.MLINKS+=cyphertite.3 ct_init_eventloop.3
LIB.MLINKS+=cyphertite.3 ct_cleanup.3
LIB.MLINKS+=cyphertite.3 ct_cleanup_eventloop.3
LIB.MLINKS+=cyphertite.3 ct_event_init.3
LIB.MLINKS+=cyphertite.3 ct_event_dispatch.3
LIB.MLINKS+=cyphertite.3 ct_event_loopbreak.3
LIB.MLINKS+=cyphertite.3 ct_event_cleanup.3
LIB.MLINKS+=cyphertite.3 ct_wakeup_file.3
LIB.MLINKS+=cyphertite.3 ct_wakeup_sha.3
LIB.MLINKS+=cyphertite.3 ct_wakeup_compress.3
LIB.MLINKS+=cyphertite.3 ct_wakeup_csha.3
LIB.MLINKS+=cyphertite.3 ct_wakeup_encrypt.3
LIB.MLINKS+=cyphertite.3 ct_wakeup_write.3
LIB.MLINKS+=cyphertite.3 ct_wakeup_complete.3
LIB.MLINKS+=cyphertite.3 ct_setup_wakeup_file.3
LIB.MLINKS+=cyphertite.3 ct_setup_wakeup_sha.3
LIB.MLINKS+=cyphertite.3 ct_setup_wakeup_compress.3
LIB.MLINKS+=cyphertite.3 ct_setup_wakeup_csha.3
LIB.MLINKS+=cyphertite.3 ct_setup_wakeup_encrypt.3
LIB.MLINKS+=cyphertite.3 ct_setup_wakeup_write.3
LIB.MLINKS+=cyphertite.3 ct_setup_wakeup_complete.3
LIB.MLINKS+=cyphertite.3 ct_set_reconnect_timeout.3
LIB.MLINKS+=cyphertite.3 ct_trans_alloc.3
LIB.MLINKS+=cyphertite.3 ct_trans_realloc_local.3
LIB.MLINKS+=cyphertite.3 ct_trans_free.3
LIB.MLINKS+=cyphertite.3 ct_dirname.3
LIB.MLINKS+=cyphertite.3 ct_basename.3
LIB.MLINKS+=cyphertite.3 ct_absolute_path.3
LIB.MLINKS+=cyphertite.3 ctfile_verify_name.3
LIB.MLINKS+=cyphertite.3 ctfile_trim_cache.3
LIB.MLINKS+=cyphertite.3 ct_prompt_for_login_password.3
LIB.MLINKS+=cyphertite.3 ct_normalize_username.3
LIB.MLINKS+=cyphertite.3 ct_normalize_path.3
LIB.MLINKS+=cyphertite.3 ct_normalize_filelist.3
LIB.MLINKS+=cyphertite.3 ct_add_operation.3
LIB.MLINKS+=cyphertite.3 ct_add_operation_after.3
LIB.MLINKS+=cyphertite.3 ct_do_operation.3
LIB.MLINKS+=cyphertite.3 ctfile_list_complete.3
LIB.MLINKS+=cyphertite.3 ct_file_on_server.3
LIB.MLINKS+=cyphertite.3 ct_cull_kick.3
LIB.MLINKS+=cyphertite.3 ct_have_remote_secrets_file.3
LIB.MLINKS+=cyphertite.3 ctfile_find_for_operation.3
LIB.MLINKS+=cyphertite.3 ct_extract_setup.3
LIB.MLINKS+=cyphertite.3 ct_extract_open_next.3
LIB.MLINKS+=cyphertite.3 ct_file_extract_open.3
LIB.MLINKS+=cyphertite.3 ct_file_extract_write.3
LIB.MLINKS+=cyphertite.3 ct_file_extract_close.3
LIB.MLINKS+=cyphertite.3 ct_file_extract_special.3
LIB.MLINKS+=cyphertite.3 ct_get_answer.3
LIB.MLINKS+=cyphertite.3 ct_prompt_password.3
LIB.MLINKS+=cyphertite.3 ct_getloginbyuid.3
LIB.MLINKS+=simplect.3 ct_do_list.3
LIB.MLINKS+=simplect.3 ct_do_archive.3
LIB.MLINKS+=simplect.3 ct_do_extract.3
LIB.MLINKS+=simplect.3 ct_do_delete.3
LIB.MLINKS+=simplect.3 ct_do_check_existance.3
LIB.MLINKS+=simplect.3 ct_setup_preinit.3
LIB.MLINKS+=simplect.3 ct_setup_config.3
LIB.MLINKS+=simplect.3 ct_cleanup_all.3
LIB.MLINKS+=cyphertite.3 ct_match.3
LIB.MLINKS+=cyphertite.3 ct_match_compile.3
LIB.MLINKS+=cyphertite.3 ct_match_fromfile.3
LIB.MLINKS+=cyphertite.3 ct_matchlist_free.3
LIB.MLINKS+=cyphertite.3 ct_matchlist_fromfile.3
LIB.MLINKS+=cyphertite.3 ct_match_unwind.3
LIB.MLINKS+=cyphertite.3 ct_body_alloc_xml.3
LIB.MDIRS = $(foreach page, $(LIB.MANPAGES), $(subst ., man, $(suffix $(page))))
LIB.MLINKS := $(foreach page, $(LIB.MLINKS), $(subst ., man, $(suffix $(page)))/$(page))

all: $(OBJPREFIX)$(LIB.STATIC)

obj:
	-$(MKDIR) obj

$(OBJPREFIX)$(LIB.STATIC): $(LIB.OBJS)
	$(AR) $(ARFLAGS) $@ $^

$(OBJPREFIX)%.o: %.c
	@echo "Generating $@.depend"
	@$(CC) $(INCFLAGS) -MM $(CPPFLAGS) $< | \
	sed 's,$*\.o[ :]*,$@ $@.depend : ,g' >> $@.depend
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ -c $<

depend:
	@echo "Dependencies are automatically generated.  This target is not necessary."

install:
	$(INSTALL) -m 0755 -d $(DESTDIR)$(LIBDIR)/
	$(INSTALL) -m 0644 $(OBJPREFIX)$(LIB.STATIC) $(DESTDIR)$(LIBDIR)/
	$(INSTALL) -m 0755 -d $(DESTDIR)$(INCDIR)/cyphertite
	$(INSTALL) -m 0644 $(LIB.HEADERS) $(DESTDIR)$(INCDIR)/cyphertite
	$(foreach page, $(LIB.MANPAGES), \
		$(INSTALL) -m 0444 $(page) $(addprefix $(DESTDIR)$(MANDIR)/, \
		$(subst ., man, $(suffix $(page))))/; \
	)
	@set $(addprefix $(DESTDIR)$(MANDIR)/, $(LIB.MLINKS)); \
	while : ; do \
		case $$# in \
			0) break;; \
			1) echo "Warning: Unbalanced MLINK: $$1"; break;; \
		esac; \
		page=$$1; shift; link=$$1; shift; \
		echo $(LN) $(LNFORCE) $$page $$link; \
		$(LN) $(LNFORCE) $$page $$link; \
	done

uninstall:
	$(RM) $(DESTDIR)$(LIBDIR)/$(LIB.STATIC)
	$(RM) $(addprefix $(DESTDIR)$(INCDIR)/cyphertite, $(LIB.HEADERS))
	$(RMDIR) $(DESTDIR)$(INCDIR)/cyphertite
	while : ; do \
		case $$# in \
			0) break;; \
			1) echo "Warning: Unbalanced MLINK: $$1"; break;; \
		esac; \
		page=$$1; shift; link=$$1; shift; \
		echo $(RM) $$link; \
		$(RM) $$link; \
	done
	$(foreach page, $(LIB.MANPAGES), \
		$(RM) $(addprefix $(DESTDIR)$(MANDIR)/, \
		$(subst ., man, $(suffix $(page))))/$(page); \
	)

clean:
	$(RM) $(LIB.OBJS)
	$(RM) $(OBJPREFIX)$(LIB.STATIC)
	$(RM) $(LIB.DEPS)

-include $(LIB.DEPS)

.PHONY: clean depend install uninstall

