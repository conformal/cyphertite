# cyphertite library code

.include "${.CURDIR}/../config/Makefile.common"
SYSTEM != uname -s
.if exists(${.CURDIR}/../config/Makefile.$(SYSTEM:L))
.  include "${.CURDIR}/../config/Makefile.$(SYSTEM:L)"
.endif

.if ${.TARGETS:M*analyze*}
CC=clang
CFLAGS+=--analyze
.elif ${.TARGETS:M*clang*}
CC=clang
.endif

LOCALBASE?=/usr/local
BINDIR?=${LOCALBASE}/bin
INCDIR?=${LOCALBASE}/include
LIBDIR?=${LOCALBASE}/lib
.PATH: ${.CURDIR}/../ctutil

LIB=	cyphertite
SRCS=	ct_match.c ct_proto.c ct_xdr.c ct_db.c ct_trees.c ct_crypto.c
SRCS+=	ct_aes_xts.c

SRCS=	ct_aes_xts.c ct_bw_lim.c ct_config.c ct_config_paths.c ct_crypto.c
SRCS+=	ct_ctfile_mode.c ct_ctfile_remote.c ct_ctfile_traverse.c ct_db.c
SRCS+=	ct_event.c ct_files.c ct_match.c ct_ops.c ct_proto.c ct_sapi.c
SRCS+=	ct_queue.c ct_trees.c ct_util.c ct_xdr.c
INCS=	ct_crypto.h ct_ctfile.h ct_db.h ct_ext.h cyphertite.h ct_match.h
INCS+=	ct_proto.h ct_types.h
MAN= ct.3 simplect.3
MLINKS+=ct.3 ct_create_secrets.3
MLINKS+=ct.3 ct_unlock_secrets.3
MLINKS+=ct.3 ctfile_parse.3
MLINKS+=ct.3 ctfile_parse_seek.3
MLINKS+=ct.3 ctfile_parse_close.3
MLINKS+=ct.3 ctfile_parse_tell.3
MLINKS+=ct.3 ctfile_parse_finddir.3
MLINKS+=ct.3 ctfile_parse_insertdir.3
MLINKS+=ct.3 ctfile_write_init.3
MLINKS+=ct.3 ctdb_shutdown.3
MLINKS+=ct.3 ct_basis_setup.3
MLINKS+=ct.3 ct_load_config.3
MLINKS+=ct.3 ct_unload_config.3
MLINKS+=ct.3 ct_system_config.3
MLINKS+=ct.3 ct_user_config.3
MLINKS+=ct.3 ct_user_config_old.3
MLINKS+=ct.3 ct_write_config.3
MLINKS+=ct.3 ct_default_config.3
MLINKS+=ct.3 ct_download_decode_and_save_certs.3
MLINKS+=ct.3 ct_setup_state.3
MLINKS+=ct.3 ct_set_file_state.3
MLINKS+=ct.3 ct_queue_transfer.3
MLINKS+=ct.3 ct_ssl_connect.3
MLINKS+=ct.3 ct_ssl_cleanup.3
MLINKS+=ct.3 ct_assl_negotiate_poll.3
MLINKS+=ct.3 ct_init.3
MLINKS+=ct.3 ct_init_eventloop.3
MLINKS+=ct.3 ct_cleanup.3
MLINKS+=ct.3 ct_cleanup_eventloop.3
MLINKS+=ct.3 ct_event_init.3
MLINKS+=ct.3 ct_event_dispatch.3
MLINKS+=ct.3 ct_event_loopbreak.3
MLINKS+=ct.3 ct_event_cleanup.3
MLINKS+=ct.3 ct_wakeup_file.3
MLINKS+=ct.3 ct_wakeup_sha.3
MLINKS+=ct.3 ct_wakeup_compress.3
MLINKS+=ct.3 ct_wakeup_csha.3
MLINKS+=ct.3 ct_wakeup_encrypt.3
MLINKS+=ct.3 ct_wakeup_write.3
MLINKS+=ct.3 ct_wakeup_complete.3
MLINKS+=ct.3 ct_setup_wakeup_file.3
MLINKS+=ct.3 ct_setup_wakeup_sha.3
MLINKS+=ct.3 ct_setup_wakeup_compress.3
MLINKS+=ct.3 ct_setup_wakeup_csha.3
MLINKS+=ct.3 ct_setup_wakeup_encrypt.3
MLINKS+=ct.3 ct_setup_wakeup_write.3
MLINKS+=ct.3 ct_setup_wakeup_complete.3
MLINKS+=ct.3 ct_set_reconnect_timeout.3
MLINKS+=ct.3 ct_trans_alloc.3
MLINKS+=ct.3 ct_trans_realloc_local.3
MLINKS+=ct.3 ct_trans_free.3
MLINKS+=ct.3 ct_dirname.3
MLINKS+=ct.3 ct_basename.3
MLINKS+=ct.3 ct_absolute_path.3
MLINKS+=ct.3 ctfile_verify_name.3
MLINKS+=ct.3 ctfile_trim_cache.3
MLINKS+=ct.3 ct_prompt_for_login_password.3
MLINKS+=ct.3 ct_normalize_username.3
MLINKS+=ct.3 ct_normalize_path.3
MLINKS+=ct.3 ct_normalize_filelist.3
MLINKS+=ct.3 ct_add_operation.3
MLINKS+=ct.3 ct_add_operation_after.3
MLINKS+=ct.3 ct_do_operation.3
MLINKS+=ct.3 ctfile_list_complete.3
MLINKS+=ct.3 ct_file_on_server.3
MLINKS+=ct.3 ct_cull_kick.3
MLINKS+=ct.3 ct_have_remote_secrets_file.3
MLINKS+=ct.3 ctfile_find_for_operation.3
MLINKS+=ct.3 ct_extract_setup.3
MLINKS+=ct.3 ct_extract_open_next.3
MLINKS+=ct.3 ct_file_extract_open.3
MLINKS+=ct.3 ct_file_extract_write.3
MLINKS+=ct.3 ct_file_extract_close.3
MLINKS+=ct.3 ct_file_extract_special.3
MLINKS+=ct.3 ct_get_answer.3
MLINKS+=ct.3 ct_prompt_password.3
MLINKS+=ct.3 ct_getloginbyuid.3
MLINKS+=simplect.3 ct_do_remotelist.3
MLINKS+=simplect.3 ct_do_remotearchive.3
MLINKS+=simplect.3 ct_do_remoteextract.3
MLINKS+=ct.3 ct_match.3
MLINKS+=ct.3 ct_match_compile.3
MLINKS+=ct.3 ct_match_fromfile.3
MLINKS+=ct.3 ct_matchlist_free.3
MLINKS+=ct.3 ct_matchlist_fromfile.3
MLINKS+=ct.3 ct_match_unwind.3
MLINKS+=ct.3 ct_body_alloc_xml.3

NOPIC=	nopic

INCFLAGS+= -I${.CURDIR}/../ctutil -I${LOCALBASE}/include -I${.CURDIR}
CFLAGS+= ${INCFLAGS} ${WARNFLAGS}

analyze: all
clang: all

.include <bsd.lib.mk>
