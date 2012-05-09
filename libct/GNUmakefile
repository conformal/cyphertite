
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
LNFLAGS ?= -sf
MKDIR ?= mkdir
RM ?= rm -f

# Compiler and linker flags.
CPPFLAGS += -DNEED_LIBCLENS -D_PASSWORD_LEN=128
INCFLAGS += -I. -I../ctutil -I$(INCDIR)/clens -I$(LOCALBASE)/ssl/include
CFLAGS += $(INCFLAGS) $(WARNFLAGS) $(OPTLEVEL) $(DEBUG)

LIB.NAME = ct

LIB.SRCS  = ct_aes_xts.c ct_bw_lim.c ct_config.c ct_config_paths.c ct_crypto.c
LIB.SRCS += ct_ctfile_mode.c ct_ctfile_remote.c ct_ctfile_traverse.c ct_db.c
LIB.SRCS += ct_event.c ct_files.c ct_match.c ct_ops.c ct_proto.c ct_queue.c
LIB.SRCS += ct_trees.c ct_util.c ct_xdr.c
LIB.HEADERS = ct_crypto.h ct_ctfile.h ct_db.h ct_ext.h ct_lib.h ct_match.h
LIB.HEADERS += ct_proto.h ct_types.h
LIB.OBJS = $(addprefix $(OBJPREFIX), $(LIB.SRCS:.c=.o))
LIB.DEPS = $(addsuffix .depend, $(LIB.OBJS))

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

uninstall:
	$(RM) $(DESTDIR)$(LIBDIR)/$(LIB.STATIC)
	$(RM) $(addprefix $(DESTDIR)$(INCDIR)/cyphertite, $(LIB.HEADERS))
	$(RMDIR) $(DESTDIR)$(INCDIR)/cyphertite

clean:
	$(RM) $(LIB.OBJS)
	$(RM) $(OBJPREFIX)$(LIB.STATIC)
	$(RM) $(LIB.DEPS)

-include $(LIB.DEPS)

.PHONY: clean depend install uninstall

