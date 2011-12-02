
# Attempt to include platform specific makefile.
# OSNAME may be passed in.
OSNAME ?= $(shell uname -s)
OSNAME := $(shell echo $(OSNAME) | tr A-Z a-z)
-include ../config/Makefile.$(OSNAME)
-include ../config/Makefile.common

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
CC ?= gcc
INSTALL ?= install
LN ?= ln
LNFORCE ?= -f
MKDIR ?= mkdir
RM ?= rm -f

# Get correct ctutil directory.
ifeq "$(wildcard ../ctutil/obj)" ""
CTUTILDIR=../ctutil/obj
else
CTUTILDIR=../ctutil
endif

# Compiler and linker flags.
CPPFLAGS += -DNEED_LIBCLENS
INCFLAGS += -I../ctutil -I$(INCDIR)/clens -I$(LOCALBASE)/ssl/include
CFLAGS += $(INCFLAGS) $(WARNFLAGS) $(DEBUG)
LDFLAGS += -L$(LOCALBASE)/ssl/lib
LDFLAGS += -L../ctutil/obj -L../ctutil -lctutil -lassl -lclog -levent -lexude
LDFLAGS += -lshrink -lxmlsd -lexpat -lsqlite3 -llzma -llzo2 -lz -lclens -lbsd
LDFLAGS += -Wl,-Bstatic -lssl -lcrypto -Wl,-Bdynamic -ldl -ledit -lncurses

BIN.NAME = cyphertite
BIN.LINKS = ct cyphertitectl ctctl cyphertitefb ctfb
BIN.SRCS = ct_main.c ct_metadata.c ct_files.c ct_util.c ct_queue.c ct_event.c
BIN.SRCS += ct_aes_xts.c ct_crypto.c ct_match.c
BIN.SRCS += ct_db.c ct_xdr.c ct_bw_lim.c ct_ctl.c ct_md_xdr.c
BIN.SRCS += ct_config.c ct_md_traverse.c ct_fb.c
BIN.MANPAGES = cyphertite.1 cyphertite.conf.5 cyphertitefb.1
BIN.OBJS = $(addprefix $(OBJPREFIX), $(BIN.SRCS:.c=.o))
BIN.DEPS = $(addsuffix .depend, $(BIN.OBJS))
BIN.LDFLAGS = $(LDFLAGS.EXTRA) $(LDFLAGS) $(LDADD)
BIN.MDIRS = $(foreach page, $(BIN.MANPAGES), $(subst ., man, $(suffix $(page))))

all: $(OBJPREFIX)$(BIN.NAME)

obj:
	-$(MKDIR) obj

$(OBJPREFIX)$(BIN.NAME): $(BIN.OBJS)
	$(CC) $^ $(BIN.LDFLAGS) -o $@


$(OBJPREFIX)%.o: %.c
	@echo "Generating $@.depend"
	@$(CC) $(INCFLAGS) -MM $(CPPFLAGS) $< | \
	sed 's,$*\.o[ :]*,$@ $@.depend : ,g' >> $@.depend
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ -c $<

depend:
	@echo "Dependencies are automatically generated.  This target is not necessary."

install:
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)/
	$(INSTALL) -m 0755 $(OBJPREFIX)$(BIN.NAME) $(DESTDIR)$(BINDIR)/
	$(INSTALL) -m 0755 -d $(addprefix $(DESTDIR)$(MANDIR)/, $(BIN.MDIRS))
	$(foreach link, $(BIN.LINKS), \
		$(LN) $(LNFORCE) $(DESTDIR)$(BINDIR)/$(BIN.NAME) \
		$(DESTDIR)$(BINDIR)/$(link); \
	)
	$(foreach page, $(BIN.MANPAGES), \
		$(INSTALL) -m 0444 $(page) $(addprefix $(DESTDIR)$(MANDIR)/, \
		$(subst ., man, $(suffix $(page))))/; \
	)

uninstall:
	$(RM) $(DESTDIR)$(BINDIR)/$(BIN.NAME)
	$(foreach link, $(BIN.LINKS), \
		$(RM) $(DESTDIR)$(BINDIR)/$(link); \
	)
	$(foreach page, $(BIN.MANPAGES), \
		$(RM) $(addprefix $(DESTDIR)$(MANDIR)/, \
		$(subst ., man, $(suffix $(page))))/$(page); \
	)

clean:
	$(RM) $(BIN.OBJS)
	$(RM) $(OBJPREFIX)$(BIN.NAME)
	$(RM) $(BIN.DEPS)

-include $(BIN.DEPS)

.PHONY: clean depend install uninstall

