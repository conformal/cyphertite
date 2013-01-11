
-include ../config/Makefile.common

# Attempt to include platform specific makefile.
# OSNAME may be passed in.
OSNAME ?= $(shell uname -s | sed -e 's/[-_].*//g')
OSNAME := $(shell echo $(OSNAME) | tr A-Z a-z)
-include ../config/Makefile.$(OSNAME)

# Default paths.
DESTDIR ?=
LOCALBASE ?= /usr/local
BINDIR ?= ${LOCALBASE}/bin
LIBDIR ?= ${LOCALBASE}/lib
INCDIR ?= ${LOCALBASE}/include
MANDIR ?= $(LOCALBASE)/share/man

BUILDVERSION=$(shell sh ${CURDIR}/../buildver.sh)
ifneq ("${BUILDVERSION}", "")
CPPFLAGS+= -DBUILDSTR=\"$(BUILDVERSION)\"
endif

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

# curl
CURL.LDLIBS = $(shell curl-config --static-libs)

# Compiler and linker flags.
CPPFLAGS += -DNEED_LIBCLENS
INCFLAGS += -I../ctutil -I../libcyphertite -I$(INCDIR)/clens -I.
CFLAGS += $(INCFLAGS) $(WARNFLAGS) $(OPTLEVEL) $(DEBUG)
LDLIBS += -L../ctutil/obj -L../ctutil -L../libcyphertite/obj -L../libcyphertite
LDLIBS += -lcyphertite -lctutil -lassl -lexude -lclog -lshrink -lxmlsd
LDLIBS += -lclens -levent_core -lexpat -lsqlite3 -llzma -llzo2
LDLIBS += $(LIB.LINKSTATIC) $(CURL.LDLIBS) -lssl -lcrypto
LDLIBS += $(LIB.LINKDYNAMIC) -ldl -ledit -lncurses -lz

BIN.NAME = cyphertite
BIN.LINKS = ct cyphertitectl ctctl cyphertitefb ctfb
BIN.SRCS = ct_main.c ct_ctl.c ct_fb.c ct_fb_ops.c $(CT_EXT_SRC)
BIN.MANPAGES = cyphertite.1 cyphertite.conf.5 cyphertitefb.1 cyphertitectl.1
BIN.MLINKS  = cyphertite.1 ct.1
BIN.MLINKS += cyphertitefb.1 ctfb.1
BIN.MLINKS += cyphertitectl.1 ctctl.1
BIN.OBJS = $(addprefix $(OBJPREFIX), $(BIN.SRCS:.c=.o))
BIN.DEPS = $(addsuffix .depend, $(BIN.OBJS))
BIN.LDFLAGS = $(LDFLAGS.EXTRA) $(LDFLAGS)
BIN.LDLIBS = $(LDLIBS) $(LDADD)
BIN.MDIRS = $(foreach page, $(BIN.MANPAGES), $(subst ., man, $(suffix $(page))))
BIN.MLINKS := $(foreach page, $(BIN.MLINKS), $(subst ., man, $(suffix $(page)))/$(page))

all: $(OBJPREFIX)$(BIN.NAME)

obj:
	-$(MKDIR) obj

$(OBJPREFIX)$(BIN.NAME): $(BIN.OBJS)
	$(CC) $(BIN.LDFLAGS) -o $@ $^ ${BIN.LDLIBS}


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
	@set $(addprefix $(DESTDIR)$(MANDIR)/, $(BIN.MLINKS)); \
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
	$(RM) $(DESTDIR)$(BINDIR)/$(BIN.NAME)
	$(foreach link, $(BIN.LINKS), \
		$(RM) $(DESTDIR)$(BINDIR)/$(link); \
	)
	@set $(addprefix $(DESTDIR)$(MANDIR)/, $(BIN.MLINKS)); \
	while : ; do \
		case $$# in \
			0) break;; \
			1) echo "Warning: Unbalanced MLINK: $$1"; break;; \
		esac; \
		page=$$1; shift; link=$$1; shift; \
		echo $(RM) $$link; \
		$(RM) $$link; \
	done
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

