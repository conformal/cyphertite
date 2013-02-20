
-include ../../config/Makefile.common

# Attempt to include platform specific makefile.
# OSNAME may be passed in.
OSNAME ?= $(shell uname -s | sed -e 's/[-_].*//g')
OSNAME := $(shell echo $(OSNAME) | tr A-Z a-z)
-include ../../config/Makefile.$(OSNAME)

# Default paths.
DESTDIR ?=
LOCALBASE ?= /usr/local
BINDIR ?= ${LOCALBASE}/bin
LIBDIR ?= ${LOCALBASE}/lib
INCDIR ?= ${LOCALBASE}/include
MANDIR ?= $(LOCALBASE)/share/man

BUILDVERSION=$(shell sh ${CURDIR}/../../buildver.sh)
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
ifeq "$(wildcard ../../ctutil/obj)" ""
CTUTILDIR=../../ctutil/obj
else
CTUTILDIR=../../ctutil
endif

# curl
CURL.LDLIBS = $(shell PATH=$(BINDIR):$$PATH curl-config --static-libs | \
    sed -e 's/-lssl//g' -e 's/-lcrypto//g' -e 's/-lz//g' -e 's/ \+/ /g')

# Compiler and linker flags.
CPPFLAGS += -DNEED_LIBCLENS
INCFLAGS += -I../../ctutil -I../../libcyphertite -I$(INCDIR)/clens -I. -I$(INCDIR)
CFLAGS += $(INCFLAGS) $(WARNFLAGS) $(OPTLEVEL) $(DEBUG)
LDLIBS += -L../../ctutil/obj -L../../ctutil -L../../libcyphertite/obj
LDLIBS += -L../../libcyphertite
LDLIBS += -lcyphertite -lctutil -lassl -lexude -lclog -lshrink -lxmlsd
LDLIBS += -lclens -levent_core -lexpat -lsqlite3 -llzma -llzo2 $(CURL.LDLIBS)
LDLIBS += ${LIB.LINKSTATIC} -lssl -lcrypto
LDLIBS += ${LIB.LINKDYNAMIC} -ldl -ledit -lncurses -lz

BIN.NAME = ct_archive
BIN.SRCS = ct_archive.c
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

uninstall:

clean:
	$(RM) $(BIN.OBJS)
	$(RM) $(OBJPREFIX)$(BIN.NAME)
	$(RM) $(BIN.DEPS)

test:

-include $(BIN.DEPS)

.PHONY: clean depend install uninstall

