# $cyphertite$

# Attempt to include platform specific makefile.
# OSNAME may be passed in.
OSNAME ?= $(shell uname -s)
OSNAME := $(shell echo $(OSNAME) | tr A-Z a-z)
-include ../config/Makefile.$(OSNAME)

# Default paths.
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
CC ?= gcc
INSTALL ?= install
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
INCFLAGS += -I ../ctutil -I $(INCDIR)/clens
WARNFLAGS ?= -Wall -Werror
DEBUG += -g
CFLAGS += $(INCFLAGS) $(WARNFLAGS) $(DEBUG)
LDFLAGS += -L/usr/local/ssl/lib
LDFLAGS += -L../ctutil/obj -L../ctutil -lctutil -lassl -lclog -levent -lexude
LDFLAGS += -lshrink -lsqlite3 -llzma -llzo2 -lz -lclens -lbsd -Wl,-Bstatic -lssl -lcrypto
LDFLAGS += -Wl,-Bdynamic -ldl

BIN.NAME = cyphertite
BIN.SRCS = ct_main.c ct_metadata.c ct_files.c ct_util.c ct_queue.c ct_event.c
BIN.SRCS += ct_aes_xts.c ct_crypto.c ct_match.c
BIN.SRCS += ct_db.c ct_xdr.c
BIN.OBJS = $(addprefix $(OBJPREFIX), $(BIN.SRCS:.c=.o))
BIN.DEPS = $(addsuffix .depend, $(BIN.OBJS))
BIN.LDFLAGS = $(LDFLAGS.EXTRA) $(LDFLAGS) $(LDADD)

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
	$(INSTALL) -m 555 $(OBJPREFIX)$(BIN.NAME) $(BINDIR)/
	
uninstall:
	$(RM) $(BINDIR)/$(BIN.NAME)
	
clean:
	$(RM) $(BIN.OBJS)
	$(RM) $(OBJPREFIX)$(BIN.NAME)
	$(RM) $(BIN.DEPS)

-include $(BIN.DEPS)

.PHONY: clean depend install uninstall

