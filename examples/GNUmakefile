SUBDIRS = remote_list remote_archive remote_extract exists_ctfile

all: $(SUBDIRS)

$(TARGETS):
	@for i in $(SUBDIRS); do echo "===> $$i ($@)"; $(MAKE) -C $$i/ $@; done

$(SUBDIRS):
	@echo "===> $@"
	$(MAKE) -C $@

install:

clean:

uninstall:

.PHONY: all $(SUBDIRS) $(TARGETS)

