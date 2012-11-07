SUBDIRS = remote_list remote_archive remote_extract exists_ctfile
TARGETS = clean obj install uninstall depend

all: $(SUBDIRS)

$(TARGETS):
	@for i in $(SUBDIRS); do echo "===> $$i ($@)"; $(MAKE) -C $$i/ $@; done

$(SUBDIRS):
	@echo "===> $@"
	$(MAKE) -C $@

.PHONY: all $(SUBDIRS) $(TARGETS)

