SUBDIRS = ct_list ct_archive ct_extract ct_exists ct_delete
TARGETS = clean obj install uninstall depend test

all: $(SUBDIRS)

$(TARGETS):
	@for i in $(SUBDIRS); do echo "===> $$i ($@)"; $(MAKE) -C $$i/ $@; done

$(SUBDIRS):
	@echo "===> $@"
	$(MAKE) -C $@

.PHONY: all $(SUBDIRS) $(TARGETS)

