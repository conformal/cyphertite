SUBDIRS = test_ct_fts
TARGETS = clean obj install uninstall depend test regress

all: $(SUBDIRS)

$(TARGETS):
	@for i in $(SUBDIRS); do echo "===> $$i ($@)"; $(MAKE) -C $$i/ $@; done

$(SUBDIRS):
	@echo "===> $@"
	$(MAKE) -C $@

.PHONY: all $(SUBDIRS) $(TARGETS)

