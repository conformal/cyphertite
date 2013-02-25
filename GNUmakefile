SUBDIRS = ctutil libcyphertite cyphertite examples
TARGETS = clean obj install uninstall depend test

all: $(SUBDIRS)

$(TARGETS):
	@for i in $(SUBDIRS); do echo "===> $$i ($@)"; $(MAKE) -C $$i/ $@; done

$(SUBDIRS):
	@echo "===> $@"
	$(MAKE) -C $@

.PHONY: all $(SUBDIRS) $(TARGETS)

