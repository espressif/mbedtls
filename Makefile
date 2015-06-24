
DESTDIR=/usr/local
PREFIX=mbedtls_

.SILENT:

.PHONY: all no_test programs lib tests install uninstall clean test check covtest lcov apidoc apidoc_clean

all: programs tests

no_test: programs

programs:
	$(MAKE) -C programs

lib:
	$(MAKE) -C library

tests:
	$(MAKE) -C tests

ifndef WINDOWS
install: all
	mkdir -p $(DESTDIR)/include/mbedtls
	cp -r include/mbedtls $(DESTDIR)/include
	
	mkdir -p $(DESTDIR)/lib
	cp -RP library/libmbedtls.* $(DESTDIR)/lib
	
	mkdir -p $(DESTDIR)/bin
	for p in programs/*/* ; do              \
	    if [ -x $$p ] && [ ! -d $$p ] ;     \
	    then                                \
	        f=$(PREFIX)`basename $$p` ;     \
	        cp $$p $(DESTDIR)/bin/$$f ;     \
	        ln -sf $$f $(DESTDIR)/bin/$$o ; \
	    fi                                  \
	done

uninstall:
	rm -rf $(DESTDIR)/include/mbedtls
	rm -f $(DESTDIR)/lib/libmbedtls.*
	
	for p in programs/*/* ; do              \
	    if [ -x $$p ] && [ ! -d $$p ] ;     \
	    then                                \
	        f=$(PREFIX)`basename $$p` ;     \
	        rm -f $(DESTDIR)/bin/$$f ;      \
	        rm -f $(DESTDIR)/bin/$$o ;      \
	    fi                                  \
	done
endif

clean:
	$(MAKE) -C library clean
	$(MAKE) -C programs clean
	$(MAKE) -C tests clean
ifndef WINDOWS
	find . \( -name \*.gcno -o -name \*.gcda -o -name *.info \) -exec rm {} +
endif

ifndef WINDOWS
check:
	$(MAKE) -C tests check

test: check

# note: for coverage testing, build with:
# make CFLAGS='--coverage -g3 -O0'
covtest:
	make check
	programs/test/selftest
	( cd tests && ./compat.sh )
	( cd tests && ./ssl-opt.sh )

lcov:
	rm -rf Coverage
	lcov --capture --initial --directory library -o files.info
	lcov --capture --directory library -o tests.info
	lcov --add-tracefile files.info --add-tracefile tests.info -o all.info
	lcov --remove all.info -o final.info '*.h'
	gendesc tests/Descriptions.txt -o descriptions
	genhtml --title "mbed TLS" --description-file descriptions --keep-descriptions --legend --no-branch-coverage -o Coverage final.info
	rm -f files.info tests.info all.info final.info descriptions

apidoc:
	mkdir -p apidoc
	doxygen doxygen/mbedtls.doxyfile

apidoc_clean:
	rm -rf apidoc
endif
