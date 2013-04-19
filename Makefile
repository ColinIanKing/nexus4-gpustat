VERSION=0.01.01

CFLAGS += -Wall -DVERSION='"$(VERSION)"'

BINDIR=/usr/bin
MANDIR=/usr/share/man/man8

nexus4-gpustat: nexus4-gpustat.o
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

nexus4-gpustat.8.gz: nexus4-gpustat.8
	gzip -c $< > $@

dist:
	git archive --format=tar --prefix="nexus4-gpustat-$(VERSION)/" V$(VERSION) | \
		gzip > nexus4-gpustat-$(VERSION).tar.gz

clean:
	rm -f nexus4-gpustat nexus4-gpustat.o nexus4-gpustat.8.gz
	rm -f nexus4-gpustat-$(VERSION).tar.gz

install: nexus4-gpustat nexus4-gpustat.8.gz
	mkdir -p ${DESTDIR}${BINDIR}
	cp nexus4-gpustat ${DESTDIR}${BINDIR}
	mkdir -p ${DESTDIR}${MANDIR}
	cp nexus4-gpustat.8.gz ${DESTDIR}${MANDIR}
