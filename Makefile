#
# Copyright (C) 2013-2016 Canonical, Ltd.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
#

VERSION=0.01.05

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
