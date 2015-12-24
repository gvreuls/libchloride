## Makefile
## Created on: Dec 22, 2015
##     Author: gv
## 
## This file is part of libchloride.
## Copyright (C) 2015 Guy Vreuls
##
## Libchloride is free software: you can redistribute it and/or modify
## it under the terms of the GNU Lesser General Public License as
## published by the Free Software Foundation, either version 2.1 of
## the License, or (at your option) any later version.
##
## Libchloride is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU Lesser General Public License for more details.
##
## You should have received a copy of the Lesser GNU General Public
## License along with libchloride.  If not, see
## <http://www.gnu.org/licenses/>.

CXXFLAGS=-Wall -Wconversion -Wcast-qual -Wextra -Wshadow -Werror -pedantic -pedantic-errors -fmessage-length=0
CPPFLAGS=-std=c++11 -I.
LDFLAGS=
ARFLAGS=
LDLIBS=
TAGSFLAGS=

ifdef DEBUG
	override CXXFLAGS+=-g3
	override CPPFLAGS+=-DDEBUG=$(DEBUG)
	override TAGSFLAGS+=-I DEBUG=$(DEBUG)
	BUILDDIR=Debug
	BUILDSUFFIX=-debug
else
	override CXXFLAGS+=-O3
	override CPPFLAGS+=-DNDEBUG
	BUILDDIR=Release
	BUILDSUFFIX=
endif

LD=$(CXX)
CP=cp
TAR=tar
MKDIR=mkdir
STRIP=strip
INSTALL=install -c
CTAGS=ctags
ETAGS=etags
DEVNULL=/dev/null

TARGETNAME=chloride
INCLUDEDIR=$(TARGETNAME)
SOURCEDIR=src

BASEHEADERS:=$(wildcard *.h)
SUBHEADERS:=$(wildcard $(INCLUDEDIR)/Crypto*.h)
VERSIONHEADER:=$(INCLUDEDIR)/version.h
HEADERS:=$(BASEHEADERS) $(SUBHEADERS)
SOURCES:=$(wildcard $(SOURCEDIR)/*.cpp)
OBJECTS:=$(SOURCES:$(SOURCEDIR)/%.cpp=$(BUILDDIR)/%.o)
DEPS:=$(OBJECTS:.o=.d)
AUXFILES=Makefile LICENSE.LGPL2.1 README example.cpp

CTAGSFILE=tags
ETAGSFILE=TAGS

ARCHIVE=$(BUILDDIR)/lib$(TARGETNAME)$(BUILDSUFFIX).a
LIBRARY=$(ARCHIVE:.a=.so)

prefixdir:=/usr
bindir:=$(prefixdir)/bin
incdir:=$(prefixdir)/include
libdir:=$(prefixdir)/lib
mandir:=$(prefixdir)/man

version_major=0
version_minor=1
version_revision=0
version:=$(version_major).$(version_minor).$(version_revision)

mdistdir:=lib$(TARGETNAME)-$(version)
distribution:=$(mdistdir).tar.gz
distfiles:=$(BASEHEADERS) $(INCLUDEDIR) $(SOURCEDIR) $(AUXFILES)

NONDEPGOALS=clean depclean realclean distclean install uninstall exampleclean

all: lib

clean:
	-$(RM) $(ARCHIVE) $(LIBRARY) $(OBJECTS) $(VERSIONHEADER) example

depclean: clean
	-$(RM) $(DEPS)

realclean: depclean
	-$(RM) $(CTAGSFILE) $(ETAGSFILE)

distclean: realclean
	-$(RM) $(distribution)

install:
	-$(INSTALL) -d $(incdir) $(incdir)/$(INCLUDEDIR) $(libdir)
	$(INSTALL) $(BASEHEADERS) $(incdir)
	$(INSTALL) $(SUBHEADERS) $(incdir)/$(INCLUDEDIR)
	$(INSTALL) $(ARCHIVE) $(LIBRARY) $(libdir)

uninstall:
	-$(RM) $(addprefix $(incdir)/,$(BASEHEADERS))
	-$(RM) -r $(incdir)/$(INCLUDEDIR)
	-$(RM) $(libdir)/$(ARCHIVE) $(libdir)/$(LIBRARY)

lib: $(ARCHIVE) $(LIBRARY)

distribution: $(distribution)

$(VERSIONHEADER): Makefile
	@echo "generating $@"
	@echo "/* Automatically generated header file, do not edit. */" > $@
	@echo "" >> $@
	@echo "#ifndef CHLORIDE_VERSION_H_" >> $@
	@echo "#define CHLORIDE_VERSION_H_" >> $@
	@echo "" >> $@
	@echo "#define CHLORIDE_VERSION_MAJOR		$(version_major)" >> $@
	@echo "#define CHLORIDE_VERSION_MINOR		$(version_minor)" >> $@
	@echo "#define CHLORIDE_VERSION_REVISION	$(version_revision)" >> $@
	@echo "" >> $@
	@echo "#endif /* CHLORIDE_VERSION_H_ */" >> $@
	@echo "" >> $@

#.NOTPARALLEL:
#$(ARCHIVE)($(OBJECTS)): $(OBJECTS)

$(ARCHIVE): $(OBJECTS)
	$(AR) $(ARFLAGS) -cr $@ $^

$(LIBRARY): $(OBJECTS)
	$(CXX) -shared -o $@ $^

$(CTAGSFILE): $(HEADERS) $(SOURCES)
	$(CTAGS) -f $@ $(TAGSFLAGS) $^

$(ETAGSFILE): $(HEADERS) $(SOURCES)
	$(ETAGS) -f $@ $(TAGSFLAGS) $^

$(distribution): $(distfiles)
	-$(MKDIR) $(mdistdir)
	$(CP) -r $(distfiles) $(mdistdir)
	$(TAR) -czf $(distribution) $(mdistdir)/*
	$(RM) -rf $(mdistdir)

example: example.cpp $(ARCHIVE)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -o $@ $^ -lsodium

ifdef MAKECMDGOALS
ifneq ($(filter-out $(NONDEPGOALS),$(MAKECMDGOALS)),)
-include $(DEPS)
endif
else
-include $(DEPS)
endif

%.o: override CPPFLAGS+=-MMD

$(BUILDDIR)/%.o: override CXXFLAGS+=-fPIC
$(BUILDDIR)/%.o: $(SOURCEDIR)/%.cpp $(VERSIONHEADER)
	$(CXX) -c $(CXXFLAGS) $(CPPFLAGS) -o $@ $<

.PHONY:	all clean depclean realclean distclean install uninstall lib distribution exampleclean

.NOEXPORT:
