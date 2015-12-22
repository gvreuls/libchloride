## Makefile
## Created on: Dec 22, 2015
##     Author: gv

CXXFLAGS=-Wall -Wconversion -Wcast-qual -Wextra -Wshadow -Werror -pedantic -pedantic-errors -fmessage-length=0 -fPIC
CPPFLAGS=-std=c++11 -I.
LDFLAGS=
ARFLAGS=
LIBS=
TAGSFLAGS=

ifdef DEBUG
	override CXXFLAGS+=-g
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
SUBHEADERS:=$(wildcard $(INCLUDEDIR)/*.h)
HEADERS:=$(BASEHEADERS) $(SUBHEADERS)
SOURCES:=$(wildcard $(SOURCEDIR)/*.cpp)
OBJECTS:=$(SOURCES:$(SOURCEDIR)/%.cpp=$(BUILDDIR)/%.o)
DEPS:=$(OBJECTS:.o=.d)
AUXFILES=Makefile

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

mdistdir:=$(TARGETNAME)-$(version)
distribution:=$(mdistdir).tar.gz
distfiles:=$(BASEHEADERS) $(INCLUDEDIR) $(SOURCEDIR) $(AUXFILES)

NONDEPGOALS=clean depclean realclean distclean install uninstall dep $(DEPS) $(CTAGSFILE) $(ETAGSFILE)

all: libs

clean:
	-$(RM) $(ARCHIVE) $(LIBRARY) $(OBJECTS)

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

dep: $(DEPS)

libs: $(ARCHIVE) $(LIBRARY)

distribution: $(distribution)

#$(ARCHIVE): $(ARCHIVE)($(OBJECTS))
$(ARCHIVE): $(OBJECTS)
	$(AR) $(ARFLAGS) -cr $@ $^

$(ARCHIVE)($(OBJECTS)): $(OBJECTS)

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

ifdef MAKECMDGOALS
ifneq ($(filter-out $(NONDEPGOALS),$(MAKECMDGOALS)),)
-include $(DEPS)
endif
else
-include $(DEPS)
endif

$(BUILDDIR)/%.o: $(SOURCEDIR)/%.cpp
	$(CXX) -c $(CXXFLAGS) $(CPPFLAGS) -o $@ $<

$(BUILDDIR)/%.d: $(SOURCEDIR)/%.cpp
	$(CXX) $(CPPFLAGS) -MMD -MF $@ -MT $@ -MT $(<:$(SOURCEDIR)/%.cpp=$(BUILDDIR)/%.o) -E $< > $(DEVNULL)

.NOTPARALLEL:

.PHONY:	all clean depclean realclean distclean install uninstall dep libs distribution

.NOEXPORT:
