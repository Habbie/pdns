pkglib_LTLIBRARIES = libldapbackend.la

EXTRA_DIST = OBJECTFILES OBJECTLIBS

libldapbackend_la_SOURCES = \
	ldapbackend.cc ldapbackend.hh \
	powerldap.cc powerldap.hh \
	ldaputils.cc ldaputils.hh \
	ldapauthenticator.cc ldapauthenticator_p.hh ldapauthenticator.hh \
	utils.hh exceptions.hh

libldapbackend_la_LDFLAGS = -module -avoid-version
libldapbackend_la_LIBADD = $(LDAP_LIBS) -lkrb5
