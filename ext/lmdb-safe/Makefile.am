EXTRA_DIST = \
        LICENSE

EXTRA_PROGRAMS = \
        lmdb-safe-testrunner

lmdb_safe_testrunner_SOURCES = \
        lmdb-safe.hh \
        test-lmdb-safe.cc

lmdb_safe_testrunner_LDFLAGS = \
        $(AM_LDFLAGS) \
        $(BOOST_UNIT_TEST_FRAMEWORK_LDFLAGS)

lmdb_safe_testrunner_LDADD = \
        $(BOOST_UNIT_TEST_FRAMEWORK_LIBS)

if UNIT_TESTS
noinst_PROGRAMS = lmdb-safe-testrunner
TESTS_ENVIRONMENT = env BOOST_TEST_LOG_LEVEL=message BOOST_TEST_RANDOM=1 SRCDIR='$(srcdir)'
TESTS=lmdb-safe-testrunner
else
check-local:
        @echo "Unit tests are not enabled"
        @echo "Run ./configure --enable-unit-tests"
endif
