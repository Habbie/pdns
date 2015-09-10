dnl FIXME use odbc_config --prefix etc.

AC_DEFUN([PDNS_WITH_UNIXODBC],[
	AC_ARG_WITH(unixodbc,
	    AC_HELP_STRING([--with-unixodbc=<path>],[root directory path of unixodbc installation]),
	    [UNIXODBC_lib_check="$withval/lib/unixodbc $with_unixodbc/lib $withval/lib"
	     UNIXODBC_inc_check="$withval/include/unixodbc $withval/include"],
	    [UNIXODBC_lib_check="/usr/local/unixodbc/lib/unixodbc /usr/local/lib/unixodbc /usr/lib/unixodbc /usr/local/unixodbc/lib /usr/local/lib /opt/unixodbc/lib /usr/lib /usr/lib/x86_64-linux-gnu /usr/lib64"
	     UNIXODBC_inc_check="/usr/local/unixodbc/include/unixodbc /usr/local/include/unixodbc/ /usr/local/include /opt/unixodbc/include/unixodbc /opt/unixodbc/include /usr/include/ /usr/include/unixodbc"])
	AC_ARG_WITH(unixodbc-lib,
	    AC_HELP_STRING([--with-unixodbc-lib=<path>],[directory path of unixodbc library installation]),
	    [UNIXODBC_lib_check="$withval/lib/unixodbc $withval/unixodbc $withval"])
	AC_ARG_WITH(unixodbc-includes,
	    AC_HELP_STRING([--with-unixodbc-includes=<path>],[directory path of unixodbc header installation]),
	    [UNIXODBC_inc_check="$withval/include $withval/include/unixodbc $withval/unixodbc $withval"])
	AC_MSG_CHECKING([for unixodbc library directory])
	UNIXODBC_libdir=
	for m in $UNIXODBC_lib_check; do
	        if test -d "$m" && \
	           (test -f "$m/libodbc.so" || test -f "$m/libodbc.dylib" || test -f "$m/libodbc.a")
	        then
	                UNIXODBC_libdir=$m
	                break
	        fi
	done
	        if test -z "$UNIXODBC_libdir"; then
	        AC_MSG_ERROR([Didn't find the unixodbc library dir in '$UNIXODBC_lib_check'])
	fi
	case "$UNIXODBC_libdir" in
	   /usr/lib ) UNIXODBC_lib="" ;;
	  /* ) UNIXODBC_lib="-L$UNIXODBC_libdir -Wl,-rpath,$UNIXODBC_libdir"
	       LDFLAGS="$UNIXODBC_lib $LDFLAGS"
	       ;;
	  * )  AC_MSG_ERROR([The unixodbc library directory ($UNIXODBC_libdir) must be an absolute path.]) ;;
	esac

	AC_SUBST(UNIXODBC_lib)
	AC_MSG_RESULT([$UNIXODBC_libdir])
	AC_MSG_CHECKING([for unixodbc include directory])
	UNIXODBC_incdir=
	for m in $UNIXODBC_inc_check; do
	        if test -d "$m" && test -f "$m/sql.h"
	        then
	                UNIXODBC_incdir=$m
	                break
	        fi
	done
	        if test -z "$UNIXODBC_incdir"; then
	        AC_MSG_ERROR([Didn't find the unixodbc include dir in '$UNIXODBC_inc_check'])
	fi
	case "$UNIXODBC_incdir" in
	  /* ) ;;
	  * )  AC_MSG_ERROR([The unixodbc include directory ($UNIXODBC_incdir) must be an absolute path.]) ;;
	esac
	AC_SUBST(UNIXODBC_incdir)
	AC_MSG_RESULT([$UNIXODBC_incdir])

	#       LIBS="$LIBS -lunixodbc"
])