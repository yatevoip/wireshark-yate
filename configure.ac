 #
# Autoconf script for Wireshark-YATE Plugin
#


AC_INIT(Wireshark-YATE, 6.1.1)
AC_CONFIG_SRCDIR([README])


# Minimum autoconf version we require.
AC_PREREQ(2.52)

if echo "$ac_confdir/$ac_pwd" | grep -q '[[[:space:]\\\$\"'\'']]'; then
    AC_ERROR([Unsupported character(s) in source or current directory name])
fi

# Variable expansion doesn't work in AC_PREREQ()
AC_MIN_VERSION=2.52
AC_SUBST(AC_MIN_VERSION)

# Check if we should look for alternate library names
AC_ARG_WITH(archlib,AC_HELP_STRING([--with-archlib=NAME],[use NAME as library directory name]),[ac_cv_use_archlib=$withval])
AC_MSG_CHECKING([for libraries directory name])
archname=`dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null`
test -z "$archname" && archname=`uname -m 2>/dev/null`
test -z "$archname" && archname=`arch -k 2>/dev/null`
test -z "$archname" && archname=`arch 2>/dev/null`
ARCHLIB=""
case "x$archname" in
    x*-*-*)
	test -d "/usr/lib/$archname" && ARCHLIB="lib/$archname"
	;;
esac
if [[ -z "$ARCHLIB" ]]; then
    case "x$archname" in
	x*x86_64*|xppc64*|xaarch64)
	    ARCHLIB="lib64"
	    ;;
	*)
	    ARCHLIB="lib"
    esac
fi
case "x$ac_cv_use_archlib" in
    x|xyes)
	;;
    xno)
	ARCHLIB="lib"
	;;
    *)
	ARCHLIB="$ac_cv_use_archlib"
esac
test -d "/usr/$ARCHLIB" || ARCHLIB="lib"
AC_MSG_RESULT([$ARCHLIB])
AC_SUBST(ARCHLIB)

#
# Checks for programs used in the main build process.
#

AC_PROG_CC


HAVE_WIRESHARKDEVEL=no
WIRESHARKDEVEL_INC=""
WIRESHARKDEVEL_LIB=""
AC_ARG_WITH(WIRESHARKDEVEL,AC_HELP_STRING([--with-WIRESHARKDEVEL=DIR],[use wireshark-devel library from DIR]),[ac_cv_use_wiresharkdevel=$withval],[ac_cv_use_wiresharkdevel=yes])

if [[ "x$ac_cv_use_wiresharkdevel" != "xno" ]]; then
if [[ "x$ac_cv_use_wiresharkdevel" = "xyes" ]]; then

AC_MSG_CHECKING([for wireshark-devel using pkg-config])

WIRESHARKDEVEL_INC=`(pkg-config --cflags wireshark) 2>/dev/null`

WIRESHARKDEVEL_LIB=`(pkg-config --libs wireshark) 2>/dev/null`

if [[ "x$WIRESHARKDEVEL_INC$WIRESHARKDEVEL_LIB" = "x" ]]; then
WIRESHARKDEVEL_INC=""
WIRESHARKDEVEL_LIB=""
else
HAVE_WIRESHARKDEVEL=yes
fi

else
AC_MSG_CHECKING([for wireshark-devel in $ac_cv_use_wiresharkdevel])
local_lib = "$ARCHLIB"
wiresharkinc = "$ac_cv_use_wiresharkdevel/include/WIRESHARKDEVEL"
test -f "$ac_cv_use_wiresharkdevel/$local_lib/libyimp.so" || local_lib="lib"
if [[ -f "$ac_cv_use_wiresharkdevel/$local_lib/libyimp.so" ]]; then
HAVE_WIRESHARKDEVEL=yes
WIRESHARKDEVEL_LIB="-L$ac_cv_use_wiresharkdevel/$local_lib -lWIRESHARKDEVEL"
WIRESHARKDEVEL_INC="-I$wiresharkinc"
fi
fi
AC_MSG_RESULT([$HAVE_WIRESHARKDEVEL])
fi


# - plugins directory
	AC_ARG_WITH([wireshark-plugin-dir],
		AC_HELP_STRING([--with-wireshark-plugin-dir=DIR],[path to Wireshark plugins dir (/usr/lib64/wireshark)]),
		WIRESHARKDIR="$withval"
		,
		WIRESHARKDIR="/usr/lib64/wireshark"
	)
	AC_MSG_CHECKING([for existence of Wireshark plugins directory $WIRESHARKDIR])
	if test ! -d "$WIRESHARKDIR"; then
		AC_MSG_RESULT([missing])
		AC_MSG_ERROR([Wrong path, $WIRESHARKDIR does not exist.])
	else
		AC_MSG_RESULT([yes])
		AC_SUBST(WIRESHARKDIR)
	fi

AC_SUBST(HAVE_WIRESHARKDEVEL)
AC_SUBST(WIRESHARKDEVEL_INC)
AC_SUBST(WIRESHARKDEVEL_LIB)


HAVE_GLIBDEVEL=no
GLIBDEVEL_INC=""
GLIBDEVEL_LIB=""

AC_ARG_WITH(glibdevel,AC_HELP_STRING([--with-glibdevel=DIR],[use GLib library from DIR]), [ac_cv_use_glibdevel=$whitval],[ac_cv_use_glibdevel=yes])

if [[ "x$ac_cv_use_glibdevel" != "xno" ]]; then
if [[ "x$ac_cv_use_glibdevel" = "xyes" ]]; then

AC_MSG_CHECKING([for GLib-devel using pkg-config])
GLIBDEVEL_INC=`(pkg-config --cflags glib-2.0) 2>/dev/null`
GLIBDEVEL_LIB=`(pkg-config --libs glib-2.0) 2>/dev/null`
if [[ "x$GLIBDEVEL_INC$GLIBDEVEL_LIB" = "x" ]]; then
GLIBDEVEL_INC=""
GLIBDEVEL_LIB=""
else
HAVE_GLIBDEVEL=yes
fi
fi
AC_MSG_RESULT([$HAVE_GLIBDEVEL])
fi
AC_SUBST(HAVE_GLIBDEVEL)
AC_SUBST(GLIBDEVEL_INC)
AC_SUBST(GLIBDEVEL_LIB)

AC_CONFIG_FILES([ packaging/rpm/SPECS/yimp.spec
Makefile
])
AC_SUBST(CONFIGURE_FILES)
AC_OUTPUT


echo ""
echo "The Wireshark - Yate package has been configured."
