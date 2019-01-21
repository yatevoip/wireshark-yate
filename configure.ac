 #
# Autoconf script for Wireshark-YATE Plugin
#

PACKAGE_RELEASE="1"
AC_SUBST(PACKAGE_RELEASE)

AC_INIT(Wireshark-YATE, 6.1.1)
AC_CONFIG_SRCDIR([README])

PACKAGE_RELEASE="1"
AC_SUBST(PACKAGE_RELEASE)
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
 AC_ARG_WITH(wiresharkdevel,AC_HELP_STRING([--with-wiresharkdevel=DIR],[use Wireshark library from DIR]), [ac_cv_use_wiresharkdevel=$withval],[ac_cv_use_wiresharkdevel=yes])
 
if [[ "x$ac_cv_use_wiresharkdevel" = "xyes" ]]; then

AC_MSG_CHECKING([for wireshark-devel using pkg-config])

WIRESHARKDEVEL_INC=`(pkg-config --cflags wireshark) 2>/dev/null`

WIRESHARKDEVEL_LIB=`(pkg-config --libs wireshark) 2>/dev/null`

if [[ -z "$WIRESHARKDEVEL_INC" -o -z "$WIRESHARKDEVEL_LIB" ]]; then
WIRESHARKDEVEL_INC=""
WIRESHARKDEVEL_LIB=""
else
HAVE_WIRESHARKDEVEL=yes
fi
AC_MSG_RESULT([$HAVE_WIRESHARKDEVEL])
fi
if [[ "x$ac_cv_use_wiresharkdevel" != "xno" ]]; then
if [[ "x$ac_cv_use_wiresharkdevel" == "xyes" ]]; then
ac_cv_use_wiresharkdevel=/usr
fi
AC_MSG_CHECKING([for wireshark-devel in $ac_cv_use_wiresharkdevel])
local_lib="$ARCHLIB"
wiresharkinc="$ac_cv_use_wiresharkdevel/include/wireshark"
test -f "$ac_cv_use_wiresharkdevel/$local_lib/libwireshark.so" || local_lib="lib"
if [[ -f "$wiresharkinc/config.h" -a -f "$ac_cv_use_wiresharkdevel/$local_lib/libwireshark.so" ]]; then
HAVE_WIRESHARKDEVEL=yes
WIRESHARKDEVEL_LIB="-L$ac_cv_use_wiresharkdevel/$local_lib -lwireshark"
WIRESHARKDEVEL_INC="-I$wiresharkinc"
fi
AC_MSG_RESULT([$HAVE_WIRESHARKDEVEL])
fi

if [[ "X$HAVE_WIRESHARKDEVEL" != "Xyes" ]]; then
AC_MSG_ERROR([wireshark-devel is required])
fi

AC_SUBST(HAVE_WIRESHARKDEVEL)
AC_SUBST(WIRESHARKDEVEL_INC)
AC_SUBST(WIRESHARKDEVEL_LIB)



# - plugins directory

HAVE_WIRESHARKPLUGINDIR=no
WIRESHARKPLUGINDIR=""
AC_ARG_WITH(wireshark-plugin-dir, AC_HELP_STRING([--with-wireshark-plugin-dir=DIR],[path to Wireshark plugins dir]),[ac_cv_use_wiresharkdir="$withval"],[ac_cv_use_wiresharkdir=yes])
		
if [[ "x$ac_cv_use_wiresharkdir" = "xyes" ]]; then

AC_MSG_CHECKING([for existence of Wireshark plugins directory using pkg-config])

WIRESHARKPLUGINDIR=`(pkg-config --variable=plugindir wireshark) 2>/dev/null`

if [[ -z "$WIRESHARKPLUGINDIR" ]]; then
WIRESHARKPLUGINDIR=""
else
HAVE_WIRESHARKPLUGINDIR=yes
fi
AC_MSG_RESULT([$HAVE_WIRESHARKPLUGINDIR])
fi
if [[ "x$ac_cv_use_wiresharkdir" = "xyes" ]]; then
ac_cv_use_wiresharkdir=/usr
fi
local_lib="$ARCHLIB"
plugindir="$ac_cv_use_wiresharkdir/$local_lib/wireshark"
AC_MSG_CHECKING([for existence of Wireshark plugin directory in $plugindir])
test -f "$ac_cv_use_wiresharkdir/$local_lib/wireshark" || local_lib="lib"
if [[ -d "$plugindir" ]]; then
HAVE_WIRESHARKPLUGINDIR=yes
WIRESHARKPLUGINDIR="$plugindir"
fi
AC_MSG_RESULT([$HAVE_WIRESHARKPLUGINDIR])

if [[ "x$HAVE_WIRESHARKPLUGINDIR" != "xyes" ]]; then
AC_MSG_ERROR([Could not find Wireshark plugin directory])
fi

AC_SUBST(HAVE_WIRESHARKPLUGINDIR)
AC_SUBST(WIRESHARKPLUGINDIR)

	
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

AC_CONFIG_FILES([yimp.spec
Makefile
])
CONFIGURE_FILES=`echo "$ac_config_files config.status config.log" | sed 's/^.*\.spec *//'`
AC_SUBST(CONFIGURE_FILES)
AC_OUTPUT


echo ""
echo "The Wireshark - Yate package has been configured."
