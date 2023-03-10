#
# Autoconf script for Wireshark-YATE Plugin
#

AC_INIT(Wireshark-YATE, 0.0.1)
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
WIRESHARK_VERS_MAJOR=""
WIRESHARK_VERS_MINOR=""
WIRESHARK_PLUGIN_DIR=""

AC_ARG_WITH(wiresharkdevel,AC_HELP_STRING([--with-wiresharkdevel=DIR],[use Wireshark library from DIR]), [ac_cv_use_wiresharkdevel=$withval],[ac_cv_use_wiresharkdevel=yes])
if [[ "x$ac_cv_use_wiresharkdevel" = "xno" ]]; then
    AC_MSG_ERROR([Wireshark support is required])
fi
if [[ "x$ac_cv_use_wiresharkdevel" = "xyes" ]]; then
    AC_MSG_CHECKING([for wireshark-devel using pkg-config])
    WIRESHARKDEVEL_INC=`(pkg-config --cflags wireshark) 2>/dev/null`
    WIRESHARKDEVEL_LIB=`(pkg-config --libs wireshark) 2>/dev/null`
    version=`(pkg-config --modversion wireshark) 2>/dev/null`
    if [[ -z "$WIRESHARKDEVEL_INC" -o -z "$WIRESHARKDEVEL_LIB" ]]; then
	WIRESHARKDEVEL_INC=""
	WIRESHARKDEVEL_LIB=""
	ac_cv_use_wiresharkdevel="/usr"
    else
	HAVE_WIRESHARKDEVEL=yes
	ac_cv_use_wiresharkdevel=""
	WIRESHARK_VERS_MAJOR=`echo $version | sed -E s/\\([[0-9]]+\\)\.\\([[0-9]]+\\)\..*\/\\\1/g 2>/dev/null`
	WIRESHARK_VERS_MINOR=`echo $version | sed -E s/\\([[0-9]]+\\)\.\\([[0-9]]+\\)\..*\/\\\2/g 2>/dev/null`
	WIRESHARK_PLUGIN_DIR=`pkg-config --variable=plugindir wireshark 2>/dev/null`
	WIRESHARK_PLUGIN_DIR="$WIRESHARK_PLUGIN_DIR"
    fi
#    AC_MSG_RESULT([$HAVE_WIRESHARKDEVEL])
fi

if [[ "x$ac_cv_use_wiresharkdevel" != "x" ]]; then
    AC_MSG_CHECKING([for wireshark-devel in $ac_cv_use_wiresharkdevel])
    wiresharklib="$ac_cv_use_wiresharkdevel/$ARCHLIB"
    wiresharkinc="$ac_cv_use_wiresharkdevel/include/wireshark"
    if [[ -f "$wiresharkinc/config.h" -a -f "$wiresharklib/libwireshark.so" ]]; then
	HAVE_WIRESHARKDEVEL=yes
	WIRESHARKDEVEL_LIB="-L$wiresharklib -lwireshark"
	WIRESHARKDEVEL_INC="-I$wiresharkinc"
	WIRESHARK_VERS_MAJOR=`cat $wiresharkinc/config.h 2>/dev/null | grep "#define VERSION_MAJOR " | sed 's/#define VERSION_MAJOR //g' | sed 's/[[:space:]]\+//g' 2>/dev/null`
	WIRESHARK_VERS_MINOR=`cat $wiresharkinc/config.h 2>/dev/null | grep "#define VERSION_MINOR " | sed 's/#define VERSION_MINOR //g' | sed 's/[[:space:]]\+//g' 2>/dev/null`
	WIRESHARK_PLUGIN_DIR="$wiresharklib/wireshark/plugins/$WIRESHARK_VERS_MAJOR.$WIRESHARK_VERS_MINOR"
    fi
#    AC_MSG_RESULT([$HAVE_WIRESHARKDEVEL])
fi

#AC_MSG_NOTICE([vers major $WIRESHARK_VERS_MAJOR])
#AC_MSG_NOTICE([vers minor $WIRESHARK_VERS_MINOR])
if [[ "x$HAVE_WIRESHARKDEVEL" != "xyes" ]]; then
    AC_MSG_ERROR([wireshark-devel is required])
else
    if [[ $WIRESHARK_VERS_MAJOR -lt 3 ]]; then
	AC_MSG_ERROR([wireshark-devel version 3.0 at least is required])
    fi
    AC_MSG_RESULT([wireshark $WIRESHARK_VERS_MAJOR.$WIRESHARK_VERS_MINOR])
fi

AC_SUBST(HAVE_WIRESHARKDEVEL)
AC_SUBST(WIRESHARKDEVEL_INC)
AC_SUBST(WIRESHARKDEVEL_LIB)
AC_SUBST(WIRESHARK_VERS_MAJOR)
AC_SUBST(WIRESHARK_VERS_MINOR)


# checking existence of plugins directory
#AC_MSG_NOTICE([plugindir $WIRESHARK_PLUGIN_DIR])
extra_msg="autodetected"
AC_ARG_WITH(wireshark-plugin-dir, AC_HELP_STRING([--with-wireshark-plugin-dir=DIR],[path to Wireshark plugins directory]),[ac_cv_use_wiresharkpdir="$withval"],[ac_cv_use_wiresharkpdir=yes])
if [[ "x$ac_cv_use_wiresharkpdir" = "xno" ]]; then
    if [[ "x$WIRESHARK_PLUGIN_DIR" = "x" ]]; then
	AC_MSG_ERROR([Missing wireshark plugin directory])
    fi
fi
if [[ "x$ac_cv_use_wiresharkpdir" != "xyes" ]]; then
    AC_MSG_CHECKING([for existence of wireshark plugins directory $ac_cv_use_wiresharkpdir])
    if [[ "x$ac_cv_use_wiresharkpdir" != "x" ]]; then
	WIRESHARK_PLUGIN_DIR="$ac_cv_use_wiresharkpdir"
    else
	extra_msg=""
    fi
fi
AC_MSG_CHECKING([for existence of Wireshark $extra_msg plugin directory])
if [[ "x$WIRESHARK_PLUGIN_DIR" = "x" ]]; then
    AC_MSG_ERROR([Missing wireshark plugin directory])
fi
if [[ -d "$WIRESHARK_PLUGIN_DIR/epan" ]]; then
    WIRESHARK_PLUGIN_DIR="$WIRESHARK_PLUGIN_DIR/epan"
    AC_MSG_RESULT([$WIRESHARK_PLUGIN_DIR])
elif [[ -d "$WIRESHARK_PLUGIN_DIR/plugins/$WIRESHARK_VERS_MAJOR.$WIRESHARK_VERS_MINOR/epan" ]]; then
    WIRESHARK_PLUGIN_DIR="$WIRESHARK_PLUGIN_DIR/plugins/$WIRESHARK_VERS_MAJOR.$WIRESHARK_VERS_MINOR/epan"
    AC_MSG_RESULT([$WIRESHARK_PLUGIN_DIR])
else
    AC_MSG_ERROR([Missing wireshark plugin directory $WIRESHARK_PLUGIN_DIR])
fi
AC_SUBST(WIRESHARK_PLUGIN_DIR)

# wireshark 3 devel does not include "config.h", generate it for what we need
AC_MSG_CHECKING([for Wireshark config.h])

SAVE_CFLAGS="$CFLAGS"
CFLAGS="$WIRESHARKDEVEL_INC"
have_config="no"
`rm -f config.h 2>/dev/null`
AC_TRY_COMPILE([
#include "config.h"
],[
],have_config="yes")
if [[ "x$have_config" = "xno" ]]; then
    `echo "/* Version number of package */
#define VERSION_MAJOR $WIRESHARK_VERS_MAJOR
#define VERSION_MINOR $WIRESHARK_VERS_MINOR
" > config.h 2>/dev/null`
have_config="self-generated"
fi
CFLAGS="$SAVE_CFLAGS"
AC_MSG_RESULT([$have_config])


# check for GLIB-2.0 in case wireshark was not detected with pkg-config
HAVE_GLIBDEVEL=no
GLIBDEVEL_INC=""
GLIBDEVEL_LIB=""
AC_ARG_WITH(glibdevel,AC_HELP_STRING([--with-glibdevel=DIR],[use GLib library from DIR]), [ac_cv_use_glibdevel=$whitval],[ac_cv_use_glibdevel=yes])
if [[ "x$ac_cv_use_glibdevel" = "xno" ]]; then
    AC_MSG_ERROR([GLIB-2.0 support is mandatory])
fi
if [[ "x$ac_cv_use_glibdevel" = "xyes" ]]; then
    AC_MSG_CHECKING([for GLib-2.0-devel using pkg-config])
    GLIBDEVEL_INC=`(pkg-config --cflags glib-2.0) 2>/dev/null`
    GLIBDEVEL_LIB=`(pkg-config --libs glib-2.0) 2>/dev/null`
    if [[ "x$GLIBDEVEL_INC$GLIBDEVEL_LIB" = "x" ]]; then
	GLIBDEVEL_INC=""
	GLIBDEVEL_LIB=""
    else
	HAVE_GLIBDEVEL=yes
    fi
    AC_MSG_RESULT([$HAVE_GLIBDEVEL])
fi
AC_SUBST(HAVE_GLIBDEVEL)
AC_SUBST(GLIBDEVEL_INC)
AC_SUBST(GLIBDEVEL_LIB)



# check for YATE (we need a header file)
# Check for Yate (required)
YATE_INC_H=""
YATE_HEADER=""
HAVE_YATE="no"
yc="yate-config"
AC_ARG_WITH(yate,AS_HELP_STRING([--with-yate=DIR],[use Yate from DIR]),[ac_cv_use_yate=$withval],[ac_cv_use_yate=yes])
if [[ "x$ac_cv_use_yate" = "xno" ]]; then
    AC_MSG_ERROR([Yate header is required])
fi
if [[ "x$ac_cv_use_yate" != "xyes" ]]; then
    dir=`cd "$ac_cv_use_yate"; pwd`
    YATE_INC_H="-I$dir"
    YATE_HEADER="$dir/yatewiresniff.h"
else
    YATE_INC_H=`"$yc" --includes 2>/dev/null`
    YATE_HEADER=`echo $YATE_INC_H | sed 's/-I//g' 2>/dev/null`
    YATE_HEADER="$YATE_HEADER/yatewiresniff.h"
fi
AC_MSG_CHECKING([for Yate includes path])
if [[ "x$YATE_INC_H" = "x" ]]; then
    AC_MSG_ERROR([Yate header include path is required])
fi
if [[ ! -f "$YATE_HEADER" ]]; then
    AC_MSG_ERROR([Missing YATE header $YATE_HEADER])
fi
YATE_VERSION=`"$yc" --version 2>/dev/null`
AC_MSG_RESULT([$YATE_INC_H])
AC_SUBST(YATE_INC_H)
AC_SUBST(YATE_HEADER)
AC_SUBST(YATE_VERSION)


AC_CONFIG_FILES([yimp.spec
                 Makefile
])
CONFIGURE_FILES=`echo "$ac_config_files config.status config.log" | sed 's/^.*\.spec *//'`
AC_SUBST(CONFIGURE_FILES)
AC_OUTPUT

echo ""
echo "The Wireshark - Yate package has been configured."
