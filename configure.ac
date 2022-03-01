AC_INIT([ipt_geofence], 1.0)
AC_LANG(C)

AC_PROG_CPP
AC_PROG_CXX

DATE=`date +%y%m%d`
VERSION="1.0.0"
RELEASE=`git log --pretty=oneline | wc -l`
REVISION=`git rev-list --all |wc -l`
GIT_BRANCH=`git branch --no-color|cut -d ' ' -f 2`
GIT_HASH=`git log --pretty=format:"%H (%ad)"|head -1`
DATE=`date -R`
MACHINE=`uname -m`

AC_LANG_CPLUSPLUS

AC_CHECK_HEADERS([libnetfilter_queue/libnetfilter_queue.h], AC_DEFINE_UNQUOTED(HAVE_NETFILTER, 1, [nfq is present]))

if test "x$ac_cv_header_libnetfilter_queue_libnetfilter_queue_h" = xyes; then :
   LIBS="$LIBS -lnetfilter_queue -lnfnetlink"
else
  echo "Please do apt-get install libnetfilter-queue-dev and try again"
  exit 0
fi

dnl> GeoIP
AC_CHECK_LIB([maxminddb], [MMDB_lookup_sockaddr])
AC_HAVE_HEADERS(maxminddb.h)
if ! (test ".${ac_cv_lib_maxminddb_MMDB_lookup_sockaddr}" = ".yes" && test ".${ac_cv_header_maxminddb_h}" = ".yes"); then
  echo "Please do apt-get install libmaxminddb-dev and try again"
  exit 0
fi

AC_CHECK_LIB([jsoncpp], [main])

if ! test ".${ac_cv_lib_jsoncpp_main}" = ".yes"; then
  echo "Please do apt-get install libjsoncpp-dev and try again"
  exit 0
fi

 LIBS="$LIBS -lpthread"

EXTN=
if test $MACHINE = "x86_64"; then
   EXTN="amd64"
else
   if test $MACHINE = "i686"; then 
     EXTN="i386"
   else
     if test $MACHINE = "aarch64"; then
       EXTN="arm64"
     fi
   fi
fi

AC_SUBST(VERSION)
AC_SUBST(RELEASE)
AC_SUBST(REVISION)
AC_SUBST(GIT_BRANCH)
AC_SUBST(GIT_HASH)
AC_SUBST(DATE)
AC_SUBST(EXTN)

AC_CONFIG_HEADERS(config.h)
AC_CONFIG_FILES(Makefile)

AC_OUTPUT
