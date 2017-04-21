#!/bin/sh
#
# This file is part of veraPDF Installer, a module of the veraPDF project.
# Copyright (c) 2015, veraPDF Consortium <info@verapdf.org>
# All rights reserved.
#
# veraPDF Installer is free software: you can redistribute it and/or modify
# it under the terms of either:
#
# The GNU General public license GPLv3+.
# You should have received a copy of the GNU General Public License
# along with veraPDF Installer as the LICENSE.GPL file in the root of the source
# tree.  If not, see http://www.gnu.org/licenses/ or
# https://www.gnu.org/licenses/gpl-3.0.en.html.
#
# The Mozilla Public License MPLv2+.
# You should have received a copy of the Mozilla Public License along with
# veraPDF Installer as the LICENSE.MPL file in the root of the source tree.
# If a copy of the MPL was not distributed with this file, you can obtain one at
# http://mozilla.org/MPL/2.0/.
#

# resolve links - $0 may be a softlink
PRG="$0"

while [ -h "$PRG" ]; do
  ls=$(ls -ld "$PRG")
  link=$(expr "$ls" : '.*-> \(.*\)$')
  if expr "$link" : '/.*' > /dev/null; then
    PRG="$link"
  else
    PRG=$(dirname "$PRG")/"$link"
  fi
done

PRGDIR=$(dirname "$PRG")
BASEDIR=$(cd "$PRGDIR/" >/dev/null; pwd)

# Reset the REPO variable. If you need to influence this use the environment setup file.
REPO=


# OS specific support.  $var _must_ be set to either true or false.
cygwin=false;
darwin=false;
case "$(uname)" in
  CYGWIN*) cygwin=true ;;
  Darwin*) darwin=true
           if [ -z "$JAVA_VERSION" ] ; then
             JAVA_VERSION="CurrentJDK"
           else
             echo "Using Java version: $JAVA_VERSION"
           fi
		   if [ -z "$JAVA_HOME" ]; then
		      if [ -x "/usr/libexec/java_home" ]; then
			      JAVA_HOME=$(/usr/libexec/java_home)
			  else
			      JAVA_HOME=/System/Library/Frameworks/JavaVM.framework/Versions/${JAVA_VERSION}/Home
			  fi
           fi
           ;;
esac

if [ -z "$JAVA_HOME" ] ; then
  if [ -r /etc/gentoo-release ] ; then
    JAVA_HOME=$(java-config --jre-home)
  fi
fi

# For Cygwin, ensure paths are in UNIX format before anything is touched
if $cygwin ; then
  [ -n "$JAVA_HOME" ] && JAVA_HOME=$(cygpath --unix "$JAVA_HOME")
  [ -n "$CLASSPATH" ] && CLASSPATH=$(cygpath --path --unix "$CLASSPATH")
fi

# If a specific java binary isn't specified search for the standard 'java' binary
if [ -z "$JAVACMD" ] ; then
  if [ -n "$JAVA_HOME"  ] ; then
    if [ -x "$JAVA_HOME/jre/sh/java" ] ; then
      # IBM's JDK on AIX uses strange locations for the executables
      JAVACMD="$JAVA_HOME/jre/sh/java"
    else
      JAVACMD="$JAVA_HOME/bin/java"
    fi
  else
    JAVACMD=$(which java)
  fi
fi

if [ ! -x "$JAVACMD" ] ; then
  echo "Error: JAVA_HOME is not defined correctly." 1>&2
  echo "  We cannot execute $JAVACMD" 1>&2
  exit 1
fi

if [ -z "$REPO" ]
then
  REPO="$BASEDIR"/bin
fi

CLASSPATH="$BASEDIR"/etc:"$REPO"/*

ENDORSED_DIR=
if [ -n "$ENDORSED_DIR" ] ; then
  CLASSPATH="$BASEDIR"/"$ENDORSED_DIR"/*:"$CLASSPATH"
fi

if [ -n "$CLASSPATH_PREFIX" ] ; then
  CLASSPATH=$CLASSPATH_PREFIX:$CLASSPATH
fi

# For Cygwin, switch paths to Windows format before running java
if $cygwin; then
  [ -n "$CLASSPATH" ] && CLASSPATH=$(cygpath --path --windows "$CLASSPATH")
  [ -n "$JAVA_HOME" ] && JAVA_HOME=$(cygpath --path --windows "$JAVA_HOME")
  [ -n "$HOME" ] && HOME=$(cygpath --path --windows "$HOME")
  [ -n "$BASEDIR" ] && BASEDIR=$(cygpath --path --windows "$BASEDIR")
  [ -n "$REPO" ] && REPO=$(cygpath --path --windows "$REPO")
fi

exec "$JAVACMD" $JAVA_OPTS  \
  -Dfile.encoding="UTF8" \
  -Dapp.name="Apache Tika" \
  -Dapp.pid="$$" \
  -Dapp.repo="$REPO" \
  -Dapp.home="$BASEDIR" \
  -Dbasedir="$BASEDIR" \
  -jar "$BASEDIR"/tika-app-1.14.jar \
  "$@"
