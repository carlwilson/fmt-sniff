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
  ls=`ls -ld "$PRG"`
  link=`expr "$ls" : '.*-> \(.*\)$'`
  if expr "$link" : '/.*' > /dev/null; then
    PRG="$link"
  else
    PRG=`dirname "$PRG"`/"$link"
  fi
done

PRGDIR=`dirname "$PRG"`
BASEDIR=`cd "$PRGDIR/" >/dev/null; pwd`
PYTHONCMD='python'

exec "$PYTHONCMD"  \
  "$BASEDIR"/fido/fido.py \
  "$@"
