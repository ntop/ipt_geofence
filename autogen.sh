#!/bin/sh

#
# (C) 2022-23 - ntop.org

#
/bin/rm -f config.h config.h.in *~ #*
autoreconf -if

./configure
