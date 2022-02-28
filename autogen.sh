#!/bin/bash

#
# (C) 2022 - ntop.org

#
/bin/rm -f config.h config.h.in *~ #*
autoreconf -if

./configure
