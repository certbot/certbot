#!/bin/sh

PACKAGES="
  app-admin/augeas
  app-misc/ca-certificates
  dev-lang/python:2.7
  dev-libs/libffi
  dev-python/virtualenv
  sys-apps/dialog
  virtual/libssl
  virtual/pkg-config
"

cave resolve --keep-targets if-possible $PACKAGES -x
