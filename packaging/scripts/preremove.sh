#!/bin/sh
set -e
# deb: "remove"/"upgrade"; rpm: $1 = 0 on erase, 1 on upgrade
case "${1:-}" in
  remove|0)
    if [ -d /run/systemd/system ]; then systemctl disable --now diysca.service >/dev/null 2>&1 || true; fi ;;
esac
