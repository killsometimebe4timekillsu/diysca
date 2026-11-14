#!/bin/sh
set -e
if command -v systemd-sysusers >/dev/null 2>&1; then
  systemd-sysusers /usr/lib/sysusers.d/diysca.conf || true
fi
if ! getent passwd diysca >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/diysca --shell /usr/sbin/nologin diysca 2>/dev/null || \
  adduser -S -h /var/lib/diysca -s /sbin/nologin diysca 2>/dev/null || true
fi
install -d -m 0750 -o diysca -g diysca /var/lib/diysca 2>/dev/null || true
install -d -m 0700 -o diysca -g diysca /var/lib/diysca/.ssh 2>/dev/null || true
chgrp diysca /etc/diysca/config.yml 2>/dev/null && chmod 0640 /etc/diysca/config.yml || true
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
  echo "diysca installed. Edit /etc/diysca/config.yml, put the SSH key in /var/lib/diysca/.ssh/, then:"
  echo "  systemctl enable --now diysca"
fi
