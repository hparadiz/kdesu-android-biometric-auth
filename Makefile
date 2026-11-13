# Desktop components of Navi Authenticator (the Android app is built with ./build.sh).
#
#   make
#   make install DESTDIR=/ [ENABLE_SUDO=yes]
#
# ENABLE_SUDO=yes additionally installs the optional sudo approval helper. It stays inactive
# until an administrator adds the pam_exec line printed at the end of `make install` to
# /etc/pam.d/sudo. Nothing here edits PAM configuration.

PREFIX        ?= /usr
LIBEXECDIR    ?= $(PREFIX)/libexec/navi-auth
POLKITDIR     ?= $(PREFIX)/share/polkit-1/actions
POLKIT_SRC    ?= packaging/polkit
CC            ?= cc
CFLAGS        ?= -O2
INSTALL       ?= install

ENABLE_SUDO    ?= no
SUDO_TERMINALS ?= /usr/bin/konsole /usr/bin/kitty
SUDO_TIMEOUT   ?= 60

PYTHON_FILES = rootauth.py host.py configure-authority.py kdeconnect_transport.py ntfy_transport.py

ifeq ($(filter $(ENABLE_SUDO),yes no),)
$(error ENABLE_SUDO must be yes or no)
endif

all: authorize

authorize: authorize.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -fPIE -pie -Wl,-z,relro,-z,now -o $@ $<

install: authorize
	$(INSTALL) -d -m 0755 $(DESTDIR)$(LIBEXECDIR) $(DESTDIR)$(POLKITDIR)
	$(INSTALL) -m 0755 $(PYTHON_FILES) $(DESTDIR)$(LIBEXECDIR)/
	$(INSTALL) -m 4755 authorize $(DESTDIR)$(LIBEXECDIR)/authorize
	# polkit entry point for "Administrator prompts" in System Settings.
	$(INSTALL) -m 0755 $(POLKIT_SRC)/navi-auth-configure $(DESTDIR)$(LIBEXECDIR)/configure
	$(INSTALL) -m 0644 $(POLKIT_SRC)/in.akuj.navi-auth.policy $(DESTDIR)$(POLKITDIR)/
ifeq ($(ENABLE_SUDO),yes)
	$(INSTALL) -m 0755 sudo_approve.py sudo_pam.py $(DESTDIR)$(LIBEXECDIR)/
	# pkexec entry point for the "Approve sudo from the phone" switch in System Settings.
	printf '%s\n' '#!/bin/sh' \
	    '# Turns phone approval for sudo on/off in /etc/pam.d/sudo (System Settings runs this via pkexec).' \
	    'exec /usr/bin/python3 -I $(LIBEXECDIR)/sudo_pam.py "$$@"' \
	    > $(DESTDIR)$(LIBEXECDIR)/sudo-pam
	chmod 0755 $(DESTDIR)$(LIBEXECDIR)/sudo-pam
	$(INSTALL) -m 0644 $(POLKIT_SRC)/in.akuj.navi-auth.sudo.policy $(DESTDIR)$(POLKITDIR)/
	printf '%s\n' '#!/bin/sh' \
	    '# Optional sudo approval: run by pam_exec from /etc/pam.d/sudo (see INSTALL).' \
	    'exec /usr/bin/python3 -I $(LIBEXECDIR)/sudo_approve.py $(foreach t,$(SUDO_TERMINALS),--terminal $(t)) --timeout $(SUDO_TIMEOUT)' \
	    > $(DESTDIR)$(LIBEXECDIR)/sudo-approve
	chmod 0755 $(DESTDIR)$(LIBEXECDIR)/sudo-approve
	@echo
	@echo "Sudo approval is installed but not active. Turn it on in System Settings ->"
	@echo "Navi Authenticator (asks for the administrator password), or as root run:"
	@echo
	@echo "    $(LIBEXECDIR)/sudo-pam enable"
	@echo
	@echo "which adds this line to /etc/pam.d/sudo above the system-auth rules:"
	@echo "    auth  sufficient  pam_exec.so quiet stdout seteuid $(LIBEXECDIR)/sudo-approve"
	@echo
endif

clean:
	rm -f authorize

.PHONY: all install clean
