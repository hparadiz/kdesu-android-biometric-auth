# Desktop components of Navi Authenticator (the Android app is built with ./build.sh).
#
#   make
#   make install DESTDIR=/ [ENABLE_SUDO=yes] [ENABLE_LOGIN=yes] [MAX_COMMAND=10240]
#   make dictionary   (developers: builds a new committed compression dictionary; never run by install)
#
# MAX_COMMAND is the longest command (in characters) offered for phone approval, 512-16384.
# Navi must be built with at least the same limit (NAVI_MAX_COMMAND for ./build.sh).
#
# Optional phone approvals, each off unless requested:
#   ENABLE_SUDO=yes   sudo in local Konsole/Kitty terminals
#   ENABLE_LOGIN=yes  the SDDM login screen and the Plasma lock screen
# Installing them changes no PAM configuration: each is switched on later in System Settings
# (administrator password) or with `navi-pam enable sudo|sddm|kde` as root.

PREFIX        ?= /usr
LIBEXECDIR    ?= $(PREFIX)/libexec/navi-auth
POLKITDIR     ?= $(PREFIX)/share/polkit-1/actions
POLKIT_SRC    ?= packaging/polkit
CC            ?= cc
CFLAGS        ?= -O2
INSTALL       ?= install

ENABLE_SUDO    ?= no
ENABLE_LOGIN   ?= no
SUDO_TERMINALS ?= /usr/bin/konsole /usr/bin/kitty
SUDO_TIMEOUT   ?= 60
MAX_COMMAND    ?= 10240
PYTHON         ?= /usr/bin/python3

PYTHON_FILES = rootauth.py host.py configure-authority.py kdeconnect_transport.py ntfy_transport.py

ifeq ($(filter $(ENABLE_SUDO),yes no),)
$(error ENABLE_SUDO must be yes or no)
endif
ifeq ($(filter $(ENABLE_LOGIN),yes no),)
$(error ENABLE_LOGIN must be yes or no)
endif
ifeq ($(shell printf '%s' '$(MAX_COMMAND)' | grep -Ex '[0-9]{3,5}'),)
$(error MAX_COMMAND must be a number from 512 to 16384)
endif
ifneq ($(shell [ $(MAX_COMMAND) -ge 512 ] && [ $(MAX_COMMAND) -le 16384 ] && echo ok),ok)
$(error MAX_COMMAND must be a number from 512 to 16384)
endif
PAM_APPROVAL := $(if $(filter yes,$(ENABLE_SUDO) $(ENABLE_LOGIN)),yes,no)

all: authorize

authorize: authorize.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -fPIE -pie -Wl,-z,relro,-z,now -o $@ $<

install: authorize
	$(INSTALL) -d -m 0755 $(DESTDIR)$(LIBEXECDIR) $(DESTDIR)$(POLKITDIR)
	$(INSTALL) -m 0755 $(PYTHON_FILES) $(DESTDIR)$(LIBEXECDIR)/
	# The configured command limit, set in exactly one line of the installed host.py.
	sed -i 's/^MAX_COMMAND = [0-9]*  # set by make install/MAX_COMMAND = $(MAX_COMMAND)  # set by make install/' $(DESTDIR)$(LIBEXECDIR)/host.py
	grep -qx 'MAX_COMMAND = $(MAX_COMMAND)  # set by make install.*' $(DESTDIR)$(LIBEXECDIR)/host.py
	# Committed DEFLATE dictionaries, copied as-is (they are never generated here).
	$(INSTALL) -d -m 0755 $(DESTDIR)$(LIBEXECDIR)/dictionaries
	$(INSTALL) -m 0644 dictionaries/DEFAULT dictionaries/navi-deflate-*.dict $(DESTDIR)$(LIBEXECDIR)/dictionaries/
	$(INSTALL) -m 4755 authorize $(DESTDIR)$(LIBEXECDIR)/authorize
	# polkit entry point for "Administrator prompts" in System Settings.
	$(INSTALL) -m 0755 $(POLKIT_SRC)/navi-auth-configure $(DESTDIR)$(LIBEXECDIR)/configure
	$(INSTALL) -m 0644 $(POLKIT_SRC)/in.akuj.navi-auth.policy $(DESTDIR)$(POLKITDIR)/
ifeq ($(PAM_APPROVAL),yes)
	$(INSTALL) -m 0755 pam_common.py pam_switch.py $(DESTDIR)$(LIBEXECDIR)/
	# pkexec entry point for the phone-approval switches in System Settings.
	printf '%s\n' '#!/bin/sh' \
	    '# Turns optional phone approval on/off in /etc/pam.d (System Settings runs this via pkexec).' \
	    'exec /usr/bin/python3 -I $(LIBEXECDIR)/pam_switch.py "$$@"' \
	    > $(DESTDIR)$(LIBEXECDIR)/navi-pam
	chmod 0755 $(DESTDIR)$(LIBEXECDIR)/navi-pam
	$(INSTALL) -m 0644 $(POLKIT_SRC)/in.akuj.navi-auth.pam.policy $(DESTDIR)$(POLKITDIR)/
endif
ifeq ($(ENABLE_SUDO),yes)
	$(INSTALL) -m 0755 sudo_approve.py $(DESTDIR)$(LIBEXECDIR)/
	printf '%s\n' '#!/bin/sh' \
	    '# Optional sudo approval: run by pam_exec from /etc/pam.d/sudo (navi-pam enable sudo).' \
	    'exec /usr/bin/python3 -I $(LIBEXECDIR)/sudo_approve.py $(foreach t,$(SUDO_TERMINALS),--terminal $(t)) --timeout $(SUDO_TIMEOUT)' \
	    > $(DESTDIR)$(LIBEXECDIR)/sudo-approve
	chmod 0755 $(DESTDIR)$(LIBEXECDIR)/sudo-approve
endif
ifeq ($(ENABLE_LOGIN),yes)
	$(INSTALL) -m 0755 login_approve.py $(DESTDIR)$(LIBEXECDIR)/
	printf '%s\n' '#!/bin/sh' \
	    '# Optional SDDM login / lock screen approval: run by pam_exec (navi-pam enable sddm|kde).' \
	    'exec /usr/bin/python3 -I $(LIBEXECDIR)/login_approve.py' \
	    > $(DESTDIR)$(LIBEXECDIR)/login-approve
	chmod 0755 $(DESTDIR)$(LIBEXECDIR)/login-approve
endif
ifeq ($(PAM_APPROVAL),yes)
	@echo
	@echo "Optional phone approval is installed but not active. Turn it on in"
	@echo "System Settings -> Navi Authenticator (asks for the administrator password),"
	@echo "or as root: $(LIBEXECDIR)/navi-pam enable$(if $(filter yes,$(ENABLE_SUDO)), sudo)$(if $(filter yes,$(ENABLE_LOGIN)), sddm|kde)"
	@echo
endif

# Developer command: writes the next dictionaries/navi-deflate-N.dict from navi-deflate.sections and
# makes it the default. Commit the result; builds and installs only copy committed dictionaries.
dictionary:
	$(PYTHON) tools/make_dictionary.py

clean:
	rm -f authorize

.PHONY: all install clean dictionary
