# Desktop components of Navi Authenticator (the Android app is built with ./build.sh).
#
#   make
#   make install DESTDIR=/ [MAX_COMMAND=10240]
#
# MAX_COMMAND is the longest command (in characters) offered for phone approval, 512-16384.
# Navi must be built with at least the same limit (NAVI_MAX_COMMAND for ./build.sh).

PREFIX        ?= /usr
LIBEXECDIR    ?= $(PREFIX)/libexec/navi-auth
POLKITDIR     ?= $(PREFIX)/share/polkit-1/actions
POLKIT_SRC    ?= packaging/polkit
CC            ?= cc
CFLAGS        ?= -O2
INSTALL       ?= install

MAX_COMMAND   ?= 10240

PYTHON_FILES = rootauth.py host.py configure-authority.py kdeconnect_transport.py ntfy_transport.py

ifeq ($(shell printf '%s' '$(MAX_COMMAND)' | grep -Ex '[0-9]{3,5}'),)
$(error MAX_COMMAND must be a number from 512 to 16384)
endif
ifneq ($(shell [ $(MAX_COMMAND) -ge 512 ] && [ $(MAX_COMMAND) -le 16384 ] && echo ok),ok)
$(error MAX_COMMAND must be a number from 512 to 16384)
endif

all: authorize

authorize: authorize.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -fPIE -pie -Wl,-z,relro,-z,now -o $@ $<

install: authorize
	$(INSTALL) -d -m 0755 $(DESTDIR)$(LIBEXECDIR) $(DESTDIR)$(POLKITDIR)
	$(INSTALL) -m 0755 $(PYTHON_FILES) $(DESTDIR)$(LIBEXECDIR)/
	# The configured command limit, set in exactly one line of the installed host.py.
	sed -i 's/^MAX_COMMAND = [0-9]*  # set by make install/MAX_COMMAND = $(MAX_COMMAND)  # set by make install/' $(DESTDIR)$(LIBEXECDIR)/host.py
	grep -qx 'MAX_COMMAND = $(MAX_COMMAND)  # set by make install.*' $(DESTDIR)$(LIBEXECDIR)/host.py
	$(INSTALL) -m 4755 authorize $(DESTDIR)$(LIBEXECDIR)/authorize
	# polkit entry point for "Administrator prompts" in System Settings.
	$(INSTALL) -m 0755 $(POLKIT_SRC)/navi-auth-configure $(DESTDIR)$(LIBEXECDIR)/configure
	$(INSTALL) -m 0644 $(POLKIT_SRC)/in.akuj.navi-auth.policy $(DESTDIR)$(POLKITDIR)/

clean:
	rm -f authorize

.PHONY: all install clean
