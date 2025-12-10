# Linux Anti-Executable - Top-Level Makefile

PREFIX ?= /usr/local

.PHONY: all daemon gui clean install uninstall help

all: daemon gui

daemon:
	$(MAKE) -C src/daemon

gui:
	$(MAKE) -C src/gui

clean:
	$(MAKE) -C src/daemon clean
	$(MAKE) -C src/gui clean

install: all
	# Install daemon
	$(MAKE) -C src/daemon install PREFIX=$(PREFIX)

	# Install GUI
	$(MAKE) -C src/gui install PREFIX=$(PREFIX)

	# Install configuration
	install -d $(DESTDIR)/etc/lexec
	install -m 644 config/lexec.conf $(DESTDIR)/etc/lexec/

	# Install systemd service
	install -d $(DESTDIR)/etc/systemd/system
	install -m 644 config/lexec-daemon.service $(DESTDIR)/etc/systemd/system/

	# Install desktop file and icon
	install -d $(DESTDIR)/usr/share/applications
	install -m 644 config/lexec-gui.desktop $(DESTDIR)/usr/share/applications/
	install -d $(DESTDIR)/usr/share/icons/hicolor/scalable/apps
	install -m 644 assets/lexec.svg $(DESTDIR)/usr/share/icons/hicolor/scalable/apps/

	# NOTE: Autostart disabled by default - user should start manually
	# To enable autostart, uncomment the following lines or run:
	#   sudo cp config/lexec-gui-autostart.desktop /etc/xdg/autostart/
	# install -d $(DESTDIR)/etc/xdg/autostart
	# install -m 644 config/lexec-gui-autostart.desktop $(DESTDIR)/etc/xdg/autostart/

	# Install scripts
	install -d $(DESTDIR)$(PREFIX)/share/lexec
	install -m 755 scripts/first-run-scan.sh $(DESTDIR)$(PREFIX)/share/lexec/

	# Create data directories
	install -d $(DESTDIR)/var/lib/lexec
	install -d $(DESTDIR)/var/run/lexec

	@echo ""
	@echo "=============================================="
	@echo "  Installation complete!"
	@echo "=============================================="
	@echo ""
	@echo "First-time setup:"
	@echo "  1. Scan existing executables (as root):"
	@echo "     sudo lexec-daemon --scan --learn --foreground"
	@echo ""
	@echo "  2. Enable the daemon service:"
	@echo "     sudo systemctl enable --now lexec-daemon"
	@echo ""
	@echo "  3. Start the GUI from your applications menu:"
	@echo "     Look for 'Linux Anti-Executable' icon"
	@echo "     Or run: lexec-gui"
	@echo ""
	@echo "NOTE: The GUI does NOT auto-start. Launch it manually when needed."

uninstall:
	$(MAKE) -C src/daemon uninstall PREFIX=$(PREFIX)
	$(MAKE) -C src/gui uninstall PREFIX=$(PREFIX)
	rm -f $(DESTDIR)/etc/systemd/system/lexec-daemon.service
	rm -rf $(DESTDIR)/etc/lexec
	rm -rf $(DESTDIR)$(PREFIX)/share/lexec
	@echo "Note: /var/lib/lexec (database) was not removed"

help:
	@echo "Linux Anti-Executable Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build daemon and GUI (default)"
	@echo "  daemon    - Build only the daemon"
	@echo "  gui       - Build only the GUI"
	@echo "  install   - Install everything"
	@echo "  uninstall - Remove installation"
	@echo "  clean     - Clean build files"
	@echo ""
	@echo "Dependencies:"
	@echo "  - gcc, make"
	@echo "  - libsqlite3-dev"
	@echo "  - libssl-dev (for SHA256)"
	@echo "  - libgtk-4-dev (for GUI)"
	@echo ""
	@echo "Build:"
	@echo "  make"
	@echo "  sudo make install"
	@echo "  sudo /usr/local/share/lexec/first-run-scan.sh"
