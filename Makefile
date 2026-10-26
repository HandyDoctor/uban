CC ?= gcc
CFLAGS ?= -O3 -Wall -Wextra -Wno-unused-result -std=c99 -D_POSIX_C_SOURCE=200809L -Iinclude
LDFLAGS ?= -lm

TARGET = uban
SRC_DIR = src
OBJ_DIR = obj
ETC_DIR = etc

SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin
CONFDIR = /etc/uban
LOGROTDIR = /etc/logrotate.d
SYSTEMDDIR = /etc/systemd/system
VARDIR = /var/lib/uban
LOGDIR = /var/log/uban

.PHONY: all clean install uninstall

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
	@echo "Build complete: $(TARGET)"

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

clean:
	rm -rf $(OBJ_DIR) $(TARGET)
	@echo "Cleaned build artifacts."

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -d $(DESTDIR)$(CONFDIR)
	install -d $(DESTDIR)$(LOGROTDIR)
	install -d $(DESTDIR)$(SYSTEMDDIR)
	install -d $(DESTDIR)$(VARDIR)
	install -d $(DESTDIR)$(LOGDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
	
	@if [ -f $(ETC_DIR)/uban.conf ]; then \
		install -m 644 $(ETC_DIR)/uban.conf $(DESTDIR)$(CONFDIR)/uban.conf.example; \
		echo "Installed reference configuration to $(CONFDIR)/uban.conf.example"; \
	fi

	@if [ -f $(ETC_DIR)/uban.conf ] && [ ! -f $(DESTDIR)$(CONFDIR)/uban.conf ]; then \
		install -m 644 $(ETC_DIR)/uban.conf $(DESTDIR)$(CONFDIR)/uban.conf; \
		echo "Installed default configuration to $(CONFDIR)/uban.conf"; \
	else \
		echo "Preserved existing configuration at $(CONFDIR)/uban.conf"; \
	fi
	
	@if [ -f $(ETC_DIR)/uban.help ]; then \
		install -m 644 $(ETC_DIR)/uban.help $(DESTDIR)$(CONFDIR)/uban.help; \
		echo "Installed help manual to $(CONFDIR)/uban.help"; \
	fi
	
	@if [ -f $(ETC_DIR)/uban.logrotate ]; then \
		install -m 644 $(ETC_DIR)/uban.logrotate $(DESTDIR)$(LOGROTDIR)/uban; \
		echo "Installed logrotate script to $(LOGROTDIR)/uban"; \
	fi
	
	@if [ -f uban.service ]; then \
		install -m 644 uban.service $(DESTDIR)$(SYSTEMDDIR)/uban.service; \
		echo "Installed systemd service unit to $(SYSTEMDDIR)/uban.service"; \
	fi
	
	@echo "Installation complete."

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
	rm -f $(DESTDIR)$(CONFDIR)/uban.help
	rm -f $(DESTDIR)$(LOGROTDIR)/uban
	rm -f $(DESTDIR)$(SYSTEMDDIR)/uban.service
	@echo "Uninstalled uban binary, help text, logrotate, and service unit."
	@echo "Note: Configuration ($(CONFDIR)) and data directories ($(VARDIR), $(LOGDIR)) were preserved."
