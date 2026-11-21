CC ?= gcc
SQLITE_FLAGS = -DSQLITE_THREADSAFE=1 \
               -DSQLITE_DEFAULT_WAL_SYNCHRONOUS=1 \
               -DSQLITE_OMIT_LOAD_EXTENSION=1 \
               -DSQLITE_OMIT_DEPRECATED=1 \
               -DSQLITE_DQS=0

CFLAGS ?= -O3 -Wall -Wextra -Wno-unused-result -std=c99 -D_POSIX_C_SOURCE=200809L -Iinclude $(SQLITE_FLAGS)
LDFLAGS ?= -lpthread -ldl -lm

TARGET = uban
SRC_DIR = src
OBJ_DIR = obj
ETC_DIR = etc
SCRIPTS_DIR = scripts

SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin
CONFDIR = /etc/uban
LOGROTDIR = /etc/logrotate.d
SYSTEMDDIR = /etc/systemd/system
VARDIR = /var/lib/uban
LOGDIR = /var/log/uban
MIGRATED_DIR = $(VARDIR)/backup_v1.0_state

.PHONY: all clean install uninstall migrate

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

migrate:
	@if [ -d "$(DESTDIR)$(VARDIR)" ]; then \
		HAS_STATE=0; \
		if [ -f "$(DESTDIR)$(VARDIR)/bans.state" ]; then HAS_STATE=1; fi; \
		if ls $(DESTDIR)$(VARDIR)/*.db >/dev/null 2>&1; then HAS_STATE=1; fi; \
		if [ $$HAS_STATE -eq 1 ]; then \
			echo "=================================================="; \
			echo "Detected legacy v1.0 state files in $(DESTDIR)$(VARDIR)."; \
			if [ -f "$(SCRIPTS_DIR)/db_migration.sh" ]; then \
				chmod +x $(SCRIPTS_DIR)/db_migration.sh; \
				echo "Executing migration: $(SCRIPTS_DIR)/db_migration.sh"; \
				$(SCRIPTS_DIR)/db_migration.sh || { echo "Migration script failed!"; exit 1; }; \
				mkdir -p $(DESTDIR)$(MIGRATED_DIR); \
				if [ -f "$(DESTDIR)$(VARDIR)/bans.state" ]; then \
					mv $(DESTDIR)$(VARDIR)/bans.state $(DESTDIR)$(MIGRATED_DIR)/; \
				fi; \
				for f in $(DESTDIR)$(VARDIR)/*.db; do \
					if [ -f "$$f" ]; then mv "$$f" $(DESTDIR)$(MIGRATED_DIR)/; fi; \
				done; \
				echo "Moved legacy flat files to $(DESTDIR)$(MIGRATED_DIR)/"; \
				echo "Migration to SQLite complete."; \
			else \
				echo "WARNING: $(SCRIPTS_DIR)/db_migration.sh not found. Skipping."; \
			fi; \
			echo "=================================================="; \
		fi; \
	fi

install: $(TARGET) migrate
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
	-systemctl stop $(TARGET) 2>/dev/null || true
	-systemctl disable $(TARGET) 2>/dev/null || true
	-nft delete table inet uban_filter 2>/dev/null || true
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
	rm -f $(DESTDIR)$(CONFDIR)/uban.help
	rm -f $(DESTDIR)$(LOGROTDIR)/uban
	rm -f $(DESTDIR)$(SYSTEMDDIR)/uban.service
	-systemctl daemon-reload 2>/dev/null || true
	@echo "Uninstalled uban binary, help text, logrotate, and service unit."
	@echo "Active kernel firewall table (inet uban_filter) removed."
	@echo "Note: Configuration ($(CONFDIR)) and data directories ($(VARDIR), $(LOGDIR)) were preserved."
