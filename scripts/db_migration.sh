#!/usr/bin/env bash
set -euo pipefail

VARDIR="/var/lib/uban"
STATE_FILE="${VARDIR}/bans.state"
SQLITE_DB="${VARDIR}/uban.sqlite"
NOW=$(date +%s)

command -v sqlite3 >/dev/null 2>&1 || {
    echo "Error: sqlite3 CLI is required. Run 'sudo apt install sqlite3'." >&2
    exit 1
}

echo "Initializing SQLite database at ${SQLITE_DB}..."

sqlite3 "${SQLITE_DB}" <<'EOF'
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS uban_records (
    ip            TEXT    NOT NULL,
    jail          TEXT    NOT NULL,
    ban_end       INTEGER NOT NULL DEFAULT -1,
    orig_ban_time INTEGER NOT NULL DEFAULT -1,
    ban_count     INTEGER NOT NULL DEFAULT 1,
    last_update   INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    PRIMARY KEY (ip, jail)
);

CREATE INDEX IF NOT EXISTS idx_uban_ip ON uban_records(ip);
CREATE INDEX IF NOT EXISTS idx_uban_jail ON uban_records(jail);
CREATE INDEX IF NOT EXISTS idx_uban_lookup ON uban_records(jail, ip);
CREATE INDEX IF NOT EXISTS idx_uban_eviction ON uban_records(ban_end, last_update);
EOF

# Step 1: Migrate all jail_name.db historical files (<ip> <ban_count> [last_seen])
shopt -s nullglob
DB_FILES=("${VARDIR}"/*.db)
shopt -u nullglob

if [ ${#DB_FILES[@]} -gt 0 ]; then
    echo "Migrating ${#DB_FILES[@]} jail history file(s)..."
    for db_path in "${DB_FILES[@]}"; do
        filename=$(basename "$db_path")
        # In v1.0, jail_name.db used exact section names (e.g. nginx-444.db or nginx-200_502.db)
        jail_name="${filename%.db}"

        echo "  Importing ${filename} (jail: ${jail_name})..."
        awk -v jail="$jail_name" -v now="$NOW" '
        BEGIN { print "BEGIN TRANSACTION;" }
        NF >= 2 {
            ip = $1
            count = $2
            if (count !~ /^[0-9]+$/) count = 1
            printf "INSERT INTO uban_records (ip, jail, ban_end, orig_ban_time, ban_count, last_update) VALUES (\x27%s\x27, \x27%s\x27, -1, -1, %d, %d) ON CONFLICT(ip, jail) DO UPDATE SET ban_count = MAX(uban_records.ban_count, excluded.ban_count), last_update = excluded.last_update;\n", ip, jail, count, now
        }
        END { print "COMMIT;" }
        ' "$db_path" | sqlite3 "${SQLITE_DB}"
    done
else
    echo "No .db files found in ${VARDIR}."
fi

# Step 2: Merge active bans from bans.state (<set_or_jail> <ip> <time_left> <orig_ban_time>)
if [[ -s "${STATE_FILE}" ]]; then
    echo "Merging active bans from ${STATE_FILE}..."
    awk -v now="$NOW" '
    BEGIN { print "BEGIN TRANSACTION;" }
    NF >= 4 {
        raw_jail = $1
        ip = $2
        raw_left = $3
        orig_time = $4

        # Strip "uban_" prefix if the file recorded the nftables set name
        sub(/^uban_/, "", raw_jail)

        # Convert permanent ban notation: -1 -1 -> ban_end=0, orig_time=0
        if (raw_left == -1 && orig_time == -1) {
            ban_end = 0
            orig_time = 0
        } else {
            ban_end = now + raw_left
        }

        # Keep existing ban_count if record already exists from the .db file
        printf "INSERT INTO uban_records (ip, jail, ban_end, orig_ban_time, ban_count, last_update) VALUES (\x27%s\x27, \x27%s\x27, %d, %d, 1, %d) ON CONFLICT(ip, jail) DO UPDATE SET ban_end = excluded.ban_end, orig_ban_time = excluded.orig_ban_time, last_update = excluded.last_update;\n", ip, raw_jail, ban_end, orig_time, now
    }
    END { print "COMMIT;" }
    ' "${STATE_FILE}" | sqlite3 "${SQLITE_DB}"
    echo "Active bans merged."
else
    echo "No bans.state file found (skipping)."
fi

echo "Migration complete. Verification sample (Active Bans):"
sqlite3 "${SQLITE_DB}" "
SELECT 
    jail, 
    ip, 
    CASE 
        WHEN ban_end = 0 THEN 'PERMANENT'
        WHEN ban_end = -1 THEN 'INACTIVE'
        ELSE (ban_end - strftime('%s', 'now')) || 's left'
    END AS status,
    orig_ban_time, 
    ban_count, 
    CASE 
        WHEN ban_end > 0 THEN datetime(ban_end, 'unixepoch', 'localtime')
        ELSE 'N/A'
    END AS expires_at,
    datetime(last_update, 'unixepoch', 'localtime') AS last_update
FROM uban_records 
WHERE ban_end >= 0 
ORDER BY ban_end ASC 
LIMIT 10;
" -header -column
