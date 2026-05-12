# MySQL Pharmaceutical Honeypot (port 3306)

This sidecar replaces the old banner-only MySQL listener with a full minimal protocol responder that:

- Advertises an obviously outdated/vulnerable MySQL version (`5.5.23-0ubuntu0.14.04.1`) so nmap `-sV` and automated scanners immediately flag it as high-value.
- Accepts **any** credentials (root with empty password succeeds instantly — "super easy access").
- Serves an **infinite, deterministically generated** pharmaceutical manufacturing dataset using the exact same seeded PRNG as the HTTP data-room maze.
- Includes a `password_backup` table (poorly named by a sloppy admin) containing hundreds of thousands of realistic-looking high-cost bcrypt hashes to waste attacker cracking time and GPU budget.
- Never terminates on large `SELECT *` or `LIMIT` queries — it streams generated rows forever (or until the client disconnects).

This targets the highest-volume database scanning vector observed in 2026 honeypot telemetry.

## Theme
VitaForge Pharmaceuticals (a research division of the fictional Arden Point Capital). All data is internally consistent with the existing bait files (`BAIT_ENV`, git config, intranet, etc.).

## Port Strategy (Critical for Operators)

**Development / initial testing** (recommended):
- The compose file defaults to a high random port: `MYSQL_HONEYPOT_PORT=33306`
- No conflict with any real MySQL/Postgres/SSH on your machine.

**Production lure deployment** (maximum scanner value):
1. **Move your real services off the standard ports first**:
   - Real SSH: edit `/etc/ssh/sshd_config` → `Port 22222` (or any high port), then `systemctl restart ssh`.
   - Real MySQL (if any): change to 33306.
   - Real Postgres: change to 35432.
   - (Optional) Real FTP if you had one.

2. Update `.env` or compose override:
   ```bash
   MYSQL_HONEYPOT_PORT=3306
   ```

3. `docker compose up -d honeypot-sidecar`

4. On hosts that require root for ports <1024 (Raspberry Pi, etc.):
   - Either run the stack with `--privileged`
   - Or add `cap_add: [NET_BIND_SERVICE]` to the sidecar service
   - Or use host iptables REDIRECT: `iptables -t nat -A PREROUTING -p tcp --dport 3306 -j REDIRECT --to-port 33306`

After the change, `nmap -sV -p 3306 your-host` will report the old MySQL version and the pharma tables.

## What Attackers See

```bash
nmap -sV -p 3306 target
# 3306/tcp open  mysql    MySQL 5.5.23-0ubuntu0.14.04.1

mysql -h target -u root -p '' -e "SHOW DATABASES;"
# pharma_erp
# clinical_warehouse
# regulatory_archive
# leaked_data

mysql -h target -u root -p '' pharma_erp -e "SHOW TABLES;"
# invoices
# lab_results
# ...
# password_backup

mysql -h target -u root -p '' pharma_erp -e "SELECT * FROM lab_results LIMIT 5;"
# ... rows with real drug names (Keytruda, Ozempic, Humira...), Dr. Elena Vasquez, 99.3% purity, PASS/FAIL ...

mysql -h target -u root -p '' pharma_erp -e "SELECT * FROM password_backup LIMIT 100000;" | wc -l
# 100000+ rows of $2b$12$... bcrypt hashes (cost 12-14) — cracking these is deliberately expensive
```

Large dumps or long-running queries simply keep generating more plausible data. The same query always returns identical rows (fully deterministic via `seededRand`).

## Tables & Generated Content

- **invoices**: PO numbers, drug SKUs (real names like Keytruda-2026-Q2), vendors (Lonza, Catalent...), multi-million USD amounts, dates, statuses.
- **lab_results**: Batch IDs, real drug names, lab test names (Purity HPLC, Endotoxin LAL...), researcher names (Dr. Elena Vasquez, Dr. Marcus Hale...), purity %, PASS/FAIL.
- **password_backup**: 500k+ rows of `email`, high-cost bcrypt `hash`, `cost`, `leak_source`, `crack_status`. (Table named `password_backup` on purpose — exactly what a careless IT admin would create and leave exposed.) Some low-cost entries exist to tempt partial cracking effort.
- Others (batch_records, stability_studies, clinical_trials, investigator_payments) are stubbed to OK for now; expand as needed.

All generation reuses the exact `seededRand` + `pick` helpers from the HTTP maze for perfect consistency and reproducibility.

**Cloudflare Tunnel note**: When running behind Cloudflare Tunnel, the MySQL honeypot (and other TCP lures) remain reachable only through the tunnel. Many automated scanners and Shodan-style indexers do not follow Tunnel origins, so you will see significantly fewer hits on the `password_backup` table and pharma data.

## Logging & Future Integration
Every connection and query is logged to container stdout with `[mysql-honeypot]` prefix. Future work can tail these into `ai_honeypot_hits` with source `mysql_pharma_probe` (exactly like the HTTP monitored endpoints).

## Updating Existing Lure Documentation
- [docs/honeypot-lures.md](honeypot-lures.md) — add row under Network Banner Sidecar: "3306 | MySQL 5.5.23 (VitaForge Pharma infinite dataset + password hashes) | source=`mysql_pharma_probe`"
- [docs/lures-and-surfaces.md](lures-and-surfaces.md) — add "MySQL Pharmaceutical Trap (3306)" to the Network Banners section.

This single surface delivers both high automated-scanner hit rate and maximum time/money sink for any attacker who actually interacts with the "breached" database.