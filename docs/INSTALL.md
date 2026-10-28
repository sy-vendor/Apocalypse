# Installation and deployment

Apocalypse requires Python 3.11 or newer. Run it only against systems you own or are explicitly authorized to assess.

## Local installation

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
apocalypse --version
```

Browser crawling, login recording, and Chromium XSS confirmation require Playwright:

```bash
python -m pip install -e '.[browser]'
python -m playwright install chromium   # only when Chrome/Edge is unavailable
```

Start the loopback-only console:

```bash
apocalypse --db data/apocalypse.db serve --host 127.0.0.1 --port 8080
```

Open `http://127.0.0.1:8080`. The SQLite database and reports should be backed up according to your retention policy. They can contain target URLs and vulnerability evidence.

## Team deployment

Keep the application bound to loopback and place an authenticated TLS reverse proxy in front of it. Create the first local administrator before exposing the service:

```bash
apocalypse --db /srv/apocalypse/apocalypse.db user add --name admin --role admin
apocalypse --db /srv/apocalypse/apocalypse.db serve --host 127.0.0.1 --port 8080
```

Store the one-time token in a secret manager. Run the process as an unprivileged service account, restrict database permissions to that account, and allow outbound traffic only to approved scan targets and explicitly configured webhook/OAST providers. Do not bind to a public interface unless a trusted reverse proxy, access controls, and the `--allow-remote-ui` acknowledgement are in place.

For production service managers, use the command above with automatic restart, a dedicated working directory, and environment variables supplied from a secret store. Take a database backup before upgrades.

## Upgrade and rollback

```bash
cp /srv/apocalypse/apocalypse.db /srv/apocalypse/apocalypse.db.backup
python -m pip install --upgrade .
apocalypse --version
```

Rollback by restoring the previous package build and database backup together. Test upgrades on a copy of the database first.

## Developer verification

```bash
python -m pip install -e '.[dev]'
coverage run -m unittest discover -s tests -p 'test_core.py' -v
coverage report                         # enforces the 45% whole-package baseline
python benchmark/run_lab.py             # precision/recall regression gate
python -m playwright install chromium
APOCALYPSE_E2E=1 python -m unittest discover -s tests -p 'test_e2e.py' -v
```

The coverage gate deliberately includes currently thin CLI, web, and browser adapters; the measured baseline is 47%, with a 45% non-regression floor. Raise the floor as integration tests are added rather than excluding those modules.

The loopback benchmark exercises reviewed positive and negative cases across multiple vulnerability families. Its oracle is `benchmark/ground_truth.json`, and the independent review procedure is in `benchmark/REVIEW.md`. This remains a controlled regression suite, not a claim of broad real-world scanner accuracy. The manifest records a pending human sign-off until a maintainer completes that checklist.
