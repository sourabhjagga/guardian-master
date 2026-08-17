#!/usr/bin/env python3
"""Guardian Master — lightweight dependency/secret-rotation tracker for Coolify apps."""
import hashlib, sqlite3, os, re, io, time
from contextlib import closing
from functools import wraps
from flask import Flask, g, jsonify, render_template_string, abort
import requests, semver

DB_PATH = os.environ.get("GUARDIAN_DB", "/data/guardian.db")

COOLIFY_API = os.environ["GUARDIAN_COOLIFY_API"]  # e.g. https://coolify.yourorg.com/api/v1
COOLIFY_TOKEN = os.environ["GUARDIAN_COOLIFY_TOKEN"]
GITHUB_TOKEN = os.environ.get("GUARDIAN_GITHUB_TOKEN")  # optional, for latest-release lookup

# Hand-curated SLA table (days between required rotations)
SLA_DAYS = {
    "gpuvista": 180,
    "briefing-agent-hardened": 90,
    "tradetron-weekly-report-issue-fixed": 30,
    "tradetron-automation-optimized-hardened": 30,
    "held": float("inf"),  # held apps skip rotation checks
}
DEFAULT_SLA = 90  # fallback


app = Flask(__name__)

# --------------------------------------------------------------------------- #
# DB
# --------------------------------------------------------------------------- #
SCHEMA = """
CREATE TABLE IF NOT EXISTS apps (
    id              TEXT PRIMARY KEY,      -- Coolify application UUID
    name            TEXT UNIQUE,
    repo_url        TEXT,
    sla_days        INTEGER DEFAULT 90,
    first_seen_at   TEXT DEFAULT (datetime('now')),
    last_synced_at  TEXT
);

CREATE TABLE IF NOT EXISTS env_vars (
    app_id          TEXT REFERENCES apps(id) ON DELETE CASCADE,
    name            TEXT,
    last_value_hash TEXT,
    last_seen_at    TEXT,
    PRIMARY KEY (app_id, name)
);

CREATE TABLE IF NOT EXISTS rotations (
    app_id          TEXT,
    name            TEXT,
    rotated_at      TEXT,
    PRIMARY KEY (app_id, name, rotated_at)
);

CREATE TABLE IF NOT EXISTS dependencies (
    app_id          TEXT REFERENCES apps(id) ON DELETE CASCADE,
    name            TEXT,
    current_version TEXT,
    latest_version  TEXT,
    diff_level      TEXT,              -- major|minor|patch|up-to-date
    updated_today   INTEGER DEFAULT 0,
    last_seen_at    TEXT,
    PRIMARY KEY (app_id, name)
);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with closing(sqlite3.connect(DB_PATH)) as con:
        con.executescript(SCHEMA)
        con.commit()


# --------------------------------------------------------------------------- #
# Coolify API helpers
# --------------------------------------------------------------------------- #
def coolify():
    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {COOLIFY_TOKEN}",
        "Accept": "application/json",
    })
    return session


def _slug(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9-]", "", name.lower().replace(" ", "-"))


def _slug_to_sla(slug: str) -> int:
    for k, v in SLA_DAYS.items():
        if k in slug:
            return v
    return DEFAULT_SLA


# --------------------------------------------------------------------------- #
# Env rotation (poll-hash)
# --------------------------------------------------------------------------- #
def hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def record_rotation(app_id, name, rotated_at="now"):
    db = get_db()
    db.execute(
        "INSERT OR IGNORE INTO rotations(app_id,name,rotated_at) VALUES(?,?,datetime(?))",
        (app_id, name, rotated_at))
    db.commit()


def detect_rotations(app_id, env_rows):
    """env_rows: [{name, value}] — secrets only flagged via value-hash diff."""
    db = get_db()
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ")
    for row in env_rows:
        name, value = row["name"], row["value"] if isinstance(row, dict) else row[1]
        cur_hash = hash_secret(value)
        prev = db.execute(
            "SELECT last_value_hash FROM env_vars WHERE app_id=? AND name=?",
            (app_id, name)).fetchone()
        db.execute(
            "INSERT OR REPLACE INTO env_vars(app_id,name,last_value_hash,last_seen_at) "
            "VALUES(?,?,?,?)", (app_id, name, cur_hash, now))
        if prev and prev["last_value_hash"] != cur_hash:
            record_rotation(app_id, name, "now")  # rotation observed today
    db.commit()


# --------------------------------------------------------------------------- #
# Dependency tracking
# --------------------------------------------------------------------------- #
def parse_lockfile(repo_url: str) -> list[dict]:
    """Shallow-clone repo, read lockfile, return [{name, version}]."""
    # Placeholder: real impl shallow-clones `repo_url`, parses package-lock.json
    # / requirements.txt / Cargo.lock / go.mod based on file presence.
    return []  # stub — to be fleshed out with subprocess git clone + parsers


def latest_stable(repo_url: str, dep_name: str) -> str | None:
    """Hit GitHub latest-release API (uses GITHUB_TOKEN if set)."""
    if not GITHUB_TOKEN or not repo_url:
        return None
    m = re.match(r"https://github\.com/([^/]+)/([^/]+)", repo_url)
    if not m:
        return None
    owner, repo = m.group(1), m.group(2)
    url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
    headers = {"Authorization": f"Bearer {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}
    r = requests.get(url, headers=headers, timeout=10)
    if r.status_code == 200:
        return r.json().get("tag_name", "").lstrip("v")
    return None


def diff_level(curr: str, latest: str) -> str:
    if not curr or not latest:
        return "unknown"
    c, l = semver.VersionInfo.parse(curr.lstrip("v")), semver.VersionInfo.parse(latest.lstrip("v"))
    if c >= l:
        return "up-to-date"
    if l.major != c.major:
        return "major"
    if l.minor != c.minor:
        return "minor"
    return "patch"


def sync_dependencies(app_id, lockfile_deps, repo_url):
    db = get_db()
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ")
    for d in lockfile_deps:
        name, ver = d["name"], d["version"]
        latest = latest_stable(repo_url, name)
        level = diff_level(ver, latest)
        db.execute(
            "INSERT OR REPLACE INTO dependencies(app_id,name,current_version,latest_version,"
            "diff_level,updated_today,last_seen_at) VALUES(?,?,?,?,?,?,?)",
            (app_id, name, ver, latest, level, 1 if level == "up-to-date" else 0, now))
    db.commit()


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.route("/")
def dashboard():
    db = get_db()
    apps = db.execute(
        "SELECT id, name, sla_days, last_synced_at FROM apps ORDER BY name").fetchall()
    enriched = []
    for a in apps:
        rots = db.execute(
            "SELECT COUNT(*) c FROM rotations WHERE app_id=?", (a["id"],)).fetchone()["c"]
        last_rot = db.execute(
            "SELECT rotated_at FROM rotations WHERE app_id=? ORDER BY rotated_at DESC LIMIT 1",
            (a["id"],)).fetchone()
        last = last_rot["rotated_at"] if last_rot else None
        late = None
        on_time = True
        if last and a["last_synced_at"]:
            import datetime as _dt
            last_d = _dt.date.fromisoformat(last[:10])
            now_d = _dt.date.fromisoformat(a["last_synced_at"][:10])
            days = (now_d - last_d).days
            late = days if days > a["sla_days"] else None
            on_time = late is None
        enriched.append({
            "id": a["id"], "name": a["name"], "sla": a["sla_days"],
            "rots": rots, "late": late, "on_time": on_time,
        })
    return render_template_string(DASHBOARD_TMPL, apps=enriched)


@app.route("/sync")
def sync_handler():
    """Bi-weekly Coolify cron hook → discover apps, env, deps."""
    cs = coolify()
    r = cs.get(f"{COOLIFY_API}/applications")
    if r.status_code != 200:
        return jsonify({"error": f"Coolify returned {r.status_code}"}), 502
    apps = r.json()
    db = get_db()
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ")
    for app in apps:
        app_id = app["uuid"]           # Coolify app UUID
        name = app["name"]
        slug = _slug(name)
        repo_url = app.get("source", {}).get("repo", "") or app.get("env", {}).get("GIT_REPOSITORY")
        sla = _slug_to_sla(slug)
        db.execute(
            "INSERT OR REPLACE INTO apps(id,name,repo_url,sla_days,last_synced_at) "
            "VALUES(?,?,?,?,?)",
            (app_id, name, repo_url, sla, now))
        # 1. env vars (rotation poll-hash)
        env_r = cs.get(f"{COOLIFY_API}/applications/{app_id}/env")
        env_rows = env_r.json() if env_r.status_code == 200 else []
        # normalize: Coolify returns {key,value} list
        secrets = [{"name": e["key"], "value": e.get("value", "")} for e in env_rows]
        detect_rotations(app_id, secrets)
        # 2. deps
        deps = parse_lockfile(repo_url) if repo_url else []
        sync_dependencies(app_id, deps, repo_url)
    db.commit()
    return jsonify({"synced": len(apps), "at": now})


@app.route("/app/<app_id>")
def app_detail(app_id):
    db = get_db()
    app_row = db.execute("SELECT * FROM apps WHERE id=?", (app_id,)).fetchone()
    if not app_row:
        abort(404)
    envs = db.execute(
        "SELECT name, last_value_hash, last_seen_at FROM env_vars WHERE app_id=? ORDER BY name",
        (app_id,)).fetchall()
    deps = db.execute(
        "SELECT * FROM dependencies WHERE app_id=? ORDER BY name",
        (app_id,)).fetchall()
    rots = db.execute(
        "SELECT DISTINCT name, rotated_at FROM rotations WHERE app_id=? ORDER BY rotated_at DESC",
        (app_id,)).fetchall()
    return render_template_string(APP_TMPL, app=app_row, envs=envs, deps=deps, rots=rots)


@app.route("/rotate/<app_id>/<name>", methods=["POST"])
def manual_rotate(app_id, name):
    """Optional manual marker — marks a secret rotated today. (b) path."""
    record_rotation(app_id, name, "now")
    return jsonify({"rotated": name, "app_id": app_id})


# --------------------------------------------------------------------------- #
# Templates (Jinja2 inline)
# --------------------------------------------------------------------------- #
DASHBOARD_TMPL = """
<!doctype html><html><head><title>Guardian</title>
<link href="https://cdn.jsdelivr.net/npm/tailwindcss@3.4.0/dist/tailwind.min.css" rel="stylesheet">
</head><body class="p-4">
<h1 class="text-xl font-bold mb-4">Guardian Dashboard</h1>
<table class="w-full text-sm"><thead><tr><th class="text-left">App</th><th>SLA(d)</th><th>Rotations</th><th>Late(d)</th></tr></thead><tbody>
{% for a in apps %}
<tr class="{{ 'bg-red-100' if a['late'] else 'bg-green-50' if a['on_time'] else ''}}">
<td><a href="/app/{{a['id']}}">{{a['name']}}</a></td><td>{{a['sla']}}</td><td>{{a['rots']}}</td><td>{{a['late']}}</td></tr>
{% endfor %}
</tbody></table>
{% if not apps %}<p>No apps synced. Run <code>/sync</code>.</p>{% endif %}
</body></html>"""

APP_TMPL = """
<!doctype html><html><head><title>{{app.name}}</title>
<link href="https://cdn.jsdelivr.net/npm/tailwindcss@3.4.0/dist/tailwind.min.css" rel="stylesheet">
</head><body class="p-4">
<h1 class="text-xl font-bold mb-4">{{app.name}}</h1>
<u>Env vars (masked)</u><table class="text-sm mb-4"><tr><th class="text-left">name</th><th class="text-left">hash</th><th>last-seen</th></tr>
{% for e in envs %}<tr><td>{{e.name}}</td><td>{{e.last_value_hash[:12]}}…</td><td>{{e.last_seen_at}}</td></tr>{% endfor %}</table>
<u>Dependencies</u><table class="text-sm mb-4"><tr><th class="text-left">dep</th><th>current</th><th>latest</th><th>diff</th></tr>
{% for d in deps %}<tr class="{{ 'text-red-600' if d.diff_level=='major' else 'text-yellow-600' if d.diff_level=='minor' else '' }}">
<td>{{d.name}}</td><td>{{d.current_version}}</td><td>{{d.latest_version or 'n/a'}}</td><td>{{d.diff_level}}</td></tr>
{% endfor %}</table>
<button onclick="fetch('/rotate/{{app.id}}/API_TOKEN', {method:'POST'})" class="bg-blue-600 text-white px-2 py-1 rounded">Mark API_TOKEN rotated</button>
</body></html>"""


@app.route("/api/apps")
def api_apps():
    db = get_db()
    rows = db.execute(
        "SELECT id, name, repo_url, sla_days, last_synced_at FROM apps ORDER BY name").fetchall()
    return jsonify([dict(r) for r in rows])


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    init_db()
    # pre-render dashboard requires a pass; simplified: list apps inline
    @app.before_request
    def _pass_apps():
        if g and g.get("db"):
            g.apps = g.db.execute("SELECT * FROM apps ORDER BY name").fetchall()
        else:
            g.apps = []
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
