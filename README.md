# guardian-master

Lightweight dependency + secret-rotation tracker for Coolify apps. Phase 5 scaffold.

## Quick Deploy (DockerHub image)

Use the provided `docker-compose.yaml`:

```bash
# 1. Export your secrets (from Coolify + DockerHub)
export DOCKERHUB_USERNAME=your-dockerhub-user
export GUARDIAN_COOLIFY_API=https://coolify.yourorg.com/api/v1
export GUARDIAN_COOLIFY_TOKEN=your-coolify-token
export GUARDIAN_GITHUB_TOKEN=ghp_xxxxxxxxxxxx  # optional

# 2. Pull & run
docker compose pull
docker compose up -d
# => http://localhost:8000
```

## Deploy on Coolify

1. Create Application → "Docker (custom)" → point at this repo.
2. Environment vars:
   - `GUARDIAN_COOLIFY_API` = `https://<your-coolify>/api/v1`
   - `GUARDIAN_COOLIFY_TOKEN` = Coolify read-only API token
   - `GUARDIAN_GITHUB_TOKEN` = (optional) GitHub PAT for latest-release lookup
   - `GUARDIAN_DB` = `/data/guardian.db`
3. Volume: mount `guardian_data` (or host dir) at `/data` so SQLite persists.
4. Scheduled job (Coolify → Jobs → Cron) — bi-weekly cadence (every 2 weeks):
   ```
   0 3 */14 * * curl -X GET https://guardian.apps/sync
   ```
   or use Coolify's native scheduler.

## CLI

```bash
python app.py            # serve on :8000
GUARDIAN_DB=/tmp/g.db python app.py  # local smoke test
```
