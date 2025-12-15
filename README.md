# mrgarvey

![mrgarvey](https://github.com/user-attachments/assets/5b3cbf8d-c14c-47d1-976c-8d0207d008ab)

A CLI tool for provisioning new Discourse multisite instances on the "ofcourse.chat" platform (or any custom domain). It automates the tedious steps of spinning up a new site in a Discourse multisite deployment.

## Features

| Feature | Description |
|---------|-------------|
| **Random slug generation** | Generates friendly site slugs like `swift-ember` or `calm-prairie` from adjective-noun pairs |
| **Site plan generation** | Outputs a JSON plan with slug, hostname, database name, and Rails DB key |
| **PostgreSQL database creation** | Creates a new Postgres database inside the Docker container with required extensions (`hstore`, `pg_trgm`) and grants |
| **multisite.yml management** | Appends a new site block to the Discourse multisite YAML config (idempotent—skips if already present) |
| **Rails migrations** | Runs `db:migrate` and `db:seed_fu` for the new site via Docker |
| **Site claiming API** | REST API endpoint to claim a pre-provisioned site, create admin user, and send password reset email |
| **Unicorn restart** | Restarts the Discourse app server to pick up the new site |
| **DigitalOcean DNS** | Creates an A record via the DO API pointing the new subdomain to your droplet IP |
| **Caddyfile management** | Appends a reverse-proxy block for the new hostname and reloads Caddy |
| **Dry-run mode** | Preview all commands without executing them (`--dry-run`) |

## Commands

- **`mrgarvey plan`** — Print a site plan as JSON (optionally specify `--slug` or let it generate one)
- **`mrgarvey new`** — Pre-provision a new site: DB, config, migrations, DNS, and web server (no admin user yet)
- **`mrgarvey serve`** — Run the API server for claiming pre-provisioned sites
  - Use `--bind=private` to auto-detect and bind to the DigitalOcean private IP
  - Use `--port=8080` to specify the port (default: 8080)

## API Endpoints

### POST /claim

Claim an available pre-provisioned site and create an admin user.

**Request:**
```json
{
  "email": "admin@example.com"
}
```

**Response:**
```json
{
  "hostname": "swift-ember.ofcourse.chat",
  "email": "admin@example.com"
}
```

The endpoint will:
1. Find an unclaimed site (one without any admin users)
2. Create an admin user with the provided email
3. Trigger a password reset email so the user can set their password
4. Return the site hostname

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `DO_API_TOKEN` | DigitalOcean API token for DNS record creation |
| `DO_DROPLET_IP` | IP address for the DNS A record |