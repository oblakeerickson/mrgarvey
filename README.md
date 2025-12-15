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
| **Admin user creation** | Creates an admin user via `rake admin:create` with a random password; credentials are printed to console |
| **Unicorn restart** | Restarts the Discourse app server to pick up the new site |
| **DigitalOcean DNS** | Creates an A record via the DO API pointing the new subdomain to your droplet IP |
| **Caddyfile management** | Appends a reverse-proxy block for the new hostname and reloads Caddy |
| **Dry-run mode** | Preview all commands without executing them (`--dry-run`) |

## Commands

- **`mrgarvey plan`** — Print a site plan as JSON (optionally specify `--slug` or let it generate one)
- **`mrgarvey new`** — Provision a complete new site: DB, config, migrations, DNS, and web server

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `DO_API_TOKEN` | DigitalOcean API token for DNS record creation |
| `DO_DROPLET_IP` | IP address for the DNS A record |