use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use dropshot::{
    endpoint, ApiDescription, ConfigDropshot, ConfigLogging, ConfigLoggingLevel,
    HttpError, HttpResponseOk, RequestContext, ServerBuilder, TypedBody,
};
use rand::distributions::Alphanumeric;
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};
use reqwest::blocking::Client;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

const ADJECTIVES: &[&str] = &[
    "fancy", "bright", "quiet", "lucky", "golden", "rusty", "brave", "clever", "calm", "swift",
];

const CACHE_FILE: &str = "/var/mrgarvey/sites.json";

const NOUNS: &[&str] = &[
    "honey", "river", "maple", "pine", "sparrow", "aurora", "prairie", "summit", "ember", "canyon",
];

fn generate_password() -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(24)
        .map(char::from)
        .collect()
}

#[derive(Serialize)]
struct SitePlan<'a> {
    slug: String,
    hostname: String,
    db_name: String,
    rails_db_key: String,
    domain: &'a str,
}

fn generate_slug() -> String {
    let mut rng = thread_rng();
    let adj = ADJECTIVES.choose(&mut rng).unwrap();
    let noun = NOUNS.choose(&mut rng).unwrap();
    format!("{adj}-{noun}")
}

fn build_site_plan<'a>(slug: &str, domain: &'a str) -> SitePlan<'a> {
    let db_safe = slug.replace('-', "_");
    let db_name = format!("{db_safe}_discourse");
    let rails_db_key = db_name.clone();
    let hostname = format!("{slug}.{domain}");

    SitePlan {
        slug: slug.to_string(),
        hostname,
        db_name,
        rails_db_key,
        domain,
    }
}

fn multisite_yaml_block(plan: &SitePlan) -> String {
    // Use the rails_db_key as the key, e.g. "ms_swift_ember"
    format!(
        "{key}:\n  adapter: postgresql\n  database: {db}\n  host_names:\n    - \"{host}\"\n  pool: 25\n  timeout: 5000\n",
        key = plan.rails_db_key,
        db = plan.db_name,
        host = plan.hostname,
    )
}

fn update_multisite_file(plan: &SitePlan, path: &str, dry_run: bool) {
    let block = multisite_yaml_block(plan);
    let key_line = format!("{}:", plan.rails_db_key);
    let path_obj = Path::new(path);

    let existing = if path_obj.exists() {
        match fs::read_to_string(path_obj) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[ERROR   ] could not read {path}: {e}");
                return;
            }
        }
    } else {
        String::new()
    };

    if existing.contains(&key_line) {
        println!("[INFO    ] multisite.yml already contains key `{}`; skipping append.", plan.rails_db_key);
        return;
    }

    if dry_run {
        println!("[DRY RUN] would append to {path}:\n{block}");
        return;
    }

    println!("[RUN     ] appending new site block to {path}");

    let mut file = match OpenOptions::new()
        .create(true)
        .append(true)
        .open(path_obj)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[ERROR   ] could not open {path} for append: {e}");
            return;
        }
    };

    // If file isn't empty and doesn't end with newline, add one
    if !existing.is_empty() && !existing.ends_with('\n') {
        if let Err(e) = file.write_all(b"\n") {
            eprintln!("[ERROR   ] failed to write newline to {path}: {e}");
            return;
        }
    }

    if let Err(e) = file.write_all(block.as_bytes()) {
        eprintln!("[ERROR   ] failed to append block to {path}: {e}");
        return;
    }

    println!("[OK      ] appended site block for `{}`", plan.rails_db_key);
}

fn update_caddyfile(plan: &SitePlan, path: &str, snippet: &str, dry_run: bool) {
    let path_obj = Path::new(path);
    let contents = match fs::read_to_string(path_obj) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[ERROR   ] could not read Caddyfile {path}: {e}");
            return;
        }
    };

    let hostname = format!("{}.{}", plan.slug, plan.domain);

    // If there's already a block for this host, bail early
    let already_present = contents.lines().any(|line| {
        // e.g. "calm-prairie.ofcourse.chat {" or with leading spaces
        let trimmed = line.trim_start();
        trimmed.starts_with(&hostname) && trimmed.contains('{')
    });

    if already_present {
        println!("[INFO    ] Caddyfile already has a block for `{}`; skipping.", hostname);
        return;
    }

    // Block we want to add, e.g.:
    // calm-prairie.ofcourse.chat {
    //     import discourse_site
    // }
    let block = format!(
        "\n\n{host} {{\n    import {snippet}\n}}\n",
        host = hostname,
        snippet = snippet,
    );

    if dry_run {
        println!("[DRY RUN] would append to Caddyfile {path}:\n{block}");
        return;
    }

    println!("[RUN     ] appending new Caddy block for `{}` to {}", hostname, path);

    let mut new_contents = contents;
    new_contents.push_str(&block);

    if let Err(e) = fs::write(path_obj, new_contents) {
        eprintln!("[ERROR   ] failed to write updated Caddyfile {path}: {e}");
        return;
    }

    println!("[OK      ] updated Caddyfile {}", path);
}

fn reload_caddy(path: &str, dry_run: bool) {
    let fmt_cmd = format!("caddy fmt --overwrite {path}");
    let validate_cmd = format!("caddy validate --config {path}");
    let reload_cmd = "systemctl reload caddy".to_string();

    println!();
    run_step("caddy_fmt", &fmt_cmd, dry_run);
    run_step("caddy_validate", &validate_cmd, dry_run);
    run_step("caddy_reload", &reload_cmd, dry_run);
}

fn create_digitalocean_dns_record(
    plan: &SitePlan,
    ip: &str,
    token: &str,
    dry_run: bool,
) {
    // For DO DNS, name should be just the left label, e.g. "swift-ember"
    let name = &plan.slug;
    let domain = plan.domain;

    let body = json!({
        "type": "A",
        "name": name,
        "data": ip,
        "ttl": 3600
    });

    if dry_run {
        println!(
            "[DRY RUN] would create DO DNS record on domain `{}`: {}",
            domain,
            body
        );
        return;
    }

    println!(
        "[RUN     ] creating DO DNS A record: {}.{} -> {}",
        name, domain, ip
    );

    let client = Client::new();
    let url = format!("https://api.digitalocean.com/v2/domains/{}/records", domain);

    let resp = match client
        .post(&url)
        .bearer_auth(token)
        .json(&body)
        .send()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[ERROR   ] failed to call DO API: {e}");
            return;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().unwrap_or_default();
        eprintln!(
            "[ERROR   ] DO DNS create failed: status={} body={}",
            status, text
        );
        return;
    }

    println!("[OK      ] created DO DNS A record for {}.{}", name, domain);
}

#[derive(Parser)]
#[command(name = "mrgarvey", version, about = "ofcourse multisite provisioner helper")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Print a site plan (slug, hostname, db name) as JSON
    Plan {
        /// Optional custom slug (e.g. "my-community"); if omitted, a random slug is generated
        #[arg(long)]
        slug: Option<String>,

        /// Base domain (default: ofcourse.chat)
        #[arg(long, default_value = "ofcourse.chat")]
        domain: String,
    },

    /// Provision a new site (for now just prints the plan, later wil create DB/migrations)
    New {
        /// Base domain (default: ofcourse.chat)
        #[arg(long, default_value = "ofcourse.chat")]
        domain: String,

        /// Path to multisite.yml
        #[arg(long, default_value = "/var/discourse/shared/standalone/config/multisite.yml")]
        multisite_path: String,

        /// DigitalOcean API token (or set DO_API_TOKEN env)
        #[arg(long, env = "DO_API_TOKEN")]
        do_token: Option<String>,

        /// Droplet IP for A records (or set DO_DROPLET_IP env)
        #[arg(long, env = "DO_DROPLET_IP")]
        do_ip: Option<String>,

        /// Path to Caddyfile
        #[arg(long, default_value = "/etc/caddy/Caddyfile")]
        caddy_path: String,

        /// Caddy snippet name to import (e.g. discourse_site)
        #[arg(long, default_value = "discourse_site")]
        caddy_snippet: String,

        /// Print commands without executing them
        #[arg(long)]
        dry_run: bool,
    },

    /// Run the API server for claiming pre-provisioned sites
    Serve {
        /// Address to bind the server to (use "private" to auto-detect DO private IP)
        #[arg(long, default_value = "127.0.0.1:8080")]
        bind: String,

        /// Port to bind to (only used with --bind=private)
        #[arg(long, default_value = "8080")]
        port: u16,

        /// Path to multisite.yml
        #[arg(long, default_value = "/var/discourse/shared/standalone/config/multisite.yml")]
        multisite_path: String,

        /// Base domain (default: ofcourse.chat)
        #[arg(long, default_value = "ofcourse.chat")]
        domain: String,
    },

    /// Check how many pre-provisioned sites are available
    Status {
        /// Path to multisite.yml
        #[arg(long, default_value = "/var/discourse/shared/standalone/config/multisite.yml")]
        multisite_path: String,

        /// Base domain (default: ofcourse.chat)
        #[arg(long, default_value = "ofcourse.chat")]
        domain: String,
    },

    /// Keep the pool of pre-provisioned sites topped up (runs continuously)
    Attendance {
        /// Minimum number of unclaimed sites to maintain
        #[arg(long, default_value = "5")]
        min_unclaimed: usize,

        /// Seconds to wait between checks
        #[arg(long, default_value = "60")]
        interval: u64,

        /// Base domain (default: ofcourse.chat)
        #[arg(long, default_value = "ofcourse.chat")]
        domain: String,

        /// Path to multisite.yml
        #[arg(long, default_value = "/var/discourse/shared/standalone/config/multisite.yml")]
        multisite_path: String,

        /// DigitalOcean API token (or set DO_API_TOKEN env)
        #[arg(long, env = "DO_API_TOKEN")]
        do_token: Option<String>,

        /// Droplet IP for A records (or set DO_DROPLET_IP env)
        #[arg(long, env = "DO_DROPLET_IP")]
        do_ip: Option<String>,

        /// Path to Caddyfile
        #[arg(long, default_value = "/etc/caddy/Caddyfile")]
        caddy_path: String,

        /// Caddy snippet name to import
        #[arg(long, default_value = "discourse_site")]
        caddy_snippet: String,
    },
}

/// Shared context for the API server (empty for now, cache is file-based)
struct ApiContext;

/// Request body for claiming a site
#[derive(Deserialize, JsonSchema)]
struct ClaimRequest {
    /// Email address for the admin user
    email: String,
    /// Community name (site title)
    site_name: String,
    /// Username for the admin user
    username: String,
}

/// Response body after claiming a site
#[derive(Serialize, JsonSchema)]
struct ClaimResponse {
    /// The hostname of the claimed site
    hostname: String,
    /// The admin email
    email: String,
}

/// Claim an available pre-provisioned site
#[endpoint {
    method = POST,
    path = "/claim",
}]
async fn claim_site(
    _rqctx: RequestContext<Arc<ApiContext>>,
    body: TypedBody<ClaimRequest>,
) -> Result<HttpResponseOk<ClaimResponse>, HttpError> {
    let req = body.into_inner();

    // Load cache and find an unclaimed site
    let mut cache = SiteCache::load();
    let unclaimed = cache.find_unclaimed().cloned().ok_or_else(|| {
        HttpError::for_not_found(None, "no unclaimed sites available".to_string())
    })?;

    // Mark as claimed in cache immediately
    cache.claim_site(&unclaimed.rails_db_key);
    if let Err(e) = cache.save() {
        eprintln!("[WARN    ] failed to update cache: {}", e);
    }

    // Clone values for the background task
    let rails_db_key = unclaimed.rails_db_key.clone();
    let hostname = unclaimed.hostname.clone();
    let email = req.email.clone();
    let site_name = req.site_name.clone();
    let username = req.username.clone();

    // Spawn background task for site setup, admin creation, and password reset
    std::thread::spawn(move || {
        if let Err(e) = configure_site_sync(&rails_db_key, &site_name) {
            eprintln!("[ERROR   ] failed to configure site: {}", e);
        }
        if let Err(e) = create_admin_user_sync(&rails_db_key, &email, &username) {
            eprintln!("[ERROR   ] failed to create admin: {}", e);
            return;
        }
        if let Err(e) = trigger_password_reset_sync(&hostname, &email) {
            eprintln!("[WARN    ] failed to trigger password reset: {}", e);
        }
    });

    Ok(HttpResponseOk(ClaimResponse {
        hostname: unclaimed.hostname,
        email: req.email,
    }))
}

/// Cached site entry
#[derive(Serialize, Deserialize, Clone)]
struct CachedSite {
    rails_db_key: String,
    hostname: String,
    claimed: bool,
}

/// Site cache file structure
#[derive(Serialize, Deserialize, Default)]
struct SiteCache {
    sites: Vec<CachedSite>,
}

impl SiteCache {
    fn load() -> Self {
        fs::read_to_string(CACHE_FILE)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    fn save(&self) -> Result<(), String> {
        // Ensure directory exists
        if let Some(parent) = Path::new(CACHE_FILE).parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create cache directory: {e}"))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("failed to serialize cache: {e}"))?;
        fs::write(CACHE_FILE, json)
            .map_err(|e| format!("failed to write cache: {e}"))?;
        Ok(())
    }

    fn add_site(&mut self, rails_db_key: String, hostname: String) {
        // Don't add duplicates
        if !self.sites.iter().any(|s| s.rails_db_key == rails_db_key) {
            self.sites.push(CachedSite {
                rails_db_key,
                hostname,
                claimed: false,
            });
        }
    }

    fn claim_site(&mut self, rails_db_key: &str) -> bool {
        if let Some(site) = self.sites.iter_mut().find(|s| s.rails_db_key == rails_db_key) {
            site.claimed = true;
            true
        } else {
            false
        }
    }

    fn find_unclaimed(&self) -> Option<&CachedSite> {
        self.sites.iter().find(|s| !s.claimed)
    }

    fn stats(&self) -> (usize, usize, usize) {
        let total = self.sites.len();
        let claimed = self.sites.iter().filter(|s| s.claimed).count();
        (total, claimed, total - claimed)
    }
}

/// Configure site settings (title, disable wizard)
fn configure_site_sync(rails_db_key: &str, name: &str) -> Result<(), String> {
    let ruby_code = [
        &format!("SiteSetting.title = '{}'; ", name.replace('\'', "\\'")),
        "SiteSetting.wizard_enabled = false",
    ]
    .concat();

    let cmd = [
        "docker exec app bash -lc \"",
        "cd /var/www/discourse && ",
        &format!("RAILS_DB={} ", rails_db_key),
        "sudo -E -u discourse bundle exec rails runner \\\"",
        &ruby_code,
        "\\\"\"",
    ]
    .concat();

    let status = Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .status()
        .map_err(|e| format!("failed to configure site: {e}"))?;

    if !status.success() {
        return Err("site configuration command failed".to_string());
    }

    println!("[OK      ] site configured: title='{}', wizard disabled", name);
    Ok(())
}

/// Create an admin user for a site (sync version for background thread)
fn create_admin_user_sync(rails_db_key: &str, email: &str, username: &str) -> Result<(), String> {
    let password = generate_password();
    let admin_cmd = [
        "docker exec app bash -lc \"",
        "cd /var/www/discourse && ",
        &format!("RAILS_DB={} ", rails_db_key),
        "sudo -E -u discourse bundle exec rake admin:create <<-EOF\n",
        &format!("{email}\n"),
        &format!("{password}\n"),
        &format!("{password}\n"),
        "Y\n",
        "EOF\"",
    ]
    .concat();

    let status = Command::new("sh")
        .arg("-c")
        .arg(&admin_cmd)
        .status()
        .map_err(|e| format!("failed to create admin: {e}"))?;

    if !status.success() {
        return Err("admin creation command failed".to_string());
    }

    // Update the username (rake admin:create generates a default one)
    let ruby_code = format!(
        "user = User.find_by_email('{}'); user.update!(username: '{}') if user",
        email,
        username.replace('\'', "\\'")
    );

    let update_cmd = [
        "docker exec app bash -lc \"",
        "cd /var/www/discourse && ",
        &format!("RAILS_DB={} ", rails_db_key),
        "sudo -E -u discourse bundle exec rails runner \\\"",
        &ruby_code,
        "\\\"\"",
    ]
    .concat();

    let status = Command::new("sh")
        .arg("-c")
        .arg(&update_cmd)
        .status()
        .map_err(|e| format!("failed to update username: {e}"))?;

    if !status.success() {
        eprintln!("[WARN    ] failed to update username to {}", username);
    }

    println!("[OK      ] admin user created: {} ({})", username, email);
    Ok(())
}

/// Trigger a password reset email via Rails console (avoids CSRF issues)
fn trigger_password_reset_sync(hostname: &str, email: &str) -> Result<(), String> {
    // Extract rails_db_key from hostname (e.g., "swift-ember.ofcourse.chat" -> "swift_ember_discourse")
    let subdomain = hostname.split('.').next().unwrap_or(hostname);
    let rails_db_key = format!("{}_discourse", subdomain.replace('-', "_"));

    let ruby_code = [
        &format!("user = User.find_by_email('{}'); ", email),
        "if user; ",
        "email_token = user.email_tokens.create!(",
        "email: user.email, ",
        "scope: EmailToken.scopes[:password_reset]",
        "); ",
        "UserNotifications.forgot_password(",
        "user, ",
        "email_token: email_token.token",
        ").deliver_now; ",
        "end",
    ]
    .concat();

    let cmd = [
        "docker exec app bash -lc \"",
        "cd /var/www/discourse && ",
        &format!("RAILS_DB={} ", rails_db_key),
        "sudo -E -u discourse bundle exec rails runner \\\"",
        &ruby_code,
        "\\\"\"",
    ]
    .concat();

    let status = Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .status()
        .map_err(|e| format!("failed to trigger password reset: {e}"))?;

    if !status.success() {
        return Err("password reset command failed".to_string());
    }

    println!("[OK      ] password reset email sent to {}", email);
    Ok(())
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Plan { slug, domain } => {
            let slug = slug.unwrap_or_else(generate_slug);
            let plan = build_site_plan(&slug, &domain);
            let json = serde_json::to_string_pretty(&plan).expect("serialize plan");
            println!("{json}");
        }

        Commands::New {
            domain,
            multisite_path,
            do_token,
            do_ip,
            caddy_path,
            caddy_snippet,
            dry_run,
        } => {
            let slug = generate_slug();
            let plan = build_site_plan(&slug, &domain);

            let json = serde_json::to_string_pretty(&plan).expect("serialize plan");
            println!("{json}");
            println!();

            let db_cmd = format!(
                "docker exec app bash -lc \"sudo -u postgres createdb {db} && \
                 sudo -u postgres psql {db} <<EOF\n\
                 ALTER SCHEMA public OWNER TO discourse;\n\
                 CREATE EXTENSION IF NOT EXISTS hstore;\n\
                 CREATE EXTENSION IF NOT EXISTS pg_trgm;\n\
                 GRANT ALL PRIVILEGES ON DATABASE {db} TO discourse;\n\
EOF\"",
                db = plan.db_name
            );

            let migrate_cmd = format!(
                "docker exec app bash -lc \"cd /var/www/discourse && \
                 RAILS_DB={rails_db} sudo -E -u discourse bundle exec rake db:migrate db:seed_fu\"",
                rails_db = plan.rails_db_key
            );

            let restart_cmd = "docker exec app sv restart unicorn".to_string();

            println!("Planned commands:");

            // 1) Create DB
            run_step("create_database", &db_cmd, dry_run);

            // 2) Update multisite.yml
            println!();
            println!("multisite.yml snippet:");
            println!("{}", multisite_yaml_block(&plan));
            println!();
            update_multisite_file(&plan, &multisite_path, dry_run);

            // 3) Restart unicorn (so it picks up the new site from multisite.yml)
            run_step("restart_unicorn", &restart_cmd, dry_run);

            // 4) Migrate & seed (must happen after unicorn knows about the site)
            run_step("migrate_and_seed", &migrate_cmd, dry_run);

            // 5) Create DigitalOcean DNS record (if creds provided)
            if let (Some(token), Some(ip)) = (do_token.as_deref(), do_ip.as_deref()) {
                println!();
                create_digitalocean_dns_record(&plan, ip, token, dry_run);
            } else {
                println!();
                println!("[INFO    ] skipping DO DNS creation (no token or IP provided)");
            }

            // 6) Caddyfile update + reload
            println!();
            update_caddyfile(&plan, &caddy_path, &caddy_snippet, dry_run);
            reload_caddy(&caddy_path, dry_run);

            // Add to cache (unless dry run)
            if !dry_run {
                let mut cache = SiteCache::load();
                cache.add_site(plan.rails_db_key.clone(), plan.hostname.clone());
                if let Err(e) = cache.save() {
                    eprintln!("[WARN    ] failed to update cache: {}", e);
                }
            }

            println!();
            println!("[INFO    ] Site pre-provisioned (no admin user yet)");
            println!("           Use `mrgarvey serve` and POST /claim to assign an admin");
        }

        Commands::Serve {
            bind,
            port,
            multisite_path: _,
            domain: _,
        } => {
            // Resolve bind address (support "private" for DO private IP)
            let bind_addr = if bind == "private" {
                let ip = get_do_private_ip().expect("failed to get DO private IP");
                format!("{}:{}", ip, port)
            } else {
                bind
            };

            // Run the async server
            let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
            rt.block_on(async {
                run_server(&bind_addr).await.expect("server failed");
            });
        }

        Commands::Status {
            multisite_path: _,
            domain: _,
        } => {
            let cache = SiteCache::load();
            let (total, claimed, unclaimed) = cache.stats();

            println!("Site Status (from cache):");
            println!("  Total sites:     {}", total);
            println!("  Claimed:         {}", claimed);
            println!("  Unclaimed:       {}", unclaimed);

            if total == 0 {
                println!();
                println!("⚠️  Cache is empty. Run `mrgarvey new` to provision sites.");
            } else if unclaimed == 0 {
                println!();
                println!("⚠️  No unclaimed sites available. Run `mrgarvey new` to provision more.");
            }
        }

        Commands::Attendance {
            min_unclaimed,
            interval,
            domain,
            multisite_path,
            do_token,
            do_ip,
            caddy_path,
            caddy_snippet,
        } => {
            println!("[ATTENDANCE] Starting roll call...");
            println!("[ATTENDANCE] Maintaining {} unclaimed sites", min_unclaimed);
            println!("[ATTENDANCE] Checking every {} seconds", interval);
            println!();

            loop {
                let cache = SiteCache::load();
                let (total, claimed, unclaimed) = cache.stats();

                println!(
                    "[ATTENDANCE] Roll call: {} total, {} claimed, {} unclaimed",
                    total, claimed, unclaimed
                );

                if unclaimed < min_unclaimed {
                    let needed = min_unclaimed - unclaimed;
                    println!(
                        "[ATTENDANCE] Need {} more sites, provisioning 1...",
                        needed
                    );

                    // Provision one site at a time to avoid overwhelming the server
                    provision_site(
                        &domain,
                        &multisite_path,
                        do_token.as_deref(),
                        do_ip.as_deref(),
                        &caddy_path,
                        &caddy_snippet,
                    );
                } else {
                    println!("[ATTENDANCE] Pool is healthy, all seats filled.");
                }

                std::thread::sleep(std::time::Duration::from_secs(interval));
            }
        }
    }
}

/// Fetch the DigitalOcean droplet's private IP from the metadata service
fn get_do_private_ip() -> Result<String, String> {
    let client = Client::new();
    let resp = client
        .get("http://169.254.169.254/metadata/v1/interfaces/private/0/ipv4/address")
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .map_err(|e| format!("failed to fetch DO metadata: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("DO metadata returned status {}", resp.status()));
    }

    let ip = resp.text().map_err(|e| format!("failed to read response: {e}"))?;
    Ok(ip.trim().to_string())
}

async fn run_server(bind: &str) -> Result<(), String> {
    let log = ConfigLogging::StderrTerminal {
        level: ConfigLoggingLevel::Info,
    }
    .to_logger("mrgarvey")
    .map_err(|e| e.to_string())?;

    let mut api = ApiDescription::new();
    api.register(claim_site).expect("failed to register claim_site endpoint");

    let ctx = Arc::new(ApiContext);

    let addr: SocketAddr = bind.parse().map_err(|e| format!("invalid bind address: {e}"))?;

    let server = ServerBuilder::new(api, ctx, log)
        .config(ConfigDropshot {
            bind_address: addr,
            ..Default::default()
        })
        .start()
        .map_err(|e| format!("failed to start server: {e}"))?;

    println!("[INFO    ] mrgarvey API server listening on {}", bind);
    server.await
}

/// Provision a new site (used by both `new` command and `attendance`)
fn provision_site(
    domain: &str,
    multisite_path: &str,
    do_token: Option<&str>,
    do_ip: Option<&str>,
    caddy_path: &str,
    caddy_snippet: &str,
) {
    let slug = generate_slug();
    let plan = build_site_plan(&slug, domain);

    println!("[PROVISION] Creating site: {}", plan.hostname);

    let db_cmd = format!(
        "docker exec app bash -lc \"sudo -u postgres createdb {db} && \
         sudo -u postgres psql {db} <<EOF\n\
         ALTER SCHEMA public OWNER TO discourse;\n\
         CREATE EXTENSION IF NOT EXISTS hstore;\n\
         CREATE EXTENSION IF NOT EXISTS pg_trgm;\n\
         GRANT ALL PRIVILEGES ON DATABASE {db} TO discourse;\n\
EOF\"",
        db = plan.db_name
    );

    let migrate_cmd = format!(
        "docker exec app bash -lc \"cd /var/www/discourse && \
         RAILS_DB={rails_db} sudo -E -u discourse bundle exec rake db:migrate db:seed_fu\"",
        rails_db = plan.rails_db_key
    );

    let restart_cmd = "docker exec app sv restart unicorn".to_string();

    // 1) Create DB
    run_step("create_database", &db_cmd, false);

    // 2) Update multisite.yml
    update_multisite_file(&plan, multisite_path, false);

    // 3) Restart unicorn (so it picks up the new site from multisite.yml)
    run_step("restart_unicorn", &restart_cmd, false);

    // 4) Migrate & seed (must happen after unicorn knows about the site)
    run_step("migrate_and_seed", &migrate_cmd, false);

    // 5) Create DigitalOcean DNS record (if creds provided)
    if let (Some(token), Some(ip)) = (do_token, do_ip) {
        create_digitalocean_dns_record(&plan, ip, token, false);
    }

    // 6) Caddyfile update + reload
    update_caddyfile(&plan, caddy_path, caddy_snippet, false);
    reload_caddy(caddy_path, false);

    // Add to cache
    let mut cache = SiteCache::load();
    cache.add_site(plan.rails_db_key.clone(), plan.hostname.clone());
    if let Err(e) = cache.save() {
        eprintln!("[WARN    ] failed to update cache: {}", e);
    }

    println!("[PROVISION] Site {} ready", plan.hostname);
}

/// Run a shell command, or just print it if dry_run is true.
fn run_step(name: &str, cmd: &str, dry_run: bool) {
    if dry_run {
        println!("[DRY RUN] {name}: {cmd}");
        return;
    }

    println!("[RUN     ] {name}: {cmd}");
    let status = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .status();

    match status {
        Ok(s) if s.success() => {
            println!("[OK      ] {name}");
        }
        Ok(s) => {
            eprintln!("[ERROR   ] {name}: command exited with status {s}");
        }
        Err(e) => {
            eprintln!("[ERROR   ] {name}: failed to spawn command: {e}");
        }
    }
}
