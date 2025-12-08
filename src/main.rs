use std::process::Command;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use clap::{Parser, Subcommand};
use rand::seq::SliceRandom;
use rand::thread_rng;
use serde::Serialize;
use serde_json::json;
use reqwest::blocking::Client;

const ADJECTIVES: &[&str] = &[
    "fancy", "bright", "quiet", "lucky", "golden", "rusty", "brave", "clever", "calm", "swift",
];

const NOUNS: &[&str] = &[
    "honey", "river", "maple", "pine", "sparrow", "aurora", "prairie", "summit", "ember", "canyon",
];

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

fn update_caddyfile(plan: &SitePlan, path: &str, dry_run: bool) {
    let path_obj = Path::new(path);
    let contents = match fs::read_to_string(path_obj) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[ERROR   ] could not read Caddyfile {path}: {e}");
            return;
        }
    };

    let mut lines: Vec<String> = contents.lines().map(|l| l.to_string()).collect();
    let mut changed = false;
    let new_host = format!("{}.{}", plan.slug, plan.domain);

    // Find the server block hosting Discourse (by reverse_proxy target)
    for i in 0..lines.len() {
        if lines[i].contains("reverse_proxy 127.0.0.1:8080") {
            if i == 0 {
                eprintln!("[ERROR   ] Caddyfile format unexpected (reverse_proxy on first line)");
                break;
            }

            let host_line = &mut lines[i - 1];
            // host line looks like: "multisite01.ofcourse.chat, try.ofcourse.chat, swift-ember.ofcourse.chat {"
            let brace_pos = host_line.find('{').unwrap_or(host_line.len());
            let (hosts_part, rest) = host_line.split_at(brace_pos);
            let hosts_trimmed = hosts_part.trim_end();

            if hosts_trimmed.contains(&new_host) {
                println!("[INFO    ] Caddyfile already contains host `{}`; skipping.", new_host);
                return;
            }

            let updated_hosts = if hosts_trimmed.is_empty() {
                new_host.clone()
            } else {
                format!("{}, {}", hosts_trimmed, new_host)
            };

            let new_line = format!("{}{}", updated_hosts, rest);
            if dry_run {
                println!("[DRY RUN] would update Caddyfile host line:");
                println!("  from: {}", host_line);
                println!("  to:   {}", new_line);
            } else {
                println!("[RUN     ] updating Caddyfile host line:");
                println!("  from: {}", host_line);
                println!("  to:   {}", new_line);
                *host_line = new_line;
                changed = true;
            }

            break;
        }
    }

    if !changed {
        if !dry_run {
            // changed = false also when host already existed or error; we already logged those
        }
        return;
    }

    if dry_run {
        println!("[DRY RUN] would write updated Caddyfile to {path}");
        return;
    }

    let new_contents = lines.join("\n");
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

        /// Path to multisite.yml (local dev default; on server you'll point to the real file)
        #[arg(long, default_value = "multisite.yml")]
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

        /// Print commands without executing them
        #[arg(long)]
        dry_run: bool,
    },
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

            // 3) Migrate & seed
            run_step("migrate_and_seed", &migrate_cmd, dry_run);

            // 4) Restart unicorn
            run_step("restart_unicorn", &restart_cmd, dry_run);

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
            update_caddyfile(&plan, &caddy_path, dry_run);
            reload_caddy(&caddy_path, dry_run);
        }
    }
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
