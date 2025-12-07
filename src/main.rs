use std::process::Command;

use clap::{Parser, Subcommand};
use rand::seq::SliceRandom;
use rand::thread_rng;
use serde::Serialize;

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

        Commands::New { domain, dry_run } => {
            let slug = generate_slug();
            let plan = build_site_plan(&slug, &domain);

            // Print the plan as JSON first

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

            let restart_cmd =
                "docker exec app sv restart unicorn".to_string();

            println!("Planned commands:");
            run_step("create_database", &db_cmd, dry_run);
            run_step("migrate_and_seed", &migrate_cmd, dry_run);
            run_step("restart_unicorn", &restart_cmd, dry_run);

            println!();
            println!("multisite.yml snippet:");
            println!("{}", multisite_yaml_block(&plan));
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
