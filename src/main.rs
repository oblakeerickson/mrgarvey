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
    let db_name = format!("ms_{db_safe}");
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
        domain: String
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

        Commands::New { domain } => {
            // For now, "new" just generates a random plan.
            // Later this will:
            //  - docker exec to create DB
            //  - update multisite.yml
            //  - run migrations
            //  - restart unicorn
            let slug = generate_slug();
            let plan = build_site_plan(&slug, &domain);
            let json = serde_json::to_string_pretty(&plan).expect("serialize plan");
            println!("{json}");
        }
    }

}
