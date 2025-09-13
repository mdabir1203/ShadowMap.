use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Target domain to perform subdomain enumeration on
    #[arg(short, long, default_value = "example.com")]
    pub domain: String,

    /// Maximum number of concurrent connections
    #[arg(short, long, default_value = "50")]
    pub concurrency: usize,

    /// Request timeout in seconds
    #[arg(short, long, default_value = "10")]
    pub timeout: u64,

    /// Number of retries for failed requests
    #[arg(short, long, default_value = "3")]
    pub retries: usize,
}
