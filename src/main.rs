use clap::Parser;
use shadowmap::{run, Args};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    run(args).await.map(|_| ())
}
