use once_cell::sync::Lazy;
use regex::Regex;
use std::time::Duration;

pub const COMMON_PORTS: &[u16] = &[
    21, 22, 25, 80, 443, 3306, 8080, 8443, 3389, 5432, 27017, 9200, 9300,
];

pub const DNS_TIMEOUT: Duration = Duration::from_secs(5);

pub static USER_AGENTS: Lazy<Vec<&'static str>> = Lazy::new(|| {
    vec![
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    ]
});

pub static SUBDOMAIN_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-z0-9][-a-z0-9\.]*[a-z0-9]\.([a-z0-9-]+\.)*[a-z0-9]+$").unwrap());

pub static IP_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$").unwrap());

pub static CLOUD_SAAS_PATTERNS: Lazy<Vec<(&'static str, Regex)>> = Lazy::new(|| {
    vec![
        (
            "AWS S3",
            Regex::new(r"^[a-z0-9-]+\.s3\.amazonaws\.com$").unwrap(),
        ),
        (
            "Azure Blob",
            Regex::new(r"^[a-z0-9-]+\.blob\.core\.windows\.net$").unwrap(),
        ),
        (
            "GCP Storage",
            Regex::new(r"^[a-z0-9-]+\.storage\.googleapis\.com$").unwrap(),
        ),
        (
            "Heroku",
            Regex::new(r"^[a-z0-9-]+\.herokuapp\.com$").unwrap(),
        ),
        (
            "Netlify",
            Regex::new(r"^[a-z0-9-]+\.netlify\.app$").unwrap(),
        ),
        (
            "Shopify",
            Regex::new(r"^[a-z0-9-]+\.myshopify\.com$").unwrap(),
        ),
        ("Vercel", Regex::new(r"^[a-z0-9-]+\.vercel\.app$").unwrap()),
        ("Firebase", Regex::new(r"^[a-z0-9-]+\.web\.app$").unwrap()),
    ]
});
