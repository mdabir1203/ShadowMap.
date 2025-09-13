use std::collections::{HashMap, HashSet};

pub async fn check_subdomain_takeover(subs: &HashSet<String>) -> HashMap<String, Vec<String>> {
    let mut result = HashMap::new();
    let takeover_patterns = vec![
        ("heroku", "Heroku App"),
        ("s3", "AWS S3"),
        ("azure", "Microsoft Azure"),
        ("cloudfront", "AWS CloudFront"),
        ("github", "GitHub Pages"),
        ("firebase", "Firebase"),
        ("netlify", "Netlify"),
        ("vercel", "Vercel"),
    ];

    for sub in subs.iter() {
        let sub_lower = sub.to_lowercase();
        let mut vulnerabilities = Vec::new();

        for (pattern, service) in &takeover_patterns {
            if sub_lower.contains(pattern) {
                vulnerabilities.push(format!("Potential {} takeover", service));
            }
        }

        if !vulnerabilities.is_empty() {
            result.insert(sub.clone(), vulnerabilities);
        }
    }
    result
}
