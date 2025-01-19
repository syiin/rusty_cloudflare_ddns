use reqwest::{header, Client};
use serde::{Deserialize, Serialize};
use std::env;
use std::error::Error;
use std::time::Duration;
use tokio::time;

#[derive(Serialize)]
struct DnsUpdate {
    comment: String,
    content: String,
    name: String,
    proxied: bool,
    ttl: u32,
    #[serde(rename = "type")]
    record_type: String,
}

#[derive(Deserialize)]
struct CloudflareResponse {
    success: bool,
    errors: Vec<CloudflareError>,
}

#[derive(Deserialize)]
struct CloudflareError {
    code: i32,
    message: String,
}

async fn get_public_ip() -> Result<String, Box<dyn Error>> {
    let response = reqwest::get("https://api.ipify.org").await?;
    Ok(response.text().await?)
}

async fn update_dns(
    client: &Client,
    ip: &str,
    zone_id: &str,
    record_id: &str,
    domain: &str,
) -> Result<bool, Box<dyn Error>> {
    let update = DnsUpdate {
        comment: "Dynamic DNS update".to_string(),
        content: ip.to_string(),
        name: domain.to_string(),
        proxied: false,
        ttl: 3600,
        record_type: "A".to_string(),
    };

    let response = client
        .patch(&format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
            zone_id, record_id
        ))
        .json(&update)
        .send()
        .await?;

    let cloudflare_response: CloudflareResponse = response.json().await?;

    if !cloudflare_response.success {
        for error in cloudflare_response.errors {
            eprintln!("Cloudflare error {}: {}", error.code, error.message);
        }
        return Ok(false);
    }

    Ok(true)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Load environment variables
    dotenv::dotenv().ok();

    let api_key = env::var("CLOUDFLARE_API_KEY")?;
    let zone_id = env::var("ZONE_ID")?;
    let record_id = env::var("DNS_RECORD_ID")?;
    let domain = env::var("DOMAIN")?;

    // Create HTTP client with headers
    let mut headers = header::HeaderMap::new();
    headers.insert(
        "Authorization",
        header::HeaderValue::from_str(&format!("Bearer {}", api_key))?,
    );
    headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );

    let client = Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(10))
        .build()?;

    let mut interval = time::interval(Duration::from_secs(600)); // 10 minutes
    let mut last_ip = String::new();

    println!("Starting Cloudflare DDNS updater for {}", domain);

    loop {
        interval.tick().await;

        match get_public_ip().await {
            Ok(current_ip) => {
                if current_ip != last_ip {
                    println!("IP changed from {} to {}", last_ip, current_ip);

                    match update_dns(&client, &current_ip, &zone_id, &record_id, &domain).await {
                        Ok(true) => {
                            println!("Successfully updated DNS record");
                            last_ip = current_ip;
                        }
                        Ok(false) => println!("Failed to update DNS record"),
                        Err(e) => eprintln!("Error updating DNS record: {}", e),
                    }
                }
            }
            Err(e) => eprintln!("Error getting public IP: {}", e),
        }
    }
}
