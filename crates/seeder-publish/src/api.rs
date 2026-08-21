use std::collections::HashMap;
use std::sync::Mutex;
use url::Url;

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("zone not found: {0}")]
    ZoneNotFound(String),
    #[error("too many zones: {0}")]
    TooManyZones(String),
    #[error("api error: {0}")]
    Api(String),
}

#[derive(Debug, Deserialize)]
struct CfResponse<T> {
    result: Vec<T>,
    #[serde(rename = "result_info")]
    result_info: Option<CfResultInfo>,
    success: bool,
    errors: Vec<CfError>,
}

#[derive(Debug, Deserialize)]
struct CfResultInfo {
    total_pages: usize,
}

#[derive(Debug, Deserialize)]
struct CfError {
    #[allow(dead_code)]
    code: usize,
    #[allow(dead_code)]
    message: String,
}

#[derive(Debug, Deserialize)]
struct DnsRecord {
    id: String,
    #[allow(dead_code)]
    #[serde(rename = "type")]
    record_type: String,
    #[allow(dead_code)]
    name: String,
    content: String,
}

#[derive(Debug, Serialize)]
struct NewDnsRecord {
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    content: String,
    ttl: Option<u32>,
}

pub struct CloudflareSeeder {
    client: reqwest::Client,
    api_token: String,
    domain: String,
    prefix: String,
    zone_id: Mutex<Option<String>>,
}

impl CloudflareSeeder {
    pub fn new(api_token: String, domain: String, prefix: String) -> Self {
        CloudflareSeeder {
            client: reqwest::Client::new(),
            api_token,
            domain,
            prefix,
            zone_id: Mutex::new(None),
        }
    }

    async fn zone_id(&self) -> Result<String, Error> {
        if let Some(ref id) = *self.zone_id.lock().unwrap() {
            return Ok(id.clone());
        }

        let url = Url::parse_with_params(
            "https://api.cloudflare.com/client/v4/zones",
            &[("name", &self.domain)],
        )
        .map_err(|e| Error::Api(format!("url: {e}")))?;
        let resp: CfResponse<HashMap<String, serde_json::Value>> = self
            .client
            .get(url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .header("Content-Type", "application/json")
            .send()
            .await?
            .json()
            .await?;

        if !resp.success {
            return Err(Error::Api(format!("{:?}", resp.errors)));
        }
        if resp.result.is_empty() {
            return Err(Error::ZoneNotFound(self.domain.clone()));
        }
        if resp.result.len() > 1 {
            return Err(Error::TooManyZones(self.domain.clone()));
        }

        let id = resp.result[0]
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Api("missing zone id".into()))?
            .to_string();
        *self.zone_id.lock().unwrap() = Some(id.clone());
        Ok(id)
    }

    pub async fn get_seeds(&self, flags: bool) -> Result<Vec<String>, Error> {
        let zone_id = self.zone_id().await?;
        let name = if flags {
            format!("x9.{}.{}", self.prefix, self.domain)
        } else {
            format!("{}.{}", self.prefix, self.domain)
        };

        let mut page = 0usize;
        let mut all_records = Vec::new();
        loop {
            page += 1;
            let url = Url::parse_with_params(
                &format!(
                    "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
                ),
                &[
                    ("name", name.as_str()),
                    ("type", "A,AAAA"),
                    ("per_page", "10"),
                    ("page", &page.to_string()),
                ],
            )
            .map_err(|e| Error::Api(format!("url: {e}")))?;
            let resp: CfResponse<DnsRecord> = self
                .client
                .get(url)
                .header("Authorization", format!("Bearer {}", self.api_token))
                .send()
                .await?
                .json()
                .await?;

            all_records.extend(resp.result);
            let total = resp.result_info.map(|r| r.total_pages).unwrap_or(0);
            if page >= total {
                break;
            }
        }

        Ok(all_records.into_iter().map(|r| r.content).collect())
    }

    pub async fn set_seed(&self, ip: &str, flags: bool, ttl: Option<u32>) -> Result<(), Error> {
        let zone_id = self.zone_id().await?;

        let is_v6 = ip.contains(':');
        let record_type = if is_v6 { "AAAA" } else { "A" };

        let name = if flags {
            format!("x9.{}.{}", self.prefix, self.domain)
        } else {
            format!("{}.{}", self.prefix, self.domain)
        };

        let record = NewDnsRecord {
            name,
            record_type: record_type.to_string(),
            content: ip.to_string(),
            ttl,
        };

        let resp = self
            .client
            .post(format!(
                "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
            ))
            .header("Authorization", format!("Bearer {}", self.api_token))
            .json(&record)
            .send()
            .await?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(Error::Api(text));
        }

        Ok(())
    }

    pub async fn delete_seeds(&self, ips: &[String]) -> Result<(), Error> {
        let zone_id = self.zone_id().await?;

        // Get all records and delete matching ones
        for flags in &[false, true] {
            let name = if *flags {
                format!("x9.{}.{}", self.prefix, self.domain)
            } else {
                format!("{}.{}", self.prefix, self.domain)
            };

            let mut page = 0usize;
            loop {
                page += 1;
                let url = Url::parse_with_params(
                    &format!(
                        "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
                    ),
                    &[
                        ("name", name.as_str()),
                        ("type", "A,AAAA"),
                        ("per_page", "10"),
                        ("page", &page.to_string()),
                    ],
                )
                .map_err(|e| Error::Api(format!("url: {e}")))?;
                let resp: CfResponse<DnsRecord> = self
                    .client
                    .get(url)
                    .header("Authorization", format!("Bearer {}", self.api_token))
                    .send()
                    .await?
                    .json()
                    .await?;

                for record in &resp.result {
                    if ips.contains(&record.content) {
                        self.client
                            .delete(format!(
                                "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{}",
                                record.id
                            ))
                            .header("Authorization", format!("Bearer {}", self.api_token))
                            .send()
                            .await?;
                    }
                }

                let total = resp.result_info.map(|r| r.total_pages).unwrap_or(0);
                if page >= total {
                    break;
                }
            }
        }

        Ok(())
    }
}
