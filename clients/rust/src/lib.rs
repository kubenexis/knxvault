use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;

#[derive(Clone)]
pub struct Client {
    base_url: String,
    token: String,
    http: reqwest::Client,
}

impl Client {
    pub fn new(base_url: Option<&str>, token: Option<&str>) -> Self {
        Self {
            base_url: base_url
                .or_else(|| env::var("KNXVAULT_ADDR").ok().as_deref())
                .unwrap_or("http://localhost:8200")
                .trim_end_matches('/')
                .to_string(),
            token: token
                .or_else(|| env::var("KNXVAULT_TOKEN").ok().as_deref())
                .unwrap_or("")
                .to_string(),
            http: reqwest::Client::new(),
        }
    }

    pub async fn health(&self) -> Result<Value, reqwest::Error> {
        self.get_json("/health", false).await
    }

    pub async fn kv_put(&self, path: &str, data: Value) -> Result<(), reqwest::Error> {
        let body = serde_json::json!({ "data": data });
        let _: Value = self
            .post_json(&format!("/secrets/kv/{}", path.trim_start_matches('/')), body)
            .await?;
        Ok(())
    }

    pub async fn kv_get(&self, path: &str) -> Result<KVResponse, reqwest::Error> {
        self.get_json(&format!("/secrets/kv/{}", path.trim_start_matches('/')), true)
            .await
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(&self, path: &str, auth: bool) -> Result<T, reqwest::Error> {
        let mut req = self.http.get(format!("{}{}", self.base_url, path));
        if auth && !self.token.is_empty() {
            req = req.header(AUTHORIZATION, format!("Bearer {}", self.token));
        }
        req.send().await?.error_for_status()?.json().await
    }

    async fn post_json<T: for<'de> Deserialize<'de>, B: Serialize>(
        &self,
        path: &str,
        body: B,
    ) -> Result<T, reqwest::Error> {
        let mut req = self
            .http
            .post(format!("{}{}", self.base_url, path))
            .header(CONTENT_TYPE, "application/json");
        if !self.token.is_empty() {
            req = req.header(AUTHORIZATION, format!("Bearer {}", self.token));
        }
        req.json(&body).send().await?.error_for_status()?.json().await
    }
}

#[derive(Debug, Deserialize)]
pub struct KVResponse {
    pub data: Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn health_rejects_closed_port() {
        let client = Client::new(Some("http://127.0.0.1:1"), None);
        assert!(client.health().await.is_err());
    }
}