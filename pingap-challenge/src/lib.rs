// Copyright 2024-2025 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::fingerprint::{CalculateFlags, Fingerprint};
use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use chrono::Utc;
use cookie::{Cookie, SameSite};
use ctor::ctor;
use hmac::{Hmac, Mac};
use http::header::{self, HeaderValue};
use http::StatusCode;
use pingap_config::PluginConf;
use pingap_core::{
    get_cookie_value, new_internal_error, now_sec, Ctx, HttpResponse, Plugin,
    PluginStep, RequestPluginResult, TtlLruLimit,
};
use pingap_plugin::{
    get_duration_conf, get_hash_key, get_int_conf, get_plugin_factory,
    get_str_conf, Error,
};
use pingora::proxy::Session;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info};
use uuid::{ContextV7, Timestamp, Uuid};

/// The embedded HTML content for the challenge page.
const CHALLENGE_HTML: &str = include_str!("assets/challenge.html");
const CHALLENGE_FINGERPRINT_JS: &str =
    include_str!("assets/fingerprint.min.js");
const CHALLENGE_CRYPTO_JS: &str = include_str!("assets/crypto-js.min.js");
/// The default name for the challenge cookie if not specified in the configuration.
const DEFAULT_COOKIE_NAME: &str = "pingap_challenge";
/// The default fingerprint score threshold required to pass the challenge.
const DEFAULT_THRESHOLD: i32 = 60;
/// The time-to-live for a nonce in seconds to prevent replay attacks.
const NONCE_TTL_SECS: u64 = 10;

type HmacSha256 = Hmac<Sha256>;
type Result<T, E = Error> = std::result::Result<T, E>;

/// Main struct for the Challenge plugin, holding its configuration.
pub struct Challenge {
    hash_value: String,
    cookie_name: String,
    ttl: Option<Duration>,
    url: String,
    threshold: i32,
    nonce_limit: TtlLruLimit,
    nonce_ttl: Duration,
    secret_hmac: HmacSha256,
}

impl TryFrom<&PluginConf> for Challenge {
    type Error = Error;
    fn try_from(conf: &PluginConf) -> Result<Self> {
        debug!(params = conf.to_string(), "new challenge plugin");

        let secret = get_str_conf(conf, "secret");
        if secret.is_empty() {
            return Err(Error::Invalid {
                category: "challenge".to_string(),
                message: "secret is required".to_string(),
            });
        }

        let url = get_str_conf(conf, "url");
        if url.is_empty() {
            return Err(Error::Invalid {
                category: "challenge".to_string(),
                message: "url is required".to_string(),
            });
        }

        let ttl = get_duration_conf(conf, "ttl");
        let threshold = get_int_conf(conf, "threshold") as i32;
        let mut cookie_name = get_str_conf(conf, "cookie_name");
        if cookie_name.is_empty() {
            cookie_name = DEFAULT_COOKIE_NAME.to_string();
        }

        let nonce_ttl = get_duration_conf(conf, "nonce_ttl")
            .unwrap_or(Duration::from_secs(NONCE_TTL_SECS));

        Ok(Self {
            hash_value: get_hash_key(conf),
            cookie_name,
            secret_hmac: HmacSha256::new_from_slice(secret.as_bytes())
                .map_err(|e| Error::Invalid {
                    category: "challenge".to_string(),
                    message: e.to_string(),
                })?,
            ttl,
            url,
            threshold: if threshold > 0 {
                threshold
            } else {
                DEFAULT_THRESHOLD
            },
            nonce_ttl,
            nonce_limit: TtlLruLimit::new(
                1024,
                Duration::from_secs(nonce_ttl.as_secs()),
                1,
            ),
        })
    }
}

/// Represents the JSON payload sent from the client after solving the challenge.
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
struct ChallengeSignParams {
    fingerprint: String,
    nonce: String,
    signature: String,
    elapsed: u32,
}

impl Challenge {
    /// Public constructor for the Challenge plugin.
    pub fn new(params: &PluginConf) -> Result<Self> {
        Self::try_from(params)
    }

    /// Signs the given data using HMAC-SHA256 with the configured secret.
    fn sign(&self, data: &[u8]) -> Result<String> {
        let mut mac = self.secret_hmac.clone();
        mac.update(data);
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    /// Verifies a hex-encoded signature against the given data.
    fn verify_signature(&self, data: &[u8], expected_hex: &str) -> Result<()> {
        let signature = self.sign(data)?;
        if signature != expected_hex {
            return Err(Error::Invalid {
                category: "signature".to_string(),
                message: "invalid signature".to_string(),
            });
        }
        Ok(())
    }

    /// Parses and validates the challenge cookie from the request headers.
    fn validate_cookie(&self, session: &Session) -> Result<()> {
        let cookie_value =
            get_cookie_value(session.req_header(), &self.cookie_name)
                .ok_or_else(|| Error::Invalid {
                    category: "cookie".to_string(),
                    message: "cookie not found".to_string(),
                })?;

        let (uuid_str, signature) =
            cookie_value.split_once('.').ok_or_else(|| Error::Invalid {
                category: "cookie".to_string(),
                message: "invalid cookie format".to_string(),
            })?;

        let uuid = Uuid::parse_str(uuid_str).map_err(|e| Error::Invalid {
            category: "cookie".to_string(),
            message: e.to_string(),
        })?;

        self.verify_signature(uuid_str.as_bytes(), signature)?;

        if let Some(ttl) = self.ttl {
            let (ts, _) = uuid
                .get_timestamp()
                .ok_or_else(|| Error::Invalid {
                    category: "cookie".to_string(),
                    message: "invalid cookie timestamp".to_string(),
                })?
                .to_unix();

            if ts + ttl.as_secs() < now_sec() {
                return Err(Error::Invalid {
                    category: "cookie".to_string(),
                    message: "cookie is expired".to_string(),
                });
            }
        }
        Ok(())
    }

    /// Generates and returns the challenge HTML page.
    fn handle_challenge_html(&self) -> pingora::Result<RequestPluginResult> {
        let nonce = new_uuid_v7().to_string();
        let signature = self
            .sign(nonce.as_bytes())
            .map_err(|e| new_internal_error(500, e.to_string()))?;

        let config_json = json!({
            "nonce": nonce,
            "signature": signature,
        })
        .to_string();

        let html = CHALLENGE_HTML
            .replace("__CHALLENGE_CONFIG__", &config_json)
            .replace("__CHALLENGE_JS__", CHALLENGE_FINGERPRINT_JS)
            .replace("__CHALLENGE_CRYPTO_JS__", CHALLENGE_CRYPTO_JS);
        Ok(RequestPluginResult::Respond(HttpResponse::html(html)))
    }

    /// Handles the POST request from the client containing the solved challenge (fingerprint).
    async fn handle_challenge_response(
        &self,
        session: &mut Session,
    ) -> pingora::Result<RequestPluginResult> {
        let body = get_request_body(session).await?;
        let params: ChallengeSignParams = serde_json::from_slice(&body)
            .map_err(|e| new_internal_error(500, e.to_string()))?;

        // 1. Verify the nonce to prevent replay attacks.
        self.verify_nonce(&params.nonce, &params.signature)
            .map_err(|e| new_internal_error(500, e.to_string()))?;

        if !self.nonce_limit.validate(&params.nonce) {
            return Err(new_internal_error(500, "nonce is expired"));
        }
        self.nonce_limit.inc(&params.nonce);

        let fingerprint_data =
            decrypt::decrypt(&params.fingerprint, &params.nonce)
                .map_err(|e| new_internal_error(500, e.to_string()))?;
        // 2. Calculate the fingerprint score.
        let fingerprint: Fingerprint = serde_json::from_str(&fingerprint_data)
            .map_err(|e| new_internal_error(500, e.to_string()))?;
        let result = fingerprint.calculate_score(&CalculateFlags::default());

        // 3. Check if the score meets the threshold.
        if result.score >= self.threshold {
            // Success: build and send a verification cookie.
            let (cookie_header, cookie_value) = self
                .build_success_cookie()
                .map_err(|e| new_internal_error(500, e.to_string()))?;
            let resp = HttpResponse::builder(StatusCode::NO_CONTENT)
                .header((cookie_header, cookie_value))
                .finish();
            Ok(RequestPluginResult::Respond(resp))
        } else {
            // Failure: log the reasons and respond with an error.
            error!(
                score = result.score,
                reasons = result.reasons.join(","),
                "fingerprint score is too low"
            );
            Ok(RequestPluginResult::Respond(HttpResponse::unknown_error(
                "invalid fingerprint".as_bytes(),
            )))
        }
    }

    /// Validates the nonce from the client by checking its signature and timestamp (TTL).
    fn verify_nonce(&self, nonce_str: &str, signature: &str) -> Result<()> {
        self.verify_signature(nonce_str.as_bytes(), signature)?;
        let nonce = Uuid::parse_str(nonce_str).map_err(|e| Error::Invalid {
            category: "nonce".to_string(),
            message: e.to_string(),
        })?;
        let (ts, _) = nonce
            .get_timestamp()
            .ok_or_else(|| Error::Invalid {
                category: "nonce".to_string(),
                message: "invalid nonce timestamp".to_string(),
            })?
            .to_unix();

        if ts.abs_diff(now_sec()) > self.nonce_ttl.as_secs() {
            return Err(Error::Invalid {
                category: "nonce".to_string(),
                message: "nonce is expired".to_string(),
            });
        }
        Ok(())
    }

    /// Creates the `Set-Cookie` header and value for a successfully verified client.
    fn build_success_cookie(
        &self,
    ) -> Result<(header::HeaderName, HeaderValue)> {
        let uuid = new_uuid_v7().to_string();
        let signature = self.sign(uuid.as_bytes())?;

        let mut cookie_builder =
            Cookie::build((&self.cookie_name, format!("{uuid}.{signature}")))
                .path("/")
                .http_only(true)
                .same_site(SameSite::Strict);

        if let Some(ttl) = self.ttl {
            cookie_builder = cookie_builder
                .max_age(cookie::time::Duration::seconds(ttl.as_secs() as i64));
        }

        let cookie = cookie_builder.build();
        let value =
            HeaderValue::from_str(&cookie.to_string()).map_err(|e| {
                Error::Invalid {
                    category: "cookie".to_string(),
                    message: e.to_string(),
                }
            })?;
        Ok((header::SET_COOKIE, value))
    }
}

#[async_trait]
impl Plugin for Challenge {
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        _ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if step != PluginStep::Request {
            return Ok(RequestPluginResult::Skipped);
        }

        if session.req_header().uri.path() == self.url {
            return match session.req_header().method {
                http::Method::POST => {
                    self.handle_challenge_response(session).await
                },
                _ => self.handle_challenge_html(),
            };
        }

        if let Err(e) = self.validate_cookie(session) {
            info!(
                cookie = &self.cookie_name,
                error = e.to_string(),
                "cookie validation failed, redirecting to challenge"
            );
            let redirect_url = format!(
                "{}?url={}",
                self.url,
                urlencoding::encode(&session.req_header().uri.to_string())
            );
            return Ok(RequestPluginResult::Respond(HttpResponse::redirect(
                &redirect_url,
            )?));
        }

        Ok(RequestPluginResult::Continue)
    }
}

/// Generates a new version 7 UUID based on the current time.
fn new_uuid_v7() -> Uuid {
    let now = Utc::now();
    let ts = Timestamp::from_unix(
        ContextV7::new(),
        now.timestamp() as u64,
        now.timestamp_subsec_nanos(),
    );
    Uuid::new_v7(ts)
}

/// Asynchronously reads the entire request body into a `Bytes` buffer.
async fn get_request_body(session: &mut Session) -> pingora::Result<Bytes> {
    let mut buf = BytesMut::new();
    // Pre-allocate buffer if content-length is available
    if let Some(len_str) = session.req_header().headers.get("content-length") {
        if let Ok(len) = len_str.to_str().unwrap_or("0").parse::<usize>() {
            buf.reserve(len);
        }
    }
    while let Some(chunk) = session.read_request_body().await? {
        buf.put(chunk);
    }
    Ok(buf.freeze())
}

#[ctor]
fn init() {
    get_plugin_factory()
        .register("challenge", |params| Ok(Arc::new(Challenge::new(params)?)));
}

mod decrypt;
mod fingerprint;

#[cfg(test)]
mod tests {
    use super::*;
    use http::header;
    use pingap_config::PluginConf;
    use pretty_assertions::assert_eq;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::time::sleep;

    fn create_dummy_session(
        headers: Vec<String>,
        url: String,
    ) -> std::sync::mpsc::Receiver<Option<pingora::proxy::Session>> {
        let (tx, rx) = std::sync::mpsc::sync_channel(0);
        std::thread::spawn(move || {
            match tokio::runtime::Runtime::new() {
                Ok(rt) => {
                    let send = async move {
                        let headers = headers.join("\r\n");
                        let input_header =
                            format!("GET {url} HTTP/1.1\r\n{headers}\r\n\r\n");
                        let mock_io = tokio_test::io::Builder::new()
                            .read(input_header.as_bytes())
                            .build();

                        let mut session =
                            pingora::proxy::Session::new_h1(Box::new(mock_io));
                        session.read_request().await.unwrap();
                        let _ = tx.send(Some(session));
                    };
                    rt.block_on(send);
                },
                Err(_e) => {
                    let _ = tx.send(None);
                },
            };
        });
        rx
    }

    // Helper to create a basic Challenge instance for testing
    fn create_challenge() -> Challenge {
        let mut conf = PluginConf::new();
        conf.insert("secret".to_string(), "my-secret".into());
        conf.insert("url".to_string(), "/challenge".into());
        Challenge::try_from(&conf).unwrap()
    }

    #[test]
    fn test_config_parsing() {
        let mut conf = PluginConf::new();
        conf.insert("secret".to_string(), "test-secret".into());
        conf.insert("url".to_string(), "/verify".into());
        conf.insert("ttl".to_string(), "1h".into());
        conf.insert("threshold".to_string(), 80.into());
        conf.insert("cookie_name".to_string(), "my_challenge_cookie".into());

        let challenge = Challenge::try_from(&conf).unwrap();
        assert_eq!(challenge.url, "/verify");
        assert_eq!(challenge.threshold, 80);
        assert_eq!(challenge.cookie_name, "my_challenge_cookie");
        assert_eq!(challenge.ttl, Some(Duration::from_secs(3600)));
    }

    #[test]
    fn test_config_defaults() {
        let mut conf = PluginConf::new();
        conf.insert("secret".to_string(), "default-secret".into());
        conf.insert("url".to_string(), "/default-challenge".into());

        let challenge = Challenge::try_from(&conf).unwrap();
        assert_eq!(challenge.url, "/default-challenge");
        assert_eq!(challenge.threshold, DEFAULT_THRESHOLD);
        assert_eq!(challenge.cookie_name, DEFAULT_COOKIE_NAME);
        assert_eq!(challenge.ttl, None);
    }
    #[test]
    fn test_config_missing_required_fields() {
        let mut conf_no_secret = PluginConf::new();
        conf_no_secret.insert("url".to_string(), "/no-secret".into());
        assert!(Challenge::try_from(&conf_no_secret).is_err());

        let mut conf_no_url = PluginConf::new();
        conf_no_url.insert("secret".to_string(), "no-url-secret".into());
        assert!(Challenge::try_from(&conf_no_url).is_err());
    }

    #[test]
    fn test_sign_and_verify() {
        let challenge = create_challenge();
        let data = b"test_data";
        let signature = challenge.sign(data).unwrap();
        assert!(challenge.verify_signature(data, &signature).is_ok());
        assert!(challenge
            .verify_signature(b"wrong_data", &signature)
            .is_err());
    }

    #[test]
    fn test_validate_cookie() {
        let challenge = create_challenge();
        let uuid = new_uuid_v7().to_string();
        let signature = challenge.sign(uuid.as_bytes()).unwrap();

        let headers = vec![format!(
            "Cookie:{}={}.{}",
            challenge.cookie_name, uuid, signature
        )
        .parse()
        .unwrap()];
        let session = create_dummy_session(headers, "/".to_string())
            .recv()
            .unwrap()
            .unwrap();
        assert!(challenge.validate_cookie(&session).is_ok());
    }
    #[test]
    fn test_validate_cookie_invalid_cases() {
        let challenge = create_challenge();

        // No cookie
        let session_no_cookie = create_dummy_session(vec![], "/".to_string())
            .recv()
            .unwrap()
            .unwrap();
        assert!(challenge.validate_cookie(&session_no_cookie).is_err());

        // Invalid format
        let headers_invalid_format = vec![format!(
            "Cookie:{}={}",
            challenge.cookie_name, "invalid_format"
        )
        .parse()
        .unwrap()];
        let session_invalid_format =
            create_dummy_session(headers_invalid_format, "/".to_string())
                .recv()
                .unwrap()
                .unwrap();
        assert!(challenge.validate_cookie(&session_invalid_format).is_err());

        // Invalid signature
        let uuid = new_uuid_v7().to_string();

        let headers_invalid_sig = vec![format!(
            "Cookie:{}={}.{}",
            challenge.cookie_name, uuid, "invalid_signature"
        )
        .parse()
        .unwrap()];

        let session_invalid_sig =
            create_dummy_session(headers_invalid_sig, "/".to_string())
                .recv()
                .unwrap()
                .unwrap();
        assert!(challenge.validate_cookie(&session_invalid_sig).is_err());
    }
    #[tokio::test]
    async fn test_cookie_ttl() {
        let mut conf = PluginConf::new();
        conf.insert("secret".to_string(), "ttl-secret".into());
        conf.insert("url".to_string(), "/ttl-challenge".into());
        conf.insert("ttl".to_string(), "1s".into());
        let challenge = Challenge::try_from(&conf).unwrap();

        let uuid = new_uuid_v7().to_string();
        let signature = challenge.sign(uuid.as_bytes()).unwrap();

        let headers = vec![format!(
            "Cookie:{}={}.{}",
            challenge.cookie_name, uuid, signature
        )
        .parse()
        .unwrap()];

        // Should be valid initially
        let session_now =
            create_dummy_session(headers.clone(), "/".to_string())
                .recv()
                .unwrap()
                .unwrap();
        assert!(challenge.validate_cookie(&session_now).is_ok());
        // Wait for cookie to expire
        sleep(Duration::from_secs(2)).await;

        let session_expired = create_dummy_session(headers, "/".to_string())
            .recv()
            .unwrap()
            .unwrap();
        let result = challenge.validate_cookie(&session_expired);
        assert!(result.is_err());
        if let Err(Error::Invalid { message, .. }) = result {
            assert_eq!(message, "cookie is expired");
        } else {
            panic!("Expected cookie expired error");
        }
    }

    #[test]
    fn test_verify_nonce() {
        let challenge = create_challenge();
        let nonce = new_uuid_v7().to_string();
        let signature = challenge.sign(nonce.as_bytes()).unwrap();
        assert!(challenge.verify_nonce(&nonce, &signature).is_ok());

        // Invalid signature
        assert!(challenge.verify_nonce(&nonce, "invalid_signature").is_err());
    }

    #[tokio::test]
    async fn test_nonce_ttl() {
        let mut conf = PluginConf::new();
        conf.insert("secret".to_string(), "nonce-ttl-secret".into());
        conf.insert("url".to_string(), "/nonce-ttl-challenge".into());
        conf.insert("nonce_ttl".to_string(), "1s".into());
        let challenge = Challenge::try_from(&conf).unwrap();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expired_ts = Timestamp::from_unix(ContextV7::new(), now - 2, 0);
        let expired_nonce = Uuid::new_v7(expired_ts).to_string();
        let signature = challenge.sign(expired_nonce.as_bytes()).unwrap();

        let result = challenge.verify_nonce(&expired_nonce, &signature);
        assert!(result.is_err());
        if let Err(Error::Invalid { message, .. }) = result {
            assert_eq!(message, "nonce is expired");
        } else {
            panic!("Expected nonce expired error");
        }
    }

    #[test]
    fn test_nonce_limit() {
        let challenge = create_challenge();
        let nonce = new_uuid_v7().to_string();
        // First use should be valid
        assert!(challenge.nonce_limit.validate(&nonce));
        challenge.nonce_limit.inc(&nonce);
        // Second use should be invalid (limit is 1)
        assert!(!challenge.nonce_limit.validate(&nonce));
    }

    #[test]
    fn test_build_success_cookie() {
        let mut conf = PluginConf::new();
        conf.insert("secret".to_string(), "cookie-build-secret".into());
        conf.insert("url".to_string(), "/cookie-build-challenge".into());
        conf.insert("ttl".to_string(), "30m".into());
        let challenge = Challenge::try_from(&conf).unwrap();

        let (header_name, header_value) =
            challenge.build_success_cookie().unwrap();
        assert_eq!(header_name, header::SET_COOKIE);
        let cookie_str = header_value.to_str().unwrap();
        assert!(cookie_str.starts_with(&format!("{}=", challenge.cookie_name)));
        assert!(cookie_str.contains("Path=/"));
        assert!(cookie_str.contains("HttpOnly"));
        assert!(cookie_str.contains("SameSite=Strict"));
        assert!(cookie_str.contains("Max-Age=1800"));
    }

    #[test]
    fn test_handle_challenge_html() {
        let challenge = create_challenge();

        let result = challenge.handle_challenge_html();
        assert!(result.is_ok(), "handle_challenge_html should not fail");

        let plugin_result = result.unwrap();
        let response = match plugin_result {
            RequestPluginResult::Respond(resp) => resp,
            _ => panic!("Expected a RequestPluginResult::Respond variant"),
        };

        // 4. Assertions on the HTTP Response, validate the content type
        assert_eq!(response.status, StatusCode::OK);
        let header = format!("{:?}", response.headers.unwrap().clone());
        assert_eq!(
            header,
            r#"[("content-type", "text/html; charset=utf-8"), ("cache-control", "private, no-cache")]"#
        );

        // 5. Assertions on the HTML Body, validate the body content
        let body = String::from_utf8(response.body.to_vec()).unwrap();

        // validate the body content
        assert!(body.contains("</html>"), "Response body should be HTML");
        assert!(
            !body.contains("__CHALLENGE_CONFIG__"),
            "Placeholder should have been replaced"
        );

        // 6. Extract and validate the injected JSON config, validate the injected JSON config
        // get ` CHALLENGE_CONFIG = {...};` from the body
        const START_TOKEN: &str = "var CHALLENGE_CONFIG = ";
        const END_TOKEN: &str = ";";

        let start_pos = body
            .find(START_TOKEN)
            .expect("Could not find start of config JSON in HTML");
        let end_pos = body[start_pos..]
            .find(END_TOKEN)
            .expect("Could not find end of config JSON in HTML");

        // extract the JSON string
        let json_str =
            &body[start_pos + START_TOKEN.len()..start_pos + end_pos];

        // 7. Parse the JSON and verify its contents, parse the JSON and verify its contents
        let config_value: serde_json::Value = serde_json::from_str(json_str)
            .expect("Failed to parse injected JSON");

        let nonce = config_value["nonce"]
            .as_str()
            .expect("Nonce not found or not a string");
        let signature = config_value["signature"]
            .as_str()
            .expect("Signature not found or not a string");

        // validate the nonce is a valid UUID
        assert!(
            Uuid::parse_str(nonce).is_ok(),
            "Nonce should be a valid UUID"
        );

        // validate the signature is correct for the given nonce
        assert!(
            challenge
                .verify_signature(nonce.as_bytes(), signature)
                .is_ok(),
            "Signature verification for the nonce should succeed"
        );
    }
}
