use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use http_body_util::Full;
use bytes::Bytes;
use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};
use reqwest::Client;
use tokio::net::TcpListener;
use tokio::time;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn, error, debug};

use acme_rfc8555::{
    Account, Authorization, ChallengeType, Directory, NewAccount, NewOrder, Order, OrderState,
    Challenge,
};

use crate::error::{Error, Result};
use crate::provider::{CertProvider, BackgroundGuard};

const LETS_ENCRYPT_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";
const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

pub struct AcmeRfc8555Provider {
    contact_email: String,
    directory_url: String,
    client: Client,
}

impl AcmeRfc8555Provider {
    pub fn new(contact_email: impl Into<String>) -> Self {
        Self::with_directory(contact_email, LETS_ENCRYPT_PRODUCTION)
    }

    pub fn staging(contact_email: impl Into<String>) -> Self {
        Self::with_directory(contact_email, LETS_ENCRYPT_STAGING)
    }

    fn with_directory(contact_email: impl Into<String>, directory_url: impl Into<String>) -> Self {
        Self {
            contact_email: contact_email.into(),
            directory_url: directory_url.into(),
            client: Client::new(),
        }
    }
}

#[async_trait]
impl CertProvider for AcmeRfc8555Provider {
    async fn init(
        self: Box<Self>,
        cert_dir: PathBuf,
        domains: Option<Vec<String>>,
    ) -> Result<BackgroundGuard> {
        let domains = domains.ok_or_else(|| Error::Config("domains required".into()))?;
        if domains.is_empty() {
            return Err(Error::Config("at least one domain required".into()));
        }

        tokio::fs::create_dir_all(&cert_dir).await?;

        // Load or create account
        let account = create_or_load_account(&cert_dir, &self.contact_email, &self.directory_url, &self.client).await?;

        // Obtain certificate (blocking until ready)
        let (fullchain, privkey) = obtain_certificate(&account, &domains, &self.client).await?;
        tokio::fs::write(cert_dir.join("fullchain.pem"), &fullchain).await?;
        tokio::fs::write(cert_dir.join("privkey.pem"), &privkey).await?;

        info!("Certificate written to {:?}", cert_dir);

        // Spawn background renewal loop
        let cancel = CancellationToken::new();
        let bg_cancel = cancel.clone();
        let cert_dir_clone = cert_dir.clone();
        let domains_clone = domains.clone();
        let client_clone = self.client.clone();
        let account_clone = account.clone(); // store serialized account keys for renewal

        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(24 * 3600));
            loop {
                tokio::select! {
                    _ = bg_cancel.cancelled() => {
                        info!("ACME renewal loop stopped");
                        return;
                    }
                    _ = interval.tick() => {
                        // Check expiry (load cert from disk)
                        if certificate_will_expire_soon(&cert_dir_clone).await {
                            info!("Certificate near expiry, renewing...");
                            match obtain_certificate(&account_clone, &domains_clone, &client_clone).await {
                                Ok((fullchain, privkey)) => {
                                    if let Err(e) = tokio::fs::write(cert_dir_clone.join("fullchain.pem"), &fullchain).await {
                                        error!("Failed to write renewed fullchain: {}", e);
                                    }
                                    if let Err(e) = tokio::fs::write(cert_dir_clone.join("privkey.pem"), &privkey).await {
                                        error!("Failed to write renewed privkey: {}", e);
                                    }
                                    info!("Certificate renewed successfully");
                                }
                                Err(e) => error!("Renewal failed: {}", e),
                            }
                        }
                    }
                }
            }
        });

        Ok(BackgroundGuard::new(cancel))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn create_or_load_account(
    cert_dir: &PathBuf,
    email: &str,
    directory_url: &str,
    client: &Client,
) -> Result<Account> {
    let account_key_path = cert_dir.join("account.key.pem");
    let key_pair = if account_key_path.exists() {
        let pem = tokio::fs::read_to_string(&account_key_path).await?;
        KeyPair::from_pem(&pem).map_err(|e| Error::Account(e.to_string()))?
    } else {
        let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| Error::Account(e.to_string()))?;
        tokio::fs::write(&account_key_path, kp.serialize_pem()).await?;
        kp
    };

    let dir = Directory::from_url(client, directory_url).await
        .map_err(|e| Error::AcmeProtocol(e.to_string()))?;

    let account = Account::create(
        NewAccount { contact: vec![format!("mailto:{}", email)], terms_of_service_agreed: true },
        &key_pair,
        &dir,
        client,
    )
    .await
    .map_err(|e| Error::Account(e.to_string()))?;
    Ok(account)
}

async fn obtain_certificate(
    account: &Account,
    domains: &[String],
    client: &Client,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let dir = account.directory.clone();
    let mut order = Order::create(&dir, NewOrder { domains: domains.to_vec() }, client)
        .await
        .map_err(|e| Error::Order(e.to_string()))?;

    // Solve HTTP-01 challenges for all authorizations
    let authorizations = order.authorizations(&dir, client)
        .await
        .map_err(|e| Error::Order(e.to_string()))?;

    // Start a temporary HTTP server to serve all challenge tokens.
    // Build a map: token -> key_authorization
    let mut challenges_map = std::collections::HashMap::new();
    for auth in &authorizations {
        let challenge = auth.http_challenge().ok_or_else(|| Error::Challenge("HTTP-01 challenge not available".into()))?;
        let key_auth = challenge.key_authorization(&account.key_pair)
            .map_err(|e| Error::Challenge(e.to_string()))?;
        challenges_map.insert(challenge.token.clone(), key_auth.clone());
    }

    // Bind an HTTP server on a random port (or 80). For simplicity we bind to 0.0.0.0:80.
    // In a real deployment you may want to configure the port.
    let listener = TcpListener::bind("0.0.0.0:80").await
        .map_err(|e| Error::HttpChallengeServer(format!("bind: {e}")))?;
    let challenge_data = challenges_map.clone();
    let server_cancel = CancellationToken::new();
    let server_cancel_clone = server_cancel.clone();

    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = server_cancel_clone.cancelled() => {
                    return;
                }
                res = listener.accept() => {
                    match res {
                        Ok((stream, _)) => {
                            let challenge_data = challenge_data.clone();
                            let io = TokioIo::new(stream);
                            tokio::spawn(async move {
                                let svc = service_fn(move |req: Request<Incoming>| {
                                    let challenge_data = challenge_data.clone();
                                    async move {
                                        if req.uri().path().starts_with("/.well-known/acme-challenge/") {
                                            let token = req.uri().path()
                                                .strip_prefix("/.well-known/acme-challenge/")
                                                .unwrap_or("");
                                            if let Some(key_auth) = challenge_data.get(token) {
                                                Ok::<_, hyper::Error>(Response::builder()
                                                    .status(StatusCode::OK)
                                                    .body(Full::new(Bytes::from(key_auth.clone())))
                                                    .unwrap())
                                            } else {
                                                Ok(Response::builder()
                                                    .status(StatusCode::NOT_FOUND)
                                                    .body(Full::new(Bytes::from("not found")))
                                                    .unwrap())
                                            }
                                        } else {
                                            Ok(Response::builder()
                                                .status(StatusCode::NOT_FOUND)
                                                .body(Full::new(Bytes::from("not found")))
                                                .unwrap())
                                        }
                                    }
                                });
                                if let Err(e) = http1::Builder::new()
                                    .serve_connection(io, svc)
                                    .await
                                {
                                    warn!("HTTP server connection error: {}", e);
                                }
                            });
                        }
                        Err(e) => warn!("HTTP server accept error: {}", e),
                    }
                }
            }
        }
    });

    // Validate all challenges
    for auth in &authorizations {
        let challenge = auth.http_challenge().unwrap();
        challenge.validate(&dir, client).await
            .map_err(|e| Error::Challenge(e.to_string()))?;
    }

    // Wait a few seconds for validation to propagate (may not be needed, but safe)
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Finalise order
    let csr = order.create_csr(&account.key_pair, domains).map_err(|e| Error::Order(e.to_string()))?;
    order.finalize(&dir, &csr, client).await.map_err(|e| Error::Order(e.to_string()))?;

    // Poll until certificate is ready
    let cert = loop {
        match order.poll(&dir, client).await.map_err(|e| Error::Order(e.to_string()))? {
            OrderState::Ready => {
                let cert = order.certificate(&dir, client).await
                    .map_err(|e| Error::Order(e.to_string()))?;
                break cert;
            }
            OrderState::Invalid => return Err(Error::Order("Order became invalid".into())),
            _ => {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    };

    // Shutdown HTTP server
    server_cancel.cancel();
    handle.await.ok();

    // Download PEM
    let fullchain = reqwest::get(cert.url().to_string()).await
        .map_err(|e| Error::HttpClient(e.to_string()))?
        .bytes().await
        .map_err(|e| Error::HttpClient(e.to_string()))?;

    let private_key_pem = account.key_pair.serialize_pem();
    Ok((fullchain.to_vec(), private_key_pem.as_bytes().to_vec()))
}

async fn certificate_will_expire_soon(cert_dir: &PathBuf) -> bool {
    // Simple check: try to parse the cert and see if expires in less than 7 days.
    // Use the `x509-parser` or `rustls-pemfile` to get NotAfter.
    // For brevity, we'll just check if the file exists and is older than 60 days.
    let fullchain_path = cert_dir.join("fullchain.pem");
    match tokio::fs::metadata(&fullchain_path).await {
        Ok(meta) => {
            if let Ok(modified) = meta.modified() {
                let now = std::time::SystemTime::now();
                if let Ok(age) = now.duration_since(modified) {
                    return age > Duration::from_secs(60 * 24 * 3600); // 60 days
                }
            }
            true // if we can't determine, renew anyway
        }
        Err(_) => true,
    }
}