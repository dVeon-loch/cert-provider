use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rustls::pki_types::ServerName;
use rustls::client::danger::{ServerCertVerified, ServerCertVerifier, HandshakeSignatureValid};
use rustls::crypto::CryptoProvider;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_rustls_acme::{AcmeConfig, caches::DirCache};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn, error};

use crate::error::{Error, Result};
use crate::provider::{CertProvider, BackgroundGuard};

#[derive(Clone)]
pub struct TokioAcmeProvider {
    contact_email: String,
}

impl TokioAcmeProvider {
    pub fn new(contact_email: impl Into<String>) -> Self {
        Self { contact_email: contact_email.into() }
    }
}

#[async_trait]
impl CertProvider for TokioAcmeProvider {
    async fn init(
        self: Box<Self>,
        cert_dir: PathBuf,
        domains: Option<Vec<String>>,
    ) -> Result<BackgroundGuard> {
        let domains = domains.ok_or_else(|| Error::Config("domains required".into()))?;
        if domains.is_empty() {
            return Err(Error::Config("at least one domain required".into()));
        }

        // Cache for ACME account & certificates
        let cache_dir = cert_dir.join("cache");
        tokio::fs::create_dir_all(&cache_dir).await?;

        let acme_config = AcmeConfig::new(domains.clone())
            .contact_push(format!("mailto:{}", self.contact_email))
            .cache(DirCache::new(cache_dir.clone()));

        let acceptor = acme_config.tls_acceptor();

        // Bind a temporary loopback listener to trigger initial certificate issuance
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let local_port = listener.local_addr()?.port();

        let cancel = CancellationToken::new();
        let bg_cancel = cancel.clone();

        // Background worker that drives ACME renewal (polls the incoming stream)
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = bg_cancel.cancelled() => {
                        info!("ACME renewal loop stopped");
                        return;
                    }
                    res = listener.accept() => {
                        match res {
                            Ok((stream, _)) => {
                                let acceptor = acceptor.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = acceptor.accept(stream).await {
                                        warn!("TLS accept error (ACME loop): {}", e);
                                    }
                                });
                            }
                            Err(e) => {
                                error!("TCP accept error: {}", e);
                            }
                        }
                    }
                }
            }
        });

        // Force a TLS handshake against ourselves so the certificate is issued immediately.
        // Use a trust‑all verifier because the server may serve a staging certificate or a Let's Encrypt
        // certificate we don't yet trust.
        #[derive(Debug)]
        struct AcceptAllVerifier;
        impl ServerCertVerifier for AcceptAllVerifier {
            fn verify_server_cert(
                &self,
                _end_entity: &rustls::pki_types::CertificateDer<'_>,
                _intermediates: &[rustls::pki_types::CertificateDer<'_>],
                _server_name: &ServerName<'_>,
                _ocsp_response: &[u8],
                _now: rustls::pki_types::UnixTime,
            ) -> std::result::Result<ServerCertVerified, rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }
            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &rustls::pki_types::CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &rustls::pki_types::CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                vec![rustls::SignatureScheme::RSA_PKCS1_SHA256]
            }
        }

        let client_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAllVerifier))
            .with_no_client_auth();
        let mut client_config_with_alpn = client_config.clone();
        client_config_with_alpn.alpn_protocols = vec![b"h2".to_vec()];

        let connector = TlsConnector::from(Arc::new(client_config_with_alpn));
        let domain = ServerName::try_from(domains[0].as_str())
            .map_err(|_| Error::Config("invalid domain name".into()))?;

        let tcp_stream = TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], local_port))).await
            .map_err(|e| Error::Io(e))?;
        let tls_stream = connector.connect(domain, tcp_stream).await
            .map_err(|e| Error::Tls(e.to_string()))?;
        drop(tls_stream); // complete the handshake, certificate should be cached

        // Brief wait for cache file writes
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Locate certificate & key inside the cache.
        // Directory hierarchy: cache/<acme-directory>/directory/<domain>/
        let acme_dir = cache_dir
            .join("acme-v02.api.letsencrypt.org")
            .join("directory");
        let domain_dir = acme_dir.join(&domains[0]);
        let cert_path = domain_dir.join("cert.pem");
        let key_path = domain_dir.join("key.pem");

        if !cert_path.exists() || !key_path.exists() {
            // May be using staging – search recursively for cert.pem
            let found_cert = find_file_in_cache(&cache_dir, "cert.pem", &domains[0])
                .ok_or_else(|| Error::Challenge("No certificate found in cache".into()))?;
            let found_key = find_file_in_cache(&cache_dir, "key.pem", &domains[0])
                .ok_or_else(|| Error::Challenge("No private key found in cache".into()))?;
            // Copy to standard names
            tokio::fs::copy(&found_cert, cert_dir.join("fullchain.pem")).await?;
            tokio::fs::copy(&found_key, cert_dir.join("privkey.pem")).await?;
        } else {
            tokio::fs::copy(&cert_path, cert_dir.join("fullchain.pem")).await?;
            tokio::fs::copy(&key_path, cert_dir.join("privkey.pem")).await?;
        }

        info!("Certificate obtained and written to {:?}", cert_dir);

        Ok(BackgroundGuard::new(cancel))
    }
}

/// Naive search for a file named `filename` inside a cache directory, preferring paths containing `domain`.
fn find_file_in_cache(root: &PathBuf, filename: &str, domain: &str) -> Option<PathBuf> {
    use std::fs;
    fn walk(dir: &PathBuf, target: &str, domain: &str) -> Option<PathBuf> {
        let entries = fs::read_dir(dir).ok()?;
        let mut best: Option<PathBuf> = None;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(found) = walk(&path, target, domain) {
                    return Some(found);
                }
            } else if path.file_name().map(|n| n == target).unwrap_or(false) {
                // Prefer one whose parent directory contains the domain name.
                let parent = path.parent().and_then(|p| p.file_name()).and_then(|n| n.to_str());
                if parent.map(|p| p.contains(domain)).unwrap_or(false) {
                    return Some(path);
                }
                best = Some(path);
            }
        }
        best
    }
    walk(root, filename, domain)
}