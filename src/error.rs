use std::path::PathBuf;
use thiserror::Error;

/// Result alias for certificate provisioning operations.
pub type Result<T> = std::result::Result<T, Error>;

/// All errors that can occur during certificate provisioning and renewal.
#[derive(Debug, Error)]
pub enum Error {
    /// An I/O error occurred (disk, permissions, etc.).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The certificate directory is missing or invalid.
    #[error("Certificate directory not found: {0}")]
    CertDirNotFound(PathBuf),

    /// Failed to parse or write PEM-encoded certificate/key data.
    #[error("PEM error: {0}")]
    Pem(String),

    /// The ACME protocol itself returned an error (RFC 8555 problem document).
    #[error("ACME protocol error: {0}")]
    AcmeProtocol(String),

    /// The ACME account could not be created or loaded.
    #[error("ACME account error: {0}")]
    Account(String),

    /// A challenge (HTTP-01, TLS-ALPN-01, etc.) could not be completed.
    #[error("ACME challenge failed: {0}")]
    Challenge(String),

    /// The certificate order is invalid (e.g., zero domains).
    #[error("ACME order error: {0}")]
    Order(String),

    /// The certificate has expired and could not be renewed.
    #[error("Certificate expired and renewal failed: {0}")]
    Expired(String),

    /// Failed to start or bind the temporary HTTP server for HTTP-01 validation.
    #[error("HTTP challenge server error: {0}")]
    HttpChallengeServer(String),

    /// A generic network / HTTP client error occurred.
    #[error("HTTP client error: {0}")]
    HttpClient(String),

    /// TLS-related error (e.g., certificate loading, key mismatch).
    #[error("TLS error: {0}")]
    Tls(String),

    /// The provider configuration is contradictory or missing required fields.
    #[error("Configuration error: {0}")]
    Config(String),

    /// An error specific to the `tokio-rustls-acme` provider.
    #[cfg(feature = "tokio-acme")]
    #[error("tokio-rustls-acme error: {0}")]
    TokioAcme(#[from] tokio_rustls_acme::acme::AcmeError),

    /// An error originating from the `rustls` TLS library.
    #[cfg(feature = "tokio-acme")]
    #[error("rustls error: {0}")]
    Rustls(#[from] rustls::Error),

    /// A reqwest HTTP error (used in the rfc8555 provider).
    #[cfg(feature = "rfc8555")]
    #[error("reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),

    /// Failed to generate a self-signed certificate or key (rcgen).
    #[cfg(feature = "rfc8555")]
    #[error("rcgen error: {0}")]
    Rcgen(#[from] rcgen::Error),

    /// Hyper server error (HTTP-01 challenge).
    #[cfg(feature = "rfc8555")]
    #[error("hyper error: {0}")]
    Hyper(#[from] hyper::Error),

    /// An internal cancellation or shutdown signal.
    #[error("Provider cancelled")]
    Cancelled,
}

// Manual From impls for stringly-typed errors we need to coerce.
impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::Config(s.to_owned())
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::Config(s)
    }
}