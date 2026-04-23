use std::path::PathBuf;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

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
        &mut self,
        cert_dir: PathBuf,
        domains: Option<Vec<String>>,
    ) -> Result<BackgroundGuard> {
        let domains = domains.ok_or_else(|| Error::Config("domains required".into()))?;
        if domains.is_empty() {
            return Err(Error::Config("at least one domain required".into()));
        }

        // TODO: Implement tokio-rustls-acme provider properly with current API
        // The current implementation uses an API that is no longer available in tokio-rustls-acme 0.9
        // For now, return error indicating this provider is not yet implemented
        Err(Error::Config("tokio-acme provider not yet implemented with current tokio-rustls-acme API".into()))
    }
}