use std::path::PathBuf;

use async_trait::async_trait;

use crate::error::{Error, Result};
use crate::provider::{CertProvider, BackgroundGuard};

pub struct AcmeRfc8555Provider {
    contact_email: String,
}

impl AcmeRfc8555Provider {
    pub fn new(contact_email: impl Into<String>) -> Self {
        Self {
            contact_email: contact_email.into(),
        }
    }

    pub fn staging(contact_email: impl Into<String>) -> Self {
        Self::new(contact_email)
    }
}

#[async_trait]
impl CertProvider for AcmeRfc8555Provider {
    async fn init(
        &mut self,
        _cert_dir: PathBuf,
        domains: Option<Vec<String>>,
    ) -> Result<BackgroundGuard> {
        let domains = domains.ok_or_else(|| Error::Config("domains required".into()))?;
        if domains.is_empty() {
            return Err(Error::Config("at least one domain required".into()));
        }

        // TODO: Implement RFC 8555 provider properly
        // The acme-rfc8555 crate cannot be properly linked in the current environment
        Err(Error::Config("rfc8555 provider not yet implemented".into()))
    }
}