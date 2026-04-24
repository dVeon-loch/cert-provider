#[cfg(feature = "tokio-acme")]
pub mod tokio_acme;
#[cfg(feature = "rfc8555")]
pub mod rfc8555;
#[cfg(feature = "dns01")]
pub mod dns01;

use async_trait::async_trait;
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;
use crate::error::Result;

#[async_trait]
pub trait CertProvider: Send + Sync + 'static {
    /// Prepare the certificate directory, obtain or renew certs if needed.
    /// `cert_dir` – path where PEM files will be written (e.g. `/certs`).
    /// `domains` – list of domains to request (e.g. `["example.com"]`); `None` = default.
    /// Returns a `BackgroundGuard` that stops renewal on drop.
    async fn init(
        &mut self,
        cert_dir: PathBuf,
        domains: Option<Vec<String>>,
    ) -> Result<BackgroundGuard>;
}

/// Opaque handle – keep it alive for the process lifetime.
pub struct BackgroundGuard {
    cancel: CancellationToken,
}

impl BackgroundGuard {
    pub(crate) fn new(cancel: CancellationToken) -> Self {
        Self { cancel }
    }
}

impl Drop for BackgroundGuard {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}