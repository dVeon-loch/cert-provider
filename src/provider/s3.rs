use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use crate::error::Result;
use crate::provider::{BackgroundGuard, CertProvider};
use crate::s3_sync::S3CertSync;

const DEFAULT_SYNC_INTERVAL: Duration = Duration::from_secs(300);

pub struct S3CertProvider<C: CertProvider> {
    inner: C,
    s3_sync: Arc<S3CertSync>,
    sync_interval: Duration,
}

impl<C: CertProvider> S3CertProvider<C> {
    pub fn new(inner: C, s3_sync: S3CertSync) -> Self {
        Self {
            inner,
            s3_sync: Arc::new(s3_sync),
            sync_interval: DEFAULT_SYNC_INTERVAL,
        }
    }

    pub fn from_arc(inner: C, s3_sync: Arc<S3CertSync>) -> Self {
        Self {
            inner,
            s3_sync,
            sync_interval: DEFAULT_SYNC_INTERVAL,
        }
    }

    pub fn sync_interval(mut self, interval: Duration) -> Self {
        self.sync_interval = interval;
        self
    }
}

#[async_trait]
impl<C: CertProvider> CertProvider for S3CertProvider<C> {
    async fn init(
        &mut self,
        cert_dir: PathBuf,
        domains: Option<Vec<String>>,
    ) -> Result<BackgroundGuard> {
        tokio::fs::create_dir_all(&cert_dir).await?;

        self.s3_sync.pull_to(&cert_dir).await?;

        let inner_guard = self.inner.init(cert_dir.clone(), domains).await?;

        self.s3_sync.push_from(&cert_dir).await?;

        let stop_token = CancellationToken::new();
        let bg_stop = stop_token.clone();
        let bg_sync = self.s3_sync.clone();
        let bg_dir = cert_dir;
        let interval = self.sync_interval;

        let inner = Arc::new(std::sync::Mutex::new(Some(inner_guard)));
        let bg_inner = inner.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = bg_stop.cancelled() => break,
                    _ = tokio::time::sleep(interval) => {}
                }
                if let Err(e) = bg_sync.push_from(&bg_dir).await {
                    tracing::warn!(error = %e, "S3 background sync failed");
                }
            }

            if let Some(guard) = bg_inner.lock().unwrap().take() {
                drop(guard);
            }
        });

        Ok(BackgroundGuard::new(stop_token))
    }
}
