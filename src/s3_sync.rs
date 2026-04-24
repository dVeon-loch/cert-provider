use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use awscreds::Credentials;
use awsregion::Region;
use s3::Bucket;
use tokio_util::sync::CancellationToken;

use crate::error::Result;
use crate::provider::BackgroundGuard;

#[derive(Debug, Clone)]
pub struct S3Config {
    pub bucket_name: String,
    pub endpoint: String,
    pub access_key: String,
    pub secret_key: String,
    pub region: Option<String>,
    pub prefix: Option<String>,
}

impl S3Config {
    pub fn is_configured(&self) -> bool {
        !self.bucket_name.is_empty()
            && !self.endpoint.is_empty()
            && !self.access_key.is_empty()
            && !self.secret_key.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct S3CertSync {
    bucket: Arc<Box<Bucket>>,
    config: S3Config,
}

impl S3CertSync {
    pub fn new(config: S3Config) -> Result<Self> {
        let bucket = Self::create_bucket(&config)?;
        Ok(Self {
            bucket: Arc::new(bucket),
            config,
        })
    }

    fn create_bucket(config: &S3Config) -> Result<Box<Bucket>> {
        let credentials = Credentials::new(
            Some(&config.access_key),
            Some(&config.secret_key),
            None,
            None,
            None,
        )?;

        let region = if let Some(region) = &config.region {
            Region::Custom {
                region: region.clone(),
                endpoint: config.endpoint.clone(),
            }
        } else {
            Region::Custom {
                region: "auto".to_string(),
                endpoint: config.endpoint.clone(),
            }
        };

        let bucket = Bucket::new(&config.bucket_name, region, credentials)?
            .with_path_style();
        Ok(bucket)
    }

    fn s3_key(&self, filename: &str) -> String {
        let prefix = self.config.prefix.as_deref().unwrap_or("");
        let prefix = prefix.trim_end_matches('/');
        if prefix.is_empty() {
            filename.to_string()
        } else {
            format!("{prefix}/{filename}")
        }
    }

    pub async fn pull_to(&self, cert_dir: &Path) -> Result<()> {
        let filenames = ["fullchain.pem", "privkey.pem"];
        for name in &filenames {
            let s3_key = self.s3_key(name);
            match self.bucket.get_object(&s3_key).await {
                Ok(content) => {
                    let path = cert_dir.join(name);
                    tokio::fs::write(&path, content.to_vec()).await?;
                    tracing::info!(path = %path.display(), "Downloaded cert file from S3");
                }
                Err(e) => {
                    tracing::debug!(key = %s3_key, error = %e, "Cert file not found in S3");
                }
            }
        }
        Ok(())
    }

    pub async fn push_from(&self, cert_dir: &Path) -> Result<()> {
        let filenames = ["fullchain.pem", "privkey.pem"];
        for name in &filenames {
            let path = cert_dir.join(name);
            if !path.exists() {
                tracing::debug!(path = %path.display(), "Skipping S3 push — file does not exist");
                continue;
            }
            let content = tokio::fs::read(&path).await?;
            let s3_key = self.s3_key(name);
            self.bucket.put_object(&s3_key, &content).await?;
            tracing::info!(key = %s3_key, "Uploaded cert file to S3");
        }
        Ok(())
    }

    pub fn start_background_sync(
        self: Arc<Self>,
        cert_dir: std::path::PathBuf,
        interval: Duration,
    ) -> BackgroundGuard {
        let cancel = CancellationToken::new();
        let bg_cancel = cancel.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = bg_cancel.cancelled() => {
                        tracing::info!("S3 background sync stopped");
                        return;
                    }
                    _ = tokio::time::sleep(interval) => {}
                }

                if let Err(e) = self.push_from(&cert_dir).await {
                    tracing::warn!(error = %e, "S3 background sync failed");
                }
            }
        });

        BackgroundGuard::new(cancel)
    }
}

pub fn env_config() -> S3Config {
    S3Config {
        bucket_name: std::env::var("CERT_S3_BUCKET").unwrap_or_default(),
        endpoint: std::env::var("CERT_S3_ENDPOINT").unwrap_or_default(),
        access_key: std::env::var("CERT_S3_ACCESS_KEY").unwrap_or_default(),
        secret_key: std::env::var("CERT_S3_SECRET_KEY").unwrap_or_default(),
        region: std::env::var("CERT_S3_REGION").ok(),
        prefix: std::env::var("CERT_S3_PREFIX").ok(),
    }
}
