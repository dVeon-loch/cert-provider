pub mod provider;
mod error;
#[cfg(feature = "s3-sync")]
pub mod s3_sync;

pub use error::Error;
pub use provider::{CertProvider, BackgroundGuard};
#[cfg(feature = "s3-sync")]
pub use provider::s3::S3CertProvider;